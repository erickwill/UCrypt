/**
 * UCrypt — R76 Part E "Secure Direct Device Transfer" — TRANSFER CORE
 * (device-trust plane keys + device identity). New in v2.42.14.
 *
 * LAYER SEPARATION (owner order, binding): the transfer subsystem COMPLEMENTS
 * encrypted cloud vault sync; it never replaces it and never shares raw key
 * material, objects or mutable state with the sync plane:
 *
 *   PLANE KEY MAP (the six keys of the R76 Part E order)
 *   ─────────────────────────────────────────────────────────────────────
 *   1. K_sync_envelope        lib/sync.js deriveSyncKey(words)   [EXISTS —
 *                             vault envelope; NOT derived here, never used
 *                             by this plane]
 *   2. K_device_registry      'ucrypt:plane:v1:device-registry'  [NEW —
 *                             AES-GCM: seals the device identity blob, the
 *                             TOFU peer map and transfer-local state]
 *   3. K_rendezvous_locator   'ucrypt:plane:v1:rendezvous-locator' [NEW —
 *                             raw 256 bits, used as the HMAC-SHA-256 key for
 *                             opaque mailbox locators]
 *   4. K_rendezvous_group     'ucrypt:plane:v1:rendezvous-group' [NEW —
 *                             AES-GCM: seals PRESENCE payloads shared with
 *                             every device of the same sync chain]
 *   5. K_transfer_authorization 'ucrypt:plane:v1:transfer-authorization' [NEW
 *                             — AES-GCM, derived and reserved by the order;
 *                             no current writer — reserved for future
 *                             transfer-authorization receipts]
 *   6. K_transfer_audit       'ucrypt:plane:v1:transfer-audit'   [NEW —
 *                             AES-GCM, derived and reserved by the order;
 *                             no current writer — reserved for future
 *                             audit-receipt sealing]
 *   ─────────────────────────────────────────────────────────────────────
 *
 * CRYPTO POLICY (honesty is a gate): audited browser primitives ONLY, via
 * WebCrypto — PBKDF2-SHA-256, HKDF-SHA-256, ECDH P-256, ECDSA P-256 with
 * SHA-256, AES-256-GCM. NO custom crypto. No mobile, no passkey, no native
 * claims anywhere.
 *
 * The worker owns ALL key material. Pages never import this module's secrets;
 * they exchange already-sealed envelopes and non-secret artifacts.
 */

import { encryptString, decryptString, sha256, secureRandomBytes, bytesToBase64, base64ToBytes } from '../crypto.js'
import { syncFingerprint } from '../sync.js'
// R140 §6.1 — the default device name ("<Browser> on <OS>" — a device is
// never nameless); the banned placeholder class lives in THE RELAY module
import { defaultDeviceName, isBannedPlaceholder } from '../beam3/spine.js'

// --- Domain-separation constants --------------------------------------------

/** PBKDF2 salt for the chain root — DIFFERENT from the sync salt, so the
 * chain root can never equal the sync envelope key even for the same words. */
const CHAIN_ROOT_SALT_TEXT = 'ucrypt:chain-root:v1'
/** PBKDF2 iterations — the OWASP 2023 guidance value used by the vault key. */
export const CHAIN_ROOT_ITERATIONS = 600000
/** Fixed HKDF salt for the plane-key derivation (info labels do the rest). */
const PLANE_HKDF_SALT_TEXT = 'ucrypt:plane-salt:v1'
/** info label prefix shared by every plane key (owner order). */
export const PLANE_INFO_PREFIX = 'ucrypt:plane:v1:'

const PAIRWISE_SALT_TEXT = 'ucrypt:pairwise-signal:v1'
const PAIRWISE_INFO_TEXT = 'ucrypt:transfer:signal:v1'
const TRANSFER_KEY_INFO_TEXT = 'ucrypt:transfer:key:v1'
/**
 * R79 (F-R78-1): the chunk nonce prefix is HKDF-derived from the SAME ECDH
 * shared secret under a DISTINCT info label, so both devices compute the
 * identical 32-bit per-transfer prefix without putting it on the wire.
 * Domain separation: K_transfer (file encryption) and the nonce prefix
 * (channel construction) can never derive each other's bits.
 */
const TRANSFER_NONCE_PREFIX_INFO_TEXT = 'ucrypt:transfer:chunk-nonce-prefix:v1'
const TRANSCRIPT_PREFIX = 'ucrypt:transfer-transcript:v1'
const RECORD_PREFIX = 'ucrypt:transfer-record:v1'

/**
 * R79 (F-R78-1): ONE versioned transfer-frame schema. Every chunk frame's
 * AAD names the protocol and schema version explicitly, so a future schema
 * change is a deliberate version bump — never an accidental re-interpretation
 * of the same bytes.
 */
export const TRANSFER_FRAME_VERSION = 1
export const TRANSFER_PROTOCOL_NAME = 'ucrypt-transfer'

export const IDENTITY_STORAGE_KEY = 'ucrypt:transfer:identity'
export const PEERS_STORAGE_KEY = 'ucrypt:transfer:peers'

// --- Small byte/hex/base64url helpers (local; base64 comes from crypto.js) ---

export function utf8Bytes(text) {
  return new TextEncoder().encode(text)
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Base64url without padding — used for mailbox locators (URL-safe path seg). */
export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** 32 random bytes as lowercase hex — message ids, nonces, deviceIds. */
export function randomHex32() {
  return bytesToHex(secureRandomBytes(32))
}

// --- Chain root + plane keys --------------------------------------------------

/**
 * Derive the chain root from the recovery words. PBKDF2-SHA-256 over the SAME
 * word normalization lib/sync.js deriveSyncKey uses (`replace(/[\s\-]+/g,' ')
 * .trim()`), salt = utf8 'ucrypt:chain-root:v1', 600000 iterations, 256 bits.
 * Because the salt differs from the sync salt, this root can NEVER equal
 * K_sync_envelope — the two planes share no bits by construction.
 *
 * @param {string} words the 24-word sync chain mnemonic (never persisted here)
 * @returns {Promise<ArrayBuffer>} raw 32-byte chain root
 */
export async function deriveChainRoot(words) {
  const normalized = String(words || '').replace(/[\s\-]+/g, ' ').trim()
  if (!normalized) throw new Error('Transfer plane: no sync chain words provided')
  const base = await crypto.subtle.importKey('raw', utf8Bytes(normalized), 'PBKDF2', false, ['deriveBits'])
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: utf8Bytes(CHAIN_ROOT_SALT_TEXT), iterations: CHAIN_ROOT_ITERATIONS, hash: 'SHA-256' },
    base,
    256
  )
}

/** Plane names → HKDF info labels (every one prefixed 'ucrypt:plane:v1:'). */
export const PLANE_LABELS = {
  deviceRegistry: PLANE_INFO_PREFIX + 'device-registry',
  rendezvousLocator: PLANE_INFO_PREFIX + 'rendezvous-locator',
  rendezvousGroup: PLANE_INFO_PREFIX + 'rendezvous-group',
  transferAuthorization: PLANE_INFO_PREFIX + 'transfer-authorization',
  transferAudit: PLANE_INFO_PREFIX + 'transfer-audit',
}

/**
 * Derive the five transfer-plane keys from the chain root via HKDF-SHA-256
 * with distinct info labels (see the plane key map at the top of the file).
 * - device-registry / rendezvous-group / transfer-authorization / transfer-audit
 *   → non-extractable AES-GCM-256 keys (encrypt/decrypt only).
 * - rendezvous-locator → raw 256 bits (an HMAC-SHA-256 key material; imported
 *   per call so it never lives in an extractable CryptoKey).
 *
 * K_sync_envelope is deliberately NOT produced here — it remains the product
 * of lib/sync.js deriveSyncKey (plane 1 of the map above).
 *
 * @param {ArrayBuffer} chainRoot from deriveChainRoot
 */
export async function derivePlaneKeys(chainRoot) {
  const base = await crypto.subtle.importKey('raw', chainRoot, 'HKDF', false, ['deriveBits'])
  const salt = utf8Bytes(PLANE_HKDF_SALT_TEXT)

  const aesPlane = async (label) => {
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: utf8Bytes(label) }, base, 256
    )
    return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  }

  const locatorBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8Bytes(PLANE_LABELS.rendezvousLocator) }, base, 256
  )

  return {
    deviceRegistry: await aesPlane(PLANE_LABELS.deviceRegistry),
    // Raw bits — used as the HMAC-SHA-256 key for mailbox locators.
    rendezvousLocator: new Uint8Array(locatorBits),
    rendezvousGroup: await aesPlane(PLANE_LABELS.rendezvousGroup),
    // Reserved by the owner order (derived, non-extractable, unused today).
    transferAuthorization: await aesPlane(PLANE_LABELS.transferAuthorization),
    transferAudit: await aesPlane(PLANE_LABELS.transferAudit),
  }
}

/**
 * Derive the full chain key set from the words: chain root → plane keys, plus
 * the NON-SECRET chainTag used for fast foreign-chain rejection.
 *
 * chainTag = the 8 hex characters of lib/sync.js syncFingerprint(words)
 * (the existing export — imported, never reimplemented), dash-stripped and
 * lowercased. The order's "first 8 bytes hex" maps to this existing 8-hex-char
 * fingerprint output (sha256 over the normalized words, first 4 bytes); it is
 * a non-secret discriminator carried in every rendezvous record so a record
 * from a foreign sync chain can be dropped before any decryption.
 */
export async function deriveChainKeys(words) {
  const chainRoot = await deriveChainRoot(words)
  const planes = await derivePlaneKeys(chainRoot)
  const fp = await syncFingerprint(String(words || ''))
  const chainTag = fp.replace(/-/g, '').toLowerCase()
  return { chainRoot, chainTag, ...planes }
}

// --- Device identity -----------------------------------------------------------

async function importEcdsaPublic(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
}

async function importEcdsaPrivate(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
}

async function importEcdhPublic(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
}

async function importEcdhPrivate(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
}

/** Strip private-material JWK fields for a shareable public JWK copy. */
function publicJwkCopy(jwk) {
  const { d, ...pub } = jwk
  return { ...pub }
}

/**
 * Load (or create, once) this device's transfer identity from
 * chrome.storage.local key 'ucrypt:transfer:identity'. The stored blob is a
 * single sealed envelope under the device-registry plane key (lib/crypto.js
 * encryptString — AES-256-GCM); plaintext identity material NEVER touches
 * storage. The identity contains:
 *   - deviceId: 16 random bytes hex (crypto.getRandomValues)
 *   - ECDSA P-256 signing keypair (sign/verify; private JWK extractable so it
 *     can be sealed into the identity blob)
 *   - ECDH P-256 agreement keypair (for pairwise signal keys)
 * Persisted shape: {deviceId, signPubJwk, agrPubJwk, signPrivJwk, agrPrivJwk}.
 *
 * @param {{deviceRegistry: CryptoKey}} chainKeys from deriveChainKeys
 */
export async function getOrCreateDeviceIdentity(chainKeys) {
  const { [IDENTITY_STORAGE_KEY]: sealed } = await chrome.storage.local.get(IDENTITY_STORAGE_KEY)
  if (sealed) {
    try {
      const json = await decryptString(sealed, chainKeys.deviceRegistry)
      const rec = JSON.parse(json)
      if (rec && rec.deviceId && rec.signPrivJwk && rec.agrPrivJwk) {
        return {
          deviceId: rec.deviceId,
          // R100 (the CEO's Brave-style device list): the device's OWN name —
          // user-set, sealed with the identity, published in the presence and
          // the chain roster. Optional (pre-name identities read as '').
          label: typeof rec.label === 'string' ? rec.label.slice(0, 60) : '',
          // R113 §3.1 — the self-declared device type survives the LOAD (the
          // sealed record is the truth; the label's exact pattern). Without
          // this, every worker restart dropped the type from the cache and
          // the presence/roster stamps sealed without it. (F-R113-DT-LOAD-1)
          deviceType: (rec && typeof rec.deviceType === 'string' && ['phone', 'tablet', 'computer'].includes(rec.deviceType)) ? rec.deviceType : '',
          typeSetAt: Number(rec.typeSetAt) || 0,
          signKeys: {
            privateKey: await importEcdsaPrivate(rec.signPrivJwk),
            publicKey: await importEcdsaPublic(rec.signPubJwk),
          },
          agrKeys: {
            privateKey: await importEcdhPrivate(rec.agrPrivJwk),
            publicKey: await importEcdhPublic(rec.agrPubJwk),
          },
          signPubJwk: rec.signPubJwk,
          agrPubJwk: rec.agrPubJwk,
          // R77-C audit fix: the pairwise ECDH call sites consume the private
          // agreement JWK (worker-memory-only, same trust zone as the
          // CryptoKeys above; it was already inside the sealed blob).
          signPrivJwk: rec.signPrivJwk,
          agrPrivJwk: rec.agrPrivJwk,
        }
      }
    } catch (e) {
      // A seal that no longer opens (different chain, corrupt record) is NOT a
      // silent reset signal — log and create a fresh identity below, exactly
      // like a first run. The old blob is overwritten by the new sealed one.
      console.warn('[UCrypt] Transfer identity blob could not be opened — recreating:', e?.message || e)
    }
  }

  const deviceId = bytesToHex(secureRandomBytes(16))
  const signKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const agrKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  const signPubJwk = publicJwkCopy(await crypto.subtle.exportKey('jwk', signKeys.publicKey))
  const signPrivJwk = await crypto.subtle.exportKey('jwk', signKeys.privateKey)
  const agrPubJwk = publicJwkCopy(await crypto.subtle.exportKey('jwk', agrKeys.publicKey))
  const agrPrivJwk = await crypto.subtle.exportKey('jwk', agrKeys.privateKey)
  // R140 §6.1 — A DEVICE IS NEVER NAMELESS: the label DEFAULTS to
  // "<Browser> on <OS>" at creation (the Brave lesson), user-editable in
  // settings; the banned nameless placeholder is unrepresentable at birth
  const defaultLabel = defaultDeviceName(typeof navigator !== 'undefined' ? navigator.userAgent : '')

  const sealedBlob = await encryptString(JSON.stringify({ deviceId, signPubJwk, agrPubJwk, signPrivJwk, agrPrivJwk, label: defaultLabel }), chainKeys.deviceRegistry)
  await chrome.storage.local.set({ [IDENTITY_STORAGE_KEY]: sealedBlob })

  return {
    deviceId,
    // R140 §6.1 — the default name rides the returned record (never nameless)
    label: defaultLabel,
    signKeys: {
      privateKey: await importEcdsaPrivate(signPrivJwk),
      publicKey: await importEcdsaPublic(signPubJwk),
    },
    agrKeys: {
      privateKey: await importEcdhPrivate(agrPrivJwk),
      publicKey: await importEcdhPublic(agrPubJwk),
    },
    signPubJwk,
    agrPubJwk,
    // R77-C audit fix — see the cached-return note above.
    signPrivJwk,
    agrPrivJwk,
  }
}

/** R108 §3.3 — the ONE label sanitizer (the mutual-rename law): trimmed,
 * control characters stripped, 1–40 characters enforced (empty → '' meaning
 * "unnamed" — the callers decide whether that is an error). Every rename
 * path (self, peer, the Accept-dialog optional field) funnels through HERE —
 * one law, no divergent caps. */
export function sanitizeDeviceLabel(raw) {
  let s = String(raw || '')
  // eslint-disable-next-line no-control-regex
  s = s.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40)
  return s
}

/** R100 (the CEO's Brave-style device list): name THIS device. The label is
 * sealed with the identity (it never rides the wire as a secret — it is
 * published in the presence record and the chain roster BY DESIGN, like
 * Brave's device names). Returns the updated identity record.
 * R108 §3.2 — the label now carries its write time (labelSetAt): the
 * per-entry LAST-WRITER law for the mutual rename (any device may rename any
 * device; the newest write wins on merge; the roster carries it to everyone). */
export async function setDeviceIdentityLabel(chainKeys, label) {
  const clean = sanitizeDeviceLabel(label)
  const { [IDENTITY_STORAGE_KEY]: sealed } = await chrome.storage.local.get(IDENTITY_STORAGE_KEY)
  if (!sealed) throw new Error('no identity to name')
  const rec = JSON.parse(await decryptString(sealed, chainKeys.deviceRegistry))
  if (!rec || !rec.deviceId) throw new Error('identity record unreadable')
  rec.label = clean
  rec.labelSetAt = Date.now()
  const sealedBlob = await encryptString(JSON.stringify(rec), chainKeys.deviceRegistry)
  await chrome.storage.local.set({ [IDENTITY_STORAGE_KEY]: sealedBlob })
  return clean
}

/** R113 §3.1 — the SELF-DECLARED device type (phone / tablet / computer). The
 * type is sealed with the identity like the label, carries its write time
 * (typeSetAt) under the SAME per-entry last-writer law, and rides the
 * presence/roster stamp BY DESIGN (it is a self-declared label, never a
 * secret). Self-only: a device never types another — peers' types arrive
 * through learnPeer's merge, never through a remote write. */
export const DEVICE_TYPES = ['phone', 'tablet', 'computer']

export function sanitizeDeviceType(raw) {
  const t = String(raw || '').trim().toLowerCase()
  return DEVICE_TYPES.includes(t) ? t : ''
}

export async function setDeviceIdentityType(chainKeys, type) {
  const clean = sanitizeDeviceType(type)
  if (!clean) throw new Error('the device type must be phone, tablet or computer')
  const { [IDENTITY_STORAGE_KEY]: sealed } = await chrome.storage.local.get(IDENTITY_STORAGE_KEY)
  if (!sealed) throw new Error('no identity to type')
  const rec = JSON.parse(await decryptString(sealed, chainKeys.deviceRegistry))
  if (!rec || !rec.deviceId) throw new Error('identity record unreadable')
  rec.deviceType = clean
  rec.typeSetAt = Date.now()
  const sealedBlob = await encryptString(JSON.stringify(rec), chainKeys.deviceRegistry)
  await chrome.storage.local.set({ [IDENTITY_STORAGE_KEY]: sealedBlob })
  return clean
}

// --- Pairwise + transfer session keys ------------------------------------------

async function ecdhBits(privJwk, peerPubJwk) {
  const priv = await importEcdhPrivate(privJwk)
  const pub = await importEcdhPublic(peerPubJwk)
  // R77-C audit fix: the peer public key belongs in the ALGORITHM parameter,
  // and deriveBits requires a finite length (256 bits of shared secret).
  return crypto.subtle.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: pub }, priv, 256)
}

async function hkdfAesKey(rawBits, saltBytes, infoText) {
  const base = await crypto.subtle.importKey('raw', rawBits, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: utf8Bytes(infoText) }, base, 256
  )
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/**
 * Pairwise SIGNAL key for the rendezvous plane: ECDH P-256 (my agreement
 * private × peer agreement public) → HKDF-SHA-256(salt 'ucrypt:pairwise-
 * signal:v1', info 'ucrypt:transfer:signal:v1') → AES-256-GCM key. This key
 * seals every offer/answer/ice/cancel/complete record payload.
 */
export async function derivePairwiseSignalKey(myAgrPrivJwk, peerAgrPubJwk) {
  return hkdfAesKey(await ecdhBits(myAgrPrivJwk, peerAgrPubJwk), utf8Bytes(PAIRWISE_SALT_TEXT), PAIRWISE_INFO_TEXT)
}

/**
 * Ephemeral P-256 ECDH keypair for one transfer. The private JWK never
 * leaves the worker; the public JWK rides inside the (sealed) offer payload.
 */
export async function generateEphemeralKeys() {
  const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  const privJwk = await crypto.subtle.exportKey('jwk', keys.privateKey)
  const pubJwk = publicJwkCopy(await crypto.subtle.exportKey('jwk', keys.publicKey))
  return { privJwk, pubJwk }
}

/**
 * Canonical transfer transcript hash: sha256 over the fixed-order string
 *   `ucrypt:transfer-transcript:v1|<offerMsgId>|<answerMsgId>|<offerPayloadHashHex>|<answerPayloadHashHex>`
 * (payload hashes are the sha256-hex of each record's payload CIPHERTEXT
 * bytes, per canonicalRecordBytes). Returned as raw bytes; it is the HKDF
 * salt of K_transfer and the input of transferFingerprint.
 */
export async function transcriptHash(offerMsgId, answerMsgId, offerPayloadHashHex, answerPayloadHashHex) {
  const canon = `${TRANSCRIPT_PREFIX}|${offerMsgId}|${answerMsgId}|${offerPayloadHashHex}|${answerPayloadHashHex}`
  return sha256(utf8Bytes(canon))
}

/**
 * Derive the TRANSFER-plane session key (K_transfer): ECDH P-256 between the
 * two per-transfer EPHEMERAL keys → HKDF-SHA-256(salt = transcriptHashBytes,
 * info 'ucrypt:transfer:key:v1') → AES-256-GCM. Both devices derive the same
 * key; the transcript binding makes the key unusable for any other pairing of
 * records (a full transcript swap is detectable — the GCM tag fails).
 */
export async function deriveTransferKey(myEphemeralPrivJwk, peerEphemeralPubJwk, transcriptHashBytes) {
  return hkdfAesKey(await ecdhBits(myEphemeralPrivJwk, peerEphemeralPubJwk), transcriptHashBytes, TRANSFER_KEY_INFO_TEXT)
}

/**
 * R79 (F-R78-1): derive BOTH per-transfer artifacts in one ECDH pass:
 *   - key:         K_transfer (AES-256-GCM) — unchanged semantics
 *   - noncePrefix: 32 deterministic bits for the chunk-nonce construction
 * Both sides call this with their own ephemeral PRIVATE key and the peer's
 * ephemeral PUBLIC key, so both arrive at the same (key, prefix) pair. The
 * prefix never travels on the wire and never repeats across transfers (the
 * ECDH shared secret is unique per transfer because the ephemeral keys are).
 */
export async function deriveTransferSecrets(myEphemeralPrivJwk, peerEphemeralPubJwk, transcriptHashBytes) {
  const shared = await ecdhBits(myEphemeralPrivJwk, peerEphemeralPubJwk)
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits'])
  const keyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: transcriptHashBytes, info: utf8Bytes(TRANSFER_KEY_INFO_TEXT) }, base, 256
  )
  const key = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonceBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: transcriptHashBytes, info: utf8Bytes(TRANSFER_NONCE_PREFIX_INFO_TEXT) }, base, 32
  )
  return { key, noncePrefix: new Uint8Array(nonceBits) }
}

// --- Canonical chunk-frame schema (R79, owner order §1.1) ------------------------

/**
 * THE one canonical chunk AAD builder (owner order R79 §1.1). The sender and
 * the receiver MUST construct the AAD through this shared function — no call
 * site may hand-roll an AAD, so the two sides can never disagree about which
 * values are bound to the ciphertext (the F-R78-1 defect: the sender bound
 * totalChunks where the receiver bound totalBytes).
 *
 * Bound fields (both sides supply identical values from the offer/session):
 *   protocol        'ucrypt-transfer' (fixed)
 *   version         TRANSFER_FRAME_VERSION (1)
 *   transferId      the per-transfer id from the sealed offer record
 *   senderDeviceId  sending device's registered deviceId
 *   receiverDeviceId receiving device's registered deviceId
 *   chunkIndex      0-based index of this chunk
 *   totalChunks     Math.ceil(totalBytes / CHUNK_SIZE) — the chunk COUNT
 *   totalBytes      the offered file size in bytes
 *   metadataHash    the offer's file digest (sha256hex) — binds every chunk
 *                   to the exact offered metadata; a different file under
 *                   the same transfer id cannot be spliced in
 *
 * Canonical serialization: fixed field order via a single JSON.stringify of
 * a literal object — deterministic across both platforms (no key sorting
 * ambiguity, no locale/format drift).
 *
 * @param {{transferId:string, senderDeviceId:string, receiverDeviceId:string,
 *          chunkIndex:number, totalChunks:number, totalBytes:number,
 *          metadataHash:string}} f
 * @returns {Uint8Array} AAD bytes for AES-GCM
 */
export function buildChunkAad(f) {
  const canon = JSON.stringify({
    protocol: TRANSFER_PROTOCOL_NAME,
    version: TRANSFER_FRAME_VERSION,
    transferId: String((f && f.transferId) || ''),
    senderDeviceId: String((f && f.senderDeviceId) || ''),
    receiverDeviceId: String((f && f.receiverDeviceId) || ''),
    chunkIndex: Number((f && f.chunkIndex) || 0),
    totalChunks: Number((f && f.totalChunks) || 0),
    totalBytes: Number((f && f.totalBytes) || 0),
    metadataHash: String((f && f.metadataHash) || ''),
  })
  return utf8Bytes(canon)
}

/**
 * R79 (F-R78-1): deterministic chunk nonce —
 *   nonce(12 bytes) = transferNoncePrefix(4) || uint64bigEndian(chunkIndex)(8)
 * Unique under one transfer key: the prefix is fixed per transfer and the
 * index is strictly increasing, so a nonce never repeats; different transfers
 * use different ephemeral keys AND different prefixes. Deterministic nonces
 * additionally let the receiver REFUSE a frame whose claimed nonce deviates
 * from the construction (a mutated or replayed-from-elsewhere frame fails
 * before any decryption).
 *
 * @param {Uint8Array} noncePrefix 4 bytes from deriveTransferSecrets
 * @param {number} chunkIndex 0-based chunk index
 * @returns {Uint8Array} 12-byte GCM IV
 */
export function chunkNonce(noncePrefix, chunkIndex) {
  const prefix = noncePrefix instanceof Uint8Array ? noncePrefix : new Uint8Array(noncePrefix || [])
  if (prefix.length !== 4) throw new Error('Transfer frame: the nonce prefix must be exactly 4 bytes')
  const idx = Number(chunkIndex) || 0
  if (idx < 0 || !Number.isInteger(idx) || idx > Number.MAX_SAFE_INTEGER) {
    throw new Error('Transfer frame: chunk index out of range')
  }
  const nonce = new Uint8Array(12)
  nonce.set(prefix, 0)
  const bi = BigInt(idx)
  for (let i = 0; i < 8; i++) {
    nonce[11 - i] = Number((bi >> BigInt(8 * i)) & 0xffn)
  }
  return nonce
}

/**
 * Human-verifiable transfer fingerprint: "XXXX XXXX XXXX XXXX" — uppercase
 * hex groups of the FIRST 8 BYTES of the transcript hash. BOTH devices display
 * this before the channel is used ("Compare this code with the other device
 * before continuing"). Equal codes ⇒ both sides derived the same K_transfer
 * transcript; unequal ⇒ something is between the devices — cancel.
 */
export function transferFingerprint(transcriptHashBytes) {
  const hex = bytesToHex(new Uint8Array(transcriptHashBytes).slice(0, 8)).toUpperCase()
  return hex.replace(/(.{4})(.{4})(.{4})(.{4})/, '$1 $2 $3 $4')
}

// --- Mailbox locator -------------------------------------------------------------

/**
 * Opaque rendezvous mailbox locator for one device: base64url(HMAC-SHA-256(
 * key = K_rendezvous_locator raw bits, data = utf8 `${chainTag}:box:${deviceId}`)).
 * The locator reveals nothing (it is an HMAC of opaque inputs); the file name
 * on the rendezvous server is `<locator>.json`.
 */
export async function mailboxLocator(chainKeys, deviceId) {
  const key = await crypto.subtle.importKey(
    'raw', chainKeys.rendezvousLocator, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, utf8Bytes(`${chainKeys.chainTag}:box:${deviceId}`))
  return bytesToBase64Url(new Uint8Array(sig))
}

// --- Canonical records + ECDSA signatures ----------------------------------------

export async function sha256HexOfBytes(bytes) {
  return bytesToHex(await sha256(bytes))
}

/**
 * Canonical record bytes — the EXACT signing input for every rendezvous
 * record. FIXED field order (documented per the owner order):
 *
 *   `ucrypt:transfer-record:v1|messageId|transferId|from|to|expiresAt|seq|nonce|kind|payloadHashHex`
 *
 * where payloadHashHex = sha256-hex of the record's `payload` CIPHERTEXT
 * (base64-decoded) bytes. The signature therefore covers every envelope field
 * AND binds the sealed payload — any field swap or payload splice breaks it.
 *
 * @param {object} rec a record envelope (schema in lib/transfer/mailbox.js)
 * @returns {Promise<Uint8Array>} bytes of the canonical string
 */
export async function canonicalRecordBytes(rec) {
  const payloadHashHex = await sha256HexOfBytes(base64ToBytes(String(rec.payload || '')))
  const canon = [
    RECORD_PREFIX,
    rec.messageId, rec.transferId, rec.from, rec.to, rec.expiresAt,
    String(rec.seq), String(rec.nonce || ''), rec.kind, payloadHashHex,
  ].join('|')
  return utf8Bytes(canon)
}

/** ECDSA P-256 / SHA-256 signature over the canonical bytes → base64. */
export async function signRecord(privKey, canonicalBytes) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, canonicalBytes)
  return bytesToBase64(new Uint8Array(sig))
}

/** Verify an ECDSA P-256/SHA-256 base64 signature over the canonical bytes. */
export async function verifyRecord(pubJwk, sigB64, canonicalBytes) {
  let pub
  try {
    pub = await importEcdsaPublic(pubJwk)
  } catch {
    return false
  }
  try {
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, base64ToBytes(sigB64), canonicalBytes)
  } catch {
    return false
  }
}
