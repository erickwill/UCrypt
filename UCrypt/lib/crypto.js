/**
 * UCrypt — Crypto utilities (reused from UCrypt, zero changes needed).
 *
 * All randomness via crypto.getRandomValues with rejection sampling (zero bias).
 * Works in service workers, content scripts, and extension pages.
 */

const UINT32_BOUND = 0x100000000

export function secureRandomInt(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error('maxExclusive must be a positive integer')
  }
  if (maxExclusive > UINT32_BOUND) {
    throw new Error(`maxExclusive (${maxExclusive}) exceeds Uint32 max`)
  }
  const limit = Math.floor(UINT32_BOUND / maxExclusive) * maxExclusive
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if (buf[0] < limit) return buf[0] % maxExclusive
  }
}

export function secureRandomIntRange(min, maxInclusive) {
  return min + secureRandomInt(maxInclusive - min + 1)
}

export function securePick(arr) {
  if (arr.length === 0) throw new Error('Cannot pick from empty array')
  return arr[secureRandomInt(arr.length)]
}

export function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1)
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

export function secureRandomBytes(n) {
  const buf = new Uint8Array(n)
  crypto.getRandomValues(buf)
  return buf
}

// --- AES-GCM encryption (for the vault) ---

/**
 * Derive an AES-GCM key from a passphrase.
 * v2.2.0: iterations bumped to 600,000 (OWASP 2023 guidance for PBKDF2-SHA256)
 * for master passphrases. The sync code (~256-bit entropy mnemonic) uses fewer
 * iterations safely — pass `iterations` explicitly when deriving it.
 */
export async function deriveKey(passphrase, salt, iterations = 600000) {
  const enc = new TextEncoder()
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encryptString(plaintext, key) {
  const iv = secureRandomBytes(12)
  const enc = new TextEncoder()
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
  )
  // Pack iv + ciphertext as base64
  const combined = new Uint8Array(iv.length + ct.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ct), iv.length)
  return bytesToBase64(combined)
}

export async function decryptString(packed, key) {
  const combined = base64ToBytes(packed)
  const iv = combined.slice(0, 12)
  const ct = combined.slice(12)
  const dec = new TextDecoder()
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, key, ct
  )
  return dec.decode(plain)
}

export async function sha256(data) {
  const buf = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(buf)
}

// --- R45-A §2.3 — CREDENTIAL-ENVELOPE KEY (domain-separated) ----------------
//
// Cloud transport secrets (tokens, passwords) are encrypted at rest with a
// key that is DERIVED AT UNLOCK and exists ONLY in the service worker's
// memory. It is NEVER persisted — not as bytes, not as a CryptoKey object —
// and it is NOT the vault key: PBKDF2 runs again over the SAME random salt
// prefixed with an explicit, versioned domain-separation tag, so the two
// keys share no bits and a compromise of one cannot open the other's data.

export const CRED_ENV_DOMAIN = 'ucrypt:credential-envelope:v1'
/** Envelope wire marker: every sealed value starts with this prefix. */
export const CRED_ENV_SCHEMA = 'ucrypt:cred-env:1'

const CRED_ENV_SALT_TAG = new TextEncoder().encode(CRED_ENV_DOMAIN + ':')

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

/**
 * Derive the credential-envelope AES-GCM key from the master passphrase.
 * Same salt as the vault key PLUS the domain tag in the PBKDF2 salt input
 * (the security order's acceptable alternative: explicit versioned domain
 * separation, never the raw vault key). Non-extractable, encrypt/decrypt
 * only — identical guarantees to the vault key.
 */
export async function deriveCredentialKey(passphrase, salt, iterations = 600000) {
  const enc = new TextEncoder()
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: concatBytes(CRED_ENV_SALT_TAG, salt), iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/**
 * Seal a transport secret into a versioned envelope with a FRESH IV and an
 * AAD that binds the schema version + the transport id — an envelope saved
 * for transport A can never be opened while claiming to belong to transport
 * B, and a value sealed by another schema version is refused loudly.
 */
export async function sealSecret(plaintext, key, transportId) {
  const iv = secureRandomBytes(12)
  const enc = new TextEncoder()
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(`${CRED_ENV_DOMAIN}|${transportId}`) },
    key,
    enc.encode(String(plaintext))
  )
  return `${CRED_ENV_SCHEMA}.${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ct))}`
}

/** True when the value already is a sealed envelope of the current schema. */
export function isSealedEnvelope(value) {
  return typeof value === 'string' && value.startsWith(CRED_ENV_SCHEMA + '.')
}

/**
 * Open a sealed envelope. The AAD must match (schema + transport id) or the
 * GCM tag fails — a misattributed or tampered envelope never decrypts.
 */
export async function openSecret(envelope, key, transportId) {
  if (!isSealedEnvelope(envelope)) {
    throw new Error('Value is not a sealed credential envelope')
  }
  const parts = envelope.split('.')
  if (parts.length !== 3) throw new Error('Malformed credential envelope')
  const iv = base64ToBytes(parts[1])
  const ct = base64ToBytes(parts[2])
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`${CRED_ENV_DOMAIN}|${transportId}`) },
    key,
    ct
  )
  return new TextDecoder().decode(plain)
}

// --- Base64 helpers ---

export function bytesToBase64(bytes) {
  // Chunked conversion — String.fromCharCode.apply blows the stack on
  // large vault blobs (v2.2.0 hardening).
  let bin = ''
  const CH = 0x8000
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH))
  }
  return btoa(bin)
}

export function base64ToBytes(b64) {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
