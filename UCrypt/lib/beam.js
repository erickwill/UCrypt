/**
 * UCrypt — R98 "Sync Beam — Direct Join" (S8) — THE BEAM PLANE.
 * New in v2.56.0.
 *
 * THE LAW (CSA ORDER R98 §2.1, S8.1): when two devices are simultaneously
 * present, chain join — and thereafter synchronization — travels
 * device-to-device over the direct encrypted channel. The cloud transport is
 * the durable backup and the store-and-forward for devices not simultaneously
 * online. No UCrypt server exists in either role, ever.
 *
 * This module implements the JOIN HANDSHAKE (S8.4) and the ORIGIN'S MOMENT
 * (S8.5) record machinery on the existing rendezvous rails
 * (lib/transfer/mailbox.js + core.js). The beam TRANSFER itself (S8.6) rides
 * the existing WebRTC file plane unchanged — the payload is the sealed vault
 * envelope, the exact bytes the cloud would carry.
 *
 * ─── The join record ────────────────────────────────────────────────────────
 * A new record kind 'join' (added to RECORD_KINDS — additions-only). The
 * joiner HAS the words (that is the entry), so it can derive every chain key
 * and the ORIGIN's agreement key from the origin's presence record (TOFU).
 * The ORIGIN has never heard of the joiner, so the join record's ENVELOPE
 * carries the joiner's public keys (signPubJwk/agrPubJwk) as clear envelope
 * fields, covered by the envelope signature; the PAYLOAD is sealed under the
 * PAIRWISE signal key (joiner agr-private × origin agr-public). The origin:
 *   1. verifies the envelope signature against the carried signPubJwk,
 *   2. derives the pairwise key from its own agr-private × the carried
 *      agrPubJwk and opens the payload,
 *   3. verifies the CHAIN-PROOF — an HMAC-SHA-256 under a chain-derived
 *      subkey (HKDF from the chain root, domain-separated info label) over
 *      `label|deviceId|timestamp`. The proof is verifiable only by chain
 *      members and is useless to a rendezvous intruder; the words never
 *      leave the joiner's device.
 *   4. learns the joiner into the sealed TOFU peer map (first contact),
 *   5. shows the dialog: label + the short human-comparable DEVICE
 *      FINGERPRINT (rendered identically on both screens) + time —
 *      Accept / Decline, never auto-dismissed (law 0.8).
 *
 * Security summary (S8.10): the QR carries the full secret (the standing
 * model — a stolen QR is a stolen key). The Beam adds the chain-proof (no
 * fake joins without the words), the origin's explicit acceptance, the
 * bounded window, and unchanged end-to-end envelope encryption. The Beam
 * changes the transport, never the trust model. The beam NEVER transports
 * credentials — the cloud hint is provider + URL only (the payload law).
 *
 * Replay: consumed join decisions (accept/decline) are one-shot — the
 * messageId is recorded and a second decision attempt is refused. Listing
 * pending joins stays idempotent (the dialog may re-render, the decision
 * cannot re-fire). Failed proofs from one device id are RATE-LIMITED with
 * typed copy.
 */

import { encryptString, decryptString, sha256 } from './crypto.js'
import {
  derivePairwiseSignalKey,
  bytesToHex,
  utf8Bytes,
  randomHex32,
  canonicalRecordBytes,
  signRecord,
  verifyRecord,
  mailboxLocator,
} from './transfer/core.js'
import {
  transferError,
  isRecordStructurallyValid,
  RECORD_KINDS,
  RECORD_TTL_MS,
  sealForPeer,
  putRecordToMailbox,
  readOwnMailbox,
  learnPeer,
  loadPeerMap,
} from './transfer/mailbox.js'

// --- Domain separation + constants -------------------------------------------

/** HKDF info label for the join-proof subkey — derived under the EXISTING
 * chain root (no new key material; a distinct label does the separating). */
const BEAM_JOIN_PROOF_INFO = 'ucrypt:beam:join-proof:v1'
/** The HMAC input's domain separator (defence in depth — the label names the
 * protocol, the device id and the timestamp are the signed commitment). */
const BEAM_JOIN_PROOF_PREFIX = 'ucrypt:beam:join-proof:v1'
/** Human fingerprint rendering — identical on BOTH screens (S8.5). */
const FINGERPRINT_GROUP_RE = /(.{4})(.{4})(.{4})(.{4})/

/** The beam window (S8.3): bounded, default 10 minutes — aligned with the
 * record TTL (the join record lives exactly as long as the window). */
export const BEAM_WINDOW_MINUTES_DEFAULT = 10
export const BEAM_WINDOW_MINUTES_MAX = 60
/** Join records inherit the rendezvous record TTL (10 min). */
export const BEAM_JOIN_TTL_MS = RECORD_TTL_MS

/** Rate limiting (S8.4): failed proofs from one device id are rate-limited
 * with typed copy. Bounded, device-local, windowed. */
export const BEAM_PROOF_FAIL_LIMIT = 3
export const BEAM_PROOF_FAIL_WINDOW_MS = 10 * 60 * 1000
const BEAM_FAIL_KEY = 'ucrypt:beam:join:failures'
/** One-shot decision ledger (replay protection for consumed joins). */
const BEAM_SEEN_KEY = 'ucrypt:beam:join:seen'
const BEAM_SEEN_CAP = 100

/** The beam transfer's envelope file name — the joiner's digest gate and the
 * oversized-fallback copy both name it. */
export const BEAM_ENVELOPE_NAME = 'ucrypt-vault.enc'

// --- Small helpers -------------------------------------------------------------

function nowIso() {
  return new Date().toISOString()
}

async function hmacKeyFromChainRoot(chainRootBits) {
  const base = await crypto.subtle.importKey('raw', chainRootBits, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8Bytes('ucrypt:plane-salt:v1'), info: utf8Bytes(BEAM_JOIN_PROOF_INFO) },
    base, 256
  )
  return crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

function timingSafeEqualHex(a, b) {
  const ab = utf8Bytes(String(a || ''))
  const bb = utf8Bytes(String(b || ''))
  if (ab.length !== bb.length || ab.length === 0) return false
  let diff = 0
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i]
  return diff === 0
}

/**
 * The CHAIN-PROOF (S8.4): HMAC-SHA-256 under the chain-derived join-proof
 * subkey over the domain-separated `prefix|deviceId|timestamp`. Verifiable
 * only by word-holders; useless to a rendezvous intruder.
 */
export async function createJoinProof(chainRootBits, deviceId, timestampMs) {
  if (!chainRootBits) throw transferError('internal', 'Beam join proof requires the chain root')
  const key = await hmacKeyFromChainRoot(chainRootBits)
  const data = utf8Bytes(`${BEAM_JOIN_PROOF_PREFIX}|${deviceId}|${timestampMs}`)
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, data))
  return bytesToHex(sig)
}

/** Verify a chain-proof (timing-safe; bounded clock skew 2 min). */
export async function verifyJoinProof(chainRootBits, deviceId, timestampMs, proofHex, { skewMs = 2 * 60 * 1000 } = {}) {
  const ts = Number(timestampMs)
  if (!Number.isFinite(ts)) return false
  if (Math.abs(Date.now() - ts) > skewMs) return false
  try {
    const expected = await createJoinProof(chainRootBits, deviceId, ts)
    return timingSafeEqualHex(expected, proofHex)
  } catch {
    return false
  }
}

/**
 * The short human-comparable DEVICE FINGERPRINT (S8.5): "XXXX XXXX XXXX
 * XXXX" from sha256 over the canonical JWK coordinates of the device's
 * SIGNING public key. Both screens render the SAME value from the SAME
 * public key — compare them, then accept.
 */
export async function deviceFingerprint(signPubJwk) {
  const canon = JSON.stringify({ crv: signPubJwk && signPubJwk.crv, x: signPubJwk && signPubJwk.x, y: signPubJwk && signPubJwk.y })
  const h = await sha256(utf8Bytes(canon))
  const hex = bytesToHex(new Uint8Array(h).slice(0, 8)).toUpperCase()
  return hex.replace(FINGERPRINT_GROUP_RE, '$1 $2 $3 $4')
}

// --- Replay + rate-limit ledgers (device-local, bounded) -------------------------

async function loadSeen() {
  const { [BEAM_SEEN_KEY]: cur } = await chrome.storage.local.get(BEAM_SEEN_KEY)
  return Array.isArray(cur) ? cur.filter((x) => typeof x === 'string') : []
}

/** One-shot consumption: returns false when the messageId was already used. */
export async function consumeJoinMessageId(messageId) {
  const id = String(messageId || '')
  if (!id) return false
  const seen = await loadSeen()
  if (seen.includes(id)) return false
  seen.push(id)
  while (seen.length > BEAM_SEEN_CAP) seen.shift()
  await chrome.storage.local.set({ [BEAM_SEEN_KEY]: seen })
  return true
}

async function loadFailures() {
  const { [BEAM_FAIL_KEY]: cur } = await chrome.storage.local.get(BEAM_FAIL_KEY)
  return cur && typeof cur === 'object' ? cur : {}
}

async function recordProofFailure(deviceId) {
  const map = await loadFailures()
  const id = String(deviceId || 'unknown')
  const now = Date.now()
  const entry = map[id] && now - map[id].windowStart < BEAM_PROOF_FAIL_WINDOW_MS
    ? { count: map[id].count + 1, windowStart: map[id].windowStart }
    : { count: 1, windowStart: now }
  // bounded map: at most 50 tracked ids (FIFO by windowStart)
  const ids = Object.keys(map)
  if (!map[id] && ids.length >= 50) {
    let oldest = ids[0]
    for (const k of ids) if (map[k].windowStart < map[oldest].windowStart) oldest = k
    delete map[oldest]
  }
  map[id] = entry
  await chrome.storage.local.set({ [BEAM_FAIL_KEY]: map })
  return entry
}

export async function proofFailuresFor(deviceId) {
  const map = await loadFailures()
  const e = map[String(deviceId || 'unknown')]
  if (!e) return { count: 0, windowStart: 0 }
  if (Date.now() - e.windowStart >= BEAM_PROOF_FAIL_WINDOW_MS) return { count: 0, windowStart: 0 }
  return e
}

/** True when this device id is currently rate-limited for failed proofs. */
export async function isRateLimited(deviceId) {
  const f = await proofFailuresFor(deviceId)
  return f.count >= BEAM_PROOF_FAIL_LIMIT
}

// --- The joiner's side (S8.4) ---------------------------------------------------

/**
 * Publish the sealed join record to the ORIGIN's mailbox. The joiner already
 * validated the words locally (the wizard did), derived its chain keys, and
 * learned the origin from the presence index (TOFU — listAvailablePeers).
 * The words never leave the joiner's device; the payload carries the device
 * id, the label, the chain-proof, the timestamp and the NON-SECRET cloud
 * hint echo (provider + URL — never credentials, the payload law).
 *
 * @returns the sealed record (also staged manually by the caller on publish
 *   failure, exactly like presence — the manual zero-transport path S8.8).
 */
export async function publishJoinRecord(chainKeys, identity, originPeer, { label = '', cloudHint = null } = {}) {
  if (!originPeer || !originPeer.deviceId || !originPeer.agrPubJwk) {
    throw transferError('peer_invalid', 'The origin device is not learned yet — presence first contact is required')
  }
  const ts = Date.now()
  const proof = await createJoinProof(chainKeys.chainRoot, identity.deviceId, ts)
  const payload = {
    deviceId: identity.deviceId,
    label: String(label || '').slice(0, 60),
    ts,
    proof,
    beam: 1, // protocol version of the join payload
    cloudHint: cloudHint && typeof cloudHint === 'object'
      ? { provider: String(cloudHint.provider || '').slice(0, 24), url: String(cloudHint.url || '').slice(0, 300) }
      : null,
  }
  const sealedKey = await derivePairwiseSignalKey(identity.agrPrivJwk, originPeer.agrPubJwk)
  const cipher = await encryptString(JSON.stringify(payload), sealedKey)
  const rec = {
    v: 1,
    kind: 'join',
    messageId: randomHex32(),
    transferId: '',
    from: identity.deviceId,
    to: String(originPeer.deviceId),
    expiresAt: new Date(Date.now() + BEAM_JOIN_TTL_MS).toISOString(),
    seq: 0,
    nonce: '',
    chainTag: chainKeys.chainTag,
    payload: cipher,
    // FIRST-CONTACT KEYS: the origin has never heard of this device — the
    // public keys ride the SIGNED envelope (tampering them breaks the sig;
    // forging the sig without the chain-proof's key gets the record refused).
    signPubJwk: identity.signPubJwk,
    agrPubJwk: identity.agrPubJwk,
    sig: '',
  }
  rec.sig = await signRecord(identity.signKeys.privateKey, await canonicalRecordBytes(rec))
  return rec
}

/** Put a sealed join record into the origin's mailbox file. */
export async function deliverJoinRecord(chainKeys, identity, originDeviceId, record) {
  const locator = await mailboxLocator(chainKeys, String(originDeviceId))
  await putRecordToMailbox(chainKeys, identity, locator, record)
}

// --- The origin's side (S8.4/S8.5) ----------------------------------------------

/**
 * Open ONE join record envelope. Every gate is typed:
 *   structure → foreign chain → expiry → signature → pairwise open →
 *   chain-proof → replay(consumption is separate) → rate limit.
 * A failed PROOF is rate-limited per device id (typed 'rate_limited' once the
 * budget is spent); a failed signature or decrypt is refused WITHOUT learning
 * the sender (TOFU discipline — the safe direction).
 */
export async function openJoinRecord(chainKeys, identity, rec, { learn = true } = {}) {
  if (!isRecordStructurallyValid(rec)) throw transferError('bad_record', 'Join record failed the E4 schema check')
  if (rec.kind !== 'join') throw transferError('bad_kind', `Not a join record: ${rec.kind}`)
  if (!RECORD_KINDS.includes('join')) throw transferError('bad_kind', 'Join records are not enabled in the record whitelist')
  if (String(rec.chainTag || '') !== String(chainKeys.chainTag)) {
    throw transferError('foreign_chain', 'Join record is from a foreign sync chain')
  }
  const expires = Date.parse(rec.expiresAt || '')
  if (Number.isFinite(expires) && expires <= Date.now()) throw transferError('expired', 'Join record expired before it was opened')
  if (!rec.signPubJwk || !rec.agrPubJwk || String(rec.to) !== String(identity.deviceId)) {
    throw transferError('bad_record', 'Join envelope is not addressed to this origin')
  }
  // 1. envelope signature against the CARRIED signing key
  const sigOk = await verifyRecord(rec.signPubJwk, rec.sig, await canonicalRecordBytes(rec))
  if (!sigOk) throw transferError('bad_signature', 'Join record signature failed against the carried key')

  // Rate limit BEFORE the expensive proof path (the budget counts failures)
  if (await isRateLimited(rec.from)) {
    throw transferError('rate_limited', 'Too many failed join attempts from this device — try again later')
  }

  // 2. pairwise open (origin agr-private × carried joiner agr-public)
  const pairwise = await derivePairwiseSignalKey(identity.agrPrivJwk, rec.agrPubJwk)
  let payload = null
  try {
    payload = JSON.parse(await decryptString(rec.payload, pairwise))
  } catch {
    await recordProofFailure(rec.from)
    throw transferError('decrypt_failed', 'Join payload failed to open under the pairwise key')
  }
  if (!payload || payload.deviceId !== rec.from || typeof payload.proof !== 'string' || !Number.isFinite(payload.ts)) {
    await recordProofFailure(rec.from)
    throw transferError('bad_record', 'Join payload identity mismatch')
  }
  // 3. the chain-proof — verifiable only by chain members
  const proofOk = await verifyJoinProof(chainKeys.chainRoot, rec.from, payload.ts, payload.proof)
  if (!proofOk) {
    const f = await recordProofFailure(rec.from)
    if (f.count >= BEAM_PROOF_FAIL_LIMIT) {
      throw transferError('rate_limited', `Too many failed join attempts from this device — try again after ${Math.ceil(BEAM_PROOF_FAIL_WINDOW_MS / 60000)} minutes`)
    }
    throw transferError('bad_proof', 'Join proof failed — the words were not typed correctly on the joining device')
  }
  // 4. TOFU learn (first contact) — the safe direction: proof passed first
  if (learn) {
    await learnPeer(chainKeys, {
      deviceId: rec.from,
      signPubJwk: rec.signPubJwk,
      agrPubJwk: rec.agrPubJwk,
      label: String(payload.label || '').slice(0, 60),
    })
  }
  return {
    messageId: rec.messageId,
    kind: 'join',
    from: rec.from,
    label: String(payload.label || '').slice(0, 60),
    ts: payload.ts,
    timeIso: new Date(payload.ts).toISOString(),
    expiresAt: rec.expiresAt,
    fingerprint: await deviceFingerprint(rec.signPubJwk),
    cloudHint: payload.cloudHint || null,
  }
}

/**
 * Read the origin's mailbox and return the PENDING join requests (S8.5):
 * typed projections for the dialog, TTL-filtered, deduped by messageId,
 * newest first. Failed records are counted into the rate limiter exactly
 * like direct opens (the poll is the ONLY entry point in production).
 */
export async function listJoinRequests(chainKeys, identity) {
  const records = await readOwnMailbox(chainKeys, identity)
  const out = []
  const refused = []
  for (const rec of records) {
    if (!rec || rec.kind !== 'join') continue
    try {
      out.push(await openJoinRecord(chainKeys, identity, rec))
    } catch (e) {
      const code = (e && (e.transferCode || e.code)) || 'internal'
      refused.push({ messageId: rec.messageId, from: rec.from, code })
    }
  }
  out.sort((a, b) => b.ts - a.ts)
  return { joins: out, refused }
}

/**
 * The ORIGIN'S DECISION (S8.5). Accept → the caller fires the beam transfer
 * (the WebRTC file plane). Decline → the joiner receives a TYPED refusal: a
 * pairwise-sealed 'decline' record in the JOINER's mailbox carrying
 * reason:'join' + the join messageId (the R85 first-class decline kind, reused
 * — no new wire kind for the refusal). Both decisions are ONE-SHOT (replay
 * gate) and only valid while the record is unexpired.
 */
export async function decideJoinRequest(chainKeys, identity, joinProjection, accept, { reason = '' } = {}) {
  if (!joinProjection || !joinProjection.messageId) throw transferError('bad_record', 'No join request to decide')
  const fresh = Date.parse(joinProjection.expiresAt || '') > Date.now()
  if (!fresh) throw transferError('expired', 'The join request expired — the joining device must try again')
  const consumed = await consumeJoinMessageId(joinProjection.messageId)
  if (!consumed) throw transferError('replay', 'This join request was already decided')
  if (!accept) {
    const peer = await resolveJoinerPeer(chainKeys, joinProjection.from)
    if (peer) {
      const sealed = await sealForPeer(chainKeys, identity, peer, 'decline', {
        reason: 'join',
        joinMessageId: joinProjection.messageId,
        note: String(reason || '').slice(0, 120),
      })
      await deliverJoinRecord(chainKeys, identity, joinProjection.from, sealed.record)
    }
  }
  return { ok: true, accepted: !!accept, deviceId: joinProjection.from }
}

async function resolveJoinerPeer(chainKeys, deviceId) {
  const map = await loadPeerMap(chainKeys)
  return map[String(deviceId || '')] || null
}

// --- The joiner's refusal reader (S8.5) ------------------------------------------

/**
 * The JOINER reads its typed refusals (S8.5: "Decline sends the joiner a
 * typed refusal"). Two refusal shapes share the R85 first-class 'decline'
 * wire kind:
 *   reason 'join'      — the origin said no;
 *   reason 'oversized' — the join was legitimate but the envelope exceeds the
 *                        20 MB beam cap: the typed CLOUD FALLBACK copy, with
 *                        the origin's cloud hint (provider + stripped URL).
 * The joiner knows the origin (presence first contact), so the pairwise open
 * works; one-shot consumption rides the SAME seen-ledger (the refusal's own
 * messageId — the UI may re-render, the refusal never re-fires side effects).
 */
export async function listJoinRefusals(chainKeys, identity) {
  const records = await readOwnMailbox(chainKeys, identity)
  const out = []
  for (const rec of records) {
    if (!rec || rec.kind !== 'decline') continue
    try {
      const map = await loadPeerMap(chainKeys)
      const peer = map[rec.from] || null
      if (!peer || !peer.agrPubJwk) continue // unknown refuser — not our origin
      const pairwise = await derivePairwiseSignalKey(identity.agrPrivJwk, peer.agrPubJwk)
      const payload = JSON.parse(await decryptString(rec.payload, pairwise))
      if (!payload || (payload.reason !== 'join' && payload.reason !== 'oversized')) continue
      out.push({
        messageId: rec.messageId,
        reason: String(payload.reason),
        joinMessageId: String(payload.joinMessageId || ''),
        from: rec.from,
        note: String(payload.note || '').slice(0, 120),
        sizeBytes: Number(payload.sizeBytes) || null,
        limitBytes: Number(payload.limitBytes) || null,
        cloudHint: payload.cloudHint && typeof payload.cloudHint === 'object'
          ? { provider: String(payload.cloudHint.provider || ''), url: String(payload.cloudHint.url || '') }
          : null,
        expiresAt: rec.expiresAt,
      })
    } catch { /* per-record gates never abort the poll */ }
  }
  return out
}
