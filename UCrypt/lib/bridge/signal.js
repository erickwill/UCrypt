/**
 * UCrypt — R142 §5.2-b2 — THE BRIDGE SIGNALING (dual, cloud-free parity).
 *
 * (a) CLOUD-UP: signaling rides the mailbox as typed BRIDGE envelopes —
 *     bridge-offer / bridge-answer / bridge-ice (TTL 120 s, one index row per
 *     session, swept on close or expiry).
 * (b) CLOUD-FREE (the owner's F-1 law): the SAME typed offer bundle rides a
 *     QR CODE (multi-frame — the encoder is the vendored spec-compliant
 *     lib/qr.js), imported on the other side by CAMERA or by IMAGE UPLOAD,
 *     and a copy/paste WORDS-TOKEN carries the identical bundle as the third
 *     path. The bundle is sealed with the chain group seal, is SINGLE-USE,
 *     and expires in 10 minutes — a leaked screenshot is worthless.
 *
 * PURE — the framing/validation lives here; the sealing and the QR pixels
 * live in the page module. Battery-pinned (G95).
 */

export const BRIDGE_SIGNAL_KINDS = Object.freeze([
  'bridge-offer', 'bridge-answer', 'bridge-ice',
  // R147 §5 — the road's control plane (the ancestor's frozen kinds, ported
  // verbatim by R156; the kinds ride the SAME lane, the SAME TTL, the SAME
  // single-use sweep):
  'bridge-confirm',   // the receiver's code-ok / code-mismatch (J-1's carrier)
  'bridge-sdp',       // the re-homed SDP block (the compact offer's §5.2 law)
  'bridge-chunk',     // the relay road's data plane (64 KiB chunks)
  'bridge-ack',       // the chunk / receipt acks (cumulative watermark)
  'bridge-receipt',   // the completion envelope (final sha256)
])
export const BRIDGE_SIGNAL_TTL_MS = 120 * 1000        // the relay signal's life
export const BRIDGE_BUNDLE_TTL_MS = 10 * 60 * 1000    // the QR/words bundle's life
export const BRIDGE_BUNDLE_VERSION = 1

export function signalError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_SIGNAL_${code}`
  return e
}

/** Build one relay signal envelope (the mailbox carries it as type BRIDGE). */
export function buildSignalEnvelope({ kind, sessionId, payload, now = Date.now(), ttlMs = BRIDGE_SIGNAL_TTL_MS, singleUse = true }) {
  if (!BRIDGE_SIGNAL_KINDS.includes(kind)) throw signalError('KIND', `unknown signal kind ${String(kind)}`)
  if (!sessionId || typeof sessionId !== 'string') throw signalError('SHAPE', 'a signal needs a sessionId')
  if (!payload || typeof payload !== 'object') throw signalError('SHAPE', 'a signal needs a payload object')
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw signalError('TTL', 'the ttl must be positive')
  return {
    v: BRIDGE_BUNDLE_VERSION,
    type: 'BRIDGE',
    kind,
    sessionId: String(sessionId),
    payload,
    issuedAt: now,
    expiresAt: now + ttlMs,
    singleUse,
    consumedAt: null,
  }
}

/** Validate one relay signal: the shape, the kind, the clock. */
export function validateSignalEnvelope(raw, { now = Date.now() } = {}) {
  if (!raw || typeof raw !== 'object') throw signalError('SHAPE', 'the signal is malformed')
  if (raw.type !== 'BRIDGE') throw signalError('TYPE', 'this door carries BRIDGE envelopes only')
  if (!BRIDGE_SIGNAL_KINDS.includes(raw.kind)) throw signalError('KIND', `unknown signal kind ${String(raw.kind)}`)
  if (typeof raw.sessionId !== 'string' || !raw.sessionId) throw signalError('SHAPE', 'the sessionId is malformed')
  if (!Number.isFinite(raw.issuedAt) || !Number.isFinite(raw.expiresAt)) throw signalError('TTL', 'the clock fields are malformed')
  if (now > raw.expiresAt) throw signalError('EXPIRED', 'the signal expired — the session moved on')
  if (raw.consumedAt != null) throw signalError('CONSUMED', 'the signal was already consumed (single-use)')
  if (!raw.payload || typeof raw.payload !== 'object') throw signalError('SHAPE', 'the payload is malformed')
  return true
}

/** Mark consumed (the sweep and the single-use law). */
export function consumeSignalEnvelope(env, now = Date.now()) {
  validateSignalEnvelope(env, { now })
  return { ...env, consumedAt: now }
}

/** Should the index row be swept? (close or expiry — §5.2-b2(a)) */
export function signalRowExpired(env, now = Date.now()) {
  return !!env && Number.isFinite(env.expiresAt) && now > env.expiresAt
}

/* ── The cloud-free bundle (QR / words / paste — one format, three doors) ── */

/**
 * The bundle the QR carries. `sealedPayload` is the chain-sealed string the
 * page produces (ciphertext of the SDP bundle under the chain group seal) —
 * this module frames and parses, it never sees keys.
 */
export function buildOfferBundleText({ role, sessionId, sealedPayload, now = Date.now(), ttlMs = BRIDGE_BUNDLE_TTL_MS }) {
  if (role !== 'sender' && role !== 'receiver') throw signalError('SHAPE', 'the bundle role is sender or receiver')
  if (!sessionId || typeof sessionId !== 'string') throw signalError('SHAPE', 'the bundle needs a sessionId')
  if (typeof sealedPayload !== 'string' || sealedPayload.length < 8) throw signalError('SHAPE', 'the sealed payload is malformed')
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw signalError('TTL', 'the bundle ttl must be positive')
  return JSON.stringify({ v: BRIDGE_BUNDLE_VERSION, t: 'ucrypt-bridge', role, sessionId, p: sealedPayload, issuedAt: now, expiresAt: now + ttlMs })
}

export function parseOfferBundleText(text, { now = Date.now() } = {}) {
  let raw
  try { raw = JSON.parse(String(text || '')) } catch { throw signalError('SHAPE', 'the bundle is not readable') }
  if (!raw || raw.t !== 'ucrypt-bridge') throw signalError('TYPE', 'this is not a UCrypt transfer bundle')
  if (raw.v !== BRIDGE_BUNDLE_VERSION) throw signalError('VERSION', 'the bundle version is unknown')
  if (raw.role !== 'sender' && raw.role !== 'receiver') throw signalError('SHAPE', 'the bundle role is malformed')
  if (typeof raw.sessionId !== 'string' || !raw.sessionId) throw signalError('SHAPE', 'the bundle sessionId is malformed')
  if (typeof raw.p !== 'string' || raw.p.length < 8) throw signalError('SHAPE', 'the bundle payload is malformed')
  if (!Number.isFinite(raw.expiresAt)) throw signalError('TTL', 'the bundle clock is malformed')
  if (now > raw.expiresAt) throw signalError('EXPIRED', 'the bundle expired (10 minutes) — generate a fresh one')
  return raw
}

/**
 * THE MULTI-FRAME QR FRAMING: the encoder carries ~450 bytes per frame
 * (versions ≤15, ECC M); the SDP bundle rides 1–N frames "i|n|chunk".
 * Frames are self-describing so ANY missing frame names itself.
 */
export function frameBundleText(text, { perFrame = 440 } = {}) {
  const t = String(text || '')
  if (!t) throw signalError('SHAPE', 'nothing to frame')
  if (!Number.isInteger(perFrame) || perFrame < 64) throw signalError('SHAPE', 'the frame size is malformed')
  const chunks = []
  for (let i = 0; i < t.length; i += perFrame) chunks.push(t.slice(i, i + perFrame))
  const n = chunks.length
  if (n > 99) throw signalError('MANY', 'the bundle needs too many frames — trim the SDP')
  return chunks.map((c, i) => `${i + 1}|${n}|${c}`)
}

export function parseBundleFrames(frames) {
  const arr = (Array.isArray(frames) ? frames : []).map((f) => String(f || '')).filter(Boolean)
  if (!arr.length) throw signalError('SHAPE', 'no frames to read')
  const parts = arr.map((f) => {
    const m = f.match(/^(\d{1,2})\|(\d{1,2})\|([\s\S]+)$/)
    if (!m) throw signalError('SHAPE', 'a frame is malformed')
    return { i: Number(m[1]), n: Number(m[2]), chunk: m[3] }
  })
  const n = parts[0].n
  if (!Number.isInteger(n) || n < 1 || parts.some((p) => p.n !== n)) throw signalError('SHAPE', 'the frame count disagrees')
  const byI = new Map()
  for (const p of parts) {
    if (p.i < 1 || p.i > n) throw signalError('SHAPE', 'a frame index is out of range')
    if (byI.has(p.i)) throw signalError('DUPLICATE', `frame ${p.i} appeared twice`)
    byI.set(p.i, p.chunk)
  }
  const missing = []
  for (let i = 1; i <= n; i++) if (!byI.has(i)) missing.push(i)
  if (missing.length) throw signalError('INCOMPLETE', `missing frames: ${missing.join(', ')}`)
  return Array.from({ length: n }, (_, k) => byI.get(k + 1)).join('')
}

/* ── R154 §5 (A.2) — THE BOND TEXT (the device-pairing invitation) ───────
   The invitation wraps the bond stamp (itself sealed under the chain group
   key) in a typed, TTL'd envelope. Pure — the sealing lives worker-side;
   this module frames, parses and expires. Battery-pinned (G-bond). */
export const BOND_BUNDLE_TTL_MS = 10 * 60 * 1000

export function buildBondText({ sealedPayload, now = Date.now(), ttlMs = BOND_BUNDLE_TTL_MS }) {
  if (typeof sealedPayload !== 'string' || sealedPayload.length < 8) throw signalError('SHAPE', 'the bond stamp is malformed')
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw signalError('TTL', 'the bond ttl must be positive')
  return JSON.stringify({ ucrypt: 1, kind: 'bond', p: sealedPayload, issuedAt: now, exp: now + ttlMs })
}

export function parseBondText(text, { now = Date.now() } = {}) {
  let raw
  try { raw = JSON.parse(String(text || '')) } catch { throw signalError('SHAPE', 'the bond is not readable') }
  if (!raw || raw.kind !== 'bond' || raw.ucrypt !== 1) throw signalError('TYPE', 'this is not a UCrypt pairing invitation')
  if (typeof raw.p !== 'string' || raw.p.length < 8) throw signalError('SHAPE', 'the bond stamp is malformed')
  if (!Number.isFinite(raw.exp)) throw signalError('TTL', 'the bond clock is malformed')
  if (now > raw.exp) throw signalError('EXPIRED', 'the bond invitation expired (10 minutes) — ask for a fresh one')
  return { sealed: raw.p }
}

/**
 * THE WORDS TOKEN: the same bundle as pronounceable base32 groups
 * ("UCRY-PTBR-IDG-E4TQ-…") — the camera-less, screenless fallback that is
 * still cloud-free. Pure base32 (RFC 4648, no padding), grouped by 4.
 */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function bundleToWordsToken(text) {
  const bytes = new TextEncoder().encode(String(text || ''))
  if (!bytes.length) throw signalError('SHAPE', 'nothing to encode')
  let bits = 0, value = 0, out = ''
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return (out.match(/.{1,4}/g) || []).join('-')
}

export function wordsTokenToBundle(token) {
  const clean = String(token || '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  if (!clean) throw signalError('SHAPE', 'the words token is empty')
  let bits = 0, value = 0
  const bytes = []
  for (const c of clean) {
    const idx = B32.indexOf(c)
    if (idx < 0) throw signalError('SHAPE', 'the words token carries a foreign character')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
  } catch {
    throw signalError('SHAPE', 'the words token does not decode to a bundle')
  }
}
