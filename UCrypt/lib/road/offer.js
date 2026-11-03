/**
 * UCrypt — R147 §5.2 — THE COMPACT OFFER (lib/road/offer.js — NEW namespace).
 *
 * THE R147 ROAD PURGE: the R142 oversized frame encoder (frameBundleText's
 * "Frame N of 8" machinery, and its "(this frame is too large — use the
 * words token below)" degradation — the CEO's J-3 finding, capture A2/A3/A4)
 * is DEAD. What replaces it is ONE envelope with TWO renderings:
 *
 *   THE COMPACT FORM (the QR)  — v, session id, 16-byte chain fingerprint,
 *       32-byte ephemeral public key, ONE host-candidate hint, the
 *       signature, the clock. Fits ONE QR frame ALWAYS.
 *   THE FULL FORM (the words)  — the SAME envelope + the sealed SDP block
 *       (the minimal data-channel SDP, group-sealed). One copyable blob —
 *       the words have no frame limit.
 *
 * §5.2's size law: the full envelope targets ≤ 1,200 B with a HARD CAP of
 * 1,800 B. There is no "frame too large" state in this namespace — the
 * builder either fits the cap or re-homes the SDP block to the established
 * control road (the contract's own instruction), always loudly (tier).
 *
 * PURE — no chrome.*, no DOM. The seal is injected (the page passes the
 * BRIDGE_SEAL door). Battery: tests/road/r147-offer.test.mjs.
 */

import { signalError } from '../bridge/signal.js'

/** The envelope version (the road's own — v1). */
export const ROAD_OFFER_VERSION = 1

/** §5.2 — the size law. The target is a goal; the cap is the law. */
export const OFFER_TARGET_BYTES = 1200
export const OFFER_HARD_CAP_BYTES = 1800

/** The QR frame budget of the vendored encoder (byte mode, ECC M, v15). */
export const QR_FRAME_BUDGET_BYTES = 440

/** The typed errors (the silence law — a failure here is NEVER a placeholder). */
export function offerError(code, message) {
  const e = new Error(message)
  e.code = `ROAD_OFFER_${code}`
  return e
}

/* ── §5.2 — THE LEGACY-ENVELOPE LAW (R149) ──────────────────────────────────
 * THE WIRE VERSION DISCIPLINE: ROAD_OFFER_VERSION stays (no bump); the NONCE
 * PRESENCE INSIDE THE SEAL is the version marker. The parser reads the
 * version field first (v !== ROAD_OFFER_VERSION → the typed ROAD_OFFER_VERSION
 * error); the SEAL-OPEN layer reads the nonce presence — a sealed payload
 * with sdp/sessionId but NO nonce is an older build's envelope, and it is
 * answered with a TYPED verdict, never a crash and never a placeholder.
 * (The v3.6.0 answer to version aging.) */
export const ROAD_LEGACY_ENVELOPE = 'ROAD_LEGACY_ENVELOPE'

/** The typed legacy-envelope error (the same silence law as offerError). */
export function legacyEnvelopeError(message = 'the sealed handshake carries no session nonce — an older UCrypt built it') {
  const e = new Error(message)
  e.code = ROAD_LEGACY_ENVELOPE
  return e
}

/** THE CONTRACT VERDICT (the exact wording, one source of truth): the
 * LEGACY_OFFER and LEGACY_ANSWER classes both answer with this line. */
export const ROAD_LEGACY_NEXT_STEP = 'These words came from an older UCrypt. Update both devices to the same version and paste again — nothing was lost.'

/** The sealed payload's nonce reader (the tolerant read). The modern seal
 * (R148 K-1a) carries the nonce under `nonce`; the pre-K-1a page code read it
 * under `nonceA`/`nonceB` — the tolerant order keeps those hypothetical
 * intermediate seals derivable. An EMPTY result is the §5.2 legacy marker:
 * the caller answers typed (LEGACY_OFFER / LEGACY_ANSWER), never silent. */
export function sealedNonceOf(payload) {
  if (!payload || typeof payload !== 'object') return ''
  for (const k of ['nonce', 'nonceA', 'nonceB']) {
    const v = payload[k]
    if (typeof v === 'string' && v) return v
  }
  return ''
}

/* ── the minimal SDP (the J-3 cure's first half) ──────────────────────────── */

const SDP_KEEP_PREFIX = [
  'v=', 'o=', 's=', 't=', 'a=group:', 'a=msid-semantic:',
  'm=application', 'c=', 'a=ice-ufrag:', 'a=ice-pwd:', 'a=ice-options:',
  'a=fingerprint:', 'a=setup:', 'a=mid:', 'a=sctp-port:', 'a=max-message-size:',
]

/**
 * THE MINIMAL DATA-CHANNEL SDP: keep the structural + security lines and the
 * BEST host candidate; drop every other candidate line (the mDNS storms are
 * the old bundle's bulk). Deterministic: the same input always yields the
 * same bytes (the battery pins it). Returns { sdp, hostHint } — hostHint is
 * "ip:port" from the kept candidate ('' when only obfuscated routes exist).
 */
export function minimalDataChannelSdp(sdp) {
  const raw = String(sdp || '')
  if (!raw.includes('m=application')) throw offerError('SDP_SHAPE', 'the offer SDP carries no data-channel m-line')
  const lines = raw.split(/\r?\n/).filter((l) => l.length > 0)
  const keep = []
  let numericHost = null
  let anyHost = null
  let srflxCandidate = null
  for (const line of lines) {
    if (line.startsWith('a=candidate:')) {
      const isHost = /\btyp\s+host\b/.test(line)
      const isSrflx = /\btyp\s+srflx\b/.test(line)
      if (isHost) {
        // a numeric-IP host beats an mDNS .local host (the .local name only
        // resolves on the owner's own machine — the ROAD hint wants a route)
        if (!anyHost) anyHost = line
        const ip = line.split(/\s+/)[4] || ''
        if (!numericHost && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) numericHost = line
      } else if (isSrflx && !srflxCandidate) srflxCandidate = line
      continue
    }
    if (SDP_KEEP_PREFIX.some((p) => line.startsWith(p))) keep.push(line)
  }
  const candidate = numericHost || anyHost || srflxCandidate
  if (candidate) keep.push(candidate)
  let hostHint = ''
  const chosen = numericHost || anyHost
  if (chosen) {
    // a=candidate:1 1 udp 2122260223 192.168.1.10 54321 typ host → ip:port
    const parts = chosen.split(/\s+/)
    if (parts.length >= 6) hostHint = `${parts[4]}:${parts[5]}`
  }
  return { sdp: keep.join('\r\n') + '\r\n', hostHint }
}

/* ── the ephemeral key + signature (§5.2's named fields) ─────────────────── */

/** 32-byte ephemeral keypair for the road's handshake (ECDSA P-256 — the
 * signature proves the envelope's integrity alongside the group seal). */
export async function newRoadKeypair() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return { privateKey: pair.privateKey, publicKeyRaw: rawPub }
}

/** Sign the envelope's canonical byte string (every field but z). */
export async function signEnvelope(privateKey, envelope) {
  const data = canonicalEnvelopeBytes(envelope)
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
  return new Uint8Array(sig)
}

export async function verifyEnvelopeSignature(publicKeyB64url, envelope) {
  try {
    const rawPub = b64urlDecode(publicKeyB64url)
    const key = await crypto.subtle.importKey('raw', rawPub, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
    const data = canonicalEnvelopeBytes({ ...envelope, z: null })
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, new Uint8Array(b64urlDecode(envelope.z)), data)
  } catch {
    return false
  }
}

function canonicalEnvelopeBytes(env) {
  // the canonical signing order — z (the signature) never signs itself
  const parts = [env.v, env.s, env.f || '', env.k, env.h || '', env.d || '', env.at || 0, env.exp || 0]
  return new TextEncoder().encode(JSON.stringify(parts))
}

/* ── base64url helpers (compact — no padding, URL-safe) ──────────────────── */

export function b64urlEncode(bytes) {
  let bin = ''
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  for (let i = 0; i < u8.length; i += 32768) bin += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + 32768, u8.length)))
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(text) {
  const t = String(text || '').replace(/-/g, '+').replace(/_/g, '/')
  const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : ''
  const bin = atob(t + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function byteLengthOf(s) {
  return new TextEncoder().encode(s).length
}

/* ── the builder ─────────────────────────────────────────────────────────── */

/**
 * Build the compact offer envelope. Args:
 *   sessionId  — the session's wire id (the s field rides as-is)
 *   chainFpHex — the 16-byte chain fingerprint, hex (32 chars), or ''
 *   sdp        — the raw offer SDP (the builder minimizes + seals it)
 *   sealFn     — async (payloadObject) => { ok, sealedB64 } (the BRIDGE_SEAL door)
 *   ttlMs      — the envelope's life (default 10 min — the bundle TTL law)
 *
 * Returns { envelope, compact, full, words, bytes, compactBytes, tier, hostHint }:
 *   envelope — the full JS object (the wire truth)
 *   compact  — the QR form: the envelope WITHOUT d (ONE frame, always)
 *   full     — the full JSON text (what the words encode)
 *   words    — the house base32 form of the FULL envelope (the words token)
 *   bytes    — the full envelope's byte size (the §5.2 measure)
 *   tier     — 'target' (≤1,200) | 'cap' (≤1,800) | 'no-sdp' (re-homed)
 *
 * R148 §4 (the K-1a cure): the SEALED PAYLOAD now carries the sender's/receiver's
 * session nonce ({ sdp, sessionId, role, nonce }) — the 6-digit safety code is
 * derived from BOTH nonces on BOTH screens (safety-code.js refuses to derive
 * from a missing one), so the nonce MUST cross inside the seal. The offer seals
 * role:'sender' + the sender's nonceA; the answer seals role:'receiver' + the
 * receiver's nonceB. An older build's envelope (no nonce in the payload) opens
 * fine — the door then names the honest typed guidance instead of a dead code.
 */
export async function buildCompactOffer({ sessionId, chainFpHex = '', sdp, sealFn, role = 'sender', nonce = '', ttlMs = 10 * 60 * 1000, now = Date.now() } = {}) {
  if (!sessionId || typeof sessionId !== 'string') throw offerError('SHAPE', 'the offer needs a sessionId')
  if (!sdp) throw offerError('SHAPE', 'the offer needs the offer SDP')
  if (typeof sealFn !== 'function') throw offerError('SHAPE', 'the offer needs the seal door')
  if (role !== 'sender' && role !== 'receiver') throw offerError('SHAPE', `the seal role is '${String(role)}' — only sender|receiver exist`)
  if (!nonce || typeof nonce !== 'string') throw offerError('SHAPE', 'the seal payload needs the session nonce (the safety code derives from it)')
  const min = minimalDataChannelSdp(sdp)
  const keypair = await newRoadKeypair()

  const buildWith = async (sdpText, hostHintOverride) => {
    let sealedB64 = ''
    if (sdpText) {
      // R148 §4 — the nonce rides INSIDE the seal (the K-1a cure): both
      // screens derive the SAME safety code from chainRoot + nonceA + nonceB.
      const r = await sealFn({ sdp: sdpText, sessionId, role, nonce })
      if (!r || !r.ok) throw offerError('SEAL', (r && r.userMessage) || 'the seal door refused the offer')
      sealedB64 = r.sealedB64
    }
    const env = {
      v: ROAD_OFFER_VERSION,
      s: String(sessionId),
      f: chainFpHex ? b64urlEncode(hexToBytes(chainFpHex)) : '',
      k: b64urlEncode(keypair.publicKeyRaw),
      h: hostHintOverride !== undefined ? hostHintOverride : (min.hostHint || ''),
      d: sealedB64,
      at: now,
      exp: now + ttlMs,
      z: null,
    }
    env.z = b64urlEncode(await signEnvelope(keypair.privateKey, env))
    return env
  }

  let envelope = await buildWith(min.sdp)
  let bytes = byteLengthOf(JSON.stringify(envelope))
  let tier = bytes <= OFFER_TARGET_BYTES ? 'target' : 'cap'
  if (bytes > OFFER_HARD_CAP_BYTES) {
    // re-home attempt 1: drop the host hint (the SDP's kept candidate still
    // carries the route — the hint is an optimization, not a requirement)
    envelope = await buildWith(min.sdp, '')
    bytes = byteLengthOf(JSON.stringify(envelope))
  }
  if (bytes > OFFER_HARD_CAP_BYTES) {
    // re-home attempt 2 (the last resort §5.2 names): the SDP block leaves
    // the envelope entirely — it will ride the established control road.
    envelope = await buildWith(null)
    bytes = byteLengthOf(JSON.stringify(envelope))
    tier = 'no-sdp'
  }

  const compact = compactOf(envelope)
  const compactBytes = byteLengthOf(JSON.stringify(compact))
  if (compactBytes > QR_FRAME_BUDGET_BYTES) throw offerError('OVERSIZED', `the compact offer exceeds one QR frame (${compactBytes} B > ${QR_FRAME_BUDGET_BYTES} B)`)
  return { envelope, compact, full: JSON.stringify(envelope), words: envelopeToWordsToken(envelope), bytes, compactBytes, tier, hostHint: envelope.h, keypair }
}

/** The QR form — the envelope without the SDP block. */
export function compactOf(envelope) {
  const { d, ...rest } = envelope
  return rest
}

/** The compact form's JSON text (what the QR renders). */
export function compactText(envelope) {
  return JSON.stringify(compactOf(envelope))
}

/** Parse + verify EITHER form's shape. Returns { envelope, complete } —
 * complete=true when the SDP block rides inside (the words form, normally). */
export function parseOfferEnvelope(text, { now = Date.now() } = {}) {
  let raw
  try { raw = JSON.parse(String(text || '')) } catch { throw offerError('SHAPE', 'the offer envelope is not readable') }
  if (!raw || raw.v !== ROAD_OFFER_VERSION) throw offerError('VERSION', 'the offer envelope version is unknown')
  if (typeof raw.s !== 'string' || !raw.s) throw offerError('SHAPE', 'the offer sessionId is malformed')
  if (typeof raw.k !== 'string' || !raw.k) throw offerError('SHAPE', 'the offer key is malformed')
  if (!Number.isFinite(raw.at) || !Number.isFinite(raw.exp)) throw offerError('TTL', 'the offer clock is malformed')
  if (now > raw.exp) throw offerError('EXPIRED', 'the offer expired (10 minutes) — ask the sender to show it again')
  if (!raw.z) throw offerError('SIGNATURE', 'the offer carries no signature')
  if (typeof raw.d !== 'string') raw.d = ''
  return { envelope: raw, complete: !!raw.d }
}

/** The words token: the house base32 form (the SAME envelope — §5.2). */
export function envelopeToWordsToken(envelope) {
  const bytes = new TextEncoder().encode(JSON.stringify(envelope))
  if (!bytes.length) throw offerError('SHAPE', 'nothing to encode')
  let bits = 0, value = 0, out = ''
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return (out.match(/.{1,4}/g) || []).join('-')
}

export function wordsTokenToEnvelope(token) {
  const clean = String(token || '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  if (!clean) throw offerError('SHAPE', 'the words token is empty')
  let bits = 0, value = 0
  const bytes = []
  for (const c of clean) {
    const idx = B32.indexOf(c)
    if (idx < 0) throw offerError('SHAPE', 'the words token carries a foreign character')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  let raw
  try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))) } catch { throw offerError('SHAPE', 'the words token does not decode to an offer') }
  return parseOfferEnvelope(JSON.stringify(raw))
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function hexToBytes(hex) {
  const clean = String(hex || '').replace(/[^0-9a-f]/gi, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

export { signalError }
