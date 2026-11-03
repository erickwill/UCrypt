/**
 * UCrypt — R135 §2 — THE TRANSCRIPT-BOUND HANDSHAKE CODE (the R135-F2 fix).
 * New in v2.92.0 (additions-only on the sealed v2.91.0 base).
 *
 * THE FINDING (class-a, fixed before seal): the sealed Beam 2 renders the
 * code from the OFFER payload's `fingerprint` field — a SENDER-ASSERTED
 * value. A man-in-the-middle who substitutes a rogue device key during the
 * mailbox exchange could keep that field self-consistent: the code would
 * match on both screens while the keys do not.
 *
 * THE FIX: the code shown on both screens is DERIVED from the handshake
 * TRANSCRIPT — the canonical bytes of BOTH signed envelopes (the OFFER and
 * the ACCEPT), which cover both device public keys and both nonces. The
 * receiver derives it from offerEnv+acceptEnv before rendering the modal's
 * code; the sender derives it from its offerEnv + the received acceptEnv.
 * A rogue-key substitution changes the transcript ⇒ DIFFERENT codes render
 * on the two screens ⇒ the mismatch is VISIBLE, and verifyTranscriptCode
 * refuses a shown code that does not match (typed terminal, never a silent
 * fallback).
 *
 * Entropy: 16 hex nibbles = 64 bits rendered; the envelope signatures are
 * the first factor, matching by eye the second.
 */

import { canonicalJsonBytes } from './identity.js'

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Canonical TRANSCRIPT bytes for one handshake: the canonical JSON of BOTH
 * envelopes (sig included — a re-signed envelope is a different transcript;
 * the sig is part of what was exchanged), offer first, then accept, each
 * 4-byte big-endian length-prefixed so the concatenation is unambiguous.
 */
export function transcriptBytes(offerEnv, acceptEnv) {
  if (!offerEnv || typeof offerEnv !== 'object' || !acceptEnv || typeof acceptEnv !== 'object') {
    const e = new Error('transcriptBytes requires both envelopes')
    e.beam2Code = 'bad_transcript'
    throw e
  }
  const o = canonicalJsonBytes(offerEnv)
  const a = canonicalJsonBytes(acceptEnv)
  const out = new Uint8Array(8 + o.length + a.length)
  const dv = new DataView(out.buffer)
  dv.setUint32(0, o.length)
  dv.setUint32(4, a.length)
  out.set(o, 8)
  out.set(a, 8 + o.length)
  return out
}

/**
 * The BOTH-SCREENS CODE: "XXXX XXXX XXXX XXXX" (upper-case hex, 4×4) from
 * sha-256 over the transcript bytes. Deterministic — the same handshake
 * derives the same code on both screens.
 */
export async function handshakeCode({ offerEnv, acceptEnv }) {
  const digest = await crypto.subtle.digest('SHA-256', transcriptBytes(offerEnv, acceptEnv))
  const h = hex(new Uint8Array(digest).slice(0, 8)).toUpperCase()
  return h.replace(/(.{4})(.{4})(.{4})(.{4})/, '$1 $2 $3 $4')
}

/**
 * The MITM gate: the derived code MUST equal the code the peer rendered.
 * A mismatch is a typed refusal (beam2Code 'transcript_mismatch') — the
 * session state machine moves to a typed terminal, never a silent continue.
 */
export async function verifyTranscriptCode({ offerEnv, acceptEnv, shownCode }) {
  const derived = await handshakeCode({ offerEnv, acceptEnv })
  const shown = String(shownCode || '').toUpperCase().replace(/\s+/g, '')
  const mine = derived.toUpperCase().replace(/\s+/g, '')
  if (!shown || shown.length !== mine.length) {
    const e = new Error('The transcript code is missing or malformed')
    e.beam2Code = 'transcript_mismatch'
    throw e
  }
  let diff = 0
  for (let i = 0; i < mine.length; i += 1) diff |= mine.charCodeAt(i) ^ shown.charCodeAt(i)
  if (diff !== 0) {
    const e = new Error(`The transcript code does not match (${derived} vs ${String(shownCode)}) — a key substitution or a tampered handshake is visible on both screens`)
    e.beam2Code = 'transcript_mismatch'
    throw e
  }
  return derived
}
