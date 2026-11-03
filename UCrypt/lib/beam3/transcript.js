/**
 * UCrypt — R136 §5.3 — THE MANIFEST-BOUND TRANSCRIPT (the R135-F2 law,
 * extended): the both-screens code now derives from the handshake
 * transcript AND the offer manifest, so an offer cannot be substituted
 * after pairing.
 *
 *   transcriptBytesV3 = len(offerEnv) || offerEnv || len(acceptEnv) ||
 *                       acceptEnv || len(manifest) || manifest
 *
 * (canonical JSON, each segment 4-byte big-endian length-prefixed — the
 * R135 concatenation discipline, one segment grown additions-only.)
 *
 * A MITM who substitutes keys changes segments 1–2; a substituted OFFER
 * changes segments 1 and 3 — BOTH make the codes differ on the two
 * screens, and verifyTranscriptCodeV3 refuses the mismatch typed.
 *
 * PURE — battery-pinned (TRF-TRANSCRIPT-*, the MITM-on-manifest rows).
 */

import { canonicalJsonBytes } from '../beam2/identity.js'

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function seg(out, bytes, offset) {
  const dv = new DataView(out.buffer)
  dv.setUint32(offset, bytes.length)
  out.set(bytes, offset + 4)
  return offset + 4 + bytes.length
}

/**
 * The V3 transcript bytes: offer + accept + manifest, each length-prefixed.
 */
export function transcriptBytesV3(offerEnv, acceptEnv, manifest) {
  if (!offerEnv || typeof offerEnv !== 'object' || !acceptEnv || typeof acceptEnv !== 'object') {
    const e = new Error('transcriptBytesV3 requires both envelopes')
    e.beam3Code = 'bad_transcript'
    throw e
  }
  if (!manifest || typeof manifest !== 'object') {
    const e = new Error('transcriptBytesV3 requires the offer manifest (the offer cannot be substituted after pairing)')
    e.beam3Code = 'bad_transcript'
    throw e
  }
  const o = canonicalJsonBytes(offerEnv)
  const a = canonicalJsonBytes(acceptEnv)
  const m = canonicalJsonBytes(manifest)
  const out = new Uint8Array(12 + o.length + a.length + m.length)
  let off = seg(out, o, 0)
  off = seg(out, a, off)
  seg(out, m, off)
  return out
}

/**
 * The BOTH-SCREENS CODE (4×4 hex) over the V3 transcript. Deterministic —
 * the same handshake + manifest derive the same code on both screens.
 */
export async function handshakeCodeV3({ offerEnv, acceptEnv, manifest }) {
  const digest = await crypto.subtle.digest('SHA-256', transcriptBytesV3(offerEnv, acceptEnv, manifest))
  const h = hex(new Uint8Array(digest).slice(0, 8)).toUpperCase()
  return h.replace(/(.{4})(.{4})(.{4})(.{4})/, '$1 $2 $3 $4')
}

/**
 * The MITM gate, V3: the derived code MUST equal the code the peer
 * rendered — a key substitution OR a manifest substitution is visible and
 * refused (typed terminal, never a silent continue).
 */
export async function verifyTranscriptCodeV3({ offerEnv, acceptEnv, manifest, shownCode }) {
  const derived = await handshakeCodeV3({ offerEnv, acceptEnv, manifest })
  const shown = String(shownCode || '').toUpperCase().replace(/\s+/g, '')
  const mine = derived.toUpperCase().replace(/\s+/g, '')
  if (!shown || shown.length !== mine.length) {
    const e = new Error('The transcript code is missing or malformed')
    e.beam3Code = 'transcript_mismatch'
    throw e
  }
  let diff = 0
  for (let i = 0; i < mine.length; i += 1) diff |= mine.charCodeAt(i) ^ shown.charCodeAt(i)
  if (diff !== 0) {
    const e = new Error(`The transcript code does not match (${derived} vs ${String(shownCode)}) — a key or file substitution is visible on both screens`)
    e.beam3Code = 'transcript_mismatch'
    throw e
  }
  return derived
}
