/**
 * UCrypt — R134 §2/§3 — THE BEAM 2 PROTOCOL CORE: capability negotiation,
 * mixed-version compatibility, and the deterministic race resolutions.
 *
 * §3 MIGRATION & COMPATIBILITY (anti-trimming, deployment honesty): a chain
 * may hold mixed versions — one machine on v2.91, another still on v2.90.
 * HELLO/CAPS carries the protocol version; on detecting a LEGACY peer, Beam
 * 2 degrades to the legacy bridge — the v2.90 transfer path, moved intact
 * to lib/transfer/legacy-bridge.js, maintained, not deleted. Old serialized
 * sessions remain readable (law 0.36 input preservation).
 *
 * PURE — battery-pinned (BEAM2-PROTOCOL-*, BEAM2-COMPAT-*).
 */

import { LANES, CHUNK_SIZE } from './lanes.js'

/** The Beam 2 protocol version marker carried in every HELLO/CAPS. */
export const BEAM2_PROTOCOL_VERSION = 2

/**
 * Negotiate caps between two devices. Returns the typed decision:
 *   protocol 'beam2'  — the Beam 2 path (lane per selectLane)
 *   protocol 'legacy' — the peer predates Beam 2 → the legacy bridge owns
 *                       the transfer (lib/transfer/legacy-bridge.js)
 * @param {{beam2?:boolean, webrtc?:boolean, rendezvous?:boolean, maxChunk?:number, protocolVersion?:string}} mine
 * @param {object|null} theirs null/absent caps = a legacy peer (no HELLO seen)
 */
export function negotiateCaps(mine, theirs) {
  const m = mine || {}
  const t = theirs || {}
  if (!t.beam2) {
    return { protocol: 'legacy', lane: LANES.C, bridge: 'lib/transfer/legacy-bridge.js', reason: 'peer-has-no-beam2' }
  }
  const bothWebRtc = !!(m.webrtc && t.webrtc)
  const lane = bothWebRtc ? LANES.W : LANES.C
  const maxChunk = Math.min(Number(m.maxChunk) || CHUNK_SIZE, Number(t.maxChunk) || CHUNK_SIZE)
  return {
    protocol: 'beam2',
    lane,
    degraded: false, // negotiation-time selection is never a degradation — ICE-failure degradation is typed via lanes.degradeToRelay
    maxChunk: Math.max(1024, maxChunk),
    bridge: null,
    reason: bothWebRtc ? 'direct' : 'relay',
  }
}

/**
 * CONCURRENT BIDIRECTIONAL OFFERS (the pinned EDGE): both devices send
 * simultaneously — deterministic resolution by device-ID ordering, BOTH
 * sessions survive. The lexicographically smaller device id is the "sender
 * of record" for the shared session name-space; each offer keeps its own
 * session id, so both transfer sessions proceed independently, deterministically
 * ordered in the UI.
 * @returns {{order:[string,string], survivorA:boolean, survivorB:boolean, primarySessionId:string}}
 */
export function resolveConcurrentOffers(offerA, offerB) {
  const idA = String(offerA && offerA.from)
  const idB = String(offerB && offerB.from)
  if (!idA || !idB) throw new Error('BEAM2_PROTOCOL_RACE: both offers must carry their sender ids')
  const [first, second] = idA <= idB ? [idA, idB] : [idB, idA]
  return {
    order: [first, second],
    survivorA: true,
    survivorB: true,
    primarySessionId: idA <= idB ? String(offerA.sessionId) : String(offerB.sessionId),
  }
}

/**
 * DOUBLE-ACCEPT RACE (the pinned EDGE): two ACCEPT envelopes for one offer
 * — the first is delivered, the duplicate is flagged idempotent (never a
 * second transfer spawn).
 */
export function resolveDoubleAccept(firstAt, secondAt) {
  if (!Number.isFinite(firstAt)) return { deliver: true, duplicate: false }
  if (!Number.isFinite(secondAt)) return { deliver: false, duplicate: false }
  return secondAt >= firstAt
    ? { deliver: false, duplicate: true }
    : { deliver: true, duplicate: false }
}

/**
 * REPLAYED COMPLETE (the pinned EDGE): idempotent — a COMPLETE that arrives
 * twice verifies once and the re-send is a no-op typed row, never an error.
 */
export function resolveReplayedComplete(seenCompleteIds, completeId) {
  const seen = seenCompleteIds instanceof Set ? seenCompleteIds : new Set(seenCompleteIds || [])
  if (seen.has(completeId)) return { deliver: false, idempotent: true }
  seen.add(completeId)
  return { deliver: true, idempotent: false }
}

/**
 * LATE-DECLINE-AFTER-ACCEPT (the pinned EDGE): DECLINE after ACCEPT is
 * honored at every PRE-TRANSFERRING state (law §2.G); once TRANSFERRING, a
 * DECLINE maps to CANCEL propagation (typed rows both directions) — never a
 * silent swallow. The state machine owns the verdict; this helper names the
 * typed outcome for the UI row.
 */
export function lateDeclineOutcome(state) {
  switch (state) {
    case 'OFFERED':
    case 'ACCEPTED':
      return { honored: true, terminal: 'DECLINED', row: 'beam2DeclineHonored' }
    case 'TRANSFERRING':
    case 'VERIFYING':
      return { honored: true, terminal: 'CANCELED', row: 'beam2CancelPropagated' }
    default:
      return { honored: false, terminal: null, row: 'beam2DeclineLate' }
  }
}

/**
 * CANCEL PROPAGATION (the pinned EDGE): a CANCEL at any pre-terminal state
 * produces typed rows on BOTH sides; this returns the propagation plan.
 */
export function cancelPropagation(state) {
  if (['IDLE', 'OFFERED', 'ACCEPTED', 'TRANSFERRING', 'VERIFYING'].includes(state)) {
    return { propagate: true, terminal: 'CANCELED', bothSides: true }
  }
  return { propagate: false, terminal: state, bothSides: false }
}

/**
 * CLOCK-SKEW TTL (the pinned EDGE): an envelope whose ts lies in the future
 * is judged by ITS OWN expiresAt, never by the local send time — a skewed
 * sender cannot extend its own session beyond the TTL envelope it declared.
 */
export function skewSafeExpiry(envTs, ttlMs, now) {
  const ts = Number(envTs) || 0
  const declared = ts + Number(ttlMs)
  return { expiresAt: declared, expired: declared <= now }
}

/**
 * OLD SERIALIZED SESSIONS REMAIN READABLE (law 0.36): a legacy session
 * record (the v2.90 shape: { transferId, stage, offer, answer, ... }) is
 * recognized and mapped to its typed reader verdict — never a crash, never
 * a silent drop.
 */
export function readLegacySessionRecord(rec) {
  if (!rec || typeof rec !== 'object') return { readable: false, reason: 'not-an-object' }
  if (rec.v === 2 && rec.sessionId) return { readable: true, kind: 'beam2' }
  if (rec.transferId && typeof rec.transferId === 'string') {
    return { readable: true, kind: 'legacy', transferId: rec.transferId, stage: String(rec.stage || '') }
  }
  return { readable: false, reason: 'unknown-shape' }
}
