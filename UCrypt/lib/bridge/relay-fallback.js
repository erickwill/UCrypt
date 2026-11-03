/**
 * UCrypt — R142 §5.2-b5 — THE RELAY FALLBACK (the SAME journey, one road over).
 *
 * When the direct road fails its 10-second window, the journey demotes
 * AUTOMATICALLY to the mailbox relay (the R141 MAILBOX family — RETAINED,
 * Road 3). The user learns ONE journey: the same states, the same code
 * compare, the same progress, the same receipt. The badge change is
 * announced in plain words (§5.1 road honesty).
 *
 * PURE — the relay's writes ride the existing MAILBOX_* worker doors; this
 * module carries the parity laws and the announcements. Battery-pinned (G95).
 */

import { BRIDGE_ROADS, roadLabel } from './session.js'

export function relayError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_RELAY_${code}`
  return e
}

/**
 * The demotion announcement: plain words, never jargon. The banned-words
 * lint (§12.1) forbids "mailbox"/"offer"/"envelope"/"road" in USER copy —
 * the announcement speaks of the connection, not the machinery.
 */
export function demotionAnnouncement({ from = BRIDGE_ROADS.DIRECT_LAN, to = BRIDGE_ROADS.RELAY, reason = '' } = {}) {
  const fromL = roadLabel(from) || 'the direct connection'
  const toL = roadLabel(to) || 'your connected cloud'
  const why = reason ? ` (${reason})` : ''
  return `Direct did not open${why} — continuing via ${toL}. The file still arrives; the encryption is unchanged.`
}

/**
 * THE PARITY LAW: every state the direct journey shows, the relay journey
 * shows too — same meaning, same order, same receipt. The battery asserts
 * this mapping; a missing state here is a G95 failure.
 */
export const RELAY_STATE_PARITY = Object.freeze({
  SIGNALING: 'SENDING',     // the connection is being made ≈ the write is in flight
  HANDSHAKE: 'SENDING',     // the code comparison ≈ the same human gate (the relay code compare rides the accept card)
  OPEN: 'SENDING',          // the pipe is ready ≈ the write confirmed in flight
  STREAMING: 'SENDING',     // the chunks are moving
  SEALED: 'DELIVERED',      // the fingerprint checked ≈ the backend confirmed
  DONE: 'VERIFIED',         // the receipt rode back
})

/** Map a bridge state to its relay-parity state (typed; unknown throws). */
export function relayParityState(bridgeState) {
  const s = RELAY_STATE_PARITY[bridgeState]
  if (!s) throw relayError('PARITY', `${bridgeState} has no relay parity — the journeys diverged`)
  return s
}

/**
 * The relay carries the file through the mailbox's OWN typed journey — the
 * relay never invents states, it maps them (the ONE machine law, §5.1).
 */
export function relayJourneyAdapter({ bridgeState, mailboxJourney, now = Date.now() }) {
  if (!mailboxJourney) throw relayError('SHAPE', 'the relay needs the mailbox journey it is carrying')
  return relayParityState(bridgeState)
}

/** The relay's honest wait line (AGE, never a countdown — the mailbox law). */
export function relayWaitingLine({ ageMs, peerName = '' }) {
  if (!(Number.isFinite(ageMs) && ageMs >= 0)) throw relayError('SHAPE', 'the wait line needs the age')
  const mins = Math.floor(ageMs / 60000)
  const age = mins < 1 ? 'less than a minute' : mins === 1 ? '1 minute' : `${mins} minutes`
  const who = peerName ? ` for ${peerName}` : ''
  return `Waiting for the other device to collect it${who} — sent ${age} ago.`
}

/**
 * THE DEMOTION TIMERS: the relay applies no artificial clock to the FILE
 * (the 7-day mailbox TTL is the offer's own honest life); the SIGNALS it
 * carries expire at 120 s (signal.js). This module only declares the
 * constants so the battery pins ONE truth.
 */
export const RELAY_TIMER_LAWS = Object.freeze({
  signalTtlMs: 120 * 1000,
  offerTtlDays: 7,
  pollIntervalMs: 60 * 1000,
})
