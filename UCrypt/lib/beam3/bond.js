/**
 * UCrypt — R139 §5 — THE BOND ("two deliberate acts, then a machine that
 * simply works, visibly, in seconds").
 *
 * ONE finite state machine per transfer session (§5.1's exact vocabulary):
 *
 *   IDLE → ARMED → WAITING_FOR_PEER → SIGNAL_EXCHANGED → CODE_SHOWN
 *        → CONNECTED → TRANSFERRING → VERIFIED → DONE
 *
 * and the typed terminals:
 *
 *   PEER_TIMEOUT (budget×2 while waiting for the peer),
 *   RELAY_UNAVAILABLE (with the failing hop),
 *   REPLAY_NOOP (friendly, NON-terminal — a re-opened signal re-renders
 *   the current truth; it never refuses, never punishes — D7),
 *   CONSENT_DECLINED (the receiver said no — nothing was received),
 *   CANCELLED (the user's own cancel).
 *
 * THE LAWS THIS MODULE MAKES UNREPRESENTABLE:
 * §5.1 One machine, one writer — EVERY rendered element of the transfer
 *        surface (readiness rows, glyphs, prose, buttons, the step rail,
 *        the roster, availability, fallback visibility) is a pure function
 *        of THIS machine through projectBond(). Independent presentation
 *        writers are deleted, not disciplined (the D10 class is extinct by
 *        architecture: glyph and text derive from the same fact in the same
 *        expression, and a row whose text says connected can never carry a
 *        failure glyph).
 *   §5.2 Three doors, one bond — the word code, the QR scan, and the QR
 *        image upload converge to the identical pairing payload and hence
 *        to the same machine; the 4×4 code remains the human check.
 *   §5.3 The durable waiting law — ARMED and WAITING_FOR_PEER are durable:
 *        a device that armed, or opened its peer's signal, HOLDS the bond
 *        open until the peer completes, the transport confirms, or the user
 *        cancels. No expiry fires from a waiting state. Re-entry is free:
 *        re-pasting the same signal (payload-hash keyed) is the friendly
 *        no-op REPLAY_NOOP that re-renders the truth (D7). Waiting is a
 *        first-class success path — it is what the word "available" means.
 *   §5.4 The gated connect — 'Codes match — connect' renders DISABLED with
 *        a live reason line whenever its prerequisites are unmet, and when
 *        enabled every click lands CONNECTED or a typed failure within
 *        budget. User confirmation and transport confirmation are
 *        independent paths to CONNECTED — the first wins, the other
 *        confirms. A dead click is unrepresentable (D9).
 *   §5.5 Latency honesty — honest clocks are machine law: the slow-path
 *        notice fires at budget/2 and names the measured slow hop; at
 *        budget×2 the machine emits a typed terminal (PEER_TIMEOUT or
 *        RELAY_UNAVAILABLE) with its one-tap fix; if the transport can
 *        still complete asynchronously the terminal carries the explicit
 *        persistent-pending state and the completion notification. An
 *        unbounded silent search is unrepresentable; the string "the
 *        connection still completes" is retired everywhere (D12).
 *   §5.6 One availability surface, default-armed — availability
 *        consolidates to ONE card with ONE truth: default-ARMED when the
 *        chain joins, shown explicitly as On/True with the minutes
 *        remaining and Stop; the duplicate Receive-side cluster is removed
 *        into that one surface; the strip can never contradict the card
 *        because both are the same projection (D10, D11).
 *   §5.7 Layout order — the page order is a constant of THIS module
 *        (readiness → intent actions → guide → manual fallback →
 *        diagnostics drawer) and the one grammar (pair, confirm, transfer,
 *        verify) names its steps identically across surfaces (D4).
 *
 * PURE — no DOM, no chrome.*, no timers at import time. Battery-pinned
 * (G88 BOND MACHINE — every state × every event; surface coherence per
 * state; fake-clock budget rows; replay idempotency on payload-hash keys).
 */

import { BEAM3_SIGNAL_TTL_MS } from './planes.js'

/** The Bond states (§5.1's exact vocabulary). */
export const BOND_STATES = {
  IDLE: 'IDLE',
  ARMED: 'ARMED',
  WAITING_FOR_PEER: 'WAITING_FOR_PEER',
  SIGNAL_EXCHANGED: 'SIGNAL_EXCHANGED',
  CODE_SHOWN: 'CODE_SHOWN',
  CONNECTED: 'CONNECTED',
  TRANSFERRING: 'TRANSFERRING',
  VERIFIED: 'VERIFIED',
  DONE: 'DONE',
  // the typed terminals
  PEER_TIMEOUT: 'PEER_TIMEOUT',
  RELAY_UNAVAILABLE: 'RELAY_UNAVAILABLE',
  REPLAY_NOOP: 'REPLAY_NOOP',
  CONSENT_DECLINED: 'CONSENT_DECLINED',
  CANCELLED: 'CANCELLED',
}

/** The typed Bond events. */
export const BOND_EVENTS = {
  ARM: 'ARM', // the intent declared — availability arms (default-armed when the chain joins)
  ADVERTISED: 'ADVERTISED', // the advertisement confirmed out (the ≤2s budget, measured)
  DISARM: 'DISARM', // Stop pressed — the instant hide
  PEER_SEEN: 'PEER_SEEN', // the roster sighted the peer (the wait continues, visibly)
  SIGNAL_COPIED: 'SIGNAL_COPIED', // this device's signal went out (step 1)
  SIGNAL_OPENED: 'SIGNAL_OPENED', // the peer's signal opened HERE — the answer exists the same instant
  ANSWER_APPLIED: 'ANSWER_APPLIED', // the peer's answer opened here — the exchange is proven
  TRANSPORT_CONFIRMED: 'TRANSPORT_CONFIRMED', // the transport confirmed the pair (independent path)
  CODE_CONFIRMED: 'CODE_CONFIRMED', // the user pressed 'Codes match — connect'
  REPLAY_OPEN: 'REPLAY_OPEN', // an already-processed signal was re-opened — the friendly no-op
  OFFER: 'OFFER', // the sender's manifest went out
  OFFER_IN: 'OFFER_IN', // the receiver's offer card rendered
  ACCEPT: 'ACCEPT',
  DECLINE: 'DECLINE',
  BEGIN: 'BEGIN', // the chunks started moving
  CHUNKS_DONE: 'CHUNKS_DONE', // the last chunk acknowledged (VERIFIED is the digest's gate)
  VERIFY_OK: 'VERIFY_OK',
  VERIFY_FAIL: 'VERIFY_FAIL',
  BUDGET_SLOW: 'BUDGET_SLOW', // budget/2 crossed — the typed slow notice with the measured hop
  TO_PEER_TIMEOUT: 'TO_PEER_TIMEOUT', // budget×2 crossed with no relay failure — the typed terminal
  TO_RELAY_UNAVAILABLE: 'TO_RELAY_UNAVAILABLE', // budget×2 with the failing relay hop — the typed terminal
  BUDGET_EXPIRED: 'BUDGET_EXPIRED', // (the terminal family's generic name — the two typed edges above are the law)
  RELAY_FAIL: 'RELAY_FAIL', // a relay hop failed with its name
  CANCEL: 'CANCEL', // the user's own cancel
  RESET: 'RESET', // the user's one dismiss (terminals stay until this)
  COMPLETE_LATE: 'COMPLETE_LATE', // the transport completed AFTER the typed terminal (the pending law)
  // ── R140 §6.4 — THE HONEST MAILBOX LAW's machine facts (self-loop events:
  // they advance the JOURNEY RECORD, never the state — the waiting copy and
  // the header status derive from them) ──
  OFFER_WRITTEN: 'OFFER_WRITTEN', // the relay write CONFIRMED (commit/etag receipt in hand)
  OFFER_FETCHED: 'OFFER_FETCHED', // the relay read registered on the sender side (the peer's poll read the offer)
  INBOX_POLL: 'INBOX_POLL', // the inbox polled itself (§6.3 — one reported hop, ok or failed)
}

/** The typed terminal reasons (each carries its fix affordance in the projection). */
export const BOND_TERMINALS = {
  peerTimeout: 'peer-timeout',
  relayUnavailable: 'relay-unavailable',
  replayNoop: 'replay-noop',
  consentDeclined: 'consent-declined',
  cancelled: 'cancelled',
}

/** The typed failure detail for VERIFY_FAIL / RELAY_FAIL carriers. */
export const BOND_FAIL_REASONS = {
  integrity: 'integrity',
  network: 'network',
  invalid: 'invalid',
}

/** The legal-edge table — every other edge throws (typed, never silence).
 * WAITING_FOR_PEER and ARMED have NO expiry edge: the durable waiting law. */
export const BOND_TRANSITIONS = {
  [`${BOND_STATES.IDLE}|${BOND_EVENTS.ARM}`]: BOND_STATES.ARMED,
  [`${BOND_STATES.IDLE}|${BOND_EVENTS.SIGNAL_OPENED}`]: BOND_STATES.SIGNAL_EXCHANGED, // manual inbound on a fresh surface
  [`${BOND_STATES.IDLE}|${BOND_EVENTS.OFFER_IN}`]: BOND_STATES.CODE_SHOWN, // an inbound offer is a bond in progress
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.ADVERTISED}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.PEER_SEEN}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.SIGNAL_COPIED}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.SIGNAL_OPENED}`]: BOND_STATES.SIGNAL_EXCHANGED,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.ANSWER_APPLIED}`]: BOND_STATES.CODE_SHOWN, // the SENDER's path: the peer's answer arrives while waiting
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.DISARM}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.BUDGET_SLOW}`]: BOND_STATES.ARMED, // the honest clock: the notice never lies about the state
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.TO_PEER_TIMEOUT}`]: BOND_STATES.PEER_TIMEOUT,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.TO_RELAY_UNAVAILABLE}`]: BOND_STATES.RELAY_UNAVAILABLE,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.PEER_SEEN}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.SIGNAL_COPIED}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.SIGNAL_OPENED}`]: BOND_STATES.SIGNAL_EXCHANGED,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.ANSWER_APPLIED}`]: BOND_STATES.CODE_SHOWN, // the SENDER's path from the waiting state (the two-way protocol's return)
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.DISARM}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.OFFER_IN}`]: BOND_STATES.CODE_SHOWN,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.BUDGET_SLOW}`]: BOND_STATES.WAITING_FOR_PEER, // the notice never lies about the state
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.TO_PEER_TIMEOUT}`]: BOND_STATES.PEER_TIMEOUT,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.TO_RELAY_UNAVAILABLE}`]: BOND_STATES.RELAY_UNAVAILABLE,
  [`${BOND_STATES.SIGNAL_EXCHANGED}|${BOND_EVENTS.ANSWER_APPLIED}`]: BOND_STATES.CODE_SHOWN,
  [`${BOND_STATES.SIGNAL_EXCHANGED}|${BOND_EVENTS.TRANSPORT_CONFIRMED}`]: BOND_STATES.CONNECTED, // the transport's independent path — the first wins
  [`${BOND_STATES.SIGNAL_EXCHANGED}|${BOND_EVENTS.CODE_CONFIRMED}`]: BOND_STATES.CONNECTED, // the user's independent path — the first wins
  [`${BOND_STATES.SIGNAL_EXCHANGED}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.CODE_CONFIRMED}`]: BOND_STATES.CONNECTED,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.TRANSPORT_CONFIRMED}`]: BOND_STATES.CONNECTED,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.OFFER_IN}`]: BOND_STATES.CODE_SHOWN,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.ACCEPT}`]: BOND_STATES.TRANSFERRING, // the receiver's consent — the chunks may move
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.DECLINE}`]: BOND_STATES.CONSENT_DECLINED, // the receiver's no — nothing was received
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.OFFER}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.OFFER_IN}`]: BOND_STATES.CODE_SHOWN, // a second inbound offer shows its card
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.DECLINE}`]: BOND_STATES.CONSENT_DECLINED,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.ACCEPT}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.BEGIN}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.CHUNKS_DONE}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.VERIFY_OK}`]: BOND_STATES.VERIFIED,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.VERIFY_FAIL}`]: BOND_STATES.TRANSFERRING, // the typed integrity terminal is the projection's typed row; the machine holds for the retry decision
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.RELAY_FAIL}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.CANCEL}`]: BOND_STATES.CANCELLED,
  [`${BOND_STATES.VERIFIED}|${BOND_EVENTS.RESET}`]: BOND_STATES.DONE, // the receipt: verified → the user's dismiss turns it DONE (nothing auto-closes)
  [`${BOND_STATES.VERIFIED}|${BOND_EVENTS.COMPLETE_LATE}`]: BOND_STATES.VERIFIED,
  [`${BOND_STATES.DONE}|${BOND_EVENTS.RESET}`]: BOND_STATES.IDLE,
  // the terminals' only exit is the user's dismiss (the iron law)
  [`${BOND_STATES.PEER_TIMEOUT}|${BOND_EVENTS.RESET}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.PEER_TIMEOUT}|${BOND_EVENTS.COMPLETE_LATE}`]: BOND_STATES.VERIFIED, // the transport landed after the typed terminal — the pending law's completion notification
  [`${BOND_STATES.RELAY_UNAVAILABLE}|${BOND_EVENTS.RESET}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.RELAY_UNAVAILABLE}|${BOND_EVENTS.COMPLETE_LATE}`]: BOND_STATES.VERIFIED,
  [`${BOND_STATES.CONSENT_DECLINED}|${BOND_EVENTS.RESET}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.CANCELLED}|${BOND_EVENTS.RESET}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.CANCELLED}|${BOND_EVENTS.ARM}`]: BOND_STATES.ARMED, // a cancelled journey can re-arm — a pause, not a loss
  // ── R140 §6 — the relay facts' self-loop edges (additions-only; they
  // record the hop receipt / inbox truth without moving the state) ──
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.ARMED,
  [`${BOND_STATES.SIGNAL_EXCHANGED}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.SIGNAL_EXCHANGED,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.CODE_SHOWN,
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.CONNECTED,
  [`${BOND_STATES.TRANSFERRING}|${BOND_EVENTS.OFFER_WRITTEN}`]: BOND_STATES.TRANSFERRING,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.OFFER_FETCHED}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.OFFER_FETCHED}`]: BOND_STATES.ARMED,
  [`${BOND_STATES.IDLE}|${BOND_EVENTS.INBOX_POLL}`]: BOND_STATES.IDLE,
  [`${BOND_STATES.ARMED}|${BOND_EVENTS.INBOX_POLL}`]: BOND_STATES.ARMED,
  [`${BOND_STATES.WAITING_FOR_PEER}|${BOND_EVENTS.INBOX_POLL}`]: BOND_STATES.WAITING_FOR_PEER,
  [`${BOND_STATES.CODE_SHOWN}|${BOND_EVENTS.INBOX_POLL}`]: BOND_STATES.CODE_SHOWN,
  [`${BOND_STATES.CONNECTED}|${BOND_EVENTS.INBOX_POLL}`]: BOND_STATES.CONNECTED,
}

export function bondError(code, detail) {
  const e = new Error(`BOND_${code}: ${detail}`)
  e.code = `BOND_${code}`
  return e
}

/** The pure step. Throws typed on an illegal edge; REPLAY_OPEN never throws. */
export function bondStep(state, event) {
  const next = BOND_TRANSITIONS[`${state}|${event}`]
  if (!next) throw bondError('STATE_ILLEGAL', `${event} in ${state}`)
  return next
}

/** The tri-state glyph vocabulary (the ONLY glyphs the projection emits). */
export const BOND_GLYPHS = { done: '✓', active: '▶', pending: '·', fail: '✗' }

/** The honest-clock budgets (§5.5 — machine law, not targets). */
export const BOND_BUDGETS = {
  advertiseMs: 2000, // advertise on arm within 2 seconds (measured)
  directP50Ms: 5000, // p50 ≤ 5 s same-network
  relayP50Ms: 15000, // p50 ≤ 15 s via cloud relay
  pollMinMs: 2000, // 2–4 s jittered polling while searching
  pollMaxMs: 4000,
}

/** The per-hop telemetry names (the presence path — each a testable seam).
 * R140 §6.6 additions-only: the relay's offer-write/fetch hops and the
 * inbox's self-poll hop join the drawer's table (the R139 rows stand). */
export const BOND_HOPS = ['arm', 'advertise', 'relayWrite', 'relayRead', 'roster', 'render', 'relayOfferWrite', 'relayOfferFetch', 'inboxPoll']

/** §5.7 — the fixed page order (D4, the CEO's command). */
export const BOND_LAYOUT_ORDER = [
  'readiness-strip',
  'intent-actions',
  'guide',
  'manual-fallback',
  'diagnostics-drawer',
]

/** budgetFor(plane): the honest p50 budget for the plane. */
export function budgetFor(plane) {
  return plane === 'B' ? BOND_BUDGETS.relayP50Ms : BOND_BUDGETS.directP50Ms
}

/** FNV-1a over the signal text — the payload-hash idempotency key (D7:
 * the key is the SIGNAL PAYLOAD HASH, never a session-scoped ledger a
 * legitimate re-paste can trip). */
export function bondPayloadHash(text) {
  const s = String(text || '')
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return ('00000000' + (h >>> 0).toString(16)).slice(-8) + '-' + s.length.toString(16)
}

/**
 * THE GATED CONNECT (§5.4, D9): the connect control is state-gated. When
 * prerequisites are unmet it renders DISABLED with a live reason line;
 * when enabled, every click lands CONNECTED or a typed failure. The
 * disabled state is the product teaching the user exactly what is missing.
 */
export function connectGate(state, facts = {}) {
  const relayReadOk = facts.relayReadOk !== false
  switch (state) {
    case BOND_STATES.WAITING_FOR_PEER:
      return { enabled: false, reasonKey: 'bondConnectWaitingSignal', reason: 'Waiting for the other device to open your signal…', fix: 'show-fallback' }
    case BOND_STATES.SIGNAL_EXCHANGED:
      if (!relayReadOk) return { enabled: false, reasonKey: 'bondConnectRelayRead', reason: 'Relay read is failing — run the doctor.', fix: 'open-doctor' }
      return { enabled: true, reasonKey: '', reason: '', fix: null }
    case BOND_STATES.CODE_SHOWN:
      if (!relayReadOk) return { enabled: false, reasonKey: 'bondConnectRelayRead', reason: 'Relay read is failing — run the doctor.', fix: 'open-doctor' }
      return { enabled: true, reasonKey: '', reason: '', fix: null }
    case BOND_STATES.CONNECTED:
    case BOND_STATES.TRANSFERRING:
    case BOND_STATES.VERIFIED:
    case BOND_STATES.DONE:
      return { enabled: false, reasonKey: 'bondConnectAlready', reason: 'Already connected — pick the file and press Send (sending is the last step).', fix: null }
    default:
      return { enabled: false, reasonKey: 'bondConnectPairFirst', reason: 'Pair the devices first — the 4×4 code shows on both screens when the signals have crossed.', fix: 'show-fallback' }
  }
}

/**
 * THE BOND SESSION — one machine per transfer journey. The engine owns the
 * instance (worker-side, crash-safe): the snapshot persists after every
 * fire, and the append-only journal is the typed record of the journey.
 */
export class BondSession {
  constructor({ role = 'send', now = Date.now(), sessionId = '', peerDeviceId = '' } = {}) {
    if (!['send', 'receive'].includes(role)) throw bondError('ROLE', 'role must be send|receive')
    this.role = role
    this.sessionId = String(sessionId || '')
    this.peerDeviceId = String(peerDeviceId || '')
    this.state = BOND_STATES.IDLE
    this.armedAt = 0
    this.advertisedAt = 0
    this.waitingSince = 0
    this.exchangedAt = 0
    this.codeShownAt = 0
    this.connectedAt = 0
    this.transferStartedAt = 0
    this.lastProgressAt = now
    this.verifiedAt = 0
    this.doneAt = 0
    this.cancelledAt = 0
    this.terminalAt = 0
    this.terminalDetail = null // { hop } for RELAY_UNAVAILABLE; { seconds } for PEER_TIMEOUT
    this.plane = null
    this.mySignalHash = ''
    this.mySignalText = '' // the crash-safe restore (the copy box refills after a restart)
    this.peerSignalHash = ''
    this.answerReady = false
    this.answerText = '' // the crash-safe restore of the two-way protocol's answer
    this.codesMatchedAt = 0
    this.transportConfirmedAt = 0
    this.integrityFailed = false
    // the durable-waiting idempotency ring (D7): payload-hash keyed, bounded
    this.replayRing = [] // [{ hash, at, count }]
    this.replayNoops = 0
    // the honest clocks (§5.5)
    this.slowNoticedAt = 0 // the budget/2 notice's fire time (0 = not fired)
    this.pendingCompletion = false // the typed terminal's persistent-pending law
    // ── R140 §6.4 — the honest mailbox facts (the sender's receipts) ──
    this.offerWrittenAt = 0 // the confirmed relay write (commit/etag receipt)
    this.writeReceipt = null // { at, store, commit }
    this.offerFetchedAt = 0 // the relay read registered (the peer's poll read the offer)
    this.peerReadKnown = false // the receiver's read capability, from the ONE chain truth
    this.peerName = '' // §6.1 — the peer's ROSTER name (never a placeholder)
    this.inboxLastPollAt = 0 // §6.3 — the inbox's self-poll truth
    this.inboxLastOkAt = 0
    this.inboxLastError = null
    this.inboxPeriodSec = 3
    // the per-hop telemetry + the measured latencies
    this.hops = {}
    this.latencies = {}
    // the append-only typed journal (the journey record)
    this.journal = []
  }

  _journal(entry, at) {
    this.journal.push({ ...entry, at: at || Date.now() })
    if (this.journal.length > 400) this.journal.splice(0, this.journal.length - 400)
  }

  /** Fire a typed event. REPLAY_OPEN is always the friendly no-op (D7). */
  fire(event, meta = {}) {
    const at = Number(meta.now) || Date.now()
    // ── the D7 law: a re-opened signal is the friendly no-op that re-renders truth ──
    if (event === BOND_EVENTS.REPLAY_OPEN) {
      const hash = String(meta.hash || '')
      const known = this.replayRing.find((r) => r.hash === hash)
      if (known) known.count += 1
      else this.replayRing.push({ hash, at, count: 1 })
      while (this.replayRing.length > 32) this.replayRing.shift()
      this.replayNoops += 1
      this._journal({ type: 'replay-noop', hash }, at)
      return { state: this.state, noop: true }
    }
    const from = this.state
    const next = bondStep(from, event)
    this.state = next
    this.lastProgressAt = at
    if (event === BOND_EVENTS.ARM) {
      this.armedAt = at
      this._journal({ type: 'armed', role: this.role }, at)
    }
    if (event === BOND_EVENTS.ADVERTISED) {
      this.advertisedAt = at
      this.waitingSince = at
      if (this.armedAt) this.latencies.advertise = at - this.armedAt
      this._journal({ type: 'advertised', ms: this.latencies.advertise || 0 }, at)
    }
    if (event === BOND_EVENTS.PEER_SEEN && !this.firstSightAt) {
      this.firstSightAt = at
      this._journal({ type: 'peer-seen' }, at)
    }
    if (event === BOND_EVENTS.SIGNAL_COPIED) {
      this.mySignalHash = String(meta.hash || this.mySignalHash || '')
      if (!this.waitingSince) this.waitingSince = at
      this._journal({ type: 'signal-copied' }, at)
    }
    if (event === BOND_EVENTS.SIGNAL_OPENED) {
      this.exchangedAt = at
      this.peerSignalHash = String(meta.hash || '')
      if (meta.answerReady !== undefined) this.answerReady = !!meta.answerReady
      if (this.waitingSince) this.latencies.pair = at - this.waitingSince
      this.slowNoticedAt = 0 // the wait resolved — the honest clock resets
      this._journal({ type: 'signal-exchanged' }, at)
    }
    if (event === BOND_EVENTS.ANSWER_APPLIED) {
      this.codeShownAt = at
      this._journal({ type: 'code-shown' }, at)
    }
    if (event === BOND_EVENTS.TRANSPORT_CONFIRMED) {
      this.transportConfirmedAt = at
      this._journal({ type: 'transport-confirmed' }, at)
    }
    if (event === BOND_EVENTS.CODE_CONFIRMED) {
      this.codesMatchedAt = at
      this._journal({ type: 'code-confirmed' }, at)
    }
    if (next === BOND_STATES.CONNECTED && !this.connectedAt) {
      this.connectedAt = at
      this.latencies.connect = this.waitingSince ? at - this.waitingSince : 0
      this._journal({ type: 'connected', via: event === BOND_EVENTS.TRANSPORT_CONFIRMED ? 'transport' : 'user' }, at)
    }
    if (event === BOND_EVENTS.OFFER || event === BOND_EVENTS.OFFER_IN) {
      this.transferStartedAt = at
      this._journal({ type: event === BOND_EVENTS.OFFER ? 'offer-out' : 'offer-in', name: meta.name || '', bytes: meta.bytes || 0 }, at)
    }
    if (event === BOND_EVENTS.BEGIN) this._journal({ type: 'chunks-moving' }, at)
    if (event === BOND_EVENTS.CHUNKS_DONE) this._journal({ type: 'chunks-done', lastAcked: meta.lastAcked || 0 }, at)
    if (event === BOND_EVENTS.VERIFY_OK) {
      this.verifiedAt = at
      this.pendingCompletion = false
      this._journal({ type: 'verified' }, at)
    }
    if (event === BOND_EVENTS.VERIFY_FAIL) {
      this.integrityFailed = true
      this._journal({ type: 'integrity-failed' }, at)
    }
    if (event === BOND_EVENTS.OFFER_IN && meta.name !== undefined) {
      // the offer card's manifest rides the journal for the AirDrop card
    }
    if (event === BOND_EVENTS.ACCEPT) {
      this.transferStartedAt = this.transferStartedAt || at
      this._journal({ type: 'accepted' }, at)
    }
    if (event === BOND_EVENTS.BUDGET_SLOW) {
      this.slowNoticedAt = at
      this._journal({ type: 'budget-slow', elapsedMs: meta.elapsedMs || 0, hop: meta.hop || '' }, at)
    }
    if (event === BOND_EVENTS.TO_PEER_TIMEOUT || event === BOND_EVENTS.TO_RELAY_UNAVAILABLE || event === BOND_EVENTS.BUDGET_EXPIRED) {
      this.terminalAt = at
      this.terminalDetail = { hop: meta.hop || '', seconds: Math.round((meta.elapsedMs || 0) / 1000) }
      this.pendingCompletion = meta.pendingCompletion !== false // the persistent-pending law (§5.5)
      this._journal({ type: 'budget-terminal', terminal: next, hop: this.terminalDetail.hop }, at)
    }
    if (event === BOND_EVENTS.RELAY_FAIL) {
      this._journal({ type: 'relay-fail', hop: meta.hop || '' }, at)
    }
    if (event === BOND_EVENTS.CANCEL) {
      this.cancelledAt = at
      this.terminalAt = at
      this._journal({ type: 'cancelled' }, at)
    }
    if (event === BOND_EVENTS.DECLINE) {
      this.terminalAt = at
      this._journal({ type: 'consent-declined' }, at)
    }
    if (event === BOND_EVENTS.RESET) {
      this._journal({ type: 'reset', from }, at)
    }
    if (event === BOND_EVENTS.COMPLETE_LATE) {
      this.pendingCompletion = false
      this.verifiedAt = at
      this._journal({ type: 'completed-after-terminal' }, at)
    }
    // ── R140 §6.4/§6.3 — the relay receipt + inbox facts (self-loops: the
    // state is unchanged; the journey record and the copy derive) ──
    if (event === BOND_EVENTS.OFFER_WRITTEN) {
      this.offerWrittenAt = at
      this.writeReceipt = { at, store: String(meta.store || ''), commit: String(meta.commit || '') }
      this.peerReadKnown = meta.peerReadKnown === true
      this._journal({ type: 'offer-written', store: this.writeReceipt.store }, at)
    }
    if (event === BOND_EVENTS.OFFER_FETCHED) {
      this.offerFetchedAt = at
      this._journal({ type: 'offer-fetched', by: String(meta.peerName || '') }, at)
    }
    if (event === BOND_EVENTS.INBOX_POLL) {
      this.inboxLastPollAt = at
      if (meta.ok !== false) this.inboxLastOkAt = at
      else this.inboxLastError = String(meta.error || 'failed').slice(0, 120)
      if (meta.periodSec) this.inboxPeriodSec = Math.max(1, Math.round(Number(meta.periodSec)))
      this._journal({ type: 'inbox-poll', ok: meta.ok !== false }, at)
    }
    if (meta.peerName) this.peerName = String(meta.peerName).slice(0, 80)
    if (meta.plane) this.plane = String(meta.plane)
    if (meta.peerDeviceId) this.peerDeviceId = String(meta.peerDeviceId)
    return { state: this.state, noop: false, from }
  }

  /** Record one hop of the presence path. */
  recordHop(name, { ok = true, detail = '', at = Date.now() } = {}) {
    if (!BOND_HOPS.includes(name)) throw bondError('HOP', `unknown hop ${name}`)
    const prev = this.hops[name]
    const ms = prev && prev.at ? Math.max(0, at - prev.at) : 0
    this.hops[name] = { ok: !!ok, detail: String(detail || ''), at, ms }
    this.lastProgressAt = at
    return this.hops[name]
  }

  /** THE HONEST CLOCK (§5.5): the machine-law tick. Fires BUDGET_SLOW at
   * budget/2 (once per wait) and BUDGET_EXPIRED at budget×2 — the typed
   * terminal with the failing hop named. A silent unbounded wait is
   * unrepresentable: at 30 seconds on the relay path the machine HAS spoken. */
  clockTick(now = Date.now()) {
    if (![BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(this.state)) return []
    const start = this.waitingSince || this.armedAt
    if (!start) return []
    const elapsed = Math.max(0, now - start)
    const plane = this.plane || 'A'
    const budget = budgetFor(plane)
    const fired = []
    const halfBudget = budget / 2
    if (elapsed >= halfBudget && elapsed < budget * 2 && !this.slowNoticedAt) {
      // §5.5: the slow-path notice fires at budget/2 and names the measured slow hop
      fired.push({ event: BOND_EVENTS.BUDGET_SLOW, elapsedMs: elapsed, hop: this.slowestHop() })
      this.fire(BOND_EVENTS.BUDGET_SLOW, { now, elapsedMs: elapsed, hop: this.slowestHop() })
    } else if (elapsed >= budget * 2 && this.state !== BOND_STATES.PEER_TIMEOUT && this.state !== BOND_STATES.RELAY_UNAVAILABLE) {
      const relayReadFailing = this.hops.relayRead && this.hops.relayRead.ok === false
      const event = relayReadFailing ? BOND_EVENTS.TO_RELAY_UNAVAILABLE : BOND_EVENTS.TO_PEER_TIMEOUT
      fired.push({ event: relayReadFailing ? BOND_STATES.RELAY_UNAVAILABLE : BOND_STATES.PEER_TIMEOUT, elapsedMs: elapsed, hop: relayReadFailing ? 'relayRead' : 'peer' })
      this.fire(event, { now, elapsedMs: elapsed, hop: relayReadFailing ? 'relayRead' : 'peer', pendingCompletion: true })
    }
    return fired
  }

  slowestHop() {
    let slow = ''
    let max = -1
    for (const h of BOND_HOPS) {
      const hop = this.hops[h]
      if (hop && hop.ok && hop.ms > max) { max = hop.ms; slow = h }
    }
    return slow
  }

  /** The live waiting counter ('Searching… Xs' — the wait is never silent). */
  waitSeconds(now = Date.now()) {
    if (![BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(this.state)) return 0
    const start = this.waitingSince || this.armedAt
    return start ? Math.max(0, Math.floor((now - start) / 1000)) : 0
  }

  /** Serializable snapshot (the crash-safe law — the engine persists it). */
  snapshot() {
    return {
      role: this.role,
      sessionId: this.sessionId,
      peerDeviceId: this.peerDeviceId,
      state: this.state,
      armedAt: this.armedAt,
      advertisedAt: this.advertisedAt,
      waitingSince: this.waitingSince,
      exchangedAt: this.exchangedAt,
      codeShownAt: this.codeShownAt,
      connectedAt: this.connectedAt,
      transferStartedAt: this.transferStartedAt,
      lastProgressAt: this.lastProgressAt,
      verifiedAt: this.verifiedAt,
      doneAt: this.doneAt,
      cancelledAt: this.cancelledAt,
      terminalAt: this.terminalAt,
      terminalDetail: this.terminalDetail,
      plane: this.plane,
      mySignalHash: this.mySignalHash,
      mySignalText: this.mySignalText,
      peerSignalHash: this.peerSignalHash,
      answerReady: this.answerReady,
      answerText: this.answerText,
      codesMatchedAt: this.codesMatchedAt,
      transportConfirmedAt: this.transportConfirmedAt,
      integrityFailed: this.integrityFailed,
      replayRing: this.replayRing.slice(),
      replayNoops: this.replayNoops,
      slowNoticedAt: this.slowNoticedAt,
      pendingCompletion: this.pendingCompletion,
      offerWrittenAt: this.offerWrittenAt,
      writeReceipt: this.writeReceipt,
      offerFetchedAt: this.offerFetchedAt,
      peerReadKnown: this.peerReadKnown,
      peerName: this.peerName,
      inboxLastPollAt: this.inboxLastPollAt,
      inboxLastOkAt: this.inboxLastOkAt,
      inboxLastError: this.inboxLastError,
      inboxPeriodSec: this.inboxPeriodSec,
      hops: { ...this.hops },
      latencies: { ...this.latencies },
      journal: this.journal.slice(-120),
    }
  }

  static from(snapshot) {
    const s = new BondSession({ role: snapshot.role || 'send', sessionId: snapshot.sessionId || '', peerDeviceId: snapshot.peerDeviceId || '' })
    Object.assign(s, snapshot, {
      hops: { ...(snapshot.hops || {}) },
      latencies: { ...(snapshot.latencies || {}) },
      replayRing: Array.isArray(snapshot.replayRing) ? snapshot.replayRing.slice() : [],
      journal: Array.isArray(snapshot.journal) ? snapshot.journal.slice() : [],
    })
    return s
  }
}

/**
 * THE SINGLE-WRITER PROJECTION (§5.1): EVERY rendered element of the
 * transfer surface derives from THIS function. Glyph and text derive from
 * the same fact in the same expression. The retired contradiction strings
 * are unrepresentable here by construction.
 *
 * @param {BondSession} bs
 * @param {{chainJoined?:boolean, visibleDevices?:number, plane?:string|null,
 *          relayLabel?:string, relayConnected?:boolean, availability?:{armed:boolean,minutes:number},
 *          defaultArmed?:boolean, beamIdentity?:string, now?:number}} facts
 */
export function projectBond(bs, facts = {}) {
  const now = Number(facts.now) || Date.now()
  const chainOk = !!facts.chainJoined
  const devices = Math.max(0, Number(facts.visibleDevices) || 0)
  const plane = facts.plane || bs.plane || null
  const relayOk = !!facts.relayConnected
  const relayLabel = String(facts.relayLabel || 'cloud')

  // ── the readiness rows: ONE fact per row; glyph+text from the same expression ──
  const rows = []
  // the I18N-3 redundancy law: the rows REUSE the canonical hs*/beam3* keys where
  // the sentence already exists — one sentence per truth, never a duplicate writer
  rows.push(chainOk
    ? { id: 'chain', glyph: BOND_GLYPHS.done, state: 'done', key: 'hsRowChainOk', fallback: 'Sync chain joined', fix: null }
    : { id: 'chain', glyph: BOND_GLYPHS.fail, state: 'fail', key: 'hsRowChainNo', fallback: 'Sync chain not joined — join or create one to transfer between your devices', fix: { action: 'open-cloud-sync', key: 'bondFixChain', fallback: 'Connect your chain' } })
  // the route row: the label is interpolated with a guarded default so an
  // empty relay label can never produce a dangling route sentence (D13's root fix)
  if (plane === 'A') rows.push({ id: 'route', glyph: BOND_GLYPHS.done, state: 'done', key: 'beam3RouteDirect', fallback: 'Route: same network — direct device-to-device, end-to-end encrypted.', fix: null })
  else if (plane === 'B') rows.push(relayLabel
    ? { id: 'route', glyph: BOND_GLYPHS.done, state: 'done', key: 'beam3RouteRelay', subs: [relayLabel], fallback: `Route: through your connected ${relayLabel} — sealed chunks only, end-to-end encrypted.`, fix: null }
    : { id: 'route', glyph: BOND_GLYPHS.done, state: 'done', key: 'beam3RouteRelayNoLabel', fallback: 'Route: through your connected cloud — sealed chunks only, end-to-end encrypted.', fix: null })
  else if (plane === 'C') rows.push({ id: 'route', glyph: BOND_GLYPHS.done, state: 'done', key: 'beam3RouteManual', fallback: 'Route: manual exchange — the code travels with you; the transfer completes device-to-device when a path exists.', fix: null })
  else rows.push({ id: 'route', glyph: BOND_GLYPHS.pending, state: 'pending', key: 'bondRowRoutePending', fallback: 'Route not chosen yet — pick Send a file or Receive above', fix: { action: 'show-intent', key: 'hsFixRoute', fallback: 'Choose Send or Receive' } })
  if (devices > 0) rows.push({ id: 'devices', glyph: BOND_GLYPHS.done, state: 'done', key: 'bondRowDevicesOk', subs: [String(devices)], fallback: `Devices visible: ${devices} on your chain`, fix: null })
  else if (bs.state === BOND_STATES.IDLE) rows.push({ id: 'devices', glyph: BOND_GLYPHS.pending, state: 'pending', key: 'bondRowDevicesPending', fallback: 'Devices appear here once you pick Send a file or Receive (or pair by code)', fix: { action: 'show-intent', key: 'hsFixRoute', fallback: 'Choose Send or Receive' } })
  else rows.push({ id: 'devices', glyph: BOND_GLYPHS.fail, state: 'fail', key: 'bondRowDevicesNone', fallback: 'No other chain device visible yet — the other device must be online with availability armed (or pair by code)', fix: { action: 'show-pairing', key: 'hsFixRoster', fallback: 'Pair by code' } })

  // ── the availability card (§5.6 — ONE surface, default-armed, shown as True) ──
  const availability = (() => {
    const armed = !!(facts.availability && facts.availability.armed)
    const minutes = Math.max(0, Number(facts.availability && facts.availability.minutes) || 0)
    return {
      mode: 'card', // the ONE availability surface (the duplicate cluster is removed)
      defaultArmed: facts.defaultArmed !== false, // ships ON (the CEO's command)
      armed,
      stateWord: armed ? 'On' : 'Off',
      minutesRemaining: minutes,
      key: armed ? 'bondAvailOn' : 'bondAvailOff',
      subs: armed ? [String(minutes)] : undefined,
      fallback: armed
        ? `Availability: On — this device is visible to your chain for ${minutes} minute${minutes === 1 ? '' : 's'}. Stop hides you instantly.`
        : 'Availability: Off — press Arm availability to become visible to your chain.',
      canStop: armed,
      canArm: !armed,
    }
  })()

  // ── the step rail (§5.7's grammar: pair, confirm, transfer, verify) ──
  const journey = [
    { id: 'intent', label: 'Choose Send a file or Receive', key: 'bondRailIntent', doneAt: bs.armedAt },
    { id: 'pair', label: 'Pair the devices', key: 'hsRailPair', doneAt: bs.exchangedAt },
    { id: 'confirm', label: 'Confirm the code — compare the 4×4 code on both screens', key: 'hsRailConfirm', doneAt: bs.connectedAt },
    { id: 'transfer', label: 'Transfer — pick the file and press Send (the last step), or await the offer', key: 'hsRailTransfer', doneAt: bs.transferStartedAt },
    { id: 'verify', label: 'Verify — the digest is checked before anything is saved', key: 'hsRailVerify', doneAt: bs.verifiedAt },
    { id: 'done', label: 'Done — the receipt stays until you dismiss it', key: 'hsRailDone', doneAt: bs.doneAt },
  ]
  const activeIdx = journey.findIndex((j) => !j.doneAt)
  const steps = journey.map((j, i) => ({
    id: j.id,
    label: j.label,
    key: j.key,
    glyph: j.doneAt ? BOND_GLYPHS.done : i === activeIdx ? BOND_GLYPHS.active : BOND_GLYPHS.pending,
    state: j.doneAt ? 'done' : i === activeIdx ? 'active' : 'pending',
    target: j.id, // the deep-link target (never inert text)
  }))

  // ── the prose: the honest clocks + the typed terminals ──
  const waitSec = bs.waitSeconds(now)
  const start = bs.waitingSince || bs.armedAt
  const elapsed = start && [BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(bs.state) ? Math.max(0, now - start) : 0
  const budget = budgetFor(plane || 'A')
  const prose = {
    search: [BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(bs.state)
      ? { key: 'hsProseSearching', fallback: `Searching for the other device… ${waitSec}s`, live: true, seconds: waitSec }
      : null,
    slow: bs.slowNoticedAt && elapsed >= budget / 2 && elapsed < budget * 2
      ? { key: 'bondProseSlow', fallback: `Taking longer than usual — the slow hop is ${bs.slowestHop() || 'the relay read'}; the doctor is one click away.`, hop: bs.slowestHop(), live: false }
      : null,
    waiting: bs.state === BOND_STATES.WAITING_FOR_PEER
      ? { key: 'bondProseWaiting', fallback: 'Waiting for the other device — this stays open while you wait. Nothing expires while it waits.', live: true }
      : null,
    terminal: (bs.state === BOND_STATES.PEER_TIMEOUT || bs.state === BOND_STATES.RELAY_UNAVAILABLE)
      ? {
          key: bs.state === BOND_STATES.PEER_TIMEOUT ? 'bondProsePeerTimeout' : 'bondProseRelayUnavailable',
          fallback: bs.state === BOND_STATES.PEER_TIMEOUT
            ? `No connection after ${bs.terminalDetail ? bs.terminalDetail.seconds : Math.round(elapsed / 1000)} seconds — check the other device is online with availability armed, or pair by code below.${bs.pendingCompletion ? ' Still trying in the background — we will tell you when it lands.' : ''}`
            : `The cloud relay is not answering (hop: ${bs.terminalDetail ? bs.terminalDetail.hop : 'relayRead'}) — run the connection doctor, or pair by code below.${bs.pendingCompletion ? ' Still trying in the background — we will tell you when it lands.' : ''}`,
          pending: !!bs.pendingCompletion,
          fix: bs.state === BOND_STATES.PEER_TIMEOUT ? 'show-pairing' : 'open-doctor',
        }
      : null,
    noop: bs.replayNoops > 0 && bs.state !== BOND_STATES.IDLE
      ? { key: 'bondProseReplayNoop', fallback: 'This signal is already active — here is where you are.', live: false }
      : null,
    declined: bs.state === BOND_STATES.CONSENT_DECLINED
      ? { key: 'bondProseDeclined', fallback: 'Declined — nothing was received. You can send again any time.', live: false }
      : null,
    cancelled: bs.state === BOND_STATES.CANCELLED
      ? { key: 'bondProseCancelled', fallback: 'Canceled — you can start again any time; nothing was lost.', live: false }
      : null,
    integrity: bs.integrityFailed
      ? { key: 'bondProseIntegrity', fallback: 'The digest did not match — the file was NOT saved; press Retry to verify again.', live: false }
      : null,
  }

  // ── the buttons: exactly what the state makes meaningful; the GATED CONNECT ──
  const gate = connectGate(bs.state, { relayReadOk: !(bs.hops.relayRead && bs.hops.relayRead.ok === false) })
  const buttons = {
    send: true,
    receive: true,
    stop: [BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(bs.state),
    connect: {
      visible: [BOND_STATES.WAITING_FOR_PEER, BOND_STATES.SIGNAL_EXCHANGED, BOND_STATES.CODE_SHOWN, BOND_STATES.CONNECTED, BOND_STATES.TRANSFERRING].includes(bs.state), // the receipt (VERIFIED/DONE) is the surface — no connect control on it
      enabled: gate.enabled,
      reasonKey: gate.reasonKey,
      reason: gate.reason,
      fix: gate.fix,
    },
    openDiagnostics: true,
    showFallback: true,
    regenerate: [BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER].includes(bs.state),
  }

  // ── the fallback decision (§5.7): collapsed when a better plane satisfies the
  // journey; the persistent 'Show manual fallback' affordance never disappears ──
  const betterPlaneSatisfied = plane === 'A' || (plane === 'B' && relayOk)
  const fallback = {
    collapsedByDefault: betterPlaneSatisfied && ![BOND_STATES.IDLE].includes(bs.state),
    reason: betterPlaneSatisfied ? 'a faster plane is connected — the manual path stays one click away' : '',
    persistReopen: true,
  }

  // ── R140 F2 — THE HEADER STATUS (Table S, the single writer): the CEO
  // commanded the motto's retirement; the live connection status takes its
  // place, derived HERE so it can never contradict the glyph, the guide,
  // or the drawer. Placeholders resolve to the peer's ROSTER name (§6.1 —
  // the banned placeholder is unrepresentable) ──
  const peerDisplay = String(facts.peerName || bs.peerName || '').trim() || 'Device'
  const progress = facts.progress && typeof facts.progress === 'object' ? facts.progress : null
  const pct = progress && Number.isFinite(Number(progress.percent)) ? Math.max(0, Math.min(100, Math.round(Number(progress.percent)))) : null
  const rate = progress && progress.rate ? String(progress.rate) : ''
  const headerStatus = (() => {
    switch (bs.state) {
      case BOND_STATES.IDLE:
        return { key: 'spineHeaderIdle', fallback: 'Not connected — no device is linked right now.', tone: 'idle' }
      case BOND_STATES.ARMED:
        return { key: 'spineHeaderArmed', fallback: 'Visible to your chain — waiting for a device to appear.', tone: 'armed' }
      case BOND_STATES.WAITING_FOR_PEER:
        return { key: 'spineHeaderPeerFound', subs: [peerDisplay], fallback: `Device found: ${peerDisplay} — compare codes to connect.`, tone: 'found' }
      case BOND_STATES.SIGNAL_EXCHANGED:
      case BOND_STATES.CODE_SHOWN:
        return { key: 'spineHeaderPairing', subs: [peerDisplay], fallback: `Pairing with ${peerDisplay} — codes shown below.`, tone: 'pairing' }
      case BOND_STATES.CONNECTED:
        return { key: 'spineHeaderConnected', subs: [peerDisplay], fallback: `Connected to ${peerDisplay} — ready to transfer.`, tone: 'connected' }
      case BOND_STATES.TRANSFERRING:
        return bs.role === 'receive'
          ? { key: 'spineHeaderReceiving', subs: [peerDisplay, String(pct == null ? '…' : pct), rate], fallback: `Receiving from ${peerDisplay} — ${pct == null ? '…' : pct}%${rate ? ` · ${rate}` : ''}.`, tone: 'transferring' }
          : { key: 'spineHeaderSending', subs: [peerDisplay, String(pct == null ? '…' : pct), rate], fallback: `Sending to ${peerDisplay} — ${pct == null ? '…' : pct}%${rate ? ` · ${rate}` : ''}.`, tone: 'transferring' }
      case BOND_STATES.VERIFIED:
      case BOND_STATES.DONE:
        return { key: 'spineHeaderVerified', fallback: 'Verified — SHA-256 matches. Transfer complete.', tone: 'verified' }
      default:
        // the typed terminals — the reason is the machine's own typed detail
        return { key: 'spineHeaderStopped', fallback: 'Stopped — nothing was corrupted; start again any time.', tone: 'stopped', reason: bs.terminalDetail || null }
    }
  })()

  // ── R140 §6.4 — THE HONEST MAILBOX CLAIM (the sender's waiting copy):
  // derived from the two facts and nothing else — a receipt without the
  // claim is PENDING_PROOF, the claim without a receipt is UNREPRESENTABLE ──
  const mailbox = (() => {
    if (bs.role !== 'send') return null
    if (bs.offerFetchedAt) {
      return { claim: 'fetched', key: 'spineMailFetched', subs: [peerDisplay, new Date(bs.offerFetchedAt).toLocaleTimeString([], { hour12: false })], fallback: `Offer fetched by ${peerDisplay} at ${new Date(bs.offerFetchedAt).toLocaleTimeString([], { hour12: false })}`, at: bs.offerFetchedAt }
    }
    if (bs.writeReceipt && bs.writeReceipt.at && bs.peerReadKnown) {
      return { claim: 'written', key: 'spineMailWritten', subs: [String(facts.relayLabel || 'cloud'), new Date(bs.writeReceipt.at).toLocaleTimeString([], { hour12: false })], fallback: `Offer written to your ${String(facts.relayLabel || 'cloud')} at ${new Date(bs.writeReceipt.at).toLocaleTimeString([], { hour12: false })} · their device checks automatically`, at: bs.writeReceipt.at }
    }
    if (bs.writeReceipt && bs.writeReceipt.at) {
      return { claim: 'pending-proof', key: 'spineMailPendingProof', subs: [String(facts.relayLabel || 'cloud'), new Date(bs.writeReceipt.at).toLocaleTimeString([], { hour12: false })], fallback: `Offer written to your ${String(facts.relayLabel || 'cloud')} at ${new Date(bs.writeReceipt.at).toLocaleTimeString([], { hour12: false })} — delivery is confirmed when their device reads it; the manual route below works right now.`, at: bs.writeReceipt.at }
    }
    if (bs.state === BOND_STATES.WAITING_FOR_PEER || bs.state === BOND_STATES.ARMED) {
      return { claim: 'undeliverable', key: 'spineMailUndeliverable', fallback: 'Their device is not reachable directly and the offer could not be delivered through your cloud — the manual route below is the road: one copy, one paste.', at: 0 }
    }
    return null
  })()

  // ── R140 §6.3 — THE INBOX VIEW (the receiver's self-polling truth) ──
  const inbox = (() => {
    const active = bs.role === 'receive' && [BOND_STATES.ARMED, BOND_STATES.WAITING_FOR_PEER, BOND_STATES.CODE_SHOWN, BOND_STATES.CONNECTED].includes(bs.state)
    const ago = bs.inboxLastPollAt ? Math.max(0, Math.round((now - bs.inboxLastPollAt) / 1000)) : null
    return {
      active,
      periodSec: bs.inboxPeriodSec || 3,
      lastCheckedAt: bs.inboxLastPollAt || 0,
      secondsAgo: ago,
      lastOkAt: bs.inboxLastOkAt || 0,
      lastError: bs.inboxLastError || null,
      key: !active
        ? 'spineInboxIdle'
        : bs.inboxLastError && !bs.inboxLastOkAt
          ? 'spineInboxFailing'
          : 'spineInboxActive',
      subs: active ? [String(bs.inboxPeriodSec || 3), String(ago == null ? '…' : ago)] : undefined,
      fallback: !active
        ? 'The inbox checks when you open Receive with availability armed.'
        : bs.inboxLastError && !bs.inboxLastOkAt
          ? `Checking for offers every ${bs.inboxPeriodSec || 3} s · the last check failed (${bs.inboxLastError}) — retrying.`
          : `Checking for offers every ${bs.inboxPeriodSec || 3} s · last checked ${ago == null ? '…' : ago + 's ago'}`,
    }
  })()

  // ── R140 §6.6 — the diagnostics drawer (§5.7): the chrome lives ONLY here (D6) ──
  const failingHops = BOND_HOPS.filter((h) => bs.hops[h] && bs.hops[h].ok === false)
  const drawer = {
    openOnLoad: failingHops.length > 0 || !!prose.terminal,
    anomaly: failingHops.length > 0,
    hops: BOND_HOPS.map((h) => {
      const hop = bs.hops[h]
      return {
        name: h,
        glyph: !hop ? BOND_GLYPHS.pending : hop.ok ? BOND_GLYPHS.done : BOND_GLYPHS.fail,
        state: !hop ? 'pending' : hop.ok ? 'done' : 'fail',
        detail: hop ? hop.detail : '',
        fix: !hop || hop.ok ? null : (h === 'relayRead' || h === 'relayWrite' ? { action: 'open-doctor', key: 'bondFixDoctor', fallback: 'Run the connection doctor' } : { action: 'open-diagnostics', key: 'bondFixDiagnostics', fallback: 'Open diagnostics' }),
      }
    }),
    identity: String(facts.beamIdentity || ''), // the Beam chrome renders ONLY inside the drawer (D6)
    openSettings: true, // the doctor's last resort, never its whole body (D5)
  }

  return {
    state: bs.state,
    headerStatus, // R140 F2 — the live connection status (the motto retired)
    rows,
    steps,
    prose,
    mailbox,
    inbox,
    buttons,
    availability,
    fallback,
    drawer,
    layoutOrder: BOND_LAYOUT_ORDER,
    clock: { waitSeconds: waitSec, elapsedMs: elapsed, budgetMs: budget, slowFired: !!bs.slowNoticedAt, pendingCompletion: !!bs.pendingCompletion },
  }
}
