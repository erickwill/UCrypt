/**
 * UCrypt — R81 "No Ghost Device, No Stuck Transfer" — TRANSFER LIFECYCLE CORE
 * (pure state machine + presence-precedence rules). New in v2.42.16.
 * R83 "Transfer That Recovers Safely" (v2.42.18): the ladder gained the
 * CONNECTING / VERIFYING / RECEIVER_SAVE_PENDING rungs, the RECEIVER-active
 * gate, the canonical reported-stage whitelist, the typed terminal-copy map
 * and the lazy sender-offer expiry rule — one shared machine for worker,
 * page and tests (owner order §R83-F2/F3).
 * R83 "Transfer That Recovers Safely" (v2.42.18): the ladder gained the
 * CONNECTING / VERIFYING / RECEIVER_SAVE_PENDING rungs, the RECEIVER-active
 * gate, the canonical reported-stage whitelist, the typed terminal-copy map
 * and the lazy sender-offer expiry rule — one shared machine for worker,
 * page and tests (owner order §R83-F2/F3).
 *
 * This module is PURE: no chrome.* APIs, no WebRTC, no crypto, no I/O. It holds
 * the ONE documented transfer state machine and the ONE presence-precedence
 * model so the worker (lib/transfer/worker.js), the rendezvous mailbox
 * (lib/transfer/mailbox.js) and the transfer page (lib/transfer/page.js) can
 * never disagree about what is active, what is terminal, and which presence
 * record wins. Everything here is directly unit-testable without a browser.
 *
 * Owner order (R81): do not loosen or merge the four planes to fix lifecycle
 * behavior; this module only NAMES the rules the planes already follow.
 */

// --- Transfer session states (the ONE ladder) ----------------------------------

/**
 * Sender/receiver session states. Non-terminal states are "the transfer can
 * still legitimately proceed"; terminal states are "one idempotent cleanup,
 * then the UI is ready again".
 */
export const TRANSFER_STATES = {
  // sender ladder
  OFFER_SENT: 'offer_sent',
  ANSWER_RECEIVED: 'answer_received',
  TRANSFERRING: 'transferring',
  // shared ladder rungs (R83): worker-session truth for connection/verify/
  // save-pending — reported by the page from REAL events, never invented.
  CONNECTING: 'connecting',
  VERIFYING: 'verifying',
  RECEIVER_SAVE_PENDING: 'receiver_save_pending',
  // receiver ladder
  OFFER_PENDING: 'offer_pending',
  ACCEPTED: 'accepted',
  // terminal (ALL of them — no exceptions, no "documented stuck states")
  COMPLETED: 'completed',
  RECEIVER_DECLINED: 'receiver_declined',
  CANCELLED: 'cancelled',
  EXPIRED: 'expired',
  FAILED: 'failed',
}

/** Terminal states: every one of these runs the single cleanup path. */
export const TERMINAL_STATES = new Set([
  TRANSFER_STATES.COMPLETED,
  TRANSFER_STATES.RECEIVER_DECLINED,
  TRANSFER_STATES.CANCELLED,
  TRANSFER_STATES.EXPIRED,
  TRANSFER_STATES.FAILED,
])

/** True when a session state can no longer proceed (and must be cleaned up). */
export function isTerminalState(state) {
  return TERMINAL_STATES.has(String(state || ''))
}

/** Non-terminal sender states — an active outgoing transfer blocks a second one. */
export const ACTIVE_SENDER_STATES = new Set([
  TRANSFER_STATES.OFFER_SENT,
  TRANSFER_STATES.ANSWER_RECEIVED,
  TRANSFER_STATES.CONNECTING,
  TRANSFER_STATES.TRANSFERRING,
  TRANSFER_STATES.VERIFYING,
])

/** True when a sender session counts as the device's one active outgoing transfer. */
export function isActiveSenderState(state) {
  return ACTIVE_SENDER_STATES.has(String(state || ''))
}

/**
 * R83 — non-terminal RECEIVER states. A receiver session occupies the
 * device's receiving surface from the moment the offer is opened until the
 * one-time export happens (or the session ends terminally). After the save
 * the session is a tombstone (RECEIVER_SAVE_PENDING) awaiting the one
 * TRANSFER_FINISH that runs the terminal cleanup.
 */
export const ACTIVE_RECEIVER_STATES = new Set([
  TRANSFER_STATES.OFFER_PENDING,
  TRANSFER_STATES.ACCEPTED,
  TRANSFER_STATES.TRANSFERRING,
  TRANSFER_STATES.VERIFYING,
  TRANSFER_STATES.RECEIVER_SAVE_PENDING,
])

/** True when a receiver session still occupies the receiving surface. */
export function isActiveReceiverState(state) {
  return ACTIVE_RECEIVER_STATES.has(String(state || ''))
}

/** True when ANY session (either role) still occupies its surface. */
export function isActiveSessionState(state) {
  return isActiveSenderState(state) || isActiveReceiverState(state)
}

/**
 * Terminal cleanup plan for a session. PURE: returns what the caller (worker
 * or page) must clear. The cleanup itself is idempotent by construction —
 * clearing something already cleared is a no-op — and the plan is identical
 * for every terminal state, so no terminal path can forget a resource.
 */
export function cleanupPlan(reason) {
  return {
    terminal: true,
    reason: String(reason || 'unknown'),
    clearSession: true,
    clearChannel: true,
    clearPeerConnection: true,
    clearChunkQueue: true,
    clearEphemeralKeys: true,
    clearWatchdogs: true,
    clearProgressUI: true,
    restoreReadyControls: true,
  }
}

/**
 * Whether a retry after a terminal state must use fresh material. The owner
 * order is absolute: a new transfer ID, a new capability nonce, new ephemeral
 * keys, a new offer. Nothing from the failed session may be reused.
 */
export function retryRequiresFreshMaterial() {
  return true
}

// --- Presence state model (R81-F1) ------------------------------------------------

/** Presence states carried INSIDE the sealed presence payload (v2 fields). */
export const PRESENCE_STATES = {
  AVAILABLE: 'available',
  WITHDRAWN: 'withdrawn',
}

/**
 * Default freshness threshold (ms): presence older than this is still an
 * advertisement, but the UI must show "Presence may be stale" instead of a
 * live "Available". The refresh cadence is 60 s (worker), so 2.5× the
 * cadence tolerates two missed refreshes before doubt is shown.
 */
export const PRESENCE_FRESH_THRESHOLD_MS = 150 * 1000

/**
 * Evaluate ONE presence record against the local precedence state.
 *
 * @param {object|null} payload the DECRYPTED presence payload (or null)
 * @param {{now?:number}} opts
 * @returns {{usable:boolean, state:'available'|'withdrawn'|'unknown',
 *            sequence:number, stale:boolean, reason?:string}}
 *   usable=false means the record must NOT be shown as available (skip it).
 */
export function evaluatePresenceRecord(payload, opts = {}) {
  const now = Number(opts.now) || Date.now()
  if (!payload || typeof payload !== 'object' || !payload.deviceId) {
    return { usable: false, state: 'unknown', sequence: 0, stale: false, reason: 'malformed' }
  }
  // Legacy records (R76–R79) carry no presenceState and no sequence: they are
  // advertisements, read as 'available' with sequence 0 (compat rule).
  const state = payload.presenceState === PRESENCE_STATES.WITHDRAWN
    ? PRESENCE_STATES.WITHDRAWN
    : PRESENCE_STATES.AVAILABLE
  const sequence = Number.isInteger(payload.sequence) && payload.sequence >= 0 ? payload.sequence : 0
  const publishedAt = Date.parse(payload.publishedAt || '') || 0
  const stale = state === PRESENCE_STATES.AVAILABLE &&
    publishedAt > 0 && (now - publishedAt) > PRESENCE_FRESH_THRESHOLD_MS
  return { usable: true, state, sequence, stale }
}

/**
 * Withdrawn high-water gate: the device-local memory of the newest WITHDRAWN
 * sequence seen for each deviceId. An 'available' record whose sequence is
 // not STRICTLY newer than the remembered withdrawal must not resurrect the
 * device ("stale available cannot override later withdrawn"). Withdrawn
 * records always update the high-water mark.
 *
 * @param {Record<string, number>|undefined} highWater deviceId → newest withdrawn sequence
 * @param {{deviceId:string, state:string, sequence:number}} evaluated
 * @returns {{accept:boolean, next:Record<string, number>, reason?:string}}
 *   accept=true when the record may be shown/learned; next is the updated map.
 */
export function applyPresenceHighWater(highWater, evaluated) {
  const map = { ...(highWater && typeof highWater === 'object' ? highWater : {}) }
  const id = String(evaluated && evaluated.deviceId || '')
  if (!id) return { accept: false, next: map, reason: 'malformed' }
  const current = Number.isInteger(map[id]) ? map[id] : -1
  if (evaluated.state === PRESENCE_STATES.WITHDRAWN) {
    if (evaluated.sequence > current) map[id] = evaluated.sequence
    return { accept: true, next: map }
  }
  // available: must be strictly newer than any remembered withdrawal.
  if (evaluated.sequence <= current) {
    return { accept: false, next: map, reason: 'stale_resurrection' }
  }
  return { accept: true, next: map }
}

// --- User-visible stage ladder (R81-F3) ----------------------------------------------

/**
 * The exact ladder the owner order mandates, in display order. The transfer
 * page maps runtime events onto these stages; text lives in the locales, the
 * NAMES live here so worker/page/tests agree.
 */
export const SEND_STAGES = {
  PREPARING: 'preparing',
  REQUEST_PUBLISHED: 'request_published',
  WAITING_ANSWER: 'waiting_answer',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  TRANSFERRING: 'transferring',
  VERIFYING: 'verifying',
  COMPLETED: 'completed',
}

/** Terminal SEND outcomes (map 1:1 onto TRANSFER_STATES terminal set). */
export const SEND_TERMINAL_OUTCOMES = {
  DECLINED: TRANSFER_STATES.RECEIVER_DECLINED,
  CANCELLED: TRANSFER_STATES.CANCELLED,
  EXPIRED: TRANSFER_STATES.EXPIRED,
  FAILED: TRANSFER_STATES.FAILED,
  COMPLETED: TRANSFER_STATES.COMPLETED,
}

/**
 * Bounded per-stage deadlines (ms). The owner order: every stage has a
 * deadline; a breach converts to a TYPED terminal state (never a silent
 * hang, never a guessed re-label).
 */
export const STAGE_DEADLINES_MS = {
  [SEND_STAGES.PREPARING]: 20 * 1000,        // file hashing + offer build
  [SEND_STAGES.REQUEST_PUBLISHED]: 20 * 1000,// cloud publish (or manual fallback)
  [SEND_STAGES.WAITING_ANSWER]: 10 * 60 * 1000, // offer TTL (receiver has 10 min)
  [SEND_STAGES.CONNECTING]: 45 * 1000,       // SDP answer applied → channel open
  [SEND_STAGES.TRANSFERRING]: 60 * 1000,     // inactivity deadline (reset on progress)
  [SEND_STAGES.VERIFYING]: 90 * 1000,        // receiver SHA-256 + explicit save
}

/** Deadline for a stage, or null when the stage has none (never guessed). */
export function stageDeadlineMs(stage) {
  const v = STAGE_DEADLINES_MS[String(stage || '')]
  return Number.isFinite(v) ? v : null
}

/**
 * Watchdog evaluation: given the current stage, when it was entered, and the
 * last progress tick, decide whether the deadline has been breached. PURE.
 *
 * @returns {{breached:boolean, terminalOutcome?:string}}
 */
export function evaluateStageWatchdog({ stage, enteredAt, lastProgressAt, now = Date.now() }) {
  const deadline = stageDeadlineMs(stage)
  if (deadline == null || !Number.isFinite(enteredAt)) return { breached: false }
  const anchor = stage === SEND_STAGES.TRANSFERRING
    ? Math.max(Number(lastProgressAt) || 0, Number(enteredAt) || 0)
    : Number(enteredAt) || 0
  if (now - anchor > deadline) {
    return {
      breached: true,
      terminalOutcome: stage === SEND_STAGES.WAITING_ANSWER
        ? SEND_TERMINAL_OUTCOMES.EXPIRED
        : SEND_TERMINAL_OUTCOMES.FAILED,
    }
  }
  return { breached: false }
}

/**
 * R83 — stages the transfer PAGE may report into the canonical worker
 * session (TRANSFER_REPORT_STAGE). The worker knows ANSWER_RECEIVED (answer
 * opened) and TRANSFERRING (chunks sealing) from protocol events itself;
 * CONNECTING and VERIFYING are visible only to the page (WebRTC/SDP and the
 * pump tail), so the page REPORTS them from real events — never on a timer.
 * Anything else is refused (typed) — the worker session cannot be pushed
 * into a state the reporter is not allowed to claim.
 */
export const REPORTABLE_STAGES = new Set([
  TRANSFER_STATES.CONNECTING,
  TRANSFER_STATES.VERIFYING,
])

/** True when a page-reported stage may update the canonical session state. */
export function isReportableStage(stage) {
  return REPORTABLE_STAGES.has(String(stage || ''))
}

/**
 * R83 — lazy sender-offer expiry rule. An OFFER_SENT session whose
 * authenticated expiry has passed is dead: the worker sweeps it to EXPIRED
 * (terminal cleanup) instead of holding the one-active-send gate closed
 * forever when the page that owned the watchdog is gone. PURE.
 *
 * @param {{state?:string, expiresAt?:string}} session
 * @param {number} [now]
 * @returns {boolean} true when the session must be swept to EXPIRED.
 */
export function senderOfferExpired(session, now = Date.now()) {
  if (!session || typeof session !== 'object') return false
  if (session.state !== TRANSFER_STATES.OFFER_SENT) return false
  const t = Date.parse(session.expiresAt || '')
  return Number.isFinite(t) && t <= now
}

/**
 * R83 — THE typed terminal-copy map. ONE table owns the recovery action for
 * every terminal outcome, so worker/tests/page can never disagree about
 * what a terminal state tells the user to do next. Keys reference locale
 * messages; fallbacks mirror them for pre-locale rendering.
 *
 * @param {string} outcome a TRANSFER_STATES terminal value
 * @returns {{key:string, fallback:string}}
 */
export function terminalResultFor(outcome) {
  switch (String(outcome || '')) {
    case TRANSFER_STATES.RECEIVER_DECLINED:
      return { key: 'transferTermDeclinedNext', fallback: 'Receiver declined — choose another device or send a different file.' }
    case TRANSFER_STATES.CANCELLED:
      return { key: 'transferTermCancelledNext', fallback: 'Transfer cancelled — Send another file.' }
    case TRANSFER_STATES.EXPIRED:
      return { key: 'transferTermExpired', fallback: 'Request expired — the other device did not respond in time. Request the transfer again.' }
    case TRANSFER_STATES.COMPLETED:
      return { key: 'transferSendDoneConfirm', fallback: 'Delivered — the other device verified the file.' }
    case TRANSFER_STATES.FAILED:
    default:
      return { key: 'transferFailNoRoute', fallback: 'Could not establish a direct route — the transfer stopped safely. Try again.' }
  }
}

/**
 * Route classification from WebRTC stats (R81-F3 honesty rule): the label
 * "direct" is allowed ONLY when the selected candidate pair provably uses
 * host↔host candidates; "relay" only for a relay pair; anything else —
 * including stats being unavailable — must render as "route type unavailable".
 * PURE over the already-extracted stats array.
 *
 * @param {Array<{type:string,state:string,selected?:boolean,
 *                 localCandidateId?:string,remoteCandidateId?:string,nominated?:boolean}>} stats
 * @param {Map<string,{candidateType?:string}>|null} candidates id → candidate stats
 */
export function classifyRoute(stats, candidates) {
  if (!Array.isArray(stats) || !(candidates instanceof Map)) return 'unavailable'
  const pair = stats.find(s => s && s.type === 'candidate-pair' &&
    (s.state === 'succeeded') && (s.selected === true || s.nominated === true))
  if (!pair) return 'unavailable'
  const local = candidates.get(pair.localCandidateId)
  const remote = candidates.get(pair.remoteCandidateId)
  if (!local || !remote) return 'unavailable'
  if (local.candidateType === 'relay' || remote.candidateType === 'relay') return 'relay'
  if (local.candidateType === 'host' && remote.candidateType === 'host') return 'direct'
  return 'unavailable'
}
