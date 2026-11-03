/**
 * UCrypt — R138 §4 — THE HANDSHAKE ("two devices, seconds apart, one chain").
 *
 * ONE machine, ONE truth (§4.1): every renderable element on the transfer
 * surface derives from THIS machine through projectHandshake() — readiness
 * rows, glyphs, prose lines, buttons, the step rail, the fallback panel.
 * Independent polling writers are retired from the presentation layer:
 * there is nothing left to contradict, because there is only one writer.
 *
 *   IDLE → ARMED → SEARCHING → PAIRED → CONNECTED → OFFERED → TRANSFERRING
 *   → DONE, and the typed terminal FAILED(reason) — every transition
 *   visible and bounded: a state the machine enters must either progress,
 *   produce a typed terminal, or produce a visible waiting state with a
 *   live counter — never a silent stall.
 *
 * The TWO-WAY MANUAL PROTOCOL (§4.2, six explicit steps) is a first-class
 * path: the answer signal exists the instant the inbound signal opens, its
 * return path is stated in plain copy, an applied answer deterministically
 * reaches CONNECTED (or a typed failure) within the budget, and NO step
 * ever needs to be repeated (idempotent opens — the no-redo law).
 *
 * Discovery budgets (F3, binding): advertise on arm within 2 seconds; the
 * live 'Searching… Xs' counter; p50 ≤ 5 s same-network / ≤ 15 s via relay,
 * else a typed slow-path notice with the reason. The per-hop telemetry
 * (F4: arm, advertise, relayWrite, relayRead, roster, render) feeds the
 * diagnostics drawer and the doctor card 'Why can't we see each other?'.
 *
 * The tri-state glyph law (F5): done (✓) / active (▶) / pending (·) — no
 * check may ever adorn an unfulfilled state and no failure glyph may adorn
 * a satisfied one; the projection makes that contradiction impossible by
 * construction (glyph and text derive from the same fact in one function).
 *
 * PURE — no DOM, no chrome.*, no timers at import time. Battery-pinned
 * (G83 H1–H8; the R138 handshake battery).
 */

import { BEAM3_SIGNAL_TTL_MS } from './planes.js'

/** The handshake states (§4.1's exact vocabulary). */
export const HS_STATES = {
  IDLE: 'IDLE',
  ARMED: 'ARMED',
  SEARCHING: 'SEARCHING',
  PAIRED: 'PAIRED',
  CONNECTED: 'CONNECTED',
  OFFERED: 'OFFERED',
  TRANSFERRING: 'TRANSFERRING',
  DONE: 'DONE',
  FAILED: 'FAILED',
}

/** The typed handshake events. */
export const HS_EVENTS = {
  ARM: 'ARM', // intent declared — availability armed (auto), advertisement scheduled
  ADVERTISED: 'ADVERTISED', // the advertisement confirmed out (the ≤2s F3 budget)
  DISARM: 'DISARM', // Stop pressed — back to IDLE (the instant hide)
  SIGHT: 'SIGHT', // a peer appeared in the roster (telemetry; stays searching)
  PAIR_OPEN: 'PAIR_OPEN', // an inbound peer signal opened (manual step 2 → the answer exists)
  ANSWER_APPLIED: 'ANSWER_APPLIED', // the answer signal opened here (manual step 3) — deterministic connect
  TRANSPORT_CONFIRMED: 'TRANSPORT_CONFIRMED', // the transport confirmed the pair before the user acted
  CODES_MATCH: 'CODES_MATCH', // the user confirmed the 4×4 code ('Codes match — connect')
  OFFER: 'OFFER', // the sender's manifest went out
  OFFER_IN: 'OFFER_IN', // the receiver's offer card rendered
  ACCEPT: 'ACCEPT',
  DECLINE: 'DECLINE',
  BEGIN: 'BEGIN', // the transfer began (chunks moving)
  CHUNKS_DONE: 'CHUNKS_DONE', // the last chunk acknowledged (still TRANSFERRING until verified)
  VERIFY_OK: 'VERIFY_OK',
  VERIFY_FAIL: 'VERIFY_FAIL',
  NETWORK_FAIL: 'NETWORK_FAIL',
  EXPIRE: 'EXPIRE', // the signal horizon fired on an unconsumed signal
  RESET: 'RESET', // the user's one dismiss action (terminals stay until this)
}

/** The typed FAILED reasons (each carries its fix affordance in the projection). */
export const HS_FAIL_REASONS = {
  declined: 'declined',
  expired: 'expired',
  invalid: 'invalid',
  replay: 'replay',
  network: 'network',
  integrity: 'integrity',
  stalled: 'stalled',
}

/** The legal-edge table — every other edge throws (typed, never silence). */
export const HS_TRANSITIONS = {
  [`${HS_STATES.IDLE}|${HS_EVENTS.ARM}`]: HS_STATES.ARMED,
  [`${HS_STATES.IDLE}|${HS_EVENTS.PAIR_OPEN}`]: HS_STATES.PAIRED, // manual inbound on a fresh surface
  [`${HS_STATES.IDLE}|${HS_EVENTS.EXPIRE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.expired}`,
  [`${HS_STATES.ARMED}|${HS_EVENTS.ADVERTISED}`]: HS_STATES.SEARCHING,
  [`${HS_STATES.ARMED}|${HS_EVENTS.PAIR_OPEN}`]: HS_STATES.PAIRED,
  // the sender's answer application: the answer's EXISTENCE proves the peer
  // paired with my signal — pairing and connect land in one bounded transition
  // (the no-redo law: the sender never repeats a pairing act)
  [`${HS_STATES.ARMED}|${HS_EVENTS.ANSWER_APPLIED}`]: HS_STATES.CONNECTED,
  [`${HS_STATES.ARMED}|${HS_EVENTS.DISARM}`]: HS_STATES.IDLE,
  [`${HS_STATES.ARMED}|${HS_EVENTS.EXPIRE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.expired}`,
  [`${HS_STATES.SEARCHING}|${HS_EVENTS.SIGHT}`]: HS_STATES.SEARCHING, // roster truth updates; the search continues
  [`${HS_STATES.SEARCHING}|${HS_EVENTS.PAIR_OPEN}`]: HS_STATES.PAIRED,
  [`${HS_STATES.SEARCHING}|${HS_EVENTS.ANSWER_APPLIED}`]: HS_STATES.CONNECTED,
  [`${HS_STATES.SEARCHING}|${HS_EVENTS.DISARM}`]: HS_STATES.IDLE,
  [`${HS_STATES.SEARCHING}|${HS_EVENTS.EXPIRE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.expired}`,
  [`${HS_STATES.PAIRED}|${HS_EVENTS.ANSWER_APPLIED}`]: HS_STATES.CONNECTED,
  [`${HS_STATES.PAIRED}|${HS_EVENTS.TRANSPORT_CONFIRMED}`]: HS_STATES.CONNECTED,
  [`${HS_STATES.PAIRED}|${HS_EVENTS.CODES_MATCH}`]: HS_STATES.CONNECTED,
  [`${HS_STATES.PAIRED}|${HS_EVENTS.EXPIRE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.expired}`,
  [`${HS_STATES.CONNECTED}|${HS_EVENTS.OFFER}`]: HS_STATES.OFFERED,
  [`${HS_STATES.CONNECTED}|${HS_EVENTS.OFFER_IN}`]: HS_STATES.OFFERED,
  [`${HS_STATES.OFFERED}|${HS_EVENTS.ACCEPT}`]: HS_STATES.TRANSFERRING,
  [`${HS_STATES.OFFERED}|${HS_EVENTS.DECLINE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.declined}`,
  [`${HS_STATES.OFFERED}|${HS_EVENTS.NETWORK_FAIL}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.network}`,
  [`${HS_STATES.OFFERED}|${HS_EVENTS.EXPIRE}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.expired}`,
  [`${HS_STATES.TRANSFERRING}|${HS_EVENTS.CHUNKS_DONE}`]: HS_STATES.TRANSFERRING, // the verify receipt is the DONE gate
  [`${HS_STATES.TRANSFERRING}|${HS_EVENTS.VERIFY_OK}`]: HS_STATES.DONE,
  [`${HS_STATES.TRANSFERRING}|${HS_EVENTS.VERIFY_FAIL}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.integrity}`,
  [`${HS_STATES.TRANSFERRING}|${HS_EVENTS.NETWORK_FAIL}`]: `${HS_STATES.FAILED}:${HS_FAIL_REASONS.network}`,
  [`${HS_STATES.DONE}|${HS_EVENTS.RESET}`]: HS_STATES.IDLE,
  [`${HS_STATES.FAILED}|${HS_EVENTS.RESET}`]: HS_STATES.IDLE,
}

export function hsError(code, detail) {
  const e = new Error(`HS_${code}: ${detail}`)
  e.code = `HS_${code}`
  return e
}

/** The pure step. The FAILED target carries its typed reason. Throws on an illegal edge. */
export function hsStep(state, event) {
  const next = HS_TRANSITIONS[`${state}|${event}`]
  if (!next) throw hsError('STATE_ILLEGAL', `${event} in ${state}`)
  if (next.startsWith(`${HS_STATES.FAILED}:`)) return { state: HS_STATES.FAILED, reason: next.split(':')[1] }
  return { state: next, reason: null }
}

/** The tri-state glyphs (F5) — the ONLY glyph vocabulary the projection emits. */
export const HS_GLYPHS = { done: '✓', active: '▶', pending: '·', fail: '✗' }

/** The discovery budgets (F3 — binding, machine-derived). */
export const HS_BUDGETS = {
  advertiseMs: 2000, // advertise on arm within 2 seconds
  directP50Ms: 5000, // p50 ≤ 5 s same-network
  relayP50Ms: 15000, // p50 ≤ 15 s via cloud relay
  stallMs: 30000, // a wait longer than this is a TYPED notice, never silent
  pollMinMs: 2000, // 2–4 s jittered polling while SEARCHING
  pollMaxMs: 4000,
}

/** The per-hop telemetry names (F4 — the presence path, each a testable seam). */
export const HS_HOPS = ['arm', 'advertise', 'relayWrite', 'relayRead', 'roster', 'render']

/** The six-step two-way manual protocol (§4.2) — phase-correct copy (F10). */
export const HS_MANUAL_STEPS = [
  { n: 1, key: 'hsManualStep1', phase: 'pairing', fallback: 'Step 1 — Copy this device\'s signal. It is a discovery signal for your chain — safe to paste into the other device; it is not a secret.' },
  { n: 2, key: 'hsManualStep2', phase: 'pairing', fallback: 'Step 2 — On the other device, paste this signal and press Open signal. That device immediately shows an answer — copy the answer back to this device.' },
  { n: 3, key: 'hsManualStep3', phase: 'pairing', fallback: 'Step 3 — Paste the answer here and press Open answer. If your cloud is connected the answer may arrive by itself — this step is skipped and the surface says which return path was used.' },
  { n: 4, key: 'hsManualStep4', phase: 'pairing', fallback: 'Step 4 — The same 4×4 code shows on both screens. Press Codes match — connect when they match.' },
  { n: 5, key: 'hsManualStep5', phase: 'connected', fallback: 'Step 5 — Connected. Pick the file and press Send — sending is the last step of the flow.' },
  { n: 6, key: 'hsManualStep6', phase: 'terminal', fallback: 'Step 6 — The receipt stays on screen until you dismiss it. Nothing closes by itself.' },
]

/** The typed fix affordances (every red row and every FAILED carries one — §4.1). */
export const HS_FIX = {
  arm: { action: 'open-cloud-sync', key: 'hsFixArm', fallback: 'Check availability in Cloud Sync' },
  chain: { action: 'open-cloud-sync', key: 'hsFixChain', fallback: 'Connect your cloud' },
  route: { action: 'show-intent', key: 'hsFixRoute', fallback: 'Choose Send or Receive' },
  devices: { action: 'show-pairing', key: 'hsFixDevices', fallback: 'Pair by code' },
  advertise: { action: 'open-diagnostics', key: 'hsFixAdvertise', fallback: 'Open diagnostics' },
  relayWrite: { action: 'open-diagnostics', key: 'hsFixRelay', fallback: 'Check your cloud connection' },
  relayRead: { action: 'open-diagnostics', key: 'hsFixRelay', fallback: 'Check your cloud connection' },
  roster: { action: 'show-pairing', key: 'hsFixRoster', fallback: 'Pair by code' },
  render: { action: 'reload-surface', key: 'hsFixRender', fallback: 'Reload this tab' },
  declined: { action: 'show-intent', key: 'hsFixDeclined', fallback: 'Start again — pick Send or Receive' },
  expired: { action: 'regenerate', key: 'hsFixExpired', fallback: 'Regenerate the signal' },
  invalid: { action: 'show-pairing', key: 'hsFixInvalid', fallback: 'Paste the signal again' },
  replay: { action: 'regenerate', key: 'hsFixReplay', fallback: 'Ask the other device to regenerate' },
  network: { action: 'resume', key: 'hsFixNetwork', fallback: 'Resume the transfer' },
  integrity: { action: 'retry', key: 'hsFixIntegrity', fallback: 'Try the transfer again' },
  stalled: { action: 'open-diagnostics', key: 'hsFixStalled', fallback: 'Open diagnostics' },
}

/** The plane→budget mapping (F3). */
export function budgetFor(plane) {
  return plane === 'B' ? HS_BUDGETS.relayP50Ms : HS_BUDGETS.directP50Ms
}

/**
 * THE HANDSHAKE SESSION — one machine per transfer journey, one truth per
 * surface. Pure: the caller persists the serializable snapshot if it wants
 * crash-safety (the transfer machine's journal remains the transfer-side
 * record; this machine is the journey record).
 */
export class HandshakeSession {
  constructor({ role = 'send', now = Date.now(), sessionId = '' } = {}) {
    if (!['send', 'receive'].includes(role)) throw hsError('ROLE', 'role must be send|receive')
    this.role = role
    this.sessionId = String(sessionId || '')
    this.state = HS_STATES.IDLE
    this.reason = null
    this.armedAt = 0
    this.advertisedAt = 0
    this.searchStartedAt = 0
    this.firstSightAt = 0
    this.pairedAt = 0
    this.connectedAt = 0
    this.doneAt = 0
    this.failedAt = 0
    this.lastProgressAt = now
    // the manual protocol bookkeeping (§4.2) — the no-redo law lives here
    this.mySignalText = ''
    this.openedPeerSignalText = ''
    this.answerText = ''
    this.answerViaRelay = false
    this.answerAppliedAt = 0
    this.codesMatchedAt = 0
    this.idempotentOpens = 0
    // the per-hop telemetry (F4)
    this.hops = {}
    // the measured discovery latencies (F3 — land in r138-readiness-inputs.json)
    this.latencies = {}
  }

  /** Fire a typed event. Idempotent-friendly where the law demands it. */
  fire(event, meta = {}) {
    const from = this.state
    // the no-redo law: repeating a completed pairing action is a friendly no-op
    if (event === HS_EVENTS.PAIR_OPEN && (this.state === HS_STATES.PAIRED || this.state === HS_STATES.CONNECTED)) {
      if (meta.text && meta.text === this.openedPeerSignalText) {
        this.idempotentOpens += 1
        return { state: this.state, reason: null, idempotent: true }
      }
    }
    if (event === HS_EVENTS.ANSWER_APPLIED && this.state === HS_STATES.CONNECTED && this.answerAppliedAt) {
      return { state: this.state, reason: null, idempotent: true }
    }
    // the transport or the user confirming AFTER connect is a confirmation of
    // what already happened — never a gate that can strand or fork the journey
    if ((event === HS_EVENTS.CODES_MATCH || event === HS_EVENTS.TRANSPORT_CONFIRMED) && this.state === HS_STATES.CONNECTED && this.connectedAt) {
      if (event === HS_EVENTS.CODES_MATCH) this.codesMatchedAt = Number(meta.now) || Date.now()
      return { state: this.state, reason: null, idempotent: true }
    }
    const step = hsStep(from, event)
    this.state = step.state
    this.reason = step.reason
    const at = Number(meta.now) || Date.now()
    this.lastProgressAt = at
    if (event === HS_EVENTS.ARM) this.armedAt = at
    if (event === HS_EVENTS.ADVERTISED) {
      this.advertisedAt = at
      this.searchStartedAt = at
      if (this.armedAt) this.latencies.advertise = at - this.armedAt
    }
    if (event === HS_EVENTS.SIGHT && !this.firstSightAt) this.firstSightAt = at
    if (event === HS_EVENTS.PAIR_OPEN) {
      this.pairedAt = at
      if (meta.text) this.openedPeerSignalText = String(meta.text)
      if (this.searchStartedAt) this.latencies.pair = at - this.searchStartedAt
    }
    if (event === HS_EVENTS.ANSWER_APPLIED) {
      this.answerAppliedAt = at
      this.connectedAt = at
      this.latencies.connect = this.pairedAt ? at - this.pairedAt : 0
    }
    if (event === HS_EVENTS.TRANSPORT_CONFIRMED || event === HS_EVENTS.CODES_MATCH) {
      if (!this.connectedAt) this.connectedAt = at
      if (event === HS_EVENTS.CODES_MATCH) this.codesMatchedAt = at
    }
    if (event === HS_EVENTS.VERIFY_OK) this.doneAt = at
    if (this.state === HS_STATES.FAILED) this.failedAt = at
    return { state: this.state, reason: this.reason, idempotent: false, from }
  }

  /** Record one hop of the presence path (F4). */
  recordHop(name, { ok = true, detail = '', at = Date.now() } = {}) {
    if (!HS_HOPS.includes(name)) throw hsError('HOP', `unknown hop ${name}`)
    const prev = this.hops[name]
    const ms = prev && prev.at ? Math.max(0, at - prev.at) : 0
    this.hops[name] = { ok: !!ok, detail: String(detail || ''), at, ms }
    this.lastProgressAt = at
    return this.hops[name]
  }

  /** The signal horizon (the 24h law — only while UNPAIRED). */
  expiredAt(now = Date.now(), signalIssuedAt = 0) {
    if (![HS_STATES.IDLE, HS_STATES.ARMED, HS_STATES.SEARCHING].includes(this.state)) return false
    if (!signalIssuedAt) return false
    return now >= signalIssuedAt + BEAM3_SIGNAL_TTL_MS
  }

  /** The live search counter ('Searching… Xs' — F3, the wait is never silent). */
  searchSeconds(now = Date.now()) {
    if (this.state !== HS_STATES.SEARCHING || !this.searchStartedAt) return 0
    return Math.max(0, Math.floor((now - this.searchStartedAt) / 1000))
  }

  /** The latency verdict (F3): met / slow-path typed notice with the reason. */
  latencyVerdict(now = Date.now()) {
    const plane = this.latencies.plane || 'A'
    const budget = budgetFor(plane)
    const start = this.searchStartedAt || this.armedAt
    const elapsed = start ? Math.max(0, (this.connectedAt || this.pairedAt || now) - start) : 0
    const met = !start || elapsed <= budget
    return {
      plane,
      budgetMs: budget,
      elapsedMs: elapsed,
      met,
      slowPathWords: met
        ? ''
        : plane === 'B'
          ? 'Taking longer than usual through your cloud relay — the slow hop is named in the diagnostics drawer; run the connection doctor there.'
          : 'Taking longer than usual on the same network — the slow hop is named in the diagnostics drawer; run the connection doctor there.',
    }
  }

  /** The stall verdict (the determinism clause — a 30s wait is TYPED, never silent, never auto-dismissed). */
  stallVerdict(now = Date.now()) {
    if ([HS_STATES.DONE, HS_STATES.FAILED, HS_STATES.IDLE].includes(this.state)) return { stalled: false, sinceMs: 0, words: '' }
    const since = Math.max(0, now - this.lastProgressAt)
    if (since <= HS_BUDGETS.stallMs) return { stalled: false, sinceMs: since, words: '' }
    const words = {
      [HS_STATES.ARMED]: 'The advertisement has not confirmed yet — open the diagnostics drawer to see which hop is waiting.',
      [HS_STATES.SEARCHING]: 'Still searching longer than expected — open the diagnostics drawer, or pair by code below; both paths stay open.',
      [HS_STATES.PAIRED]: 'Paired but not connected yet — open the diagnostics drawer, or press Codes match — connect if the codes agree.',
      [HS_STATES.CONNECTED]: 'Connected but nothing moved yet — pick the file and press Send (sending is the last step).',
      [HS_STATES.OFFERED]: 'Waiting on the accept decision — the card stays until you decide.',
      [HS_STATES.TRANSFERRING]: 'The transfer is slower than expected — it continues; the receipt stays until you dismiss it.',
    }[this.state] || 'Waiting — open the diagnostics drawer for the live hop trace.'
    return { stalled: true, sinceMs: since, words }
  }

  /** Serializable snapshot (the crash-safe law — the caller persists it). */
  snapshot() {
    return {
      role: this.role,
      sessionId: this.sessionId,
      state: this.state,
      reason: this.reason,
      armedAt: this.armedAt,
      advertisedAt: this.advertisedAt,
      searchStartedAt: this.searchStartedAt,
      firstSightAt: this.firstSightAt,
      pairedAt: this.pairedAt,
      connectedAt: this.connectedAt,
      doneAt: this.doneAt,
      failedAt: this.failedAt,
      lastProgressAt: this.lastProgressAt,
      mySignalText: this.mySignalText,
      openedPeerSignalText: this.openedPeerSignalText,
      answerText: this.answerText,
      answerViaRelay: this.answerViaRelay,
      answerAppliedAt: this.answerAppliedAt,
      codesMatchedAt: this.codesMatchedAt,
      idempotentOpens: this.idempotentOpens,
      hops: { ...this.hops },
      latencies: { ...this.latencies },
    }
  }

  static from(snapshot) {
    const s = new HandshakeSession({ role: snapshot.role || 'send', sessionId: snapshot.sessionId || '' })
    Object.assign(s, snapshot, { hops: { ...(snapshot.hops || {}) }, latencies: { ...(snapshot.latencies || {}) } })
    return s
  }
}

/**
 * THE SINGLE-WRITER PROJECTION (F2, §4.1): EVERY rendered element of the
 * transfer surface derives from THIS function — the readiness rows, the
 * glyphs, the prose, the buttons, the step rail, the fallback decision.
 * Glyph and text derive from the same fact in the same expression, so a
 * row whose text says connected can never carry a failure glyph, and a
 * pending decision can never carry a check. The retired contradiction
 * strings are unrepresentable here by construction.
 *
 * @param {HandshakeSession} hs
 * @param {{chainJoined?:boolean, visibleDevices?:number, plane?:string|null,
 *          relayLabel?:string, relayConnected?:boolean, now?:number}} facts
 * @returns {{rows:Array, steps:Array, prose:Object, buttons:Object, fallback:Object, drawer:Object}}
 */
export function projectHandshake(hs, facts = {}) {
  const now = Number(facts.now) || Date.now()
  const chainOk = !!facts.chainJoined
  const devices = Math.max(0, Number(facts.visibleDevices) || 0)
  const plane = facts.plane || null
  const relayOk = !!facts.relayConnected

  // ── the readiness rows: glyph + text + fix derive from ONE fact each ──
  const rows = []
  rows.push(
    chainOk
      ? { id: 'chain', glyph: HS_GLYPHS.done, state: 'done', key: 'hsRowChainOk', fallback: 'Sync chain joined', fix: null }
      : { id: 'chain', glyph: HS_GLYPHS.fail, state: 'fail', key: 'hsRowChainNo', fallback: 'Sync chain not joined — join or create one to transfer between your devices', fix: HS_FIX.chain },
  )
  // the route row (F5): a pending CHOICE is a pending dot with the linked action — never a check;
  // a chosen plane states the plane truth in one plain line (§4.4 — intent first, route second).
  // R138 I18N-3 (the redundancy law): the route line REUSES the canonical
  // beam3Route* keys (routeTruthLine's own strings) — one sentence per truth,
  // never a duplicate writer.
  if (plane) {
    const routeKey = { A: 'beam3RouteDirect', B: 'beam3RouteRelay', C: 'beam3RouteManual' }[plane] || 'beam3RouteUnknown'
    const line = {
      A: 'Route: same network — direct device-to-device, end-to-end encrypted.',
      B: `Route: through your connected ${facts.relayLabel || 'cloud'} — sealed chunks only, end-to-end encrypted.`,
      C: 'Route: manual exchange — the code travels with you; the transfer completes device-to-device when a path exists.',
    }[plane] || 'Route chosen.'
    rows.push({ id: 'route', glyph: HS_GLYPHS.done, state: 'done', key: routeKey, fallback: line, fix: null })
  } else {
    rows.push({ id: 'route', glyph: HS_GLYPHS.pending, state: 'pending', key: 'hsRowRoutePending', fallback: 'Route not chosen yet — pick Send or Receive below', fix: HS_FIX.route })
  }
  // the devices row: zero visible is a FAIL with the pairing fix when the user is
  // past intent; the text never claims what the glyph denies (the F2 law)
  if (devices > 0) {
    rows.push({ id: 'devices', glyph: HS_GLYPHS.done, state: 'done', key: 'hsRowDevicesOk', fallback: `${devices} device(s) visible on your chain`, fix: null })
  } else if (hs.state === HS_STATES.IDLE) {
    rows.push({ id: 'devices', glyph: HS_GLYPHS.pending, state: 'pending', key: 'hsRowDevicesPending', fallback: 'Devices appear here once you pick Send or Receive (or pair by code)', fix: HS_FIX.route })
  } else {
    rows.push({ id: 'devices', glyph: HS_GLYPHS.fail, state: 'fail', key: 'hsRowDevicesNone', fallback: 'No other chain device visible yet — the other device must be online with availability armed (or pair by code)', fix: HS_FIX.devices })
  }

  // ── the step rail (F6): every row is a deep link; the tri-state glyphs; auto-advance by completion ──
  const journey = [
    { id: 'intent', label: 'Choose Send or Receive', key: 'hsRailIntent', doneAt: hs.armedAt },
    { id: 'readiness', label: 'Check the readiness strip', key: 'hsRailReadiness', doneAt: hs.armedAt && (chainOk || plane) ? hs.armedAt : 0 },
    { id: 'pair', label: 'Pair the devices', key: 'hsRailPair', doneAt: hs.pairedAt },
    { id: 'confirm', label: 'Confirm the code — compare the 4×4 code on both screens', key: 'hsRailConfirm', doneAt: hs.connectedAt },
    { id: 'transfer', label: 'Transfer — pick the file and press Send (the last step), or await the offer', key: 'hsRailTransfer', doneAt: hs.state === HS_STATES.OFFERED || hs.state === HS_STATES.TRANSFERRING ? now : 0 },
    { id: 'verify', label: 'Verify — the digest is checked before anything is saved', key: 'hsRailVerify', doneAt: hs.doneAt },
    { id: 'done', label: 'Done — the receipt stays until you dismiss it', key: 'hsRailDone', doneAt: hs.doneAt },
  ]
  const activeIdx = journey.findIndex((j) => !j.doneAt)
  const steps = journey.map((j, i) => ({
    id: j.id,
    label: j.label,
    key: j.key,
    glyph: j.doneAt ? HS_GLYPHS.done : i === activeIdx ? HS_GLYPHS.active : HS_GLYPHS.pending,
    state: j.doneAt ? 'done' : i === activeIdx ? 'active' : 'pending',
    target: j.id, // the deep-link target area (F6 — never inert text)
  }))

  // ── the prose: ONE line per truth, from the same facts ──
  const latency = hs.latencyVerdict(now)
  const stall = hs.stallVerdict(now)
  const prose = {
    search: hs.state === HS_STATES.SEARCHING
      ? { key: 'hsProseSearching', fallback: `Searching for the other device… ${hs.searchSeconds(now)}s`, live: true }
      : null,
    latency: !latency.met ? { key: 'hsProseSlow', fallback: latency.slowPathWords, live: false } : null,
    stall: stall.stalled ? { key: 'hsProseStall', fallback: stall.words, live: false } : null,
    failed: hs.state === HS_STATES.FAILED
      ? { key: 'hsProseFailed', fallback: `Stopped: ${hs.reason || 'failed'} — the fix is one tap away.`, live: false }
      : null,
  }

  // ── the buttons: exactly the actions the state makes meaningful ──
  const buttons = {
    send: true,
    receive: true,
    stop: hs.state === HS_STATES.ARMED || hs.state === HS_STATES.SEARCHING,
    codesMatchConnect: hs.state === HS_STATES.PAIRED,
    openDiagnostics: true,
    showFallback: true,
  }

  // ── the fallback decision (F7): auto-collapse when a better plane satisfies
  // the journey; collapsed-with-reopen is the satisfied default; the collapse is
  // a layout state the user can always reverse with one visible click ──
  const betterPlaneSatisfied = plane === 'A' || (plane === 'B' && relayOk)
  const fallback = {
    collapsedByDefault: betterPlaneSatisfied && hs.state !== HS_STATES.IDLE,
    reason: betterPlaneSatisfied ? 'a faster plane is connected — the manual path stays one click away' : '',
    persistReopen: true, // the 'Show manual fallback' affordance never disappears
  }

  // ── the diagnostics drawer (F8): collapsed one click away; opens ITSELF only on anomaly ──
  const failingHops = HS_HOPS.filter((h) => hs.hops[h] && hs.hops[h].ok === false)
  const drawer = {
    openOnLoad: failingHops.length > 0 || !!prose.stall,
    anomaly: failingHops.length > 0,
    hops: HS_HOPS.map((h) => {
      const hop = hs.hops[h]
      return {
        name: h,
        glyph: !hop ? HS_GLYPHS.pending : hop.ok ? HS_GLYPHS.done : HS_GLYPHS.fail,
        state: !hop ? 'pending' : hop.ok ? 'done' : 'fail',
        detail: hop ? hop.detail : '',
        fix: !hop || hop.ok ? null : HS_FIX[h] || HS_FIX.render,
      }
    }),
    identity: facts.beamIdentity || '',
  }

  return { state: hs.state, reason: hs.reason, rows, steps, prose, buttons, fallback, drawer, latency, stall }
}

/**
 * THE SIX-STEP MANUAL VIEW (§4.2): the render model for the manual protocol
 * with the answer's return path stated in plain copy and the phase-correct
 * language (pairing steps never speak of offers — F10). The answer's state
 * derives from the session bookkeeping; the return path names itself.
 */
export function manualProtocolView(hs, { relayConnected = false } = {}) {
  const answerReady = !!hs.answerText
  const returnPath = hs.answerViaRelay || (relayConnected && hs.answerAppliedAt === 0 && answerReady && false) ? 'relay' : 'manual'
  const states = {
    1: hs.openedPeerSignalText ? 'done' : hs.mySignalText ? 'active' : 'pending',
    2: hs.openedPeerSignalText ? 'done' : hs.mySignalText ? 'pending' : 'pending',
    3: hs.answerAppliedAt ? 'done' : hs.openedPeerSignalText ? 'active' : 'pending',
    4: hs.connectedAt ? 'done' : hs.answerAppliedAt || hs.pairedAt ? 'active' : 'pending',
    5: hs.connectedAt ? 'active' : 'pending',
    6: hs.doneAt ? 'active' : 'pending',
  }
  // the sender's view: step 2 is THEIR act; on the sender the active step after
  // step 1 is step 3 (await the answer) — the model stays honest per role
  if (hs.role === 'send' && !hs.openedPeerSignalText) states[2] = 'pending'
  return {
    steps: HS_MANUAL_STEPS.map((s) => ({ ...s, state: states[s.n] || 'pending' })),
    answerReady,
    returnPath,
    answerWords: answerReady
      ? 'Now copy this answer back to the first device.'
      : '',
    idempotentOpens: hs.idempotentOpens,
  }
}
