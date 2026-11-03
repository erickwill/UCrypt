/**
 * UCrypt — R136 §5/§6 — THE BEAM 3 ENGINE (the worker-side session logic).
 *
 * The engine is the ONLY stateful Beam 3 component and it is deliberately
 * thin: every DECISION lives in the pure modules (planes/manifest/chunks/
 * nonce-ledger/signal/machine/steps/transcript); this engine sequences
 * them behind the worker's message contract and keeps the typed journal.
 *
 * The engine NEVER touches chrome.* directly — the store and the send
 * callbacks are injected by the worker (the R96 SW boundary law).
 *
 * R136-F4 lives here: declaring an intent (Send or Receive) ARMS
 * AVAILABILITY automatically through the injected arm callback — with the
 * visible confirmation and the instant Stop owned by the UI strip.
 *
 * R136-F1 lives here: OPEN SIGNAL consumes the nonce and advances the
 * machine to PAIRED — the roster, the both-screens code, and the full
 * continuation render from there. Replay is a typed refusal; expiry is a
 * typed terminal with regenerate.
 */

import { selectPlane, degradePlane, routeTruthLine, readinessRows, PLANES, PLANE_NAMES, BEAM3_SIGNAL_TTL_MS, BEAM3_RELAY_POLL_ACTIVE_MS } from './planes.js'
import { buildManifest, validateManifest } from './manifest.js'
import { chunkCountFor, tombstonePlan } from './chunks.js'
import { consumeNonce, issueNonce, freshNonce, attemptRing, isConsumed } from './nonce-ledger.js'
import { buildSignal, openSignalGate, regenerateSignal, signalValidity, signalToText, signalFromText, buildAnswer, classifySignalRecord } from './signal.js'
import { Beam3Machine, scanResumable3, STATES3, TERMINALS3, isTerminal3, BEAM3_JOURNAL_KEY } from './machine.js'
import { newWorkflow, advanceWorkflow, WORKFLOW_EVENTS, workflowView } from './steps.js'
import { handshakeCodeV3 } from './transcript.js'
import { HandshakeSession, projectHandshake, manualProtocolView, HS_EVENTS, HS_STATES, HS_FIX } from './handshake.js'
import { BondSession, projectBond, BOND_EVENTS, BOND_STATES, bondPayloadHash, BOND_HOPS } from './bond.js'
import { choosePlane } from './spine.js'

/** The typed engine error. */
export function beam3EngineError(code, detail) {
  const e = new Error(`BEAM3_ENGINE_${code}: ${detail}`)
  e.code = `BEAM3_ENGINE_${code}`
  return e
}

/** The engine log ring (the orchestration log's Beam 3 rows). */
const LOG_CAP = 48

/** The handshake journey's persisted snapshot key (the crash-safe journey law). */
export const BEAM3_HANDSHAKE_KEY = 'ucrypt:beam3:handshake'

/** R139 §5 — THE BOND's persisted snapshot key (the ONE journey machine).
 * The legacy handshake snapshot migrates on first load: a pause, not a loss. */
export const BEAM3_BOND_KEY = 'ucrypt:beam3:bond'

/**
 * @param {object} deps
 * @param {{get:(k)=>Promise<any>, set:(k,v)=>Promise<void>}} deps.store — chrome.storage.local
 * @param {(deviceId:string)=>Promise<any>} deps.getPeer — the chain roster lookup
 * @param {(deviceId:string, env:object)=>Promise<void>} deps.sendToPeer — seal + publish a control envelope
 * @param {{deviceId:string, label:string}} deps.self — this device
 * @param {(minutes:number)=>Promise<boolean>} deps.armAvailability — R136-F4: auto-arm
 * @param {()=>Promise<boolean>} deps.disarmAvailability — the instant Stop
 * @param {()=>Promise<{available:boolean, label:string}>} deps.relayCapability — Drive OR WebDAV connected?
 * @param {(live:boolean)=>void} [deps.setPollLive] — the relay poller's live flag
 */
export function createBeam3Engine(deps) {
  const store = deps.store
  if (!store || typeof store.get !== 'function') throw beam3EngineError('BINDING', 'store required')
  const log = []
  const logRow = (row) => {
    log.push({ ...row, at: Date.now() })
    while (log.length > LOG_CAP) log.shift()
  }

  /** sessionId → {machine, workflow, plane, manifest, offerEnv, acceptEnv, signal, peerDeviceId} */
  const sessions = new Map()
  let lastWorkflow = null

  const memoryOnlyStore = {
    get: (k) => store.get(k),
    set: (k, v) => store.set(k, v),
  }

  // ── R139 §5 — THE BOND (ONE machine per transfer journey, crash-safe:
  // the snapshot persists after every fire — a crash is a pause, not a loss.
  // The legacy HandshakeSession journey MIGRATES: its role/signal adopt into
  // the Bond and the machine re-arms — no journey is lost, none is duplicated) ──
  let bond = null
  let bondLoaded = false
  async function loadBond() {
    if (bondLoaded) return bond
    bondLoaded = true
    try {
      const snap = await store.get(BEAM3_BOND_KEY)
      if (snap && typeof snap === 'object' && snap.state) bond = BondSession.from(snap)
    } catch { /* a lost snapshot is a fresh journey — never a crash */ }
    if (!bond) {
      // the migration fold: adopt the legacy handshake journey's live facts
      let legacy = null
      try {
        const hs = await store.get(BEAM3_HANDSHAKE_KEY)
        if (hs && typeof hs === 'object' && hs.state) legacy = hs
      } catch { /* best-effort */ }
      bond = new BondSession({ role: (legacy && legacy.role) || 'send', sessionId: `bond${freshNonce().slice(0, 10)}` })
      if (legacy && legacy.state !== HS_STATES.IDLE) {
        // the legacy journey had progress — re-arm the Bond from the same truth.
        // THE RE-BASELINE LAW: the migration is a pause, not a punishment — the
        // honest clock restarts NOW (the pre-migration wait never fires a
        // budget terminal at the user the moment they return).
        const now = Date.now()
        try {
          bond.fire(BOND_EVENTS.ARM, { now })
          bond.fire(BOND_EVENTS.ADVERTISED, { now }) // the advertisement re-runs with the fresh clock (WAITING_FOR_PEER)
        } catch { /* the fold is best-effort */ }
        if (legacy.mySignalText) {
          bond.mySignalHash = bondPayloadHash(legacy.mySignalText)
          bond.mySignalText = String(legacy.mySignalText)
        }
        if (legacy.openedPeerSignalText) bond.peerSignalHash = bondPayloadHash(legacy.openedPeerSignalText)
        if (legacy.answerText) {
          bond.answerReady = true
          bond.answerText = String(legacy.answerText)
        }
        if (legacy.connectedAt) {
          try { bond.fire(BOND_EVENTS.SIGNAL_OPENED, { now, hash: bond.peerSignalHash }) } catch { /* best-effort */ }
        }
        bond._journal({ type: 'migrated-from-legacy-handshake' }, now)
      }
      await saveBond()
    }
    return bond
  }
  async function saveBond() {
    if (!bond) return
    try { await store.set(BEAM3_BOND_KEY, bond.snapshot()) } catch { /* best-effort */ }
  }
  async function getBond() {
    const b = await loadBond()
    return b
  }

  /** The persisted journey's sessionId (the answer's binding target). */
  async function journeySessionId() {
    const b = await getBond()
    return b.sessionId
  }

  function sessionList() {
    return [...sessions.values()].map((s) => ({
      sessionId: s.machine.sessionId,
      role: s.machine.role,
      state: s.machine.state,
      terminal: isTerminal3(s.machine.state),
      plane: s.plane,
      planeName: PLANE_NAMES[s.plane] || '',
      peerDeviceId: s.peerDeviceId || '',
      manifest: s.manifest ? { name: s.manifest.files[0] && s.manifest.files[0].name, size: s.manifest.totalBytes, count: s.manifest.count } : null,
      countdowns: { signalMs: s.machine.signalCountdown() },
      lastAckedChunk: s.machine.lastAckedChunk,
    }))
  }

  /**
   * INTENT (R136-F4 + R139 §5.6): Send or Receive pressed. Arms availability
   * automatically (default-armed law), opens the workflow, creates the
   * pairing signal — THE BOND fires ARM (and ADVERTISED when the arm
   * succeeds: the advertisement is MEASURED here, the ≤2s budget).
   */
  async function intent({ role, route = 'auto' }) {
    if (!['send', 'receive'].includes(role)) throw beam3EngineError('ROLE', 'role must be send|receive')
    const armStart = Date.now()
    const armed = await deps.armAvailability(10).catch(() => false)
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const b = await getBond()
    b.role = role
    b.fire(BOND_EVENTS.ARM, { now: armStart })
    b.recordHop('arm', { ok: !!armed, detail: armed ? 'availability armed — presence published' : 'the arm failed — the vault may be locked', at: armStart })
    if (armed) {
      const at = Date.now()
      b.fire(BOND_EVENTS.ADVERTISED, { now: at })
      b.recordHop('advertise', { ok: true, detail: 'presence live on the chain', at })
    }
    if (relay.available) b.plane = 'B'
    await saveBond()
    let wf = newWorkflow({ role, route })
    wf = advanceWorkflow(wf, WORKFLOW_EVENTS.INTENT_DECLARED)
    const readinessNow = await readiness({ planeGuess: relay.available ? PLANES.B : PLANES.C })
    if (readinessNow.green) wf = advanceWorkflow(wf, WORKFLOW_EVENTS.READINESS_RESOLVED)
    lastWorkflow = wf
    const signal = buildSignal({ deviceId: deps.self.deviceId, deviceLabel: deps.self.label, sessionId: b.sessionId })
    await issueNonce(memoryOnlyStore, signal.nonce)
    b.mySignalHash = bondPayloadHash(signalToText(signal))
    b.mySignalText = signalToText(signal)
    await saveBond()
    const sessionId = `s${freshNonce().slice(0, 12)}`
    const machine = new Beam3Machine({ sessionId, role, store: memoryOnlyStore, signalIssuedAt: signal.issuedAt })
    await machine.fire('SIGNAL')
    // R140 §6.2/§6.6 — THE RELAY's plane chooser: the connected cloud is the
    // DEFAULT road (Plane B first-class), direct when KNOWN, manual when no
    // cloud — one honest reason each.
    const plane = choosePlane({
      manualChosen: route === 'manual',
      directKnown: false, // direct is chosen when the roster/ICE proves it (the worker upgrades)
      cloudConnected: relay.available,
      cloudHealthy: true,
      cloudLabel: relay.label || '',
    })
    sessions.set(sessionId, { machine, workflow: wf, plane: plane.plane, signal, peerDeviceId: '', manifest: null, offerEnv: null, acceptEnv: null })
    logRow({ disposition: 'intent', role, armed, plane: plane.plane, reason: plane.reasonWords || plane.reasonKey || '' })
    if (deps.setPollLive) deps.setPollLive(true)
    const availability = await bondAvailabilityFacts()
    return {
      ok: true,
      sessionId,
      journeySessionId: b.sessionId,
      armed,
      workflow: wf,
      workflowView: workflowView(wf),
      readiness: readinessNow,
      signal,
      signalText: signalToText(signal),
      signalWords: signalValidity(signal).words,
      plane: plane.plane,
      planeReason: plane.reasonWords || plane.reasonKey || '',
      routeLine: routeTruthLine(plane.plane, relay.label),
      bond: projectBond(b, bondFacts({ plane: plane.plane, relay, availability })),
      manual: manualProtocolViewV2(b),
    }
  }

  /** The availability facts (§5.6 — ONE surface's truth: armed + minutes). */
  async function bondAvailabilityFacts() {
    try {
      if (typeof deps.availabilityFacts === 'function') return await deps.availabilityFacts()
    } catch { /* best-effort */ }
    return { armed: false, minutes: 0 }
  }

  /** The projection facts bundle (the ONE writer's inputs). */
  function bondFacts({ plane = null, relay = { available: false, label: '' }, availability = { armed: false, minutes: 0 }, visibleDevices = 0, peerName = '', progress = null } = {}) {
    return {
      chainJoined: !!(deps.self && deps.self.deviceId),
      plane,
      relayConnected: !!relay.available,
      relayLabel: relay.label || '',
      availability,
      defaultArmed: true, // ships ON (§5.6 — the CEO's command)
      visibleDevices,
      peerName, // R140 §6.1 — the peer's ROSTER name (never a placeholder)
      progress, // R140 F2 — the TRANSFERRING header's percent/rate facts
      beamIdentity: typeof deps.beamIdentity === 'function' ? deps.beamIdentity() : (deps.beamIdentity || ''),
      now: Date.now(),
    }
  }

  /** The Bond-era manual view: the six-step protocol's render model from the Bond's facts. */
  function manualProtocolViewV2(b) {
    return {
      answerReady: !!b.answerReady,
      waitingForPeer: b.state === BOND_STATES.WAITING_FOR_PEER,
      signalExchanged: b.state === BOND_STATES.SIGNAL_EXCHANGED || !!b.exchangedAt,
      codeShown: !!b.codeShownAt || [BOND_STATES.CODE_SHOWN, BOND_STATES.CONNECTED].includes(b.state),
      connected: b.state === BOND_STATES.CONNECTED || !!b.connectedAt,
      replayNoops: b.replayNoops,
    }
  }

  /** The canonical readiness rows (R136-F5 — ONE strip). */
  async function readiness({ planeGuess = null, visibleDevices = 0 } = {}) {
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const chainJoined = !!(deps.self && deps.self.deviceId)
    const rows = readinessRows({
      chainJoined,
      plane: planeGuess,
      visibleDevices,
      cloudLabel: relay.label,
    })
    return { rows, green: rows.every((r) => r.ok) }
  }

  /**
   * OPEN SIGNAL (R139 §5.2/§5.3 — the ONE door, the classifier decides):
   * paste the peer's SIGNAL → consume the nonce → SIGNAL_EXCHANGED + the
   * ANSWER exists the same instant; paste the peer's ANSWER → the answer
   * path. THE D7 LAW: opening a signal that was ALREADY processed is the
   * friendly no-op REPLAY_OPEN — it re-renders the current truth and NEVER
   * refuses (the red-refusal class survives only for genuinely foreign,
   * stale, or tampered records).
   */
  async function openSignal({ text }) {
    const record = signalFromText(text)
    const kind = classifySignalRecord(record)
    if (kind === 'answer') return applyAnswer({ text, record })
    const b = await getBond()
    const textHash = bondPayloadHash(text)
    // ── D7: the payload-hash idempotency — the SAME signal re-opened is the
    // friendly no-op, keyed on the signal payload hash (never a session ledger) ──
    if (b.peerSignalHash && textHash === b.peerSignalHash && b.state !== BOND_STATES.IDLE) {
      b.fire(BOND_EVENTS.REPLAY_OPEN, { now: Date.now(), hash: textHash })
      await saveBond()
      logRow({ disposition: 'replay-noop', hash: textHash })
      const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
      const availability = await bondAvailabilityFacts()
      return {
        ok: true,
        noop: true,
        replayNoop: true,
        sessionId: b.sessionId,
        state: b.state,
        words: 'This signal is already active — here is where you are.',
        bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })),
        manual: manualProtocolViewV2(b),
      }
    }
    const signal = record
    let consumed = false
    if (signal && signal.nonce) {
      try { consumed = await isConsumed(memoryOnlyStore, signal.nonce) } catch { consumed = false }
    }
    const gate = openSignalGate(signal, { consumed })
    if (!gate.ok) {
      // a genuinely foreign/stale/tampered record — the typed refusal stands
      if (gate.terminal === 'replay' && signal && signal.nonce) {
        try { await consumeNonce(memoryOnlyStore, signal.nonce, { issuedAt: signal.issuedAt || 0 }) } catch { /* already recorded */ }
      }
      logRow({ disposition: 'open-refused', terminal: gate.terminal })
      return { ok: false, terminal: gate.terminal, words: gate.words, regenerate: gate.terminal === 'expired' || gate.terminal === 'replay' }
    }
    const consume = await consumeNonce(memoryOnlyStore, signal.nonce, { issuedAt: signal.issuedAt || 0 })
    if (!consume.ok) {
      // the nonce ledger says consumed: if it is the SAME signal this journey
      // already paired with, the friendly no-op holds even across surfaces
      if (textHash === b.peerSignalHash && b.state !== BOND_STATES.IDLE) {
        b.fire(BOND_EVENTS.REPLAY_OPEN, { now: Date.now(), hash: textHash })
        await saveBond()
        const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
        const availability = await bondAvailabilityFacts()
        return { ok: true, noop: true, replayNoop: true, sessionId: b.sessionId, state: b.state, words: 'This signal is already active — here is where you are.', bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })), manual: manualProtocolViewV2(b) }
      }
      logRow({ disposition: 'open-refused', terminal: consume.reason })
      return { ok: false, terminal: consume.reason, words: consume.reason === 'replay' ? 'That signal was already used by its own device — ask the other device to regenerate if you need a fresh one.' : 'That signal expired before it was used.', regenerate: true }
    }
    // the machine advances: SIGNAL_EXCHANGED — the ANSWER exists THE SAME INSTANT
    const sessionId = `s${freshNonce().slice(0, 12)}`
    const machine = new Beam3Machine({ sessionId, role: 'receive', store: memoryOnlyStore })
    await machine.fire('PAIR')
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const plane = choosePlane({ bothAdvertiseWebRtc: true, directKnown: true, cloudConnected: relay.available, cloudHealthy: true, cloudLabel: relay.label || '' })
    const wf0 = lastWorkflow && lastWorkflow.role === 'receive' ? lastWorkflow : newWorkflow({ role: 'receive' })
    let wf = wf0
    for (const ev of [WORKFLOW_EVENTS.INTENT_DECLARED, WORKFLOW_EVENTS.READINESS_RESOLVED, WORKFLOW_EVENTS.PEER_SIGNAL_OPENED]) {
      try { wf = advanceWorkflow(wf, ev) } catch { /* already advanced */ }
    }
    lastWorkflow = wf
    b.role = 'receive'
    b.fire(BOND_EVENTS.SIGNAL_OPENED, { now: Date.now(), hash: textHash, answerReady: true })
    const answer = buildAnswer({ forSignal: signal, deviceId: deps.self.deviceId, deviceLabel: deps.self.label })
    await issueNonce(memoryOnlyStore, answer.nonce)
    b.answerReady = true
    b.answerText = signalToText(answer)
    b.recordHop('roster', { ok: true, detail: `paired with ${signal.device ? signal.device.id || 'peer' : 'peer'}`, at: Date.now() })
    await saveBond()
    sessions.set(sessionId, { machine, workflow: wf, plane: plane.plane, signal, peerDeviceId: signal.device ? signal.device.id : '', manifest: null, offerEnv: null, acceptEnv: null })
    logRow({ disposition: 'paired', peerDeviceId: signal.device && signal.device.id, plane: plane.plane, answerIssued: true })
    const availability = await bondAvailabilityFacts()
    return {
      ok: true,
      sessionId,
      paired: true,
      idempotent: false,
      state: b.state,
      peer: signal.device || { id: '', label: '' },
      plane: plane.plane,
      routeLine: routeTruthLine(plane.plane, relay.label),
      workflow: wf,
      workflowView: workflowView(wf),
      answerText: signalToText(answer),
      answerWords: 'Now copy this answer back to the first device.',
      bond: projectBond(b, bondFacts({ plane: plane.plane, relay, availability })),
      manual: manualProtocolViewV2(b),
    }
  }

  /**
   * THE ANSWER PATH (§5.2's return half): the pasted record is an answer
   * bound to MY journey → ANSWER_APPLIED → CODE_SHOWN deterministically
   * (the answer's existence proves the peer paired — the code shows, the
   * gated connect unlocks). A re-opened SAME answer is the friendly no-op
   * (D7); a foreign answer is a typed refusal.
   */
  async function applyAnswer({ text, record }) {
    const b = await getBond()
    const mySession = b.sessionId
    const bindsMe = String(record.refSession || '') === String(mySession) || !record.refSession
    if (!bindsMe) {
      logRow({ disposition: 'answer-refused', reason: 'foreign' })
      return { ok: false, terminal: 'invalid', words: 'This answer was issued for a different pairing — paste the answer that replies to THIS device\'s signal.', regenerate: false }
    }
    const textHash = bondPayloadHash(text)
    // the answer consumes ITS OWN nonce too (single-use, the ledger law)
    let consumed = false
    try { consumed = await isConsumed(memoryOnlyStore, record.nonce) } catch { consumed = false }
    if (consumed) {
      // the D7 law: re-opening the SAME answer is the friendly no-op that re-renders truth
      if (textHash === b.peerSignalHash && b.state !== BOND_STATES.IDLE) {
        b.fire(BOND_EVENTS.REPLAY_OPEN, { now: Date.now(), hash: textHash })
        await saveBond()
        const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
        const availability = await bondAvailabilityFacts()
        return { ok: true, connected: b.state === BOND_STATES.CONNECTED, noop: true, replayNoop: true, sessionId: b.sessionId, state: b.state, words: 'This answer is already active — here is where you are.', bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })), manual: manualProtocolViewV2(b) }
      }
      logRow({ disposition: 'answer-refused', reason: 'replay' })
      return { ok: false, terminal: 'replay', words: 'That answer was already used — answers are single-use. Ask the other device to send a fresh signal.', regenerate: true }
    }
    const consume = await consumeNonce(memoryOnlyStore, record.nonce, { issuedAt: record.issuedAt || 0 })
    if (!consume.ok) {
      logRow({ disposition: 'answer-refused', reason: consume.reason })
      return { ok: false, terminal: consume.reason, words: 'That answer could not be accepted — paste it again or ask for a fresh signal.', regenerate: true }
    }
    b.fire(BOND_EVENTS.ANSWER_APPLIED, { now: Date.now() })
    b.peerSignalHash = textHash
    b.recordHop('relayRead', { ok: true, detail: 'the answer arrived (manual carry)', at: Date.now() })
    await saveBond()
    logRow({ disposition: 'answer-applied', state: b.state })
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const availability = await bondAvailabilityFacts()
    return {
      ok: true,
      connected: b.state === BOND_STATES.CONNECTED,
      idempotent: false,
      sessionId: b.sessionId,
      state: b.state,
      answerApplied: true,
      bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })),
      manual: manualProtocolViewV2(b),
    }
  }

  /**
   * CODES MATCH — CONNECT (§5.4): the user's independent path. When the
   * gate is enabled every click lands CONNECTED (or a typed failure);
   * a transport confirmation AFTER the user's connect is the confirmation,
   * never a second gate.
   */
  async function codesMatch() {
    const b = await getBond()
    if (b.state === BOND_STATES.CONNECTED) {
      // the confirmation-after-connect idempotency (the no-redo law)
      const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
      const availability = await bondAvailabilityFacts()
      return { ok: true, connected: true, idempotent: true, state: b.state, bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })), manual: manualProtocolViewV2(b) }
    }
    const res = b.fire(BOND_EVENTS.CODE_CONFIRMED, { now: Date.now() })
    await saveBond()
    logRow({ disposition: 'codes-match', state: b.state })
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const availability = await bondAvailabilityFacts()
    return {
      ok: true,
      connected: b.state === BOND_STATES.CONNECTED,
      idempotent: !!res.noop,
      state: b.state,
      bond: projectBond(b, bondFacts({ plane: b.plane || 'C', relay, availability })),
      manual: manualProtocolViewV2(b),
    }
  }

  /**
   * THE TRANSPORT CONFIRMATION (§5.4's independent path): the transport
   * confirmed the pair — the FIRST path to CONNECTED wins, the other
   * confirms; the worker's mirror calls this when the relay/roster proves
   * the peer is live on the same bond.
   */
  async function transportConfirm({ peerDeviceId = '', plane = null } = {}) {
    const b = await getBond()
    if (b.state === BOND_STATES.CONNECTED) {
      return { ok: true, connected: true, idempotent: true, state: b.state }
    }
    try { b.fire(BOND_EVENTS.TRANSPORT_CONFIRMED, { now: Date.now() }) } catch (e) {
      return { ok: false, terminal: 'illegal', words: String(e && e.message || e).slice(0, 160) }
    }
    if (peerDeviceId) b.peerDeviceId = String(peerDeviceId)
    if (plane) b.plane = String(plane)
    await saveBond()
    logRow({ disposition: 'transport-confirmed', state: b.state })
    return { ok: true, connected: b.state === BOND_STATES.CONNECTED, state: b.state }
  }

  /**
   * THE TRANSPORT MIRROR (the worker's one event source): the transport
   * executors (Beam 2 sessions, the legacy path) report their truth here
   * and THE BOND advances — one journey machine, one truth, whatever the
   * plane. Unknown mirrors are ignored (never a crash, never a fork).
   */
  async function noteTransport(mirror = {}) {
    const b = await getBond()
    const type = String(mirror.type || '')
    try {
      if (type === 'offer-out') b.fire(BOND_EVENTS.OFFER, { now: Date.now(), name: mirror.name, bytes: mirror.bytes, peerDeviceId: mirror.peerDeviceId, plane: mirror.plane })
      else if (type === 'offer-in') b.fire(BOND_EVENTS.OFFER_IN, { now: Date.now(), name: mirror.name, bytes: mirror.bytes, peerDeviceId: mirror.peerDeviceId })
      else if (type === 'accept') b.fire(BOND_EVENTS.ACCEPT, { now: Date.now() })
      else if (type === 'decline') b.fire(BOND_EVENTS.DECLINE, { now: Date.now() })
      else if (type === 'begin') b.fire(BOND_EVENTS.BEGIN, { now: Date.now() })
      else if (type === 'chunks') b.fire(BOND_EVENTS.CHUNKS_DONE, { now: Date.now(), lastAcked: mirror.lastAcked })
      else if (type === 'verify-ok') b.fire(BOND_EVENTS.VERIFY_OK, { now: Date.now() })
      else if (type === 'verify-fail') b.fire(BOND_EVENTS.VERIFY_FAIL, { now: Date.now() })
      else if (type === 'relay-fail') b.fire(BOND_EVENTS.RELAY_FAIL, { now: Date.now(), hop: mirror.hop })
      else if (type === 'complete-late') b.fire(BOND_EVENTS.COMPLETE_LATE, { now: Date.now() })
      // ── R140 §6.4/§6.3 — the relay receipts + the inbox's self-poll hop ──
      else if (type === 'offer-fetched') b.fire(BOND_EVENTS.OFFER_FETCHED, { now: Date.now(), peerName: mirror.peerName })
      else if (type === 'offer-write-fail') { b.recordHop('relayOfferWrite', { ok: false, detail: String(mirror.detail || 'the relay write failed'), at: Date.now() }) }
      else if (type === 'inbox-poll') b.fire(BOND_EVENTS.INBOX_POLL, { now: Date.now(), ok: mirror.ok !== false, error: mirror.error, periodSec: mirror.periodSec })
      else if (type === 'transport-confirm') return await transportConfirm(mirror)
      else return { ok: true, ignored: true }
    } catch (e) {
      // an illegal mirror edge is logged, never thrown at the poller
      logRow({ disposition: 'mirror-illegal', type, detail: String(e && e.message || e).slice(0, 120) })
      return { ok: false, terminal: 'illegal' }
    }
    await saveBond()
    return { ok: true, state: b.state }
  }

  /** The honest-clock tick (§5.5 — the STATUS poll drives the machine law). */
  async function clockTick() {
    const b = await getBond()
    const fired = b.clockTick(Date.now())
    if (fired.length) await saveBond()
    return fired
  }

  /** The per-hop telemetry ingest (the doctor drawer's live rows). */
  async function noteHop({ name, ok, detail }) {
    const b = await getBond()
    const row = b.recordHop(String(name || ''), { ok: ok !== false, detail: String(detail || ''), at: Date.now() })
    await saveBond()
    return { ok: true, hop: row }
  }

  /** RESET (the user's one dismiss — terminals stay until this). */
  async function handshakeReset() {
    const b = await getBond()
    try { b.fire(BOND_EVENTS.RESET, { now: Date.now() }) } catch { /* IDLE already */ }
    if (b.state !== BOND_STATES.IDLE) { b.state = BOND_STATES.IDLE }
    b.answerReady = false
    b.slowNoticedAt = 0
    b.pendingCompletion = false
    b.integrityFailed = false
    b.mySignalText = ''
    b.mySignalHash = ''
    b.answerText = ''
    b.peerSignalHash = ''
    b.waitingSince = 0
    await saveBond()
    return { ok: true, state: b.state }
  }

  /** REGENERATE (the one-tap fresh signal — in-flight sessions untouched). */
  async function regenerate({ previous }) {
    const signal = regenerateSignal(previous || null)
    await issueNonce(memoryOnlyStore, signal.nonce)
    logRow({ disposition: 'regenerated' })
    return { ok: true, signal, signalText: signalToText(signal), signalWords: signalValidity(signal).words }
  }

  /**
   * OFFER (the sender): validate the files, build the manifest, advance
   * OFFERING, publish on the chosen plane.
   */
  async function offer({ sessionId, files, peerDeviceId }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    const manifest = await buildManifest(files)
    await validateManifest(manifest) // self-check: the outbound manifest must pass its own gate
    const peer = await deps.getPeer(String(peerDeviceId || s.peerDeviceId))
    if (!peer) throw beam3EngineError('PEER', 'the peer device is not on your chain')
    // the roster pick IS the pairing act on the sender side (the machine
    // walks SIGNALING → PAIRED when the target is identified) — the paste
    // path pairs via openSignal instead
    if (s.machine.state === 'SIGNALING') {
      try { await s.machine.fire('PAIR') } catch { /* already paired */ }
    }
    await s.machine.fire('OFFER')
    const env = {
      v: 2,
      type: 'OFFER',
      sessionId,
      from: deps.self.deviceId,
      to: String(peerDeviceId || s.peerDeviceId),
      seq: 0,
      ts: Date.now(),
      payload: { manifest, plane: s.plane, fromLabel: String(deps.self.label || '') },
      sig: '',
    }
    // R140 §6.4 — THE HONEST MAILBOX LAW: the publish's receipt decides the
    // waiting copy. A confirmed write (the commit/etag receipt in hand) fires
    // OFFER_WRITTEN; a failed write records the failing hop — an unevidenced
    // delivery promise is unrepresentable either way.
    let receipt = null
    try {
      const pub = await deps.sendToPeer(env.to, env)
      if (pub && pub.ok === false) {
        const b0 = await getBond()
        b0.recordHop('relayOfferWrite', { ok: false, detail: String(pub.error || 'the relay write failed'), at: Date.now() })
        await saveBond()
      } else {
        receipt = (pub && pub.receipt) || { at: Date.now(), store: (pub && pub.store) || '', commit: (pub && pub.commit) || '' }
      }
    } catch (e) {
      const b0 = await getBond()
      b0.recordHop('relayOfferWrite', { ok: false, detail: String((e && (e.code || e.message)) || e).slice(0, 120), at: Date.now() })
      await saveBond()
      throw e
    }
    if (receipt) {
      const b0 = await getBond()
      // §6.1 — the offer binds the peer's identity to the journey: the
      // roster name renders in the header, the waiting copy, and the receipts
      if (!b0.peerDeviceId) b0.peerDeviceId = env.to
      if (!b0.peerName && typeof deps.peerName === 'function') {
        try { const n = await deps.peerName(env.to); if (n) b0.peerName = String(n).slice(0, 80) } catch { /* best-effort */ }
      }
      // the receiver's read capability rides the ONE chain truth (§7.2):
      // known-true when the chain derivation is ok, unknown otherwise — the
      // claim says exactly what its evidence says
      let chainOk = false
      try { chainOk = typeof deps.chainTruth === 'function' ? (await deps.chainTruth()).verdict === 'ok' : false } catch { chainOk = false }
      b0.fire(BOND_EVENTS.OFFER_WRITTEN, { now: Date.now(), store: receipt.store || '', commit: receipt.commit || '', peerReadKnown: chainOk })
      b0.recordHop('relayOfferWrite', { ok: true, detail: `offer written${receipt.store ? ` to ${receipt.store}` : ''}`, at: Date.now() })
      await saveBond()
    }
    s.manifest = manifest
    s.offerEnv = env
    logRow({ disposition: 'offer', sessionId, count: manifest.count, bytes: manifest.totalBytes, plane: s.plane })
    const chunks = chunkCountFor(manifest.totalBytes)
    return { ok: true, sessionId, manifest, chunks, plane: s.plane, state: s.machine.state }
  }

  /**
   * RESPOND (the receiver): Accept/Decline on the offer card — the modal's
   * only exits (law 0.52). Accept advances OFFERING→TRANSFERRING.
   */
  async function respond({ sessionId, decision }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    // the receiver's modal renders AFTER the offer is ingested — a decision
    // from the PAIRED state implies the OFFER arrived (the machine walks
    // PAIRED → OFFERING before the decision applies)
    if (s.machine.state === 'PAIRED' && ['accept', 'decline'].includes(decision)) {
      try { await s.machine.fire('OFFER') } catch { /* already offering */ }
    }
    if (decision === 'accept') {
      await s.machine.fire('ACCEPT')
      logRow({ disposition: 'accepted', sessionId })
      return { ok: true, state: s.machine.state }
    }
    if (decision === 'decline') {
      await s.machine.fire('DECLINE')
      logRow({ disposition: 'declined', sessionId })
      return { ok: true, terminal: TERMINALS3.DECLINED, state: s.machine.state }
    }
    throw beam3EngineError('DECISION', 'decision must be accept|decline')
  }

  /** The chunk ACK ingest (sender side) — the journal cadence + resume. */
  async function noteChunkAck({ sessionId, lastAcked }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    await s.machine.noteChunk(lastAcked)
    return { ok: true, lastAckedChunk: s.machine.lastAckedChunk }
  }

  /** Chunk transfer complete → VERIFYING. */
  async function chunksDone({ sessionId }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    await s.machine.fire('CHUNKS_DONE')
    return { ok: true, state: s.machine.state }
  }

  /** The typed verify verdict. */
  async function verify({ sessionId, ok }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    await s.machine.fire(ok ? 'VERIFY_OK' : 'VERIFY_FAIL')
    if (ok) {
      try { wfAdvance(sessionId, WORKFLOW_EVENTS.VERIFIED) } catch { /* workflow may lag */ }
      logRow({ disposition: 'completed', sessionId })
    }
    return { ok: true, state: s.machine.state, terminal: ok ? null : TERMINALS3.FAILED }
  }

  /** Receiver offline mid-transfer (S6) — the typed INTERRUPTED + resume. */
  async function interrupt({ sessionId }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    // the deliberate hard stop FLUSHES the progress journal first — the
    // resume fold reads the true last acked chunk (the crash-safety law)
    await s.machine.flushProgress()
    await s.machine.fire('NETWORK_FAIL')
    logRow({ disposition: 'interrupted', sessionId, lastAckedChunk: s.machine.lastAckedChunk })
    return { ok: true, terminal: TERMINALS3.INTERRUPTED, lastAckedChunk: s.machine.lastAckedChunk }
  }

  /** Resume (S6) — a fold over the journal, not a restart. */
  async function resume({ sessionId }) {
    const s = sessions.get(sessionId)
    if (!s) throw beam3EngineError('SESSION', 'unknown session')
    if (s.machine.state !== TERMINALS3.INTERRUPTED) throw beam3EngineError('STATE', 'resume is legal only from INTERRUPTED')
    await s.machine.fire('BEGIN_TRANSFER')
    return { ok: true, state: s.machine.state, resumeFromChunk: s.machine.lastAckedChunk + 1 }
  }

  /** Workflow passthrough (the UI's step events). */
  function wfAdvance(sessionId, event) {
    const s = sessions.get(sessionId)
    if (!s) return null
    s.workflow = advanceWorkflow(s.workflow, event)
    lastWorkflow = s.workflow
    return s.workflow
  }

  /** The tombstone plan for a completed session (zero orphans). */
  function tombstone({ sessionId }) {
    const s = sessions.get(sessionId)
    if (!s || !s.manifest) throw beam3EngineError('SESSION', 'nothing to sweep')
    return tombstonePlan(sessionId, chunkCountFor(s.manifest.totalBytes))
  }

  /** STATUS — the full engine truth (the poll's payload). THE BOND's
   * projection rides here: the UI renders from THIS alone (the single-writer
   * law — there is nothing left to contradict). The honest-clock tick runs
   * here too (§5.5 — the machine law is enforced on every poll). */
  async function status({ visibleDevices = 0 } = {}) {
    const relay = await deps.relayCapability().catch(() => ({ available: false, label: '' }))
    const b = await getBond()
    const chainJoined = !!(deps.self && deps.self.deviceId)
    const active = [...sessions.values()].find((s) => !isTerminal3(s.machine.state))
    const plane = active ? active.plane : null
    // R140 §6.1 — the peer's ROSTER name rides the status (the header's
    // Table S copy resolves it; the banned placeholder is unrepresentable)
    let peerName = b.peerName || ''
    if (!peerName && b.peerDeviceId && typeof deps.peerName === 'function') {
      try { peerName = String(await deps.peerName(b.peerDeviceId) || '') } catch { peerName = '' }
    }
    if (peerName && peerName !== b.peerName) { b.peerName = peerName; await saveBond() }
    // §5.5: the honest-clock tick — the slow notice at budget/2, the typed
    // terminal at budget×2. The poll is the clock driver (machine law).
    try { b.clockTick(Date.now()) } catch { /* the tick never blocks the status */ }
    await saveBond()
    const availability = await bondAvailabilityFacts()
    const bondView = projectBond(b, bondFacts({ plane, relay, availability, visibleDevices, peerName }))
    return {
      ok: true,
      sessions: sessionList(),
      log: log.slice(),
      workflow: lastWorkflow,
      workflowView: lastWorkflow ? workflowView(lastWorkflow) : null,
      relay: relay,
      resumable: await scanResumable3(memoryOnlyStore),
      replayAttempts: (await attemptRing(memoryOnlyStore)).filter((a) => a.outcome === 'replay').slice(-8),
      caps: { chunk: 256 * 1024, maxFile: 200 * 1024 * 1024, signalTtl: BEAM3_SIGNAL_TTL_MS, pollActive: BEAM3_RELAY_POLL_ACTIVE_MS },
      journeySessionId: b.sessionId,
      mySignalText: b.mySignalText,
      answerText: b.answerText,
      bond: bondView,
    }
  }

  return {
    intent,
    openSignal,
    applyAnswer,
    codesMatch,
    transportConfirm,
    noteTransport,
    clockTick,
    noteHop,
    handshakeReset,
    regenerate,
    offer,
    respond,
    noteChunkAck,
    chunksDone,
    verify,
    interrupt,
    resume,
    readiness,
    status,
    tombstone,
    wfAdvance,
    _sessions: sessions,
    _bond: () => bond,
  }
}
