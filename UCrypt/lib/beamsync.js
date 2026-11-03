/**
 * S8.9 — THE LIVING BEAM: continuous direct sync (R99, the CEO's vision
 * completed). When chain devices are simultaneously present, synchronization
 * is point-to-point; the cloud is the durable backup and the offline
 * reconciler. No UCrypt server, ever.
 *
 * Law anchors (the R99 order §3):
 *  3.1 TRIGGER: any successful local vault mutation — the SAME events that
 *      fire the cloud push. The hook lives beside the auto-push inside the
 *      vault's save path (lib/vault.js saveVault), fire-and-forget, and the
 *      cloud push ALWAYS fires too (direct is the fast lane; the cloud is
 *      the record of truth — both legs run, both legs are recorded).
 *  3.2 PATH: the sealed envelope — the EXACT cloud bytes — travels the
 *      direct WebRTC plane to each connected chain peer; the peer adopts via
 *      the existing digest-verify + pull-first adopt/merge path. No peer →
 *      the cloud push stands (it always ran anyway).
 *  3.3 CHANNELS: one data channel per connected chain peer ('ucrypt-xfer',
 *      the transfer plane's label), established from the engine's presence /
 *      peer-map discovery, torn down on lock, withdrawal, or terminal (idle
 *      never lingers past the fan-out act). ICE policy: HOST CANDIDATES ONLY
 *      (iceServers: [] — the standing owner order "NO relay"); public STUN
 *      adds nothing on a LAN and TURN would REQUIRE a server, violating the
 *      no-server law. Where NAT blocks a direct path the leg records the
 *      typed no_route outcome and the copy names the fallback (cloud or
 *      manual) — honesty over magic.
 *  3.4 CONCURRENCY: the engine is single-flight — one mutation, one sealed
 *      state, one coordinated fan-out; mutations arriving mid-fan-out
 *      coalesce into exactly one follow-up act. The receiving merge is the
 *      EXISTING law (per-entry last-writer, tombstones honored, no partial
 *      adoption — the digest-verified pull-first adopt).
 *  3.5 TRUTH: both legs are recorded per peer with real timestamps and
 *      surfaced separately (TRANSFER_BEAMSYNC_STATUS → the Sync surface
 *      renders "Direct: <label> · <time>" / "Cloud: <transport> · <time>").
 *      "Synced" is claimed only per-ledger, never as a global feeling.
 *  3.6 LIMITS: the 20 MB envelope cap applies (oversized → the cloud path,
 *      typed reason, nothing direct); the fan-out is bounded by the sealed
 *      peer map's cap-10 roster.
 *  3.7 SECURITY: the envelope is the exact cloud-path construction, sealed,
 *      never plaintext, unchanged end-to-end; every signaling record rides
 *      the EXISTING pairwise-sealed mailbox kinds ('sync-offer' /
 *      'sync-answer' — additions-only per law 0.4; ICE reuses 'ice',
 *      completion reuses 'complete'); no new permissions, no new key
 *      material, the words never leave any device, and NO credential ever
 *      rides the beam (law 0.14).
 *
 * The zero-transport generalization (S8.8 discipline): when a signaling
 * publish fails, the EXACT sealed record is staged for hand-carry and the
 * OPEN_MANUAL surface accepts the sync kinds — the continuous beam works
 * with zero infrastructure, the same way the join does.
 */

import {
  readOwnMailbox,
  recordToManual,
  recordFromManual,
  PEER_MAP_CAP,
  loadPeerMap,
  ownLocator,
} from './transfer/mailbox.js'
import { DEFAULT_TRANSFER_LIMIT } from './transfer/session.js'

// --- Engine state (SW-resident; wiped on lock) ------------------------------

let _accessors = null // configured by lib/transfer/worker.js at module init
let _fanoutBusy = false
let _fanoutPending = false
let _channels = new Map() // peerDeviceId → { pc, channel, transferId, openedAt, lastActivity }
let _stagedManualSyncOfferB64 = '' // the zero-transport hand-carry (S8.8)
let _stagedManualAnswers = new Map() // transferId → answerRecordB64 (hand-carry back to the sender)
let _answeredSyncOffers = [] // one-shot ledger of handled sync-offer messageIds (replay law)
const _pendingSyncAnswers = new Map() // offerMessageId → { rec, session, res, attempts } — the bounded answer retry
const PENDING_ANSWER_RETRY_MAX = 10
const _pendingManualActs = new Map() // transferId → the armed zero-transport continuation (the staged-offer act)
const MANUAL_ACT_MAX_MS = 90 * 1000 // the hand-carry bound; swept with the idle
const _manualAnsweredTransfers = new Set() // the answers that arrived BY HAND while the warm-window wait was still running
const _pollRefusals = [] // the last N tick refusals, typed (the honest diagnostics ring)
const _fanoutTargets = [] // the last fan-outs' target-id prefixes (the honest diagnostics)
const POLL_REFUSAL_CAP = 6

const _pollTraces = [] // the last N tick traces: { at, records } — the honest tick visibility
function notePollTrace(records, locator, deviceId) {
  _pollTraces.push({ at: new Date().toISOString().slice(11, 23), records: Number(records) || 0, box: String(locator || '').slice(0, 12), self: String(deviceId || '').slice(0, 10) })
  while (_pollTraces.length > POLL_REFUSAL_CAP) _pollTraces.shift()
}

function notePollRefusal(kind, err, rec) {
  const row = { kind: String(kind || '').slice(0, 20), reason: String((err && (err.transferCode || err.code)) || (err && err.message) || err).slice(0, 60), at: new Date().toISOString() }
  // The bad_record schema probe: WHICH field failed the E4 check — the
  // honest diagnostic (field names only, never payload bytes).
  if (rec && typeof rec === 'object' && row.reason === 'bad_record') {
    const hex64 = (v) => /^[0-9a-f]{64}$/.test(String(v || ''))
    const hex32 = (v) => /^[0-9a-f]{32}$/.test(String(v || ''))
    const b64 = (v) => typeof v === 'string' && v.length > 0
    row.schema = {
      v: rec.v === 1 ? '' : 'v',
      kind: rec.kind,
      messageId: hex64(rec.messageId) ? '' : 'messageId',
      transferId: (rec.transferId === '' || hex64(rec.transferId)) ? '' : 'transferId',
      from: hex32(rec.from) ? '' : 'from',
      to: (rec.to === '*' || hex32(rec.to)) ? '' : 'to',
      expiresAt: (typeof rec.expiresAt === 'string' && !Number.isNaN(Date.parse(rec.expiresAt))) ? '' : 'expiresAt',
      seq: (Number.isInteger(rec.seq) && rec.seq >= 0) ? '' : 'seq',
      nonce: (rec.nonce === '' || hex64(rec.nonce)) ? '' : 'nonce',
      chainTag: (typeof rec.chainTag === 'string' && rec.chainTag.length === 8) ? '' : 'chainTag',
      payload: b64(rec.payload) ? '' : 'payload',
      sig: b64(rec.sig) ? '' : 'sig',
    }
    row.schema.failing = Object.entries(row.schema).filter(([k, v]) => v && k !== 'failing' && k !== 'kind').map(([k]) => k)
  }
  _pollRefusals.push(row)
  while (_pollRefusals.length > POLL_REFUSAL_CAP) _pollRefusals.shift()
}
let _lastDirectByPeer = new Map() // peerDeviceId → { at, ok, reason, bytes, label }
let _lastCloudLeg = null // { at, ok, transport, reason }

// --- S8.9 completion (R100): the EXECUTOR REGISTRY ---------------------------
// The platform fact stands: this Chromium's SW does NOT expose
// RTCPeerConnection (typed no_rtc_context, R99). The completion: any open
// UCrypt surface page registers as an executor (a long-lived port) and hosts
// the TRANSPORT ONLY — ICE, SDP, the data channel — while the sealed-record
// machinery, digest verification, and adopt stay HERE (the SW). The executor
// sees transport metadata and SEALED frames; no plaintext crosses any
// boundary (law 0.14). Liveness: the port IS the liveness signal —
// disconnect unregisters; lock withdraws; idle sweeps the channels.
const _executors = new Map() // executorId → { id, port, page, connectedAt, sessions:Set, reqSeq, pending:Map }
let _executorSeq = 0
let _executorsWithdrawn = false // lock withdraws; the next registration re-admits

const EXECUTOR_REQ_TIMEOUT_MS = 12000

/** background.js onConnect: the typed port registers the page. */
export function registerBeamExecutorPort(port) {
  if (!port) return { ok: false, error: 'no_port' }
  const id = 'ex' + (++_executorSeq)
  const ex = { id, port, page: 'page', connectedAt: Date.now(), sessions: new Set(), reqSeq: 0, pending: new Map() }
  _executors.set(id, ex)
  _executorsWithdrawn = false
  try {
    port.onMessage.addListener((msg) => onExecutorMessage(ex, msg))
    port.onDisconnect.addListener(() => unregisterExecutor(ex.id, 'port_disconnected'))
  } catch { unregisterExecutor(ex.id, 'port_unusable') }
  // Probe the page's identity (the ack carries it); the registry entry is
  // usable regardless — the port is the contract, the name is the truth line.
  try { port.postMessage({ cmd: 'rtc:hello' }) } catch { /* the ack is best-effort */ }
  return { ok: true, executorId: id }
}

export function unregisterExecutor(exOrId, reason) {
  const id = exOrId && typeof exOrId === 'object' ? exOrId.id : exOrId
  const ex = _executors.get(id)
  if (!ex) return
  _executors.delete(ex.id)
  for (const sessionId of [...ex.sessions]) {
    closeExecutorSession(ex, sessionId).catch(() => {})
  }
  console.warn('[UCrypt] BeamSync: executor unregistered', reason || '')
}

/** Lock teardown (order §2.2: lock withdraws executors). The registry clears
 * COMPLETELY (the truth surface shows the honest zero) and each port is
 * disconnected — the page's existing reconnect loop re-registers when the
 * vault unlocks (self-healing, no ghost lane). */
export function withdrawExecutors() {
  _executorsWithdrawn = true
  for (const ex of [..._executors.values()]) {
    for (const sessionId of [...ex.sessions]) closeExecutorSession(ex, sessionId).catch(() => {})
    try { ex.port.disconnect() } catch { /* already dead */ }
    _executors.delete(ex.id)
  }
}

function pickExecutor() {
  if (_executorsWithdrawn) return null
  let best = null
  for (const ex of _executors.values()) {
    if (!best || ex.sessions.size < best.sessions.size) best = ex // least-loaded
  }
  return best
}

function executorRequest(ex, payload, { timeoutMs = EXECUTOR_REQ_TIMEOUT_MS } = {}) {
  const reqId = 'r' + (++ex.reqSeq)
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      ex.pending.delete(reqId)
      resolve({ ok: false, error: 'executor_timeout' })
    }, timeoutMs)
    ex.pending.set(reqId, { resolve, timer })
    try { ex.port.postMessage({ ...payload, reqId }) } catch (e) {
      clearTimeout(timer); ex.pending.delete(reqId)
      resolve({ ok: false, error: 'executor_port_dead' })
    }
  })
}

function settleExecutor(ex, reqId, reply) {
  const p = ex.pending.get(reqId)
  if (!p) return
  ex.pending.delete(reqId)
  clearTimeout(p.timer)
  p.resolve(reply)
}

function closeExecutorSession(ex, sessionId) {
  ex.sessions.delete(sessionId)
  try { ex.port.postMessage({ cmd: 'rtc:close', sessionId }) } catch { /* port dead; the session dies with it */ }
  return Promise.resolve()
}

function onExecutorMessage(ex, msg) {
  if (!msg || typeof msg !== 'object') return
  if (msg.cmd && String(msg.cmd).startsWith('rtc:') && msg.cmd.endsWith(':done')) {
    settleExecutor(ex, msg.reqId, msg)
    return
  }
  switch (msg.evt) {
    case 'rtc:hello-ack':
      ex.page = String(msg.page || ex.page).slice(0, 20)
      break
    case 'rtc:frame': {
      // The executor forwards a SEALED frame — the same bytes the local
      // channel.onmessage would deliver. The sink is per-session.
      const sink = _executorFrameSinks.get(msg.sessionId)
      if (sink) sink(msg.frame)
      break
    }
    case 'rtc:sent': {
      const w = _executorSentWaits.get(msg.sessionId + ':' + msg.seq)
      if (w) { _executorSentWaits.delete(msg.sessionId + ':' + msg.seq); clearTimeout(w.timer); w.resolve(msg.reason ? { ok: false, reason: msg.reason } : { ok: true }) }
      break
    }
    case 'rtc:sendfail': {
      const w = _executorSentWaits.get(msg.sessionId + ':' + msg.seq)
      if (w) { _executorSentWaits.delete(msg.sessionId + ':' + msg.seq); clearTimeout(w.timer); w.resolve({ ok: false, reason: String(msg.reason || 'sendfail').slice(0, 40) }) }
      break
    }
    case 'rtc:candidate': {
      // Late ICE from the executor-hosted answerer — the SAME sealed 'ice'
      // publish the local path runs (machinery unchanged, SW-side).
      const st = _executorSessions.get(msg.sessionId)
      if (st && st.onCandidate) st.onCandidate(msg.candidate).catch(() => {})
      break
    }
    case 'rtc:open': case 'rtc:close': case 'rtc:error':
      // Channel lifecycle events: the local path reads readyState on demand;
      // the executor mirrors it. Nothing sealed rides these.
      break
    case 'rtc:executor-up':
      ex.page = String(msg.page || ex.page).slice(0, 20)
      break
    default: break
  }
}

const _executorFrameSinks = new Map() // sessionId → (frame) => void
const _executorSentWaits = new Map() // sessionId:seq → { resolve, timer }
const _executorSessions = new Map() // sessionId → { onCandidate, via }
let _executorSessionSeq = 0

const SYNC_POLL_ALARM = 'ucrypt:beam-sync'
const SYNC_CHANNEL_IDLE_MS = 2 * 60 * 1000

/** Configure the engine with the worker's state accessors (no import cycle:
 * the engine never imports lib/vault.js or the worker module directly). */
export function configureBeamSync(accessors) {
  if (!accessors || typeof accessors !== 'object') throw new Error('beamsync: accessors required')
  _accessors = accessors
  restoreLegs().catch(() => { /* the surface starts empty — honest zero */ })
}

// --- R100 FIX: the legs ledger persists (the SW recycle law) ----------------
// The MV3 worker recycles when idle; an in-memory ledger let the truth
// surface forget a recorded leg mid-life (the live matrix caught it). The
// ledger is NON-SECRET by law 3.5 (sizes, outcomes, timestamps, labels —
// never envelope bytes) and dies with the unlock (the lock law wipes it).
const LEGS_STORAGE_KEY = 'ucrypt:beam:legs'
const LEGS_MAX = 12

async function persistLegs() {
  try {
    await chrome.storage.local.set({
      [LEGS_STORAGE_KEY]: {
        direct: [..._lastDirectByPeer.entries()].slice(-LEGS_MAX),
        cloud: _lastCloudLeg,
      },
    })
  } catch { /* the surface falls back to the in-memory truth */ }
}

async function restoreLegs() {
  try {
    const { [LEGS_STORAGE_KEY]: saved } = await chrome.storage.local.get(LEGS_STORAGE_KEY)
    if (!saved || typeof saved !== 'object') return
    if (Array.isArray(saved.direct)) {
      for (const [k, v] of saved.direct) {
        if (k && v && typeof v === 'object' && !_lastDirectByPeer.has(k)) _lastDirectByPeer.set(k, v)
      }
    }
    if (saved.cloud && !_lastCloudLeg) _lastCloudLeg = saved.cloud
  } catch { /* the surface starts empty — honest zero */ }
}

function acc(name) {
  if (!_accessors || typeof _accessors[name] !== 'function') {
    throw new Error(`beamsync: accessor ${name} not configured`)
  }
  return _accessors[name]
}

// --- Trigger (3.1) + single-flight (3.4) ------------------------------------

/** Called by lib/vault.js beside every cloud push (the same mutation events).
 * Fire-and-forget by contract: the caller never awaits the beam. */
export function noteVaultMutation(kind) {
  const kindSafe = String(kind || 'mutation').slice(0, 40)
  fanout(reasonFromKind(kindSafe)).catch((e) => {
    console.warn('[UCrypt] BeamSync: fan-out failed:', e && e.message ? String(e.message).slice(0, 120) : e)
  })
  return { ok: true, queued: true }
}

function reasonFromKind(kind) {
  return 'mutation:' + kind
}

/** The cloud leg's outcome is recorded by lib/vault.js after every push. */
export function recordCloudLeg(outcome) {
  const o = outcome && typeof outcome === 'object' ? outcome : {}
  _lastCloudLeg = {
    at: new Date().toISOString(),
    ok: !!o.ok,
    transport: String(o.transport || '').slice(0, 40),
    reason: String(o.reason || '').slice(0, 60),
  }
  persistLegs().catch(() => {})
}

/** The fan-out act (3.2/3.4): one sealed state, coordinated per-peer run. */
export async function fanout(reason = 'manual') {
  if (_fanoutBusy) {
    _fanoutPending = true // coalesce — ONE follow-up act, never a queue storm
    return { ok: false, busy: true, reason }
  }
  _fanoutBusy = true
  try {
    const env = await acc('envelopeOf')()
    if (!env || !env.ok) {
      return { ok: false, reason: (env && env.reason) || 'envelope_unavailable' }
    }
    if (env.empty) {
      // The empty-vault case: a fresh chain has nothing to push — the join
      // flow covers first contact; there is nothing to fan out (typed truth).
      return { ok: true, empty: true, reason }
    }
    if (env.size > DEFAULT_TRANSFER_LIMIT) {
      // 3.6 — the 20 MB cap: oversized → the cloud path (typed), nothing direct.
      _lastCloudLeg = _lastCloudLeg || { at: new Date().toISOString(), ok: false, transport: '', reason: '' }
      _lastDirectByPeer.set('*', { at: new Date().toISOString(), ok: false, reason: 'oversized', bytes: env.size, label: '' })
      persistLegs().catch(() => {})
      return { ok: false, oversized: true, sizeBytes: env.size, limitBytes: DEFAULT_TRANSFER_LIMIT, reason }
    }
    const { chainKeys, identity } = await acc('ensureChainReady')()
    let peers = []
    try {
      const map = await loadPeerMap(chainKeys)
      peers = Object.values(map || {}).filter((p) => p && p.deviceId && p.agrPubJwk)
    } catch { /* the map read fails → no known targets; the cloud stands */ }
    // R100 FIX (the live matrix found it): the fan-out NEVER targets this
    // device itself (a self-entry in the map would start a self-conversation
    // and eat the single-flight offer slot).
    const selfId = identity && identity.deviceId
    peers = peers.filter((p) => p.deviceId && p.deviceId !== selfId)
    peers = peers.slice(0, PEER_MAP_CAP) // 3.6 — the roster cap bounds the fan-out
    if (!peers.length) {
      // 3.5 truth: a mutation fired the act and NO chain peer is known — the
      // legs ledger records WHY nothing direct happened (never silence).
      _lastDirectByPeer.set('*', { at: new Date().toISOString(), ok: false, reason: 'no_peers', bytes: env.size, label: '' })
      persistLegs().catch(() => {})
      return { ok: true, reason, peers: [] }
    }
    _fanoutTargets.push({ at: new Date().toISOString().slice(11, 23), ids: peers.map((p) => String(p.deviceId || '').slice(0, 10)) })
    while (_fanoutTargets.length > 4) _fanoutTargets.shift()
    const results = []
    for (const peer of peers) {
      try {
        results.push(await syncToPeer(peer, env, reason))
      } catch (e) {
        results.push({ deviceId: peer.deviceId, ok: false, reason: String((e && e.transferCode) || (e && e.message) || e).slice(0, 60) })
      }
    }
    await sweepIdleChannels()
    return { ok: true, reason, peers: results }
  } finally {
    _fanoutBusy = false
    if (_fanoutPending) {
      _fanoutPending = false
      // ONE coalesced follow-up — a mutation that landed mid-fan-out is not lost.
      setTimeout(() => { fanout(reason + '+coalesced').catch(() => {}) }, 250)
    }
  }
}

// --- The per-peer sync act (3.2/3.3) ----------------------------------------

const _actTraces = [] // the sync acts' phase transitions (the honest diagnostics)
function noteAct(phase, detail) {
  _actTraces.push({ at: new Date().toISOString().slice(11, 23), phase: String(phase).slice(0, 24), detail: String(detail || '').slice(0, 220) })
  while (_actTraces.length > 10) _actTraces.shift()
}

async function syncToPeer(peer, env, reason) {
  const at = new Date().toISOString()
  noteAct('start', String(peer.deviceId || '').slice(0, 10))
  // THE TYPED LADDER (R100 §2.2): SW RTC when the context offers it →
  // executor-hosted transport when an open UCrypt page registered → typed
  // no_executor (the cloud stands; the push already ran). Never a silent leg.
  const host = await makeOffererHost()
  if (!host.ok) {
    _lastDirectByPeer.set(peer.deviceId, { at, ok: false, reason: host.reason, bytes: env.size, label: peer.label || '' })
    persistLegs().catch(() => {})
    return { deviceId: peer.deviceId, ok: false, reason: host.reason }
  }
  // The envelope bytes decode ONCE per fan-out act (the same one-decode
  // discipline the BEAM_ACCEPT path uses; wiped with the act).
  const bytes = Uint8Array.from(atob(String(env.bytesB64 || '')), (c) => c.charCodeAt(0))
  let created = null
  try {
    created = await acc('createSyncOffer')({
      to: peer.deviceId,
      file: { name: 'ucrypt-vault.enc', size: env.size, sha256hex: env.sha256hex },
      sdp: host.sdp,
    })
  } catch (e) {
    await host.close()
    const code = String((e && (e.transferCode || e.code)) || (e && e.message) || e).slice(0, 60)
    const busy = code === 'transfer_busy'
    _lastDirectByPeer.set(peer.deviceId, { at, ok: false, reason: busy ? 'busy' : code, bytes: env.size, label: peer.label || '' })
    persistLegs().catch(() => {})
    return { deviceId: peer.deviceId, ok: false, reason: busy ? 'busy' : code }
  }
  noteAct('offer-created', host.via + ' tid=' + String(created.transferId || '').slice(0, 10))
  _channels.set(peer.deviceId, { host, transferId: created.transferId, openedAt: Date.now(), lastActivity: Date.now(), label: peer.label || '', via: host.via })
  // The offer rides the pairwise-sealed mailbox; a failure STAGES the exact
  // record for hand-carry (S8.8 generalized — the beam continues by hand).
  try {
    await acc('publishRecord')({ record: created.record, to: peer.deviceId })
    _stagedManualSyncOfferB64 = ''
  } catch {
    try { _stagedManualSyncOfferB64 = recordToManual(created.record) } catch { _stagedManualSyncOfferB64 = '' }
  }
  // The answer arrives through the mailbox poll. The wait is a BOUNDED
  // WARM-WINDOW (R100: the MV3 worker cannot sleep for minutes — a long
  // in-memory wait dies with the recycle and the act is lost); if the answer
  // does not land inside the window the leg records the typed timeout and
  // the cloud push (which always ran) stands as the carrier. The NEXT
  // mutation/alarm re-fans-out fresh — the direct lane is the fast lane,
  // not a fragile long-lived session.
  const answerOpened = await awaitAnswer(host, created.transferId, 24000)
  noteAct('answer-' + (answerOpened.ok ? 'ok' : 'fail'), String(answerOpened.reason || '').slice(0, 30))
  if (!answerOpened.ok) {
    // R100 (the zero-transport continuation): when the offer was STAGED for
    // hand-carry (S8.8), the act does NOT die with the answer-wait timeout —
    // the sealed answer can still arrive BY HAND. The act stays armed
    // (bounded); the manual answer (openManualSyncAnswer) completes it: the
    // pump fires, the leg records the truth, the channel closes.
    if (_stagedManualSyncOfferB64) {
      _pendingManualActs.set(created.transferId, { peerDeviceId: peer.deviceId, env, bytes, host, transferId: created.transferId, label: peer.label || '', stagedAt: Date.now() })
      await sweepStaleManualActs()
      return { deviceId: peer.deviceId, ok: false, reason: answerOpened.reason, armedForManual: true }
    }
    _lastDirectByPeer.set(peer.deviceId, { at, ok: false, reason: answerOpened.reason, bytes: env.size, label: peer.label || '' })
    persistLegs().catch(() => {})
    await closeChannel(peer.deviceId)
    return { deviceId: peer.deviceId, ok: false, reason: answerOpened.reason }
  }
  // THE PUMP (the beam's one-sequential-pump discipline, backpressure honored).
  const pump = await pumpEnvelope(host, created.transferId, env, bytes)
  noteAct('pump-' + (pump.ok ? 'ok' : 'fail'), String(pump.reason || '').slice(0, 30))
  _lastDirectByPeer.set(peer.deviceId, {
    at: new Date().toISOString(),
    ok: !!pump.ok,
    reason: pump.ok ? '' : String(pump.reason || 'pump_failed').slice(0, 40),
    bytes: pump.ok ? env.size : 0,
    label: peer.label || '',
  })
  persistLegs().catch(() => {})
  // The completion record is best-effort (the receiver also sends one).
  await closeChannel(peer.deviceId)
  return { deviceId: peer.deviceId, ok: !!pump.ok, reason: pump.ok ? '' : pump.reason, bytes: pump.ok ? env.size : 0 }
}

async function awaitAnswer(host, transferId, deadlineMs) {
  const deadline = Date.now() + deadlineMs
  while (Date.now() < deadline) {
    // R100: the answer may arrive BY HAND (the zero-transport lane) while
    // this wait is still running — openManualSyncAnswer flags it after its
    // setRemote; the wait honors it (setRemote is already applied).
    if (_manualAnsweredTransfers.has(transferId)) {
      _manualAnsweredTransfers.delete(transferId)
      return { ok: true }
    }
    const answered = await tryOpenSyncAnswer(transferId)
    if (answered.ok) {
      try {
        await host.setRemote(String(answered.sdp || ''))
        return { ok: true }
      } catch (e) {
        return { ok: false, reason: 'bad_answer_sdp' }
      }
    }
    await sleep(4000)
  }
  return { ok: false, reason: 'answer_timeout' }
}

const _answerWaitTraces = [] // the last answer-wait match attempts (the honest diagnostics)
const ANSWER_WAIT_TRACE_CAP = 5
function noteAnswerWait(row) {
  _answerWaitTraces.push({ at: new Date().toISOString().slice(11, 23), ...row })
  while (_answerWaitTraces.length > ANSWER_WAIT_TRACE_CAP) _answerWaitTraces.shift()
}

async function tryOpenSyncAnswer(transferId) {
  try {
    const { chainKeys, identity } = await acc('ensureChainReady')()
    const records = await readOwnMailbox(chainKeys, identity)
    for (const rec of records) {
      // R100 FIX (the live matrix found it): the WIRE kind of the real
      // answer is 'answer' (acceptOffer's sealed construction — the same
      // kind the beam join uses); the engine listened for 'sync-answer'
      // only, so the real answer sat in the mailbox unread until the typed
      // answer_timeout. Both kinds are whitelisted (law 0.4); both are ours.
      if (rec.kind !== 'sync-answer' && rec.kind !== 'answer') continue
      let opened = null
      try { opened = await acc('openSyncAnswer')({ record: rec }) } catch (e) {
        noteAnswerWait({ seen: rec.kind, result: 'threw', why: String((e && (e.transferCode || e.code)) || (e && e.message) || e).slice(0, 60) })
        throw e
      }
      const gotId = String((opened && opened.answer && opened.answer.transferId) || '')
      const matched = opened && opened.ok && gotId === String(transferId)
      noteAnswerWait({ seen: rec.kind, result: matched ? 'MATCH' : 'no-match', got: gotId.slice(0, 10), want: String(transferId).slice(0, 10) })
      if (matched) {
        return { ok: true, sdp: opened.answer && opened.answer.sdp || '' }
      }
    }
  } catch (e) {
    // R100: the swallow hid the real gate failure — the ring names it.
    notePollRefusal('sync_answer', e)
  }
  return { ok: false }
}

/** The sender's pump: seal chunk i → send chunk i → then seal i+1 (the
 * ONE-sequential-pump discipline; the backpressure pattern is the transfer
 * plane's bufferedAmountLowThreshold, mirrored by the executor's sent-ack
 * — one frame in flight, the courier acks after channel.send). */
async function pumpEnvelope(host, transferId, env, bytes) {
  const CHUNK = Number(_accessors && _accessors.chunkSize) || 16384
  const totalChunks = Math.ceil(env.size / CHUNK)
  noteAct('pump-start', totalChunks + ' chunks')
  for (let seq = 0; seq < totalChunks; seq++) {
    if (!(await host.isOpen())) return { ok: false, reason: 'no_route' }
    const slice = bytes.subarray(seq * CHUNK, Math.min(bytes.length, (seq + 1) * CHUNK))
    let b64 = ''
    try { b64 = btoa(String.fromCharCode(...slice)) } catch { return { ok: false, reason: 'slice_encode_failed' } }
    let sealed = null
    try { sealed = await acc('sealChunk')({ transferId, seq, totalChunks, totalBytes: env.size, bytesB64: b64 }) } catch (e) {
      let probe = ''
      try { if (_accessors && typeof _accessors.sessionProbe === 'function') probe = JSON.stringify(await _accessors.sessionProbe(transferId)) } catch { /* best-effort */ }
      noteAct('seal-throw', String((e && (e.transferCode || e.message)) || e).slice(0, 26) + ' want=' + String(transferId || '').slice(0, 10) + ' sess=' + probe)
      throw e
    }
    if (!sealed || !sealed.ok) { noteAct('seal-fail', String((sealed && sealed.error) || 'seal_failed').slice(0, 36)); return { ok: false, reason: String((sealed && sealed.error) || 'seal_failed').slice(0, 40) } }
    noteAct('sealed', String(seq))
    const sent = await host.send(JSON.stringify(sealed.frame), seq)
    noteAct('sent', (sent && sent.ok ? 'ok' : String(sent && sent.reason || 'fail').slice(0, 30)) + ':' + String(seq))
    if (!sent || !sent.ok) return { ok: false, reason: String((sent && sent.reason) || 'no_route').slice(0, 40) }
  }
  return { ok: true }
}

// --- The receiver's side (the auto-answering peer) ---------------------------

/** The sync poll tick: the alarm cadence (1 min while unlocked) and the
 * manual-entry point. Reads the own mailbox, auto-answers sync offers
 * (consented by chain membership; the adoption is pull-first and
 * digest-verified — the SAME law the cloud pull obeys), applies late ICE. */
export async function syncPollTick() {
  if (!_accessors) return { ok: false, reason: 'not_configured' }
  let chain = null
  try { chain = await acc('ensureChainReady')() } catch { return { ok: false, reason: 'locked' } }
  const { chainKeys, identity } = chain || {}
  if (!chainKeys) return { ok: false, reason: 'locked' }
  let records = []
  try { records = await readOwnMailbox(chainKeys, identity) } catch (e) {
    notePollRefusal('mailbox_read', e)
    return { ok: true, handled: 0 }
  }
  let traceLocator = ''
  try { traceLocator = await ownLocator(chainKeys, identity) } catch { /* the trace is best-effort */ }
  notePollTrace(records.length, traceLocator, identity && identity.deviceId)
  let handled = 0
  for (const rec of records) {
    try {
      if (rec.kind === 'sync-offer') {
        if (_answeredSyncOffers.includes(rec.messageId)) continue // one-shot (the replay law)
        // R100 FIX (the live matrix found it): openFromPeer marks the record
        // seen AT OPEN — so if the answer build or its delivery fails after
        // that, a re-open is forever blocked by the replay gate and the sync
        // would silently die. The ENGINE therefore retries on ITS OWN cached
        // session (never a re-open): a failed BUILD rebuilds on a fresh host;
        // a failed PUBLISH re-publishes the built answer. One-shot marking
        // happens ONLY on success, a real refusal, or the bounded give-up.
        const pending = _pendingSyncAnswers.get(rec.messageId)
        if (pending) {
          const outcome = await retryPendingSyncAnswer(pending)
          if (outcome.done) {
            _pendingSyncAnswers.delete(rec.messageId)
            _answeredSyncOffers.push(rec.messageId)
          }
          handled++
          continue
        }
        const session = await acc('openSyncOffer')(rec)
        if (!session) { _answeredSyncOffers.push(rec.messageId); continue } // replay-safe drop
        let r = null
        try { r = await autoAnswerSyncOffer(rec, session) } catch (e) {
          r = { ok: false, reason: String((e && e.message) || e).slice(0, 40) }
        }
        if (r && r.ok && r.published) {
          _answeredSyncOffers.push(rec.messageId)
        } else if (r && r.ok) {
          // The answer was BUILT (the executor accepted; the pc is armed) but
          // the publish failed — retry the delivery on the next tick (bounded).
          _pendingSyncAnswers.set(rec.messageId, { rec, session, res: r, attempts: 1 })
        } else if (r && !r.ok && String(r.reason) === 'accept_refused') {
          _answeredSyncOffers.push(rec.messageId) // a real refusal is terminal (the gates spoke)
        } else {
          // The BUILD failed (a transient no-executor / executor timeout) —
          // the whole answer retries on the cached session (never a re-open).
          _pendingSyncAnswers.set(rec.messageId, { rec, session, res: null, attempts: 1 })
        }
        handled++
      } else if (rec.kind === 'ice') {
        const opened = await acc('openSyncIce')({ record: rec })
        const ch = opened && opened.transferId ? findByTransferId(opened.transferId) : null
        if (ch && opened.payload && opened.payload.candidate) {
          try { await ch.host.addIce(opened.payload.candidate) } catch { /* the SDP carries the hosts */ }
        }
      }
    } catch (e) {
      notePollRefusal(rec.kind, e, rec)
      console.warn('[UCrypt] BeamSync: poll record refused:', e && (e.transferCode || e.code) || String(e).slice(0, 80))
    }
  }
  if (_answeredSyncOffers.length > 200) _answeredSyncOffers = _answeredSyncOffers.slice(-100)
  await sweepIdleChannels()
  return { ok: true, handled }
}

async function autoAnswerSyncOffer(rec, session) {
  // THE TYPED LADDER on the answering side too (R100 §2.2).
  const host = await makeAnswererHost(session)
  if (!host.ok) return { ok: false, reason: host.reason }
  const st = { host, transferId: session.transferId, openedAt: Date.now(), lastActivity: Date.now(), label: session.peerLabel || '', via: host.via }
  _channels.set(session.peerKeys.deviceId, st)
  const res = await acc('acceptSyncOffer')({ offerId: session.offerMessageId, sdp: host.sdp })
  if (!res || !res.ok) {
    await host.close()
    _channels.delete(session.peerKeys.deviceId)
    return { ok: false, reason: 'accept_refused' }
  }
  // The answer rides the mailbox; on failure the EXACT record is staged for
  // hand-carry back to the sender (S8.8 generalized) AND the tick retries the
  // delivery (the R100 bounded retry — the answer exists, the lane heals).
  let published = true
  try {
    await acc('publishRecord')({ record: res.answerRecord, to: session.peerKeys.deviceId })
  } catch {
    published = false
    try { _stagedManualAnswers.set(session.transferId, res.answerRecordB64 || recordToManual(res.answerRecord)) } catch { /* best-effort */ }
  }
  return { ok: true, published, transferId: session.transferId, answerRecord: res.answerRecord }
}

/** The receiver's frame ingest → digest verify → pull-first adopt (3.2:
 * the EXISTING law; no partial adoption ever). */
const _frameTraces = [] // the receiver's frame-path traces (the honest diagnostics)
function noteFrame(phase, transferId, detail) {
  _frameTraces.push({ at: new Date().toISOString().slice(11, 23), phase, tid: String(transferId || '').slice(0, 10), detail: String(detail || '').slice(0, 40) })
  while (_frameTraces.length > 8) _frameTraces.shift()
}

async function onSyncFrame(transferId, data) {
  const st = findByTransferId(transferId)
  if (st) st.lastActivity = Date.now()
  let frame = data
  if (typeof data === 'string') {
    try { frame = JSON.parse(data) } catch { return }
  }
  try {
    const state = await acc('ingestFrame')({ transferId, frame })
    if (!state || !state.ok) { noteFrame('ingest-fail', transferId, state && state.error); return }
    noteFrame('ingest-ok', transferId, '')
    let inbox = await acc('inboxState')({ transferId })
    if (!inbox || !inbox.ok) { noteFrame('inbox-missing', transferId, ''); return }
    // R100 FIX (the live matrix caught it): the inbox does NOT self-verify on
    // the last chunk — the digest verification runs in the FINALIZE step (the
    // transfer page calls it; the engine must too).
    if (inbox.done && !inbox.verified) {
      try { await acc('finalizeInbox')({ transferId }) } catch (e) { noteFrame('finalize-fail', transferId, String((e && e.message) || e).slice(0, 30)); return }
      inbox = await acc('inboxState')({ transferId })
      noteFrame('finalized', transferId, '')
    }
    if (!inbox || !inbox.ok || !inbox.verified) { noteFrame('inbox-unverified', transferId, ''); return }
    // ONE-SHOT export (the worker wipes its plaintext buffer after the read).
    const bytes = await acc('exportInbox')({ transferId })
    if (!bytes || !bytes.ok) { noteFrame('export-fail', transferId, ''); return }
    const adopt = await acc('adoptEnvelope')(bytes.bytesB64, inbox.verified.sha256hex)
    noteFrame(adopt && adopt.ok ? 'adopt-ok' : 'adopt-fail', transferId, String((adopt && adopt.reason) || '').slice(0, 30))
    if (adopt && adopt.ok) {
      // R111 §3.2 — THE MOMENT MADE VISIBLE: the direct lane landed changes,
      // so the receiving device records the persisted ledger line and notifies
      // the open pages ("Vault updated — 1 new login from XEON"). The toast
      // may expire (0.8); the ledger line persists. Counts + a label only.
      try {
        const from = inbox.from || (st && st.peerDeviceId) || ''
        const label = await acc('peerLabel')(from)
        acc('recordSyncMoment')({ lane: 'direct', added: adopt.added || 0, updated: adopt.updated || 0, by: label })
      } catch { /* the moment never blocks the adopt */ }
      // The sender learns COMPLETED through the EXISTING 'complete' kind.
      try {
        const from = inbox.from || (st && st.peerDeviceId) || ''
        if (from) {
          const sealed = await acc('sealComplete')({ to: from, transferId })
          if (sealed && sealed.ok) await acc('publishRecord')({ record: sealed.record, to: from })
        }
      } catch { /* best-effort */ }
    }
    await closeChannel(transferIdToDeviceId(transferId) || '')
  } catch (e) {
    console.warn('[UCrypt] BeamSync: frame refused:', e && (e.transferCode || e.code) || String(e).slice(0, 80))
  }
}

// --- Channel lifecycle (3.3) -------------------------------------------------

async function closeChannel(peerDeviceId) {
  const st = _channels.get(peerDeviceId)
  if (!st) return
  _channels.delete(peerDeviceId)
  try { if (st.host) await st.host.close() } catch { /* already closed */ }
}

/** Lock / withdrawal teardown (3.3): every channel dies with the unlock.
 * R100 §2.2: lock ALSO withdraws the executors (the registry clears; the
 * live pages re-register on their next port — the ladder re-arms). */
export async function teardownAll() {
  for (const id of [..._channels.keys()]) await closeChannel(id)
  withdrawExecutors()
  _fanoutPending = false
  _stagedManualSyncOfferB64 = ''
  _stagedManualAnswers = new Map()
  _answeredSyncOffers = []
  _pendingSyncAnswers.clear()
  for (const [, act] of [..._pendingManualActs.entries()]) { try { await act.host.close() } catch { /* already closed */ } }
  _pendingManualActs.clear()
  _manualAnsweredTransfers.clear()
  try { chrome.storage.local.remove(LEGS_STORAGE_KEY).catch(() => {}) } catch { /* locked */ }
}

/** The bounded retry for a pending sync answer (R100): a failed BUILD
 * rebuilds on a fresh host; a failed PUBLISH re-publishes the built answer.
 * NEVER a re-open — the replay gate is law; the cached session is the key. */
async function retryPendingSyncAnswer(pending) {
  pending.attempts++
  const exhausted = pending.attempts >= PENDING_ANSWER_RETRY_MAX
  try {
    if (!pending.res) {
      const host = await makeAnswererHost(pending.session)
      if (!host.ok) { pending.lastReason = String(host.reason || 'no_executor').slice(0, 40); return { done: exhausted } } // the lane is still absent — retry or expire
      const res = await acc('acceptSyncOffer')({ offerId: pending.session.offerMessageId, sdp: host.sdp })
      if (!res || !res.ok) {
        await host.close()
        pending.lastReason = 'accept_refused'
        return { done: true } // a real refusal — the gates spoke
      }
      let published = true
      try {
        await acc('publishRecord')({ record: res.answerRecord, to: pending.session.peerKeys.deviceId })
      } catch {
        published = false
        try { _stagedManualAnswers.set(pending.session.transferId, res.answerRecordB64 || recordToManual(res.answerRecord)) } catch { /* best-effort */ }
      }
      pending.res = { ok: true, published, transferId: pending.session.transferId, answerRecord: res.answerRecord }
      if (!published) pending.lastReason = 'publish_failed'
      return { done: published || exhausted }
    }
    await acc('publishRecord')({ record: pending.res.answerRecord, to: pending.session.peerKeys.deviceId })
    return { done: true }
  } catch {
    return { done: exhausted }
  }
}

/** The zero-transport continuation: a hand-carried answer completes the
 * armed act — the pump fires, the leg records the truth, the channel closes. */
async function completeManualAct(transferId) {
  const act = _pendingManualActs.get(transferId)
  if (!act) return { ok: false, error: 'no_armed_act' }
  _pendingManualActs.delete(transferId)
  noteAct('manual-continue', String(transferId || '').slice(0, 10))
  const pump = await pumpEnvelope(act.host, act.transferId, act.env, act.bytes)
  noteAct('pump-' + (pump.ok ? 'ok' : 'fail'), String(pump.reason || '').slice(0, 30))
  _lastDirectByPeer.set(act.peerDeviceId, {
    at: new Date().toISOString(),
    ok: !!pump.ok,
    reason: pump.ok ? '' : String(pump.reason || 'pump_failed').slice(0, 40),
    bytes: pump.ok ? act.env.size : 0,
    label: act.label || '',
  })
  persistLegs().catch(() => {})
  await closeChannel(act.peerDeviceId)
  return { ok: !!pump.ok, reason: pump.ok ? '' : pump.reason }
}

async function sweepStaleManualActs() {
  const now = Date.now()
  for (const [transferId, act] of [..._pendingManualActs.entries()]) {
    if (now - act.stagedAt > MANUAL_ACT_MAX_MS) {
      _pendingManualActs.delete(transferId)
      try { await act.host.close() } catch { /* already closed */ }
      _lastDirectByPeer.set(act.peerDeviceId, { at: new Date().toISOString(), ok: false, reason: 'manual_act_expired', bytes: act.env.size, label: act.label || '' })
      persistLegs().catch(() => {})
    }
  }
}

async function sweepIdleChannels() {
  const now = Date.now()
  for (const [id, st] of [..._channels.entries()]) {
    if (now - (st.lastActivity || st.openedAt || now) > SYNC_CHANNEL_IDLE_MS) await closeChannel(id)
  }
}

function findByTransferId(transferId) {
  for (const st of _channels.values()) if (st.transferId === transferId) return st
  return null
}

// --- The RTC host abstraction (R100 §2.1) ------------------------------------
// One interface, two carriers: the SW's own RTCPeerConnection when the
// context offers one, else an executor page's (transport hosted by the page,
// everything sealed stays here). Both carriers return the SAME host shape:
// { ok, via, sdp, isOpen(), send(frame, seq), setRemote(sdp), close() }.

async function makeOffererHost() {
  if (typeof RTCPeerConnection !== 'undefined') {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] }) // 3.3 — host candidates only; no relay
      const channel = pc.createDataChannel('ucrypt-xfer', { ordered: true })
      channel.binaryType = 'arraybuffer'
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      await waitIce(pc)
      return {
        ok: true, via: 'sw', sdp: pc.localDescription.sdp,
        isOpen: async () => channel.readyState === 'open',
        send: async (frame, seq) => {
          if (channel.readyState !== 'open') return { ok: false, reason: 'no_route' }
          channel.send(frame)
          return { ok: true }
        },
        setRemote: async (sdp) => { await pc.setRemoteDescription({ type: 'answer', sdp }) },
        addIce: async (candidate) => { try { await pc.addIceCandidate(JSON.parse(candidate)) } catch { /* the SDP carries the hosts */ } },
        close: async () => { try { channel.close() } catch { /* already closed */ } try { pc.close() } catch { /* already closed */ } },
      }
    } catch (e) {
      return { ok: false, reason: String((e && e.message) || e).slice(0, 40) }
    }
  }
  // The executor lane: a live open page hosts the transport.
  const ex = pickExecutor()
  if (!ex) return { ok: false, reason: 'no_executor' }
  const sessionId = 'es' + (++_executorSessionSeq)
  ex.sessions.add(sessionId)
  _executorSessions.set(sessionId, { via: 'executor:' + ex.id, onCandidate: null })
  const reply = await executorRequest(ex, { cmd: 'rtc:offer', sessionId })
  if (!reply || !reply.ok) {
    ex.sessions.delete(sessionId)
    _executorSessions.delete(sessionId)
    return { ok: false, reason: String((reply && reply.error) || 'executor_failed').slice(0, 40) }
  }
  return {
    ok: true, via: 'executor:' + ex.id, sdp: String(reply.sdp || ''),
    isOpen: async () => {
      // The courier's honest open check: a send of nothing is wasteful; the
      // session's alive-ness is the pump's own sent-ack (the pump fails typed
      // on the first refused frame). The offer phase counts as open.
      return true
    },
    send: (frame, seq) => executorSend(ex, sessionId, frame, seq),
    setRemote: async (sdp) => {
      const r = await executorRequest(ex, { cmd: 'rtc:set-remote', sessionId, sdp })
      if (!r || !r.ok) throw new Error(String((r && r.error) || 'set_remote_failed').slice(0, 40))
    },
    addIce: async (candidate) => {
      await executorRequest(ex, { cmd: 'rtc:add-ice', sessionId, candidate })
    },
    close: async () => {
      _executorFrameSinks.delete(sessionId)
      _executorSessions.delete(sessionId)
      ex.sessions.delete(sessionId)
      try { ex.port.postMessage({ cmd: 'rtc:close', sessionId }) } catch { /* port dead */ }
    },
  }
}

async function makeAnswererHost(session) {
  if (typeof RTCPeerConnection !== 'undefined') {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] }) // 3.3 — host candidates only
      const localCands = []
      pc.onicecandidate = (e) => { if (e.candidate) localCands.push(e.candidate.candidate) }
      pc.ondatachannel = (e) => {
        const channel = e.channel
        if (!channel || channel.label !== 'ucrypt-xfer') return
        channel.binaryType = 'arraybuffer'
        const st = _channels.get(session.peerKeys.deviceId) || {}
        st.lastActivity = Date.now()
        _channels.set(session.peerKeys.deviceId, st)
        channel.onmessage = (ev) => { onSyncFrame(session.transferId, ev.data).catch(() => {}) }
        channel.onclose = () => { /* the sender's terminal or the idle sweep */ }
      }
      await pc.setRemoteDescription({ type: 'offer', sdp: String(session.sdp || '') })
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      await waitIce(pc)
      // Late ICE (the robustness net) — the SAME sealed 'ice' publish.
      for (const c of localCands) {
        try {
          const sealed = await acc('sealIce')({ to: session.peerKeys.deviceId, transferId: session.transferId, candidate: c })
          if (sealed && sealed.ok) await acc('publishRecord')({ record: sealed.record, to: session.peerKeys.deviceId })
        } catch { /* best-effort */ }
      }
      return {
        ok: true, via: 'sw', sdp: pc.localDescription.sdp,
        isOpen: async () => true,
        send: async () => ({ ok: true }), // the answerer only receives (the completion rides the mailbox)
        setRemote: async () => {},
        addIce: async (candidate) => { try { await pc.addIceCandidate(JSON.parse(candidate)) } catch { /* the SDP carries the hosts */ } },
        close: async () => { try { pc.close() } catch { /* already closed */ } },
      }
    } catch (e) {
      return { ok: false, reason: String((e && e.message) || e).slice(0, 40) }
    }
  }
  // The executor lane: the page accepts the offer and returns the answer SDP.
  const ex = pickExecutor()
  if (!ex) return { ok: false, reason: 'no_executor' }
  const sessionId = 'es' + (++_executorSessionSeq)
  ex.sessions.add(sessionId)
  const publishLateIce = async (candidate) => {
    try {
      const sealed = await acc('sealIce')({ to: session.peerKeys.deviceId, transferId: session.transferId, candidate })
      if (sealed && sealed.ok) await acc('publishRecord')({ record: sealed.record, to: session.peerKeys.deviceId })
    } catch { /* best-effort */ }
  }
  _executorSessions.set(sessionId, { via: 'executor:' + ex.id, onCandidate: publishLateIce })
  _executorFrameSinks.set(sessionId, (frame) => { onSyncFrame(session.transferId, frame).catch(() => {}) })
  const reply = await executorRequest(ex, { cmd: 'rtc:accept', sessionId, sdp: String(session.sdp || '') })
  if (!reply || !reply.ok) {
    _executorFrameSinks.delete(sessionId)
    _executorSessions.delete(sessionId)
    ex.sessions.delete(sessionId)
    return { ok: false, reason: String((reply && reply.error) || 'executor_failed').slice(0, 40) }
  }
  return {
    ok: true, via: 'executor:' + ex.id, sdp: String(reply.sdp || ''),
    isOpen: async () => true,
    send: async () => ({ ok: true }), // the answerer only receives (the completion rides the mailbox)
    setRemote: async () => {},
    addIce: async () => { /* the executor's late ICE rides the sealed 'ice' publish */ },
    close: async () => {
      _executorFrameSinks.delete(sessionId)
      _executorSessions.delete(sessionId)
      ex.sessions.delete(sessionId)
      try { ex.port.postMessage({ cmd: 'rtc:close', sessionId }) } catch { /* port dead */ }
    },
  }
}

// R100 battery access (additive; the worker never uses these directly):
export { makeOffererHost, makeAnswererHost }

/** The executor courier's send: one frame in flight; the ack (rtc:sent) is
 * the backpressure — the R99 lesson's poll-to-deadline applied to the pump.
 * The channel-open gap (setRemote → open) is typed and bounded: a
 * 'channel_not_open' refusal retries on a short poll until the lane opens
 * or the bound expires (never a silent drop, never an unbounded wait). */
async function executorSend(ex, sessionId, frame, seq) {
  const OPEN_WAIT_MS = 12000
  const openDeadline = Date.now() + OPEN_WAIT_MS
  for (;;) {
    const r = await executorSendOnce(ex, sessionId, frame, seq)
    if (r.ok) return r
    if (String(r.reason) !== 'channel_not_open' || Date.now() >= openDeadline) { noteAct('send-final', String(r.reason || '').slice(0, 30)); return r }
    noteAct('send-retry', String(r.reason || '').slice(0, 30))
    await sleep(300)
  }
}

function executorSendOnce(ex, sessionId, frame, seq) {
  return new Promise((resolve) => {
    const key = sessionId + ':' + seq
    const timer = setTimeout(() => {
      _executorSentWaits.delete(key)
      resolve({ ok: false, reason: 'executor_send_timeout' })
    }, 15000)
    _executorSentWaits.set(key, { resolve, timer })
    try { ex.port.postMessage({ cmd: 'rtc:send', sessionId, seq, frame }) } catch (e) {
      clearTimeout(timer); _executorSentWaits.delete(key)
      resolve({ ok: false, reason: 'executor_port_dead' })
    }
  })
}

function transferIdToDeviceId(transferId) {
  for (const [id, st] of _channels.entries()) if (st.transferId === transferId) return id
  return ''
}

async function waitIce(pc) {
  if (pc.iceGatheringState === 'complete') return
  await new Promise((resolve) => {
    const done = () => { try { pc.removeEventListener('icegatheringstatechange', onChange) } catch { /* noop */ } ; resolve() }
    const onChange = () => { if (pc.iceGatheringState === 'complete') done() }
    try { pc.addEventListener('icegatheringstatechange', onChange) } catch { /* noop */ }
    setTimeout(done, 2500) // the beam's bounded gather — the SDP carries the hosts
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// --- The zero-transport manual surface (S8.8 generalized) --------------------

/** OPEN_MANUAL branch: a hand-carried sync-offer enters the SAME auto-answer
 * path (the same typed gates — seal, proof, replay, rate limit). The typed
 * gates are ANSWERED, never thrown to a user surface (the manual box renders
 * the refusal — a throw would leave the paste dead). */
export async function openManualSyncSignal(signal) {
  let record = null
  try { record = recordFromManual(String(signal || '')) } catch { record = null }
  if (!record || record.kind !== 'sync-offer') {
    return { ok: false, error: 'bad_record', userMessageKey: 'beamErrInternal' }
  }
  let session = null
  try {
    session = await acc('openSyncOffer')(record)
  } catch (e) {
    return { ok: false, error: String((e && (e.transferCode || e.code)) || (e && e.message) || e).slice(0, 60) }
  }
  if (!session) return { ok: false, error: 'replay', userMessageKey: 'beamErrInternal' } // one-shot (the replay law)
  const r = await autoAnswerSyncOffer(record, session)
  _answeredSyncOffers.push(record.messageId)
  return { ok: !!r.ok, published: !!(r && r.published), transferId: session.transferId, error: r.ok ? '' : String(r.reason || 'auto_answer_failed').slice(0, 60) }
}

/** A hand-carried ANSWER (the sender side): the same gate the cloud path uses. */
export async function openManualSyncAnswer(signal) {
  let record = null
  try { record = recordFromManual(String(signal || '')) } catch { record = null }
  // R100 FIX: both answer kinds are ours (the real answer is 'answer').
  if (!record || (record.kind !== 'sync-answer' && record.kind !== 'answer')) {
    return { ok: false, error: 'bad_record', userMessageKey: 'beamErrInternal' }
  }
  let opened = null
  try {
    opened = await acc('openSyncAnswer')({ record })
  } catch (e) {
    return { ok: false, error: String((e && (e.transferCode || e.code)) || (e && e.message) || e).slice(0, 60) }
  }
  if (!opened || !opened.ok) return { ok: false, error: 'bad_answer' }
  const ch = findByTransferId(opened.answer && opened.answer.transferId || '')
  if (!ch) return { ok: false, error: 'no_session' }
  try {
    // R100: the channel carries the host abstraction (sw or executor) — the
    // answer applies through it, never through a bare pc field.
    await ch.host.setRemote(String(opened.answer.sdp || ''))
    // The zero-transport continuation, BOTH ORDERS: (a) the act is already
    // armed (the warm window expired) — its pump fires now; (b) the warm
    // window is STILL waiting — the flag hands the answer to it and the
    // normal flow completes the act honestly.
    if (_pendingManualActs.has(opened.answer.transferId)) {
      const done = await completeManualAct(opened.answer.transferId)
      return { ok: true, transferId: opened.answer.transferId, carried: !!done.ok, reason: done.reason || '' }
    }
    _manualAnsweredTransfers.add(String(opened.answer.transferId || ''))
    return { ok: true, transferId: opened.answer.transferId }
  } catch (e) {
    return { ok: false, error: 'bad_answer_sdp: ' + String((e && e.message) || e).slice(0, 60) }
  }
}

// --- Truth (3.5): the legs, per ledger ---------------------------------------

export function legsStatus() {
  const direct = []
  for (const [deviceId, leg] of _lastDirectByPeer.entries()) {
    direct.push({ deviceId, ...leg })
  }
  const stagedAnswers = []
  for (const [transferId, b64] of _stagedManualAnswers.entries()) {
    stagedAnswers.push({ transferId, answerRecordB64: b64 })
  }
  const executors = []
  for (const ex of _executors.values()) {
    executors.push({ id: ex.id, page: ex.page, connectedAt: new Date(ex.connectedAt).toISOString(), sessions: ex.sessions.size })
  }
  const pendingSyncAnswers = []
  for (const [messageId, p] of _pendingSyncAnswers.entries()) {
    pendingSyncAnswers.push({ messageId: String(messageId).slice(0, 12), attempts: p.attempts, lastReason: String(p.lastReason || (p.res ? 'publish_pending' : 'build_pending')).slice(0, 40) })
  }
  let executorHosted = 0
  for (const st of _channels.values()) if (st.via && String(st.via).startsWith('executor:')) executorHosted++
  return {
    ok: true,
    direct,
    cloud: _lastCloudLeg,
    stagedManualSyncOfferB64: _stagedManualSyncOfferB64 || '',
    stagedManualAnswers: stagedAnswers,
    channels: _channels.size,
    fanoutBusy: _fanoutBusy,
    rtcContext: typeof RTCPeerConnection !== 'undefined',
    executors,
    executorHosted,
    pendingSyncAnswers,
    pollRefusals: [..._pollRefusals],
    pollTraces: [..._pollTraces],
    fanoutTargets: [..._fanoutTargets],
    answerWaitTraces: [..._answerWaitTraces],
    actTraces: [..._actTraces],
    frameTraces: [..._frameTraces],
  }
}
