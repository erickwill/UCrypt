/**
 * UCrypt — R76 Part E "Secure Direct Device Transfer" — WORKER ORCHESTRATION
 * (transfer-plane message router). New in v2.42.14.
 *
 * The MV3 service worker owns ALL transfer key material: chain keys, device
 * identity, per-transfer ephemeral keys, K_transfer and the receiver inbox.
 * Pages (transfer.html, popup, options) never see recovery words or plane
 * keys — they exchange already-sealed record envelopes and non-secret
 * artifacts (deviceIds, labels, fingerprints, progress) via runtime messages.
 * Every TRANSFER_* message the background router forwards lands here.
 *
 * Layer separation (owner order): the SYNC plane (lib/sync.js + lib/vault.js
 * + lib/transports/*) keeps its semantics untouched — the only read this
 * module makes across the boundary is vault.getUnlockedSyncMnemonic(), the
 * additive read-only export that mirrors the post-unlock derivation path.
 *
 * Honesty gates enforced here:
 *   - availability is temporary (default 10 minutes) and user-enabled;
 *   - the receiver ALWAYS explicitly accepts (no auto-open, no auto-execute);
 *   - default transfer limit 20 MB, hard cap 100 MB;
 *   - NO relay: the page creates RTCPeerConnection({iceServers: []});
 *   - lock cancels everything (onVaultLocked wipes all state).
 *
 * R85 (T7, F-R84-XFER-4): session TRUTH and availability now survive MV3
 * worker recycles within a browser session. A SEALED snapshot (AES-GCM under
 * the chain-derived device-registry plane key) of the resumable sessions +
 * the availability record lives in chrome.storage.session — it never reaches
 * disk, clears at browser session end (honest boundary), and the vault lock
 * clears it (the honest lock boundary is unchanged). On worker wake the
 * snapshot is restored: resumable sessions (sender waiting on an answer,
 * receiver with a pending decision) come back live; in-flight WebRTC-bound
 * states terminate with a typed "interrupted — resend" notice — never a
 * silent reset.
 */

import {
  configureSyncChainBridge, getVaultState, getUnlockedSyncMnemonic, markRosterDirty,
  vaultEntryCountPublic, buildChainStateRecord, handleIncomingChainState,
  setChainStateSelfId, recordSyncMoment } from '../vault.js'
import { bytesToBase64, base64ToBytes, encryptString, decryptString } from '../crypto.js'
import {
  deriveChainKeys,
  getOrCreateDeviceIdentity,
  generateEphemeralKeys,
  transcriptHash,
  deriveTransferSecrets,
  transferFingerprint,
  mailboxLocator,
  randomHex32,
  setDeviceIdentityLabel,
  setDeviceIdentityType,
  sanitizeDeviceType,
} from './core.js'
import {
  publishPresence,
  withdrawPresence,
  listAvailablePeers,
  removePeer,
  forgetPeer,
  knownPeers,
  getPeerEntry,
  sealForPeer,
  openFromPeer,
  putRecordToMailbox,
  readOwnMailbox,
  recordToManual,
  recordFromManual,
  sealPresenceRecord,
  sealPresenceCarrier,
  publishSealedPresence,
  transferError,
  countPeers,
  loadPeerMap,
  learnPeer,
  renamePeerLabel,
  augmentRosterFromMap,
} from './mailbox.js'
import {
  TRANSFER_STATES,
  isActiveSenderState,
  isActiveReceiverState,
  isTerminalState,
  cleanupPlan,
  isReportableStage,
  senderOfferExpired,
  PRESENCE_STATES,
} from './lifecycle.js'
import {
  CHUNK_SIZE,
  DEFAULT_TRANSFER_LIMIT,
  HARD_TRANSFER_CAP,
  sanitizeFilename,
  executableOrArchiveWarning,
  buildFileOffer,
  buildFrameMeta,
  validateTransferRequest,
  sealChunk,
  openChunk,
  finalizeInbox,
} from './session.js'
// R135-F2 (§2): the transcript-bound handshake code — static import (the R96
// SW boundary law: the service worker's import graph stays static-only).
import { handshakeCode as beam2HandshakeCode } from '../beam2/transcript.js'
import { rendezvousCapability, resetRendezvousSession } from './mailbox.js' // R142-A3: knownPeers already rides the STATIC import block above (line 59) — the dynamic import() the roster used was doubly wrong (the A2 path AND the SW-banned mechanism; the G93 field harness caught it)
// R134 §2 — BEAM 2: the new architecture's modules (identity law 0.54, the
// typed envelopes, the crash-safe machine law 0.56, the lane truth law 0.55,
// the protocol core incl. the legacy-bridge negotiation).
import {
  getOrCreateBeam2Identity,
  loadBeam2SigningKey,
  signPayloadWithDeviceKey,
  verifyPayloadAgainstChainKey,
  publishToChainRoster,
  assertNoSecretsRide,
  BEAM2_IDENTITY_KEY,
  BEAM2_CHAIN_KEYS_KEY,
} from '../beam2/identity.js'
import {
  buildEnvelope,
  sealEnvelope,
  validateEnvelope,
  InboundTracker,
  OutboundTracker,
  sweepExpired,
  compactMailbox,
  sessionDeadlines,
  remainingMs,
  OFFER_TTL_MS,
  SESSION_TTL_MS,
} from '../beam2/envelope.js'
import {
  Beam2Session,
  scanResumableSessions,
  compactJournal,
  STATES as BEAM2_STATES,
  TERMINALS as BEAM2_TERMINALS,
  EVENTS as BEAM2_EVENTS,
  BEAM2_JOURNAL_KEY,
} from '../beam2/session.js'
import {
  LANES as BEAM2_LANES,
  LANE_NAMES as BEAM2_LANE_NAMES,
  laneTruthRow,
  selectLane as beam2SelectLane,
  advertiseCaps as beam2AdvertiseCaps,
  CHUNK_SIZE as BEAM2_CHUNK_SIZE,
  MAX_FILE_BYTES as BEAM2_MAX_FILE_BYTES,
  validateFileEdge as beam2ValidateFileEdge,
  chunkCountFor as beam2ChunkCountFor,
} from '../beam2/lanes.js'
import {
  negotiateCaps as beam2NegotiateCaps,
  BEAM2_PROTOCOL_VERSION,
  resolveConcurrentOffers,
  lateDeclineOutcome,
  cancelPropagation,
  skewSafeExpiry,
} from '../beam2/protocol.js'
// R136 §5 — THE BEAM 3 ENGINE (static imports — the R96 SW boundary law).
import { createBeam3Engine, beam3EngineError } from '../beam3/engine.js'
import { InboxPoller, relayGate, deviceDisplayName, defaultDeviceName, isBannedPlaceholder, choosePlane } from '../beam3/spine.js'
import { deriveChainState } from '../chain-state.js'
import { PLANES as BEAM3_PLANES, routeTruthLine as beam3RouteTruth, selectPlane as beam3SelectPlane } from '../beam3/planes.js'
import {
  configureBeamSync,
  syncPollTick,
  teardownAll as beamSyncTeardownAll,
  legsStatus as beamSyncLegsStatus,
  fanout as beamSyncFanout,
  openManualSyncSignal,
  openManualSyncAnswer,
  registerBeamExecutorPort,
} from '../beamsync.js'
// R98 (S8) — the Beam plane: the join handshake, the origin's decision and
// the joiner's adoption all ride the EXISTING rendezvous + file-plane rails.
import {
  BEAM_WINDOW_MINUTES_DEFAULT,
  BEAM_WINDOW_MINUTES_MAX,
  BEAM_ENVELOPE_NAME,
  deviceFingerprint,
  openJoinRecord,
  listJoinRequests,
  listJoinRefusals,
  decideJoinRequest,
  publishJoinRecord,
  deliverJoinRecord,
} from '../beam.js'
import { beamEnvelope, adoptBeamEnvelope, getTransportRecord } from '../vault.js'
// R98 (S8.6): the cloud hint reuses the R95 pairing payload's EXACT
// non-secret projection (provider + stripped URL — the F-95-03 vetted path).
import { safeCloudForPairing } from '../sync.js'

// --- Worker-local transfer state (memory only; wiped on lock) -------------------

/** Chain key cache — derived at availability-enable, cleared on lock. */
let _chainKeys = null
let _identity = null
// R148 §6.5 (LAW #74) — the SELF-REMOVED state: this device finds its own
// tombstone in the chain's roster → the typed banner + the push gate (the
// removed device learns its state and stops pushing; the rejoin path is the
// words/Cloud Sync door). Persisted so a fresh worker inherits the state.
const SELF_REMOVED_KEY = 'ucrypt:transfer:selfRemoved'
let _selfRemoved = null
;(async () => { try { const c = (globalThis.chrome && chrome.storage && chrome.storage.local) ? chrome.storage.local : null; if (!c) return; const g = await c.get(SELF_REMOVED_KEY); _selfRemoved = (g && g[SELF_REMOVED_KEY]) || null } catch { /* fresh state */ } })()
/** {enabled, expiresAt, label} — the ONLY availability source of truth. */
let _availability = null
/** Devices seen in the most recent presence listing (non-secret). */
let _lastAvailablePeers = []
/** transferId → session (both roles). Never persisted. */
const _sessions = new Map()

// ═════════════════════════════════════════════════════════════════════════
// R134 §2 — BEAM 2 ENGINE ("Beam Two — The AirDrop Standard") — the new
// architecture riding the same rendezvous plane. The legacy path above is
// MAINTAINED, NOT DELETED (lib/transfer/legacy-bridge.js is its named
// façade); Beam 2 degrades to the bridge when a peer predates it (§3).
//
//   A. Identity — law 0.54: the ECDSA P-256 device key, created at join,
//      public key published to the chain roster; EVERY control envelope is
//      signed and verified BEFORE any modal renders.
//   B. Presence — law 0.46 ride-along: the heartbeat now advertises the
//      Beam 2 caps (sealPresenceRecord's beam2Caps block).
//   C. Signaling — the typed v2 envelopes over the 'beam2' record kind.
//   D. Lanes — law 0.55: W (WebRTC direct, STUN only) → C (cloud relay)
//      → M (manual); degradation is TYPED and VISIBLE.
//   E. Sessions — law 0.56: the crash-safe machine with the append-only
//      journal; a crash is a pause, not a loss.
// ═════════════════════════════════════════════════════════════════════════

/** The Beam 2 identity + signing key (lazy, restored per worker life). */
let _beam2Identity = null
let _beam2SigningKey = null

/** The Beam 2 session machines + trackers (in-memory; the journal persists). */
const _beam2Sessions = new Map() // sessionId → Beam2Session
const _beam2Inbound = new InboundTracker()
const _beam2Outbound = new OutboundTracker()
const _beam2SeenComplete = new Set()
/** The most recent typed orchestration rows for the transfer page (bounded). */
const _beam2Log = []
const BEAM2_LOG_CAP = 24
/** The adaptive polling cadence (law §2.B): fast during an active session,
 * slow idle, exponential backoff on failure. */
const BEAM2_POLL_ACTIVE_MS = 2000
const BEAM2_POLL_IDLE_MS = 30000
const BEAM2_POLL_BACKOFF_MAX_MS = 5 * 60 * 1000
let _beam2PollPhase = 'idle' // 'idle' | 'active'
let _beam2PollFailures = 0
let _beam2LastPollAt = 0

/** The chrome.storage.local adapter for the Beam 2 journal + identity. */
const beam2Store = {
  get: async (k) => {
    const { [k]: v } = await chrome.storage.local.get(k)
    return v
  },
  set: async (k, v) => {
    await chrome.storage.local.set({ [k]: v })
  },
}

function beam2LogRow(row) {
  _beam2Log.push({ ...row, at: Date.now() })
  while (_beam2Log.length > BEAM2_LOG_CAP) _beam2Log.shift()
}

// ── R136 §5 — THE BEAM 3 ENGINE BINDING ──────────────────────────────
let _beam3Engine = null
/**
 * The Beam 3 engine (lazy, one per worker lifetime). The bindings follow
 * the R96 SW boundary law: chrome.* lives HERE, the engine stays pure.
 * R136-F2: the relay capability counts Drive AND WebDAV AND Dropbox —
 * "the connected cloud IS the relay"; the WebDAV-only requirement is dead.
 */
async function beam3Engine() {
  if (_beam3Engine) return _beam3Engine
  const { deviceId, label } = await (async () => {
    try {
      if (!_identity) return { deviceId: '', label: '' }
      return { deviceId: String(_identity.deviceId || ''), label: String(_identity.label || '') }
    } catch { return { deviceId: '', label: '' } }
  })()
  _beam3Engine = createBeam3Engine({
    store: {
      get: async (k) => {
        const { [k]: v } = await chrome.storage.local.get(k)
        return v
      },
      set: async (k, v) => {
        await chrome.storage.local.set({ [k]: v })
      },
    },
    self: { deviceId, label },
    getPeer: async (peerDeviceId) => {
      try { return await getPeerEntry(_chainKeys, String(peerDeviceId)) } catch { return null }
    },
    sendToPeer: async (peerDeviceId, env) => {
      // R140 §6.4 — the publish path returns the RECEIPT (the commit etag is
      // the confirmed-write fact the honest mailbox law derives from)
      return await beam2Send(peerDeviceId, env) // the same signed, sealed publish path (law 0.54)
    },
    armAvailability: async (minutes) => {
      // R136-F4: the auto-arm. A locked vault is a TYPED no (the strip's
      // red row carries its one-tap fix), never a throw into the void.
      try {
        await enableAvailability({ minutes: Number(minutes) || 10 })
        return true
      } catch { return false }
    },
    disarmAvailability: async () => {
      try { await disableAvailability({ publish: true }); return true } catch { return false }
    },
    relayCapability: async () => {
      try {
        const rec = await getTransportRecord()
        if (!rec || !rec.id) return { available: false, label: '' }
        const RELAY_KINDS = { gdrive: 'Google Drive', webdav: 'WebDAV', custom: 'your cloud', http: 'your cloud', dropbox: 'Dropbox' }
        const label = RELAY_KINDS[rec.id]
        if (!label) return { available: false, label: '' }
        return { available: true, label, transport: rec.id }
      } catch { return { available: false, label: '' } }
    },
    // R139 §5.6 — the availability facts (ONE surface's truth: armed + minutes)
    availabilityFacts: async () => {
      const a = availabilityActive()
      if (!a) return { armed: false, minutes: 0 }
      const minutes = Math.max(0, Math.round((Date.parse(a.expiresAt) - Date.now()) / 60000))
      return { armed: true, minutes }
    },
    // R140 §7.2 — THE ONE CHAIN TRUTH: the engine's cloud gate, the strip,
    // and the pill all read THIS derivation (never a second writer)
    chainTruth: async () => {
      try {
        const { ['ucrypt:chainState:wake']: wake } = await chrome.storage.local.get('ucrypt:chainState:wake')
        const { ['ucrypt:lastPull']: lastPull } = await chrome.storage.local.get('ucrypt:lastPull')
        const rec = await getTransportRecord()
        const RELAY_KINDS = { gdrive: 'Google Drive', webdav: 'WebDAV', custom: 'your cloud', http: 'your cloud', dropbox: 'Dropbox' }
        const label = rec && rec.id ? (RELAY_KINDS[rec.id] || '') : ''
        return deriveChainState({ cloudConnected: !!(rec && rec.id), cloudLabel: label, wake: wake || null, lastPull: lastPull || null })
      } catch {
        return deriveChainState({ cloudConnected: false })
      }
    },
    // R140 §6.1 — the peer's ROSTER name (the header status resolves it)
    peerName: async (peerDeviceId) => {
      try {
        const peer = await getPeerEntry(_chainKeys, String(peerDeviceId))
        const fromRoster = peer && (peer.label || peer.name) ? String(peer.label || peer.name) : ''
        if (fromRoster && !isBannedPlaceholder(fromRoster)) return fromRoster
        const avail = _lastAvailablePeers.find((p) => p.deviceId === String(peerDeviceId))
        return avail && avail.label && !isBannedPlaceholder(avail.label) ? String(avail.label) : ''
      } catch { return '' }
    },
    // R139 D6 — the Beam chrome renders ONLY inside the diagnostics drawer;
    // the engine's projection carries it there and nowhere else
    beamIdentity: () => (_beam2Identity && _beam2Identity.thumb)
      ? `Beam 2 — device key ${String(_beam2Identity.thumb).slice(0, 12)}… · protocol v${BEAM2_PROTOCOL_VERSION} — every transfer is signed and chain-verified`
      : '',
  })
  return _beam3Engine
}

/** R139 §5.1 — THE TRANSPORT MIRROR: the ONE event source that feeds the
 * transport executors' truth into THE BOND. Whatever plane moves the bytes
 * (Beam 2 sessions today), the journey machine advances from HERE — never
 * from a second presentation writer. Diff-based: each session's state fires
 * exactly the edges the delta proves, once per delta. */
const _bondMirrorSeen = new Map() // sessionId → last mirrored state

// ── R140 §6.3 — THE INBOX THAT POLLS ITSELF (the worker's own poller) ──
// Receiving is passive: while the Receive intent is open and availability is
// armed, the inbox polls every 2–4 s (jittered), again on focus, and reports
// its own truth. The STATUS handler drives it (a page-open poll every 2 s
// resurrects it across worker restarts); its own timer covers the SW-alive
// page-closed case.
const _beam3Inbox = new InboxPoller({ onPoll: () => pollMailbox(), now: () => Date.now() })
let _beam3IntentRole = '' // the last declared intent ('send' | 'receive' | '')
const INBOX_DUE_MS = 3000 // the STATUS-driven poll is due at most every 3 s (the 2–4 s cadence's midpoint)
async function mirrorBondTransport() {
  if (!_beam3Engine) return
  try {
    const eng = await beam3Engine()
    const snap = beam2StatusSnapshot()
    for (const s of snap.sessions || []) {
      const prev = _bondMirrorSeen.get(s.sessionId)
      if (prev === s.state) continue
      _bondMirrorSeen.set(s.sessionId, s.state)
      if (s.state === 'OFFERED' && s.role === 'receive') await eng.noteTransport({ type: 'offer-in' })
      else if (s.state === 'ACCEPTED') {
        // R140 §6.4 — the sender's receipt upgrade: the peer's ACCEPT proves
        // the offer was FETCHED (the relay read registered) — the waiting
        // copy upgrades from 'written' to 'fetched' the same instant
        if (prev === 'OFFERED') await eng.noteTransport({ type: 'offer-fetched', peerName: s.peerLabel || '' })
        await eng.noteTransport({ type: 'accept' })
      }
      else if (s.state === 'TRANSFERRING') await eng.noteTransport({ type: 'begin' })
      else if (s.state === 'VERIFYING') await eng.noteTransport({ type: 'chunks', lastAcked: s.lastAckedChunk })
      else if (s.state === 'COMPLETED') await eng.noteTransport({ type: 'verify-ok' })
      else if (s.state === 'FAILED_INTEGRITY') await eng.noteTransport({ type: 'verify-fail' })
      else if (s.state === 'DECLINED') await eng.noteTransport({ type: 'decline' })
      else if (s.state === 'CANCELED') await eng.noteTransport({ type: 'decline' }) // the peer's cancel ends the wait — the same typed terminal family
      else if (s.state === 'FAILED_NETWORK') await eng.noteTransport({ type: 'relay-fail', hop: 'relayWrite' })
    }
    // the terminal cleanup: drop mirror entries whose sessions vanished
    const live = new Set((snap.sessions || []).map((s) => s.sessionId))
    for (const k of [..._bondMirrorSeen.keys()]) if (!live.has(k)) _bondMirrorSeen.delete(k)
  } catch { /* the mirror is best-effort — it never takes the poll down */ }
}

/**
 * R138 §4.1 — THE VISIBLE-DEVICE COUNT (the single fact behind the devices
 * row): OTHER chain devices currently reachable (available AND fresh).
 * The same sources the roster renders from — one fact, one truth.
 */
async function beam3VisibleDeviceCount() {
  try {
    const mine = _identity ? _identity.deviceId : null
    return _lastAvailablePeers.filter((a) => a.deviceId !== mine && !a.stale).length
  } catch { return 0 }
}

/** Get-or-create the Beam 2 identity (law 0.54) — idempotent per device. */
async function ensureBeam2Ready() {
  if (_beam2Identity && _beam2SigningKey) return _beam2Identity
  _beam2Identity = await getOrCreateBeam2Identity(
    () => beam2Store.get(BEAM2_IDENTITY_KEY),
    (v) => beam2Store.set(BEAM2_IDENTITY_KEY, v),
  )
  _beam2SigningKey = await loadBeam2SigningKey(_beam2Identity)
  if (!_beam2SigningKey) throw transferError('internal', 'Beam 2 signing key unavailable')
  // publish the PUBLIC key into the chain roster (the replication lane's
  // config-metadata class — a public key is not a secret)
  try {
    await publishToChainRoster(
      (k) => beam2Store.get(k),
      (k, v) => beam2Store.set(k, v),
      _identity.deviceId,
      _beam2Identity.pubJwk,
    )
  } catch { /* the roster write is best-effort; the local key still works */ }
  return _beam2Identity
}

/** The caps THIS device advertises (Lane W attempted, C always available). */
function beam2OwnCaps() {
  return beam2AdvertiseCaps({
    beam2: true,
    webrtc: typeof globalThis.RTCPeerConnection === 'function',
    rendezvous: true,
    maxChunk: BEAM2_CHUNK_SIZE,
    protocolVersion: `2.${Math.floor(BEAM2_PROTOCOL_VERSION)}.0`,
  })
}

/**
 * Seal + publish a Beam 2 control envelope to a peer: the envelope rides
 * INSIDE the sealed 'beam2' payload (the mailbox sees only ciphertext —
 * §2.G), signed TWICE: the record sig (the legacy plane's discipline) and
 * the device-key signature over the payload (law 0.54).
 */
async function beam2Send(peerDeviceId, env) {
  assertNoSecretsRide(env.payload, `beam2:${env.type}`)
  const peer = await getPeerEntry(_chainKeys, String(peerDeviceId))
  if (!peer) throw transferError('peer_unknown', `Beam 2 cannot seal to an unknown peer: ${String(peerDeviceId)}`)
  const { record } = await sealForPeer(_chainKeys, _identity, peer, 'beam2', env, {
    transferId: '', seq: env.seq, nonce: '', expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  })
  // R140 §6.4 — THE RECEIPT: the mailbox merge-write returns its commit etag —
  // the confirmed-write fact the sender's waiting copy derives from (an
  // unevidenced delivery promise is unrepresentable from this call on)
  const put = await putRecordToMailbox(_chainKeys, _identity, await mailboxLocator(_chainKeys, String(peerDeviceId)), record)
  let storeLabel = ''
  try {
    const rec = await getTransportRecord()
    storeLabel = rec && rec.id ? ({ gdrive: 'Google Drive', webdav: 'WebDAV', custom: 'your cloud', http: 'your cloud', dropbox: 'Dropbox' })[rec.id] || '' : ''
  } catch { /* the label is best-effort — the receipt's etag is the fact */ }
  return { ok: true, record, receipt: { at: Date.now(), store: storeLabel, commit: String((put && put.etag) || '') } }
}

/** Build + sign + send a typed control envelope in one step. */
async function beam2Emit(peerDeviceId, sessionId, type, payload, seq) {
  const id = _beam2Identity
  const draft = buildEnvelope({
    type, sessionId, from: id.thumb, to: String(peerDeviceId),
    seq: Number.isInteger(seq) ? seq : _beam2Outbound.alloc(sessionId),
    payload,
  })
  const sig = await signPayloadWithDeviceKey(_beam2SigningKey.privateKey, { ...draft, sig: '' })
  const sealed = sealEnvelope(draft, sig)
  await beam2Send(peerDeviceId, sealed)
  return sealed
}

/** The active Beam 2 session for a device pair, if any. */
function beam2ActiveSession() {
  for (const s of _beam2Sessions.values()) {
    if (!isBeam2Terminal(s.state)) return s
  }
  return null
}
function isBeam2Terminal(state) {
  return Object.values(BEAM2_TERMINALS).includes(state)
}

/**
 * THE BEAM 2 TICK — poll the mailbox for 'beam2' records; verify, dedupe,
 * drive the machine. Called from the presence cadence (adaptive: fast while
 * a session is live, slow idle) and from TRANSFER_BEAM2_TICK.
 */
async function beam2Tick() {
  if (!(_chainKeys && _identity) && !(await selfHealOrLocked())) return { ok: false, locked: true }
  const now = Date.now()
  _beam2LastPollAt = now
  let records = []
  try {
    records = await readOwnMailbox(_chainKeys, _identity)
    _beam2PollFailures = 0
  } catch (e) {
    _beam2PollFailures++
    return { ok: false, error: e && e.message, backoffMs: Math.min(BEAM2_POLL_BACKOFF_MAX_MS, BEAM2_POLL_IDLE_MS * 2 ** _beam2PollFailures) }
  }
  const beam2Records = records.filter((r) => r && r.kind === 'beam2')
  const processed = []
  for (const rec of beam2Records) {
    try {
      const opened = await openFromPeer(_chainKeys, _identity, rec)
      const env = validateEnvelope(opened.payload)
      // law 0.54: verify the device-key signature BEFORE anything renders
      const senderPub = await (async () => {
        const roster = (await beam2Store.get(BEAM2_CHAIN_KEYS_KEY)) || {}
        return roster[opened.from] ? roster[opened.from].pubJwk : (opened.payload && opened.payload.senderPubJwk) || null
      })()
      const verdict = await verifyPayloadAgainstChainKey(senderPub, env.sig, { ...env, sig: '' })
      if (!verdict.ok) {
        beam2LogRow({ kind: 'row', type: env.type, sessionId: env.sessionId, from: env.from, verdict: 'signature-refused', reason: verdict.reason })
        continue
      }
      const tracker = _beam2Inbound.offer(env)
      if (!tracker.deliver) {
        processed.push({ sessionId: env.sessionId, type: env.type, disposition: tracker.reason })
        continue
      }
      processed.push(await beam2DriveMachine(env, opened.from))
    } catch (e) {
      beam2LogRow({ kind: 'row', type: 'TICK', verdict: 'error', reason: String((e && e.message) || e).slice(0, 120) })
    }
  }
  // the terminal sweep — no orphan ciphertext is ever left behind
  const compaction = compactMailbox(beam2Records, now)
  await compactJournal(beam2Store, now)
  return { ok: true, processed, compactionRemoved: compaction.removed }
}

/**
 * Drive the session machine for one verified, de-duplicated envelope.
 * Every transition journals (law 0.56); every outcome produces a typed row.
 */
async function beam2DriveMachine(env, senderDeviceId = '') {
  const sid = env.sessionId
  let sess = _beam2Sessions.get(sid)
  if (!sess) {
    sess = new Beam2Session({ sessionId: sid, role: 'receiver', store: beam2Store })
    _beam2Sessions.set(sid, sess)
  }
  const P = env.payload || {}
  switch (env.type) {
    case 'HELLO':
    case 'CAPS': {
      beam2LogRow({ kind: 'row', type: env.type, sessionId: sid, from: env.from, verdict: 'caps-learned', caps: P.caps || null })
      return { sessionId: sid, type: env.type, disposition: 'caps' }
    }
    case 'OFFER': {
      // the manifest: { name, size, mime, sha256, chunkSize, lane, ttl }
      if (sess.state !== BEAM2_STATES.IDLE) {
        return { sessionId: sid, type: env.type, disposition: 'already-known' }
      }
      await sess.fire(BEAM2_EVENTS.OFFER, { offerExpiresAt: sess.offerExpiresAt, manifest: P.manifest || null })
      // R135-F2 (§2): the receiver keeps the OFFER envelope — the transcript
      // code derives from BOTH envelopes when this device accepts.
      sess.offerEnv = env
      beam2LogRow({ kind: 'row', type: 'OFFER', sessionId: sid, from: env.from, verdict: 'modal-armed' })
      // R140 §6.1 — the sender's ROSTER label rides the disposition (the
      // offer card names its sender; the banned placeholder is unrepresentable)
      let senderLabel = String((env.payload && env.payload.fromLabel) || '')
      if (!senderLabel) {
        try {
          const peer = await getPeerEntry(_chainKeys, String(senderDeviceId || env.from || ''))
          senderLabel = peer && peer.label && !isBannedPlaceholder(peer.label) ? String(peer.label) : ''
        } catch { senderLabel = '' }
      }
      return { sessionId: sid, type: env.type, disposition: 'incoming-offer', senderDeviceId, senderLabel, manifest: P.manifest || null, senderPubJwk: P.senderPubJwk || null, fingerprint: P.fingerprint || null, transcriptPending: true }
    }
    case 'ACCEPT': {
      await sess.fire(BEAM2_EVENTS.ACCEPT)
      await sess.fire(BEAM2_EVENTS.BEGIN_TRANSFER)
      // R135-F2 (§2): the SENDER derives the transcript-bound code from its
      // OFFER + the received ACCEPT — the same handshake bytes the receiver
      // derived its code from. A rogue-key substitution shows DIFFERENT codes.
      if (sess.role === 'sender' && sess.offerEnv) {
        try {
          sess.transcriptCode = await beam2HandshakeCode({ offerEnv: sess.offerEnv, acceptEnv: env })
          beam2LogRow({ kind: 'row', type: 'ACCEPT', sessionId: sid, verdict: 'transcript-code-derived' })
        } catch (e) {
          beam2LogRow({ kind: 'row', type: 'ACCEPT', sessionId: sid, verdict: 'transcript-error', reason: String((e && e.message) || e).slice(0, 80) })
        }
      }
      beam2LogRow({ kind: 'row', type: 'ACCEPT', sessionId: sid, verdict: 'transfer-begin' })
      return { sessionId: sid, type: env.type, disposition: 'transfer-begin', transcriptCode: sess.transcriptCode || null }
    }
    case 'DECLINE': {
      const outcome = lateDeclineOutcome(sess.state)
      if (outcome.honored) await sess.fire(BEAM2_EVENTS.DECLINE)
      beam2LogRow({ kind: 'row', type: 'DECLINE', sessionId: sid, verdict: outcome.terminal || 'late' })
      return { sessionId: sid, type: env.type, disposition: outcome.terminal || 'late-decline' }
    }
    case 'CANCEL': {
      const prop = cancelPropagation(sess.state)
      if (prop.propagate) await sess.fire(BEAM2_EVENTS.CANCEL)
      beam2LogRow({ kind: 'row', type: 'CANCEL', sessionId: sid, verdict: prop.propagate ? 'propagated' : 'ignored-terminal' })
      return { sessionId: sid, type: env.type, disposition: prop.propagate ? 'canceled' : 'terminal-ignored' }
    }
    case 'ACK': {
      if (!isBeam2Terminal(sess.state)) await sess.noteChunk(Number(P.chunk) || 0)
      return { sessionId: sid, type: env.type, disposition: 'acked', chunk: Number(P.chunk) || 0 }
    }
    case 'PROGRESS': {
      return { sessionId: sid, type: env.type, disposition: 'progress', sent: Number(P.sent) || 0, total: Number(P.total) || 0 }
    }
    case 'COMPLETE': {
      // replayed COMPLETE is idempotent (the pinned EDGE)
      const replay = resolveReplayedCompleteTyped(sid, env.seq)
      if (replay.idempotent) return { sessionId: sid, type: env.type, disposition: 'idempotent-complete' }
      await sess.fire(BEAM2_EVENTS.CHUNKS_DONE)
      await sess.fire(P.verdict === 'sha-match' ? BEAM2_EVENTS.VERIFY_OK : BEAM2_EVENTS.VERIFY_FAIL)
      beam2LogRow({ kind: 'row', type: 'COMPLETE', sessionId: sid, verdict: P.verdict || 'sha-mismatch' })
      return { sessionId: sid, type: env.type, disposition: P.verdict === 'sha-match' ? 'completed' : 'failed-integrity' }
    }
    case 'BYE': {
      if (!isBeam2Terminal(sess.state)) await sess.fire(BEAM2_EVENTS.CANCEL)
      _beam2Inbound.release(sid)
      _beam2Outbound.release(sid)
      _beam2Sessions.delete(sid)
      return { sessionId: sid, type: env.type, disposition: 'cleanup' }
    }
    default:
      return { sessionId: sid, type: env.type, disposition: 'unhandled' }
  }
}

function resolveReplayedCompleteTyped(sessionId, seq) {
  const key = `${sessionId}:${seq}`
  if (_beam2SeenComplete.has(key)) return { deliver: false, idempotent: true }
  _beam2SeenComplete.add(key)
  return { deliver: true, idempotent: false }
}

/** Sender-side OFFER creation: the ONE-TOUCH ceremony's first machine step. */
async function beam2CreateOffer(peerDeviceId, manifest) {
  await ensureBeam2Ready()
  const edge = beam2ValidateFileEdge(manifest && manifest.size)
  if (!edge.ok) {
    return { ok: false, error: edge.code, userMessageKey: 'beam2ErrOverCap' }
  }
  const sessionId = `bsess-${randomHex32()}`
  const sess = new Beam2Session({ sessionId, role: 'sender', store: beam2Store })
  _beam2Sessions.set(sessionId, sess)
  const deadlines = sessionDeadlines()
  const payload = {
    manifest: { name: String(manifest.name || '').slice(0, 160), size: Number(manifest.size) || 0, mime: String(manifest.mime || '').slice(0, 80), sha256: String(manifest.sha256 || '').slice(0, 64) },
    chunkSize: BEAM2_CHUNK_SIZE,
    lane: BEAM2_LANE_NAMES.W,
    ttl: OFFER_TTL_MS,
    senderPubJwk: _beam2Identity.pubJwk,
    caps: beam2OwnCaps(),
  }
  await sess.fire(BEAM2_EVENTS.OFFER, { offerExpiresAt: deadlines.offerExpiresAt })
  const env = await beam2Emit(String(peerDeviceId), sessionId, 'OFFER', payload)
  // R135-F2 (§2): the sender keeps its OFFER envelope — the transcript-bound
  // handshake code derives from BOTH envelopes once the ACCEPT arrives.
  sess.offerEnv = env
  beam2LogRow({ kind: 'row', type: 'OFFER', sessionId, to: String(peerDeviceId), verdict: 'offered', manifestName: payload.manifest.name })
  return { ok: true, sessionId, offerExpiresAt: deadlines.offerExpiresAt, sessionExpiresAt: deadlines.sessionExpiresAt, envelopeSeq: env.seq, caps: payload.caps }
}

/** Receiver-side typed decisions (the modal's two buttons + cancel). */
async function beam2Respond(sessionId, peerDeviceId, decision) {
  const sess = _beam2Sessions.get(String(sessionId))
  if (!sess) return { ok: false, error: 'BEAM2_SESSION_UNKNOWN' }
  await ensureBeam2Ready()
  if (decision === 'accept') {
    await sess.fire(BEAM2_EVENTS.ACCEPT)
    const sealedAccept = await beam2Emit(String(peerDeviceId), String(sessionId), 'ACCEPT', { acceptedAt: Date.now() })
    // R135-F2 (§2): the receiver derives the transcript-bound code from the
    // OFFER it received + the ACCEPT it just sent — the sender derives the
    // same code from the same bytes. Both screens render THE code.
    let transcriptCode = null
    try {
      sess.acceptEnv = sealedAccept
      if (sess.offerEnv) transcriptCode = await beam2HandshakeCode({ offerEnv: sess.offerEnv, acceptEnv: sealedAccept })
      sess.transcriptCode = transcriptCode
    } catch { /* the code stays null — the page renders the pending truth */ }
    beam2LogRow({ kind: 'row', type: 'ACCEPT', sessionId, verdict: transcriptCode ? 'accepted+transcript-code' : 'accepted' })
    return { ok: true, state: sess.state, transcriptCode }
  }
  if (decision === 'decline') {
    const outcome = lateDeclineOutcome(sess.state)
    if (outcome.honored) await sess.fire(BEAM2_EVENTS.DECLINE)
    await beam2Emit(String(peerDeviceId), String(sessionId), 'DECLINE', { declinedAt: Date.now() })
    beam2LogRow({ kind: 'row', type: 'DECLINE', sessionId, verdict: 'declined' })
    return { ok: true, state: sess.state, terminal: outcome.terminal }
  }
  if (decision === 'cancel') {
    const prop = cancelPropagation(sess.state)
    if (prop.propagate) await sess.fire(BEAM2_EVENTS.CANCEL)
    await beam2Emit(String(peerDeviceId), String(sessionId), 'CANCEL', { canceledAt: Date.now() })
    beam2LogRow({ kind: 'row', type: 'CANCEL', sessionId, verdict: 'canceled' })
    return { ok: true, state: sess.state }
  }
  return { ok: false, error: 'BEAM2_DECISION_UNKNOWN' }
}

/** The status surface the transfer page renders (the lane truth + rows). */
function beam2StatusSnapshot() {
  const active = beam2ActiveSession()
  const lane = active && active.lane ? active.lane : null
  return {
    ok: true,
    ready: !!(_beam2Identity && _beam2SigningKey),
    thumb: _beam2Identity ? _beam2Identity.thumb : '',
    caps: beam2OwnCaps(),
    protocolVersion: BEAM2_PROTOCOL_VERSION,
    sessions: [..._beam2Sessions.values()].map((s) => ({
      sessionId: s.sessionId, role: s.role, state: s.state,
      lastAckedChunk: s.lastAckedChunk,
      countdowns: s.countdowns(),
      terminal: isBeam2Terminal(s.state),
    })),
    activeLane: lane,
    laneTruth: lane ? laneTruthRow(lane) : null,
    poll: { phase: _beam2PollPhase, lastPollAt: _beam2LastPollAt, failures: _beam2PollFailures, activeMs: BEAM2_POLL_ACTIVE_MS, idleMs: BEAM2_POLL_IDLE_MS },
    log: [..._beam2Log],
  }
}

/** R105 §2.3 — THE MULTI-WINDOW OFFER HINT (the bounded UI exception): when
 * one UCrypt surface consumes a transfer offer while ANOTHER surface polled
 * the same mailbox, the losing surface must show the typed one-line notice —
 * never silence. The worker witnesses both facts (session-scoped, dies with
 * the worker like every plane state, carries NO offer content):
 *   _offerSeenByCtx   offerId → Set<ctx>  — every surface the poll SERVED the offer to
 *   _offerConsumedBy  offerId → { ctx, at } — the surface whose ACCEPT consumed it
 * ctx = "tab:<id>" (extension pages) or the sender URL (popup-style views).
 * Cap: 32 entries FIFO per map — bounded memory per the same law as every
 * session ring. */
const _offerSeenByCtx = new Map()
const _offerConsumedBy = new Map()
const OFFER_HINT_CAP = 32
function ctxOf(sender) {
  const t = sender && sender.tab && sender.tab.id
  if (t != null) return `tab:${t}`
  return String((sender && sender.url) || 'ctx-unknown').slice(0, 120)
}
function offerSeenStamp(offerId, ctx) {
  if (!offerId || !ctx) return
  let set = _offerSeenByCtx.get(offerId)
  if (!set) { set = new Set(); _offerSeenByCtx.set(offerId, set) }
  set.add(ctx)
  if (_offerSeenByCtx.size > OFFER_HINT_CAP) {
    const oldest = _offerSeenByCtx.keys().next().value
    _offerSeenByCtx.delete(oldest)
  }
}
function offerConsumedStamp(offerId, ctx) {
  if (!offerId || !ctx) return
  _offerConsumedBy.set(offerId, { ctx, at: Date.now() })
  if (_offerConsumedBy.size > OFFER_HINT_CAP) {
    const oldest = _offerConsumedBy.keys().next().value
    _offerConsumedBy.delete(oldest)
  }
}
/** The losing surfaces for one consumed offer: every ctx that SAW it, minus
 * the consumer. The page renders the typed notice for each of these on its
 * next poll tick. */
function offerLoserContexts(offerId) {
  const consumed = _offerConsumedBy.get(offerId)
  const seen = _offerSeenByCtx.get(offerId)
  if (!consumed || !seen) return []
  return [...seen].filter((c) => c !== consumed.ctx)
}

/** R105 §2.3 observability seam (non-secret: two sizes, ids never) — the
 * battery pins the FIFO bounds through it. */
export function offerHintStats() {
  return { seen: _offerSeenByCtx.size, consumed: _offerConsumedBy.size, cap: OFFER_HINT_CAP }
}

/** R98 (S8.3) — the Beam window state (memory; the availability state is the
 * source of truth for the presence plane — this carries the BEAM truth: the
 * Add-device surface armed the beam, the window end, and the envelope for an
 * in-flight origin-side transfer). Wiped on lock like every plane state. */
let _beam = null
/** The origin's in-memory beam envelope {bytes: Uint8Array, size, sha256hex,
 * joinerDeviceId} for one transfer. The envelope is CIPHERTEXT (the exact
 * cloud bytes), but the memory discipline is the same as every plane secret:
 * lock wipes it. */
let _beamEnvelope = null
/** The joiner's beam state ({role:'joiner', phase, joinMessageId, origin…}).
 * Session-persisted (advisory — survives a worker recycle within the browser
 * session; cleared on lock like everything else). */
let _beamJoinState = null
/** S8.8 — join records that arrived by HAND (the zero-transport path). The
 * origin's poll merges them with the mailbox-rendezvous joins. Cleared on
 * lock like every plane state. */
let _manualJoins = []

/** S8.3 truthful beam status for every beam response. */
async function beamStatusMessage() {
  if (_beam && _availability && !_availability.enabled) _beam = null
  return {
    beam: {
      armed: !!(_beam && _beam.armed),
      windowEnd: (_beam && _beam.windowEnd) || '',
      envelopeLive: !!_beamEnvelope,
      joinPhase: _beamJoinState ? _beamJoinState.phase : '',
    },
  }
}

/** The joiner's fingerprint as the origin now knows it (post-learn). */
async function joinerFingerprint(chainKeys, deviceId) {
  try {
    const map = await loadPeerMap(chainKeys)
    const peer = map[String(deviceId || '')]
    return peer && peer.signPubJwk ? await deviceFingerprint(peer.signPubJwk) : ''
  } catch { return '' }
}

/** S8.6 — the ORIGIN'S cloud config hint (type + URL — never credentials,
 * the payload law): rides the beam offer so the joiner's next step is named.
 * The projection is the R95 pairing payload's vetted safeCloudForPairing —
 * the SAME strip-userinfo path the QR carrier has used since F-95-03. */
async function originCloudHint() {
  try {
    const t = await getTransportRecord()
    return t ? safeCloudForPairing(t) : null
  } catch { return null }
}

export const TRANSFER_AVAILABILITY_ALARM = 'ucrypt:transfer:availability'

// S8.9 (R99) — THE LIVING BEAM: the continuous direct-sync engine is wired
// here with THIS module's state accessors (no import cycle: the engine never
// imports the worker or lib/vault.js). The trigger fires from lib/vault.js
// beside every cloud push; the alarm tick fires from the background worker.
configureBeamSync({
  ensureChainReady,
  envelopeOf: () => beamEnvelope(),
  adoptEnvelope: (bytesB64, sha256hex) => adoptBeamEnvelope(String(bytesB64 || ''), String(sha256hex || '')),
  createSyncOffer: (args) => createOffer({ ...args, sync: true }),
  // R100 FIX (the live matrix found it, in TWO layers): (1) the accessor
  // previously passed the RECORD into the chainKeys parameter slot —
  // openOfferRecord(chainKeys, identity, record, opts) — so every real
  // sync-offer open died with 'bad_record' before a single gate ran; (2) the
  // projection shape (offerId/from/sdp) was handed to an engine expecting the
  // opened-session shape (offerMessageId/peerKeys/sdp) — the engine read
  // undefined and the auto-answer threw before the executor round-trip. The
  // battery's override re-implemented the open and masked BOTH; the live
  // beam caught them. The mapping below is the engine's contract.
  openSyncOffer: async (record) => {
    const { chainKeys, identity } = await ensureChainReady()
    const projection = await openOfferRecord(chainKeys, identity, record, { sync: true })
    if (!projection) return null
    return {
      transferId: projection.transferId,
      offerMessageId: projection.offerId,
      peerKeys: { deviceId: projection.from },
      peerLabel: projection.fromLabel || '',
      sdp: projection.sdp || '',
    }
  },
  acceptSyncOffer: (args) => acceptOffer(args),
  openSyncAnswer: async ({ record }) => {
    const { chainKeys, identity } = await ensureChainReady()
    const res = await openAnswerRecord(chainKeys, identity, record, null)
    return { ok: true, answer: res }
  },
  openSyncIce: async ({ record }) => {
    const { chainKeys, identity } = await ensureChainReady()
    const opened = await openFromPeer(chainKeys, identity, record, {})
    return { ok: true, transferId: opened.transferId, from: opened.from, payload: opened.payload || {} }
  },
  sealIce: ({ to, transferId, candidate }) => sealRecord({ kind: 'ice', to, transferId, payload: { candidate } }),
  sealComplete: ({ to, transferId }) => sealRecord({ kind: 'complete', to, transferId, payload: {} }),
  publishRecord: (args) => publishRecord(args),
  sealChunk: (args) => sealChunkMessage(args),
  // R100 diagnostics: the seal gate's session truth (role/key/state only —
  // never material), so the act trace can name WHY a seal refused.
  sessionProbe: async (transferId) => {
    const id = String(transferId || '')
    const sess = _sessions.get(id)
    const cleaned = _cleanupLedger.filter((e) => e.transferId === id.slice(0, 8)).slice(-2)
    return { exists: !!sess, role: sess ? sess.role : '', hasKey: !!(sess && sess.key), state: sess ? sess.state : '', cleanups: cleaned }
  },
  ingestFrame: (args) => ingestFrame(args),
  inboxState: (args) => inboxState(args),
  finalizeInbox: (args) => finalizeInboxMessage(args), // R100: the digest verification runs HERE (the engine's receiver path)
  exportInbox: (args) => exportInbox(args),
  // R111 §3.2 — the visible moment: the engine records the persisted ledger
  // line + notifies the open pages when a direct-lane envelope lands; the
  // peer label lookup names the sender honestly (the map's label or '').
  recordSyncMoment: (m) => recordSyncMoment(m),
  peerLabel: async (deviceId) => {
    try {
      if (!_chainKeys || !deviceId) return ''
      const p = await getPeerEntry(_chainKeys, String(deviceId))
      return (p && p.label) || ''
    } catch { return '' }
  },
  localCandidates: async (pc) => (pc.LocalCandidates || []),
  chunkSize: CHUNK_SIZE,
  channelLowWater: 128 * 1024,
})

// R100 (S8.9 completion) — THE CHAIN-ROSTER→TRANSFER-MAP SEEDING (the R99
// candidate, now law): every push stamps THIS device's public identity onto
// the wire snapshot; every pull learns the whole chain into the transfer
// peer map (TOFU preserved — a key change is learnPeer's incident, never an
// update). The living beam's fan-out reads THAT map: after one pull the
// chain devices are the fan-out's targets. Public keys only cross the wire.
configureSyncChainBridge({
  // R111 §3.1 — the identity provider accepts the push options ({ lane }) and
  // stamps the device's own LIVING-SYNC telemetry onto its roster row: the
  // last sync is THIS push (the moment is now), the lane is the lane that
  // carries this envelope, and the entry count is this device's real count.
  identityProvider: async (opts = {}) => {
    try {
      const { identity } = await ensureChainReady()
      if (!identity || !identity.deviceId) return null
      // R108 §3.2 — the self label rides with its write time (the per-entry
      // last-writer law needs it on the wire, like every other device's).
      // R111 §3.1 — the self row also names its last sync (when + lane) and
      // its entry count — the per-device sync surface reads exactly this.
      setChainStateSelfId(identity.deviceId)
      const lane = opts && opts.lane === 'direct' ? 'direct' : 'cloud'
      // R113 §3.1 — the self-declared device type rides the stamp (the label
      // law's carrier; the type merges by typeSetAt everywhere it lands).
      return { deviceId: identity.deviceId, signPubJwk: identity.signPubJwk, agrPubJwk: identity.agrPubJwk, label: identity.label || '', labelSetAt: Number(identity.labelSetAt) || 0, deviceType: sanitizeDeviceType(identity.deviceType), typeSetAt: Number(identity.typeSetAt) || 0, syncAt: Date.now(), syncLane: lane, entryCount: vaultEntryCountPublic() }
    } catch { return null } // locked / chain-less: stamp nothing, the push stands
  },
  chainDevicesSink: async (devices) => {
    const { chainKeys, identity } = await ensureChainReady() // throws while locked — the caller warns, the pull stands
    // R148 §6.5 (LAW #74) — THE SELF-TOMBSTONE CHECK: the removed device
    // LEARNS ITS OWN STATE — the incoming roster carrying THIS device's
    // removed mark flips the worker's self-removed state (the typed banner,
    // the push gate). The map skips self (the R100 law stands); the mark is
    // recorded beside it.
    for (const d of devices) {
      if (identity && d && String(d.deviceId) === String(identity.deviceId)) {
        if (d && d.removed && Number(d.removed.at)) {
          _selfRemoved = { at: Number(d.removed.at), by: String(d.removed.by || '') }
          try { await chrome.storage.local.set({ [SELF_REMOVED_KEY]: _selfRemoved }) } catch { /* best-effort */ }
          console.warn('[UCrypt] roster: THIS device was removed from the chain at', new Date(_selfRemoved.at).toISOString())
        }
        continue
      }
      try { await learnPeer(chainKeys, d) } catch (e) {
        console.warn('[UCrypt] roster seed refused for', d && d.deviceId ? String(d.deviceId).slice(0, 8) + '…' : '?', e && (e.transferCode || e.code) || String(e).slice(0, 80))
      }
    }
  },
  // R108 §3.2 — THE ROSTER AUGMENTER (the mutual-rename propagation): the
  // push roster is merged with THIS device's sealed peer map BEFORE the
  // envelope leaves — a peer's newest label (per-entry last-writer by
  // labelSetAt) and any map device the snapshot does not yet carry ride the
  // next sync, so a rename made anywhere reaches everyone. The pure law
  // lives in mailbox.js (augmentRosterFromMap) — battery-pinned; the worker
  // only wires it. TOFU keys come from the map verbatim (the learn sink
  // re-verifies on every pull); the SELF entry's own label (the R100
  // self-rename) always wins for self; the cap holds inside the law.
  rosterAugmenter: async (roster) => {
    try {
      if (!_chainKeys) return roster
      const map = await loadPeerMap(_chainKeys)
      return augmentRosterFromMap(roster, map, _identity ? _identity.deviceId : '')
    } catch { return roster } // the push stands un-augmented
  },
  // S9 (R111) — THE CHAIN-SHARED STATE: the provider builds the record from
  // this device's transport (transit-sealed credentials under the opt-in);
  // the sink merges an incoming record under the monotonic-counter law and
  // applies it (the typed notice / the conflict card / the pending override).
  // Both stand down on failure — the push/pull is never blocked by the
  // chain-state plane (the same law as the roster bridge).
  chainStateProvider: async () => {
    try { return await buildChainStateRecord() } catch { return null }
  },
  chainStateSink: async (rec) => {
    try { return await handleIncomingChainState(rec) } catch (e) {
      console.warn('[UCrypt] chain state sink refused:', e && e.message ? String(e.message).slice(0, 100) : e)
      return { applied: false, reason: 'sink-error' }
    }
  },
})
const AVAILABILITY_STATE_KEY = 'ucrypt:transfer:availability'
const DEFAULT_MINUTES = 10

// --- T7 session persistence (R85 / F-R84-XFER-4) ---------------------------------

/** Sealed snapshot key — chrome.storage.SESSION (cleared at browser session
 * end by the platform; the honest T7 boundary). The blob itself is AES-GCM
 * sealed under the device-registry plane key, so nothing readable ever rests
 * in session storage. */
const SESSIONS_STATE_KEY = 'ucrypt:transfer:sessions'
const SESSION_SNAPSHOT_MAX = 20
const INTERRUPTED_LEDGER_MAX = 5
/** Non-secret in-flight interruption ledger (T7: typed "interrupted — resend"
 * affordance, never a silent reset). Surfaced through statusMessage(). */
const _interruptedLedger = []
/** R89 (F-R89-MANUAL-1): the LATEST sealed presence record failed to publish
 * (no transport / unreachable rendezvous) — its manual (base64) form is
 * stashed here so the transfer page's Copy button can hand-carry first
 * contact. Non-secret (a sealed envelope); cleared on the next successful
 * publish. Surfaced through statusMessage(). */
let _stagedManualPresenceB64 = null
let _bootstrapped = false
let _bootstrapPromise = null
let _persistChain = Promise.resolve()

/** Serialize the resumable core of one session (NO CryptoKey, NO buffers —
 * every field is JSON; the ephemeral JWKs re-import deterministically on
 * wake via deriveTransferSecrets, so no raw key material is invented). */
function serializeSession(s) {
  if (!s || !s.transferId) return null
  const base = {
    transferId: s.transferId,
    role: s.role,
    state: s.state,
    peerKeys: s.peerKeys || null,
    peerLabel: s.peerLabel || '',
    offer: s.offer || null,
    offerMessageId: s.offerMessageId || '',
    offerPayloadHashHex: s.offerPayloadHashHex || '',
    nonce: s.nonce || '',
    expiresAt: s.expiresAt || '',
    accepted: !!s.accepted,
    lastActivity: s.lastActivity || Date.now(),
    // R129 GRAND AUDIT (FINDING R129-H2 — the hardening pass, the busy-gate
    // class sweep): the sync flag MUST ride the snapshot. It is a non-secret
    // boolean — without it, a worker recycle resurrects the beam's sync-offer
    // session as a USER file session (syncTransfer: undefined → falsy), and
    // the restored machinery wedges activeSenderSession's one-active-send
    // gate again — the R128 fix bypassed by a restart. The interleaving law
    // must survive the recycle, not just the process.
    syncTransfer: !!s.syncTransfer,
  }
  if (s.role === 'sender') {
    // OFFER_SENT is the ONLY resumable sender rung — waiting on the answer
    // needs the ephemeral private JWK (re-imported at answer time) and the
    // offer binding. Anything WebRTC-bound terminates as interrupted.
    if (s.state !== TRANSFER_STATES.OFFER_SENT) return null
    base.ephemeral = s.ephemeral ? { pubJwk: s.ephemeral.pubJwk, privJwk: s.ephemeral.privJwk } : null
    return base
  }
  // Receiver: a PENDING DECISION resumes (the poll re-renders the card from
  // the sealed offer; the decision itself stays with the user). Anything past
  // acceptance was WebRTC/inbox-bound — interrupted, never silently dropped.
  if (s.state !== TRANSFER_STATES.OFFER_PENDING) return null
  base.sdp = String(s.sdp || '')
  base.senderEphemeralPubJwk = s.senderEphemeralPubJwk || null
  return base
}

/** R100 (F-R100-LEDGER-1): the truthful interrupted projection — an entry
 * whose transfer is STILL a live non-terminal session is a transfer in
 * flight, not an interruption; only entries whose session is truly gone
 * (the worker recycled under it) surface the typed note. */
function interruptedProjection() {
  return _interruptedLedger.slice(-INTERRUPTED_LEDGER_MAX).filter((e) => {
    const s = _sessions.get(String(e.transferId || ''))
    return !s || !isActiveSenderState(s.state)
  })
}

/** Seal + write the snapshot (single-flight; never throws to the caller).
 * R85 (T7): sessions whose rung is NOT resumable (WebRTC-bound: answer
 * received / connecting / transferring / verifying / receiver accepted+) are
 * dropped from the resumable set. R101 (F-R100-1, the CEO's binding defect
 * report): the persist path NEVER writes a healthy session into the
 * interrupted ledger — a LIVE WebRTC transfer is not an interruption, it is
 * a transfer. What the snapshot carries instead is a non-secret BOUND RECORD
 * ({ transferId, role, name, state } — state evidence, no keys, no buffers)
 * per active-but-unresumable session. The wake-restore — the only moment the
 * interruption is actually KNOWN (the recycle happened under it) — converts
 * each bound record into a typed ledger entry carrying its transferId. While
 * the worker lives and the transfer runs, the ledger stays empty; a clean
 * terminal simply stops staging the bound record (and retracts any legacy
 * entry). */
const _interruptedSeen = new Set()
function queueSnapshotPersist() {
  _persistChain = _persistChain.then(async () => {
    try {
      if (!_chainKeys) return // cannot seal without the plane key — nothing to write
      const sessions = []
      const bound = []
      for (const s of _sessions.values()) {
        const ser = serializeSession(s)
        if (ser) {
          sessions.push(ser)
        } else {
          // R101 (F-R100-1): stage STATE EVIDENCE only — never a claim that
          // the transfer was interrupted. The ledger is untouched here.
          const live = s.role === 'sender' ? isActiveSenderState(s.state) : isActiveReceiverState(s.state)
          if (live) {
            bound.push({
              transferId: String(s.transferId || ''),
              role: s.role,
              name: String(s.offer && s.offer.name || '').slice(0, 80),
              state: String(s.state || ''),
              lastActivity: s.lastActivity || Date.now(),
            })
            if (bound.length >= SESSION_SNAPSHOT_MAX) break
          }
        }
        if (sessions.length >= SESSION_SNAPSHOT_MAX) break
      }
      const snapshot = {
        savedAt: Date.now(),
        availability: _availability && _availability.enabled
          ? { enabled: true, expiresAt: _availability.expiresAt, label: _availability.label || '', beamArmed: !!(_beam && _beam.armed) }
          : null,
        // The RAW interrupted ledger rides the snapshot (it is the record of
        // what the recycle is about to lose). Under F-R100-1 it holds ONLY
        // real interruptions: the persist path can no longer add entries.
        interrupted: _interruptedLedger.slice(-INTERRUPTED_LEDGER_MAX),
        // R101 (F-R100-1): the WebRTC-bound sessions' state evidence.
        bound,
        sessions,
      }
      const sealed = await encryptString(JSON.stringify(snapshot), _chainKeys.deviceRegistry)
      await chrome.storage.session.set({ [SESSIONS_STATE_KEY]: sealed })
    } catch (e) {
      console.warn('[UCrypt] Transfer: session snapshot persist skipped:', e && (e.transferCode || e.code || e.message || e))
    }
  }).catch(() => { /* the chain never rejects */ })
  return _persistChain
}

/** Worker-wake restore (T7). Idempotent, single-flight, never throws.
 * Honest boundaries: locked vault → snapshot cleared (availability and
 * sessions are unlocked-vault state); expired entries → dropped. */
async function bootstrapFromSessionSnapshot() {
  if (_bootstrapped) return
  _bootstrapped = true
  let snap = null
  try {
    // The vault-unlock state governs the restore (R45-A lock boundary).
    // getVaultState is sync in production; `await` tolerates both shapes and
    // a throw — never call .catch() on it directly (non-promise TypeError).
    let state = null
    try { state = await getVaultState() } catch { state = null }
    if (!state || !state.isUnlocked) {
      await chrome.storage.session.remove(SESSIONS_STATE_KEY).catch(() => {})
      return
    }
    const mnemonic = await getUnlockedSyncMnemonic().catch(() => null)
    if (!mnemonic) {
      await chrome.storage.session.remove(SESSIONS_STATE_KEY).catch(() => {})
      return
    }
    // R86 (live-matrix finding, T7 class-a): the chain keys must be re-derived
    // on EVERY unlocked boot — NOT gated on a snapshot existing. The previous
    // code returned before this line when no snapshot was stored, so a worker
    // recycled with availability off answered every transfer message with the
    // mislabeled 'locked' error while the vault was in fact unlocked (the
    // page then rendered a false "Vault locked" line). ensureChainReady's
    // 'locked' stays truthful: with the bootstrap fixed it can only throw it
    // when the vault really is locked.
    _chainKeys = await deriveChainKeys(mnemonic)
    _identity = await getOrCreateDeviceIdentity(_chainKeys)
    const { [SESSIONS_STATE_KEY]: sealed } = await chrome.storage.session.get(SESSIONS_STATE_KEY)
    if (sealed) snap = JSON.parse(await decryptString(sealed, _chainKeys.deviceRegistry))
  } catch (e) {
    console.warn('[UCrypt] Transfer: session snapshot restore skipped:', e && (e.transferCode || e.code || e.message || e))
    await chrome.storage.session.remove(SESSIONS_STATE_KEY).catch(() => {})
    _chainKeys = null
    _identity = null
    return
  }
  if (!snap || typeof snap !== 'object') return
  // (a) interrupted ledger — T7's typed "interrupted — resend" affordance.
  // R101 (F-R100-1): entries carry their transferId through the restore —
  // the retraction-by-transferId in terminalCleanup must reach entries that
  // crossed a worker recycle, and the truth surface names what it retracts.
  if (Array.isArray(snap.interrupted)) {
    for (const it of snap.interrupted) {
      if (it && (it.role === 'sender' || it.role === 'receiver')) {
        _interruptedLedger.push({ role: it.role, name: String(it.name || '').slice(0, 80), transferId: String(it.transferId || ''), at: Number(it.at) || 0 })
      }
    }
    while (_interruptedLedger.length > INTERRUPTED_LEDGER_MAX) _interruptedLedger.shift()
  }
  // (a2) R101 (F-R100-1): the previous life's WebRTC-bound sessions. The
  // recycle killed them — THIS is the moment the interruption becomes real
  // and knowable, so the ledger entry is written HERE (once per entry per
  // worker life), carrying the transferId. A snapshot written by a healthy
  // running worker can therefore never manufacture an interruption: the
  // bound records only become entries when the worker that wrote them is
  // actually gone.
  if (Array.isArray(snap.bound)) {
    for (const b of snap.bound) {
      if (!b || !b.transferId || (b.role !== 'sender' && b.role !== 'receiver')) continue
      const key = `${b.role}:${b.transferId}`
      if (_interruptedSeen.has(key)) continue
      _interruptedSeen.add(key)
      _interruptedLedger.push({ role: b.role, name: String(b.name || '').slice(0, 80), transferId: String(b.transferId || ''), at: Date.now() })
    }
    while (_interruptedLedger.length > INTERRUPTED_LEDGER_MAX) _interruptedLedger.shift()
  }
  // (b) availability — only a window that is STILL open re-arms.
  const avail = snap.availability
  if (avail && avail.enabled && Date.parse(avail.expiresAt) > Date.now()) {
    _availability = { enabled: true, expiresAt: avail.expiresAt, label: String(avail.label || '').slice(0, 60) }
    // R98 (S8.3): a still-open window that was BEAM-ARMED re-arms the beam —
    // the beam truth rides the same snapshot shape (windowEnd alignment).
    if (avail.beamArmed) _beam = { armed: true, since: Date.now(), windowEnd: avail.expiresAt }
    try { await chrome.alarms.create(TRANSFER_AVAILABILITY_ALARM, { periodInMinutes: 1 }) } catch { /* lazy expiry governs */ }
    try { await refreshAvailabilityPresence() } catch { /* stale copy governs */ }
    try { await chrome.storage.local.set({ [AVAILABILITY_STATE_KEY]: { enabled: true, expiresAt: avail.expiresAt } }) } catch { /* advisory */ }
  }
  // (b2) R98 (S8.4): the joiner's await state — session-persisted so a worker
  // recycle mid-join never leaves the joiner's screen lying.
  try {
    const { 'ucrypt:beam:joinState': js } = await chrome.storage.session.get('ucrypt:beam:joinState')
    if (js && js.role === 'joiner' && Date.parse(js.expiresAt || '') > Date.now()) _beamJoinState = js
  } catch { /* advisory restore */ }
  // (c) sessions — resumable rungs come back live; everything else lands in
  // the interrupted ledger (typed notice) and is dropped.
  let restored = 0
  for (const entry of (Array.isArray(snap.sessions) ? snap.sessions : [])) {
    if (!entry || !entry.transferId || _sessions.has(entry.transferId)) continue
    if (entry.role === 'sender' && entry.state === TRANSFER_STATES.OFFER_SENT) {
      if (Date.parse(entry.expiresAt) <= Date.now()) continue // expired — honest drop
      _sessions.set(entry.transferId, {
        transferId: entry.transferId,
        role: 'sender',
        state: TRANSFER_STATES.OFFER_SENT,
        peerKeys: entry.peerKeys,
        peerLabel: entry.peerLabel || '',
        offer: entry.offer,
        ephemeral: entry.ephemeral,
        offerMessageId: entry.offerMessageId,
        offerPayloadHashHex: entry.offerPayloadHashHex,
        nonce: entry.nonce,
        expiresAt: entry.expiresAt,
        accepted: false,
        key: null,
        outbox: null,
        lastActivity: Number(entry.lastActivity) || Date.now(),
        restored: true,
        // R129 (H2): the machinery flag rides the restore — a restored
        // sync-offer session never wedges the file-send busy gate (0.42's
        // class law across the recycle boundary).
        syncTransfer: !!entry.syncTransfer,
      })
      restored += 1
    } else if (entry.role === 'receiver' && entry.state === TRANSFER_STATES.OFFER_PENDING) {
      _sessions.set(entry.transferId, {
        transferId: entry.transferId,
        role: 'receiver',
        state: TRANSFER_STATES.OFFER_PENDING,
        peerKeys: entry.peerKeys,
        peerLabel: entry.peerLabel || '',
        offer: entry.offer,
        sdp: String(entry.sdp || ''),
        senderEphemeralPubJwk: entry.senderEphemeralPubJwk || null,
        offerMessageId: entry.offerMessageId,
        offerPayloadHashHex: entry.offerPayloadHashHex,
        nonce: entry.nonce,
        expiresAt: entry.expiresAt,
        accepted: false,
        key: null,
        inbox: null,
        lastActivity: Number(entry.lastActivity) || Date.now(),
        restored: true,
        syncTransfer: !!entry.syncTransfer, // R129 (H2): symmetric with the sender restore
      })
      restored += 1
    } else {
      // R101 (F-R100-1): this defensive branch (a snapshot session shape the
      // resumable restore does not recognize) carries the transferId too.
      _interruptedLedger.push({ role: entry.role, name: String(entry.offer && entry.offer.name || '').slice(0, 80), transferId: String(entry.transferId || ''), at: Date.now() })
      while (_interruptedLedger.length > INTERRUPTED_LEDGER_MAX) _interruptedLedger.shift()
    }
  }
  if (restored > 0) console.info('[UCrypt] Transfer: restored', restored, 'session(s) from the sealed worker-wake snapshot')
}

/** Single-flight bootstrap trigger — called on every message + the alarm. */
function ensureBootstrapped() {
  if (_bootstrapped) return Promise.resolve()
  if (!_bootstrapPromise) {
    _bootstrapPromise = bootstrapFromSessionSnapshot().catch(() => { /* honest failure — memory state governs */ })
  }
  return _bootstrapPromise
}

// --- Error surface ---------------------------------------------------------------

/** Stable code → i18n key for user-actionable copy (worker never localizes
 * secrets — these are error classifications only). */
const ERROR_KEYS = {
  locked: 'transferErrLocked',
  no_sync_code: 'transferErrNoSyncCode',
  rendezvous_unavailable: 'transferErrRendezvousUnavailable',
  rendezvous_protocol: 'transferErrRendezvousProtocol',
  foreign_chain: 'transferErrForeignChain',
  replay: 'transferErrReplay',
  // R137 G80 FP-P1 (Table 3): the legacy expiry terminal rides the typed-expiry
  // copy — the same sentence the Beam 3 open gate renders (the one-tap
  // Regenerate affordance named). The dead-end sentence renders NOWHERE.
  expired: 'beam3RefusalExpired',
  unknown_sender: 'transferErrUnknownSender',
  key_change: 'transferErrKeyChange',
  decrypt_failed: 'transferErrDecryptFailed',
  nonce_mismatch: 'transferErrNonceMismatch',
  bad_record: 'transferErrBadRecord',
  bad_signature: 'transferErrBadSignature',
  bad_kind: 'transferErrBadKind',
  peer_invalid: 'transferErrPeerInvalid',
  plaintext_leak: 'transferErrPlaintextLeak',
  over_limit: 'transferErrOverLimit',
  hard_cap: 'transferErrHardCap',
  empty: 'transferErrEmpty',
  no_session: 'transferErrNoSession',
  gap: 'transferErrGap',
  duplicate: 'transferErrDuplicate',
  size_mismatch: 'transferErrSizeMismatch',
  sha_mismatch: 'transferErrShaMismatch',
  not_verified: 'transferErrNotVerified',
  declined: 'transferErrDeclined',
  // R79 — readiness truth (F-R78-3) + answer-path typed codes (F-R78-6) +
  // rendezvous busy (F-R78-4). Codes stay lowercase internally; the answer
  // result objects carry the order's exact ANSWER_* strings.
  no_sync_code_ready: 'transferErrNoSyncCode',
  answer_expired: 'beam3RefusalExpired',
  answer_replayed: 'transferErrReplay',
  answer_invalid_signature: 'transferErrBadSignature',
  answer_wrong_recipient: 'transferErrWrongRecipient',
  answer_unknown_device: 'transferErrUnknownSender',
  answer_invalid_capability: 'transferErrBadRecord',
  answer_decrypt_failed: 'transferErrDecryptFailed',
  rendezvous_busy: 'transferErrRendezvousBusy',
  // R81 — lifecycle closure codes.
  transfer_busy: 'transferErrSendBusy',
  stage_timeout: 'transferErrStageTimeout',
}

function fail(e) {
  const code = (e && (e.transferCode || e.code)) || 'internal'
  // R79 (owner order §1.2): the answer-path's typed ANSWER_* classification
  // rides the failure response too — the lowercase code stays canonical for
  // the module taxonomy; typedCode is the order's exact vocabulary.
  const out = { ok: false, error: code, userMessageKey: ERROR_KEYS[code] || 'transferErrInternal' }
  if (e && e.typedCode) out.typedCode = e.typedCode
  // R98: the honest detail (bounded) — the pages surface it, never swallow it.
  if (e && e.message) out.detail = String(e.message).slice(0, 200)
  return out
}

function sessionNotFound(transferId) {
  return transferError('no_session', `No active transfer session for ${String(transferId).slice(0, 8)}…`)
}

// --- Session helpers ---------------------------------------------------------------

function availabilityActive(now = Date.now()) {
  if (!_availability || !_availability.enabled) return null
  if (Date.parse(_availability.expiresAt) <= now) {
    _availability = null
    try { chrome.alarms.clear(TRANSFER_AVAILABILITY_ALARM) } catch { /* worker recycled */ }
    chrome.storage.local.remove(AVAILABILITY_STATE_KEY).catch(() => {})
    return null
  }
  return _availability
}

/** R86 (live-matrix finding, T7 class-a): LAZY chain-key derivation.
 *
 * The worker-wake bootstrap is single-flight per worker GENERATION, but the
 * vault unlock is a mid-generation event (the user unlocks through the popup
 * while this worker lives). The old ensureChainReady threw the mislabeled
 * 'locked' whenever the memory keys were absent — after any recycle whose
 * bootstrap first ran while the vault was still locked, EVERY transfer
 * message failed with "Vault locked" until the next recycle, even though the
 * vault was in fact unlocked. Now: when the memory keys are missing we check
 * the TRUTHFUL unlock state and re-derive on the spot (single-flight), so
 * polls/peers/offers recover within the same worker generation. The 'locked'
 * refusal remains — but only when the vault is genuinely locked. */
let _chainDerivePromise = null
async function ensureChainReady() {
  if (_chainKeys && _identity) return { chainKeys: _chainKeys, identity: _identity }
  // getVaultState is sync in production; `await` tolerates both shapes and a
  // throw — never call .catch() on it directly (non-promise TypeError).
  let state = null
  try { state = await getVaultState() } catch { state = null }
  if (!state || !state.isUnlocked) {
    throw transferError('locked', 'Transfer requires an unlocked vault (chain keys derived at enable time) [r86-lazy]')
  }
  const mnemonic = await getUnlockedSyncMnemonic()
  if (!mnemonic) {
    // Unlocked but chain-less device: transfer-plane keys cannot exist yet.
    // Kept on the legacy 'locked' code (the UI maps it); the honest copy for
    // this corner is tracked as a follow-up observation, not this round.
    throw transferError('locked', 'No sync chain available on this device for direct transfer')
  }
  if (!_chainDerivePromise) {
    _chainDerivePromise = (async () => {
      const keys = await deriveChainKeys(mnemonic)
      const identity = await getOrCreateDeviceIdentity(keys)
      // re-check the lock boundary AFTER the async derive: a lock that landed
      // mid-derivation must not resurrect key material (R45-A)
      let after = null
      try { after = await getVaultState() } catch { after = null }
      if (!after || !after.isUnlocked) {
        throw transferError('locked', 'Vault locked during transfer-plane key derivation')
      }
      _chainKeys = keys
      _identity = identity
    })().finally(() => { _chainDerivePromise = null })
  }
  await _chainDerivePromise
  return { chainKeys: _chainKeys, identity: _identity }
}

/** R145 §5.3 (the G-2 cure, §4.3's recurring-disease law) — THE IDENTITY
 * SELF-HEAL AT EVERY DOOR: a joined, unlocked device NEVER sees "locked"
 * from a stale worker lifetime. Every user-facing transfer door lazily
 * re-derives the chain keys + identity BEFORE failing (the named writer:
 * ensureChainReady runs in EVERY arc that can put a user on a door — boot
 * restore, status render, and now the action doors). Only a genuinely
 * locked vault or a chain-less device still answers locked — the truth.
 * Battery rows: tests/r145-round.test.mjs (the gate OPENS on a joined
 * profile after a simulated worker recycle). */
async function selfHealOrLocked() {
  if (_chainKeys && _identity) return true
  try {
    await ensureChainReady()
    return !!(_chainKeys && _identity)
  } catch {
    return false
  }
}

async function resolvePeerKeys(deviceId) {
  const { chainKeys } = await ensureChainReady()
  for (const s of _sessions.values()) {
    if (s.peerKeys && s.peerKeys.deviceId === deviceId) return s.peerKeys
  }
  const known = await getPeerEntry(chainKeys, deviceId)
  if (known) return known
  const avail = _lastAvailablePeers.find(p => p.deviceId === deviceId)
  if (avail) return { deviceId: avail.deviceId, signPubJwk: avail.signPubJwk, agrPubJwk: avail.agrPubJwk, label: avail.label || '' }
  return null
}

function newInbox(offer) {
  return {
    expectedSeq: 0,
    parts: [],
    received: 0,
    total: Number(offer.size) || 0,
    // R79 (F-R78-1): the receiver binds the CHUNK COUNT too — both counts
    // come from the authenticated offer, so both sides agree by construction.
    totalChunks: Number(offer.totalChunks) || 0,
    done: false,
    verified: null,
    plaintext: null,
    exported: false,
  }
}

function wipeSession(transferId) {
  const s = _sessions.get(transferId)
  if (s) {
    // Best-effort scrub of plaintext buffers before dropping the reference.
    if (s.inbox && Array.isArray(s.inbox.parts)) s.inbox.parts.length = 0
    s.inbox = null
    s.key = null
    s.ephemeral = null
  }
  _sessions.delete(transferId)
}

/**
 * R81-F2 — THE one idempotent terminal cleanup. Every terminal transition
 * (completed / receiver_declined / cancelled / expired / failed) goes through
 * HERE on the worker side; the transfer page mirrors it with finishSend().
 * The cleanup plan is pure (lifecycle.js) so every terminal path clears the
 * same resources: session, key material, buffers. Idempotent by contract —
 * a second call for the same transferId is a no-op (the session is already
 * gone) and never throws. A bounded in-memory ledger (≤20 entries, non-secret
 * ids only) keeps diagnostics honest without persisting anything.
 */
const _cleanupLedger = []
function terminalCleanup(transferId, reason) {
  const id = String(transferId || '')
  const existed = _sessions.has(id)
  const plan = cleanupPlan(reason)
  if (existed) wipeSession(id)
  // R100 (F-R100-LEDGER-1): a clean terminal RETRACTS the pending
  // interruption entry — the transfer completed, so it was never interrupted.
  const rIdx = _interruptedLedger.findIndex((e) => String(e.transferId || '') === id)
  if (rIdx >= 0) _interruptedLedger.splice(rIdx, 1)
  _cleanupLedger.push({ transferId: id.slice(0, 8), reason: plan.reason, at: Date.now() })
  while (_cleanupLedger.length > 20) _cleanupLedger.shift()
  // R85 (T7): terminal transitions are session mutations — the sealed
  // snapshot must never resurrect a session that already terminated.
  queueSnapshotPersist()
  return { existed, plan }
}

/** Active (non-terminal) outgoing sender session — the one-active-send gate.
 * R83: expired OFFER_SENT sessions are swept to EXPIRED (terminal cleanup)
 * FIRST, so a dead page can never hold the busy gate closed forever. */
function activeSenderSession() {
  sweepExpiredSenderOffers()
  for (const s of _sessions.values()) {
    // R128 §3 (the CEO's S5 — "the device signal mechanism is intermittent,
    // sometimes it doesn't work" — THE MECHANISM, live-caught by the owner's-
    // flow walk): the beam's sync-offer session is MACHINERY, not a user's
    // file transfer. The one-active-send gate exists to keep FILE transfers
    // from interleaving — a living sync session (the join's own sync-offer,
    // TTL-bounded, auto-answered by the origin's engine) must never wedge
    // the sender's file flow with transfer_busy for up to the offer TTL.
    // The gate still refuses a second FILE session (the interleaving law
    // holds); the sync plane's own single-flight is the engine's business.
    if (s.role === 'sender' && !s.syncTransfer && isActiveSenderState(s.state)) return s
  }
  return null
}

/**
 * R83 — lazy expiry sweep. The page watchdog owns the live countdown, but a
 * closed/reloaded page can leave an OFFER_SENT session behind; its typed
 * answer is the same terminal cleanup every other path uses.
 */
function sweepExpiredSenderOffers() {
  // R87-LIVE-1: the sweep REPORTS what it terminated — the poll surfaces the
  // ids on the page's expired channel (R86-LIVE-3's contract, now fully
  // wired: the channel was consumed by page.js but never populated).
  const swept = []
  for (const [id, s] of [..._sessions.entries()]) {
    if (s.role === 'sender' && senderOfferExpired(s)) {
      terminalCleanup(id, TRANSFER_STATES.EXPIRED)
      swept.push(id)
    }
  }
  return swept
}

/**
 * R83 — non-secret projection of the first active session (sender preferred).
 * This is the CANONICAL state the transfer page queries on load/reload so a
 * reopened window can never render a false ready/locked state (owner order
 * §R83-F2/F3). No key material, no SDP, no buffers — projection only.
 */
function activeSessionProjection() {
  sweepExpiredSenderOffers()
  // R100 FIX (the live matrix caught it): the SYNC sessions are the ENGINE's
  // — the transfer page must never render, restore, or cancel them. The old
  // projection handed the engine's sender session to the page, whose T7
  // restore then CANCELLED it on load ("the window was reloaded") — the
  // direct act died mid-flight the moment any transfer window opened.
  let pick = null
  for (const s of _sessions.values()) {
    if (s.syncTransfer) continue
    if (s.role === 'sender' && isActiveSenderState(s.state)) { pick = s; break }
  }
  if (!pick) {
    for (const s of _sessions.values()) {
      if (s.syncTransfer) continue
      if (s.role === 'receiver' && isActiveReceiverState(s.state)) { pick = s; break }
    }
  }
  if (!pick) return null
  return {
    transferId: pick.transferId,
    role: pick.role,
    state: pick.state || null,
    peerLabel: pick.peerLabel || '',
    peerDeviceId: pick.peerKeys ? pick.peerKeys.deviceId : null,
    offerName: pick.offer ? pick.offer.name : '',
    offerSize: pick.offer ? pick.offer.size : 0,
    expiresAt: pick.expiresAt || null,
    route: pick.route || null,
    fingerprint: pick.fingerprint || null,
  }
}

function offerProjection(session) {
  const f = session.offer || {}
  return {
    offerId: session.offerMessageId,
    transferId: session.transferId,
    from: session.peerKeys ? session.peerKeys.deviceId : '',
    fromLabel: session.peerLabel || '',
    name: f.name || '',
    size: f.size || 0,
    // R79 (F-R78-1): the chunk count is part of the authenticated offer —
    // the receiver UI can show honest progress against it.
    totalChunks: Number(f.totalChunks) || 0,
    sha256: f.sha256hex || '',
    mime: f.mime || 'application/octet-stream',
    warning: executableOrArchiveWarning(f.name || ''),
    expiresAt: session.expiresAt || '',
    // Non-secret transport metadata: the page owns the RTCPeerConnection, so
    // it needs the offer SDP to build its answer. Never key material.
    sdp: session.sdp || '',
    // R98 (S8.6): the beam's cloud hint (provider + stripped URL — never
    // credentials) — null for ordinary transfers; the joiner's backup step
    // is named from this.
    beamCloudHint: session.beamCloudHint || null,
  }
}

// --- Availability (R81-F1: refresh cadence + immediate withdrawal) ---------------------

async function enableAvailability({ label, minutes } = {}) {
  const state = await getVaultState()
  if (!state || !state.isUnlocked) {
    throw transferError('locked', 'Unlock the vault before enabling direct transfer availability')
  }
  const mnemonic = await getUnlockedSyncMnemonic()
  if (!mnemonic) {
    throw transferError('no_sync_code', 'Direct transfer needs the sync chain (no sync code is set up on this device)')
  }
  // The words are used in-memory here and never stored, logged or cached.
  _chainKeys = await deriveChainKeys(mnemonic)
  _identity = await getOrCreateDeviceIdentity(_chainKeys)
  const mins = Number(minutes) > 0 ? Math.min(Number(minutes), 60) : DEFAULT_MINUTES
  // R89 (F-R89-MANUAL-1): a failed presence publish STAGES the exact sealed
  // record for the manual surface — availability still turns on locally (the
  // window is user-owned); the cloud copy is retried by the cadence alarm.
  // F-R99-1 (R99): the enable is NON-BLOCKING and the fallback is EAGER — the
  // record is sealed locally (fast, no network), staged for hand-carry in the
  // same instant, and the cloud write continues in the background (a fresh
  // record rides the 1-minute cadence regardless). Under a hostile network
  // the toggle no longer waits out the retry ladder and the manual
  // affordance exists the moment the window opens.
  // R100 (the CEO's Brave-style list): an unnamed arm announces the device's
  // OWN name (the identity label) — the roster shows real names, never a
  // wall of "A UCrypt device".
  const armLabel = String(label || '').trim().slice(0, 60) || String(_identity.label || '').slice(0, 60)
  const sealedPresence = await sealPresenceRecord(_chainKeys, _identity, armLabel, mins, {})
  // R107 (F-R107-CARRY-1): the MANUAL surface stages the CARRIER — the same
  // presence payload sealed with the envelope living to the window end, not
  // the ≤2-minute cloud envelope (the CEO's S9 forensic: a hand-carried
  // 2-minute record is refused 'expired' at T+130 s). The cloud publish
  // below keeps the ORIGINAL 2-minute record — the R81-F1 anti-ghost law is
  // untouched; only the hand-carry channel got its own honest horizon.
  try {
    const carrier = await sealPresenceCarrier(_chainKeys, _identity, armLabel, mins, { windowEnd: sealedPresence.availableUntil })
    _stagedManualPresenceB64 = recordToManual(carrier.record)
  } catch { /* staging is best-effort — the old cloud-record fallback below still applies */ }
  if (!_stagedManualPresenceB64) { try { _stagedManualPresenceB64 = recordToManual(sealedPresence.record) } catch { /* best-effort */ } }
  _availability = { enabled: true, expiresAt: sealedPresence.availableUntil, label: armLabel }
  publishSealedPresence(sealedPresence, _chainKeys, _identity)
    .then(() => { _stagedManualPresenceB64 = null }) // the cloud is reachable — drop the hand-carry copy
    // R107 (F-R107-CARRY-1): the failure path must NEVER downgrade a staged
    // CARRIER (window-end envelope) to the cloud record (≤2-minute envelope)
    // — that clobber was the S9 forensic's exact kill: the carrier died at
    // T+2 min because the publish failure re-staged the short-lived record
    // over it seconds after every arm/refresh.
    .catch((e) => { if (e && e.stagedManualB64 && !_stagedManualPresenceB64) _stagedManualPresenceB64 = String(e.stagedManualB64) })
  try {
    // R81-F1: REPEATING 1-minute cadence — each tick re-publishes presence
    // (fresh sequence + publishedAt, bounded envelope TTL) so peers see a
    // live freshness signal; a dead device stops advertising within ≤2 ticks
    // even if withdrawal never lands. The alarm self-clears on expiry.
    await chrome.alarms.create(TRANSFER_AVAILABILITY_ALARM, { periodInMinutes: 1 })
  } catch { /* alarms unavailable — expiry handled lazily */ }
  // Advisory persistence (audit/alarm bookkeeping; the in-memory state above
  // remains the source of truth — a worker restart reports the truth: off).
  try {
    // R100 FIX (F-R100-ARM-1): the F-R99-1 refactor renamed the seal result
    // to `sealedPresence` and made the publish non-blocking — this advisory
    // write still referenced the pre-refactor `published` (a dead reference
    // swallowed by the non-fatal catch). The seal result carries the window.
    await chrome.storage.local.set({ [AVAILABILITY_STATE_KEY]: { enabled: true, expiresAt: sealedPresence.availableUntil } })
  } catch { /* non-fatal */ }
  return _availability
}

/**
 * R81-F1 — republish presence with the SAME window end (fresh sequence +
 * publishedAt). Called by the 1-minute availability alarm while the window is
 * open. Never throws: a failed refresh simply means peers will see the record
 * age past the freshness threshold and show the truthful stale copy.
 */
async function refreshAvailabilityPresence() {
  if (!_chainKeys || !_identity || !_availability || !_availability.enabled) return
  // R107 (F-R107-CARRY-1): every refresh tick ALSO re-stages the manual
  // carrier (fresh sequence + publishedAt, window-end envelope) — a copy the
  // user takes later is always the freshest honest carrier. When the cloud
  // publish succeeds the staged copy is dropped exactly as before.
  try {
    const carrier = await sealPresenceCarrier(_chainKeys, _identity, _availability.label || '', 10,
      { windowEnd: _availability.expiresAt })
    _stagedManualPresenceB64 = recordToManual(carrier.record)
  } catch { /* staging is best-effort */ }
  try {
    await publishPresence(_chainKeys, _identity, _availability.label || '', 10,
      { windowEnd: _availability.expiresAt })
    _stagedManualPresenceB64 = null // the cloud is reachable again — drop the hand-carry copy
  } catch (e) {
    // R89 (F-R89-MANUAL-1): refresh failures ALSO stage (a fresh record beats
    // a stale one on the manual surface); the stale-copy governs regardless.
    // R107 (F-R107-CARRY-1): never downgrade the CARRIER staged above this
    // try with the failure's ≤2-minute cloud record — the carrier's
    // window-end envelope is the honest hand-carry horizon.
    if (e && e.stagedManualB64 && !_stagedManualPresenceB64) _stagedManualPresenceB64 = String(e.stagedManualB64)
    console.warn('[UCrypt] Transfer: presence refresh failed (stale copy governs):', e?.code || e?.message || e)
  }
}

/**
 * R81-F1 — immediate, truthful withdrawal. Runs on EVERY explicit availability
 * stop path (disable toggle, lock, page-owned window close). Best-effort: the
 * boolean result is surfaced to the caller so the UI can say exactly what
 * happened — never a claimed withdrawal that did not reach the cloud.
 */
async function withdrawAvailabilityPresence() {
  if (!_chainKeys || !_identity) return { attempted: false, tombstoneOk: false }
  try {
    return await withdrawPresence(_chainKeys, _identity)
  } catch {
    return { attempted: true, tombstoneOk: false, indexOk: false, deleteOk: false }
  }
}

async function disableAvailability({ publish = true } = {}) {
  // Local availability stops FIRST — no refresh can resurrect it while the
  // best-effort cloud withdrawal runs.
  _availability = null
  // F-R114-MAILBOX-1: the availability session ENDS here — the next enable is
  // a new session (fresh keys, the R81 law) and re-proves its namespace
  // (405-tolerated) instead of inheriting the dead session's memo.
  resetRendezvousSession()
  try { await chrome.alarms.clear(TRANSFER_AVAILABILITY_ALARM) } catch { /* noop */ }
  try { await chrome.storage.local.remove(AVAILABILITY_STATE_KEY) } catch { /* noop */ }
  // R85 (T7): availability is part of the sealed snapshot — keep it truthful.
  queueSnapshotPersist()
  let withdrawal = { attempted: false, tombstoneOk: false }
  if (publish && _chainKeys && _identity) {
    withdrawal = await withdrawAvailabilityPresence()
  }
  return withdrawal
}

// --- Message handlers -------------------------------------------------------------------

/**
 * R146 §6.2 — THE ONE DEVICE-TRUTH PROJECTION (canonicalPeerRows).
 *
 * The CEO's H-7 ruling, executed at the wire: there is ONE device list in
 * the product — this projection. statusMessage (the Cloud Sync device list)
 * and mailboxRosterPeers (the transfer roster, via BRIDGE_ROSTER) BOTH serve
 * these rows: same members, same freshness (lastSeen/syncAt/syncLane), same
 * entry counts, same device types, same typed presence states. A joined
 * chain can never render "No other device is in your chain yet." from this
 * source, and no surface may re-derive a second roster anywhere else.
 * (The R146 autopsy ROSTER-1/ROSTER-2 cures; battery-pinned for equality.)
 */
async function canonicalPeerRows(rvAvailable = false) {
  const deviceId = _identity ? _identity.deviceId : null
  const peers = []
  if (_chainKeys) {
    // R132 (law 0.46 — THE PRESENCE-HONESTY LAW; the CEO's S1): every row
    // carries its machine-derived presence state — 'online' (the rendezvous
    // confirms), 'offline' (the rendezvous EXISTS and says so), 'unknown'
    // (this transport carries NO live presence — never a fabricated
    // offline). The derivation is the pure law in lib/presence.js; this
    // projection is its single wire source.
    const presenceStateOf = (online) => (online ? 'online' : (rvAvailable ? 'offline' : 'unknown'))
    try {
      const known = await knownPeers(_chainKeys)
      // R81-F1: peers carry the TRUTHFUL presence view — stale:true means
      // "advertised available, but the last refresh is older than the
      // freshness threshold" (device may be locked/unreachable).
      const lastOf = (id) => _lastAvailablePeers.find(a => a.deviceId === id) || null
      for (const p of known) {
        const a = lastOf(p.deviceId)
        peers.push({
          deviceId: p.deviceId,
          // R123 §2.3 (law 0.36's render face; the CEO's S3 — found LIVE by
          // the r123-live walk): the SELF row's label/type render from the
          // LIVE identity, never the peer map's stale roster stamp — a
          // self-rename must be visible the moment it saves (the map catches
          // up with the next sync; the UI never waits for it to tell the
          // truth about THIS device).
          label: (deviceId === p.deviceId ? (_identity.label || '') : (p.label || '')) || '',
          lastSeen: p.lastSeen || 0,
          // R111 §3.1 — the living-sync telemetry (self-declared by the peer,
          // refreshed by learnPeer): "direct · just now" / "cloud · 2 min ago"
          // + the entry count the peer holds. Absent on old peers (honest —).
          syncAt: Number(p.syncAt) || 0,
          syncLane: p.syncLane === 'direct' ? 'direct' : (p.syncLane === 'cloud' ? 'cloud' : ''),
          entryCount: Number.isFinite(Number(p.entryCount)) ? Number(p.entryCount) : null,
          // R148 §6.5 (LAW #74) — the tombstone rides the row: the renderers
          // show the converged truth ("Removed · <date> · by <device>" + the
          // local forget); the transfer target select excludes removed rows.
          removed: p.removed || null,
          // R113 §3.1 — the self-declared device type rides the projection
          // (dropping it here would blind the roster's icon + label again —
          // the exact F-R111-UI-1 class of defect, pre-empted). R123: the
          // self row's type renders live from the identity (the same law).
          deviceType: (deviceId === p.deviceId ? sanitizeDeviceType(_identity.deviceType) : (p.deviceType || '')) || '',
          paired: true,
          online: !!a,
          presenceState: presenceStateOf(!!a),
          stale: !!(a && a.stale),
          availableUntil: a ? a.availableUntil : null,
          mine: deviceId === p.deviceId,
        })
      }
      for (const a of _lastAvailablePeers) {
        if (!peers.some(p => p.deviceId === a.deviceId)) {
          peers.push({ deviceId: a.deviceId, label: a.label || '', lastSeen: 0, deviceType: a.deviceType || '', paired: false, online: true, presenceState: presenceStateOf(true), stale: !!a.stale, availableUntil: a.availableUntil, mine: deviceId === a.deviceId })
        }
      }
      // R113 §3.1 — THE SELF ROW IS ALWAYS PRESENT once the chain is ready:
      // the device-type selector (and the self rename) must never depend on
      // a presence round-trip (0.13: every affordance reachable; 0.26: the
      // empty roster names pairing as its precondition, never hides self).
      if (deviceId && !peers.some(p => p.mine)) {
        peers.push({
          deviceId,
          label: _identity.label || '',
          lastSeen: 0,
          deviceType: sanitizeDeviceType(_identity.deviceType),
          paired: true,
          online: false,
          presenceState: presenceStateOf(false),
          stale: false,
          availableUntil: null,
          mine: true,
        })
      }
    } catch { /* peers stay empty — rendered honestly as unknown */ }
  }
  return peers
}

async function statusMessage() {
  // R89 (roster truth — the R86-LIVE-1 law applied to the status projection):
  // a RECYCLED worker re-derives its chain keys lazily. Without this, every
  // status/roster read after a worker restart rendered a false "no chain
  // devices known" while the sealed peer map was perfectly intact.
  let unlockedEarly = false
  try { const s0 = await getVaultState(); unlockedEarly = !!(s0 && s0.isUnlocked) } catch { /* gated */ }
  if (unlockedEarly && (!_chainKeys || !_identity)) {
    try { await ensureChainReady() } catch { /* locked/gated — the honest empty view governs */ }
  }
  const avail = availabilityActive()
  let unlocked = false
  let deviceId = null
  try {
    const state = await getVaultState()
    unlocked = !!(state && state.isUnlocked)
  } catch { /* state unavailable */ }
  deviceId = _identity ? _identity.deviceId : null
  // R79 (F-R78-3): REAL readiness fields — the UI maps these to honest copy
  // and can never render "Vault locked" while the vault is actually unlocked.
  // R145 §4.3/§5.3 (the G-2 cure, the recurring-disease law's self-heal):
  // BEFORE the readiness derives from a broken intermediate, ONE re-derivation
  // of the chain material runs — a joined device whose in-memory identity was
  // lost to a worker recycle or a transient derivation failure is RE-DERIVED
  // here, silently; the user is NEVER asked to re-bind a chain they joined
  // (the heal is ledgered in the worker log for the doctor to show). Only a
  // REAL absence (no sync code) reports no_sync_code after this point.
  if (unlocked && !_chainKeys) {
    try {
      const healMnemonic = await getUnlockedSyncMnemonic()
      if (healMnemonic) {
        _chainKeys = await deriveChainKeys(healMnemonic)
        _identity = await getOrCreateDeviceIdentity(_chainKeys)
        try { console.warn('[UCrypt] R145 gate-heal: the chain identity was re-derived on boot (joined device, never re-bind)') } catch { /* log best-effort */ }
      }
    } catch { /* the heal is best-effort — the honest readiness still derives below */ }
  }
  const chainReady = !!(unlocked && _chainKeys && _identity)
  let readiness = 'locked'
  if (unlocked) {
    if (!chainReady) {
      let hasSync = false
      try { hasSync = !!(await getUnlockedSyncMnemonic()) } catch { /* treat as absent */ }
      readiness = hasSync ? 'enable_availability' : 'no_sync_code'
    } else {
      readiness = 'ready'
    }
  }
  // Rendezvous capability (F-R78-3): a transport that cannot host the
  // rendezvous namespace is reported truthfully — the UI must say
  // "unavailable for current storage", never fake a device list.
  const rendezvous = await rendezvousCapability()
  // R125 §3.1 (the CEO's S1) — the SYNC transport's identity rides the
  // status (the ID ONLY — never the config/secrets, law 0.14): the
  // promotion's words must never claim "no cloud connected" over a
  // connected sync cloud.
  let syncTransportId = null
  try {
    const rec = await getTransportRecord()
    syncTransportId = (rec && rec.id) || null
  } catch { /* locked or absent — null is the honest answer */ }
  const peers = await canonicalPeerRows(!!(rendezvous && rendezvous.available))
  return {
    ok: true,
    unlocked,
    chainReady,
    readiness,
    rendezvous,
    syncTransport: typeof syncTransportId !== 'undefined' ? syncTransportId : null,
    availability: avail ? { enabled: true, expiresAt: avail.expiresAt, label: avail.label || '' } : null,
    deviceId,
    peers,
    // R148 §6.5 (LAW #74) — the self-removed state (the removed device
    // learns its own state): the typed banner renders from this + the
    // rejoin path; the push paths gate on it.
    selfRemoved: _selfRemoved || null,
    // R83: the canonical active-session projection — the page restores truth
    // from this on every (re)load instead of guessing or rendering stale UI.
    activeSession: activeSessionProjection(),
    // R85 (T7): typed "interrupted — resend" affordance — in-flight transfers
    // cut down by a worker recycle are NEVER silent (non-secret entries only).
    // R100 (F-R100-LEDGER-1): a LIVE session is never reported interrupted.
    interrupted: interruptedProjection(),
    // R89 (F-R89-MANUAL-1): the hand-carry presence record (sealed envelope,
    // non-secret) for the manual copy/paste surface — null when the cloud
    // publish is healthy.
    stagedManualPresenceB64: _stagedManualPresenceB64 || null,
    limits: { chunkSize: CHUNK_SIZE, defaultLimit: DEFAULT_TRANSFER_LIMIT, hardCap: HARD_TRANSFER_CAP },
  }
}

/** Open one offer record and register the (unaccepted) receiver session. */
async function openOfferRecord(chainKeys, identity, record, { sync = false, noteRegistered = null } = {}) {
  const opened = await openFromPeer(chainKeys, identity, record, {})
  // S8.9 (R99): 'sync-offer' records ride the SAME session machinery and the
  // SAME typed gates as file offers — the only difference is the SURFACE:
  // a sync offer is auto-answered by the continuous-sync engine (consented
  // by chain membership; pull-first, digest-verified) and is never rendered
  // as a user-facing transfer card.
  if (opened.kind !== 'offer' && opened.kind !== 'sync-offer') return null
  const payload = opened.payload || {}
  const offer = buildFileOffer({
    name: payload.file && payload.file.name,
    size: payload.file && payload.file.size,
    sha256hex: payload.file && payload.file.sha256hex,
  })
  const transferId = opened.transferId || opened.messageId
  if (_sessions.has(transferId)) {
    // already registered — replay-safe. R105 §2.3: the caller may collect the
    // id (the multi-window offer hint — "this offer was opened in another
    // UCrypt surface"); the refusal itself stays silent and typed.
    if (typeof noteRegistered === 'function') {
      const s = _sessions.get(transferId)
      try { noteRegistered(s && s.offerMessageId ? s.offerMessageId : opened.messageId) } catch { /* best-effort */ }
    }
    return null
  }
  _sessions.set(transferId, {
    transferId,
    role: 'receiver',
    // R83: the receiver ladder is CANONICAL worker state — opened ⇒ pending.
    state: TRANSFER_STATES.OFFER_PENDING,
    syncTransfer: sync || opened.kind === 'sync-offer',
    peerKeys: opened.peer,
    peerLabel: opened.peer.label || '',
    offer,
    sdp: String(payload.sdp || ''),
    senderEphemeralPubJwk: payload.senderEphemeralPubJwk || null,
    offerMessageId: opened.messageId,
    offerPayloadHashHex: opened.payloadHashHex,
    nonce: opened.nonce,
    expiresAt: opened.expiresAt,
    accepted: false,
    key: null,
    inbox: null,
    lastActivity: Date.now(),
  })
  const session = _sessions.get(transferId)
  // R98 (S8.6): the beam's cloud hint rides the offer payload — stored so the
  // projection can name the joiner's next step (the backup step).
  session.beamCloudHint = (payload.beamHint && typeof payload.beamHint === 'object')
    ? { provider: String(payload.beamHint.provider || ''), url: String(payload.beamHint.url || '') }
    : null
  // R85 (T7): a new pending decision is a resumable session — persist it.
  queueSnapshotPersist()
  return offerProjection(session)
}

/**
 * THE MAILBOX POLL — the inbox that reads itself. R140 §6.3 LAW (the
 * capture-3 root cause, cured at the source): availability governs
 * VISIBILITY (whether OTHER devices see this one), never the read of this
 * device's OWN mailbox — an offer is addressed to this device by its chain
 * id, so a receiver who opened the page and waits MUST receive, armed or
 * not. The old `if (!availabilityActive()) return empty` gate was the
 * mechanism of the offer that never arrived: a failed arm (the cold-start
 * rendezvous race) silenced every poll while the offer sat unread.
 * opts.requireAvailability exists ONLY for callers whose contract is the
 * availability view itself (none today — the default is the honest read).
 */
async function pollMailbox(opts = {}) {
  const { chainKeys, identity } = await ensureChainReady()
  if (opts.requireAvailability === true && !availabilityActive()) {
    return { ok: true, offers: [], answers: [], ices: [], cancels: [], declines: [], completes: [], unknownSenders: 0, registeredOffers: [] }
  }
  const records = await readOwnMailbox(chainKeys, identity)
  // R85 (F-R84-XFER-2): unknownSenders counts offers refused unknown_sender
  // AFTER the auto-learn retry — the page renders the truthful "Sender
  // unknown — they must enable availability" notice from it.
  const out = { ok: true, offers: [], answers: [], ices: [], cancels: [], declines: [], completes: [], unknownSenders: 0, registeredOffers: [] }
  for (const rec of records) {
    try {
      if (rec.kind === 'offer') {
        const registeredIds = []
        let projection = null
        try {
          projection = await openOfferRecord(chainKeys, identity, rec, { noteRegistered: (id) => registeredIds.push(id) })
        } catch (e) {
          // R85 (F-R84-XFER-2): FIRST-CONTACT LEARN. The receiver's poll no
          // longer depends on the Send view having run LIST_PEERS first — on
          // unknown_sender the poll auto-learns the sender from the presence
          // index (the same replay-exempt learn the Send view's refresh
          // performs) and retries the offer ONCE. A sender that is not
          // advertising presence stays refused with the typed, truthful
          // unknown_sender code (TOFU discipline intact — the safe direction).
          if ((e && (e.transferCode || e.code)) !== 'unknown_sender') throw e
          try {
            // NOTE: listAvailablePeers(chainKeys, now) — the second parameter
            // is a TIMESTAMP, not the identity. The presence open learns the
            // sender into the sealed TOFU map as a side effect.
            await listAvailablePeers(chainKeys)
          } catch { /* learn is best-effort — the original refusal stands */ }
          projection = await openOfferRecord(chainKeys, identity, rec, { noteRegistered: (id) => registeredIds.push(id) })
        }
        if (projection) out.offers.push(projection)
        // R105 §2.3 — the poll found an offer ALREADY OPENED (registered by
        // an earlier poll/accept on this device). The id rides the response;
        // the TRANSFER_POLL layer decides whether THIS surface is a loser.
        for (const id of registeredIds) out.registeredOffers.push(id)
      } else if (rec.kind === 'answer') {
        // R79 (F-R78-6): the authenticated identity is REQUIRED — the answer
        // path can no longer be entered without it.
        const res = await openAnswerRecord(chainKeys, identity, rec, null)
        if (res) out.answers.push(res)
      } else if (rec.kind === 'ice') {
        const opened = await openFromPeer(chainKeys, identity, rec, {})
        out.ices.push({ transferId: opened.transferId, from: opened.from, candidate: opened.payload && opened.payload.candidate || null })
      } else if (rec.kind === 'cancel') {
        const opened = await openFromPeer(chainKeys, identity, rec, {})
        // R85 (F-R84-XFER-3): read the reason. A cancel record carrying
        // reason:'declined' (the v2.42 wire form of a receiver's refusal) maps
        // to the TYPED RECEIVER_DECLINED terminal — never to CANCELLED. A
        // reason-less cancel stays a true CANCELLED (sender-initiated).
        const declined = !!(opened && opened.payload && opened.payload.reason === 'declined')
        // R81-F2: a peer cancel is a TERMINAL transition — same one cleanup.
        if (opened.transferId) {
          terminalCleanup(opened.transferId, declined ? TRANSFER_STATES.RECEIVER_DECLINED : TRANSFER_STATES.CANCELLED)
        }
        if (declined) out.declines.push(opened.transferId)
        else out.cancels.push(opened.transferId)
      } else if (rec.kind === 'decline') {
        // R85 (F-R84-XFER-3): first-class decline record (the R85 wire form).
        // The receiver's refusal reaches the sender as its own T5 terminal:
        // RECEIVER_DECLINED + the ordered "Receiver declined — …" copy, with
        // the cancel family untouched for genuine sender cancels.
        const opened = await openFromPeer(chainKeys, identity, rec, {})
        if (opened.transferId) terminalCleanup(opened.transferId, TRANSFER_STATES.RECEIVER_DECLINED)
        out.declines.push(opened.transferId)
      } else if (rec.kind === 'complete') {
        const opened = await openFromPeer(chainKeys, identity, rec, {})
        // R81-F2: a consumed completion TERMINATES the sender session — the
        // one-active-send gate must open immediately, and the worker must not
        // linger on a finished transfer (terminal cleanup, idempotent).
        if (opened.transferId && _sessions.has(opened.transferId)) {
          terminalCleanup(opened.transferId, TRANSFER_STATES.COMPLETED)
        }
        out.completes.push(opened.transferId)
      }
      // 'presence' records inside a mailbox file: learned, not reported.
    } catch (e) {
      // Per-record gates (replay/expiry/foreign/unknown) never abort the poll.
      const code = (e && (e.transferCode || e.code)) || 'internal'
      if (code === 'unknown_sender') out.unknownSenders += 1
      // R105 §2.3 — a REPLAYED offer record means another surface of this
      // device already opened it (the replay ledger fires before the
      // session-exists check). The record's own messageId IS the session's
      // offerMessageId — it rides the response for the loser hint. File
      // offers only: sync offers auto-answer and are never user-facing.
      if (code === 'replay' && rec.kind === 'offer' && rec.messageId) out.registeredOffers.push(rec.messageId)
      console.warn('[UCrypt] Transfer poll: record refused:', code)
    }
  }
  return out
}

/**
 * Sender side: open the receiver's answer and derive the transfer key.
 * R79 (F-R78-6, P0): this function now REQUIRES the authenticated local
 * device identity — the previous signature allowed (and every call site
 * passed) identity=null, so the pairwise derivation crashed on
 * null.agrPrivJwk and NO accept/decline answer could ever complete the
 * handshake. The identity is threaded from the same ensureChainReady() the
 * offer path uses; a missing identity refuses BEFORE any dereference.
 *
 * Registry validation (owner order §1.2): before any ECDH, the record's
 * sender (from) must be the device this session was opened against, the
 * record's recipient (to) must be THIS device, and the sender's keys must
 * resolve in the device registry. Signature verification happens inside
 * openFromPeer BEFORE the decrypted payload may enter session state.
 *
 * Typed result codes (owner order §1.2): refusal errors carry a lowercase
 * transferCode (the module taxonomy) AND the exact ANSWER_* string from the
 * order in .typedCode; successful results carry .outcome. Mapping:
 *   expired → ANSWER_EXPIRED            replay → ANSWER_REPLAYED
 *   bad_signature → ANSWER_INVALID_SIGNATURE
 *   unknown_sender → ANSWER_UNKNOWN_DEVICE
 *   wrong_recipient → ANSWER_WRONG_RECIPIENT
 *   missing ephemeral capability → ANSWER_INVALID_CAPABILITY
 *   decrypt_failed → ANSWER_DECRYPT_FAILED
 */
async function openAnswerRecord(chainKeys, identity, record, peerOverride) {
  if (!identity || !identity.deviceId || !identity.agrPrivJwk) {
    // Compile/runtime boundary: a null identity can never reach the ECDH.
    throw transferError('internal', 'Answer processing requires the authenticated local device identity')
  }
  const transferId = record && record.transferId
  const session = transferId && _sessions.get(transferId)
  if (!session || session.role !== 'sender') {
    throw transferError('no_session', 'Answer for a transfer this device never offered')
  }

  // Recipient gate BEFORE any key derivation: the answer must be addressed
  // to THIS device and come from the device the offer was created against.
  if (String(record.to || '') !== String(identity.deviceId)) {
    const e = transferError('answer_wrong_recipient', 'Answer is not addressed to this device')
    e.typedCode = 'ANSWER_WRONG_RECIPIENT'
    throw e
  }
  if (String(record.from || '') !== String(session.peerKeys && session.peerKeys.deviceId)) {
    const e = transferError('answer_unknown_device', 'Answer claims a sender this transfer was not offered to')
    e.typedCode = 'ANSWER_UNKNOWN_DEVICE'
    throw e
  }
  // Registry gate: the peer's registered keys must still resolve (a removed
  // or re-keyed device cannot complete the handshake with stale material).
  const registered = await getPeerEntry(chainKeys, session.peerKeys.deviceId)
  if (!registered || !registered.agrPubJwk) {
    const e = transferError('answer_unknown_device', 'The offering peer is not in the device registry')
    e.typedCode = 'ANSWER_UNKNOWN_DEVICE'
    throw e
  }
  if (JSON.stringify(registered.agrPubJwk) !== JSON.stringify(session.peerKeys.agrPubJwk) ||
      JSON.stringify(registered.signPubJwk) !== JSON.stringify(session.peerKeys.signPubJwk)) {
    const e = transferError('key_change', 'Registry keys changed since the offer — refusing the answer')
    e.typedCode = 'ANSWER_UNKNOWN_DEVICE'
    throw e
  }

  let opened
  try {
    opened = await openFromPeer(chainKeys, identity, record, {
      peer: peerOverride || registered,
      expectedNonce: session.nonce,
    })
  } catch (e) {
    // Surface answer-refusals with the order's typed codes (see the map in
    // the doc comment). The underlying gate (replay/expiry/signature/...)
    // stays truthful — only the classification is enriched.
    const code = (e && (e.transferCode || e.code)) || 'internal'
    const TYPED = {
      expired: 'ANSWER_EXPIRED',
      replay: 'ANSWER_REPLAYED',
      bad_signature: 'ANSWER_INVALID_SIGNATURE',
      unknown_sender: 'ANSWER_UNKNOWN_DEVICE',
      decrypt_failed: 'ANSWER_DECRYPT_FAILED',
      nonce_mismatch: 'ANSWER_INVALID_CAPABILITY',
      foreign_chain: 'ANSWER_WRONG_RECIPIENT',
      bad_record: 'ANSWER_INVALID_CAPABILITY',
    }
    if (TYPED[code]) {
      const wrapped = transferError(code, e.message)
      wrapped.typedCode = TYPED[code]
      throw wrapped
    }
    throw e
  }
  if (!opened || opened.kind !== 'answer') return null
  session.answerMessageId = opened.messageId
  session.answerPayloadHashHex = opened.payloadHashHex
  const payload = opened.payload || {}
  if (!payload.accepted) {
    // Decline reached the sender as an encrypted, authenticated record:
    // TERMINAL (R81-F2) — one idempotent cleanup wipes the session, the
    // one-active-send gate opens, and the sender is told the truth.
    terminalCleanup(transferId, TRANSFER_STATES.RECEIVER_DECLINED)
    return { transferId, declined: true, outcome: 'ANSWER_DECLINED', receiverLabel: payload.receiverLabel || session.peerLabel || '' }
  }
  if (!payload.receiverEphemeralPubJwk) {
    const e = transferError('answer_invalid_capability', 'Answer carried no ephemeral public key')
    e.typedCode = 'ANSWER_INVALID_CAPABILITY'
    throw e
  }
  const th = await transcriptHash(session.offerMessageId, session.answerMessageId, session.offerPayloadHashHex, session.answerPayloadHashHex)
  // R79 (F-R78-1): one derivation pass yields K_transfer AND the deterministic
  // chunk-nonce prefix — the sender's half of the frame schema.
  const secrets = await deriveTransferSecrets(session.ephemeral.privJwk, payload.receiverEphemeralPubJwk, th)
  session.key = secrets.key
  session.noncePrefix = secrets.noncePrefix
  session.fingerprint = transferFingerprint(th)
  session.receiverLabel = payload.receiverLabel || ''
  session.outbox = { nextSeq: 0, sealed: 0 }
  // R81-F2: the answer was ACCEPTED — the session advances on the ladder.
  session.state = TRANSFER_STATES.ANSWER_RECEIVED
  // R85 (T7): ANSWER_RECEIVED is WebRTC-bound — NOT resumable. Persist so the
  // wake path records the typed interruption instead of a silent reset.
  queueSnapshotPersist()
  return {
    transferId,
    declined: false,
    outcome: 'ANSWER_ACCEPTED',
    fingerprint: session.fingerprint,
    receiverLabel: session.receiverLabel,
    // Non-secret transport metadata for the page's RTCPeerConnection.
    sdp: String(payload.sdp || ''),
  }
}

async function acceptOffer({ offerId, sdp } = {}) {
  const { chainKeys, identity } = await ensureChainReady()
  const session = [..._sessions.values()].find(s => s.role === 'receiver' && s.offerMessageId === offerId)
  if (!session) throw sessionNotFound(String(offerId || ''))
  if (session.accepted) {
    return { ok: true, answerRecord: session.answerRecord, answerRecordB64: recordToManual(session.answerRecord), fingerprint: session.fingerprint }
  }
  // The page's answer SDP rides INSIDE the sealed answer payload (never in
  // the envelope — the plaintext-leak audit would refuse it there).
  session.answerSdp = String(sdp || '')
  const ephemeral = await generateEphemeralKeys()
  const answerPayload = {
    accepted: true,
    echoNonce: session.nonce, // one-time capability echo INSIDE ciphertext
    receiverEphemeralPubJwk: ephemeral.pubJwk,
    receiverLabel: (_availability && _availability.label) || '',
    receiverSignPubJwk: identity.signPubJwk,
    sdp: session.answerSdp,
  }
  const sealed = await sealForPeer(chainKeys, identity, session.peerKeys, 'answer', answerPayload, {
    transferId: session.transferId,
    seq: 1,
  })
  const th = await transcriptHash(session.offerMessageId, sealed.messageId, session.offerPayloadHashHex, sealed.payloadHashHex)
  // R79 (F-R78-1): receiver-side K_transfer + nonce prefix in one pass.
  const secrets = await deriveTransferSecrets(ephemeral.privJwk, session.senderEphemeralPubJwk, th)
  session.key = secrets.key
  session.noncePrefix = secrets.noncePrefix
  session.fingerprint = transferFingerprint(th)
  session.ephemeral = ephemeral
  session.answerMessageId = sealed.messageId
  session.answerPayloadHashHex = sealed.payloadHashHex
  session.answerRecord = sealed.record
  session.accepted = true
  // R83: receiver ladder — accepted ⇒ connecting rung (canonical state).
  session.state = TRANSFER_STATES.ACCEPTED
  session.inbox = newInbox(session.offer)
  // R85 (T7): ACCEPTED is WebRTC-bound — persist for the interruption ledger.
  queueSnapshotPersist()
  return {
    ok: true,
    answerRecord: sealed.record,
    answerRecordB64: recordToManual(sealed.record),
    fingerprint: session.fingerprint,
  }
}

// R130 (FINDING R130-F4 — the concurrency pass, law 0.44): the one-active-send
// gate had a TOCTOU window — the busy check and the session registration are
// separated by awaits (chain readiness, ephemeral-key generation), so two
// TRUE parallel dispatches (a double-click's two TRANSFER_CREATE_OFFER
// messages) could BOTH pass the check before either registered. The R81 gate
// was only ever proven against sequential second offers. The gate is now ONE
// serialized unit: check + register + the offer build ride a single-flight
// chain, so a parallel rush resolves to exactly one winner and the typed
// TRANSFER_BUSY — provably serialized, never lucky.
let _offerGateChain = Promise.resolve()

function createOffer(args = {}) {
  const run = _offerGateChain.then(() => _createOfferInner(args))
  _offerGateChain = run.catch(() => {})
  return run
}

async function _createOfferInner({ to, file, sdp, beamHint, sync = false } = {}) {
  const { chainKeys, identity } = await ensureChainReady()
  // R81-F2 — ONE active outgoing transfer per sender device. A non-terminal
  // sender session (stuck on any ladder rung) refuses a second offer with a
  // typed, localized busy code instead of silently stacking sessions.
  const busy = activeSenderSession()
  if (busy) {
    const e = transferError('transfer_busy', `Transfer ${busy.transferId.slice(0, 8)}… is still active — finish or cancel it before starting another`)
    e.typedCode = 'TRANSFER_BUSY'
    throw e
  }
  const peer = await resolvePeerKeys(String(to || ''))
  if (!peer || !peer.agrPubJwk) {
    throw transferError('unknown_sender', 'Target device is not known yet — enable availability there and refresh the device list')
  }
  const size = Number(file && file.size) || 0
  const check = validateTransferRequest({ size, limit: DEFAULT_TRANSFER_LIMIT, hardCap: HARD_TRANSFER_CAP })
  if (!check.ok) throw transferError(check.reason, `Transfer refused by policy (${check.reason})`)
  const offer = buildFileOffer({ name: file && file.name, size, sha256hex: file && file.sha256hex })
  const ephemeral = await generateEphemeralKeys()
  // S8.9 (R99): a SYNC offer (kind 'sync-offer') rides the same machinery,
  // the same gates and the same single-flight; the receiver's engine
  // auto-answers it (never a user-facing transfer card).
  const kind = sync ? 'sync-offer' : 'offer'
  const payload = {
    kind,
    file: offer,
    sdp: String(sdp || ''),
    senderEphemeralPubJwk: ephemeral.pubJwk,
    senderLabel: (_availability && _availability.label) || '',
    senderSignPubJwk: identity.signPubJwk,
    // R98 (S8.6): the beam's cloud hint (provider + stripped URL — never
    // credentials) rides the SEALED offer payload so the joiner's next step
    // is named. Absent for ordinary file transfers.
    ...(beamHint && typeof beamHint === 'object' ? { beamHint: { provider: String(beamHint.provider || '').slice(0, 24), url: String(beamHint.url || '').slice(0, 300) } } : {}),
  }
  // R77-C audit fix (F-R77-D2-2): the one-time capability nonce is generated
  // HERE (32-hex, one per offer) and rides the sealed record's nonce field;
  // the receiver's answer echoes it inside its ciphertext and the
  // nonce_mismatch gate in openFromPeer actually fires now.
  const offerNonce = randomHex32()
  const sealed = await sealForPeer(chainKeys, identity, peer, kind, payload, { seq: 0, nonce: offerNonce })
  const transferId = sealed.record.transferId && sealed.record.transferId !== ''
    ? sealed.record.transferId
    : sealed.messageId // sealedForPeer leaves transferId '' when unspecified
  _sessions.set(transferId, {
    transferId,
    role: 'sender',
    syncTransfer: !!sync, // R100: the engine owns the sync act — the page never touches it
    // R81-F2: explicit ladder position — created ⇒ offer_sent.
    state: TRANSFER_STATES.OFFER_SENT,
    syncTransfer: !!sync,
    peerKeys: peer,
    peerLabel: peer.label || '',
    offer,
    ephemeral,
    offerMessageId: sealed.messageId,
    offerPayloadHashHex: sealed.payloadHashHex,
    nonce: offerNonce,
    expiresAt: sealed.record.expiresAt,
    accepted: false,
    key: null,
    outbox: null,
    lastActivity: Date.now(),
  })
  // R85 (T7): a waiting offer survives worker recycles — persist it.
  queueSnapshotPersist()
  return {
    ok: true,
    record: sealed.record,
    recordB64: recordToManual(sealed.record),
    messageId: sealed.messageId,
    transferId,
  }
}

/**
 * Generic record sealing for the page (non-secret payloads only: SDP/ICE
 * candidate JSON, cancel/complete markers, manual presence). OFFER and
 * ANSWER records are built by the dedicated flows above — they need the
 * worker's ephemeral keys and the transcript.
 */
async function sealRecord({ kind, to, payload, transferId = '', seq = 0 } = {}) {
  const { chainKeys, identity } = await ensureChainReady()
  // R85 (F-R84-XFER-3): 'decline' joins the page-facing whitelist — the
  // receiver's refusal is sealed as its own T5 terminal record (worker-side
  // mapping to RECEIVER_DECLINED happens in the poll; see above).
  if (!['ice', 'cancel', 'complete', 'decline', 'presence'].includes(String(kind))) {
    throw transferError('bad_kind', 'This record kind must be sealed by its dedicated flow')
  }
  let peer = null
  if (kind !== 'presence') {
    peer = await resolvePeerKeys(String(to || ''))
    if (!peer) throw transferError('unknown_sender', 'Unknown target device for the record')
  }
  const sealed = await sealForPeer(chainKeys, identity, peer, String(kind), payload || {}, {
    transferId: String(transferId || ''),
    seq: Number(seq) || 0,
  })
  return { ok: true, record: sealed.record, recordB64: recordToManual(sealed.record), messageId: sealed.messageId }
}

/** Publish a page-provided sealed record to a peer's mailbox (cloud path). */
async function publishRecord({ record, to } = {}) {
  const { chainKeys, identity } = await ensureChainReady()
  if (!record || typeof record !== 'object') throw transferError('bad_record', 'No record to publish')
  const locator = await mailboxLocator(chainKeys, String(to || ''))
  await putRecordToMailbox(chainKeys, identity, locator, record)
  return { ok: true }
}

/**
 * Sender-side chunk sealing (R79 frame schema v1). The page supplies the file
 * slice bytes (File objects live in the page) plus the counts it computed;
 * the AUTHENTICATED OFFER is the authority — any count disagreement, out-of-
 * range index or wrong-size slice is a rejection, never a fallback.
 */
async function sealChunkMessage({ transferId, seq, totalChunks, totalBytes, bytesB64 } = {}) {
  const session = _sessions.get(String(transferId || ''))
  if (!session || session.role !== 'sender' || !session.key) throw sessionNotFound(String(transferId || ''))
  if (!_identity || !_identity.deviceId) {
    throw transferError('locked', 'The local device identity is not available for this transfer')
  }
  const offerChunks = Number(session.offer.totalChunks) || 0
  const offerBytes = Number(session.offer.size) || 0
  if ((Number(totalChunks) || 0) !== offerChunks || (Number(totalBytes) || 0) !== offerBytes) {
    throw transferError('bad_record', 'Chunk request counts disagree with the authenticated offer')
  }
  const idx = Number(seq) || 0
  if (idx < 0 || idx >= offerChunks) {
    throw transferError('bad_record', 'Chunk index is outside the offered chunk count')
  }
  const bytes = base64ToBytes(String(bytesB64 || ''))
  // Final chunk may be partial; every other chunk must be exactly CHUNK_SIZE.
  const expected = (idx === offerChunks - 1)
    ? offerBytes - idx * CHUNK_SIZE
    : CHUNK_SIZE
  if (bytes.length !== expected) {
    throw transferError('size_mismatch', `Chunk ${idx} is ${bytes.length} bytes, expected ${expected}`)
  }
  // R79 (F-R78-1): canonical frame metadata — ONE assembly point shared with
  // the receiver (openChunk builds the identical structure from the offer).
  const meta = buildFrameMeta({
    transferId: session.transferId,
    senderDeviceId: _identity.deviceId,
    receiverDeviceId: session.peerKeys && session.peerKeys.deviceId,
    chunkIndex: idx,
    totalChunks: offerChunks,
    totalBytes: offerBytes,
    metadataHash: session.offer.sha256hex,
    noncePrefix: session.noncePrefix,
  })
  const frame = await sealChunk(session.key, meta, bytes)
  session.outbox = session.outbox || { nextSeq: 0, sealed: 0 }
  session.outbox.sealed = Math.max(session.outbox.sealed, idx + 1)
  // R81-F2: the first sealed chunk advances the ladder (transferring).
  if (session.state === TRANSFER_STATES.ANSWER_RECEIVED || !session.state) {
    session.state = TRANSFER_STATES.TRANSFERRING
  }
  session.lastActivity = Date.now()
  return { ok: true, frame }
}

async function ingestFrame({ transferId, frame } = {}) {
  const session = _sessions.get(String(transferId || ''))
  if (!session || session.role !== 'receiver' || !session.key || !session.inbox) {
    throw sessionNotFound(String(transferId || ''))
  }
  if (!_identity || !_identity.deviceId) {
    throw transferError('locked', 'The local device identity is not available for this transfer')
  }
  const seq = Number(frame && frame.seq)
  if (!Number.isInteger(seq)) throw transferError('bad_record', 'Frame without a sequence number')
  // STRICT ordering: expectedSeq only — a gap or a duplicate fails loudly.
  // R79 (P3 gap hygiene): a broken sequence WIPES the receiver session — the
  // page abandons the transfer, so the worker must not linger on it. The
  // expected value is captured BEFORE the wipe so the typed error survives
  // (wipeSession nulls the inbox — reading it afterwards lost the code).
  if (seq < session.inbox.expectedSeq) {
    const expected = session.inbox.expectedSeq
    wipeSession(transferId)
    throw transferError('duplicate', `Frame ${seq} is a duplicate (expected ${expected})`)
  }
  if (seq > session.inbox.expectedSeq) {
    const expected = session.inbox.expectedSeq
    wipeSession(transferId)
    throw transferError('gap', `Frame gap: expected ${expected}, got ${seq} — transfer fails closed`)
  }
  // Defense-in-depth (owner order): the authenticated offer bounds BOTH the
  // chunk count and the byte count — a peer cannot push past either.
  if (seq >= session.inbox.totalChunks) {
    wipeSession(transferId)
    throw transferError('size_mismatch', 'Frame index is outside the offered chunk count')
  }
  if (session.inbox.received >= session.inbox.total) {
    wipeSession(transferId)
    throw transferError('size_mismatch', 'More frames arrived than the offered file size')
  }
  // R79 (F-R78-1): canonical frame metadata — identical structure to the
  // sender's (buildFrameMeta), with the device roles swapped for the receiver.
  const meta = buildFrameMeta({
    transferId: session.transferId,
    senderDeviceId: session.peerKeys && session.peerKeys.deviceId,
    receiverDeviceId: _identity.deviceId,
    chunkIndex: seq,
    totalChunks: session.inbox.totalChunks,
    totalBytes: session.inbox.total,
    metadataHash: session.offer.sha256hex,
    noncePrefix: session.noncePrefix,
  })
  const bytes = await openChunk(session.key, meta, frame || {})
  // Byte-count gate AFTER decryption (the last chunk may be partial).
  if (session.inbox.received + bytes.length > session.inbox.total) {
    wipeSession(transferId)
    throw transferError('size_mismatch', 'Decrypted data exceeds the offered file size')
  }
  session.inbox.parts.push(bytes)
  session.inbox.received += bytes.length
  session.inbox.expectedSeq += 1
  // R83: receiver ladder — the first authenticated frame advances the
  // canonical state to TRANSFERRING (event-derived, never guessed).
  if (session.state === TRANSFER_STATES.OFFER_PENDING || session.state === TRANSFER_STATES.ACCEPTED || !session.state) {
    session.state = TRANSFER_STATES.TRANSFERRING
  }
  session.lastActivity = Date.now()
  return { ok: true, received: session.inbox.received, total: session.inbox.total }
}

async function inboxState({ transferId } = {}) {
  const session = _sessions.get(String(transferId || ''))
  if (!session || session.role !== 'receiver' || !session.inbox) throw sessionNotFound(String(transferId || ''))
  return {
    ok: true,
    received: session.inbox.received,
    total: session.inbox.total,
    done: session.inbox.received >= session.inbox.total && session.inbox.total > 0,
    verified: session.inbox.verified ? { ok: true, sha256: session.inbox.verified.sha256hex, size: session.inbox.verified.size } : null,
  }
}

async function finalizeInboxMessage({ transferId } = {}) {
  const session = _sessions.get(String(transferId || ''))
  if (!session || session.role !== 'receiver' || !session.inbox) throw sessionNotFound(String(transferId || ''))
  if (session.inbox.verified) {
    return { ok: true, sha256: session.inbox.verified.sha256hex, size: session.inbox.verified.size }
  }
  // R79: the FULL chunk set must have arrived — count, then bytes, then digest.
  if (session.inbox.expectedSeq !== session.inbox.totalChunks || session.inbox.received !== session.inbox.total) {
    wipeSession(transferId)
    throw transferError('size_mismatch', 'The transfer is incomplete — chunk count/byte count does not match the offer')
  }
  const result = await finalizeInbox(session.inbox.parts, session.offer)
  if (!result.ok) {
    // FAIL (never save): wipe the buffer on any integrity failure.
    wipeSession(transferId)
    throw transferError(result.reason || 'sha_mismatch', 'Integrity check failed — the transfer was discarded, nothing was saved')
  }
  session.inbox.verified = result
  // R83: receiver ladder — verified ⇒ VERIFYING (awaiting the explicit save).
  session.state = TRANSFER_STATES.VERIFYING
  // Assemble plaintext ONCE in worker memory for the one-time export.
  const merged = new Uint8Array(result.size)
  let off = 0
  for (const part of session.inbox.parts) {
    merged.set(part, off)
    off += part.length
  }
  session.inbox.plaintext = merged
  session.inbox.parts.length = 0
  return { ok: true, sha256: result.sha256hex, size: result.size }
}

async function exportInbox({ transferId } = {}) {
  const session = _sessions.get(String(transferId || ''))
  if (!session || session.role !== 'receiver' || !session.inbox) throw sessionNotFound(String(transferId || ''))
  if (!session.inbox.verified || !session.inbox.plaintext) {
    throw transferError('not_verified', 'The transfer is not verified yet — export refused')
  }
  if (session.inbox.exported) {
    throw transferError('not_verified', 'The buffer was already exported once and wiped — one-time read enforced')
  }
  const b64 = bytesToBase64(session.inbox.plaintext)
  // One-time read: wipe immediately after encoding.
  session.inbox.plaintext.fill(0)
  session.inbox.plaintext = null
  session.inbox.exported = true
  const name = sanitizeFilename(session.offer.name)
  const size = session.inbox.verified.size
  const sha = session.inbox.verified.sha256hex
  // Session is done — keep a minimal tombstone for UI state, drop buffers.
  session.inbox = null
  session.key = null
  // R83: receiver ladder — exported ⇒ RECEIVER_SAVE_PENDING. The session is
  // now a tombstone awaiting the ONE TRANSFER_FINISH the page sends after the
  // download actually completes; that call runs the terminal cleanup and
  // publishes the sender's 'complete' notice from the page (post-save).
  session.state = TRANSFER_STATES.RECEIVER_SAVE_PENDING
  return { ok: true, bytesB64: b64, name, size, sha256hex: sha }
}

// --- Router -------------------------------------------------------------------------------

/**
 * Single async router for every TRANSFER_* runtime message. Returns the
 * response object ({ok, ...} or {ok:false, error, userMessageKey}).
 */
export async function handleTransferMessage(msg, sender = null) {
  try {
    // R85 (T7): the FIRST message a freshly woken worker handles restores the
    // sealed snapshot (resumable sessions, availability, interrupted ledger).
    // Single-flight + idempotent — a no-op within one worker lifetime.
    await ensureBootstrapped()
    const type = String(msg && msg.type)
    switch (type) {
      case 'TRANSFER_STATUS':
        return await statusMessage()

      case 'TRANSFER_OPEN_WINDOW': {
        try {
          await chrome.windows.create({ url: 'transfer.html', type: 'popup', width: 520, height: 640 })
          return { ok: true }
        } catch (e) {
          // Some surfaces (e.g. ChromeOS kiosk) refuse popup windows — fall
          // back to a normal tab so the entry point never dead-ends.
          try {
            await chrome.tabs.create({ url: 'transfer.html' })
            return { ok: true, fallback: 'tab' }
          } catch {
            throw transferError('internal', String(e && e.message || e))
          }
        }
      }

      case 'TRANSFER_ENABLE_AVAILABILITY': {
        const availability = await enableAvailability(msg)
        return { ok: true, availability, ...(await statusMessage()) }
      }

      case 'TRANSFER_DISABLE_AVAILABILITY': {
        // R81-F1: the response carries the TRUTHFUL withdrawal record — the
        // UI must never claim "device hidden" when the tombstone never
        // reached the cloud (stale-copy warning governs instead).
        const withdrawal = await disableAvailability({ publish: true })
        return { ok: true, withdrawal, ...(await statusMessage()) }
      }

      case 'TRANSFER_SET_DEVICE_TYPE': {
        // R113 §3.1 — the SELF-DECLARED device type (phone/tablet/computer).
        // Self-only by law: a device never types another — peers' types
        // arrive via learnPeer's per-entry last-writer merge. Sealed with
        // the identity, published in the next presence/roster stamp.
        try {
          const { chainKeys } = await ensureChainReady() // the lazy-derivation law
          const clean = await setDeviceIdentityType(chainKeys, String((msg && msg.deviceType) || ''))
          if (_identity) { _identity.deviceType = clean; _identity.typeSetAt = Date.now() }
          queueSnapshotPersist()
          return { ok: true, deviceType: clean, ...(await statusMessage()) }
        } catch (e) {
          return { ok: false, error: String((e && e.message) || e).slice(0, 80) }
        }
      }
      case 'TRANSFER_SET_DEVICE_LABEL': {
        // R100 (the CEO's Brave-style list): name THIS device — sealed with
        // the identity, published in the next presence/roster stamp.
        // R108 §3.2 — MUTUAL RENAME: a deviceId (≠ self) renames THAT peer
        // in the sealed peer map (the label + its write time, the per-entry
        // last-writer law); the roster augmenter carries it to every device
        // with the next sync. Self-rename (no deviceId / own id) is the
        // unchanged R100 path.
        try {
          const { chainKeys } = await ensureChainReady() // the lazy-derivation law
          const wantId = String((msg && msg.deviceId) || '')
          const selfId = _identity ? String(_identity.deviceId || '') : ''
          if (wantId && wantId !== selfId) {
            const renamed = await renamePeerLabel(chainKeys, wantId, String((msg && msg.label) || ''))
            // R127 (law 0.41): the peer map is chain state OUTSIDE the vault —
            // the rename stamps the roster-dirty marker so the very next sync
            // pushes the envelope (the "Already in sync" gate would swallow it).
            await markRosterDirty()
            return { ok: true, deviceId: renamed.deviceId, label: renamed.label, labelSetAt: renamed.labelSetAt, ...(await statusMessage()) }
          }
          const clean = await setDeviceIdentityLabel(chainKeys, String((msg && msg.label) || ''))
          if (_identity) { _identity.label = clean; _identity.labelSetAt = Date.now() }
          queueSnapshotPersist()
          // R127 (law 0.41): the self-rename rides the same law — the next
          // sync must publish the new label even when no entry changed.
          await markRosterDirty()
          return { ok: true, label: clean, ...(await statusMessage()) }
        } catch (e) {
          return { ok: false, error: String((e && e.message) || e).slice(0, 80) }
        }
      }

      case 'TRANSFER_PEER_REMOVE': {
        // R85 (§5): the roster's Remove. R148 §6.5 (LAW #74 — the K-5 cure):
        // the removal commits a TOMBSTONE to the sealed peer map (never a
        // silent local forget) — the augmenter carries it to the whole chain
        // with the next sync; every instance (and every fresh open)
        // converges. The cloud-dead case: the tombstone commits locally and
        // the roster-dirty marker queues it ("removal pending sync").
        const { chainKeys } = await ensureChainReady()
        const deviceId = String(msg.deviceId || '')
        const removed = await removePeer(chainKeys, deviceId, { by: _identity ? _identity.deviceId : '' })
        // R127 (law 0.41): a removal is a roster change — the next sync must
        // carry the tombstoned roster (the augmenter merges the map), even
        // when the vault entries did not change.
        if (removed) await markRosterDirty()
        return { ok: true, removed, deviceId }
      }

      // R148 §6.5 — the CONVERGED tombstone's local cleanup: the removed
      // row's own button (the chain has seen the mark; the TOFU slot frees).
      case 'TRANSFER_PEER_FORGET': {
        const { chainKeys } = await ensureChainReady()
        const deviceId = String(msg.deviceId || '')
        const map = await loadPeerMap(chainKeys)
        if (!map[deviceId] || !map[deviceId].removed) {
          return { ok: false, userMessage: 'forget is only for a REMOVED row — use Remove to take a device off the chain' }
        }
        const forgotten = await forgetPeer(chainKeys, deviceId)
        return { ok: true, forgotten, deviceId }
      }

      case 'TRANSFER_LIST_PEERS': {
        // R79 (F-R78-3, P2): LIST_PEERS must return the REAL readiness state,
        // not a default 'locked' error because chain keys are not derived yet.
        // States (all {ok:true}): locked / no_sync_code / enable_availability
        // (chain not derived this worker lifetime) / rendezvous unavailable /
        // no available devices / ready.
        const avail = availabilityActive()
        let unlocked = false
        try {
          const st = await getVaultState()
          unlocked = !!(st && st.isUnlocked)
        } catch { /* state unavailable */ }
        if (!unlocked || !_chainKeys || !_identity) {
          const status = await statusMessage()
          // Truthful empty list + readiness — NEVER the locked error shape
          // when the vault is actually unlocked.
          return { ...status, peers: [] }
        }
        // R89 (F-R89-MANUAL-1): the cloud poll refreshes the FRESHNESS view —
        // it can never ERASE hand-learned devices. A rendezvous that cannot
        // answer keeps the current in-memory availability view (manual
        // learns stay visible — T2/T4), and the list renders from the sealed
        // peer map either way. Availability OFF no longer forces an empty
        // list: the sealed peer map is the identity truth and the freshness
        // flags carry the truthfulness about who is reachable.
        if (avail) {
          try {
            _lastAvailablePeers = await listAvailablePeers(_chainKeys)
          } catch (e) {
            console.warn('[UCrypt] Transfer: availability poll failed (hand-learned devices kept):', e?.code || e?.message || e)
          }
        }
        return await statusMessage()
      }

      case 'TRANSFER_POLL': {
        // R87-LIVE-1: the swept sender-offer ids ride EVERY poll response —
        // a live sender page renders the typed EXPIRED terminal at the
        // deadline even when the watchdog path is unavailable.
        const res = await pollMailbox()
        const expired = sweepExpiredSenderOffers()
        // R105 §2.3 — THE MULTI-WINDOW OFFER HINT. Two truthful loser shapes,
        // both reported to THIS surface only when ANOTHER surface is the
        // opener/consumer:
        //   (a) REGISTERED-ELSEWHERE — the poll found an offer record already
        //       opened (registered by an earlier poll/accept); the opening
        //       surface is the first ctx the offer was SERVED to;
        //   (b) VANISHED-AFTER-CONSUMPTION — an offer this surface was served
        //       earlier is no longer offered and was ACCEPTED by another ctx.
        const ctx = ctxOf(sender)
        const offeredNow = new Set((res && res.ok && Array.isArray(res.offers) ? res.offers : []).map((o) => o && o.offerId))
        for (const id of offeredNow) offerSeenStamp(id, ctx)
        const consumedElsewhere = []
        const openedBy = (offerId) => {
          const seen = _offerSeenByCtx.get(offerId)
          // the first-served surface is the OPENER (its open registered the session)
          return seen && seen.size ? [...seen][0] : null
        }
        for (const offerId of (res && res.ok && Array.isArray(res.registeredOffers) ? res.registeredOffers : [])) {
          const opener = openedBy(offerId)
          if (opener && opener !== ctx && !consumedElsewhere.some((c) => c.offerId === offerId)) {
            consumedElsewhere.push({ offerId, at: Date.now() })
          }
        }
        for (const [offerId, seenSet] of _offerSeenByCtx) {
          if (offeredNow.has(offerId) || !seenSet.has(ctx)) continue
          const consumed = _offerConsumedBy.get(offerId)
          if (consumed && consumed.ctx !== ctx && !consumedElsewhere.some((c) => c.offerId === offerId)) {
            consumedElsewhere.push({ offerId, at: consumed.at })
          }
        }
        const out = (expired.length && res && res.ok) ? { ...res, expired } : res
        return (consumedElsewhere.length && out && out.ok) ? { ...out, consumedElsewhere } : out
      }

      case 'TRANSFER_OPEN_OFFER': {
        const { chainKeys, identity } = await ensureChainReady()
        const projection = await openOfferRecord(chainKeys, identity, msg.record)
        if (!projection) throw transferError('bad_record', 'Not an offer record (or already registered)')
        return { ok: true, offer: projection }
      }

      case 'TRANSFER_ACCEPT_OFFER': {
        const r = await acceptOffer(msg)
        // R105 §2.3 — the consuming surface is stamped on EVERY accept call
        // (the idempotent retry included) so a losing surface's next poll
        // gets the typed consumed-elsewhere hint.
        if (r && r.ok) offerConsumedStamp(msg && msg.offerId, ctxOf(sender))
        return r
      }

      case 'TRANSFER_CREATE_OFFER':
        return await createOffer(msg)

      case 'TRANSFER_OPEN_ANSWER': {
        const { chainKeys, identity } = await ensureChainReady()
        // R79 (F-R78-6): identity is threaded — no null-identity answer path.
        const res = await openAnswerRecord(chainKeys, identity, msg.record, null)
        return { ok: true, answer: res }
      }

      case 'TRANSFER_SEAL_RECORD':
        return await sealRecord(msg)

      case 'TRANSFER_PUBLISH_RECORD':
        return await publishRecord(msg)

      case 'TRANSFER_SEAL_CHUNK':
        return await sealChunkMessage(msg)

      case 'TRANSFER_INGEST_FRAME':
        return await ingestFrame(msg)

      case 'TRANSFER_INBOX_STATE':
        return await inboxState(msg)

      case 'TRANSFER_FINALIZE':
        return await finalizeInboxMessage(msg)

      case 'TRANSFER_EXPORT_INBOX':
        return await exportInbox(msg)

      case 'TRANSFER_OPEN_MANUAL': {
        const { chainKeys, identity } = await ensureChainReady()
        const record = recordFromManual(msg.signal)
        if (!record) throw transferError('bad_record', 'The pasted signal is not a valid sealed record')
        if (record.kind === 'join') {
          // S8.8 — the zero-transport JOIN: the joiner's sealed record was
          // carried by hand. The same typed gates apply (proof, replay,
          // rate-limit); a valid record joins the pending-join list the
          // origin's device-management poll renders.
          const projection = await openJoinRecord(chainKeys, identity, record)
          if (!_manualJoins.some((j) => j.messageId === projection.messageId)) _manualJoins.push(projection)
          if (_manualJoins.length > 10) _manualJoins.shift()
          return { ok: true, kind: 'join', join: projection }
        }
        if (record.kind === 'presence') {
          // R107 (F-R107-SELF-1): a signal carried in a CIRCLE — the device
          // opening its OWN presence carrier — is typed TRUTHFULLY here and
          // never learned: the old path ran learnPeer(self) and the page then
          // claimed "it now appears in the device list" for a row the list
          // filters as `mine`. The receiver-guided copy says where the signal
          // actually belongs (the OTHER device's window).
          if (record.from === identity.deviceId) {
            return { ok: true, kind: 'presence', self: true, peer: { deviceId: record.from, label: '' } }
          }
          // Manual first contact: learn the peer from a pasted presence record.
          const opened = await openFromPeer(chainKeys, identity, record, {})
          _lastAvailablePeers = _lastAvailablePeers.filter(p => p.deviceId !== opened.from)
          _lastAvailablePeers.push({
            deviceId: opened.from,
            label: opened.peer.label || '',
            availableUntil: opened.payload.availableUntil || record.expiresAt,
            signPubJwk: opened.peer.signPubJwk,
            agrPubJwk: opened.peer.agrPubJwk,
          })
          return { ok: true, kind: 'presence', peer: { deviceId: opened.from, label: opened.peer.label || '', availableUntil: opened.payload.availableUntil || record.expiresAt } }
        }
        if (record.kind === 'offer') {
          const projection = await openOfferRecord(chainKeys, identity, record)
          if (!projection) throw transferError('bad_record', 'Not an offer record (or already registered)')
          return { ok: true, kind: 'offer', offer: projection }
        }
        if (record.kind === 'sync-offer') {
          // S8.9 (R99) — the zero-transport continuous sync: a hand-carried
          // sync-offer enters the SAME auto-answer engine path.
          const r = await openManualSyncSignal(msg.signal)
          return { ok: true, kind: 'sync-offer', ...r }
        }
        if (record.kind === 'sync-answer') {
          // The sender side of the zero-transport continuous sync.
          const r = await openManualSyncAnswer(msg.signal)
          return { ok: true, kind: 'sync-answer', ...r }
        }
        if (record.kind === 'answer') {
          // R79 (F-R78-6): identity threaded on the manual path too.
          const res = await openAnswerRecord(chainKeys, identity, record, null)
          return { ok: true, kind: 'answer', answer: res }
        }
        const opened = await openFromPeer(chainKeys, identity, record, {})
        if (record.kind === 'ice') return { ok: true, kind: 'ice', ice: { transferId: opened.transferId, from: opened.from, candidate: opened.payload && opened.payload.candidate || null } }
        if (record.kind === 'cancel') {
          if (opened.transferId) wipeSession(opened.transferId)
          return { ok: true, kind: 'cancel', transferId: opened.transferId }
        }
        return { ok: true, kind: 'complete', transferId: opened.transferId }
      }

      case 'TRANSFER_CANCEL': {
        const transferId = String(msg.transferId || '')
        const session = _sessions.get(transferId)
        const peerKeys = session ? session.peerKeys : null
        // R81-F2: cancel is TERMINAL — the one idempotent cleanup runs (never
        // a bare wipe), so the busy gate opens and the ledger records why.
        const cleanup = terminalCleanup(transferId, TRANSFER_STATES.CANCELLED)
        return { ok: true, hadSession: cleanup.existed || !!session, peerKeys: peerKeys ? { deviceId: peerKeys.deviceId } : null }
      }

      case 'TRANSFER_REPORT_STAGE': {
        // R83-F3: the page REPORTS a real event-derived stage (WebRTC answer
        // applied → connecting; pump tail → verifying). The whitelist gate
        // keeps the canonical machine honest — the page cannot invent states.
        const transferId = String(msg.transferId || '')
        const stage = String(msg.stage || '')
        const session = _sessions.get(transferId)
        if (!session || session.role !== 'sender') throw sessionNotFound(transferId)
        if (!isReportableStage(stage)) {
          throw transferError('bad_record', `Stage "${stage.slice(0, 24)}" is not a reportable transfer stage`)
        }
        session.state = stage
        if (msg.route && typeof msg.route === 'string') session.route = msg.route
        session.lastActivity = Date.now()
        // R85 (T7): stage runs past OFFER_SENT are WebRTC-bound — the snapshot
        // stages them as bound records and the next wake (the recycle proven)
        // converts them into the typed interrupted ledger (F-R100-1).
        queueSnapshotPersist()
        return { ok: true, transferId, state: session.state, route: session.route || null }
      }

      case 'TRANSFER_ACTIVE_SESSION': {
        // R83-F2/F3: the canonical session query. A reloaded/reopened transfer
        // window renders THIS truth (or a truthful "no active transfer") — it
        // can never invent a fresh idle state over a live session, and the
        // worker's lazy expiry sweep has already removed dead offers.
        // R101 (F-R100-2): the answer carries the truthful interrupted
        // projection too — the page's stale-sender clear renders the T7 note
        // from THE SAME authoritative answer it cleared on (no second call,
        // no truth divergence between the two surfaces).
        const session = activeSessionProjection()
        return { ok: true, activeSession: session, interrupted: interruptedProjection() }
      }

      case 'TRANSFER_FINISH': {
        // R83-F2: the receiver's save completed — the ladder's final rung.
        // This is the ONLY 'completed' terminal for the receiver role; it runs
        // the one idempotent cleanup (and only for the save-pending tombstone).
        const transferId = String(msg.transferId || '')
        const session = _sessions.get(transferId)
        if (!session || session.role !== 'receiver') {
          return { ok: true, hadSession: false } // already finished — idempotent
        }
        if (session.state === TRANSFER_STATES.RECEIVER_SAVE_PENDING || session.state === TRANSFER_STATES.VERIFYING) {
          terminalCleanup(transferId, TRANSFER_STATES.COMPLETED)
          return { ok: true, hadSession: true, completed: true }
        }
        // Any other state: the transfer cannot be "finished" from there —
        // refuse without destroying a still-active session.
        return { ok: false, error: 'no_session', userMessageKey: ERROR_KEYS.no_session }
      }

      // ═══ R98 — THE BEAM (S8): direct join over the existing rails ══════

      case 'TRANSFER_BEAM_ARM': {
        // S8.3: opening the Add-device surface auto-enables availability for
        // a bounded window (default 10 minutes, aligned with the offer TTL).
        // Truthful copy comes from the returned windowEnd — the user is never
        // surprised that presence turned on.
        const minutes = Number(msg.minutes) > 0
          ? Math.min(Number(msg.minutes), BEAM_WINDOW_MINUTES_MAX)
          : BEAM_WINDOW_MINUTES_DEFAULT
        const availability = await enableAvailability({ label: String(msg.label || '').slice(0, 60), minutes })
        _beam = { armed: true, since: Date.now(), windowEnd: availability.expiresAt }
        return { ok: true, availability, ...(await beamStatusMessage()) }
      }

      case 'TRANSFER_BEAM_DISARM': {
        // Closing the surface or the window's expiry withdraws the tombstone
        // per the presence plane law (R81-F1 immediate withdrawal).
        const withdrawal = await disableAvailability({ publish: true })
        _beam = null
        _beamEnvelope = null
        return { ok: true, withdrawal, beam: { armed: false } }
      }

      case 'TRANSFER_BEAM_STATUS': {
        // S8.3 expiry truth: the armed flag dies WITH the availability window.
        if (_beam && _availability && !_availability.enabled) _beam = null
        return { ok: true, ...(await beamStatusMessage()) }
      }

      case 'TRANSFER_BEAM_POLL_JOINS': {
        // S8.5 — the origin's moment: pending join requests for the dialog.
        // Also the expiry truth: a window that expired disarms the beam.
        if (_beam && _availability && !_availability.enabled) _beam = null
        const { chainKeys, identity } = await ensureChainReady()
        let joins = []
        let refused = []
        try {
          const res = await listJoinRequests(chainKeys, identity)
          joins = res.joins
          refused = res.refused
        } catch (e) {
          // A rendezvous that cannot answer is the typed manual-only state —
          // never a crash, never fake joins.
          return { ok: true, joins: _manualJoins.slice(), refused: [], rendezvousError: (e && (e.transferCode || e.code)) || 'internal', ...(await beamStatusMessage()) }
        }
        // S8.8: hand-carried joins merge in (newest first, deduped).
        for (const mj of _manualJoins) {
          if (!joins.some((j) => j.messageId === mj.messageId)) joins.push(mj)
        }
        joins.sort((a, b) => b.ts - a.ts)
        return { ok: true, joins, refused, ...(await beamStatusMessage()) }
      }

      case 'TRANSFER_BEAM_ACCEPT': {
        // S8.5/S8.6 — Accept fires the beam transfer: the decision is one-shot
        // (replay-gated), then the envelope is built and its DESCRIPTOR is
        // returned — the page drives the existing WebRTC file plane with it.
        // An oversized envelope falls back to the cloud path with typed copy.
        const { chainKeys, identity } = await ensureChainReady()
        const decision = await decideJoinRequest(chainKeys, identity, msg.join, true)
        _manualJoins = _manualJoins.filter((j) => j.messageId !== (msg.join && msg.join.messageId))
        _beamEnvelope = null
        const env = await beamEnvelope()
        if (!env.ok) {
          // Empty-vault origin: nothing to transfer — the joiner's first-run
          // IS the empty-vault case; the join completes with no transfer.
          return { ok: true, decision, empty: !!env.empty, reason: env.reason || '', ...(await beamStatusMessage()) }
        }
        if (env.size > DEFAULT_TRANSFER_LIMIT) {
          // S8.6: the 20 MB cap — the joiner gets the typed cloud fallback.
          // The join WAS legitimate (the proof passed; the decision stands as
          // accepted chain membership) — the note tells the joiner the beam
          // cannot carry this vault and names the cloud path instead.
          try {
            const map = await loadPeerMap(chainKeys)
            const peer = map[decision.deviceId]
            if (peer) {
              const hint = await originCloudHint()
              const sealed = await sealForPeer(chainKeys, identity, peer, 'decline', {
                reason: 'oversized',
                joinMessageId: msg.join && msg.join.messageId || '',
                sizeBytes: env.size,
                limitBytes: DEFAULT_TRANSFER_LIMIT,
                cloudHint: hint,
              })
              const locator = await mailboxLocator(chainKeys, decision.deviceId)
              await putRecordToMailbox(chainKeys, identity, locator, sealed.record)
            }
          } catch { /* the note is best-effort; the oversized truth is returned regardless */ }
          return {
            ok: true,
            decision,
            oversized: true,
            sizeBytes: env.size,
            limitBytes: DEFAULT_TRANSFER_LIMIT,
            ...(await beamStatusMessage()),
          }
        }
        // The authoritative size is the DECODED byte count (the transfer
        // plane's chunk math and the receiver's ingest count BYTES; the
        // base64 string length is a transport artifact, never a size).
        const beamBytes = base64ToBytes(env.bytesB64)
        _beamEnvelope = { bytes: beamBytes, size: beamBytes.length, sha256hex: env.sha256hex, joinerDeviceId: decision.deviceId }
        return {
          ok: true,
          decision,
          envelope: { name: BEAM_ENVELOPE_NAME, size: beamBytes.length, sha256hex: env.sha256hex },
          joinerFingerprint: await joinerFingerprint(chainKeys, decision.deviceId),
          ...(await beamStatusMessage()),
        }
      }

      case 'TRANSFER_BEAM_DECLINE': {
        // S8.5 — the typed refusal reaches the joiner's mailbox (a pairwise
        // 'decline' record carrying reason:'join' — the R85 wire kind reused).
        const { chainKeys, identity } = await ensureChainReady()
        const decision = await decideJoinRequest(chainKeys, identity, msg.join, false, { reason: String(msg.reason || '') })
        _manualJoins = _manualJoins.filter((j) => j.messageId !== (msg.join && msg.join.messageId))
        _beamEnvelope = null
        return { ok: true, decision, ...(await beamStatusMessage()) }
      }

      case 'TRANSFER_BEAM_ENVELOPE_CHUNK': {
        // The sender pump's slice source (S8.6: chunked with backpressure —
        // the page's pump pattern is the transfer plane's, the bytes come
        // from here). Decoded once at accept; wiped on lock/cancel/terminal.
        if (!_beamEnvelope) return { ok: false, error: 'no_beam_envelope', userMessageKey: 'beamErrInternal' }
        const offset = Math.max(0, Number(msg.offset) || 0)
        const length = Math.min(CHUNK_SIZE, Math.max(1, Number(msg.length) || CHUNK_SIZE))
        const slice = _beamEnvelope.bytes.slice(offset, offset + length)
        return { ok: true, bytesB64: bytesToBase64(slice), size: slice.length }
      }

      case 'TRANSFER_BEAM_ENVELOPE_DROP': {
        _beamEnvelope = null
        return { ok: true }
      }

      case 'TRANSFER_BEAM_JOIN_START': {
        // S8.4 — the joiner's handshake: the words were validated locally by
        // the wizard (SYNC_CODE_SET did it); connect the rendezvous, learn
        // the origin from the presence index (TOFU), publish the sealed join
        // record to the origin's mailbox. The words never leave this device.
        const { chainKeys, identity } = await ensureChainReady()
        // S8.8 — manual first contact: a hand-carried presence record learns
        // the origin (the same gate the transfer page's manual surface uses).
        let manualOrigin = null
        if (msg.manualPresenceB64) {
          try {
            const presenceRecord = recordFromManual(msg.manualPresenceB64)
            if (presenceRecord && presenceRecord.kind === 'presence') {
              const opened = await openFromPeer(chainKeys, identity, presenceRecord, {})
              manualOrigin = { deviceId: opened.from, label: opened.peer.label || '', signPubJwk: opened.peer.signPubJwk, agrPubJwk: opened.peer.agrPubJwk }
            }
          } catch { /* the paste is validated again below */ }
        }
        // Presence first contact — this ALSO learns the origin into the
        // sealed peer map (the safe direction: presence payloads are
        // group-sealed and signature-verified).
        let available = []
        try {
          available = await listAvailablePeers(chainKeys)
        } catch (e) {
          // S8.8: zero-transport — the manual path still works; the record
          // is staged for hand-carry below regardless of the publish outcome.
          available = []
        }
        if (manualOrigin && !available.some((p) => p.deviceId === manualOrigin.deviceId)) available.push(manualOrigin)
        if (!available.length && !msg.originDeviceId) {
          return { ok: false, error: 'no_origin_present', userMessageKey: 'beamErrNoOrigin', ...(await beamStatusMessage()) }
        }
        const chosen = msg.originDeviceId
          ? available.find((p) => p.deviceId === String(msg.originDeviceId)) || null
          : (available.length === 1 ? available[0] : null)
        if (!chosen) {
          // Multiple origins present — the user chooses (typed list).
          return {
            ok: true,
            needsChoice: true,
            origins: available.map((p) => ({ deviceId: p.deviceId, label: p.label || '', availableUntil: p.availableUntil || '' })),
            ...(await beamStatusMessage()),
          }
        }
        // The non-secret cloud hint rides the record only when the joiner has
        // none configured — S8.6: "the origin's cloud config hint travels
        // with the handshake so the joiner's next step is named". The ORIGIN
        // fills its own hint on Accept (see BEAM_JOIN_POLL's accepted shape);
        // the joiner sends its CURRENT hint state so the origin knows whether
        // the backup step needs naming.
        const joinerHint = msg.cloudHint && typeof msg.cloudHint === 'object'
          ? { provider: String(msg.cloudHint.provider || '').slice(0, 24), url: String(msg.cloudHint.url || '').slice(0, 300) }
          : null
        const record = await publishJoinRecord(chainKeys, identity, chosen, {
          label: String(msg.label || _availability?.label || '').slice(0, 60),
          cloudHint: joinerHint,
        })
        // F-R99-1 (R99): the hand-carry copy exists the instant the record is
        // sealed. A hand-carried presence proves the rendezvous is absent for
        // this join — the pointless publish ladder is SKIPPED (the manual
        // path IS the path); on the cloud path the write is attempted and a
        // failure leaves the staged copy governing.
        let stagedManualB64 = ''
        try { stagedManualB64 = btoa(JSON.stringify(record)) } catch { stagedManualB64 = '' }
        let published = false
        if (!msg.manualPresenceB64) {
          try {
            await deliverJoinRecord(chainKeys, identity, chosen.deviceId, record)
            published = true
            stagedManualB64 = '' // the cloud copy governs — drop the hand-carry
          } catch (e) {
            // S8.8: the manual zero-transport path — the EXACT sealed record is
            // copyable and the flow stays alive (the presence-publish precedent).
          }
        }
        const joinState = {
          role: 'joiner',
          phase: published ? 'awaiting' : 'manual',
          joinMessageId: record.messageId,
          origin: { deviceId: chosen.deviceId, label: chosen.label || '' },
          originFingerprint: await deviceFingerprint(chosen.signPubJwk),
          myFingerprint: await deviceFingerprint(identity.signPubJwk),
          expiresAt: record.expiresAt,
          published,
        }
        try {
          await chrome.storage.session.set({ 'ucrypt:beam:joinState': joinState })
        } catch { /* session-only advisory; memory state governs */ }
        _beamJoinState = joinState
        return {
          ok: true,
          join: joinState,
          stagedManualB64,
          ...(await beamStatusMessage()),
        }
      }

      case 'TRANSFER_BEAM_JOIN_POLL': {
        // S8.5/S8.6 — the joiner awaits: a typed refusal OR the beam offer
        // (name === ucrypt-vault.enc) means the origin answered. The mailbox
        // read is NOT gated on availability — the join record is the
        // rendezvous; the joiner never needed presence.
        const { chainKeys, identity } = await ensureChainReady()
        const refusals = await listJoinRefusals(chainKeys, identity)
        let beamOffer = null
        const records = await readOwnMailbox(chainKeys, identity)
        for (const rec of records) {
          if (!rec || rec.kind !== 'offer') continue
          try {
            const projection = await openOfferRecord(chainKeys, identity, rec)
            if (projection && projection.name === BEAM_ENVELOPE_NAME && (!_beamJoinState || !_beamJoinState.origin || projection.from === _beamJoinState.origin.deviceId)) {
              beamOffer = projection
              break
            }
          } catch { /* per-record gates never abort the poll */ }
        }
        // The beam hint rides the OFFER payload (S8.6: the origin's cloud
        // config hint travels with the handshake). openOfferRecord stores it
        // on the session; surface it through the projection if present.
        return {
          ok: true,
          refusals,
          offer: beamOffer,
          join: _beamJoinState,
          ...(await beamStatusMessage()),
        }
      }

      case 'TRANSFER_BEAM_JOIN_STATE': {
        const myFingerprint = _identity && _identity.signPubJwk ? await deviceFingerprint(_identity.signPubJwk) : ''
        return { ok: true, join: _beamJoinState, myFingerprint, ...(await beamStatusMessage()) }
      }

      case 'TRANSFER_BEAM_JOIN_CLEAR': {
        _beamJoinState = null
        try { await chrome.storage.session.remove('ucrypt:beam:joinState') } catch { /* advisory */ }
        return { ok: true }
      }

      case 'TRANSFER_BEAM_ADOPT': {
        // S8.6 — the joiner's landing: digest verified (transfer plane
        // finalize + re-verify here) → pull-first adopt → vault live. The
        // one-shot inbox export wiped the worker's copy; the bytes arrive
        // with the message. The 'complete' record is published by the UI's
        // normal completion path so the origin's session terminates cleanly.
        const res = await adoptBeamEnvelope(String(msg.bytesB64 || ''), String(msg.sha256hex || ''))
        if (res.ok) {
          // R111 §3.2 — the JOIN's landing is a direct-lane delivery: the
          // visible moment records here too (the adopt's counts + the
          // joining device's own label for the origin's ledger; the joiner's
          // ledger names the ORIGIN from the session's peer when known).
          try {
            const peerId = msg.peerDeviceId || ''
            let label = ''
            if (peerId && _chainKeys) {
              try { const pe = await getPeerEntry(_chainKeys, String(peerId)); label = (pe && pe.label) || '' } catch { /* label optional */ }
            }
            recordSyncMoment({ lane: 'direct', added: res.added || 0, updated: res.updated || 0, by: label })
          } catch { /* the moment never blocks the adopt */ }
        }
        return res.ok ? { ok: true, ...res } : { ok: false, ...res }
      }

      case 'TRANSFER_BEAMSYNC_STATUS': {
        // S8.9 (R99) — the truth surface (3.5): both legs, per ledger, plus
        // the zero-transport hand-carry state. Sizes and outcomes only — the
        // envelope bytes NEVER cross this line.
        return beamSyncLegsStatus()
      }

      case 'TRANSFER_BEAMSYNC_TICK': {
        // The alarm cadence's manual twin (the UI and the harness may drive
        // the poll directly; the SW alarm drives it anyway).
        return await syncPollTick()
      }

      case 'TRANSFER_BEAMSYNC_FANOUT': {
        // An explicit fan-out (the Sync surface's action; the mutation hook
        // calls the engine directly). Single-flight inside the engine.
        const r = await beamSyncFanout(String(msg.reason || 'manual'))
        return { ok: true, ...r }
      }

      case 'TRANSFER_BEAMSYNC_OPEN_MANUAL': {
        // S8.8 generalized: a hand-carried sync-offer enters the SAME
        // auto-answer path (the same typed gates, the same replay ledger).
        return await openManualSyncSignal(String(msg.signal || ''))
      }

      case 'TRANSFER_BEAMSYNC_OPEN_ANSWER': {
        // A hand-carried sync-ANSWER (the sender side of the zero-transport
        // continuous sync).
        return await openManualSyncAnswer(String(msg.signal || ''))
      }

      // ═══ R134 §2 — BEAM 2 message cases (the new architecture) ═══
      case 'TRANSFER_BEAM2_STATUS': {
        if (!(await selfHealOrLocked())) return { ok: true, locked: true, beam2: null }
        let identity = null
        try { identity = await ensureBeam2Ready() } catch { identity = null }
        const snap = beam2StatusSnapshot()
        snap.locked = false
        snap.identityReady = !!identity
        snap.legacyBridge = 'lib/transfer/legacy-bridge.js'
        return { ok: true, beam2: snap }
      }

      case 'TRANSFER_BEAM2_OFFER': {
        // the ONE-TOUCH send: {deviceId, manifest:{name,size,mime,sha256}}
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Vault locked'))
        const created = await beam2CreateOffer(String(msg.deviceId || ''), msg.manifest || {})
        _beam2PollPhase = 'active' // the adaptive cadence flips fast
        // R139 §5.1 — the transport mirror: the offer-out advances THE BOND
        try {
          const eng = await beam3Engine()
          await eng.noteTransport({ type: 'offer-out', peerDeviceId: String(msg.deviceId || ''), name: msg.manifest && msg.manifest.name, bytes: msg.manifest && msg.manifest.size, plane: 'B' })
        } catch { /* the mirror never blocks the offer */ }
        return created
      }

      case 'TRANSFER_BEAM2_RESPOND': {
        // the modal's decision: {sessionId, deviceId, decision:'accept'|'decline'|'cancel'}
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Vault locked'))
        _beam2PollPhase = 'active'
        return await beam2Respond(String(msg.sessionId || ''), String(msg.deviceId || ''), String(msg.decision || ''))
      }

      case 'TRANSFER_BEAM2_TICK': {
        // the mailbox poll (also driven by the adaptive presence cadence)
        const t = await beam2Tick()
        if (t && t.ok) {
          const hasLive = !!beam2ActiveSession()
          _beam2PollPhase = hasLive ? 'active' : 'idle'
        }
        // R139 §5.1 — the mirror runs on every tick: the Bond advances from
        // the transport truth whatever surface is open (one journey machine)
        await mirrorBondTransport()
        return { ok: true, ...t, beam2: beam2StatusSnapshot() }
      }

      case 'TRANSFER_BEAM2_RESUME': {
        // law 0.56: after a restart, the journal decides what resumes
        const resumable = await scanResumableSessions(beam2Store)
        return { ok: true, resumable }
      }

      case 'TRANSFER_HEALTH': {
        // R93 §5 — read-only boundedness probe for the setup self-check.
        // Sizes ONLY: nothing else crosses this line — no payloads, no keys,
        // no records of any kind.
        let peers = 0
        try { peers = _chainKeys ? await countPeers(_chainKeys) : 0 } catch { peers = 0 }
        return {
          ok: true,
          sessions: _sessions.size,
          interruptedLedger: _interruptedLedger.length,
          cleanupLedger: _cleanupLedger.length,
          peers,
        }
      }

      // ── R136 §5/§6 — THE BEAM 3 DISPATCH (Device Transfer reborn) ──
      case 'TRANSFER_BEAM3_STATUS': {
        const eng = await beam3Engine()
        // R138 F3: the search cadence — while the journey is SEARCHING this
        // poll ALSO refreshes the availability view (the relay-read hop), so
        // the roster and the devices row share one fact at the 2s cadence.
        try {
          if (availabilityActive()) _lastAvailablePeers = await listAvailablePeers(_chainKeys)
        } catch (e) {
          try { await eng.noteHop({ name: 'relayRead', ok: false, detail: `the availability poll failed: ${e && (e.transferCode || e.code) || 'unavailable'}` }) } catch { /* telemetry is best-effort */ }
        }
        // R140 §6.3 — the inbox polls ITSELF: while the Receive intent is
        // active and availability is armed, a due poll runs HERE (the page's
        // 2 s status poll resurrects the cadence across worker restarts; the
        // poller's own timer covers the page-closed case). The hop is REPORTED.
        _beam3Inbox.setActive(_beam3IntentRole === 'receive' && !!availabilityActive())
        if (_beam3Inbox.active) {
          const due = !_beam3Inbox.lastCheckedAt || (Date.now() - _beam3Inbox.lastCheckedAt) >= (INBOX_DUE_MS)
          if (due) {
            const r = await _beam3Inbox.pollOnce()
            try {
              await eng.noteTransport({ type: 'inbox-poll', ok: !!(r && r.ok !== false), error: (r && r.error) || '', periodSec: _beam3Inbox.periodSec })
            } catch { /* the hop report is best-effort */ }
          }
        }
        // R139 §5.1 — the transport mirror BEFORE the projection: the Bond
        // advances from the transport truth, then the honest-clock tick runs
        // inside status() and the ONE projection renders it all.
        await mirrorBondTransport()
        // R138 §4.1: the visible-device count rides the poll — the single-writer
        // projection derives the devices row from the SAME fact the roster renders.
        const visible = await beam3VisibleDeviceCount()
        // R139 §5.4 — the transport's independent path to CONNECTED: when the
        // roster proves the peer is live on this device's availability, the
        // transport confirms the bond (the first path wins, the other confirms).
        try {
          if (visible > 0 && availabilityActive()) await eng.transportConfirm({ plane: 'B' })
        } catch { /* best-effort */ }
        const base = await eng.status({ visibleDevices: visible })
        base.locked = !_chainKeys || !_identity
        // R140 §7.2/§6.2/§6.3 — the ONE chain truth + the evidence-based gate
        // + the inbox's self-report ride EVERY status (the page renders from
        // THIS alone — the single-writer law to the screen)
        try {
          const { ['ucrypt:chainState:wake']: wake } = await chrome.storage.local.get('ucrypt:chainState:wake')
          const { ['ucrypt:lastPull']: lastPull } = await chrome.storage.local.get('ucrypt:lastPull')
          const rec = await getTransportRecord()
          const RELAY_KINDS = { gdrive: 'Google Drive', webdav: 'WebDAV', custom: 'your cloud', http: 'your cloud', dropbox: 'Dropbox' }
          const cloudLabel = rec && rec.id ? (RELAY_KINDS[rec.id] || '') : ''
          const chain = deriveChainState({ cloudConnected: !!(rec && rec.id), cloudLabel, wake: wake || null, lastPull: lastPull || null })
          base.chain = chain
          base.gate = relayGate({ chainDerived: chain, cloudLabel })
        } catch { /* the gate facts are best-effort — the projection stands alone */ }
        base.inbox = _beam3Inbox.statusLine()
        return base
      }
      case 'TRANSFER_BEAM3_CODES_MATCH': {
        // R138 §4.2 step 4 — 'Codes match — connect': the deterministic connect.
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Unlock the vault to use Device Transfer'))
        const eng = await beam3Engine()
        return await eng.codesMatch()
      }
      case 'TRANSFER_BEAM3_HS_HOP': {
        // R138 F4 — the per-hop telemetry ingest (the doctor card's live rows).
        const eng = await beam3Engine()
        return await eng.noteHop({ name: msg.name, ok: msg.ok !== false, detail: msg.detail || '' })
      }
      case 'TRANSFER_BEAM3_HS_RESET': {
        // R138 §4.2 step 6 — the user's ONE dismiss (terminals stay until this).
        const eng = await beam3Engine()
        return await eng.handshakeReset()
      }
      case 'TRANSFER_BEAM3_INTENT': {
        // R136-F4: declaring the intent ARMS AVAILABILITY AUTOMATICALLY.
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Unlock the vault to use Device Transfer'))
        const eng = await beam3Engine()
        const out = await eng.intent({ role: msg.role, route: msg.route || 'auto' })
        // R140 §6.3 — the Receive intent ACTIVATES the self-polling inbox
        // (receiving is passive — the poller owns the cadence from here)
        _beam3IntentRole = String(msg.role || '')
        _beam3Inbox.setActive(_beam3IntentRole === 'receive' && !!availabilityActive())
        return out
      }
      case 'TRANSFER_BEAM3_OPEN_SIGNAL': {
        // R136-F1: paste → consume nonce → the PAIRED state (never a dead end).
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Unlock the vault to use Device Transfer'))
        const eng = await beam3Engine()
        return await eng.openSignal({ text: String(msg.text || '') })
      }
      case 'TRANSFER_BEAM3_REGENERATE': {
        const eng = await beam3Engine()
        return await eng.regenerate({ previous: msg.previous || null })
      }
      case 'TRANSFER_BEAM3_OFFER': {
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Vault locked'))
        const eng = await beam3Engine()
        return await eng.offer({ sessionId: msg.sessionId, files: msg.files || [], peerDeviceId: msg.deviceId || '' })
      }
      case 'TRANSFER_BEAM3_RESPOND': {
        if (!(await selfHealOrLocked())) return fail(transferError('locked', 'Vault locked'))
        const eng = await beam3Engine()
        return await eng.respond({ sessionId: msg.sessionId, decision: msg.decision })
      }
      case 'TRANSFER_BEAM3_CHUNK_ACK': {
        const eng = await beam3Engine()
        return await eng.noteChunkAck({ sessionId: msg.sessionId, lastAcked: Number(msg.lastAcked) || 0 })
      }
      case 'TRANSFER_BEAM3_CHUNKS_DONE': {
        const eng = await beam3Engine()
        return await eng.chunksDone({ sessionId: msg.sessionId })
      }
      case 'TRANSFER_BEAM3_VERIFY': {
        const eng = await beam3Engine()
        return await eng.verify({ sessionId: msg.sessionId, ok: !!msg.ok })
      }
      case 'TRANSFER_BEAM3_INTERRUPT': {
        const eng = await beam3Engine()
        return await eng.interrupt({ sessionId: msg.sessionId })
      }
      case 'TRANSFER_BEAM3_RESUME': {
        const eng = await beam3Engine()
        return await eng.resume({ sessionId: msg.sessionId })
      }
      case 'TRANSFER_BEAM3_READYNESS': {
        const eng = await beam3Engine()
        return await eng.readiness({ planeGuess: msg.plane || null, visibleDevices: Number(msg.visibleDevices) || 0 })
      }
      case 'TRANSFER_BEAM3_WORKFLOW': {
        const eng = await beam3Engine()
        const wf = eng.wfAdvance(String(msg.sessionId || ''), msg.event)
        return { ok: true, workflow: wf, workflowView: wf ? (await eng.status()).workflowView : null }
      }

      default:
        return { ok: false, error: `Unknown transfer message type: ${type}`, userMessageKey: 'transferErrInternal' }
    }
  } catch (e) {
    console.warn('[UCrypt] Transfer:', e && (e.transferCode || e.code) || 'error', '-', e && e.message ? String(e.message).slice(0, 160) : e)
    return fail(e)
  }
}

// --- Lifecycle hooks (background.js integration) ------------------------------------------

/**
 * Called by background.js on EVERY vault-lock path (explicit LOCK message,
 * lazy auto-lock broadcast). R81-F1: the lock now WITHDRAWS PRESENCE —
 *
 * Order of operations (the availability truth):
 *   1. availability stops locally FIRST (no refresh, no re-advertise);
 *   2. EVERY in-memory session is terminally cleaned (R81-F2 ladder — a lock
 *      is a terminal event for all of them, never an auto-accept);
 *   3. a signed encrypted withdrawn tombstone is published best-effort with
 *      the STILL-DERIVED chain keys (this is why withdrawal runs BEFORE the
 *      key wipe — a withdrawal attempt that would silently lose its keys is
 *      not an attempt at all);
 *   4. only then are the chain keys and identity scrubbed from memory.
 * If the tombstone cannot reach the cloud, the record is honest about it
 * (withdrawal.tombstoneOk=false): other devices show the truthful
 * "Presence may be stale" copy and the bounded envelope TTL (≤2 min) expires
 * the ghost — UCrypt never claims an immediate accuracy it cannot have (the
 * owner order: A cannot know B locked when no notification can arrive).
 */
export async function onVaultLocked() {
  // R85 (F-R84-XFER-5): the worker that processes the lock may have RECYCLED
  // since availability was enabled — in a fresh lifetime _chainKeys/_identity
  // are null and the old gate silently SKIPPED the withdrawal, leaving a
  // false "Available until …" on the wire (live-reproduced in R84). The sync
  // mnemonic is still readable at handler entry (the vault is unlocked RIGHT
  // NOW — the wipe below is what ends that), so the chain keys are re-derived
  // HERE and the tombstone ALWAYS attempts before the secrets are scrubbed.
  if (!_chainKeys || !_identity) {
    try {
      const mnemonic = await getUnlockedSyncMnemonic()
      if (mnemonic) {
        _chainKeys = await deriveChainKeys(mnemonic)
        _identity = await getOrCreateDeviceIdentity(_chainKeys)
      }
    } catch { /* re-derivation is best-effort — the stale-copy TTL governs */ }
  }
  // (1) availability stops locally first
  _availability = null
  // F-R114-MAILBOX-1: the lock ends the rendezvous session too — the next
  // unlock re-proves the namespace (the secrets died; the memo dies with them).
  resetRendezvousSession()
  // R98 (S8.3/S8.10): a lock also disarms the beam — the window dies, the
  // envelope copy is dropped, the joiner's await state is cleared (law 0.14:
  // secrets are dropped on lock; the beam never outlives the unlock).
  _beam = null
  _beamEnvelope = null
  _beamJoinState = null
  _manualJoins = []
  // S8.9 (R99, law 3.3): the continuous-sync channels die WITH the unlock —
  // every peer channel closes, the hand-carry state and the legs ledger are
  // wiped (the truth surface starts clean; the cloud remains the backup).
  try { await beamSyncTeardownAll() } catch { /* the lock is never blocked by teardown */ }
  try { await chrome.storage.session.remove('ucrypt:beam:joinState') } catch { /* advisory */ }
  try { await chrome.alarms.clear(TRANSFER_AVAILABILITY_ALARM) } catch { /* noop */ }
  try { await chrome.storage.local.remove(AVAILABILITY_STATE_KEY) } catch { /* noop */ }
  // R85 (T7): the sealed session snapshot is unlocked-vault state — a lock
  // clears it so a later wake can never resurrect pre-lock sessions.
  try { await chrome.storage.session.remove(SESSIONS_STATE_KEY) } catch { /* noop */ }
  _interruptedLedger.length = 0
  // (2) every session hits its terminal cleanup (idempotent, bounded ledger)
  for (const transferId of [..._sessions.keys()]) {
    terminalCleanup(transferId, TRANSFER_STATES.CANCELLED)
  }
  _sessions.clear()
  // (3) best-effort tombstone with the still-derived (or re-derived) keys —
  // R85 (F-R84-XFER-5): this now attempts on EVERY lock, including a lock
  // processed by a freshly recycled worker.
  let withdrawal = { attempted: false, tombstoneOk: false }
  if (_chainKeys && _identity) {
    try { withdrawal = await withdrawPresence(_chainKeys, _identity) } catch { /* stale-copy governs */ }
  }
  // (4) NOW the secrets go.
  _chainKeys = null
  _identity = null
  _lastAvailablePeers = []
  // R85 (T7): deterministic final clear — the terminal cleanups above queued
  // snapshot persists, but every persist checks !_chainKeys, so nothing can
  // re-write after this point. The key removal here is the authoritative one.
  try { await chrome.storage.session.remove(SESSIONS_STATE_KEY) } catch { /* noop */ }
  return withdrawal
}

/**
 * Availability alarm (R81-F1: 1-minute repeating cadence):
 *   - window expired  → expire availability locally (mailbox records keep
 *     their natural bounded expiry — nothing is published at expiry);
 *   - window open     → refresh presence (fresh sequence + publishedAt) so
 *     peers see a live freshness signal instead of an aging advertisement.
 */
export async function handleTransferAlarm(alarmName) {
  if (String(alarmName) !== TRANSFER_AVAILABILITY_ALARM) return
  // R85 (T7): an alarm firing in a freshly woken worker must restore the
  // snapshot first — the availability record lives in the sealed snapshot.
  await ensureBootstrapped()
  if (_availability && _availability.enabled) {
    if (Date.parse(_availability.expiresAt) <= Date.now()) {
      await disableAvailability({ publish: false })
      return
    }
    await refreshAvailabilityPresence()
  }
  // R134 §2.B — the Beam 2 adaptive-cadence tick rides the same alarm:
  // fast (~2s) while a session is live, slow (30s) idle, exponential backoff
  // on failure — the poll decides by its own phase, the alarm is just the
  // heartbeat. Failures are typed, never thrown (the cadence owns them).
  try {
    if (_chainKeys && _identity) {
      const now = Date.now()
      const due = _beam2PollPhase === 'active' ? BEAM2_POLL_ACTIVE_MS : BEAM2_POLL_IDLE_MS
      if (now - _beam2LastPollAt >= due) await beam2Tick()
    }
  } catch { /* the cadence's failure backoff owns it (typed, counted) */ }
}

/**
 * S8.9 (R99) — the continuous-sync poll tick (the alarm's entry point).
 * background.js fires 'ucrypt:beam-sync' every minute while the vault is
 * unlocked; the tick reads the own mailbox and auto-answers sync offers
 * (chain-membership consent; pull-first, digest-verified adoption).
 */
export async function beamSyncAlarmTick() {
  try { return await syncPollTick() } catch (e) {
    console.warn('[UCrypt] BeamSync: tick failed:', e && e.message ? String(e.message).slice(0, 100) : e)
    return { ok: false, reason: 'tick_failed' }
  }
}

/**
 * S8.9 completion (R100) — the executor registration entry point.
 * background.js's chrome.runtime.onConnect forwards every port named
 * 'ucrypt:beam-executor' here; the engine owns the registry (liveness via
 * port disconnect, withdrawal on lock — order §2.2). The executor hosts
 * TRANSPORT ONLY; the sealed machinery never leaves the worker.
 */
export function registerBeamExecutor(port) {
  try { return registerBeamExecutorPort(port) } catch (e) {
    console.warn('[UCrypt] BeamSync: executor registration refused:', e && e.message ? String(e.message).slice(0, 80) : e)
    return { ok: false, error: 'registration_refused' }
  }
}
export async function ensureChainReadyForMailbox() { return ensureChainReady() }

/**
 * R141 §7 — the MAILBOX roster bridge: the sealed peer map (the chain
 * roster the sync learned) is the ONE peer truth the clean-room transport
 * reads. Public fields only — labels and ids, never key material beyond
 * what the address algebra already derives from the chain.
 */
export async function mailboxRosterPeers() {
  // R146 §6.2 — THE ONE DEVICE-TRUTH LAW at the roster wire: the transfer
  // roster serves the SAME canonical projection the Cloud Sync device list
  // serves (full freshness, types, entry counts, typed presence states).
  // The v3.2.0 strip ({deviceId,label} only) is DEAD — the R146 autopsy's
  // ROSTER-1 finding (the two device-truths, H-7).
  // The R89/R145 heal laws hold: a recycled worker re-derives its chain keys
  // lazily — ONE re-derivation before any roster answer, so a joined device
  // never renders a false empty roster after a worker restart.
  // (The R142-A2/A3 path/mechanism cures ride the STATIC import — the
  // ancestor's graph already carried it; the dynamic import() stays dead —
  // Chrome disallows import() on ServiceWorkerGlobalScope.)
  let unlockedEarly = false
  try { const s0 = await getVaultState(); unlockedEarly = !!(s0 && s0.isUnlocked) } catch { /* gated */ }
  if (unlockedEarly && (!_chainKeys || !_identity)) {
    try { await ensureChainReady() } catch { /* the honest readiness governs below */ }
  }
  if (unlockedEarly && !_chainKeys) {
    try {
      const healMnemonic = await getUnlockedSyncMnemonic()
      if (healMnemonic) {
        _chainKeys = await deriveChainKeys(healMnemonic)
        _identity = await getOrCreateDeviceIdentity(_chainKeys)
      }
    } catch { /* best-effort — the honest readiness still governs */ }
  }
  const rendezvous = await rendezvousCapability().catch(() => null)
  return canonicalPeerRows(!!(rendezvous && rendezvous.available))
}
