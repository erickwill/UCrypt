/**
 * UCrypt — R142 §5 — THE DIRECT ROAD PAGE CONTROLLER (the wires of the bridge).
 *
 * The pure bridge family (session/signal/channel/safety-code/relay-fallback/
 * presence-lite/doctor2) owns the LAWS; this module owns the WIRES:
 *   - the RTCPeerConnection (host candidates first — two browsers on ONE
 *     machine is a first-class case, the owner's own topology; STUN optional);
 *   - the dual signaling: the relay envelopes (cloud up) AND the cloud-free
 *     bundle (multi-frame QR + the words token + paste) — same bytes, three
 *     doors (§5.2-b2);
 *   - the 6-digit safety code compare (mismatch aborts BEFORE any payload
 *     byte — G93 R11);
 *   - the streaming channel: 16 KiB chunks, bufferedamountlow backpressure,
 *     progressive SHA-256, the atomic part-file naming, the receipt riding
 *     back over the SAME channel (§5.2-b3/b5);
 *   - cancel-safe at every state (G93 R9): the pc closes, the relay signals
 *     sweep, the session lands CANCELLED — no orphans.
 *
 * The panels this module owns: the road badge, the QR door, the code panel,
 * the direct progress lines. The mailbox page (lib/mailbox/page.js) owns the
 * cards and calls in — ONE writer per panel (the R141 law holds).
 *
 * DOM + WebRTC + chrome.* — the battery pins the pure family; this module is
 * the G93 field matrix's subject.
 */

import {
  BRIDGE_STATES, BRIDGE_ROADS, BRIDGE_ICE_WINDOW_MS,
  newBridgeSession, stepBridge, armIceWindow, iceWindowExpired, demoteToRelay,
  pickRoad, noRoadTruth, roadLabel, bridgeError,
} from './session.js'
import {
  buildSignalEnvelope, validateSignalEnvelope,
  buildOfferBundleText, parseOfferBundleText,
  frameBundleText, parseBundleFrames, bundleToWordsToken, wordsTokenToBundle,
  BRIDGE_BUNDLE_TTL_MS,
} from './signal.js'
import {
  BRIDGE_CHUNK_BYTES, buildHeaderFrame, chunkBytes, BridgeAssembler,
  mayFeed, speedLine, CHANNEL_BACKPRESSURE, fileSha256Hex,
} from './channel.js'
import { formatSafetyCode } from './safety-code.js'
import { demotionAnnouncement } from './relay-fallback.js'
// The QR codec rides the page's classic globals (lib/qr.js renders, lib/
// qrscan.js decodes — the vetted-vendor law 0.17); transfer.html loads both
// BEFORE this module. The typeof guards keep the battery honest about it.

const $ = (id) => document.getElementById(id)

function msg(key, subs = undefined, fallback = '') {
  try {
    const s = chrome.i18n.getMessage(key, subs)
    return s || fallback
  } catch { return fallback }
}

function door(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra }).then((r) => r || { ok: false, code: 'DOOR_EMPTY' }, (e) => ({ ok: false, code: 'DOOR_ERROR', userMessage: String(e && e.message || e).slice(0, 160) }))
}

function randomHex(n = 16) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/* ── The session registry (one live session per page; cancel-safe) ───────── */

let _live = null // { session, pc, dc, file, bytes, sha256, assembler, timers:[], onLine, onProgress }

function ownsSession(sessionId) {
  return _live && _live.session && _live.session.sessionId === sessionId
}

/** THE CANCEL LAW (G93 R9): every state leaves a clean idle — no orphans. */
export async function cancelSession({ sweep = true } = {}) {
  const live = _live
  _live = null
  if (!live) return { ok: true, cancelled: false }
  try { if (live.timers) for (const t of live.timers) clearInterval(t) } catch { /* already gone */ }
  try { if (live.dc) live.dc.close() } catch { /* already gone */ }
  try { if (live.pc) live.pc.close() } catch { /* already gone */ }
  if (sweep && live.session) {
    try { await door('BRIDGE_SESSION_CLOSE', { sessionId: live.session.sessionId }) } catch { /* best-effort sweep */ }
  }
  try {
    live.session = stepBridge(live.session, BRIDGE_STATES.CANCELLED, { detail: 'the user cancelled' })
  } catch { /* a terminal session cannot re-cancel — the cleanup above already ran */ }
  setRoadBadge(null)
  hideCodePanel()
  hideQrDoor()
  return { ok: true, cancelled: true, sessionId: live.session ? live.session.sessionId : '' }
}

/* ── The panels this module owns (ONE writer each) ───────────────────────── */

export function setRoadBadge(road, { announced = false } = {}) {
  const el = $('mbRoadBadge')
  if (!el) return
  if (!road) { el.textContent = ''; el.hidden = true; return }
  el.hidden = false
  el.textContent = roadLabel(road) + (announced && road === BRIDGE_ROADS.RELAY ? ' — switched automatically' : '')
  el.className = 'road-badge' + (road === BRIDGE_ROADS.RELAY ? ' road-relay' : ' road-direct')
}

export function directLine(text) {
  const el = $('mbSendJourney')
  if (el && text != null) el.textContent = text
}

export function directProgress({ received, size, speedLine: sl = '', etaLine = '' } = {}) {
  const el = $('mbDirectProgress')
  if (!el) return
  const pct = size ? Math.min(100, Math.round((received / size) * 100)) : 0
  el.textContent = `${pct}% · ${fmtSize(received)} of ${fmtSize(size)}${sl ? ' · ' + sl : ''}${etaLine ? ' · ' + etaLine : ''}`
}

function fmtSize(n) {
  const b = Number(n) || 0
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

/* ── The code panel (the human gate — both devices, typed confirm) ───────── */

export function showCodePanel(code, { role } = {}) {
  const panel = $('mbCodePanel')
  if (!panel) return
  panel.hidden = false
  $('mbCodeShown').textContent = formatSafetyCode(code)
  $('mbCodeRole').textContent = role === 'receiver'
    ? msg('mbCodeRecvRole', undefined, 'Compare this code with the sender\u2019s screen. The file moves only after you confirm.')
    : msg('mbCodeSendRole', undefined, 'Show this code to the other device. The file moves only when they confirm the match.')
  // the actions row (mbCodeMatch / mbCodeMismatch) is static — the receiver's
  // confirm is the human gate; the sender just shows (no per-role toggling)
}

export function hideCodePanel() {
  const panel = $('mbCodePanel')
  if (panel) panel.hidden = true
}

/* ── The QR door (the cloud-free bundle: camera-less parity, §10.4) ──────── */

export function showQrFrames(frames, wordsToken) {
  const box = $('mbQrDoor')
  if (!box) return
  box.hidden = false
  const holder = $('mbQrFrames')
  holder.textContent = ''
  frames.forEach((text, i) => {
    const wrap = document.createElement('div')
    wrap.className = 'qr-frame'
    const label = document.createElement('p')
    label.className = 'card-help'
    label.textContent = msg('mbQrFrameLabel', [String(i + 1), String(frames.length)], `Frame ${i + 1} of ${frames.length}`)
    const img = document.createElement('div')
    img.className = 'qr-img'
    try {
      const url = (typeof QR !== 'undefined') ? QR.encode(text) : ''
      if (url) {
        const im = document.createElement('img')
        im.src = url
        im.alt = msg('mbQrFrameAlt', [String(i + 1)], `Transfer frame ${i + 1}`)
        im.width = 148
        im.height = 148
        img.append(im)
      } else {
        img.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — use the words token below)')
      }
    } catch {
      img.textContent = msg('mbQrTooBig', undefined, '(this frame is too large — use the words token below)')
    }
    wrap.append(label, img)
    holder.append(wrap)
  })
  const words = $('mbQrWords')
  if (words) words.value = wordsToken || ''
  box.hidden = false
}

export function hideQrDoor() {
  const box = $('mbQrDoor')
  if (box) box.hidden = true
}

/* ── The sealed bundle builders (the sender's offer / the receiver's reply) ─ */

async function sealBundlePayload(payload) {
  const r = await door('BRIDGE_SEAL', { payload })
  if (!r.ok) throw bridgeError('SEAL', r.userMessage || 'the bundle could not be sealed')
  return r.sealedB64
}

async function openBundlePayload(sealedB64) {
  const r = await door('BRIDGE_OPEN', { sealedB64 })
  if (!r.ok) throw bridgeError('SEAL', r.userMessage || 'the bundle could not be opened')
  return r.payload
}

/** The sender's offer bundle (sealed, single-use, 10-minute TTL). The sealed
 * payload carries fromMemberId so the receiver's ANSWER can ride the relay
 * back — the address is inside the seal (only the chain reads it).
 * R154 §5 (A.2.d) — the payload ALSO carries the sender's bond stamp
 * (bondSealed — itself sealed under the same chain key, a nested seal):
 * a completed road lands the peer in BOTH rosters. Absent = the older
 * bundles' shape — the parse is tolerant, the road never depends on it. */
export async function buildSenderBundle({ sessionId, sdp, nonceA, fileName, size, sha256, fromMemberId = '', bondSealed = '' }) {
  const sealedB64 = await sealBundlePayload({ sdp, nonceA, sessionId, fileName, size, sha256, role: 'sender', fromMemberId, bondSealed })
  const text = buildOfferBundleText({ role: 'sender', sessionId, sealedPayload: sealedB64 })
  return { text, frames: frameBundleText(text), words: bundleToWordsToken(text) }
}

/** The receiver's answer bundle — the same shape, the reverse ride (the
 * receiver's bond stamp rides back so the SENDER learns them too). */
export async function buildReceiverBundle({ sessionId, sdp, nonceB, bondSealed = '' }) {
  const sealedB64 = await sealBundlePayload({ sdp, nonceB, sessionId, role: 'receiver', bondSealed })
  const text = buildOfferBundleText({ role: 'receiver', sessionId, sealedPayload: sealedB64 })
  return { text, frames: frameBundleText(text), words: bundleToWordsToken(text) }
}

/* R154 §5 (A.2.d) — THE ROAD-LEARN: every handshake that opened under the
 * chain key may carry the counterparty's bond stamp (a nested seal — the
 * outer seal already proved the same chain). Learning is best-effort and
 * typed; it NEVER blocks or fails the transfer (the road's laws stand). */
export async function learnBondIfPresent(sealedB64, onLine) {
  if (!sealedB64 || typeof sealedB64 !== 'string') return
  try {
    const r = await door('BRIDGE_BOND_LEARN', { sealedB64 })
    if (r && r.ok && onLine) {
      const name = (r.learned && r.learned.label) || 'a chain device'
      onLine(msg('mbBondRoadLearned', [name], `Paired with ${name} — they are in your device list now.`))
    }
  } catch { /* the learn never breaks the road; the roster law has its own door */ }
}

/** Best-effort bond stamp for the bundles (the invitation inside the road). */
export async function myBondStampSealed() {
  try {
    const r = await door('BRIDGE_BOND_SEAL')
    return (r && r.ok && r.sealedB64) || ''
  } catch { return '' }
}

/** Import ANY bundle the user pasted / scanned / uploaded (one door, three
 * paths AND two shapes: the raw JSON bundle (as the QR carries it) and the
 * words token (as the copy/paste carries it) — the human never has to know
 * which is which. */
export async function importBundleText(text) {
  const raw = String(text || '').trim()
  let bundle = null
  try {
    bundle = parseOfferBundleText(raw)
  } catch (e) {
    // not raw JSON — the words-token shape (or garbage; the token attempt
    // throws its own typed error for the human)
    const decoded = wordsTokenToBundle(raw)
    bundle = parseOfferBundleText(decoded)
  }
  const payload = await openBundlePayload(bundle.p)
  return { bundle, payload, role: bundle.role }
}

/** Multi-frame QR import: the user uploads a QR IMAGE (the camera-less law).
 * The decode rides the vetted ladder (lib/qrscan.js — inversion, upscaling,
 * noise transforms; the R104 law, loaded as the page's classic global). */
export async function importQrImage(file) {
  if (typeof globalThis.UCryptQrScan !== 'object') throw bridgeError('QR', 'the QR reader is unavailable on this page')
  const r = await globalThis.UCryptQrScan.decodeFromBlob(file)
  if (!r || !r.ok || !r.text) throw bridgeError('QR', 'no QR code found in the image')
  return String(r.text)
}

/** The receiver's ENTRY door: the user imports the sender's handshake (words
 * pasted, or a QR image read). One door, three import paths — the cloud-free
 * parity (§5.2-b2b). Returns the session the panels now show. */
export async function startFromIncomingBundle(text, { onLine = () => {} } = {}) {
  const imported = await importBundleText(text)
  if (!imported.payload || !imported.payload.sdp || imported.payload.role !== 'sender') {
    throw bridgeError('SHAPE', 'this is not a sender\u2019s handshake — ask the sender to show theirs')
  }
  return directReceive({ payload: imported.payload, fromName: 'the sender', onLine })
}

/* ── The RTCPeerConnection wiring ────────────────────────────────────────── */

/** The relay-signaling answer window (the road-demotion timer — distinct from
 * the 10 s ICE window, which governs the connection itself). */
const BRIDGE_RELAY_ANSWER_WINDOW_MS = 25 * 1000

const DEFAULT_STUN = 'stun:stun.l.google.com:19302'

async function iceServersConfig() {
  try {
    const got = await chrome.storage.local.get('ucrypt:stun')
    const list = got && got['ucrypt:stun']
    if (Array.isArray(list) && list.length && list.every((u) => typeof u === 'string' && /^stuns?:/.test(u))) return list.map((u) => ({ urls: u }))
  } catch { /* the default stands */ }
  return [{ urls: DEFAULT_STUN }]
}

function newPc() {
  return new RTCPeerConnection({ iceServers: [] }) // host candidates FIRST — Road 1 needs no server
}

/** Wait for ICE gathering to complete (4 s cap — the complete SDP carries the candidates). */
function gatheredComplete(pc, { capMs = 4000 } = {}) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve(true)
    let done = false
    const finish = (v) => { if (!done) { done = true; resolve(v) } }
    pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') finish(true) })
    setTimeout(() => finish(false), capMs)
  })
}

/** The road truth from the connected pair (host = this network; srflx = internet). */
export async function classifyRoad(pc) {
  try {
    const stats = await pc.getStats()
    let localProto = ''
    stats.forEach((r) => {
      if (r.type === 'local-candidate' && r.candidateType && (r.candidateType === 'host' || r.candidateType === 'srflx')) {
        if (!localProto || r.candidateType === 'host') localProto = r.candidateType
      }
    })
    return localProto === 'host' ? BRIDGE_ROADS.DIRECT_LAN : BRIDGE_ROADS.DIRECT_NET
  } catch {
    return BRIDGE_ROADS.DIRECT_LAN
  }
}

/* ── THE SENDER'S JOURNEY (§5.4: pick file → pick device → code → progress → receipt) ── */

/**
 * Attempt the DIRECT road for one file. Resolves:
 *   { ok:true, road, sessionId, receipt }             — the direct transfer sealed
 *   { ok:false, demoted:true, announcement, reason }  — demote to the relay road
 *   { ok:false, userMessage }                          — a named failure
 */
export async function directSend({ file, peerMemberId, peerName = '', cloudConnected = false, onLine = () => {}, onProgress = () => {} } = {}) {
  if (!file) throw bridgeError('SHAPE', 'the direct send needs the file')
  await cancelSession() // one live session per page — the previous one swept clean

  const bytes = null // THE STREAMING LAW (the honest 100 MB door): the file is
  // never fully buffered — pass 1 computes the progressive fingerprint from
  // File slices, pass 2 streams 256 KiB reads as 16 KiB wire chunks.
  const sha256 = await progressiveFileSha(file)
  const sessionId = randomHex(12)
  const nonceA = randomHex(16)

  let session = newBridgeSession({ sessionId, role: 'sender', fileName: file.name, size: file.size })
  session = stepBridge(session, BRIDGE_STATES.SIGNALING, { road: BRIDGE_ROADS.DIRECT_LAN, detail: 'the direct attempt opens' })
  session = armIceWindow(session)
  _live = { session, pc: null, dc: null, file, bytes, sha256, assembler: null, timers: [], onLine, onProgress, peerMemberId, peerName, cloudConnected }

  setRoadBadge(BRIDGE_ROADS.DIRECT_LAN)
  onLine(msg('mbDirectTrying', undefined, 'Trying the direct connection…'))

  const pc = newPc()
  _live.pc = pc
  const dc = pc.createDataChannel('ucrypt-bridge', { ordered: true })
  _live.dc = dc

  const offer = await pc.createOffer()
  await pc.setLocalDescription(offer)
  await gatheredComplete(pc)
  const offerSdp = pc.localDescription.sdp

  // the sealed offer bundle — one format, three doors (relay / QR / words)
  let selfId = ''
  try { const ros = await door('BRIDGE_ROSTER'); if (ros.ok && ros.self) selfId = ros.self.memberId } catch { /* the QR door never needs it */ }
  // R154 (A.2.d) — the sender's bond stamp rides the offer (nested seal)
  const bondSealed = await myBondStampSealed()
  const bundle = await buildSenderBundle({ sessionId, sdp: offerSdp, nonceA, fileName: file.name, size: file.size, sha256, fromMemberId: selfId, bondSealed })
  let answered = null

  const viaRelay = cloudConnected && !!peerMemberId
  if (viaRelay) {
    const env = buildSignalEnvelope({ kind: 'bridge-offer', sessionId, payload: { sealedB64: bundle.frames.length === 1 ? bundle.text : bundle.text } })
    const put = await door('BRIDGE_SIGNAL_PUT', { toMemberId: peerMemberId, envelope: env })
    if (!put.ok) {
      onLine(msg('mbDirectNoRelay', undefined, 'The cloud would not carry the handshake — the QR handshake still works below.'))
    } else {
      onLine(msg('mbDirectOfferSent', [peerName], `Calling ${peerName} directly… (they may need to accept on their screen)`))
      // THE DEMOTION TIMER (§5.1 — the road-demotion timers are DISTINCT from
      // the 10 s ICE window): the relay-signaling round trip gets its own
      // honest window (25 s — the signals live 120 s); the ICE window still
      // governs the channel-open after the answer. No answer by the deadline
      // demotes AUTOMATICALLY (the badge announces it in plain words).
      answered = await pollForAnswer(sessionId, { onLine, deadlineAt: Date.now() + BRIDGE_RELAY_ANSWER_WINDOW_MS })
      if (!answered) {
        if (!_live) return { ok: false, userMessage: msg('mbDirectCancelled', undefined, 'The direct transfer was cancelled — nothing moved.') }
        const demoted = demoteToRelay(session, { reason: msg('mbDemoteReason', undefined, 'the other device did not answer in time') })
        _live.session = demoted
        const line = demotionAnnouncement({ from: BRIDGE_ROADS.DIRECT_LAN, to: BRIDGE_ROADS.RELAY })
        setRoadBadge(BRIDGE_ROADS.RELAY, { announced: true })
        try { await door('BRIDGE_SESSION_CLOSE', { sessionId }) } catch { /* swept */ }
        return { ok: false, demoted: true, announcement: line, reason: 'ice-window' }
      }
    }
  }
  if (!answered) {
    // THE CLOUD-FREE DOOR (human-paced): the QR + words ride ANY channel the
    // user likes — the wait is the user's (Cancel is always one click away),
    // never a machine timer that would abandon them mid-handshake.
    showQrFrames(bundle.frames, bundle.words)
    onLine(msg('mbDirectQrShown', undefined, 'Show this QR (or send the words) to the other device — they answer with theirs.'))
    answered = await pollForAnswer(sessionId, { onLine, fromDoor: true, deadlineAt: null })
  }

  if (!answered || answered.cancelled) {
    if (_live) await cancelSession()
    return { ok: false, userMessage: msg('mbDirectCancelled', undefined, 'The direct transfer was cancelled — nothing moved.') }
  }

  // the answer arrived (relay envelope or QR/words import) — complete the handshake
  if (!_live) return { ok: false, userMessage: msg('mbDirectCancelled', undefined, 'The direct transfer was cancelled — nothing moved.') }
  const { sdp: answerSdp, nonceB } = answered
  await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp })
  const code = await codeFor(sessionId, nonceA, nonceB)
  _live.session.code = code
  showCodePanel(code, { role: 'sender' })
  onLine(msg('mbDirectCompare', undefined, 'Compare the 6-digit code on both screens — the file moves when they confirm.'))

  const opened = await waitChannelOpen(dc, { deadlineAt: Date.now() + 45000, onLine })
  if (!opened) {
    if (!_live) return { ok: false, userMessage: msg('mbDirectCancelled', undefined, 'The direct transfer was cancelled — nothing moved.') }
    if (iceWindowExpired(session) || session.iceDeadlineAt == null) {
      const demoted = demoteToRelay(session, { reason: 'the direct channel did not open' })
      _live.session = demoted
      const line = demotionAnnouncement({ from: BRIDGE_ROADS.DIRECT_LAN, to: BRIDGE_ROADS.RELAY })
      setRoadBadge(BRIDGE_ROADS.RELAY, { announced: true })
      try { await door('BRIDGE_SESSION_CLOSE', { sessionId }) } catch { /* swept */ }
      hideQrDoor()
      return { ok: false, demoted: true, announcement: line, reason: 'channel-open' }
    }
    await cancelSession()
    return { ok: false, userMessage: msg('mbDirectFailed', undefined, 'The direct connection failed — run the doctor below.') }
  }

  // THE ROAD TRUTH from the connected pair — the badge says which road is in use
  const road = await classifyRoad(pc)
  _live.session = stepBridge(_live.session, BRIDGE_STATES.HANDSHAKE, { road, detail: 'the channel is open' })
  setRoadBadge(road)

  // THE HUMAN GATE (G93 R11): the receiver's code-ok arrives over the channel
  // BEFORE any payload byte. A mismatch means the receiver never confirms and
  // the journey cancels clean — zero data moved.
  onLine(msg('mbDirectWaitingCode', undefined, 'Waiting for the code confirmation on the other device…'))
  const codeOk = await waitCodeOk(dc, { timeoutMs: 120000 })
  if (!codeOk) {
    await cancelSession()
    return { ok: false, userMessage: msg('mbCodeNoConfirm', undefined, 'The code was not confirmed — nothing moved. Compare the digits and try again.') }
  }
  hideCodePanel()
  _live.session = stepBridge(_live.session, BRIDGE_STATES.OPEN, { road })

  // THE STREAM (§5.2-b3): header, then 16 KiB wire chunks fed from 256 KiB
  // reads — the file NEVER sits fully in memory (the honest 100 MB door);
  // the progressive fingerprint was computed in pass 1.
  _live.session = stepBridge(_live.session, BRIDGE_STATES.STREAMING, { road })
  const header = buildHeaderFrame({ sessionId, fileName: file.name, size: file.size, sha256Hex: sha256 })
  dc.send(JSON.stringify({ t: 'header', header }))
  const startedAt = Date.now()
  const READ = 256 * 1024
  let sent = 0
  for (let off = 0; off < file.size; off += READ) {
    const buf = new Uint8Array(await file.slice(off, Math.min(off + READ, file.size)).arrayBuffer())
    for (let i = 0; i < buf.length; i += BRIDGE_CHUNK_BYTES) {
      const chunk = buf.subarray(i, Math.min(i + BRIDGE_CHUNK_BYTES, buf.length))
      while (!mayFeed(dc.bufferedAmount)) {
        await new Promise((r) => setTimeout(r, 40))
        if (!_live || _live.dc !== dc) return { ok: false, userMessage: 'cancelled' }
      }
      dc.send(chunk)
      sent += chunk.length
      const sp = speedLine(sent, Date.now() - startedAt, file.size)
      onProgress({ received: sent, size: file.size, speedLine: sp.line, etaLine: sp.etaLine })
    }
  }
  dc.send(JSON.stringify({ t: 'end' }))

  // THE RECEIPT rides back over the SAME channel (§5.2-b5 parity)
  const receipt = await waitSealed(dc, { timeoutMs: 120000 })
  if (receipt && receipt.ok) {
    _live.session = stepBridge(_live.session, BRIDGE_STATES.SEALED, { road })
    _live.session = stepBridge(_live.session, BRIDGE_STATES.DONE, { road, detail: 'the receipt returned' })
    setRoadBadge(road)
    try { await door('BRIDGE_SESSION_CLOSE', { sessionId }) } catch { /* swept */ }
    _live = null
    return { ok: true, road, sessionId, receipt }
  }
  await cancelSession()
  return { ok: false, userMessage: msg('mbDirectNoReceipt', undefined, 'The file moved but the verification did not return — run the doctor below.') }
}

/* ── The receiver's side of the direct journey ───────────────────────────── */

/**
 * Answer an incoming direct offer (from a relay signal or an imported bundle).
 * The human gate: the receiver sees the code, compares, presses
 * Match/Mismatch. Mismatch aborts BEFORE any payload byte.
 */
export async function directReceive({ payload, fromName = '', onLine = () => {}, onProgress = () => {} }) {
  if (!payload || !payload.sdp || !payload.sessionId) throw bridgeError('SHAPE', 'the direct offer is malformed')
  await cancelSession()

  const sessionId = payload.sessionId
  const nonceB = randomHex(16)
  let session = newBridgeSession({ sessionId, role: 'receiver', fileName: payload.fileName || '', size: payload.size || 0 })
  session = stepBridge(session, BRIDGE_STATES.SIGNALING, { road: BRIDGE_ROADS.DIRECT_LAN })
  _live = { session, pc: null, dc: null, file: null, bytes: null, sha256: payload.sha256, assembler: null, timers: [], onLine, onProgress, nonceB, payload, fromName }

  const pc = newPc()
  _live.pc = pc
  pc.ondatachannel = (ev) => { _live.dc = ev.channel; wireReceiverChannel(ev.channel, { onLine, onProgress }) }
  await pc.setRemoteDescription({ type: 'offer', sdp: payload.sdp })
  const answer = await pc.createAnswer()
  await pc.setLocalDescription(answer)
  await gatheredComplete(pc)

  // R154 (A.2.d) — the offer carries the SENDER's bond stamp (nested seal):
  // the receiver learns them here — both entry paths (relay + QR/words) land.
  await learnBondIfPresent(payload.bondSealed, onLine)

  // R154 (A.2.d) — the receiver's bond stamp rides the reply (nested seal)
  const myBond = await myBondStampSealed()
  const bundle = await buildReceiverBundle({ sessionId, sdp: pc.localDescription.sdp, nonceB, bondSealed: myBond })
  // THE ANSWER'S RIDE: when the offer's sealed payload carries the sender's
  // address AND the cloud is up, the answer signals back automatically — the
  // user never touches a QR. The QR/words door still shows (the cloud-free
  // parity — the same bundle, three doors, §5.2-b2).
  if (payload.fromMemberId) {
    try {
      const env = buildSignalEnvelope({ kind: 'bridge-answer', sessionId, payload: { sealedB64: bundle.text } })
      const put = await door('BRIDGE_SIGNAL_PUT', { toMemberId: payload.fromMemberId, envelope: env })
      if (put.ok) onLine(msg('mbDirectReplySent', undefined, 'The answer is on its way — the connection completes on their screen.'))
    } catch { /* the QR door below is the fallback */ }
  }
  showQrFrames(bundle.frames, bundle.words)
  onLine(msg('mbDirectReplyShown', [fromName || msg('mbPeerWord', undefined, 'the sender')], `Send this reply to ${fromName || 'the sender'} (show the QR, or paste the words on their screen).`))

  const code = await codeFor(sessionId, payload.nonceA, nonceB)
  _live.session.code = code
  showCodePanel(code, { role: 'receiver' })
  return { ok: true, sessionId, bundle }
}

/** The receiver's verdict buttons wire HERE (Match / Mismatch — typed, human). */
export async function confirmCode(matched) {
  const live = _live
  if (!live || !live.dc) return { ok: false }
  if (!matched) {
    // THE ABORT (G93 R11): mismatch → clean cancel, zero payload bytes moved.
    try { live.dc.send(JSON.stringify({ t: 'code-mismatch' })) } catch { /* the channel may be gone */ }
    await cancelSession()
    return { ok: true, matched: false }
  }
  try { live.dc.send(JSON.stringify({ t: 'code-ok' })) } catch { /* the channel may be gone */ }
  return { ok: true, matched: true }
}

function wireReceiverChannel(dc, { onLine, onProgress }) {
  const live = _live
  let assembler = null
  let assembling = false
  dc.bufferedAmountLowThreshold = CHANNEL_BACKPRESSURE.lowWaterBytes
  dc.onopen = async () => {
    live.session = stepBridge(live.session, BRIDGE_STATES.HANDSHAKE, { road: BRIDGE_ROADS.DIRECT_LAN })
  }
  let _streamingStepped = false
  dc.onmessage = async (ev) => {
    try {
      if (typeof ev.data === 'string') {
        const m = JSON.parse(ev.data)
        if (m.t === 'header') {
          assembler = new BridgeAssembler({ size: m.header.size, sha256Hex: m.header.sha256 })
          live.assembler = assembler
          live.fileName = m.header.fileName
          onLine(msg('mbDirectIncoming', [m.header.fileName], `Receiving ${m.header.fileName} — the codes matched, the bytes may move.`))
        } else if (m.t === 'end') {
          if (!assembler) return
          assembling = true
          const seal = assembler.seal()
          live.session = stepBridge(live.session, BRIDGE_STATES.SEALED, { road: BRIDGE_ROADS.DIRECT_LAN })
          dc.send(JSON.stringify({ t: 'sealed', ok: true, sha256: seal.sha256 }))
          // THE LANDING: the same saveReceivedFile law — nothing opens itself.
          const r = await door('BRIDGE_DELIVER_FILE', { fileName: live.fileName || 'received-file', bytesB64: bytesToB64(concatParts(assembler.parts)) })
          if (r.ok) {
            live.session = stepBridge(live.session, BRIDGE_STATES.DONE, { road: BRIDGE_ROADS.DIRECT_LAN })
            onLine(msg('mbDirectSaved', [live.fileName || 'the file'], `Saved and verified — ${live.fileName || 'the file'}.`))
          } else {
            onLine(r.userMessage || msg('mbDirectSaveFailed', undefined, 'The file verified but could not be saved.'))
          }
          hideCodePanel()
          hideQrDoor()
          setRoadBadge(BRIDGE_ROADS.DIRECT_LAN)
        }
      } else {
        // a binary chunk (ArrayBuffer / typed views ride as-is)
        if (!assembler || assembling) return
        if (!_streamingStepped) {
          // the machine's honest walk: HANDSHAKE → OPEN (the codes matched)
          // → STREAMING (the first byte moved)
          try { live.session = stepBridge(live.session, BRIDGE_STATES.OPEN, { road: BRIDGE_ROADS.DIRECT_LAN }) } catch { /* already open */ }
          live.session = stepBridge(live.session, BRIDGE_STATES.STREAMING, { road: BRIDGE_ROADS.DIRECT_LAN })
          _streamingStepped = true
        }
        const chunk = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : ev.data
        const p = assembler.push(new Uint8Array(chunk))
        onProgress({ received: p.received, size: p.size })
      }
    } catch (e) {
      onLine(String((e && e.message) || e).slice(0, 160))
    }
  }
  dc.onclose = () => { try { live.session = stepBridge(live.session, BRIDGE_STATES.ERROR, { detail: 'the channel closed' }) } catch { /* terminal already */ } }
}

function concatParts(parts) {
  const total = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

function bytesToB64(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, bytes.length)))
  return btoa(s)
}

/* ── The waiters (typed, cancel-aware) ───────────────────────────────────── */

async function pollForAnswer(sessionId, { onLine = () => {}, fromDoor = false, deadlineAt = null } = {}) {
  // The answer arrives as a relay envelope (cloud) or as the user's imported
  // bundle (QR/words — the door sets _live.pendingAnswer from the import flow).
  // deadlineAt = null means HUMAN-paced (the QR door — no machine timer).
  const startedAt = Date.now()
  while (true) {
    if (deadlineAt != null && Date.now() > deadlineAt) return null
    if (deadlineAt == null && Date.now() - startedAt > 10 * 60 * 1000) return null // the human door's honest walk-away bound
    if (!_live || !_live.session || ownsSession(sessionId) === false) return null
    const live = _live
    if (live.pendingAnswer) {
      const a = live.pendingAnswer
      live.pendingAnswer = null
      return a
    }
    if (live.cloudConnected) {
      const poll = await door('BRIDGE_SIGNAL_POLL')
      if (poll.ok) {
        for (const s of poll.signals || []) {
          if (s.envelope && s.envelope.sessionId === sessionId && s.envelope.kind === 'bridge-answer') {
            try {
              await door('BRIDGE_SIGNAL_CONSUME', { sessionId, signalId: s.signalId })
              const payload = await openBundlePayload(s.envelope.payload.sealedB64 || s.envelope.payload.p || '')
              if (payload && payload.sdp) {
                // R154 (A.2.d) — the answer carries the receiver's bond stamp
                await learnBondIfPresent(payload.bondSealed, onLine)
                return { sdp: payload.sdp, nonceB: payload.nonceB }
              }
            } catch { /* a foreign/garbled answer never breaks the wait */ }
          }
        }
      }
    }
    if (!_live) return null
    await new Promise((r) => setTimeout(r, fromDoor ? 500 : 1200))
  }
  return null
}

/** The QR/words IMPORT door — the reply the user pasted/scaned lands here. */
export async function submitReplyBundle(text) {
  if (!_live) throw bridgeError('SHAPE', 'no live session to answer')
  const imported = await importBundleText(text)
  if (!imported.payload || !imported.payload.sdp) throw bridgeError('SHAPE', 'the reply does not carry an answer')
  // R154 (A.2.d) — the reply carries the receiver's bond stamp
  await learnBondIfPresent(imported.payload.bondSealed)
  _live.pendingAnswer = { sdp: imported.payload.sdp, nonceB: imported.payload.nonceB }
  hideQrDoor()
  return { ok: true }
}

function waitChannelOpen(dc, { deadlineAt, onLine = () => {} } = {}) {
  return new Promise((resolve) => {
    if (dc.readyState === 'open') return resolve(true)
    const tick = () => {
      if (!_live) return resolve(false)
      if (dc.readyState === 'open') return resolve(true)
      if (Date.now() > deadlineAt) return resolve(false)
      setTimeout(tick, 120)
    }
    dc.addEventListener('open', () => resolve(true))
    tick()
  })
}

function waitCodeOk(dc, { timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const startedAt = Date.now()
    const onMsg = (ev) => {
      try {
        const m = JSON.parse(ev.data)
        if (m && (m.t === 'code-ok' || m.t === 'code-mismatch')) {
          dc.removeEventListener('message', onMsg)
          resolve(m.t === 'code-ok')
        }
      } catch { /* binary frames flow here too — ignore */ }
    }
    dc.addEventListener('message', onMsg)
    const tick = () => {
      if (!_live) { dc.removeEventListener('message', onMsg); return resolve(false) }
      if (Date.now() - startedAt > timeoutMs) { dc.removeEventListener('message', onMsg); return resolve(false) }
      setTimeout(tick, 200)
    }
    tick()
  })
}

function waitSealed(dc, { timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const startedAt = Date.now()
    const onMsg = (ev) => {
      if (typeof ev.data !== 'string') return
      try {
        const m = JSON.parse(ev.data)
        if (m && m.t === 'sealed') {
          dc.removeEventListener('message', onMsg)
          resolve({ ok: !!m.ok, sha256: String(m.sha256 || '') })
        }
      } catch { /* ignore */ }
    }
    dc.addEventListener('message', onMsg)
    const tick = () => {
      if (!_live) { dc.removeEventListener('message', onMsg); return resolve(null) }
      if (Date.now() - startedAt > timeoutMs) { dc.removeEventListener('message', onMsg); return resolve(null) }
      setTimeout(tick, 200)
    }
    tick()
  })
}

async function codeFor(sessionId, nonceA, nonceB) {
  const r = await door('BRIDGE_CODE', { nonceA, nonceB })
  if (!r.ok) throw bridgeError('CODE', r.userMessage || 'the safety code could not be derived')
  return r.code
}

/** Pass 1 of the streaming send: the file's fingerprint, read in slices —
 * the honest 100 MB door never holds the whole file in memory. */
async function progressiveFileSha(file) {
  const { ProgressiveSha256 } = await import('./channel.js')
  const p = new ProgressiveSha256()
  const READ = 1024 * 1024
  for (let off = 0; off < file.size; off += READ) {
    const buf = new Uint8Array(await file.slice(off, Math.min(off + READ, file.size)).arrayBuffer())
    p.update(buf)
  }
  return p.hex()
}
