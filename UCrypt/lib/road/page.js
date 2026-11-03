/**
 * UCrypt — R147 §5 — THE ROAD PAGE FLOW (lib/road/page.js — NEW namespace).
 *
 * The R147 ROAD PURGE: lib/bridge/page.js — the R142 direct-road wire whose
 * confirm died silently on a closed DataChannel (the J-1 false success at
 * :521-525), whose badge reported intent as fact (:330, the J-8 disease),
 * whose offer blew its own QR frames (:205-208, the J-3 disease), and whose
 * STUN door was defined and never called (:266 vs :276) — is DEAD. The trim
 * ledger carries the CEO's verbatim quote (see releases/verification/
 * r147-trim-ledger.json).
 *
 * This module owns the LOGIC of the road; the journey controller owns the
 * DOM (ONE writer per surface — the panels render AT their beats):
 *
 *   roadSend()        — pick → compact offer → the control exchange →
 *                       the dialer (direct→relay, typed) → the 6-digit code
 *                       → the confirm watchdog (both carriers) → the pump
 *                       (64 KiB chunks, acks, hash) → the typed receipt.
 *   roadAnswerOffer() — the receiver's side: open the sealed SDP, answer,
 *                       show the code, run the pump's receive side.
 *   confirmCode()     — the human gate: rides EVERY carrier (the J-1 cure),
 *                       typed result, never a false success.
 *   cancelSession()   — the G93 R9 cancel law: no orphans, ever.
 *
 * PURE-ISH — chrome.* doors only (no DOM); every carrier is injectable for
 * the battery and for G98. Battery: tests/road/*. G98: tools/r147-e2e.mjs.
 */

import {
  buildCompactOffer, parseOfferEnvelope, wordsTokenToEnvelope, verifyEnvelopeSignature,
  b64urlDecode, compactText, sealedNonceOf, ROAD_LEGACY_NEXT_STEP,
} from './offer.js'
import { classifyEnvelopeText, routeEnvelope, ENVELOPE_KINDS } from './envelope.js'
import { createDialer, ROAD_STATES } from './dial.js'
import { sendConfirm, waitConfirm, CONFIRM_WATCHDOG_MS } from './confirm.js'
import { pumpSend, createReceiver, PUMP_CHUNK_BYTES, pumpError, RESUME_WINDOW_MS } from './pump.js'
import { landingVerdict, verdictCodeFor, resumeRecordState } from './landing.js'
import { buildSignalEnvelope, BRIDGE_SIGNAL_TTL_MS } from '../bridge/signal.js'
import { ProgressiveSha256 } from '../bridge/channel.js'
import { demotionAnnouncement } from '../bridge/relay-fallback.js'

function door(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra }).then(
    (r) => r || { ok: false, code: 'DOOR_EMPTY' },
    (e) => ({ ok: false, code: 'DOOR_ERROR', userMessage: String((e && e.message) || e).slice(0, 160) }),
  )
}

function randomHex(n = 16) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/* ── the live session registry (one per page; cancel-safe) ───────────────── */

let _live = null // the sender's or receiver's active session
const _incoming = new Map() // sessionId → the receiver's incoming session

/** The STUN door — WIRED (the R146 dead-door cure; the list rides storage). */
async function iceServersConfig() {
  try {
    const got = await chrome.storage.local.get('ucrypt:stun')
    const list = got && got['ucrypt:stun']
    if (Array.isArray(list) && list.length && list.every((u) => typeof u === 'string' && /^stuns?:/.test(u))) {
      return list.map((u) => ({ urls: u }))
    }
  } catch { /* the default stands */ }
  return [{ urls: 'stun:stun.l.google.com:19302' }]
}

function gatheredComplete(pc, { capMs = 4000 } = {}) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve(true)
    let done = false
    const finish = (v) => { if (!done) { done = true; resolve(v) } }
    pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') finish(true) })
    setTimeout(() => finish(false), capMs)
  })
}

/** The signal-lane adapter (the field wiring — the doors). */
export function signalLaneFor({ myMemberId = '', peerMemberId = '' } = {}) {
  return {
    myMemberId,
    peerMemberId,
    put: ({ toMemberId, envelope }) => door('BRIDGE_SIGNAL_PUT', { toMemberId, envelope }),
    poll: async () => {
      const r = await door('BRIDGE_SIGNAL_POLL')
      return r && r.ok ? { signals: r.signals || [] } : { signals: [] }
    },
    consume: ({ sessionId, signalId }) => door('BRIDGE_SIGNAL_CONSUME', { sessionId, signalId }),
  }
}

/** The envelope builder bound to the lane's doors. */
export function envelopeBuilder() {
  return async ({ kind, sessionId, payload, ttlMs = BRIDGE_SIGNAL_TTL_MS }) =>
    buildSignalEnvelope({ kind, sessionId, payload, ttlMs })
}

/* ── THE SENDER'S FLOW ───────────────────────────────────────────────────── */

/**
 * The full send over the road. Every ending is typed; nothing waits in
 * silence (LAW #68 governs every state below).
 *
 * @param {object} args
 *   file, peerMemberId, peerName, cloudConnected
 *   onLine(t), onProgress(p) — the journey's beat writers
 *   qrDoor — { show({ qrText, words }), hide() } — the ONE-SPOT door (the
 *            compact offer's QR + the words token AT the beat)
 *   codePanel — { show(code, {role}), hide() } — the human gate at the beat
 *   badge — the road badge machine (the journey's writer)
 * Returns the typed result:
 *   { ok:true, road, receipt } — Delivered — verified
 *   { ok:false, code, nextStep } — every failure names its next step
 */
export async function roadSend({
  file, peerMemberId, peerName = '', cloudConnected = false,
  onLine = () => {}, onProgress = () => {},
  qrDoor = { show: () => {}, hide: () => {} },
  codePanel = { show: () => {}, hide: () => {} },
  badge = null,
} = {}) {
  if (!file) return { ok: false, code: 'SHAPE', nextStep: 'pick a file first' }
  await cancelSession()

  /* pass 1 — the fingerprint (the file never sits fully in memory) */
  const psha = new ProgressiveSha256()
  const READ = 1024 * 1024
  for (let off = 0; off < file.size; off += READ) {
    const buf = new Uint8Array(await file.slice(off, Math.min(off + READ, file.size)).arrayBuffer())
    psha.update(buf)
  }
  const sha256Hex = psha.hex()

  const sessionId = randomHex(12)
  const nonceA = randomHex(16)

  /* the pc + the offer (STUN WIRED — the dead door's cure) */
  let pc = null
  let offerSdp = ''
  let hostHint = ''
  const iceServers = await iceServersConfig()
  const makePc = () => new RTCPeerConnection({ iceServers })
  pc = makePc()
  const dc = pc.createDataChannel('ucrypt-road', { ordered: true })
  const offer = await pc.createOffer()
  await pc.setLocalDescription(offer)
  await gatheredComplete(pc)
  offerSdp = pc.localDescription.sdp

  /* the chain facts (the fingerprint rides the offer; the id addresses the answer) */
  let selfId = ''
  let chainFpHex = ''
  try {
    const ros = await door('BRIDGE_ROSTER')
    if (ros.ok && ros.self) selfId = ros.self.memberId
  } catch { /* the door never blocks the offer */ }
  try {
    const fp = await door('BRIDGE_FINGERPRINT')
    if (fp && fp.ok && fp.fingerprintHex) chainFpHex = fp.fingerprintHex
  } catch { /* the fingerprint is an optimization, not a gate */ }

  /* THE COMPACT OFFER (§5.2 — one QR, one words blob; no frame chunker).
     R148 §4 — the offer's seal NOW CARRIES nonceA (the K-1a cure): both
     screens derive the SAME safety code from the chain root + BOTH nonces. */
  const built = await buildCompactOffer({
    sessionId, chainFpHex, sdp: offerSdp,
    role: 'sender', nonce: nonceA,
    sealFn: async (payload) => door('BRIDGE_SEAL', { payload }),
  })
  if (!built || !built.words || !built.envelope) {
    // THE EMPTY-TOKEN STATE LAW (§4.4): a beat surface may never render
    // without its payload — the WHY + the action, never an empty box.
    return { ok: false, code: 'OFFER_EMPTY', nextStep: 'the handshake could not be armed — unlock the vault (the words are sealed with its key) and send again' }
  }
  hostHint = built.hostHint

  _live = { role: 'sender', sessionId, pc, dc, file, sha256Hex, badge, qrDoor, codePanel, timers: [], onLine, onProgress, nonceA, selfId, peerMemberId, peerName, cloudConnected, cancelled: false, answerEnvelope: null }

  if (badge) badge.to('choosing')
  onLine('Choosing the road…')

  /* the control exchange: the offer rides the relay signals (cloud up) */
  let answered = null
  const lane = signalLaneFor({ myMemberId: selfId, peerMemberId })
  const buildEnv = envelopeBuilder()
  const viaRelay = cloudConnected && !!peerMemberId
  if (viaRelay) {
    const env = await buildEnv({ kind: 'bridge-offer', sessionId, payload: { offer: built.full, senderMemberId: selfId, fileName: file.name, size: file.size } })
    const put = await lane.put({ toMemberId: peerMemberId, envelope: env })
    if (!put.ok) {
      onLine('The cloud would not carry the handshake — the words handshake still works at the beat.')
    } else {
      onLine(`Calling ${peerName} directly… (they may need to confirm on their screen)`)
      answered = await pollForRoadAnswer({ sessionId, lane, deadlineAt: Date.now() + 25 * 1000, liveRef: () => _live })
    }
  }
  if (!answered) {
    /* THE CLOUD-FREE DOOR — the compact offer renders AT THE BEAT (the
       one-spot law): ONE QR frame + the words token + the reply box. */
    qrDoor.show({ qrText: compactText(built.envelope), words: built.words })
    onLine('Show this QR (or send the words) to the other device — they answer with theirs.')
    answered = await pollForRoadAnswer({ sessionId, lane, deadlineAt: null, liveRef: () => _live, alsoHuman: true })
  }
  if (qrDoor.hide) qrDoor.hide()

  if (!answered || answered.cancelled || !_live) {
    if (_live) await cancelSession()
    return { ok: false, code: 'CANCELLED', nextStep: 'the transfer was cancelled — nothing moved' }
  }
  if (!answered.ok) {
    await cancelSession()
    return { ok: false, code: answered.code || 'NO_ANSWER', nextStep: answered.nextStep || 'the other device did not answer in time — check both devices are online, then send again' }
  }

  /* the answer arrived — the two roads hunt for real */
  const { sdp: answerSdp, nonceB, answerEnvelope } = answered
  _live.nonceB = nonceB
  const directAdapter = {
    connect: async () => {
      await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp })
      /* R149 — the field-shaped lab's find (LAW #77): the proof may not fire
         until the channel is OPEN — send() on a 'connecting' channel throws
         and the check dies before the ICE finishes (the unit mocks' DC was
         always instantly-open; the real ICE needs its 1–2 s). The adapter
         awaits the open within the dial budget. */
      if (dc && dc.readyState !== 'open') {
        await new Promise((resolve) => {
          const t0 = Date.now()
          const tick = () => {
            if (dc.readyState === 'open' || pc.connectionState === 'failed' || Date.now() - t0 > 8000) resolve()
            else setTimeout(tick, 100)
          }
          tick()
        })
      }
      return { dc }
    },
    close: async () => { try { pc.close() } catch { /* gone */ } },
  }
  const dialer = createDialer({ direct: directAdapter, relay: lane, log: onLine })
  _live.dialer = dialer
  const road = await dialer.establish({ role: 'sender', sessionId, offerSdp, answerSdp, toMemberId: peerMemberId })
  if (!road.ok) {
    await cancelSession()
    return { ok: false, code: road.code || 'ROAD_UNAVAILABLE', nextStep: road.nextStep }
  }
  _live.road = road.road
  _live.establishedDc = road.dc || null
  if (badge) badge.to(road.road === 'direct' ? 'direct' : 'relay')

  /* THE HUMAN GATE — the code derives on BOTH screens from the chain root
     + both nonces (the field-proven seam, C2 — untouched). */
  const codeR = await door('BRIDGE_CODE', { nonceA, nonceB })
  if (!codeR.ok) {
    await cancelSession()
    return { ok: false, code: 'CODE_SEAL', nextStep: 'the safety code could not be derived — unlock the vault and send again' }
  }
  _live.code = codeR.code
  codePanel.show(codeR.code, { role: 'sender' })
  onLine('Compare the 6-digit code on both screens — the file moves when they confirm.')

  /* THE CONFIRM — both carriers, the 120 s watchdog (the J-1 cure) */
  onLine('Waiting for the code confirmation on the other device…')
  const confirm = await waitConfirm({ dc: road.road === 'direct' ? road.dc : null, lane, sessionId, timeoutMs: CONFIRM_WATCHDOG_MS })
  if (!_live) return { ok: false, code: 'CANCELLED', nextStep: 'the transfer was cancelled — nothing moved' }
  if (!confirm.ok) {
    await cancelSession()
    return { ok: false, code: confirm.code || 'CONFIRM_TIMEOUT', nextStep: confirm.nextStep }
  }
  codePanel.hide()
  onLine(confirm.matched ? 'The codes match — the bytes may move.' : 'The codes did not match — nothing moved.')

  /* THE PUMP — the bytes move, or the typed verdict names the next step */
  const pump = await pumpSend({
    road: road.road,
    dc: road.dc || null,
    lane: { ...lane, put: lane.put, poll: lane.poll, consume: lane.consume, peerMemberId },
    sessionId,
    fileName: file.name,
    size: file.size,
    sha256Hex,
    read: async (offset, length) => new Uint8Array(await file.slice(offset, offset + length).arrayBuffer()),
    buildEnvelope: buildEnv,
    storage: chrome.storage.local,
    onProgress,
  })
  if (!pump.ok) {
    await cancelSession()
    return { ok: false, code: pump.code || 'SEND_FAILED', nextStep: pump.nextStep }
  }

  /* THE PROOF BEAT — Delivered, with the hash in plain words */
  try { await door('BRIDGE_SESSION_CLOSE', { sessionId }) } catch { /* swept */ }
  _live = null
  return { ok: true, road: road.road, receipt: pump.receipt, journal: pump.journal }
}

/** The answer poll: the relay lane's bridge-answer envelope, or the human
 * reply (the words/QR pasted at the beat). deadlineAt=null → human-paced
 * with the honest 10-minute walk-away bound. */
async function pollForRoadAnswer({ sessionId, lane, deadlineAt, liveRef, alsoHuman = false }) {
  const startedAt = Date.now()
  while (true) {
    if (deadlineAt != null && Date.now() > deadlineAt) return { ok: false, code: 'NO_ANSWER' }
    if (deadlineAt == null && Date.now() - startedAt > 10 * 60 * 1000) return { ok: false, code: 'NO_ANSWER' }
    const live = liveRef()
    if (!live || live.cancelled) return { cancelled: true }
    if (live.answerEnvelope) {
      const a = live.answerEnvelope
      live.answerEnvelope = null
      return { ok: true, ...a }
    }
    const poll = await lane.poll()
    for (const s of poll.signals || []) {
      if (s.envelope && s.envelope.sessionId === sessionId && s.envelope.kind === 'bridge-answer') {
        try {
          await lane.consume({ sessionId, signalId: s.signalId })
          const p = s.envelope.payload || {}
          if (p.answer) {
            const opened = parseOfferEnvelope(p.answer)
            const sealed = opened.envelope.d
            const openR = await door('BRIDGE_OPEN', { sealedB64: sealed })
            if (openR.ok) {
              /* R149 — the nonce read is SEALEDNONCEOF: the modern seal
                 carries the receiver's nonce under `nonce` (the K-1a wire);
                 the old `payload.nonceB` read lost it (the sender's code
                 gate then starved — found-and-fixed this round). */
              return { ok: true, sdp: openR.payload.sdp, nonceB: sealedNonceOf(openR.payload), answerEnvelope: p.answer }
            }
          }
        } catch { /* a garbled answer never breaks the wait */ }
      }
    }
    await new Promise((r) => setTimeout(r, deadlineAt == null ? 500 : 1200))
  }
}

/** §5.2 — THE LEGACY-ENVELOPE LAW (R149): the SEAL-OPEN verdict (pure).
 * The parser reads the version field first (offer.js); THIS layer reads the
 * nonce presence — the version marker inside the seal. A payload without it
 * is an older build's envelope: the machine answers with the TYPED verdict,
 * never a crash and never a placeholder. Returns null when the seal is
 * modern and the flow continues. */
export function sealOpenVerdict(openR) {
  if (!openR || !openR.ok) {
    return { ok: false, code: 'SEAL', nextStep: (openR && openR.userMessage) || 'the handshake could not be opened — the sender can press Send again' }
  }
  if (!openR.payload || typeof openR.payload.nonce !== 'string' || !openR.payload.nonce) {
    return { ok: false, code: 'LEGACY_OFFER', typed: true, nextStep: ROAD_LEGACY_NEXT_STEP }
  }
  return null
}

/** THE UNIVERSAL DOOR (R148 §4.1 — LAW #72): the ONE router every words
 * surface feeds. Classifies the paste (OFFER/ANSWER/JOIN/CORRUPT) and routes
 * it — the sender's live session completes the handshake; an OFFER pasted
 * anywhere else SPAWNS the receive flow; a mis-placed type answers with
 * instant typed guidance; a corrupt paste names what to re-copy. NO box
 * swallows; NO box is role-locked.
 * R149 C-5 (THE BIRTH AT THE BEAT — LAW #69 extended): `onWait` fires at the
 * spawn boundary, BEFORE the receive flow builds its answer — the surface
 * shows the explicit waiting state ("Building your reply words…") and THE
 * box stays EMPTY until the real words render. Both layers hold: this road
 * layer owns the sequencing; the page layer owns the waiting render. */
export async function receiveEnvelopeText(text, { onLine = () => {}, onWait = null, startReceive, selfId = '', codePanel = { show: () => {}, hide: () => {} }, badge = null } = {}) {
  const t = String(text || '').trim()
  const liveSession = () => (_live ? { role: _live.role } : { role: null })
  const openDoor = async ({ sealedB64 }) => door('BRIDGE_OPEN', { sealedB64 })
  const completeHandshake = async ({ opened }) => {
    if (!_live || _live.role !== 'sender') return { ok: false, why: 'no live sender session' }
    if (!opened || !opened.sdp) return { ok: false, why: 'the answer carries no road description' }
    /* §5.2 — the LEGACY_ANSWER class through the door: an older build's
       answer (no session nonce inside the seal) cannot derive the safety
       code — the typed verdict answers here, never a dead code gate. */
    if (!sealedNonceOf(opened)) return { ok: false, code: 'LEGACY_ANSWER', typed: true, userMessage: ROAD_LEGACY_NEXT_STEP }
    _live.answerEnvelope = { sdp: opened.sdp, nonceB: sealedNonceOf(opened) }
    return { ok: true }
  }
  const defaultSpawn = async (offerText) => {
    // the default receive spawn: the same flow the Arrivals card drives —
    // answer the offer, show the code, emit the answer words
    try {
      const r = await roadAnswerOffer({ offerText, onLine, selfId, codePanel, badge })
      return r
    } catch (e) {
      return { ok: false, code: 'RECEIVE_SPAWN', nextStep: String((e && e.message) || e).slice(0, 160) }
    }
  }
  /* the spawn boundary: the waiting-writer fires BEFORE the flow builds —
     whether the spawn is this module's default or the caller's injected one. */
  const spawnReceive = async (offerText) => {
    if (typeof onWait === 'function') {
      try { onWait({ phase: 'building' }) } catch { /* the waiting render never blocks the spawn */ }
    }
    return (startReceive || defaultSpawn)(offerText)
  }
  return routeEnvelope(t, { openDoor, liveSession, startReceive: spawnReceive, completeHandshake })
}

/**
 * The sender's reply completion (the ANSWER route's executor — the universal
 * door calls this; the legacy direct call stays for the battery's shape rows).
 */
export async function submitReplyBundle(text) {
  if (!_live || _live.role !== 'sender') return { ok: false, userMessage: 'no live sender session on this page — paste the OFFER words instead and the receive flow will start' }
  const t = String(text || '').trim()
  if (!t) return { ok: false, userMessage: 'the reply is empty — paste their words or read their QR image' }
  let parsed
  try {
    parsed = wordsTokenToEnvelope(t)
  } catch (e) {
    // maybe the raw compact JSON (the QR's text form)
    try { parsed = parseOfferEnvelope(t) } catch { return { ok: false, userMessage: (e && e.message) || 'the reply does not decode' } }
  }
  if (!parsed.complete || !parsed.envelope.d) return { ok: false, userMessage: 'this is the compact form — the words token carries the answer' }
  const openR = await door('BRIDGE_OPEN', { sealedB64: parsed.envelope.d })
  if (!openR.ok) return { ok: false, userMessage: openR.userMessage || 'the reply could not be opened' }
  if (!openR.payload || openR.payload.role !== 'receiver' || !openR.payload.sdp) {
    // R148 — the type law: an OFFER is NOT an answer (the K-1c disease dies).
    if (openR.payload && openR.payload.role) {
      return { ok: false, userMessage: 'these are OFFER words, not a reply — the receive flow can answer them here: press "Receive a file" and paste them' }
    }
    /* §5.2 — the LEGACY_ANSWER class (R149): the reply carries no session
       nonce inside its seal (an older build made it) — the typed verdict
       with the CONTRACT wording answers; nothing is derived, nothing dies
       silently, nothing is lost. */
    if (!openR.payload || typeof openR.payload.nonce !== 'string' || !openR.payload.nonce) {
      return { ok: false, code: 'LEGACY_ANSWER', typed: true, userMessage: ROAD_LEGACY_NEXT_STEP }
    }
  }
  _live.answerEnvelope = { sdp: openR.payload.sdp, nonceB: sealedNonceOf(openR.payload) }
  return { ok: true }
}

/* ── THE RECEIVER'S FLOW ─────────────────────────────────────────────────── */

/**
 * Answer an incoming road offer (from a relay signal or an imported bundle).
 * The consent law: the human gate is the code compare (Match/Mismatch) —
 * zero payload bytes move before the match.
 */
export async function roadAnswerOffer({ offerText, fromName = '', onLine = () => {}, onProgress = () => {}, codePanel = { show: () => {}, hide: () => {} }, badge = null, selfId = '', peerMemberId = '' } = {}) {
  /* R149 C-5 (the A5 repro's root cause, found by the FIELD harness): the
     words token IS the owner's paste form — the receive spawn's first hop
     used to JSON.parse it directly (the words token is base32, not JSON) and
     the birth died as "the offer envelope is not readable". The parse now
     accepts BOTH forms: the raw JSON envelope AND the words token (the same
     dual-form discipline submitReplyBundle has always had). */
  let parsed
  const raw = String(offerText || '').trim()
  try {
    parsed = parseOfferEnvelope(raw)
  } catch (tokenErr) {
    parsed = wordsTokenToEnvelope(raw) /* throws the typed SHAPE verdict on a genuinely unreadable paste */
  }
  if (!parsed.complete || !parsed.envelope.d) {
    return { ok: false, code: 'INCOMPLETE_OFFER', nextStep: 'this is the compact form — ask the sender for the words token (it carries the handshake)' }
  }
  await cancelSession()
  const openR = await door('BRIDGE_OPEN', { sealedB64: parsed.envelope.d })
  /* §5.2 — THE LEGACY-ENVELOPE LAW: the seal-open verdict runs BEFORE the
     role/shape checks — an older build's envelope (no nonce in the seal)
     answers with its own typed class, not with a misleading SHAPE. */
  const legacy = sealOpenVerdict(openR)
  if (legacy) return legacy
  const { sdp: offerSdp, sessionId, role } = openR.payload
  if (role !== 'sender' || !offerSdp) return { ok: false, code: 'SHAPE', nextStep: 'this is not a sender handshake' }

  const nonceB = randomHex(16)
  const iceServers = await iceServersConfig()
  const pc = new RTCPeerConnection({ iceServers })
  let dc = null
  pc.ondatachannel = (ev) => {
    dc = ev.channel
    // THE ROAD PROOF'S ECHO — the sender's dialer pings; we answer (the
    // establishment proof crosses BOTH ways, each side proving its own leg)
    ev.channel.addEventListener('message', (m) => {
      try {
        const j = JSON.parse(typeof m.data === 'string' ? m.data : '')
        if (j && j.t === 'road-ping') ev.channel.send(JSON.stringify({ t: 'road-pong', n: j.n }))
      } catch { /* binary frames flow here too */ }
    })
  }
  await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp })
  const answer = await pc.createAnswer()
  await pc.setLocalDescription(answer)
  await gatheredComplete(pc)
  const answerSdp = pc.localDescription.sdp

  /* R148 §4 — THE ANSWER SEALS ITS OWN NONCE (the K-1a cure): the sender
     derives the SAME code from nonceA (inside the offer's seal) + nonceB
     (inside THIS answer's seal). role:'receiver' makes the envelope's type
     self-describing — the universal door routes by it (LAW #72). */
  const sealFn = async (payload) => door('BRIDGE_SEAL', { payload })
  const answerBuilt = await buildCompactOffer({ sessionId, sdp: answerSdp, sealFn, role: 'receiver', nonce: nonceB })
  const lane = signalLaneFor({ myMemberId: selfId, peerMemberId: peerMemberId || openR.payload.senderMemberId || '' })
  const buildEnv = envelopeBuilder()
  _live = {
    role: 'receiver', sessionId, pc, dcRef: () => dc, badge, codePanel, onLine, onProgress,
    nonceB, cancelled: false, fromName, lane, buildEnv, selfId, peerMemberId: lane.peerMemberId,
    /* R149 — nonceA reads SEALEDNONCEOF: the offer's seal carries the
       sender's nonce under `nonce` (the K-1a wire); the old `payload.nonceA`
       read starved the receiver's code derivation (found-and-fixed). */
    nonceA: sealedNonceOf(openR.payload), timers: [], receiverHolder: { receiver: null, meta: null, started: false },
  }
  _incoming.set(sessionId, _live)
  if (badge) { try { badge.to('choosing') } catch { /* already choosing */ } }

  /* the answer rides back — addressed by the sender's member id (the sealed
     payload's routing truth), the ack rides right behind it (the dialer's
     relay proof on the sender's side) */
  if (lane.peerMemberId) {
    const env = await buildEnv({ kind: 'bridge-answer', sessionId, payload: { answer: answerBuilt.full } })
    const put = await lane.put({ toMemberId: lane.peerMemberId, envelope: env })
    if (put.ok) {
      const ack = await buildEnv({ kind: 'bridge-ack', sessionId, payload: { bytes: 0, ready: true } })
      await lane.put({ toMemberId: lane.peerMemberId, envelope: ack }).catch(() => {})
      onLine('The answer is on its way — the connection completes on their screen.')
    } else {
      onLine('The cloud would not carry the answer — read the sender\u2019s words at the beat instead.')
    }
  }

  /* THE CODE — the same derivation, the same gate. R148: the derivation now
     RECEIVES the sender's nonceA (it rode the offer's seal — the K-1a cure). */
  const codeR = await door('BRIDGE_CODE', { nonceA: _live.nonceA, nonceB })
  const code = codeR.ok ? codeR.code : ''
  _live.code = code
  if (code) codePanel.show(code, { role: 'receiver' })
  /* R148 §4.2 — THE ANSWER-WORDS SURFACE'S PAYLOAD (the K-1b cure): the
     answer token + its QR form return to the caller — the journey renders
     them AT the receiver's beat with "Copy words" + the send-back line. */
  return { ok: true, sessionId, code, answerFull: answerBuilt.full, answerWords: answerBuilt.words, answerCompact: compactText(answerBuilt.envelope) }
}

/** The receiver's verdict (the human gate). Rides EVERY carrier; typed. */
export async function confirmCode(matched) {
  const live = _live
  if (!live || live.role !== 'receiver') return { ok: false }
  const r = await sendConfirm({
    matched,
    dc: live.dcRef ? live.dcRef() : null,
    lane: live.peerMemberId ? { ...live.lane, peerMemberId: live.peerMemberId } : null,
    sessionId: live.sessionId,
    code: live.code || '',
    buildEnvelope: live.buildEnv,
  })
  if (!matched) {
    // THE ABORT (the mismatch law): clean cancel, zero payload bytes moved
    await cancelSession()
    return { ok: true, matched: false, via: r.via, failures: r.failures }
  }
  return { ok: true, matched: true, via: r.via, failures: r.failures }
}

/**
 * THE RECEIVE ACTIVATION — the journey calls this after the receiver's
 * match click. BOTH doors listen (the sender picks the road; the receiver
 * receives on whichever delivers — the honest dual-listen):
 *   direct — the DataChannel's header/chunks/end frames (the pump's road 1)
 *   relay  — the bridge-chunk/bridge-ack/bridge-receipt loop (the pump's road 2)
 * R150 §5.3 — THE ACCEPT DOOR (Cure C): the promise "Nothing is received
 *   without your explicit Accept" is MECHANICS now — the header (or the first
 *   bridge-chunk) fires onIncoming BEFORE the first byte is pushed; the bytes
 *   hold (direct: in RAM; relay: in the lane) until answerIncoming({accept:true})
 *   flushes them into the consented basket — no second prompt. Decline saves
 *   nothing and tells the sender (the typed declined frame/envelope).
 * R150 §5.1 (Cure A-e): the 100%-WITHOUT-VERDICT STATE IS UNREPRESENTABLE —
 *   every failed landing resolves through onVerdict (typed) + onLine, and the
 *   watchdog (Cure B, the journey's 15 s budget) bounds every stall.
 */
export async function activateReceive({ onLine = () => {}, onProgress = () => {}, onIncoming = null, onVerdict = null, landing } = {}) {
  const live = _live
  if (!live || live.role !== 'receiver') return { ok: false, code: 'NO_SESSION' }
  live.received = { ok: false }
  live.onVerdict = onVerdict
  /* the Accept-gate state (Cure C) — the holder is shared by BOTH doors */
  Object.assign(live.receiverHolder, {
    accepted: false, declined: false, acceptGateShown: false,
    pending: [], pendingBytes: 0, endSeen: false,
  })
  const fireVerdict = (v) => {
    try { if (typeof onVerdict === 'function') onVerdict(v) } catch { /* the render never blocks the road */ }
  }
  const fireIncoming = (meta) => {
    const h = live.receiverHolder
    if (h.acceptGateShown) return
    h.acceptGateShown = true
    try { if (typeof onIncoming === 'function') onIncoming(meta) } catch { /* the render never blocks the road */ }
  }

  const ensureReceiver = (meta) => {
    const h = live.receiverHolder
    if (!h.receiver) {
      h.receiver = createReceiver({
        fileName: meta.fileName || 'received-file', size: Number(meta.size) || 0,
        sha256Hex: meta.sha256 || '', storage: chrome.storage.local, sessionId: live.sessionId,
      })
      h.meta = meta
      h.landing = landing
    }
    return h.receiver
  }

  /* DOOR 1 — the direct channel (when it opens at all) */
  const wireDc = (dc) => {
    if (!dc) return
    let assemblerReady = false
    dc.addEventListener('message', async (ev) => {
      try {
        if (typeof ev.data === 'string') {
          const m = JSON.parse(ev.data)
          if (m.t === 'header') {
            const h = live.receiverHolder
            const meta = { fileName: m.header.fileName, size: m.header.size, sha256: m.header.sha256 }
            const first = !h.meta
            ensureReceiver(meta)
            /* THE ACCEPT DOOR fires at the receive flow's OPEN (the header) —
               the human sees name + size + source BEFORE the first byte. */
            if (first) fireIncoming({ fileName: meta.fileName, size: Number(meta.size) || 0, from: live.fromName || '' })
            if (m.header.resumeFrom > 0) {
              /* R150 §5.4 — THE RESUME HONORING: the receiver owns the truth.
                 Its assembly is fresh (the parts live in RAM only — a closed
                 page keeps nothing), so it answers resume-ack {from: 0}; a
                 basket older than the pump's 10-minute window is EXPIRED —
                 typed, and the stale watermark is removed (nothing partial
                 is kept silently). */
              let expired = false
              try {
                const key = `ucrypt:road-resume:${live.sessionId}`
                const got = await chrome.storage.local.get(key)
                const rec = got && got[key]
                const st = resumeRecordState(rec, Date.now(), RESUME_WINDOW_MS)
                if (st.present && st.expired) { expired = true; await chrome.storage.local.remove(key) }
              } catch { /* best effort — the honest from:0 answer stands */ }
              try { dc.send(JSON.stringify({ t: 'resume-ack', from: 0, expired })) } catch { /* the road is gone */ }
              if (expired) fireVerdict({ ok: false, code: 'EXPIRED' })
              else if (first) onLine('The interrupted transfer resumes from zero — the partial bytes were not kept silently.')
              return // the corrected header re-declares the transfer
            }
            onLine(`Receiving ${m.header.fileName} — the codes matched, the bytes may move.`)
          } else if (m.t === 'end' && assemblerReady) {
            const h = live.receiverHolder
            if (!h.accepted) {
              /* the Accept gate owns the landing — the end waits behind it */
              h.endSeen = true
              return
            }
            if (h.receiver.done && live.received && live.received.ok) {
              // the relay road landed first (the honest dual-listen) — the
              // direct road just echoes the sealed receipt
              try { dc.send(JSON.stringify({ t: 'sealed', ok: true, sha256: live.received.sha256 || '' })) } catch { /* gone */ }
              return
            }
            const land = await h.receiver.verifyAndLand({ landing: h.landing })
            dc.send(JSON.stringify({ t: 'sealed', ok: !!land.ok, sha256: land.sha256 || '' }))
            if (land.ok) {
              onLine(`Received ✓ — hash verified · ${h.meta.fileName}`)
              live.received = { ok: true, sha256: land.sha256 }
              fireVerdict({ ok: true, code: 'ARRIVED', fileName: h.meta.fileName, size: Number(h.meta.size) || 0, sha256: land.sha256 })
            } else {
              fireVerdict(land)
              onLine(land.nextStep || 'the copy arrived damaged — nothing was saved')
            }
          } else if (m.t === 'ack') { /* the sender's pump owns these */ }
        } else {
          const h = live.receiverHolder
          if (h.receiver && !h.receiver.done) {
            const chunk = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new Uint8Array(ev.data)
            if (!h.accepted) {
              /* THE ACCEPT DOOR holds the bytes in RAM — nothing is pushed,
                 nothing is acked, nothing is received until the human accepts
                 (the prompt's budget is the journey's watchdog — Cure B). */
              h.pending.push(chunk)
              h.pendingBytes += chunk.length
              if (h.pendingBytes > 160 * 1024 * 1024) {
                fireVerdict({ ok: false, code: 'AWAITING_FINAL_ACK' }) // the honest bound — the sender's own watchdog types its side
              }
              return
            }
            h.receiver.push(chunk)
            onProgress({ phase: 'receiving', received: h.receiver.received, size: h.meta.size, percent: h.meta.size ? Math.min(100, Math.round((h.receiver.received / h.meta.size) * 100)) : 0, speedLine: '', etaLine: '' })
            dc.send(h.receiver.ackFrame({}))
          }
        }
      } catch (e) {
        onLine(String((e && e.message) || e).slice(0, 160))
      }
    })
  }
  const dc = live.dcRef ? live.dcRef() : null
  if (dc) wireDc(dc)
  else if (live.pc) {
    // the channel may still be negotiating — wire on arrival
    const prev = live.pc.ondatachannel
    live.pc.ondatachannel = (ev) => {
      if (typeof prev === 'function') prev.call(live.pc, ev)
      wireDc(ev.channel)
    }
  }

  /* DOOR 2 — the relay loop (runs alongside; the done flag retires it) */
  const relayLoop = (async () => {
    const holder = live.receiverHolder
    // wait for the first chunk to learn the metadata
    while (!holder.receiver && !live.cancelled) {
      try {
        const poll = await live.lane.poll()
        let found = null
        for (const s of (poll.signals || [])) {
          if (s.envelope && s.envelope.sessionId === live.sessionId && s.envelope.kind === 'bridge-chunk') {
            found = s.envelope.payload
            break
          }
        }
        if (found) {
          ensureReceiver({ fileName: found.fileName, size: found.total || found.size, sha256: found.sha256 })
          fireIncoming({ fileName: found.fileName, size: Number(found.total || found.size) || 0, from: live.fromName || '' })
          break
        }
      } catch { /* the deadline owns the exit */ }
      await new Promise((r) => setTimeout(r, 1000))
    }
    if (!holder.receiver) return
    /* THE ACCEPT DOOR (relay): the bytes hold IN THE LANE (not consumed) —
       the sender's flow control sees the honest stall; the human decides. */
    while (!holder.accepted && !holder.declined && !live.cancelled) {
      await new Promise((r) => setTimeout(r, 250))
    }
    if (holder.declined || live.cancelled) return
    await runRelayReceive({
      session: { sessionId: live.sessionId, receiver: holder.receiver, lane: { ...live.lane, peerMemberId: live.peerMemberId }, buildEnv: live.buildEnv, sha256Hex: holder.meta.sha256, fileName: holder.meta.fileName, size: holder.meta.size, cancelled: () => live.cancelled },
      onLine,
      onProgress,
      landing: holder.landing,
    }).then((r) => {
      if (r && r.ok) {
        live.received = { ok: true, sha256: r.sha256 }
        fireVerdict({ ok: true, code: 'ARRIVED', fileName: holder.meta.fileName, size: Number(holder.meta.size) || 0, sha256: r.sha256 })
      } else {
        /* R150 §5.1 — Cure A-e: a failed landing is NEVER dropped silently
           again (the B2 disease): the typed verdict renders + the bar resolves. */
        const v = r || { ok: false, code: 'RECEIVE_TIMEOUT' }
        if (v.code === 'CANCELLED') return
        fireVerdict(v)
        onLine(landingVerdict(verdictCodeFor(v.code), v.userMessage || v.nextStep || '').line)
      }
    })
  })()
  live.timers.push(relayLoop)

  return { ok: true, via: dc ? 'direct+relay' : 'relay', sessionId: live.sessionId }
}

/* ── THE ACCEPT DOOR's answers (R150 §5.3 — the journey's gate buttons) ──── */

/**
 * Answer the incoming transfer's Accept gate. Accept: the held bytes flow
 * into the consented basket (no second prompt; the save follows the hash).
 * Decline: nothing saved, the sender TOLD (the typed declined frame on the
 * direct road; the bridge-receipt envelope with declined:true on the relay
 * — the pump's own vocabulary, read typed on the sender's side).
 */
export async function answerIncoming({ accept = false } = {}) {
  const live = _live
  if (!live || live.role !== 'receiver') return { ok: false, code: 'NO_SESSION' }
  const h = live.receiverHolder
  if (!accept) {
    h.declined = true
    const dc = live.dcRef ? live.dcRef() : null
    if (dc) { try { dc.send(JSON.stringify({ t: 'declined', sessionId: live.sessionId })) } catch { /* the sender's watchdog types the silence */ } }
    if (live.lane && live.buildEnv && live.peerMemberId) {
      try {
        const env = await live.buildEnv({ kind: 'bridge-receipt', sessionId: live.sessionId, payload: { ok: false, declined: true } })
        await live.lane.put({ toMemberId: live.peerMemberId, envelope: env }).catch(() => {})
      } catch { /* the local verdict stands; the sender's watchdog types its side */ }
    }
    await cancelSession({ sweep: true })
    return { ok: true, declined: true }
  }
  h.accepted = true
  const dc = live.dcRef ? live.dcRef() : null
  for (const chunk of h.pending.splice(0)) {
    if (!h.receiver || h.receiver.done) break
    try { h.receiver.push(chunk) } catch { break /* the receiver is spent */ }
    if (typeof live.onProgress === 'function') {
      try {
        live.onProgress({ phase: 'receiving', received: h.receiver.received, size: (h.meta && h.meta.size) || 0, percent: h.meta && h.meta.size ? Math.min(100, Math.round((h.receiver.received / h.meta.size) * 100)) : 0, speedLine: '', etaLine: '' })
      } catch { /* the render never blocks the bytes */ }
    }
  }
  h.pendingBytes = 0
  if (dc && h.receiver) { try { dc.send(h.receiver.ackFrame({})) } catch { /* the direct road may be gone — the relay road continues */ } }
  if (h.endSeen && h.receiver && !h.receiver.done && typeof h.landing === 'function') {
    const land = await h.receiver.verifyAndLand({ landing: h.landing })
    if (dc) { try { dc.send(JSON.stringify({ t: 'sealed', ok: !!land.ok, sha256: land.sha256 || '' })) } catch { /* gone */ } }
    if (land.ok) {
      live.received = { ok: true, sha256: land.sha256 }
      if (typeof live.onLine === 'function') { try { live.onLine(`Received ✓ — hash verified · ${h.meta.fileName}`) } catch { /* gone */ } }
      if (typeof live.onVerdict === 'function') { try { live.onVerdict({ ok: true, code: 'ARRIVED', fileName: h.meta.fileName, size: Number(h.meta.size) || 0, sha256: land.sha256 }) } catch { /* gone */ } }
    } else if (typeof live.onVerdict === 'function') {
      try { live.onVerdict(land) } catch { /* gone */ }
    }
    return { ok: !!land.ok, landed: true, land }
  }
  return { ok: true, accepted: true }
}

/** The watchdog's ONE-button re-request: re-send the receiver's cumulative
 * ack so the sender's flow control wakes (relay) / the DC ack re-fires
 * (direct). The nudge never lies — it re-states the true watermark. */
export async function reRequestIncoming() {
  const live = _live
  if (!live || live.role !== 'receiver') return { ok: false, code: 'NO_SESSION' }
  const r = live.receiverHolder.receiver
  if (!r) return { ok: false, code: 'NO_RECEIVER' }
  const dc = live.dcRef ? live.dcRef() : null
  if (dc) { try { dc.send(r.ackFrame({})) } catch { /* the direct road is gone */ } }
  if (live.lane && live.buildEnv && live.peerMemberId) {
    try {
      const ack = await live.buildEnv({ kind: 'bridge-ack', sessionId: live.sessionId, payload: { bytes: r.received, reRequest: true } })
      await live.lane.put({ toMemberId: live.peerMemberId, envelope: ack }).catch(() => {})
    } catch { /* the sender's own watchdog types its side */ }
  }
  return { ok: true, bytes: r.received }
}

/* ── the receiver's relay receive loop (the pump's road-2 side) ──────────── */

export async function runRelayReceive({ session, onLine = () => {}, onProgress = () => {}, landing, storage = chrome.storage.local, now = () => Date.now() } = {}) {
  const { sessionId, receiver, lane, buildEnv, sha256Hex, fileName, size } = session
  const deadline = now() + 10 * 60 * 1000
  const cancelled = () => (typeof session.cancelled === 'function' ? session.cancelled() : !!session.cancelled)
  let restartAsked = false
  while (now() < deadline && !receiver.done) {
    if (cancelled()) return { ok: false, code: 'CANCELLED' }
    try {
      const poll = await lane.poll()
      for (const s of (poll.signals || [])) {
        if (!s.envelope || s.envelope.sessionId !== sessionId) continue
        if (s.envelope.kind === 'bridge-chunk') {
          const p = s.envelope.payload || {}
          await lane.consume({ sessionId, signalId: s.signalId }).catch(() => {})
          /* R150 §5.4 — THE RESUME HONORING: a resumed sender (offset > 0)
             meeting a FRESH assembly (received === 0) can never verify — the
             head was not kept silently. The receiver answers THE RESTART:
             one ack {bytes: 0, restart: true}; the sender re-sends from zero
             and the tail it already sent is not pushed twice. */
          if (!restartAsked && p.offset != null && Number(p.offset) > 0 && receiver.received === 0) {
            restartAsked = true
            const rack = await buildEnv({ kind: 'bridge-ack', sessionId, payload: { bytes: 0, restart: true, from: 0 } })
            await lane.put({ toMemberId: lane.peerMemberId, envelope: rack }).catch(() => {})
            continue
          }
          if (restartAsked && !(p.offset != null && Number(p.offset) === 0) && receiver.received === 0) {
            continue // the tail re-arrives from zero — the held tail is not pushed twice
          }
          const bytes = b64urlDecode(p.dataB64 || '')
          if (p.offset != null && p.offset < receiver.received) {
            // the resume guard: an already-held chunk is acked, not stored
          } else {
            receiver.push(bytes)
            onProgress({ phase: 'receiving', received: receiver.received, size: p.total || size, percent: p.total ? Math.min(100, Math.round((receiver.received / p.total) * 100)) : 0, speedLine: '', etaLine: '' })
          }
          const ack = await buildEnv({ kind: 'bridge-ack', sessionId, payload: { bytes: receiver.received } })
          await lane.put({ toMemberId: lane.peerMemberId, envelope: ack }).catch(() => {})
          await receiver.watermark()
        } else if (s.envelope.kind === 'bridge-confirm') {
          // the sender's confirm also lands via the relay lane — the waitConfirm
          // on the sender's side consumes it; the receiver's own gate is human
          await lane.consume({ sessionId, signalId: s.signalId }).catch(() => {})
        }
      }
      if (receiver.received >= size && size > 0 && !receiver.done) {
        const land = await receiver.verifyAndLand({ landing })
        if (land.ok) {
          const receipt = await buildEnv({ kind: 'bridge-receipt', sessionId, payload: { ok: true, sha256: land.sha256 } })
          await lane.put({ toMemberId: lane.peerMemberId, envelope: receipt }).catch(() => {})
          onLine(`Received ✓ — hash verified · ${fileName}`)
          return { ok: true, sha256: land.sha256 }
        }
        const receipt = await buildEnv({ kind: 'bridge-receipt', sessionId, payload: { ok: false, sha256: land.sha256 || '' } })
        await lane.put({ toMemberId: lane.peerMemberId, envelope: receipt }).catch(() => {})
        return land
      }
    } catch { /* a dead tick never kills the session — the deadline owns it */ }
    await new Promise((r) => setTimeout(r, 5000)) // the active-session cadence (§5.3)
  }
  return { ok: false, code: 'RECEIVE_TIMEOUT', nextStep: 'the transfer stalled — the sender can send again; the watermark holds for 10 minutes' }
}

/* ── THE CANCEL LAW (G93 R9 — no orphans) ────────────────────────────────── */

export async function cancelSession({ sweep = true } = {}) {
  const live = _live
  _live = null
  if (live) {
    live.cancelled = true
    try { for (const t of live.timers || []) clearInterval(t) } catch { /* gone */ }
    try { if (live.dialer) await live.dialer.close() } catch { /* gone */ }
    try { if (live.pc) live.pc.close() } catch { /* gone */ }
    if (sweep && live.sessionId) {
      try { await door('BRIDGE_SESSION_CLOSE', { sessionId: live.sessionId }) } catch { /* best effort */ }
    }
  }
  for (const [id, inc] of _incoming) {
    inc.cancelled = true
    try { if (inc.pc) inc.pc.close() } catch { /* gone */ }
    _incoming.delete(id)
    if (sweep) { try { await door('BRIDGE_SESSION_CLOSE', { sessionId: id }) } catch { /* best effort */ } }
  }
  return { ok: true, cancelled: true }
}

/* ── the QR image door (the camera-less law — unchanged wire) ────────────── */

export async function importQrImage(file) {
  if (typeof globalThis.UCryptQrScan !== 'object') throw new Error('the QR reader is unavailable on this page')
  const r = await globalThis.UCryptQrScan.decodeFromBlob(file)
  if (!r || !r.ok || !r.text) throw new Error('no QR code found in the image')
  return String(r.text)
}

/** The receiver's words/QR entry (the arrivals card's handshake door). */
export async function startFromIncomingBundle(text, { onLine = () => {}, onProgress = () => {}, codePanel, badge, selfId = '' } = {}) {
  const t = String(text || '').trim()
  let parsed
  try { parsed = wordsTokenToEnvelope(t) } catch (e) {
    try { parsed = parseOfferEnvelope(t) } catch { return { ok: false, userMessage: (e && e.message) || 'the handshake does not decode' } }
  }
  let selfIdFinal = selfId
  if (!selfIdFinal) {
    try { const ros = await door('BRIDGE_ROSTER'); if (ros.ok && ros.self) selfIdFinal = ros.self.memberId } catch { /* best effort */ }
  }
  return roadAnswerOffer({ offerText: JSON.stringify(parsed.envelope), onLine, onProgress, codePanel, badge, selfId: selfIdFinal, peerMemberId: '' })
}

export { CONFIRM_WATCHDOG_MS, PUMP_CHUNK_BYTES, pumpError, verifyEnvelopeSignature, b64urlDecode, ROAD_STATES, demotionAnnouncement }
