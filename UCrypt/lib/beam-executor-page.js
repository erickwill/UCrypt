/**
 * S8.9 completion (R100) — THE BEAM EXECUTOR (page side).
 *
 * The platform fact stands (the MV3 service worker in this Chromium does NOT
 * expose RTCPeerConnection — measured through the product's own pipe, R99).
 * The completion the CEO ordered: any open UCrypt surface page (popup,
 * options, transfer page) registers as a BEAM EXECUTOR — a live page that
 * hosts the TRANSPORT ONLY. The sealed-record machinery, the digest
 * verification, and the adopt path stay entirely in the service worker.
 *
 * THE TRUST BOUNDARY (law 0.14 holds):
 *  - The executor touches ONLY transport metadata (SDP, ICE candidates) and
 *    SEALED frames (the per-chunk sealed envelopes the worker produces and
 *    consumes). No plaintext vault bytes, no keys, no credentials ever cross
 *    this line — the executor could be any page; it learns nothing.
 *  - The port name 'ucrypt:beam-executor' is the typed contract; the worker
 *    refuses every other name.
 *
 * Liveness (order §2.2): the port IS the liveness signal — the worker
 * unregisters on port disconnect (page closed / worker recycled); the page
 * re-connects after a short beat (self-heal across SW recycles); lock
 * withdraws the registration worker-side (the engine refuses executors while
 * locked — the executor only matters when the vault can build the envelope).
 */

const SESSIONS = new Map() // sessionId → { pc, channel, role }
let _port = null
let _reconnectTimer = null
let _pageName = 'page'

function post(msg) {
  try { if (_port) _port.postMessage(msg) } catch { /* the port died; the reconnect re-arms */ }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function gatherIce(pc, capMs = 2500) {
  if (pc.iceGatheringState === 'complete') return
  await new Promise((resolve) => {
    const done = () => { try { pc.removeEventListener('icegatheringstatechange', onChange) } catch { /* noop */ } ; resolve() }
    const onChange = () => { if (pc.iceGatheringState === 'complete') done() }
    try { pc.addEventListener('icegatheringstatechange', onChange) } catch { /* noop */ }
    setTimeout(done, capMs) // the beam's bounded gather — the SDP carries the hosts
  })
}

function wireChannel(sessionId, channel) {
  if (!channel) return
  channel.binaryType = 'arraybuffer'
  channel.onopen = () => post({ evt: 'rtc:open', sessionId })
  channel.onclose = () => post({ evt: 'rtc:close', sessionId })
  channel.onerror = () => post({ evt: 'rtc:error', sessionId })
  channel.onmessage = (ev) => {
    // The executor is a COURIER: the frame is forwarded verbatim — sealed
    // bytes the worker ingests (digest verify + adopt live there, never here).
    const frame = typeof ev.data === 'string' ? ev.data : null
    if (frame == null) return
    post({ evt: 'rtc:frame', sessionId, frame })
  }
}

async function handleOffer(msg) {
  const { reqId, sessionId } = msg
  try {
    if (typeof RTCPeerConnection === 'undefined') throw new Error('no_rtc_in_page')
    const pc = new RTCPeerConnection({ iceServers: [] }) // the standing owner order: NO relay
    const channel = pc.createDataChannel('ucrypt-xfer', { ordered: true })
    SESSIONS.set(sessionId, { pc, channel, role: 'offerer' })
    wireChannel(sessionId, channel)
    pc.onicecandidate = (e) => { if (e.candidate) post({ evt: 'rtc:candidate', sessionId, candidate: e.candidate.candidate }) }
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    await gatherIce(pc)
    post({ cmd: 'rtc:offer:done', reqId, ok: true, sdp: pc.localDescription.sdp })
  } catch (e) {
    post({ cmd: 'rtc:offer:done', reqId, ok: false, error: String((e && e.message) || e).slice(0, 80) })
  }
}

async function handleAccept(msg) {
  const { reqId, sessionId, sdp } = msg
  try {
    if (typeof RTCPeerConnection === 'undefined') throw new Error('no_rtc_in_page')
    const pc = new RTCPeerConnection({ iceServers: [] }) // NO relay — host candidates only
    SESSIONS.set(sessionId, { pc, channel: null, role: 'answerer' })
    pc.onicecandidate = (e) => { if (e.candidate) post({ evt: 'rtc:candidate', sessionId, candidate: e.candidate.candidate }) }
    pc.ondatachannel = (e) => {
      if (!e.channel || e.channel.label !== 'ucrypt-xfer') return // only the UCrypt channel
      const st = SESSIONS.get(sessionId)
      if (st) st.channel = e.channel
      wireChannel(sessionId, e.channel)
    }
    await pc.setRemoteDescription({ type: 'offer', sdp: String(sdp || '') })
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await gatherIce(pc)
    post({ cmd: 'rtc:accept:done', reqId, ok: true, sdp: pc.localDescription.sdp })
  } catch (e) {
    post({ cmd: 'rtc:accept:done', reqId, ok: false, error: String((e && e.message) || e).slice(0, 80) })
  }
}

async function handleSetRemote(msg) {
  const { reqId, sessionId, sdp } = msg
  try {
    const st = SESSIONS.get(sessionId)
    if (!st) throw new Error('no_session')
    await st.pc.setRemoteDescription({ type: 'answer', sdp: String(sdp || '') })
    post({ cmd: 'rtc:set-remote:done', reqId, ok: true })
  } catch (e) {
    post({ cmd: 'rtc:set-remote:done', reqId, ok: false, error: String((e && e.message) || e).slice(0, 80) })
  }
}

function handleAddIce(msg) {
  const { reqId, sessionId, candidate } = msg
  const st = SESSIONS.get(sessionId)
  if (!st) { post({ cmd: 'rtc:add-ice:done', reqId, ok: false, error: 'no_session' }); return }
  st.pc.addIceCandidate(candidate == null ? null : JSON.parse(candidate))
    .then(() => post({ cmd: 'rtc:add-ice:done', reqId, ok: true }))
    .catch((e) => post({ cmd: 'rtc:add-ice:done', reqId, ok: false, error: String((e && e.message) || e).slice(0, 80) }))
}

function handleSend(msg) {
  const { sessionId, seq, frame } = msg
  const st = SESSIONS.get(sessionId)
  if (!st || !st.channel || st.channel.readyState !== 'open') {
    post({ evt: 'rtc:sendfail', sessionId, seq, reason: 'channel_not_open' })
    return
  }
  try {
    st.channel.send(String(frame))
    post({ evt: 'rtc:sent', sessionId, seq })
  } catch (e) {
    post({ evt: 'rtc:sendfail', sessionId, seq, reason: String((e && e.message) || e).slice(0, 60) })
  }
}

function handleClose(msg) {
  const st = SESSIONS.get(msg && msg.sessionId)
  if (!st) return
  SESSIONS.delete(msg.sessionId)
  try { if (st.channel) st.channel.close() } catch { /* already closed */ }
  try { st.pc.close() } catch { /* already closed */ }
}

function onMessage(msg) {
  if (!msg || typeof msg !== 'object') return
  switch (msg.cmd) {
    case 'rtc:offer': handleOffer(msg).catch(() => {}); break
    case 'rtc:accept': handleAccept(msg).catch(() => {}); break
    case 'rtc:set-remote': handleSetRemote(msg).catch(() => {}); break
    case 'rtc:add-ice': handleAddIce(msg); break
    case 'rtc:send': handleSend(msg); break
    case 'rtc:close': handleClose(msg); break
    case 'rtc:hello': post({ evt: 'rtc:hello-ack', page: _pageName }); break
    default: break
  }
}

function connect() {
  try {
    _port = chrome.runtime.connect({ name: 'ucrypt:beam-executor' })
    _port.onMessage.addListener(onMessage)
    _port.onDisconnect.addListener(() => {
      _port = null
      // Self-heal across SW recycles: a live page re-connects after a beat.
      if (_reconnectTimer) clearTimeout(_reconnectTimer)
      _reconnectTimer = setTimeout(() => { connect() }, 2500)
    })
    post({ evt: 'rtc:executor-up', page: _pageName })
  } catch { _port = null }
}

/** Register THIS page as a beam executor. Idempotent; safe on every page. */
export function registerBeamExecutor(pageName) {
  _pageName = String(pageName || 'page').slice(0, 20)
  if (_port) return _port
  connect()
  // The page lifecycle: a closed page's port dies — the worker unregisters
  // (liveness, order §2.2). A hidden page stays a valid executor; only the
  // port's death ends it.
  return _port
}

/** The page is closing — drop the port cleanly (the typed unregister). */
export function withdrawBeamExecutor() {
  if (_reconnectTimer) clearTimeout(_reconnectTimer)
  for (const [sessionId, st] of [...SESSIONS.entries()]) {
    try { if (st.channel) st.channel.close() } catch { /* already closed */ }
    try { st.pc.close() } catch { /* already closed */ }
    SESSIONS.delete(sessionId)
  }
  try { if (_port) _port.disconnect() } catch { /* already dead */ }
  _port = null
}
