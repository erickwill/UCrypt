/**
 * UCrypt — R134 §2.D — LANE W: THE WEBRTC DIRECT ADAPTER (thin, guarded).
 *
 * The file bytes NEVER touch any server: SDP/ICE exchange rides the
 * encrypted mailbox (the cloud relays only the handshake ciphertext); the
 * data channel carries 16 KiB chunks with backpressure via bufferedAmountLow
 * (256 KiB threshold). PUBLIC STUN ONLY — NO TURN RELAY, EVER (no third-party
 * relay sees bytes; that is a UCrypt law of identity — grep-gated: no line
 * of code in this file may carry a TURN scheme).
 *
 * The adapter is deliberately thin: every DECISION lives in lanes.js /
 * session.js (pure, battery-pinned); this file only shapes the browser
 * objects. Every entry point guards `typeof RTCPeerConnection` so the
 * module imports cleanly in the battery (bun) and in any surface.
 */

import { CHUNK_SIZE, BACKPRESSURE_THRESHOLD, STUN_SERVERS, MAX_FILE_BYTES } from './lanes.js'

/** Honest capability probe (the caps advertisement uses this). */
export function webrtcSupported() {
  return typeof globalThis.RTCPeerConnection === 'function'
}

/** The ICE configuration — PUBLIC STUN ONLY, the law as a constant. */
export function iceConfig() {
  return { iceServers: STUN_SERVERS.map((u) => ({ urls: u })) }
}

/** The typed lane error. */
export function laneError(code, detail) {
  const e = new Error(`BEAM2_LANE_${code}: ${detail}`)
  e.code = `BEAM2_LANE_${code}`
  return e
}

/**
 * Create the sender-side peer channel. Resolves when the data channel is
 * OPEN; rejects with BEAM2_LANE_ICE_TIMEOUT if ICE does not connect within
 * the typed window (the caller then degrades to Lane C — typed, visible).
 * @param {(localDesc: RTCSessionDescription) => Promise<void>} onLocalDesc — the caller publishes it via the mailbox
 * @param {(remoteDesc: RTCSessionDescription) => Promise<void>} applyRemoteDesc — the caller feeds the peer's desc
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{pc:RTCPeerConnection, channel:RTCDataChannel, close:()=>void}>}
 */
export async function openSenderChannel(onLocalDesc, applyRemoteDesc, opts = {}) {
  if (!webrtcSupported()) throw laneError('UNSUPPORTED', 'RTCPeerConnection unavailable — Lane W cannot arm')
  const timeoutMs = Number(opts.timeoutMs) || 8000
  const pc = new RTCPeerConnection(iceConfig())
  const channel = pc.createDataChannel('ucrypt-beam2', { ordered: true })
  let closed = false
  const close = () => {
    if (closed) return
    closed = true
    try { channel.close() } catch { /* already closed */ }
    try { pc.close() } catch { /* already closed */ }
  }
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(laneError('ICE_TIMEOUT', `ICE did not connect within ${timeoutMs} ms — degrade to Lane C (typed, visible)`)), timeoutMs)
    channel.onopen = () => { clearTimeout(timer); resolve() }
    channel.onerror = () => { clearTimeout(timer); reject(laneError('CHANNEL', 'data channel error')) }
    pc.oniceconnectionstatechange = () => {
      if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
        clearTimeout(timer)
        reject(laneError('ICE_FAILED', `ICE ${pc.iceConnectionState} — degrade to Lane C (typed, visible)`))
      }
    }
  })
  const offer = await pc.createOffer()
  await pc.setLocalDescription(offer)
  await onLocalDesc(pc.localDescription)
  return { pc, channel, ready: ready.then(() => ({ pc, channel, close })), close }
}

/**
 * The chunked send loop over an OPEN data channel — backpressure via
 * bufferedAmountLow, 16 KiB chunks, byte-real progress callback.
 * @param {RTCDataChannel} channel
 * @param {Uint8Array} bytes
 * @param {(sent:number,total:number)=>void} [onProgress]
 */
export async function sendBytesOverChannel(channel, bytes, onProgress) {
  if (!channel || channel.readyState !== 'open') throw laneError('CHANNEL_CLOSED', 'send on a non-open channel')
  if (bytes.length > MAX_FILE_BYTES) throw laneError('OVER_CAP', 'file exceeds the uniform 20 MiB cap (one truth)')
  const total = bytes.length
  let sent = 0
  for (let off = 0; off < total; off += CHUNK_SIZE) {
    const end = Math.min(off + CHUNK_SIZE, total)
    const slice = bytes.subarray(off, end)
    if (channel.bufferedAmount > BACKPRESSURE_THRESHOLD) {
      await new Promise((resolve) => {
        const h = () => { channel.removeEventListener('bufferedamountlow', h); resolve() }
        channel.addEventListener('bufferedamountlow', h)
      })
    }
    channel.send(slice)
    sent = end
    if (typeof onProgress === 'function') onProgress(sent, total)
  }
  return sent
}

/**
 * The receiver-side byte collector — assembles ordered chunks, reports
 * byte-real progress, and hands the completed Uint8Array to the verifier.
 * @param {RTCDataChannel} channel
 * @param {{size:number, onProgress?:(received:number,total:number)=>void}} spec
 */
export async function collectBytesFromChannel(channel, spec) {
  const total = Number(spec && spec.size) || 0
  if (total > MAX_FILE_BYTES) throw laneError('OVER_CAP', 'declared size exceeds the uniform 20 MiB cap (one truth)')
  return new Promise((resolve, reject) => {
    const parts = []
    let received = 0
    channel.onmessage = (ev) => {
      const u8 = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new Uint8Array(ev.data.buffer || ev.data)
      parts.push(u8)
      received += u8.length
      if (typeof (spec && spec.onProgress) === 'function') spec.onProgress(received, total)
      if (received >= total) {
        const out = new Uint8Array(total)
        let off = 0
        for (const p of parts) { out.set(p, off); off += p.length }
        channel.onmessage = null
        resolve(out)
      }
    }
    channel.onerror = () => reject(laneError('CHANNEL', 'receive channel error'))
  })
}
