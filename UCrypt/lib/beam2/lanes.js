/**
 * UCrypt — R134 §2.D — LAW 0.55: LANE TRUTH ("three lanes, one truth").
 *
 *   Lane W — WebRTC direct: SDP/ICE exchange over the encrypted mailbox (the
 *   cloud relays only the handshake ciphertext; the file bytes never touch
 *   any server). Data channel, 16 KiB chunks, backpressure via
 *   bufferedAmountLow (256 KiB threshold). PUBLIC STUN ONLY — no TURN, ever
 *   (no third-party relay sees bytes; that is a UCrypt law of identity).
 *
 *   Lane C — cloud relay (the existing capability, rebuilt): ordered chunks
 *   through the mailbox with an ack window; resume from the last acked chunk
 *   on reconnect.
 *
 *   Lane M — manual signal: the copy/paste fallback, ONE surface (0.51),
 *   with 0.47 guidance and 0.48 typed states. Zero-cloud setups still
 *   transfer.
 *
 * SELECTION IS AUTOMATIC AND TRUTHFUL: try Lane W when both peers advertise
 * it; on ICE failure or timeout, degrade to Lane C and RENDER the lane truth
 * row — degradation is typed and visible, never silent. The 20 MB cap stays
 * uniform this round (one truth); raising it for the P2P lane is a CEO
 * option documented in the report, NOT implemented unilaterally.
 *
 * PURE — no DOM, no chrome.*, no RTCPeerConnection dependency at import time
 * (webrtc.js is the thin adapter; the battery pins this module's decisions).
 */

/** The lanes, named. */
export const LANES = { W: 'W', C: 'C', M: 'M' }
export const LANE_NAMES = { W: 'webrtc-direct', C: 'cloud-relay', M: 'manual-signal' }

/** Transport constants — one truth, uniform this round. */
export const CHUNK_SIZE = 16384 // 16 KiB chunks (Lane W data channel + Lane C frames)
export const BACKPRESSURE_THRESHOLD = 256 * 1024 // 256 KiB bufferedAmountLow threshold
export const MAX_FILE_BYTES = 20 * 1024 * 1024 // 20 MiB — the uniform cap (one truth)
export const ACK_WINDOW = 32 // the Lane C sliding ack window (chunks)
export const ICE_TIMEOUT_MS = 8000 // ICE failure/timeout → typed degradation to Lane C

/** PUBLIC STUN ONLY — no TURN, ever (the identity law; grep-gated). */
export const STUN_SERVERS = [
  'stun:stun.l.google.com:19302',
  'stun:stun1.l.google.com:19302',
]

/** The typed edge validator — 0 B through 20 MiB inclusive passes. */
export function validateFileEdge(size) {
  const n = Number(size)
  if (!Number.isInteger(n) || n < 0) return { ok: false, code: 'ERR_SIZE_INVALID', typed: 'typed rejection' }
  if (n === 0) return { ok: true, code: 'EDGE_0B' }
  if (n > MAX_FILE_BYTES) return { ok: false, code: 'ERR_OVER_CAP', typed: 'typed rejection' }
  return { ok: true, code: n === MAX_FILE_BYTES ? 'EDGE_20MIB_EXACT' : 'EDGE_OK' }
}

/**
 * LANE SELECTION (pure): given both peers' advertised caps, pick the lane.
 *   both advertise beam2 + webrtc  → W (reason 'both-advertise')
 *   both reachable via rendezvous  → C (reason 'rendezvous-only')
 *   otherwise                      → M (reason 'manual-fallback')
 * The legacy compat decision lives in protocol.negotiateCaps (this module is
 * lane-only); a legacy peer never reaches Lane W.
 */
export function selectLane(mine, theirs) {
  const m = mine || {}
  const t = theirs || {}
  const bothBeam2 = !!(m.beam2 && t.beam2)
  const bothWebRtc = !!(m.webrtc && t.webrtc)
  const bothRendezvous = !!(m.rendezvous !== false && t.rendezvous !== false)
  if (bothBeam2 && bothWebRtc) return { lane: LANES.W, degraded: false, reason: 'both-advertise' }
  if (bothBeam2 && bothRendezvous) return { lane: LANES.C, degraded: m.webrtc && t.webrtc ? true : false, reason: 'rendezvous-only' }
  return { lane: LANES.M, degraded: false, reason: 'manual-fallback' }
}

/** The typed degradation step (ICE failure / timeout): W → C, visible. */
export function degradeToRelay(reason) {
  return { lane: LANES.C, degraded: true, reason: reason === 'ice-timeout' ? 'ice-timeout' : 'ice-failure' }
}

/** The lane truth row content — the law's exact two renderings + manual. */
export function laneTruthRow(lane) {
  switch (lane) {
    case LANES.W:
      return { key: 'beam2LaneTruthDirect', fallback: 'Direct peer-to-peer — end-to-end encrypted', lane: LANES.W }
    case LANES.C:
      return { key: 'beam2LaneTruthRelay', fallback: 'Relayed through your cloud — end-to-end encrypted', lane: LANES.C }
    case LANES.M:
      return { key: 'beam2LaneTruthManual', fallback: 'Manual signal path — end-to-end encrypted, zero cloud', lane: LANES.M }
    default:
      return { key: 'beam2LaneTruthUnknown', fallback: 'Lane not yet selected', lane: null }
  }
}

/**
 * The caps an ADVERTISING device publishes (the presence payload's
 * capabilities block — law §2.B: device ID, name, capabilities, TTL).
 */
export function advertiseCaps({ beam2 = true, webrtc = true, rendezvous = true, maxChunk = CHUNK_SIZE, protocolVersion = '2.91.0' } = {}) {
  return { beam2, webrtc, rendezvous, maxChunk, protocolVersion }
}

/**
 * CHUNK PLANNER — shared by Lane W and Lane C (one chunking truth):
 * returns the chunk count for a size (0 B → 0 chunks, 16 KiB exact → 1).
 */
export function chunkCountFor(size) {
  const n = Number(size)
  if (!Number.isInteger(n) || n < 0) return 0
  if (n === 0) return 0
  return Math.ceil(n / CHUNK_SIZE)
}

/**
 * THE ACK WINDOW — Lane C's sliding window: given the highest contiguous
 * acked chunk and the window size, which chunk indexes may be in flight?
 * Pure, battery-pinned (BEAM2-PROTOCOL-10).
 */
export function ackWindowRanges(lastAcked, windowSize = ACK_WINDOW, totalChunks = Infinity) {
  const first = lastAcked + 1
  const last = Math.min(lastAcked + windowSize, totalChunks - 1)
  return { first, last, count: last >= first ? last - first + 1 : 0 }
}
