/**
 * UCrypt — R142 §5.2-b1 — THE BRIDGE SESSION MACHINE (THE DIRECT ROAD).
 *
 * ONE journey, THREE roads, ZERO dead ends (§5.1 the design law):
 *   Road 1 DIRECT — this network   (WebRTC host/mDNS candidates)
 *   Road 2 DIRECT — over the internet (SRFLX via STUN; optional)
 *   Road 3 VIA YOUR CLOUD (relay)  (the R141 mailbox chunks — RETAINED)
 *
 * The machine owns the journey's TRUTH: the road that is in use, the ICE
 * window (10 s), the automatic demotion (announced, never silent), and the
 * cancel-safety law (G93 R9: cancel at EVERY state leaves no orphans).
 *
 * PURE — no DOM, no chrome.*, no WebRTC: the page module wires the wires.
 * Battery-pinned (tests/r142-bridge.test.mjs — G95).
 */

export const BRIDGE_STATES = {
  IDLE: 'IDLE',
  SIGNALING: 'SIGNALING',   // the offer/answer/ice exchange is in flight
  HANDSHAKE: 'HANDSHAKE',   // the peer is answering; the code comparison is armed
  OPEN: 'OPEN',             // the DataChannel is open — the codes matched
  STREAMING: 'STREAMING',   // the payload chunks are moving
  SEALED: 'SEALED',         // the sha256 checked on the receiving side
  DONE: 'DONE',             // the receipt rode back; the journey is complete
  ERROR: 'ERROR',           // a named hop failed (detail carries hop + action)
  CANCELLED: 'CANCELLED',   // the user cancelled — clean idle, no orphans
}

export const BRIDGE_ROADS = {
  DIRECT_LAN: 'direct-lan',   // "Direct — this network"
  DIRECT_NET: 'direct-net',   // "Direct — over the internet"
  RELAY: 'relay',             // "Via your cloud (relay)"
}

export const BRIDGE_ROAD_LABELS = Object.freeze({
  'direct-lan': 'Direct — this network',
  'direct-net': 'Direct — over the internet',
  'relay': 'Via your cloud (relay)',
})

/** The ICE window (§5.2-b1): the direct road gets 10 seconds to prove itself. */
export const BRIDGE_ICE_WINDOW_MS = 10 * 1000

/* The legal edges. CANCELLED is legal FROM EVERY STATE (cancel-safe at every
   state — G93 R9). ERROR is legal from every active state (a named hop
   failed). DONE only from SEALED. */
const EDGES = {
  IDLE: ['SIGNALING', 'CANCELLED'],
  SIGNALING: ['HANDSHAKE', 'SIGNALING', 'ERROR', 'CANCELLED'], // self-edge: ICE candidates trickle
  HANDSHAKE: ['OPEN', 'ERROR', 'CANCELLED'],
  OPEN: ['STREAMING', 'ERROR', 'CANCELLED'],
  STREAMING: ['SEALED', 'ERROR', 'CANCELLED'],
  SEALED: ['DONE', 'ERROR', 'CANCELLED'],
  DONE: [],
  ERROR: [],
  CANCELLED: [],
}

export function bridgeError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_${code}`
  return e
}

export function newBridgeSession({ sessionId, role, fileName = '', size = 0, now = Date.now() }) {
  if (!sessionId || typeof sessionId !== 'string') throw bridgeError('SHAPE', 'a session needs a string sessionId')
  if (role !== 'sender' && role !== 'receiver') throw bridgeError('SHAPE', 'the role is sender or receiver')
  return {
    sessionId: String(sessionId),
    role,
    fileName: String(fileName || ''),
    size: Number(size) || 0,
    state: BRIDGE_STATES.IDLE,
    road: null,            // the road IN USE — set before the first byte moves
    roadAnnounced: false,  // the demotion/announcement discipline (§5.1)
    iceDeadlineAt: null,
    demotedFrom: null,
    code: null,            // the 6-digit safety code (both sides derive it)
    codeMatched: null,     // the human's verdict — typed, never assumed
    journal: [{ state: BRIDGE_STATES.IDLE, at: now, road: null }],
    startedAt: now,
    endedAt: null,
  }
}

export function stepBridge(s, to, { now = Date.now(), detail = '', road = undefined } = {}) {
  if (!s || !EDGES[s.state]) throw bridgeError('SHAPE', 'the session is malformed')
  if (!Object.values(BRIDGE_STATES).includes(to)) throw bridgeError('STATE', `unknown state ${String(to)}`)
  if (!EDGES[s.state].includes(to)) {
    throw bridgeError('EDGE', `a ${s.state} session cannot step to ${to}`)
  }
  const next = { ...s, state: to, journal: [...s.journal, { state: to, at: now, road: s.road, detail: String(detail || '') }] }
  if (road !== undefined) {
    if (!Object.values(BRIDGE_ROADS).includes(road)) throw bridgeError('ROAD', `unknown road ${String(road)}`)
    next.road = road
    next.journal[next.journal.length - 1].road = road
  }
  if (to === BRIDGE_STATES.DONE || to === BRIDGE_STATES.ERROR || to === BRIDGE_STATES.CANCELLED) next.endedAt = now
  return next
}

/** Arms the 10-second ICE window (the direct road's proving period). */
export function armIceWindow(s, { now = Date.now(), ms = BRIDGE_ICE_WINDOW_MS } = {}) {
  if (s.state !== BRIDGE_STATES.SIGNALING && s.state !== BRIDGE_STATES.IDLE) {
    throw bridgeError('EDGE', `the ICE window arms while signaling (state ${s.state})`)
  }
  return { ...s, iceDeadlineAt: now + ms }
}

/** Is the ICE window expired? (honest clock — a null deadline is never expired) */
export function iceWindowExpired(s, now = Date.now()) {
  return s.iceDeadlineAt != null && now > s.iceDeadlineAt
}

/**
 * THE AUTOMATIC DEMOTION (§5.1): the direct road failed inside its window —
 * the journey demotes to the relay road and the badge change is ANNOUNCED
 * (roadAnnounced flips here; the page renders the plain-words line). Legal
 * from SIGNALING/HANDSHAKE only; never from STREAMING (the pipe is moving).
 */
export function demoteToRelay(s, { now = Date.now(), reason = 'the direct path did not open in time' } = {}) {
  if (s.state !== BRIDGE_STATES.SIGNALING && s.state !== BRIDGE_STATES.HANDSHAKE) {
    throw bridgeError('EDGE', `demotion is a signaling-time event (state ${s.state})`)
  }
  const next = { ...s, demotedFrom: s.road || BRIDGE_ROADS.DIRECT_LAN, road: BRIDGE_ROADS.RELAY, roadAnnounced: true, iceDeadlineAt: null }
  next.journal = [...s.journal, { state: s.state, at: now, road: BRIDGE_ROADS.RELAY, detail: `demoted: ${reason}` }]
  return next
}

/**
 * THE ROAD SELECTION ORDER (§5.1): 1 → 2 → 3, decided from honest facts the
 * page gathers — a peer found on this network, STUN reachability, the chain's
 * cloud truth. The user NEVER configures roads.
 */
export function pickRoad({ lanPeerFound = false, stunReachable = false, cloudConnected = false } = {}) {
  if (lanPeerFound) return BRIDGE_ROADS.DIRECT_LAN
  if (stunReachable) return BRIDGE_ROADS.DIRECT_NET
  if (cloudConnected) return BRIDGE_ROADS.RELAY
  return null // no road is up — the page shows exactly what is missing + the one action
}

/** The plain-words "no road" truth: what is missing and the one action. */
export function noRoadTruth({ lanPeerFound = false, stunReachable = false, cloudConnected = false } = {}) {
  if (pickRoad({ lanPeerFound, stunReachable, cloudConnected })) return null
  if (!lanPeerFound && !cloudConnected) {
    return {
      missing: 'the other device is not on this network, and the chain\u2019s cloud is not connected',
      action: 'open UCrypt on the other device (same network), or connect Cloud Sync for the relay, or use the QR handshake below',
    }
  }
  return { missing: 'no path to the other device right now', action: 'open UCrypt on the other device, or retry when the network returns' }
}

/** The receipt story is ONE story on every road (§5.2-b5 parity). */
export function roadLabel(road) {
  return BRIDGE_ROAD_LABELS[road] || ''
}
