/**
 * UCrypt — R136 §5.2 — THE BEAM 3 TRANSPORT PLANES ("three planes, one
 * transfer"). Beam 3 is Device Transfer reborn: planned from the operations
 * a user actually performs, informed by Brave Sync, LocalSend, and the
 * WebRTC data channel.
 *
 *   Plane A — same-network direct: WebRTC data channels over LOCAL ICE
 *   candidates (mDNS host candidates included). No STUN required on a
 *   shared LAN; no cloud involved; discovery rides the chain presence.
 *
 *   Plane B — cloud relay: THE CONNECTED CLOUD IS THE RELAY (R136-F2). The
 *   cloud the user already connected — Google Drive OR any WebDAV endpoint —
 *   carries offer records and sealed 256 KiB chunks in a dedicated UCrypt
 *   application folder. The cloud only ever stores ciphertext. Chunks are
 *   deleted by tombstone after both sides acknowledge the completed
 *   manifest. Signals and offers persist until consumed or 24 hours old —
 *   the expiry-before-use failure (R136-F1) is retired by construction.
 *
 *   Plane C — manual exchange: a FIRST-CLASS path, not a dead-end fallback.
 *   The signal renders in full, valid "until used, or 24 hours"; pasting
 *   the peer signal opens the PAIRED state; the journey from there is
 *   identical to planes A and B.
 *
 * SELECTION IS PER TRANSFER (never per session) and the readiness strip
 * names the chosen plane in plain words BEFORE the user commits
 * (routeTruthLine). The plane is a transport detail, never a behavioral
 * fork: all three planes carry identical payloads, identical offer and
 * consent semantics, and identical journal treatment.
 *
 * PURE — no DOM, no chrome.*, no RTCPeerConnection/fetch at import time.
 * Battery-pinned (TRF-PLANE-*, G71).
 */

/** The planes, named. */
export const PLANES = { A: 'A', B: 'B', C: 'C' }

/** Human plane names (the readiness strip's route words ride the i18n keys). */
export const PLANE_NAMES = {
  A: 'same-network-direct',
  B: 'cloud-relay',
  C: 'manual-exchange',
}

/** Beam 3 transport constants (the brief's exact numbers). */
export const BEAM3_CHUNK_SIZE = 256 * 1024 // 256 KiB (Plane B framing; Plane A uses the same framing)
export const BEAM3_MAX_FILE_BYTES = 200 * 1024 * 1024 // 200 MiB — S7 proves ≥100 MB per plane
export const BEAM3_SIGNAL_TTL_MS = 24 * 60 * 60 * 1000 // signals live until consumed or 24 hours (R136-F1)
export const BEAM3_RELAY_POLL_ACTIVE_MS = 2000 // plane B active polling
export const BEAM3_RELAY_POLL_IDLE_MS = 30000 // plane B idle polling
export const BEAM3_RELAY_BACKOFF_MAX_MS = 5 * 60 * 1000 // capped backoff (the R129 clinical rule)
export const BEAM3_RELAY_BACKOFF_BASE_MS = 500

/**
 * The typed edge validator for Beam 3 (0 B … 200 MiB inclusive).
 * The 20 MB uniform cap of Beam 2 stays for the legacy lane; Beam 3 planes
 * carry the raised cap (S7 commands ≥100 MB per plane; the R134-documented
 * CEO option is now commanded).
 */
export function validateBeam3FileEdge(size) {
  // the R130-F1 hostile-coercion class at this door: '5'/null/true coerce to
  // integers — the ORIGINAL type must be a number or the edge is invalid
  if (typeof size !== 'number') return { ok: false, code: 'ERR_SIZE_INVALID' }
  const n = size
  if (!Number.isInteger(n) || n < 0) return { ok: false, code: 'ERR_SIZE_INVALID' }
  if (n === 0) return { ok: true, code: 'EDGE_0B' }
  if (n > BEAM3_MAX_FILE_BYTES) return { ok: false, code: 'ERR_OVER_CAP' }
  return { ok: true, code: n === BEAM3_MAX_FILE_BYTES ? 'EDGE_CAP_EXACT' : 'EDGE_OK' }
}

/**
 * PLANE SELECTION (pure, per transfer). Priority: the user's explicit
 * manual choice (Plane C) wins — the first-class path; otherwise Plane A
 * when both peers advertise WebRTC; otherwise Plane B when a cloud relay
 * is connected on both sides; otherwise Plane C (manual still completes —
 * the zero-transport law holds).
 *
 * @param {{
 *   manualChosen?: boolean,
 *   bothAdvertiseWebRtc?: boolean,
 *   cloudRelayConnected?: boolean,
 *   peerCloudRelayConnected?: boolean,
 *   sameNetworkKnown?: boolean,
 * }} input
 * @returns {{plane:'A'|'B'|'C', reason:string, degraded:boolean}}
 */
export function selectPlane(input = {}) {
  const i = input || {}
  if (i.manualChosen) return { plane: PLANES.C, reason: 'manual-chosen', degraded: false }
  if (i.bothAdvertiseWebRtc) return { plane: PLANES.A, reason: 'both-advertise-webrtc', degraded: false }
  if (i.cloudRelayConnected && i.peerCloudRelayConnected !== false) {
    return { plane: PLANES.B, reason: 'cloud-relay', degraded: false }
  }
  return { plane: PLANES.C, reason: 'no-faster-path', degraded: false }
}

/**
 * Typed degradation: Plane A ICE failure/timeout degrades to Plane B when
 * a relay exists, else to Plane C — degradation is typed and visible,
 * never silent (the Beam 2 law, carried).
 */
export function degradePlane(fromPlane, relayAvailable) {
  if (fromPlane !== PLANES.A) return { plane: fromPlane, degraded: false, reason: 'not-degradable' }
  return relayAvailable
    ? { plane: PLANES.B, degraded: true, reason: 'ice-failure' }
    : { plane: PLANES.C, degraded: true, reason: 'ice-failure-no-relay' }
}

/**
 * THE ROUTE TRUTH LINE (R136-F2's readiness strip): plain words for what
 * will actually happen, BEFORE the user commits. The retired footnote is
 * forbidden text; honest capability replaces honest disability.
 * @returns {{key:string, fallback:string, plane:string}}
 */
export function routeTruthLine(plane, cloudLabel = '') {
  switch (plane) {
    case PLANES.A:
      return { key: 'beam3RouteDirect', fallback: 'Route: same network — direct device-to-device transfer, end-to-end encrypted.', plane }
    case PLANES.B:
      return {
        key: 'beam3RouteRelay',
        fallback: cloudLabel
          ? `Route: through your connected ${cloudLabel} — sealed chunks only, end-to-end encrypted.`
          : 'Route: through your connected cloud — sealed chunks only, end-to-end encrypted.',
        plane,
      }
    case PLANES.C:
      return { key: 'beam3RouteManual', fallback: 'Route: manual exchange — the code travels with you; the transfer completes device-to-device when a path exists.', plane }
    default:
      return { key: 'beam3RouteUnknown', fallback: 'Route: not yet chosen.', plane: null }
  }
}

/**
 * The readiness strip rows (R136-F5: ONE canonical strip, one line each —
 * chain membership, the chosen route, the visible device count; a red row
 * carries its one-tap fix inline).
 */
export function readinessRows({ chainJoined = false, plane = null, visibleDevices = 0, cloudLabel = '' } = {}) {
  const rows = [
    {
      id: 'chain',
      ok: !!chainJoined,
      key: chainJoined ? 'beam3ReadyChainOk' : 'beam3ReadyChainNo',
      fallback: chainJoined ? 'Sync chain joined' : 'Sync chain not joined — join or create one to transfer between your devices',
      fixKey: chainJoined ? null : 'beam3ReadyChainFix',
      fixFallback: chainJoined ? null : 'Open Cloud Sync',
    },
    {
      id: 'route',
      ok: !!plane,
      key: 'beam3ReadyRoute',
      fallback: plane ? routeTruthLine(plane, cloudLabel).fallback : 'Route not chosen yet — pick Send or Receive',
      fixKey: plane ? null : 'beam3ReadyRouteFix',
      fixFallback: plane ? null : 'Choose below',
    },
    {
      id: 'devices',
      ok: visibleDevices > 0,
      key: 'beam3ReadyDevices',
      fallback: visibleDevices > 0
        ? `${visibleDevices} device(s) visible on your chain`
        : 'No other chain device visible yet — the other device must be online (or pair by code)',
      fixKey: visibleDevices > 0 ? null : 'beam3ReadyDevicesFix',
      fixFallback: visibleDevices > 0 ? null : 'Pair by code',
    },
  ]
  return rows
}

/**
 * SAME-NETWORK PROBE (pure classification): given the ICE candidate types
 * observed during pairing, decide whether the peers share a network. Host
 * and mDNS candidates mean no NAT traversal was needed — the LAN path.
 */
export function classifySameNetwork(localCandidateTypes = [], remoteCandidateTypes = []) {
  const local = Array.isArray(localCandidateTypes) ? localCandidateTypes : []
  const remote = Array.isArray(remoteCandidateTypes) ? remoteCandidateTypes : []
  const localHost = local.some((t) => t === 'host' || t === 'mDNS')
  const remoteHost = remote.some((t) => t === 'host' || t === 'mDNS')
  return { sameNetwork: localHost && remoteHost, localHost, remoteHost }
}
