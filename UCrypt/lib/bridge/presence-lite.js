/**
 * UCrypt — R142 §5.2-b6 — PRESENCE LITE (presence independence, the F-5 law).
 *
 * THE LAW: the roster NEVER shows empty under a green chain check. The
 * roster is derived from the CHAIN ITSELF (the peer map every bound device
 * already has) — a dead road may never blank it. When the cloud is up,
 * presence rides the mailbox with a ≥ 15-minute TTL + heartbeat (the R141
 * 2-minute TTL class is RETIRED — it killed recovery). When the cloud is
 * down, the QR/words handshake carries the session WITHOUT any presence
 * server — the roster rows go UNKNOWN (honest), never blank.
 *
 * PURE — battery-pinned (G95; G93 R2/R3 prove it on the shipped build).
 */

import { presenceAnnotation } from '../presence.js'

export const PRESENCE_TTL_MS = 15 * 60 * 1000 // the law: ≥ 15 minutes (row 52)
export const PRESENCE_HEARTBEAT_MS = 5 * 60 * 1000 // the heartbeat rides the poll cadence

export function presenceError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_PRESENCE_${code}`
  return e
}

/** A heartbeat: refresh the device's own liveness (idempotent per stamp). */
export function presenceHeartbeat(peer, { now = Date.now(), heartbeatMs = PRESENCE_HEARTBEAT_MS } = {}) {
  if (!peer || !peer.deviceId) throw presenceError('SHAPE', 'the heartbeat needs a peer')
  const last = Number(peer.heartbeatAt) || 0
  if (now - last < heartbeatMs) return peer // the cadence owns the stamp — no spam
  return { ...peer, heartbeatAt: now, lastSeen: now }
}

/** Is the peer present? (TTL-gated; unknown/zero lastSeen is NEVER present) */
export function isPresent(peer, { now = Date.now(), ttlMs = PRESENCE_TTL_MS } = {}) {
  const last = Number(peer && peer.lastSeen) || 0
  return last > 0 && now - last <= ttlMs
}

/**
 * THE ROSTER PROJECTION (the composer reads THIS): every chain member is
 * listed — the road's health changes the ANNOTATION, never the LIST.
 * Rows merge the peer map's truth with the honest presence annotation
 * (lib/presence.js — the R132 three-state law).
 */
export function rosterProjection(peerMapRows, { now = Date.now(), rendezvousAvailable = false, selfId = '' } = {}) {
  const rows = (Array.isArray(peerMapRows) ? peerMapRows : [])
    .filter((p) => p && p.deviceId && String(p.deviceId) !== String(selfId))
    .map((p) => {
      const ann = presenceAnnotation({ online: isPresent(p, { now }), lastSeen: Number(p.lastSeen) || Number(p.syncAt) || 0, syncAt: p.syncAt }, { rendezvousAvailable })
      return {
        deviceId: p.deviceId,
        label: p.label || p.deviceId,
        deviceType: p.deviceType || '',
        state: ann.state,
        presenceKey: ann.key,
        presenceArgs: ann.args,
        lastSeen: Number(p.lastSeen) || 0,
        syncAt: Number(p.syncAt) || 0,
        entryCount: p.entryCount ?? null,
      }
    })
  return rows
}

/**
 * THE F-5 ASSERTION, as a law: the roster from a chain of N members (minus
 * self) has exactly N−1 rows — no road state can shrink it. The battery
 * pins this with the cloud DOWN and the direct DOWN.
 */
export function rosterNeverBlanks(peerMapRows, { selfId = '' } = {}) {
  const expected = peerMapRows.filter((p) => p && p.deviceId && String(p.deviceId) !== String(selfId)).length
  const projected = rosterProjection(peerMapRows, { rendezvousAvailable: false, selfId })
  if (projected.length !== expected) throw presenceError('BLANK', `the roster shrank under a dead road (${projected.length} of ${expected})`)
  return projected
}

/** The composer's empty-state teaching (the zero-dead-end law, §7.1). */
export function emptyRosterTeaching() {
  return {
    line: 'No other device is in your chain yet.',
    action: 'addDevice',
    cta: 'Add a device',
  }
}
