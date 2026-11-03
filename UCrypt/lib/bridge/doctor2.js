/**
 * UCrypt — R142 §5.5 — THE DOCTOR v2 (seven named hops, each with its ONE fix).
 *
 * R146 §7.1/§2.6 — the doctor stays current with every new seam: the ROAD hop
 * (WHY the last direct attempt failed, in plain words — the clinical record)
 * and the IDENTITY hop (the chain identity's derived truth, the v4 hop).
 *
 * The doctor answers the only questions a transfer can die of, in plain
 * words, each row carrying the ONE action that fixes it:
 *   1 "Is the other device online?"    (since when; the inline pairing door if never)
 *   2 "Can we reach each other?"       (direct found / relay reachable / neither)
 *   3 "Why did the direct road fail?"  (the road record's class, plain words)
 *   4 "Is this device's chain identity in place?" (the v4 identity hop)
 *   5 "Did the codes match?"           (compared / mismatched / not yet)
 *   6 "Is the pipe moving?"            (speed; stalled-since)
 *   7 "Did the receipt return?"        (yes/no)
 *
 * PURE — battery-pinned (G95; the page renders the rows verbatim).
 */

import { roadHop } from './road-record.js'

export const DOCTOR_HOPS = Object.freeze(['peer', 'reach', 'road', 'identity', 'code', 'pipe', 'receipt'])

export function doctorError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_DOCTOR_${code}`
  return e
}

/**
 * Build the rows. `facts` (all optional — the doctor is honest about
 * what it does not know):
 *   peerSeenAt       — the last-seen timestamp of the peer (0/absent = never)
 *   directFound      — the direct road found the peer on this network
 *   relayReachable   — the chain's cloud answers (the relay is drivable)
 *   roadRecord       — the last direct attempt's clinical record (the road hop)
 *   identityReady    — the chain identity's derived truth (the identity hop)
 *   identityId       — the derived identity's short id (rendered masked)
 *   codeCompared     — the human compared the 6-digit codes
 *   codeMatched      — the comparison's verdict
 *   speedBps         — the current pipe speed (0 = stalled)
 *   stalledSince     — when the pipe last moved (ms epoch, 0 = moving now)
 *   receiptReturned  — the receiver's receipt rode back
 *   peerEverSeen     — the peer has been seen at least once
 */
export function buildDoctorRows(facts = {}, { now = Date.now() } = {}) {
  const f = { ...facts }
  const rows = []

  // 1 — the peer
  if (f.peerEverSeen === false || (!f.peerSeenAt && f.peerEverSeen !== true)) {
    rows.push({ hop: 'peer', ok: false, line: 'Is the other device online? UCrypt has never seen it.', action: 'addDevice', actionLine: 'Add a device — pair it with the QR or the words.' })
  } else if (f.peerSeenAt) {
    const ago = Math.max(0, now - f.peerSeenAt)
    const mins = Math.floor(ago / 60000)
    const when = mins < 1 ? 'just now' : mins === 1 ? '1 minute ago' : `${mins} minutes ago`
    rows.push({ hop: 'peer', ok: true, line: `The other device was online ${when}.`, action: '' })
  } else {
    rows.push({ hop: 'peer', ok: false, line: 'Is the other device online? Its last online time is unknown.', action: 'openPeer', actionLine: 'Open UCrypt on the other device, then re-run the doctor.' })
  }

  // 2 — the reach
  if (f.directFound) {
    rows.push({ hop: 'reach', ok: true, line: 'Can we reach each other? Yes — directly, on this network.', action: '' })
  } else if (f.relayReachable) {
    rows.push({ hop: 'reach', ok: true, line: 'Can we reach each other? Yes — through your connected cloud.', action: '' })
  } else {
    rows.push({ hop: 'reach', ok: false, line: 'Can we reach each other? Not yet — no direct path and the cloud is not connected.', action: 'connectOrNear', actionLine: 'Put both devices on the same network, or connect Cloud Sync, or use the QR handshake.' })
  }

  // 2b — the ROAD hop (R146 §7.1, H-3): WHY the last direct attempt failed,
  // from the attempt's own clinical record — never a bare "did not connect".
  if (f.roadRecord) {
    const hop = roadHop(f.roadRecord)
    if (hop) rows.push({ hop: 'road', ok: hop.ok, line: hop.line, action: 'relay', actionLine: hop.actionLine })
  }

  // 2c — the IDENTITY hop (R146 §2.6-A5, the v4 dedicated hop): the chain
  // identity's derived truth. A joined device whose identity was lost to a
  // worker recycle NEVER re-binds — the self-heal re-derives it (law 14).
  if (f.identityReady === false) {
    rows.push({ hop: 'identity', ok: false, line: 'Is this device\u2019s chain identity in place? Not yet — it is being re-derived.', action: 'selfHeal', actionLine: 'Press Sync now — the heal finishes on its own; you are never asked to re-bind.' })
  } else if (f.identityReady === true) {
    const short = f.identityId ? String(f.identityId).slice(0, 8) : ''
    rows.push({ hop: 'identity', ok: true, line: short ? `Is this device\u2019s chain identity in place? Yes — ${short}\u2026.` : 'Is this device\u2019s chain identity in place? Yes.', action: '' })
  }

  // 3 — the code
  if (f.codeCompared === true && f.codeMatched === true) {
    rows.push({ hop: 'code', ok: true, line: 'Did the codes match? Yes — the 6-digit codes matched.', action: '' })
  } else if (f.codeCompared === true && f.codeMatched === false) {
    rows.push({ hop: 'code', ok: false, line: 'Did the codes match? No — the codes differ.', action: 'recompare', actionLine: 'Nothing moved. Cancel and start again — the codes must match.' })
  } else {
    rows.push({ hop: 'code', ok: false, line: 'Did the codes match? Not yet compared.', action: 'showCode', actionLine: 'Compare the 6-digit code on both devices before the file moves.' })
  }

  // 4 — the pipe
  if (f.speedBps > 0) {
    const mb = f.speedBps > 1024 * 1024 ? `${(f.speedBps / 1024 / 1024).toFixed(1)} MB/s` : `${Math.max(1, Math.round(f.speedBps / 1024))} KB/s`
    rows.push({ hop: 'pipe', ok: true, line: `Is the pipe moving? Yes — ${mb}.`, action: '' })
  } else if (f.stalledSince && now - f.stalledSince > 30 * 1000) {
    const mins = Math.floor((now - f.stalledSince) / 60000)
    rows.push({ hop: 'pipe', ok: false, line: `Is the pipe moving? No — it has been still for ${mins} minute${mins === 1 ? '' : 's'}.`, action: 'retry', actionLine: 'Cancel the transfer and start it again — nothing partial remains.' })
  } else {
    rows.push({ hop: 'pipe', ok: false, line: 'Is the pipe moving? It has not started yet.', action: '', })
  }

  // 5 — the receipt
  if (f.receiptReturned === true) {
    rows.push({ hop: 'receipt', ok: true, line: 'Did the receipt return? Yes — the other device verified the file.', action: '' })
  } else {
    rows.push({ hop: 'receipt', ok: false, line: 'Did the receipt return? Not yet.', action: 'wait', actionLine: 'The receipt returns when the other device finishes verifying.' })
  }

  return rows
}

/** The doctor's one-line verdict: the FIRST failing hop names the round's fix. */
export function doctorVerdict(rows) {
  const first = (Array.isArray(rows) ? rows : []).find((r) => !r.ok)
  return first ? { ok: false, hop: first.hop, action: first.action || '', actionLine: first.actionLine || '' } : { ok: true, hop: '', action: '', actionLine: '' }
}
