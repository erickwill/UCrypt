/**
 * UCrypt — R146 §6.2 — THE ONE-DEVICE-TRUTH (law 13, the pure law).
 *
 * The canonical chain roster is the ONLY device list in the product. This
 * module is its projection to the transfer pick-list — every surface that
 * needs devices reads THROUGH here, and nothing else may keep a second
 * roster (the gate-key-without-writer disease, outlawed at the root).
 *
 * Source of truth: the worker's canonicalPeerRows() — the SAME rows the
 * Cloud Sync page's "Your devices" list renders (DELL, Helium, Chrome). A
 * joined chain can therefore NEVER render "No other device is in your chain
 * yet." — the impossible sentence dies here by construction, and the
 * battery pins it (tests/r146-roster.test.mjs).
 *
 * Defensive by design: every field is optional, every row survives a partial
 * peer record, and the projection never throws on foreign shapes — a bad
 * row degrades to its deviceId, never to a silent empty list while the
 * chain is joined (the F-R78-3 truth law).
 */

function firstNonEmpty(...vals) {
  for (const v of vals) {
    if (v === 0) continue
    if (v) return v
  }
  return ''
}

function agoWords(ms, now) {
  if (!ms || ms <= 0) return { key: 'jrFreshnessNever', args: [], fallback: 'not seen yet' }
  const s = Math.max(1, Math.round((now - ms) / 1000))
  if (s < 90) return { key: 'jrFreshnessNow', args: [], fallback: 'available now' }
  const m = Math.round(s / 60)
  if (m < 60) return { key: 'jrFreshnessMin', args: [String(m)], fallback: `synced ${m} min ago` }
  const h = Math.round(m / 60)
  if (h < 36) return { key: 'jrFreshnessHours', args: [String(h)], fallback: `synced ${h} h ago` }
  const d = Math.round(h / 24)
  return { key: 'jrFreshnessDays', args: [String(d)], fallback: `synced ${d} d ago` }
}

/** The pick-list rows from the CANONICAL peers. Self is excluded (a device
 * never sends to itself), duplicates collapse on deviceId, labels degrade
 * gracefully, and the freshness words derive from the row's own truth. */
export function projectChainRoster(peers, { selfId = null, now = Date.now() } = {}) {
  const list = Array.isArray(peers) ? peers : []
  const seen = new Set()
  const rows = []
  for (const p of list) {
    if (!p || typeof p !== 'object') continue
    const id = firstNonEmpty(p.deviceId, p.memberId, p.id)
    if (!id) continue
    if (selfId && String(id) === String(selfId)) continue
    // R148 §6.5 (LAW #74) — the tombstoned member LEAVES the active list:
    // the send-target select can never address a removed device. The
    // removed rows render in the device card's converged section instead.
    if (p.removed && Number(p.removed.at)) continue
    const dedupe = String(id)
    if (seen.has(dedupe)) continue
    seen.add(dedupe)
    const label = firstNonEmpty(p.label, p.name, p.deviceName) || 'A UCrypt device'
    const online = !!(p.available || p.online || p.presence === 'online')
    const lastSync = firstNonEmpty(p.lastSync, p.syncAt, p.lastSeen, p.seenAt)
    const lane = firstNonEmpty(p.lane, p.syncLane)
    const fresh = online
      ? { key: 'jrFreshnessNow', args: [], fallback: 'available now' }
      : agoWords(Number(lastSync) || 0, now)
    rows.push({
      deviceId: String(id),
      label: String(label),
      online,
      lane: lane ? String(lane) : '',
      freshness: fresh,
      entryCount: Number(p.entryCount) || 0,
      selectable: true,
    })
  }
  return rows
}

/** The roster verdict — the ONE gate the pick beat may ever show, derived
 * from the canonical status (never from a transfer-local source). */
export function rosterVerdict({ ok = false, unlocked = null, chainReady = null, readiness = '', peers = null } = {}) {
  if (ok === false) return 'unavailable'
  if (unlocked === false || readiness === 'locked') return 'locked'
  if (readiness === 'no_sync_code' || chainReady === false) return 'no-chain'
  const rows = projectChainRoster(peers || [], { selfId: null })
  if (!rows.length) return 'empty-chain'
  return 'ready'
}

/** The ONE next step for every non-ready verdict (zero dead ends). */
export function verdictNextStep(verdict) {
  switch (verdict) {
    case 'ready':
      return null
    case 'locked':
      return { state: 'pick.locked', action: 'unlockVault', lineKey: 'jrLocked', line: 'Unlock the vault to send between your devices.' }
    case 'no-chain':
      return { state: 'pick.noChain', action: 'openCloudSync', lineKey: 'jrNoChain', line: 'No sync chain on this device yet — Cloud Sync sets one up in two steps.' }
    case 'empty-chain':
      return { state: 'pick.emptyChain', action: 'openCloudSync', lineKey: 'jrEmptyChain', line: 'Your devices are your chain. To add one, use Cloud Sync.' }
    default:
      return { state: 'pick.emptyChain', action: 'openCloudSync', lineKey: 'jrRosterUnavailable', line: 'The device list could not be read — Cloud Sync re-checks it. Press Retry below.' }
  }
}

/** The select's option label — plain words, 13yo-tested: "DELL — synced 27 min ago". */
export function optionLabel(row) {
  const fresh = row.freshness ? row.freshness.fallback : ''
  return fresh ? `${row.label} — ${fresh}` : row.label
}
