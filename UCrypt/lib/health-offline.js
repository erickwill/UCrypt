/**
 * ════════════════════════════════════════════════════════════════════════
 * R165 ARC G (the R163 carry, re-commanded and DUE) — THE OFFLINE HEALTH
 * REPORT: the vault's aggregate health computed ENTIRELY on the device —
 * no network, no provider, no account — rendered as a copyable receipt.
 *
 * The health ENGINE is lib/health.js (sealed, pure); this module is the
 * REPORT half: it wraps the engine's aggregate with the honest framing
 * (offline by construction), the masked worst-offender rows (the password
 * column is NEVER the password — the analyzer's bits and the breach state
 * only), and the copyable text shape. Pure, dependency-free on the I/O
 * side (the analyzer function is injected — the battery drives it with a
 * deterministic fake).
 * ════════════════════════════════════════════════════════════════════════
 */

/**
 * Build the offline health report receipt.
 * @param {Array<{domain: string, username: string, password: string}>} entries
 *   the UNLOCKED login entries (the caller's responsibility — this module
 *   never persists them; the receipt carries NONE of their values)
 * @param {(pw: string) => {bits: number, breached?: boolean, verdict?: string}} analyzePassword
 *   the analyzer (lib/analyzer.js analyzePassword — local, offline)
 * @param {{at?: string, version?: string}} [opts]
 * @returns {{ok: boolean, report?: object, text?: string, error?: string}}
 */
export function buildOfflineHealthReport(entries, analyzePassword, opts = {}) {
  if (typeof analyzePassword !== 'function') {
    return { ok: false, error: 'the analyzer is unavailable — the report needs the local engine' }
  }
  const rows = Array.isArray(entries) ? entries : []
  const stamp = String(opts.at || new Date().toISOString())
  const perEntry = rows.map((e) => {
    const pw = String((e && e.password) || '')
    const a = analyzePassword(pw) || {}
    return {
      domain: String((e && e.domain) || '').slice(0, 80),
      user: String((e && e.username) || '').slice(0, 40),
      bits: Number(a.bits) || 0,
      breached: !!a.breached,
    }
  })
  const breached = perEntry.filter((r) => r.breached).length
  const weak = perEntry.filter((r) => !r.breached && r.bits < 40).length
  const fair = perEntry.filter((r) => !r.breached && r.bits >= 40 && r.bits < 60).length
  const strong = perEntry.filter((r) => r.bits >= 60).length
  // reuse groups: the same password on more than one entry (the count only —
  // the group MEMBERSHIP is a local display concern, never a receipt row)
  const seen = new Map()
  for (const e of rows) {
    const pw = String((e && e.password) || '')
    seen.set(pw, (seen.get(pw) || 0) + 1)
  }
  const reuseGroups = [...seen.values()].filter((c) => c > 1).length
  const reusedEntries = [...seen.values()].filter((c) => c > 1).reduce((s, c) => s + c, 0)
  let score = 100
  score -= 25 * breached
  score -= 10 * weak
  score -= 6 * Math.max(0, reusedEntries - reuseGroups)
  score = Math.max(0, Math.min(100, score))
  const band = score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : score >= 50 ? 'Fair' : 'Needs attention'
  const worst = [...perEntry].sort((a, b) => a.bits - b.bits).slice(0, 5)
  const report = {
    kind: 'offline-health-report',
    at: stamp,
    entries: perEntry.length,
    breached,
    weak,
    fair,
    strong,
    reuseGroups,
    reusedEntries,
    score,
    band,
    worst,
    offline: true,
  }
  const L = []
  L.push('UCrypt offline health report — computed entirely on this device (no network was used; nothing left the device)')
  L.push(`at: ${stamp}`)
  L.push(`entries: ${perEntry.length} · score: ${score}/100 (${band})`)
  L.push(`breached: ${breached} · weak (<40 bits): ${weak} · fair (40–59): ${fair} · strong (≥60): ${strong}`)
  L.push(`reuse: ${reuseGroups} password group(s) shared across ${reusedEntries} entr${reusedEntries === 1 ? 'y' : 'ies'}`)
  if (worst.length) {
    L.push('weakest first (passwords NEVER printed — entropy and breach state only):')
    for (const w of worst) {
      L.push(`  ${w.breached ? 'BREACHED' : 'ok     '} ${String(w.bits).padStart(3, ' ')} bits · ${w.domain}${w.user ? ` (${w.user})` : ''}`)
    }
  }
  L.push('end of report')
  return { ok: true, report, text: L.join('\n') }
}
