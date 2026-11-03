/**
 * UCrypt — Vault health report builder (v2.5.0).
 *
 * Pure, dependency-free: takes the login entries and an analyze function
 * (lib/analyzer.js analyzePassword) and produces an aggregate health report
 * for the popup's HEALTH tab. No chrome.* usage — testable in Node.
 *
 * What the report measures (all computed locally, nothing leaves the device):
 *   - breached  — passwords found in the offline breach set (or ≥8-char
 *                 breached substrings, per the analyzer's rule)
 *   - weak      — effective entropy below WEAK_BITS (40), not already breached
 *   - reuse     — the same password used on more than one entry (grouped)
 *   - buckets   — Very Weak / Weak / Fair / Strong / Excellent tallies
 *   - score     — 0..100, deterministic: start at 100, −25 per breached,
 *                 −10 per weak, −6 per reused entry beyond the first in its
 *                 group, floored at 0
 *   - worst     — the lowest-entropy entries first (what to fix first)
 *
 * Exports:
 *   WEAK_BITS
 *   buildHealthReport(entries, analyzePassword) -> report
 *   healthBand(score) -> { label, color }
 */

export const WEAK_BITS = 40

const BANDS = [
  { min: 85, label: 'Excellent', color: '#10b981' },
  { min: 70, label: 'Good', color: '#84cc16' },
  { min: 50, label: 'Fair', color: '#eab308' },
  { min: 0, label: 'Needs attention', color: '#ef4444' },
]

/** Map a 0..100 health score to a human band. */
export function healthBand(score) {
  const s = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0
  return BANDS.find(b => s >= b.min) || BANDS[BANDS.length - 1]
}

function maskUser(u) {
  const s = String(u || '')
  if (!s) return '(no username)'
  if (s.length <= 2) return s[0] + '•'.repeat(Math.max(0, s.length - 1))
  return s[0] + '•'.repeat(s.length - 2) + s[s.length - 1]
}

/**
 * Build the aggregate report.
 *
 * @param {Array<{domain, username, password, type?}>} entries — LOGIN entries
 *        only (callers must exclude TOTP token entries; getLoginEntries() does).
 * @param {(pw: string) => {effective:number, breached:boolean, len:number, patterns:string[]} | null} analyzePassword
 */
export function buildHealthReport(entries, analyzePassword) {
  const list = Array.isArray(entries) ? entries.filter(e => e && typeof e === 'object') : []
  const total = list.length

  if (total === 0) {
    return {
      total: 0, score: 100, band: healthBand(100), avgBits: 0, stale: 0,
      breached: 0, weak: 0, reusedEntries: 0, reuseGroups: [],
      buckets: { veryWeak: 0, weak: 0, fair: 0, strong: 0, excellent: 0 },
      worst: [], generatedAt: Date.now(),
    }
  }

  let breachedN = 0
  let weakN = 0
  let staleN = 0
  let bitsSum = 0
  let bitsCount = 0
  const buckets = { veryWeak: 0, weak: 0, fair: 0, strong: 0, excellent: 0 }
  const analyzed = []
  // R86 (§6 vault health panel): STALE — the password has not been updated in
  // over 180 days. Local-only signal (updatedAt rides the entry; entries that
  // never recorded one are NOT counted stale — honest absence, not a guess).
  const STALE_MS = 180 * 24 * 60 * 60 * 1000

  // R135-F3 (the R130-F1 class at the dashboard's door): a THROWING analyzer
  // (a hostile or broken corpus) degrades to "no analysis" for that entry —
  // the dashboard never crashes on the analysis layer.
  const safeAnalyze = (pw) => {
    try { return typeof analyzePassword === 'function' ? analyzePassword(String(pw || '')) : null } catch { return null }
  }
  for (const e of list) {
    const a = safeAnalyze(e.password)
    const bits = a ? a.effective : 0
    const isBreached = !!(a && a.breached)
    const isStale = !!(e.updatedAt && Number(e.updatedAt) > 0 && (Date.now() - Number(e.updatedAt)) > STALE_MS)
    if (isStale) staleN++
    if (isBreached) breachedN++
    else if (a && a.effective < WEAK_BITS) weakN++

    if (!a || a.effective < 28) buckets.veryWeak++
    else if (a.effective < 40) buckets.weak++
    else if (a.effective < 60) buckets.fair++
    else if (a.effective < 80) buckets.strong++
    else buckets.excellent++

    if (a) { bitsSum += a.effective; bitsCount++ }
    analyzed.push({ entry: e, bits, isBreached, isStale, reasons: a ? a.patterns : [] })
  }

  // Password reuse — group by exact password, keep groups of 2+.
  const byPassword = new Map()
  for (const { entry } of analyzed) {
    const pw = String(entry.password || '')
    if (!pw) continue
    if (!byPassword.has(pw)) byPassword.set(pw, [])
    byPassword.get(pw).push(entry)
  }
  const reuseGroups = []
  for (const [pw, group] of byPassword) {
    if (group.length < 2) continue
    reuseGroups.push({
      count: group.length,
      sites: group.map(e => e.domain || '(no site)'),
      entries: group.map(e => ({ domain: e.domain || '(no site)', username: e.username || '' })),
    })
  }
  reuseGroups.sort((a, b) => b.count - a.count)
  const reusedEntries = reuseGroups.reduce((n, g) => n + g.count, 0)
  const reusedPenaltyEntries = reuseGroups.reduce((n, g) => n + (g.count - 1), 0)

  // Worst-first list (cap 6) — breached entries always sort before the rest.
  const worst = [...analyzed]
    .sort((a, b) => {
      if (a.isBreached !== b.isBreached) return a.isBreached ? -1 : 1
      return a.bits - b.bits
    })
    .slice(0, 6)
    .map(({ entry, bits, isBreached, reasons }) => ({
      domain: entry.domain || '(no site)',
      username: maskUser(entry.username),
      bits: Math.round(bits * 10) / 10,
      breached: isBreached,
      reasons: (reasons || []).slice(0, 3),
    }))

  const score = Math.max(0, Math.round(
    100
    - 25 * breachedN
    - 10 * weakN
    - 6 * reusedPenaltyEntries
  ))

  return {
    total,
    score,
    band: healthBand(score),
    avgBits: bitsCount ? Math.round((bitsSum / bitsCount) * 10) / 10 : 0,
    breached: breachedN,
    weak: weakN,
    reusedEntries,
    reuseGroups,
    buckets,
    worst,
    generatedAt: Date.now(),
  }
}

/**
 * UCrypt — R134 §6 — BRAVE CHERRY-PICK, BATCH 2: PASSWORD HEALTH
 * (the options-page dashboard, LOCAL-ONLY).
 *
 * The three heuristics, exactly as the CEO commanded:
 *   weak   — the entropy model (effective entropy below WEAK_BITS)
 *   reused — the same credential across hosts (exact-password groups)
 *   stale  — unchanged > 365 days (the §6 threshold; entries that never
 *            recorded updatedAt are NOT counted — honest absence, not a guess)
 *
 * NO NETWORK CALLS, NO BREACH LOOKUPS (that would violate the
 * no-surveillance law unless the CEO commands it separately — documented as
 * a CEO option, not implemented unilaterally). The breach set's offline
 * counts remain the popup tab's own signal; this dashboard is the three
 * heuristics + drill-in + one-tap remediation (each row carries the entry
 * `id` so options.js can open the item editor in one tap).
 *
 * PURE — no DOM, no chrome.*; the clock is injectable (deterministic tests).
 *
 * @param {Array<{id?, domain, username, password, updatedAt?}>} entries
 * @param {(pw: string) => {effective:number, len:number, patterns:string[]} | null} analyzePassword
 * @param {{now?: number, staleDays?: number}} [opts]
 * @returns {{counts:{weak:number, reused:number, stale:number, total:number},
 *            weakList:Array, reuseGroups:Array, staleList:Array, staleDays:number}}
 */
export function buildPasswordHealthDashboard(entries, analyzePassword, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now()
  const staleDays = Number.isFinite(opts.staleDays) ? opts.staleDays : 365
  const STALE_MS = staleDays * 24 * 60 * 60 * 1000
  const list = (Array.isArray(entries) ? entries : []).filter((e) => e && typeof e === 'object')

  const weakList = []
  const staleList = []
  // R135-F3 (the R130-F1 class at the dashboard's door): a THROWING analyzer
  // (a hostile or broken corpus) degrades to "no analysis" for that entry —
  // the dashboard never crashes on the analysis layer.
  const safeAnalyze = (pw) => {
    try { return typeof analyzePassword === 'function' ? analyzePassword(String(pw || '')) : null } catch { return null }
  }
  for (const e of list) {
    const a = safeAnalyze(e.password)
    const bits = a ? a.effective : 0
    if (a && a.effective < WEAK_BITS) {
      weakList.push({
        id: e.id || '',
        domain: e.domain || '(no site)',
        username: maskUser(e.username),
        bits: Math.round(bits * 10) / 10,
        reasons: (a.patterns || []).slice(0, 3),
      })
    }
    const updatedAt = Number(e.updatedAt) || 0
    if (updatedAt > 0 && now - updatedAt > STALE_MS) {
      staleList.push({
        id: e.id || '',
        domain: e.domain || '(no site)',
        username: maskUser(e.username),
        days: Math.floor((now - updatedAt) / (24 * 60 * 60 * 1000)),
      })
    }
  }
  weakList.sort((a, b) => a.bits - b.bits)

  // reuse — the same credential across hosts (exact password, groups of 2+)
  const byPassword = new Map()
  for (const e of list) {
    const pw = String(e.password || '')
    if (!pw) continue
    if (!byPassword.has(pw)) byPassword.set(pw, [])
    byPassword.get(pw).push(e)
  }
  const reuseGroups = []
  for (const [, group] of byPassword) {
    if (group.length < 2) continue
    reuseGroups.push({
      count: group.length,
      entries: group.map((e) => ({ id: e.id || '', domain: e.domain || '(no site)', username: maskUser(e.username) })),
    })
  }
  reuseGroups.sort((a, b) => b.count - a.count)

  return {
    counts: {
      weak: weakList.length,
      reused: reuseGroups.reduce((n, g) => n + g.count, 0),
      stale: staleList.length,
      total: list.length,
    },
    weakList,
    reuseGroups,
    staleList,
    staleDays,
    localOnly: true,
    generatedAt: now,
  }
}
