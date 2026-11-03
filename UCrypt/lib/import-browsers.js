/**
 * UCrypt — lib/import-browsers.js (R133, §5.2 — THE BRAVE-GRADE IMPORT)
 *
 * "Import from other browsers" (the CEO's command): drag-and-drop CSV
 * import with parsers for every major export format, an import preview
 * table, host+username dedupe, and a merge report (N imported / N
 * duplicates / N conflicts) — then into the vault, where the vault's own
 * mutation fires the chain replication (law 0.49's auto-sync lane): the
 * imported data appears on EVERY machine within one cycle. That is the
 * power move.
 *
 * PURE MODULE (reuses lib/csv-import.js's RFC-4180 parser) — battery-pinned
 * (tests/r133-round.test.mjs IMPORT-1..6).
 */
import { parseCsv, mapHeader } from './csv-import.js'

// --- The supported families -------------------------------------------------

export const BROWSER_FAMILIES = [
  { id: 'chrome', name: 'Chrome', deepLink: 'chrome://settings/passwords' },
  { id: 'brave', name: 'Brave', deepLink: 'brave://settings/passwords' },
  { id: 'edge', name: 'Edge', deepLink: 'edge://settings/passwords' },
  { id: 'opera', name: 'Opera', deepLink: 'opera://settings/passwords' },
  { id: 'vivaldi', name: 'Vivaldi', deepLink: 'vivaldi://settings/passwords' },
  { id: 'firefox', name: 'Firefox', deepLink: 'about:logins' },
  { id: 'safari', name: 'Safari', deepLink: 'x-apple.systempreferences:com.apple.Passwords-Settings.extension' },
  { id: 'bitwarden', name: 'Bitwarden', deepLink: 'https://bitwarden.com/help/export-your-data/' },
  { id: '1password', name: '1Password', deepLink: 'https://support.1password.com/export/' },
  { id: 'lastpass', name: 'LastPass', deepLink: 'https://support.lastpass.com/help/export-your-passwords-lastpass' },
  { id: 'generic', name: 'Generic CSV', deepLink: '' },
]

/** The guided export steps for a family (the per-browser deep link + the
 * exact menu names) — the preview's side card renders these verbatim. */
export function exportGuide(familyId, detectedName = '') {
  const fam = BROWSER_FAMILIES.find((f) => f.id === familyId) || BROWSER_FAMILIES[BROWSER_FAMILIES.length - 1]
  const stepsByFamily = {
    chromium: [
      'Open $DL$ (copy it into the address bar).',
      'Next to "Saved Passwords" choose Export (Chrome/Brave/Edge: the ⋮ menu; Vivaldi/Opera: the … menu).',
      'Confirm with your device sign-in and save the passwords.csv file.',
      'Drop the file below — nothing leaves this device.',
    ],
    firefox: [
      'Open $DL$ (copy it into the address bar).',
      'Click the ⋯ menu at the top of the Logins list → "Export Logins".',
      'Confirm and save the passwords.csv file.',
      'Drop the file below — nothing leaves this device.',
    ],
    safari: [
      'Open Settings → Passwords (System Settings on macOS).',
      'Choose ⋯ → "Export All Passwords…".',
      'Confirm with your device sign-in and save the .csv file.',
      'Drop the file below — nothing leaves this device.',
    ],
    manager: [
      'Open the manager\u2019s export page ($DL$).',
      'Export as CSV (Bitwarden: Vault → Tools → "Export vault" → .csv; 1Password: File → Export → All items → CSV; LastPass: Account Options → Advanced → Export).',
      'Save the .csv file.',
      'Drop the file below — nothing leaves this device.',
    ],
    generic: [
      'Your CSV needs at least these columns: name, url, username, password.',
      'Save the .csv file.',
      'Drop the file below — nothing leaves this device.',
    ],
  }
  const group = ['firefox', 'safari'].includes(fam.id) ? fam.id : ['bitwarden', '1password', 'lastpass'].includes(fam.id) ? 'manager' : fam.id === 'generic' ? 'generic' : 'chromium'
  const who = detectedName && detectedName !== fam.name ? ` (${detectedName} detected — steps shown for ${fam.name})` : ''
  return {
    family: fam.id,
    name: fam.name,
    deepLink: fam.deepLink,
    brandNote: who,
    steps: stepsByFamily[group].map((s) => s.replace('$DL$', fam.deepLink || 'the export page')),
  }
}

// --- Format detection --------------------------------------------------------

/** Detect the export format from the header row (case-insensitive, BOM-safe).
 * Returns { format, family } — 'generic' with confidence when nothing exact. */
export function detectFormat(rows) {
  if (!Array.isArray(rows) || !rows.length) return { format: 'empty', family: 'generic' }
  const head = (rows[0] || []).map((h) => String(h || '').trim().toLowerCase().replace(/^\ufeff/, ''))
  const has = (...names) => names.some((n) => head.includes(n))
  const startsWith = (...names) => names.some((n) => head[0] === n)
  // Bitwarden: folder,favorite,type,name,notes,fields,reprompt,login_uri,…
  if (head.includes('login_uri') && head.includes('login_username')) return { format: 'bitwarden', family: 'bitwarden' }
  // LastPass: url,username,password,extra,name,grouping,fav
  if (head.includes('grouping') && head.includes('extra') && head.includes('fav')) return { format: 'lastpass', family: 'lastpass' }
  // Firefox: "url","username","password","httpRealm","formActionOrigin",…
  if (head.includes('httprealm') || head.includes('formactionorigin')) return { format: 'firefox', family: 'firefox' }
  // Safari: Title,URL,Username,Password,Notes,OTPAuth (checked BEFORE 1Password —
  // the OTPAuth column is the discriminator; both start with Title,Url,…)
  if (head.includes('otpauth')) return { format: 'safari', family: 'safari' }
  // 1Password CSV: Title,Url,Username,Password,Notes (or "Title,Url,Username,Password")
  if (startsWith('title') && head.includes('url') && head.includes('username') && head.includes('password')) return { format: '1password', family: '1password' }
  // Chromium family: name,url,username,password,(note) — identical headers,
  // so the FAMILY is the detected browser's, the FORMAT is the same parser.
  if (has('url', 'website', 'web_site', 'origin') && has('username', 'login_username', 'user') && has('password', 'login_password')) {
    return { format: 'chromium', family: 'chrome' }
  }
  if (has('url', 'website', 'origin') && (has('username', 'user') || has('password'))) return { format: 'generic', family: 'generic' }
  return { format: 'unknown', family: 'generic' }
}

// --- Normalization -----------------------------------------------------------

function domainFromUrl(raw) {
  const s = String(raw || '').trim()
  if (!s) return ''
  try {
    const u = new URL(s.includes('://') ? s : 'https://' + s)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    return u.hostname.toLowerCase()
  } catch {
    return ''
  }
}

/** Parse + normalize a CSV into candidate vault entries. Skipped rows carry
 * their typed reason (the preview table shows them — never a silent drop). */
export function importFromCsv(text, opts = {}) {
  const { rows } = parseCsv(typeof text === 'string' ? text : '')
  const fmt = detectFormat(rows)
  const { map } = mapHeader(rows[0] || [])
  const entries = []
  const skipped = []
  if (!map || (!map.url && !map.username && !map.password)) {
    return { format: fmt, entries, skipped: [{ line: 1, reason: 'no recognizable columns (need url / username / password)' }] }
  }
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i] || []
    const get = (f) => (map[f] != null ? String(row[map[f]] ?? '').trim() : '')
    const url = get('url')
    const username = get('username')
    const password = get('password')
    const line = i + 1
    if (!url && !username && !password) continue // a fully blank row is not data
    const domain = domainFromUrl(url)
    if (!domain) {
      skipped.push({ line, reason: 'not an http(s) site (android app, file, browser page) — skipped' })
      continue
    }
    if (!username && !password) {
      skipped.push({ line, reason: 'no username and no password — skipped' })
      continue
    }
    entries.push({
      type: 'login',
      domain,
      url,
      username,
      password,
      title: get('name') || domain,
      notes: get('note'),
      ...(fmt.format === 'bitwarden' && get('note') && get('note').match(/otpauth:\/\//) ? { } : {}),
    })
  }
  return { format: fmt, entries, skipped }
}

// --- Dedupe + merge report ---------------------------------------------------

/** The dedupe key: host + username (the CEO-commanded rule). */
export function dedupeKey(entry) {
  return `${String(entry.domain || '').toLowerCase()}|${String(entry.username || '').toLowerCase()}`
}

/** Dedupe within the import (the same pair twice keeps the FIRST, later rows
 * become duplicates). Returns { unique, duplicates } */
export function dedupeEntries(entries) {
  const seen = new Map()
  const duplicates = []
  for (const e of Array.isArray(entries) ? entries : []) {
    const k = dedupeKey(e)
    if (seen.has(k)) duplicates.push(e)
    else seen.set(k, e)
  }
  return { unique: Array.from(seen.values()), duplicates }
}

/** THE MERGE REPORT against the existing vault entries:
 *   imported   — not present (host+username) in the vault
 *   duplicates — present with the SAME password (kept as-is)
 *   conflicts  — present with a DIFFERENT password (the vault copy wins;
 *                the row is listed for review — never silently overwritten)
 * entries must be the DEDUPED list (dedupeEntries first). */
export function mergeReport(existingEntries, incoming) {
  const existing = new Map()
  for (const e of Array.isArray(existingEntries) ? existingEntries : []) {
    existing.set(dedupeKey(e), e)
  }
  const imported = []
  const duplicates = []
  const conflicts = []
  for (const e of Array.isArray(incoming) ? incoming : []) {
    const k = dedupeKey(e)
    const cur = existing.get(k)
    if (!cur) imported.push(e)
    else if (String(cur.password) === String(e.password)) duplicates.push(e)
    else conflicts.push({ incoming: e, existing: { domain: cur.domain, username: cur.username } })
  }
  return {
    imported,
    duplicates,
    conflicts,
    counts: {
      imported: imported.length,
      duplicates: duplicates.length,
      conflicts: conflicts.length,
      total: imported.length + duplicates.length + conflicts.length,
    },
  }
}

/** The preview table's model (the UI renders rows verbatim; no secrets beyond
 * what the user just handed the page — masked by the caller's renderer). */
export function previewModel(report) {
  return {
    counts: report.counts,
    importedRows: report.imported.map((e) => ({ domain: e.domain, username: e.username, title: e.title })),
    conflictRows: report.conflicts.map((c) => ({ domain: c.incoming.domain, username: c.incoming.username })),
  }
}
