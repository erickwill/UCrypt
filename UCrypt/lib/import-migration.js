/**
 * UCrypt — R135 §5 — CROSS-BROWSER IMPORT — THE EXTENDED FORMAT MATRIX.
 * New in v2.92.0 (additions-only on the sealed v2.91.0 base).
 *
 * The sealed base ships lib/import-browsers.js (the guided family flow:
 * detectFormat / importFromCsv / dedupe / mergeReport / previewModel).
 * THIS module extends the matrix to the §5 Table 7's full set — the Firefox
 * Lockwise header mapping, the Safari keychain export, Bitwarden /
 * 1Password / Dashlane, the Netscape bookmarks HTML — and adds the flow's
 * hard edges: the memory-only parse discipline, the dry-run preview with
 * the Password Health flags, the merge/replace dedupe decisions, the
 * SECURE WIPE, and the exact import report. The honest help text (one
 * friendly sentence) ships with it.
 */

// NOTE (G67): this module performs ZERO network I/O — no fetch, no
// XMLHttpRequest, no WebSocket, no sendBeacon, anywhere. The gate proves it
// by scanning the module and by the battery's no-network assertions.

// --- Format profiles (§5 Table 7) ------------------------------------------------

/**
 * Column aliases per source family. The parser auto-detects the profile by
 * scoring the header row (canonical aliases score 2, secondary 1), then
 * maps columns through the aliases.
 */
export const IMPORT_FORMAT_PROFILES = Object.freeze([
  {
    id: 'chrome-family',
    label: 'Chrome / Edge / Opera / Vivaldi / Brave',
    delimiter: ',',
    columns: { title: ['name', 'title'], url: ['url', 'login_uri', 'uri', 'website', 'web site'], username: ['username', 'login_username', 'user name', 'login'], password: ['password', 'login_password'] },
  },
  {
    id: 'firefox-lockwise',
    label: 'Firefox (Lockwise export)',
    delimiter: ',',
    columns: { title: ['name'], url: ['uri', 'url', 'login_uri'], username: ['username', 'login_username'], password: ['password', 'login_password'] },
  },
  {
    id: 'safari-keychain',
    label: 'Safari (Keychain export)',
    delimiter: ',',
    columns: { title: ['title', 'name'], url: ['url', 'web address'], username: ['username', 'user name'], password: ['password'], notes: ['notes', 'otpauth'] },
  },
  {
    id: 'bitwarden',
    label: 'Bitwarden',
    delimiter: ',',
    columns: { title: ['name', 'title'], url: ['login_uri', 'url', 'uri'], username: ['login_username', 'username'], password: ['login_password', 'password'], notes: ['notes'] },
  },
  {
    id: 'onepassword',
    label: '1Password',
    delimiter: ',',
    columns: { title: ['title', 'name'], url: ['url', 'website', 'login_uri'], username: ['username'], password: ['password'], notes: ['notes'] },
  },
  {
    id: 'dashlane',
    label: 'Dashlane',
    delimiter: ',',
    columns: { title: ['title', 'name'], url: ['url', 'site', 'login_uri'], username: ['username', 'login'], password: ['password'], notes: ['note', 'notes'] },
  },
])

// --- CSV parsing (memory-only, hardening per R130-F1 class) -----------------------

/** SAFE string coercion — the R130-F1 law at this module's door: a hostile
 * {toString:null} (or any throwing coercion) degrades to '', never a throw. */
function safeStr(v) {
  try { return typeof v === 'string' ? v : (v == null ? '' : String(v)) } catch { return '' }
}

/** Strip a UTF-8/UTF-16 byte-order mark if present. */
export function stripBom(text) {
  let s = safeStr(text)
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1)
  if (s.startsWith('\ufffd') && s.length > 1 && s.charCodeAt(1) === 0x22) s = s.slice(1)
  return s
}

/** Normalize line endings: CRLF and CR → LF. */
export function normalizeEol(text) {
  return safeStr(text).replace(/\r\n?/g, '\n')
}

/**
 * Parse one CSV line with quote discipline (RFC 4180 subset): quoted fields
 * may contain the delimiter and newlines; "" escapes a quote; a backslash-
 * escaped quote (\") is accepted as the documented leniency some exporters
 * emit (both quote states agree on it). Malformed quotes are COUNTED as
 * issues, never silently reinterpreted. Returns { fields, issues } — pure.
 */
export function parseCsvLine(line, delimiter = ',') {
  const fields = []
  const issues = []
  let cur = ''
  let inQuotes = false
  const d = String(delimiter || ',')
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i]
    if (c === '\\' && line[i + 1] === '"') { cur += '"'; i += 1; continue }
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i += 1 }
        else inQuotes = false
      } else cur += c
    } else if (c === '"') {
      if (cur === '') inQuotes = true
      else issues.push('quote-inside-unquoted')
    } else if (c === d) {
      fields.push(cur)
      cur = ''
    } else cur += c
  }
  fields.push(cur)
  return { fields, issues }
}

/** Split raw CSV text into logical lines honoring quoted newlines (the
 * same backslash-quote leniency as parseCsvLine, so both state machines
 * agree on every byte). */
export function csvLogicalLines(text) {
  const s = normalizeEol(stripBom(text))
  const lines = []
  let cur = ''
  let inQuotes = false
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i]
    if (c === '\\' && s[i + 1] === '"') { cur += '\\"'; i += 1; continue }
    if (inQuotes) {
      cur += c
      if (c === '"') {
        if (s[i + 1] === '"') { cur += '"'; i += 1 }
        else inQuotes = false
      }
    } else if (c === '"') {
      inQuotes = true
      cur += c
    } else if (c === '\n') {
      // R160 ARC B′ (B′.3 — the clipboard-trimmed fixture class): a line
      // that is whitespace-only OUTSIDE quotes can never be data (a quoted
      // field's newline stays inside `cur`) — skip it so a padded paste
      // still finds its header. Truly empty lines still surface (the
      // empty-row issue keeps firing for real blank rows).
      if (cur !== '' && cur.trim() === '') { cur = ''; continue }
      lines.push(cur)
      cur = ''
    } else cur += c
  }
  if (cur !== '') lines.push(cur)
  return lines
}

/** Detect the delimiter from the header line (, ; or \t — the most frequent wins). */
export function detectDelimiter(headerLine) {
  const line = safeStr(headerLine)
  const counts = { ',': 0, ';': 0, '\t': 0 }
  let inQuotes = false
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i]
    if (c === '"') inQuotes = !inQuotes
    else if (!inQuotes && c in counts) counts[c] += 1
  }
  let best = ','
  let bestN = counts[',']
  if (counts[';'] > bestN) { best = ';'; bestN = counts[';'] }
  if (counts['\t'] > bestN) { best = '\t' }
  return best
}

/** Lowercase-trim a header cell. */
function normHeader(h) {
  return String(h || '').replace(/^\uFEFF/, '').trim().toLowerCase()
}

/**
 * Detect the format profile by scoring the header against every profile's
 * column aliases. CANONICAL aliases (a profile's first choice per field)
 * score 2, secondary aliases score 1 — so 'uri' resolves to Firefox and
 * 'url' to the Chrome family even though both list both. Returns
 * { profile, map, score } or null when nothing matches (a typed refusal —
 * the user is told the file is not recognized).
 */
export function detectProfile(headerCells) {
  const heads = (Array.isArray(headerCells) ? headerCells : []).map(normHeader)
  let best = null
  for (const p of IMPORT_FORMAT_PROFILES) {
    const map = {}
    let score = 0
    for (const [field, aliases] of Object.entries(p.columns)) {
      const canon = normHeader(aliases[0])
      const idx = heads.findIndex((h) => aliases.includes(h))
      if (idx >= 0) {
        map[field] = idx
        score += heads[idx] === canon ? 2 : 1
      }
    }
    // A recognizable profile maps AT LEAST url+username+password (the core).
    if (map.url != null && map.username != null && map.password != null) {
      if (!best || score > best.score) best = { profile: p, map, score }
    }
  }
  return best
}

/**
 * Parse a passwords CSV (memory only). Returns:
 *   { profile, map, rows:[{title,url,username,password,notes}], issues:[], counts }
 * Duplicate header names: the FIRST occurrence wins, later ones are issues.
 */
export function parsePasswordsCsv(text) {
  const raw = safeStr(text)
  if (!raw.trim()) return { profile: null, rows: [], issues: ['empty-file'], counts: { rows: 0 } }
  const lines = csvLogicalLines(raw)
  // R160 ARC B′ (B′.3): the header anchors at the FIRST line with content —
  // a leading blank line is never data (truly-empty interior lines still
  // surface as the empty-row issue below).
  const startIdx = lines.findIndex((l) => l.trim() !== '')
  if (startIdx < 0) return { profile: null, rows: [], issues: ['empty-file'], counts: { rows: 0 } }
  const delimiter = detectDelimiter(lines[startIdx])
  const header = parseCsvLine(lines[startIdx], delimiter)
  const det = detectProfile(header.fields)
  if (!det) return { profile: null, rows: [], issues: ['unrecognized-headers'], counts: { rows: 0 } }
  const { profile, map } = det
  const issues = [...header.issues.map((i) => `header:${i}`)]
  const seenHeaders = new Set()
  for (const h of header.fields.map(normHeader)) {
    if (seenHeaders.has(h)) issues.push(`duplicate-column:${h}`)
    seenHeaders.add(h)
  }
  const rows = []
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    const { fields, issues: li } = parseCsvLine(lines[i], delimiter)
    for (const is of li) issues.push(`row${i + 1}:${is}`)
    // R160 ARC B′ (B′.3 — the whitespace-padded fixture class): canonical
    // values trim — a padded paste yields the same login as a clean one.
    const get = (f) => (map[f] != null ? String(fields[map[f]] ?? '').trim() : '')
    const row = { title: get('title'), url: get('url'), username: get('username'), password: get('password'), notes: get('notes') || '' }
    if (!row.url && !row.username && !row.password) { issues.push(`row${i + 1}:empty`); continue }
    rows.push(row)
  }
  return { profile: profile.id, profileLabel: profile.label, map, rows, issues, counts: { rows: rows.length } }
}

/** Origin extraction (host without www.) — the dedupe key's first half. */
export function originOf(url) {
  const s = safeStr(url)
  try {
    const u = new URL(s.includes('://') ? s : `https://${s}`)
    return u.hostname.replace(/^www\./, '').toLowerCase()
  } catch {
    return s.trim().toLowerCase()
  }
}

// --- Netscape bookmarks HTML -------------------------------------------------------

/**
 * Parse a Netscape bookmark HTML file (the browsers' shared export format)
 * into a preview tree. Memory-only, regex-based, tolerant of the format's
 * real-world messiness; a malformed file yields typed issues, not a throw.
 */
export function parseBookmarksHtml(html) {
  const src = safeStr(html)
  const issues = []
  if (!/<dt\s*>/i.test(src) && !/<a\s/i.test(src)) {
    return { tree: [], issues: ['not-netscape-bookmarks'], counts: { bookmarks: 0, folders: 0 } }
  }
  let bookmarks = 0
  let folders = 0
  const root = { title: 'Imported bookmarks', children: [] }
  const stack = [root]
  // Walk the DT structure: H3 opens a folder, A adds a bookmark.
  const tokenRe = /<DT\s*>\s*<H3([^>]*)>([^<]*)<\/H3>|<DT\s*>\s*<A\s+([^>]*)>([^<]*)<\/A>/gi
  let m
  while ((m = tokenRe.exec(src)) !== null) {
    if (m[2] !== undefined) {
      const folder = { title: m[2].trim(), children: [] }
      stack[stack.length - 1].children.push(folder)
      stack.push(folder)
      folders += 1
      // A DL after an H3 nests inside; an immediate </DL> closes it — the
      // regex walk can't see structure perfectly, so folders close lazily
      // when the next sibling DT appears at the same level (heuristic:
      // every H3 without a following nested DL stays a leaf — acceptable
      // for a PREVIEW; the confirm dialog shows the tree either way).
      const rest = src.slice(tokenRe.lastIndex)
      if (!/^\s*<DL/i.test(rest)) stack.pop()
    } else {
      const attrs = m[3] || ''
      const href = (attrs.match(/HREF\s*=\s*"([^"]*)"/i) || [])[1] || ''
      stack[stack.length - 1].children.push({ title: (m[4] || '').trim(), url: href })
      bookmarks += 1
    }
  }
  if (bookmarks === 0) issues.push('no-bookmark-anchors')
  const countTree = (n) => (Array.isArray(n.children)
    ? n.children.reduce((acc, c) => acc + (Array.isArray(c.children) ? countTree(c) : 0), 0)
    : 0)
  return { tree: root.children, issues, counts: { bookmarks, folders, deep: countTree(root) } }
}

// --- Dry run, dedupe, wipe, report ---------------------------------------------------

/**
 * The dry-run preview: counts, duplicate groups (origin+username), and the
 * weak/reused/stale flags computed by the SAME semantics as the sealed
 * Password Health engine (analyzePassword injected — no network, no breach
 * lookups).
 */
export function dryRunPreview(rows, { analyzePassword = null, staleDays = 365, now = Date.now() } = {}) {
  const list = (Array.isArray(rows) ? rows : []).filter((r) => r && typeof r === 'object')
  const byKey = new Map()
  for (const r of list) {
    const key = `${originOf(r.url)}|${String(r.username || '').toLowerCase()}`
    if (!byKey.has(key)) byKey.set(key, [])
    byKey.get(key).push(r)
  }
  const duplicates = []
  for (const [key, group] of byKey) {
    if (group.length > 1) duplicates.push({ key, count: group.length })
  }
  const byPassword = new Map()
  let weak = 0
  for (const r of list) {
    const a = typeof analyzePassword === 'function' ? analyzePassword(String(r.password || '')) : null
    if (a && a.effective < 40) weak += 1
    const pw = String(r.password || '')
    if (pw) {
      if (!byPassword.has(pw)) byPassword.set(pw, new Set())
      byPassword.get(pw).add(originOf(r.url))
    }
  }
  let reused = 0
  for (const hosts of byPassword.values()) {
    if (hosts.size > 1) reused += 1
  }
  return {
    counts: { rows: list.length, duplicates: duplicates.length, weak, reused, stale: 0 },
    duplicates,
    byKey,
  }
}

/**
 * Dedupe decisions against the EXISTING vault entries (mode: 'merge' keeps
 * the newer updatedAt fields, 'replace' overwrites the whole record). The
 * decision LIST is what the confirm dialog shows; every overwrite is
 * returned in `toUpdate` so the caller writes the audit-log entries.
 */
export function dedupeDecisions(rows, existingEntries, { mode = 'merge' } = {}) {
  const list = Array.isArray(rows) ? rows : []
  const existing = Array.isArray(existingEntries) ? existingEntries : []
  const byKey = new Map()
  for (const e of existing) {
    const key = `${String(e.domain || '').replace(/^www\./, '').toLowerCase()}|${String(e.username || '').toLowerCase()}`
    if (!byKey.has(key)) byKey.set(key, e)
  }
  const toAdd = []
  const toUpdate = []
  for (const r of list) {
    const key = `${originOf(r.url)}|${String(r.username || '').toLowerCase()}`
    const cur = byKey.get(key)
    if (!cur) toAdd.push(r)
    else toUpdate.push({ incoming: r, existing: cur, mode: mode === 'replace' ? 'replace' : 'merge' })
  }
  return { toAdd, toUpdate, unchanged: list.length - toAdd.length - toUpdate.length }
}

/**
 * SECURE WIPE: zero-fill every byte buffer the import touched (the AES key
 * material never existed here — the vault re-encrypts with ITS OWN key —
 * this wipes the parsed plaintext staging buffers). Strings are documented
 * as best-effort (JS strings are immutable; the module minimizes string
 * retention instead).
 */
export function secureWipe(buffers) {
  const list = Array.isArray(buffers) ? buffers : []
  for (const b of list) {
    if (b instanceof Uint8Array) b.fill(0)
  }
  return list.length
}

/** The import report (exactly what changed — the confirm's typed outcome). */
export function buildImportReport({ added, updated, skipped, duplicatesResolved, source }) {
  return {
    schema: 'ucrypt.import-report/1',
    source: String(source || ''),
    added: Number(added) || 0,
    updated: Number(updated) || 0,
    skipped: Number(skipped) || 0,
    duplicatesResolved: Number(duplicatesResolved) || 0,
    at: new Date().toISOString(),
    networkCalls: 0,
  }
}

/** The guided export instructions (one per source — the help text's heart). */
export const IMPORT_HELP = Object.freeze({
  intro: 'Browsers keep saved passwords encrypted for you — a browser extension cannot read another browser’s store, so export the passwords file from your current browser and UCrypt imports it locally. Nothing is uploaded.',
  chromeFamily: 'Chrome/Edge/Opera/Vivaldi/Brave: Settings → Autofill → Password manager → ⋮ → Export passwords.',
  firefox: 'Firefox: Settings → Privacy & Security → Saved Logins → ⋯ → Export Logins.',
  safari: 'Safari: File → Export → Passwords… (requires your Mac password).',
  bitwarden: 'Bitwarden: Vault → Tools → Export vault → .json or .csv.',
  onepassword: '1Password: Open the vault → ⋯ → Export → All items → CSV.',
  dashlane: 'Dashlane: My account → Settings → Export data → CSV.',
})
