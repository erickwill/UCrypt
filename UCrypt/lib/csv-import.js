/**
 * UCrypt — Browser CSV import (v2.6.0).
 *
 * Production migration path FROM other password managers (the same door
 * Brave/Chrome/Edge/Firefox users already know): export a CSV there, import
 * it here. Everything happens locally — the file never leaves the device.
 *
 * Supported export dialects (header aliases, case-insensitive, BOM-tolerant):
 *   - Chrome / Brave / Edge : name, url, username, password, note
 *   - Firefox               : url, username, password, httpRealm, formActionOrigin, guid, timeCreated, …
 *   - Bitwarden-style       : folder, favorite, type, name, notes, login_uri, login_username, login_password
 *
 * Import policy (deliberately conservative — never silently overwrites):
 *   - Rows are mapped to { domain, username, password } (domain from the URL).
 *   - Same (domain, username) already in the vault with the SAME password → duplicate, skipped.
 *   - Same (domain, username) with a DIFFERENT password → conflict, skipped and listed
 *     for manual review (the vault copy may be newer than the browser export).
 *   - Non-http(s) origins (android:// apps, file://, chrome://) → skipped with a reason.
 */

// --- Canonical fields and header aliases -----------------------------------

const HEADER_ALIASES = {
  url: ['url', 'login_uri', 'uri', 'origin', 'website', 'web_site', 'webpage', 'site', 'hostname', 'server'],
  username: ['username', 'login_username', 'user', 'user_name', 'email', 'account', 'userid', 'user id', 'login_name'],
  password: ['password', 'login_password', 'pass', 'passwd', 'pwd'],
  name: ['name', 'title', 'label'],
  note: ['note', 'notes', 'comment', 'extra'],
}

const CANONICAL = Object.keys(HEADER_ALIASES)

/**
 * Parse raw CSV text (RFC-4180-ish: quoted fields, escaped "" quotes,
 * embedded commas/newlines, CRLF/CR/LF line endings, UTF-8 BOM).
 * Returns { rows: string[][] } — no header interpretation here.
 */
export function parseCsv(text) {
  if (typeof text !== 'string') return { rows: [] }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1) // strip BOM

  const rows = []
  let row = []
  let field = ''
  let inQuotes = false

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++ }
        else inQuotes = false
      } else {
        field += ch
      }
      continue
    }
    if (ch === '"') { inQuotes = true; continue }
    if (ch === ',') { row.push(field); field = ''; continue }
    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++
      row.push(field); field = ''
      rows.push(row); row = []
      continue
    }
    field += ch
  }
  // Final field/row (files may not end with a newline)
  row.push(field)
  rows.push(row)

  // Drop trailing completely-empty rows (trailing newline) — keep interior ones
  while (rows.length > 0 && rows[rows.length - 1].every(c => c === '')) rows.pop()
  return { rows }
}

/**
 * Map a header row to canonical field indexes.
 * Returns { map: { url: idx, username: idx, … }, unknown: string[] }.
 * Missing canonical fields are simply absent from the map.
 */
export function mapHeader(headerCells) {
  const map = {}
  const unknown = []
  const taken = new Set()
  const cells = (headerCells || []).map(c => String(c || '').trim().toLowerCase().replace(/^\ufeff/, ''))

  for (const field of CANONICAL) {
    for (let i = 0; i < cells.length; i++) {
      if (taken.has(i)) continue
      if (HEADER_ALIASES[field].includes(cells[i])) {
        map[field] = i
        taken.add(i)
        break
      }
    }
  }
  for (let i = 0; i < cells.length; i++) {
    if (!taken.has(i) && cells[i] !== '') unknown.push(cells[i])
  }
  return { map, unknown }
}

/**
 * URL → login domain. Returns '' for anything that is not a http(s) web
 * origin. android:// app origins, file://, chrome:// etc. are rejected.
 */
export function csvDomain(urlStr) {
  const raw = String(urlStr || '').trim()
  if (!raw) return ''
  if (/^android:\/\//i.test(raw)) return ''
  try {
    const u = new URL(raw)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    if (!u.hostname) return ''
    return u.hostname.replace(/^www\./i, '')
  } catch {
    // Bare hostnames ("example.com") are tolerated — exported files
    // sometimes contain them. Anything with spaces or bad chars is not.
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(raw)) return raw.toLowerCase()
    return ''
  }
}

function rowToCandidate(cells, map) {
  const get = (field) => {
    const idx = map[field]
    return idx === undefined ? '' : String(cells[idx] ?? '').trim()
  }
  const domain = csvDomain(get('url'))
  const username = get('username')
  const password = get('password')
  return { domain, username, password }
}

/**
 * Build the import plan: parse the CSV, validate every row and classify it
 * against the current vault entries. Pure — no chrome.* calls, no I/O.
 *
 * @param {string} text            raw CSV file contents
 * @param {Array}  existingEntries current vault entries [{domain, username, password}]
 * @returns {ok, entries, stats, conflicts, skipped, error}
 */
export function buildImportPlan(text, existingEntries) {
  const existing = Array.isArray(existingEntries) ? existingEntries : []
  const existingMap = new Map()
  for (const e of existing) {
    if (e && e.domain) existingMap.set(`${e.domain}::${e.username || ''}`, e)
  }

  const { rows } = parseCsv(text)
  if (rows.length === 0) {
    return { ok: false, error: 'The file appears to be empty' }
  }

  const { map } = mapHeader(rows[0])
  if (map.url === undefined || map.password === undefined) {
    return {
      ok: false,
      error: 'No "url" and "password" columns found — this does not look like a browser password export (Chrome/Brave/Edge: name, url, username, password, note)',
    }
  }

  const entries = []
  const conflicts = []
  const skipped = []
  const stats = { total: 0, added: 0, duplicates: 0, conflicts: 0, skipped: 0, invalid: 0 }
  const seen = new Map() // within-file dedupe: key → {domain, username, password}

  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r]
    if (cells.every(c => String(c || '').trim() === '')) continue // blank line
    stats.total++
    const cand = rowToCandidate(cells, map)

    if (!cand.domain) {
      stats.invalid++
      stats.skipped++
      skipped.push({ domain: String(cells[map.url] ?? '').slice(0, 60), username: cand.username, reason: 'no usable web address (app or non-http origin?)' })
      continue
    }
    if (!cand.password) {
      stats.invalid++
      stats.skipped++
      skipped.push({ domain: cand.domain, username: cand.username, reason: 'empty password' })
      continue
    }

    const key = `${cand.domain}::${cand.username}`
    const inVault = existingMap.get(key)
    const inFile = seen.get(key)

    if ((inVault && inVault.password === cand.password) || (inFile && inFile.password === cand.password)) {
      stats.duplicates++
      continue
    }
    if (inVault || inFile) {
      // Same login, different password — the vault (or the first row) may be
      // newer; never overwrite silently, surface for review instead.
      stats.conflicts++
      conflicts.push({ domain: cand.domain, username: cand.username })
      continue
    }

    seen.set(key, { domain: cand.domain, username: cand.username, password: cand.password })
    entries.push({ domain: cand.domain, username: cand.username, password: cand.password })
    stats.added++
  }

  return { ok: true, entries, stats, conflicts, skipped }
}
