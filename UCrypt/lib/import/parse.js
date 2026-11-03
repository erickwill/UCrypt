/**
 * UCrypt — R150 §8.1 IMPORT FROM OTHER BROWSERS — the CSV parse + dedupe
 * engine (F11, S67: "the owner imports a real CSV by hand").
 *
 * PURE MODULE — no chrome.*, no DOM, no I/O. Fully injectable and unit
 * tested (tests/r150-import.test.mjs). The page (options.js) owns the file
 * reading and the DOM; the background door IMPORT_APPLY owns the write
 * through the vault's own APIs. Nothing here writes anything.
 *
 * Pipeline:  parseCsv → detectShape → normalizeRows → validateEntry →
 *            dedupe → computeReceipt → previewRows
 *
 * Supported shapes (the real header vocabularies):
 *   chrome    name, url, username, password, note
 *   firefox   url, username, password, hostname, httpRealm, formActionOrigin,
 *             guid, timeCreated, timeLastUsed, timePasswordChanged
 *   bitwarden folder, favorite, type, name, notes, login_uri, login_username,
 *             login_password, login_totp
 *   generic   any url/username/password triple (alias vocabulary)
 *
 * Honesty laws:
 *   - NO ROW IS EVER SILENTLY DROPPED. Every data row surfaces exactly once
 *     in the preview (previewRows), with a status and a typed reason.
 *   - The receipt arithmetic is exact: toAdd + toUpdate + duplicates +
 *     attention === the number of non-empty data rows.
 *   - LWW on conflicts: the NEWER side wins by timePasswordChanged (import)
 *     vs updatedAt (vault) when both are present; a tie keeps the vault
 *     copy. Without timestamps the import row wins and the vault copy is
 *     kept in the report.
 *   - The vault's copy is never overwritten silently: overwrites ride the
 *     previewed toUpdate list only.
 */

// --- parseCsv ---------------------------------------------------------------

const DELIMS = [',', ';', '\t']

/**
 * Sniff the delimiter: the candidate that occurs most often (outside
 * quotes) in the header line wins; ties prefer comma (Chromium's shape).
 * European exports often use semicolons; some tools use tabs.
 */
export function sniffDelimiter(text) {
  if (typeof text !== 'string' || !text.length) return ','
  const lineEnd = text.search(/\r\n|\r|\n/)
  const first = lineEnd >= 0 ? text.slice(0, lineEnd) : text
  let best = ','
  let bestCount = -1
  for (const d of DELIMS) {
    let c = 0
    let inQ = false
    for (let i = 0; i < first.length; i++) {
      const ch = first[i]
      if (ch === '"') inQ = !inQ
      else if (ch === d && !inQ) c++
    }
    if (c > bestCount) { best = d; bestCount = c }
  }
  return best
}

/**
 * Parse raw CSV text — RFC4180-ish: quoted cells, "" escaped quotes,
 * embedded commas/newlines inside quotes, CRLF / LF / lone-CR line endings,
 * UTF-8 BOM stripped, delimiter sniffed (comma / semicolon / tab).
 *
 * @param {string} text
 * @returns {{ rows: Array<{ cells: string[] }>, headers: string[], delimiter: string }}
 *   headers = the first row's cells; rows = the DATA rows (header excluded),
 *   in file order. Interior blank lines are kept (empty cells) —
 *   normalizeRows skips them; trailing blank lines are dropped (file noise).
 */
export function parseCsv(text) {
  if (typeof text !== 'string') return { rows: [], headers: [], delimiter: ',' }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1) // BOM
  const delimiter = sniffDelimiter(text)

  const all = []
  let row = []
  let field = ''
  let inQuotes = false
  const pushField = () => { row.push(field); field = '' }
  const pushRow = () => { pushField(); all.push(row); row = [] }

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
    if (ch === delimiter) { pushField(); continue }
    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++
      pushRow()
      continue
    }
    field += ch
  }
  // The final field/row — files may not end with a newline. A trailing
  // newline already pushed everything; flush only when a field/row is open.
  if (field !== '' || row.length > 0) pushRow()

  // Trailing completely-empty rows are the file's final newline(s) — drop.
  while (all.length > 0) {
    const last = all[all.length - 1]
    if (last.length === 1 && last[0] === '') all.pop()
    else if (last.length > 1 && last.every((c) => c === '')) all.pop()
    else break
  }
  if (all.length === 0) return { rows: [], headers: [], delimiter }

  const headers = all[0].map((c) => c)
  const rows = all.slice(1).map((cells) => ({ cells }))
  return { rows, headers, delimiter }
}

// --- detectShape ------------------------------------------------------------

/** Header cells → canonical names (trim, lowercase, BOM-tolerant). */
function normHeaders(headers) {
  return (Array.isArray(headers) ? headers : []).map((h) => String(h ?? '').trim().toLowerCase().replace(/^\ufeff/, ''))
}

const has = (names, n) => names.includes(n)

/**
 * Map the real export vocabularies. Detection order is specificity order:
 * bitwarden (login_*) → firefox (httpRealm / formActionOrigin / time*) →
 * chrome (the exact name/url/username/password(+note) row) → generic (any
 * url/username/password triple) → unknown.
 *
 * @param {string[]} headers
 * @returns {'chrome'|'firefox'|'bitwarden'|'generic'|'unknown'}
 */
export function detectShape(headers) {
  const n = normHeaders(headers)
  if (!n.length) return 'unknown'
  if (n.some((h) => h.startsWith('login_'))) return 'bitwarden'
  if (has(n, 'httprealm') || has(n, 'formactionorigin') || has(n, 'timepasswordchanged') ||
      (has(n, 'guid') && has(n, 'timecreated'))) return 'firefox'
  if (has(n, 'url') && has(n, 'username') && has(n, 'password') && has(n, 'name')) return 'chrome'
  const urlish = n.some((h) => ['url', 'website', 'web_site', 'webpage', 'site', 'origin', 'uri', 'hostname', 'server'].includes(h))
  const userish = n.some((h) => ['username', 'user', 'user_name', 'email', 'account', 'userid', 'user id', 'login_name'].includes(h))
  const passish = n.some((h) => ['password', 'pass', 'passwd', 'pwd'].includes(h))
  if (urlish && userish && passish) return 'generic'
  return 'unknown'
}

// --- url → login domain ------------------------------------------------------

/**
 * URL → the vault's login key (a bare hostname, www-stripped, lowercase).
 * Tolerates bare hostnames ("example.com"). Returns '' for anything that is
 * not a web origin (android:// apps, chrome:// pages, "not a url" text) —
 * the caller turns that into a typed diagnostic, never a silent drop.
 */
export function urlToDomain(urlStr) {
  const raw = String(urlStr || '').trim()
  if (!raw) return ''
  if (/^(android|chrome|edge|brave|opera|vivaldi|firefox|file|about|javascript|data):/i.test(raw)) return ''
  try {
    const u = new URL(raw.includes('://') ? raw : 'https://' + raw)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    if (!u.hostname || !u.hostname.includes('.')) return ''
    return u.hostname.replace(/^www\./i, '').toLowerCase()
  } catch {
    return ''
  }
}

// --- normalizeRows -----------------------------------------------------------

/**
 * The per-row diagnostic vocabulary. `message` is the exact English line the
 * preview renders when the locale catalog lacks the key; the page maps
 * `code` → its i18n key first. Codes are stable API.
 */
export const DIAGNOSTICS = {
  'no-username': (r) => ({ row: r, code: 'no-username', message: `row ${r}: no username — imported with an empty username` }),
  'no-password': (r) => ({ row: r, code: 'no-password', message: `row ${r}: no password — the row is saved without a password` }),
  'no-name': (r) => ({ row: r, code: 'no-name', message: `row ${r}: no name — the address is used as the name` }),
  'bad-url': (r) => ({ row: r, code: 'bad-url', message: `row ${r}: the address is not a usable web address (app or non-web origin?)` }),
  'bad-time': (r) => ({ row: r, code: 'bad-time', message: `row ${r}: the changed-date is not a readable date — it is ignored` }),
}

/** Column plan per shape: canonical entry field → header names (in order). */
const COLUMNS = {
  chrome: {
    name: ['name'], url: ['url'], username: ['username'], password: ['password'], notes: ['note'],
  },
  firefox: {
    name: [], url: ['url', 'hostname'], username: ['username'], password: ['password'], notes: [],
  },
  bitwarden: {
    name: ['name'], url: ['login_uri'], username: ['login_username'], password: ['login_password'],
    notes: ['notes'], totp: ['login_totp'],
  },
  generic: {
    name: ['name', 'title', 'label'],
    url: ['url', 'website', 'web_site', 'webpage', 'site', 'origin', 'uri', 'hostname', 'server'],
    username: ['username', 'user', 'user_name', 'email', 'account', 'userid', 'user id', 'login_name'],
    password: ['password', 'pass', 'passwd', 'pwd'],
    notes: ['note', 'notes', 'comment', 'extra'],
  },
}

/**
 * The shapes' FIXED column orders — the positional fallback when the caller
 * has no header row (the real exports are fixed-order):
 *   chrome    name,url,username,password[,note]
 *   firefox   url,username,password,hostname,httpRealm,formActionOrigin,guid,
 *             timeCreated,timeLastUsed,timePasswordChanged
 *   bitwarden folder,favorite,type,name,notes,fields,reprompt,login_uri,
 *             login_username,login_password,login_totp
 */
const SHAPE_ORDER = {
  chrome: ['name', 'url', 'username', 'password', 'note'],
  firefox: ['url', 'username', 'password', 'hostname', 'httprealm', 'formactionorigin', 'guid', 'timecreated', 'timelastused', 'timepasswordchanged'],
  bitwarden: ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'],
}

function firstIndexOf(names, candidates) {
  for (const c of candidates) {
    const i = names.indexOf(c)
    if (i >= 0) return i
  }
  return -1
}

/**
 * Resolve the column indexes for one shape. When `headers` are provided the
 * mapping is BY NAME (robust to column reordering); without them the
 * shape's fixed export order is used.
 */
function resolveIndexes(shape, headers) {
  const hdrs = normHeaders(headers)
  const plan = COLUMNS[shape] || COLUMNS.generic
  const order = SHAPE_ORDER[shape] || []
  const idx = {}
  const resolve = (field, names) => {
    if (hdrs.length) return firstIndexOf(hdrs, (names || []).map((n) => n.toLowerCase()))
    for (const n of names || []) {
      const j = order.indexOf(n.toLowerCase())
      if (j >= 0) return j
    }
    return -1
  }
  for (const [field, names] of Object.entries(plan)) idx[field] = resolve(field, names)
  // firefox: url wins, hostname is the per-row fallback; the changed-date
  // passthrough rides its own column.
  if (shape === 'firefox') {
    idx.hostname = resolve('hostname', ['hostname'])
    idx.time = resolve('timepasswordchanged', ['timepasswordchanged'])
  }
  return idx
}

/**
 * Map parsed data rows → normalized entries, one per non-empty row, with
 * per-row diagnostics. Row numbers are FILE rows (the header is row 1, so
 * the first data row is row 2) — the number the owner sees in a text editor.
 *
 * @param {string} shape                   detectShape's verdict
 * @param {Array<{cells:string[]}>} rows   parseCsv's data rows
 * @param {string[]} [headers]             parseCsv's headers (by-name mapping)
 * @returns {{ entries: Array, diagnostics: Array<{row:number, code:string, message:string}> }}
 *   entry = { row, name, url, domain, username, password, notes,
 *             totp?, timePasswordChanged? }
 */
export function normalizeRows(shape, rows, headers) {
  const list = Array.isArray(rows) ? rows : []
  const entries = []
  const diagnostics = []
  const idx = resolveIndexes(shape, headers)

  for (let k = 0; k < list.length; k++) {
    const cells = (list[k] && Array.isArray(list[k].cells)) ? list[k].cells.map((c) => String(c ?? '')) : []
    const fileRow = k + 2 // header = row 1
    if (cells.every((c) => c.trim() === '')) continue // an empty line carries nothing

    const cell = (f) => {
      const i = idx[f]
      return i >= 0 && i < cells.length ? cells[i].trim() : ''
    }

    const entry = { row: fileRow, name: '', url: '', domain: '', username: '', password: '', notes: '' }
    entry.name = cell('name')
    entry.url = cell('url')
    // firefox: the hostname column carries the origin when the url cell is
    // empty (httpRealm-only rows).
    if (!entry.url && shape === 'firefox') entry.url = cell('hostname')
    entry.username = cell('username')
    entry.password = cell('password')
    entry.notes = cell('notes')

    // firefox: the changed-date passthrough (unix epoch ms as a string) —
    // the LWW timestamp the dedupe compares against the vault's updatedAt.
    if (shape === 'firefox' && idx.time >= 0 && idx.time < cells.length) {
      const raw = cells[idx.time].trim()
      if (raw) {
        const t = Number(raw)
        if (Number.isFinite(t) && t > 0) entry.timePasswordChanged = t
        else diagnostics.push(DIAGNOSTICS['bad-time'](fileRow))
      }
    }
    // bitwarden: the TOTP seed rides to the vault (which validates/clamps it
    // and converts it into the canonical standalone token — a login never
    // persists a seed copy). An invalid seed is refused THERE, reported.
    if (shape === 'bitwarden') {
      const raw = cell('totp')
      if (raw) entry.totp = { secret: raw }
    }

    // firefox exports carry no name column — derive one from the address so
    // the preview shows the row honestly (the vault key stays the domain).
    if (!entry.name && entry.url) {
      const host = urlToDomain(entry.url)
      if (host) { entry.name = host; diagnostics.push(DIAGNOSTICS['no-name'](fileRow)) }
    }

    entry.domain = urlToDomain(entry.url)
    if (entry.url && !entry.domain) diagnostics.push(DIAGNOSTICS['bad-url'](fileRow))
    // The "imported with an empty username" diagnostic is honest only when
    // the row WILL be imported (a password exists); a password-less row is
    // needs-attention and its attention code carries the truth instead.
    if (!entry.username && entry.password) diagnostics.push(DIAGNOSTICS['no-username'](fileRow))
    if (!entry.password && entry.username) diagnostics.push(DIAGNOSTICS['no-password'](fileRow))

    entries.push(entry)
  }
  return { entries, diagnostics }
}

// --- validateEntry -----------------------------------------------------------

export const ATTENTION = {
  NOTHING_TO_SAVE: 'nothing-to-save', // no password AND no username
  BAD_URL: 'bad-url',                 // a non-empty url that is not a web origin
  NO_KEY: 'no-key',                   // no usable address AND no name — cannot key the row
}

/**
 * 'ok' | 'needs-attention' — the honest verdict classes. A needs-attention
 * row is NEVER dropped: it renders in the preview, is excluded from the
 * write set, and is counted in the receipt's K.
 *
 * Classes (contract §8.1): no password AND no username; a malformed URL.
 * Plus the honest third: a row with neither a usable address nor a name has
 * no vault key to live under.
 */
export function validateEntry(e) {
  if (!e || typeof e !== 'object') return 'needs-attention'
  const username = String(e.username ?? '').trim()
  const password = String(e.password ?? '')
  const url = String(e.url ?? '').trim()
  const domain = String(e.domain ?? '').trim()
  const name = String(e.name ?? '').trim()
  if (!password && !username) return 'needs-attention'
  if (url && !domain) return 'needs-attention'
  if (!domain && !name) return 'needs-attention'
  return 'ok'
}

/** The typed attention codes for one row (the preview's reason list). */
export function attentionCodes(e) {
  const codes = []
  if (!e || typeof e !== 'object') return [ATTENTION.NOTHING_TO_SAVE]
  const username = String(e.username ?? '').trim()
  const password = String(e.password ?? '')
  const url = String(e.url ?? '').trim()
  const domain = String(e.domain ?? '').trim()
  const name = String(e.name ?? '').trim()
  if (!password && !username) codes.push(ATTENTION.NOTHING_TO_SAVE)
  if (url && !domain) codes.push(ATTENTION.BAD_URL)
  if (!domain && !name && (password || username)) codes.push(ATTENTION.NO_KEY)
  if (!codes.length) codes.push(ATTENTION.NOTHING_TO_SAVE) // unreachable via validateEntry
  return codes
}

// --- dedupe ------------------------------------------------------------------

const loginKey = (e) => `${String(e.domain || '').toLowerCase()}::${String(e.username ?? '')}`
/** name+username fallback key (url-less rows; a vault entry's "name" is its domain). */
const nameKey = (e) => `${String(e.domain ? e.domain : String(e.name || '').toLowerCase())}::${String(e.username ?? '')}`

/**
 * The dedupe engine — against the vault AND within the batch, LWW on
 * conflicts. Attention rows (validateEntry !== 'ok') are never written and
 * never matched; they ride out in `attention`.
 *
 * Match keys, in order: (url-normalized + username), then (name + username).
 *
 * LWW law: a same-key row with a DIFFERENT password is a conflict. When the
 * import row carries timePasswordChanged and the vault copy carries
 * updatedAt, the strictly NEWER wins; a tie keeps the vault copy. Without
 * timestamps the import row wins (it is the thing being previewed) and the
 * vault copy is kept in the report. Identical passwords are duplicates —
 * skipped, never rewritten.
 *
 * @param {Array} entries   normalizeRows' entries
 * @param {Array} existing  the vault's login entries [{domain, username, password, updatedAt?}]
 * @returns {{ toAdd: Array, toUpdate: Array, duplicates: Array, conflicts: Array, attention: Array }}
 *   toAdd      entries ready for the vault's add path
 *   toUpdate   { origDomain, origUsername, domain, username, password, note, row }
 *   duplicates [{ row, reason, detail }] — every skipped row
 *   conflicts  [{ row, winner: 'import'|'vault'|'batch', detail }] — differing passwords
 *   attention  [{ row, codes: [...] }] — validateEntry's needs-attention rows
 */
export function dedupe(entries, existing) {
  const vault = (Array.isArray(existing) ? existing : [])
    .filter((e) => e && typeof e === 'object' && (e.type === undefined || e.type === 'login'))
  const byKey = new Map()
  const byName = new Map()
  for (const e of vault) {
    if (!String(e.domain || '').trim()) continue
    const k1 = loginKey(e)
    if (!byKey.has(k1)) byKey.set(k1, e)
    const k2 = nameKey(e)
    if (!byName.has(k2)) byName.set(k2, e)
  }

  const toAdd = []
  const toUpdate = []
  const duplicates = []
  const conflicts = []
  const attention = []

  // Within-batch state: the surviving representation per key.
  const batch = new Map()

  for (const e of entries) {
    if (validateEntry(e) !== 'ok') {
      attention.push({ row: e.row, codes: attentionCodes(e) })
      continue
    }
    const k1 = loginKey(e)
    const k2 = nameKey(e)

    // ── against the vault ──
    const inVault = byKey.get(k1) || (e.domain ? undefined : byName.get(k2))
    if (inVault) {
      const samePw = String(inVault.password ?? '') === String(e.password ?? '')
      if (samePw) {
        duplicates.push({ row: e.row, reason: 'same-password', detail: 'already in your vault (same login and password)' })
        continue
      }
      // conflict — LWW
      const vTime = Number(inVault.updatedAt) || 0
      const iTime = Number(e.timePasswordChanged) || 0
      let importWins
      let detail
      if (iTime && vTime) {
        importWins = iTime > vTime
        detail = importWins
          ? 'updates the existing entry (the import is newer)'
          : 'your vault has the newer password — kept the vault copy'
      } else {
        importWins = true
        detail = 'updates the existing entry (no timestamps — the import wins)'
      }
      conflicts.push({ row: e.row, winner: importWins ? 'import' : 'vault', detail })
      if (importWins) {
        toUpdate.push({
          origDomain: inVault.domain, origUsername: inVault.username ?? '',
          domain: e.domain, username: e.username ?? '', password: e.password ?? '',
          note: e.notes || '',
          row: e.row,
          detail, // the typed LWW reason — the preview renders it on the row
        })
        batch.set(k1, e)
        if (k2 !== k1) batch.set(k2, e)
      } else {
        duplicates.push({ row: e.row, reason: 'vault-newer', detail })
      }
      continue
    }

    // ── within the batch ──
    const prev = batch.get(k1) || (e.domain ? undefined : batch.get(k2))
    if (prev) {
      const samePw = String(prev.password ?? '') === String(e.password ?? '')
      if (samePw) {
        duplicates.push({ row: e.row, reason: 'batch-duplicate', detail: 'duplicate within the file — kept the first occurrence' })
        continue
      }
      const pTime = Number(prev.timePasswordChanged) || 0
      const eTime = Number(e.timePasswordChanged) || 0
      let eWins
      let detail
      if (pTime && eTime) {
        eWins = eTime > pTime
        detail = eWins ? 'newer row in the file wins (later change)' : 'an earlier row in the file is newer — kept it'
      } else {
        eWins = true
        detail = 'a later row carries a different password — the later row wins'
      }
      conflicts.push({ row: e.row, winner: eWins ? 'import' : 'batch', detail })
      if (eWins) {
        // The earlier row loses: it moves OUT of the write set into the report.
        const ai = toAdd.indexOf(prev)
        if (ai >= 0) toAdd.splice(ai, 1)
        duplicates.push({ row: prev.row, reason: 'batch-older', detail: 'an earlier duplicate row lost to a newer one in this file' })
        toAdd.push(e)
        batch.set(k1, e)
        if (k2 !== k1) batch.set(k2, e)
      } else {
        duplicates.push({ row: e.row, reason: 'batch-older', detail })
      }
      continue
    }

    toAdd.push(e)
    batch.set(k1, e)
    if (k2 !== k1) batch.set(k2, e)
  }

  return { toAdd, toUpdate, duplicates, conflicts, attention }
}

// --- computeReceipt ----------------------------------------------------------

/**
 * The exact receipt. imported = brand-new rows; updated = the previewed LWW
 * overwrites; duplicatesSkipped = every skipped row (same-password, batch
 * duplicates, vault-newer losers); needsAttention = rows shown but never
 * written. Exact arithmetic: imported + updated + duplicatesSkipped +
 * needsAttention === the number of non-empty data rows.
 *
 * @param {{ toAdd?: Array, toUpdate?: Array, duplicates?: Array, attention?: Array }} result
 * @returns {{ imported: number, duplicatesSkipped: number, needsAttention: number, updated: number }}
 */
export function computeReceipt(result) {
  const r = result || {}
  return {
    imported: (r.toAdd || []).length,
    duplicatesSkipped: (r.duplicates || []).length,
    needsAttention: (r.attention || []).length,
    updated: (r.toUpdate || []).length,
  }
}

// --- previewRows -------------------------------------------------------------

/**
 * The preview's ordered rows — EVERY data row appears EXACTLY ONCE, in file
 * order (the order normalizeRows produced), regardless of how the dedupe
 * arrays are shaped. This is the function the preview table renders and the
 * tests pin (the preview-promise: every row shown before anything is
 * written).
 *
 * @param {Array} entries  normalizeRows' entries (file order)
 * @param {object} [result] dedupe's result (may be null — pre-dedupe preview)
 * @returns {Array<{row:number, name:string, url:string, username:string,
 *                    password:string, status:'ok'|'needs-attention'|'duplicate-of-existing',
 *                    detail:string, codes?:string[]}>}
 */
export function previewRows(entries, result) {
  const r = result || { toAdd: [], toUpdate: [], duplicates: [], conflicts: [], attention: [] }
  const addRows = new Set((r.toAdd || []).map((e) => e.row))
  const updRows = new Map((r.toUpdate || []).map((u) => [u.row, u]))
  const dupByRow = new Map((r.duplicates || []).map((d) => [d.row, d]))
  const attByRow = new Map((r.attention || []).map((a) => [a.row, a]))

  return (Array.isArray(entries) ? entries : []).map((e) => {
    const base = {
      row: e.row, name: e.name || '', url: e.url || '',
      username: e.username || '', password: e.password || '',
    }
    if (attByRow.has(e.row)) {
      const a = attByRow.get(e.row)
      return { ...base, status: 'needs-attention', detail: '', codes: a.codes || [] }
    }
    if (addRows.has(e.row)) return { ...base, status: 'ok', detail: '' }
    if (updRows.has(e.row)) return { ...base, status: 'ok', detail: updRows.get(e.row).detail || '' }
    if (dupByRow.has(e.row)) {
      const d = dupByRow.get(e.row)
      return { ...base, status: 'duplicate-of-existing', detail: d.detail || '' }
    }
    // Unaccounted (defensive — the arithmetic law makes this unrepresentable):
    return { ...base, status: 'ok', detail: '' }
  })
}
