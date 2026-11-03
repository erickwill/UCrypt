/**
 * UCrypt — Universal import engine (v2.7.0 "Import Center").
 *
 * One door for every migration path INTO UCrypt:
 *   Browsers          Chrome, Edge, Brave, Vivaldi, Opera (Chromium CSV),
 *                     Firefox (CSV + JSON), Safari, + bookmarks HTML and
 *                     history exports (CSV/JSON).
 *   Password managers Bitwarden (CSV + JSON), LastPass, 1Password, Dashlane,
 *                     KeePassXC / KeePass, RoboForm, NordPass, Enpass, generic.
 *
 * What gets imported (categories):
 *   login     → a real login (domain, username, password)
 *   totp      → an authenticator seed found next to a login (otpauth:// URI
 *               or bare base32) — stored as a vault TOTP token
 *   note      → secure note                    (Bitwarden/LastPass/KeePassXC/…)
 *   card      → payment card                   (Bitwarden)
 *   address   → identity / address profile     (Bitwarden identity, RoboForm)
 *   bookmark  → browser bookmark               (Netscape bookmarks HTML)
 *   history   → visited-page record            (history CSV/JSON exports)
 *   form      → saved form-field data          (Bitwarden fields, Rf-Fields,
 *                                              generic field/value exports)
 *
 * Everything is parsed LOCALLY — the file never leaves the device. Items flow
 * into the encrypted vault through background.IMPORT_ENTRIES →
 * vault.saveEntriesBatch(), so tombstones, lastModified and the auto-push to
 * the configured cloud transport (Google Drive / Dropbox / GitHub Gist /
 * WebDAV / Custom URL) behave exactly like a manual save.
 *
 * Policy (unchanged since v2.6.0, deliberately conservative):
 *   - existing (key) with the same secret        → duplicate, skipped
 *   - existing (key) with a DIFFERENT secret     → conflict, listed, skipped
 *   - never silently overwrites anything.
 */

import { parseCsv, csvDomain } from './csv-import.js'

// --- Limits (defense against pathological files) ----------------------------

export const LIMITS = {
  MAX_ITEMS: 10000,     // total items per import
  MAX_LOGINS: 5000,
  MAX_TOTP: 500,
  MAX_NOTES: 1000,
  MAX_CARDS: 500,
  MAX_ADDRESSES: 500,
  MAX_BOOKMARKS: 5000,
  // R90 §2.2 — MAX_HISTORY=5000 is RETIRED: history no longer imports from
  // files at all. The direct browser import (Import Center → "Import
  // browsing history from this browser") replaces it with a date-range
  // selector (7/30/90 days, hard cap 20,000, preview before write) — a
  // CEO-commanded replacement, never a silent behavior change.
  MAX_FORMS: 2000,
  MAX_LEN: {
    title: 200, domain: 253, username: 320, password: 2048,
    url: 2048, note: 10000, field: 1000,
  },
}

// Pseudo-domains for non-login entries. They can never collide with a real
// website (dots required in real hostnames) and never match autofill queries,
// which look entries up by the page's real domain.
export const PSEUDO_DOMAIN = {
  note: '__note__', card: '__card__', address: '__address__',
  bookmark: '__bookmark__', history: '__history__', form: '__form__',
}
const PSEUDO_SET = new Set(Object.values(PSEUDO_DOMAIN))

// --- Source catalog (drives the Import Center UI) ---------------------------

export const SOURCES = [
  {
    id: 'chrome', label: 'Chrome / Chromium', icon: '🌐', group: 'browsers',
    steps: [
      'Open chrome://settings/passwords (Chrome → Settings → Autofill → Password Manager).',
      'Click ⋮ next to "Saved Passwords" → Export passwords.',
      'Confirm with your OS login, save the .csv file, then drop it below.',
    ],
    hint: 'Expected: a .csv with columns name, url, username, password, note',
  },
  {
    id: 'brave', label: 'Brave', icon: '🦁', group: 'browsers',
    steps: [
      'Open brave://settings/passwords.',
      'Click ⋮ next to "Saved Passwords" → Export passwords.',
      'Save the .csv file, then drop it below.',
    ],
    hint: 'Expected: a .csv with columns name, url, username, password, note',
  },
  {
    id: 'edge', label: 'Microsoft Edge', icon: '🌊', group: 'browsers',
    steps: [
      'Open edge://settings/passwords.',
      'Click ⋮ next to "Saved Passwords" → Export passwords.',
      'Save the .csv file, then drop it below.',
    ],
    hint: 'Expected: a .csv with columns name, url, username, password, note',
  },
  {
    id: 'vivaldi', label: 'Vivaldi', icon: '🎭', group: 'browsers',
    steps: [
      'Open vivaldi://settings/passwords (Settings → Privacy → Passwords).',
      'Click ⋮ next to "Saved Passwords" → Export passwords.',
      'Save the .csv file, then drop it below.',
    ],
    hint: 'Expected: a .csv with columns name, url, username, password, note',
  },
  {
    id: 'opera', label: 'Opera', icon: '🎭', group: 'browsers',
    steps: [
      'Opera may not expose a password export on every build — if the button is missing, use Opera\'s bookmark export for bookmarks, and a Chromium CSV for passwords.',
      'Open opera://settings/passwords when available → ⋮ → Export passwords.',
      'Save the .csv file, then drop it below.',
    ],
    hint: 'Expected: a .csv with columns name, url, username, password, note',
  },
  {
    id: 'firefox', label: 'Firefox', icon: '🦊', group: 'browsers',
    steps: [
      'Open about:logins (Firefox menu → Passwords).',
      'Click ⋯ at the top of the logins list → Export Logins… (CSV) — or File → Export for JSON builds.',
      'Save the file (.csv or .json), then drop it below. Both are supported.',
    ],
    hint: 'Expected: a .csv with url, username, password, httpRealm, formActionOrigin… or a .json {logins:[…]}',
  },
  {
    id: 'safari', label: 'Safari (macOS)', icon: '🧭', group: 'browsers',
    steps: [
      'Open Safari → File → Export → Passwords… (macOS Ventura or newer).',
      'Choose "No encrypted file" for a plain .csv UCrypt can read.',
      'Drop the .csv below.',
    ],
    hint: 'Expected: a .csv with Title, URL, Username, Password columns',
  },
  {
    id: 'bitwarden', label: 'Bitwarden', icon: '🛡️', group: 'managers',
    steps: [
      'Open the Bitwarden vault (web or desktop app).',
      'Tools → Export vault → File format .json (unencrypted) or .csv.',
      'If offered "password protected" — do NOT pick it; UCrypt reads the unencrypted export. Drop the file below.',
    ],
    hint: 'Logins, secure notes, cards, identities and TOTP seeds are imported.',
  },
  {
    id: 'lastpass', label: 'LastPass', icon: '🔑', group: 'managers',
    steps: [
      'Open vault.lastpass.com → Advanced Options → Export → LastPass CSV File.',
      'Save the .csv, then drop it below. otpauth seeds in the "extra" column are picked up.',
    ],
    hint: 'Expected: a .csv with url, username, password, extra, name, grouping',
  },
  {
    id: 'onepassword', label: '1Password', icon: '❶', group: 'managers',
    steps: [
      'Open 1Password → All items (select the vault to migrate).',
      'File → Export → All Items → CSV (unencrypted).',
      'Drop the .csv below. OTPAuth columns become UCrypt 2FA tokens.',
    ],
    hint: 'Expected: a .csv with Title, Url, Username, Password, Notes, OTPAuth',
  },
  {
    id: 'dashlane', label: 'Dashlane', icon: '🏊', group: 'managers',
    steps: [
      'Open the Dashlane web app → My account → Settings → Export data → Export to CSV.',
      'Do not use the "secured file" option — UCrypt reads the plain CSV.',
      'Drop the .csv below. otpSecret columns become UCrypt 2FA tokens.',
    ],
    hint: 'Expected: a .csv with username, title, password, note, url, category, otpSecret',
  },
  {
    id: 'keepassxc', label: 'KeePassXC / KeePass', icon: '🔐', group: 'managers',
    steps: [
      'Open your database in KeePassXC → Database → Export → CSV File (KeePass: File → Export → Keepass CSV).',
      'Save the .csv, then drop it below. TOTP columns and custom fields are honoured.',
    ],
    hint: 'Expected: Group, Title, Username, Password, URL, Notes, TOTP — or Account, Login Name, Password, Web Site, Comments',
  },
  {
    id: 'roboform', label: 'RoboForm', icon: '🤖', group: 'managers',
    steps: [
      'Open RoboForm → Options → Account & Data → Export… → CSV files.',
      'Save the .csv, then drop it below.',
    ],
    hint: 'Expected: a .csv with Url, Name, Login, Pwd, Note, Folder, Rf-Fields',
  },
  {
    id: 'nordpass', label: 'NordPass', icon: '🐻', group: 'managers',
    steps: [
      'Open NordPass → Settings → Export items → export the CSV.',
      'Drop the .csv below.',
    ],
    hint: 'Expected: a .csv with name, url, username, password, note',
  },
  {
    id: 'enpass', label: 'Enpass', icon: '🐘', group: 'managers',
    steps: [
      'Open Enpass → File → Export → As CSV (unencrypted).',
      'Drop the .csv below.',
    ],
    hint: 'Expected: a .csv with Title, Subtitle, URLs, Usernames, Passwords, Websites, Note',
  },
  {
    id: 'bookmarks', label: 'Bookmarks (HTML)', icon: '🔖', group: 'data',
    steps: [
      'Chrome/Edge/Brave/Vivaldi: Bookmark Manager → ⋮ → Export bookmarks. Firefox: Bookmarks → Manage bookmarks → Import and Backup → Export Bookmarks to HTML.',
      'Drop the .html file below — folders and titles are preserved.',
    ],
    hint: 'Bookmarks are stored in your encrypted vault as "other data" and sync to your cloud transport like everything else.',
  },
  {
    id: 'history', label: 'History (CSV/JSON)', icon: '🕘', group: 'data',
    steps: [
      'Browsers do not offer a one-click history export; use your export tool/extension of choice ("Chrome History export", "Firefox history JSON", Google Takeout "Chrome/Browser History" CSV).',
      'Drop the .csv or .json below — the parser auto-detects url/title/visit columns.',
    ],
    hint: 'History records are stored as "other data" entries (URL, title, visit count, last visit).',
  },
  {
    id: 'generic', label: 'Any CSV (auto)', icon: '🧩', group: 'data',
    steps: [
      'Any password CSV with columns like url/website, username/email, password works — drop it below and the dialect is auto-detected.',
    ],
    hint: 'Unknown columns are ignored; the report lists anything skipped.',
  },
]

// --- Small helpers -----------------------------------------------------------

function trunc(s, max) {
  return String(s ?? '').slice(0, max)
}

function cleanStr(s) {
  return String(s ?? '').replace(/\r\n/g, '\n').trim()
}

function decodeEntities(s) {
  return String(s ?? '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => {
      const code = Number(n)
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : ''
    })
}

const BASE32_RE = /^[A-Z2-7]+=*$/

/**
 * v2.42.5 — R69 (F-R69-IMP-1): TOTP algorithm DIALECT normalization. Real
 * exports (Google Authenticator spec, Bitwarden) write SHA1/SHA256/SHA512
 * without the dash; the runtime canonical form is SHA-1/SHA-256/SHA-512.
 * Without this, `algorithm=SHA256` silently degraded to SHA-1 at the token
 * save whitelist — WRONG CODES, silently. Unknown algorithms fall back to
 * the TOTP default SHA-1.
 */
function normTotpAlgorithm(a) {
  const s = String(a || '').toUpperCase().replace(/^SHA(\d)/, 'SHA-$1')
  return ['SHA-1', 'SHA-256', 'SHA-512'].includes(s) ? s : 'SHA-1'
}

/** Extract a TOTP seed from otpauth:// URIs or bare base32 strings. */
export function parseTotpSecret(raw) {
  const s = cleanStr(raw)
  if (!s) return null
  const uri = s.match(/otpauth:\/\/totp\/[^\s"'<>]+/i)
  if (uri) {
    try {
      const u = new URL(uri[0].replace(/&#(\d+);/g, ''))
      const secret = (u.searchParams.get('secret') || '').toUpperCase().replace(/\s/g, '')
      if (BASE32_RE.test(secret) && secret.replace(/=/g, '').length >= 16) {
        return {
          secret,
          label: decodeURIComponent(u.pathname.replace(/^\/+/, '')).slice(0, 64) || '',
          issuer: (u.searchParams.get('issuer') || '').slice(0, 64) || '',
          digits: Number(u.searchParams.get('digits')) || 6,
          period: Number(u.searchParams.get('period')) || 30,
          algorithm: normTotpAlgorithm(u.searchParams.get('algorithm') || 'SHA-1'),
        }
      }
    } catch { /* fall through */ }
  }
  const bare = s.toUpperCase().replace(/[\s-]/g, '')
  if (BASE32_RE.test(bare) && bare.replace(/=/g, '').length >= 16) return { secret: bare, label: '', issuer: '', digits: 6, period: 30, algorithm: 'SHA-1' }
  return null
}

/** Normalized item shape — every parser converges on this. */
function item(category, data = {}) {
  return {
    category,                       // login|totp|note|card|address|bookmark|history|form
    title: trunc(cleanStr(data.title), LIMITS.MAX_LEN.title),
    domain: String(data.domain || '').toLowerCase().slice(0, LIMITS.MAX_LEN.domain),
    username: trunc(cleanStr(data.username), LIMITS.MAX_LEN.username),
    password: trunc(String(data.password ?? ''), LIMITS.MAX_LEN.password),
    url: trunc(cleanStr(data.url), LIMITS.MAX_LEN.url),
    note: trunc(cleanStr(data.note), LIMITS.MAX_LEN.note),
    totp: data.totp || null,        // {secret,label,issuer,digits,period,algorithm}
    // v2.42.7 — R70 (F-R70-MODEL-1): the expansion-derived association
    // metadata on derived 'totp' items — the login's nonsecret stable key.
    // NEVER a secret: the login entry itself stops persisting any totp copy.
    linkedLoginKey: data.linkedLoginKey ? String(data.linkedLoginKey).slice(0, 400) : null,
    uris: Array.isArray(data.uris) && data.uris.length
      ? data.uris.slice(0, 10).map(u => trunc(cleanStr(u), LIMITS.MAX_LEN.url)).filter(Boolean)
      : null,                         // v2.17.0 — R26-B1: Bitwarden multi-URI → alias domains
    card: data.card || null,        // {holder,brand,number,expMonth,expYear,code}
    address: data.address || null,  // {name,email,phone,org,street,city,state,zip,country}
    fields: Array.isArray(data.fields) && data.fields.length
      ? data.fields.slice(0, 50).map(f => ({
          name: trunc(cleanStr(f.name), 100),
          value: trunc(String(f.value ?? ''), LIMITS.MAX_LEN.field),
        })).filter(f => f.name)
      : null,
    meta: data.meta && typeof data.meta === 'object'
      ? { visitedAt: Number(data.meta.visitedAt) || 0, visitCount: Number(data.meta.visitCount) || 0, folder: trunc(cleanStr(data.meta.folder), 200) }
      : null,
  }
}

// --- Extended header aliases (superset of csv-import.js) ---------------------

const ALIASES = {
  url: ['url', 'login_uri', 'uri', 'urls', 'origin', 'website', 'web_site', 'websites', 'webpage', 'site', 'web site', 'hostname', 'server'],
  username: ['username', 'login_username', 'user', 'user_name', 'usernames', 'email', 'account', 'userid', 'user id', 'login_name', 'login name'],
  password: ['password', 'login_password', 'pass', 'passwd', 'pwd', 'passwords'],
  name: ['name', 'title', 'label'],
  note: ['note', 'notes', 'comment', 'comments', 'extra'],
  totp: ['login_totp', 'otpauth', 'totp', 'otpsecret', 'otp_secret', 'otp'],
  folder: ['grouping', 'group', 'folder'],
  fields: ['fields', 'rf-fields', 'custom_fields'],
}

function mapHeaderExt(headerCells) {
  const map = {}
  const taken = new Set()
  const cells = (headerCells || []).map(c => String(c || '').trim().toLowerCase().replace(/^\ufeff/, ''))
  for (const [field, aliases] of Object.entries(ALIASES)) {
    for (let i = 0; i < cells.length; i++) {
      if (taken.has(i)) continue
      if (aliases.includes(cells[i])) { map[field] = i; taken.add(i); break }
    }
  }
  // Bitwarden card_*/identity_* columns — keep a side map of raw indexes.
  const extra = {}
  for (let i = 0; i < cells.length; i++) {
    if (taken.has(i)) continue
    if (/^card_/.test(cells[i])) extra[cells[i]] = i
    if (/^identity_/.test(cells[i])) extra[cells[i]] = i
  }
  return { map, extra }
}

// --- Dialect detection -------------------------------------------------------

/**
 * Fingerprint the export format from its first CSV row / JSON shape / HTML
 * prologue. Returns {kind, dialect, label} — kind: csv|json|html|unknown.
 */
export function detectFormat(text) {
  if (typeof text !== 'string' || !text.trim()) return { kind: 'unknown', dialect: 'unknown', label: 'empty file' }
  const head = text.slice(0, 4000)

  // Netscape bookmarks HTML
  if (/NETSCAPE-Bookmark/i.test(head) || (/<dt>\s*<a\s/i.test(head) && /<dl/i.test(head))) {
    return { kind: 'html', dialect: 'bookmarks', label: 'Netscape bookmarks HTML' }
  }

  // JSON exports
  const trimmed = head.trimStart()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(text)
      if (data && typeof data === 'object') {
        if (data.encrypted || data.encryptedData || (data.items && data.items.length && data.items[0].encrypted)) {
          return { kind: 'json', dialect: 'encrypted', label: 'password-protected / encrypted export' }
        }
        if (Array.isArray(data.logins)) return { kind: 'json', dialect: 'firefox-json', label: 'Firefox JSON export' }
        if (Array.isArray(data.items)) return { kind: 'json', dialect: 'bitwarden-json', label: 'Bitwarden JSON export' }
        if (Array.isArray(data.accounts)) return { kind: 'json', dialect: 'dashlane-json', label: 'Dashlane JSON export' }
        if (Array.isArray(data)) {
          const first = data.find(x => x && typeof x === 'object') || {}
          const keys = Object.keys(first).map(k => k.toLowerCase())
          if (keys.includes('uri') || keys.includes('url') || keys.includes('hostname')) {
            return { kind: 'json', dialect: 'history-json', label: 'history JSON export' }
          }
        }
        return { kind: 'json', dialect: 'unknown-json', label: 'JSON (unrecognized shape)' }
      }
    } catch {
      return { kind: 'unknown', dialect: 'unknown', label: 'malformed file (looks like broken JSON)' }
    }
  }

  // CSV dialects — fingerprint by header row
  const { rows } = parseCsv(text.slice(0, 200000)) // header only needs a slice
  if (rows.length === 0) return { kind: 'unknown', dialect: 'unknown', label: 'empty file' }
  const h = new Set(rows[0].map(c => String(c || '').trim().toLowerCase().replace(/^\ufeff/, '')))
  const has = (...names) => names.every(n => h.has(n))

  if (has('type', 'login_uri') || has('folder', 'fields') || [...h].some(c => c.startsWith('card_') || c.startsWith('identity_'))) {
    return { kind: 'csv', dialect: 'bitwarden-csv', label: 'Bitwarden CSV export' }
  }
  if (has('formactionorigin') || has('httprealm', 'timecreated') || has('formsubmiturl')) {
    return { kind: 'csv', dialect: 'firefox-csv', label: 'Firefox CSV export' }
  }
  if (has('grouping', 'extra')) return { kind: 'csv', dialect: 'lastpass', label: 'LastPass CSV export' }
  if (has('rf-fields') || has('pwd', 'rf-fields')) return { kind: 'csv', dialect: 'roboform', label: 'RoboForm CSV export' }
  if (has('group', 'title', 'totp') || (has('group', 'title', 'url') && h.has('notes'))) {
    return { kind: 'csv', dialect: 'keepassxc', label: 'KeePassXC CSV export' }
  }
  if (has('account', 'login name', 'web site') || has('account', 'login name')) {
    return { kind: 'csv', dialect: 'keepass', label: 'KeePass CSV export' }
  }
  if (has('username', 'title', 'otpsecret') || has('username', 'title', 'category')) {
    return { kind: 'csv', dialect: 'dashlane', label: 'Dashlane CSV export' }
  }
  if (has('subtitle') || has('websites') || has('urls')) return { kind: 'csv', dialect: 'enpass', label: 'Enpass CSV export' }
  if (has('otpauth')) return { kind: 'csv', dialect: '1password', label: '1Password / Safari CSV export' }
  if (has('name', 'url', 'username', 'password')) {
    return { kind: 'csv', dialect: 'chromium', label: 'Chrome / Brave / Edge / Vivaldi / Opera / NordPass CSV export' }
  }
  if (has('url', 'username', 'password')) return { kind: 'csv', dialect: 'chromium', label: 'generic browser CSV export' }

  // History CSV: url + at least one of title/visit markers
  if (h.has('url') && [...h].some(c => c === 'title' || c.includes('visit') || c.includes('lastvisit'))) {
    return { kind: 'csv', dialect: 'history-csv', label: 'history CSV export' }
  }
  if (has('url', 'username') || has('url', 'password')) {
    return { kind: 'csv', dialect: 'generic', label: 'generic CSV export' }
  }
  return { kind: 'unknown', dialect: 'unknown', label: 'unrecognized file format' }
}

// --- Parsers -----------------------------------------------------------------

function csvItems(text, detected) {
  const { rows } = parseCsv(text)
  if (rows.length < 2) return { items: [], warning: 'CSV has a header but no data rows' }
  const { map, extra } = mapHeaderExt(rows[0])
  const get = (cells, field) => {
    const idx = map[field]
    return idx === undefined ? '' : cleanStr(cells[idx])
  }

  const items = []
  // v2.18.0 — R27-F11: rows the parser CANNOT represent are no longer silent:
  // each one becomes a droppedRows entry (file row + reason) that surfaces in
  // the import report. Previously rows with neither a usable URL nor a
  // password (and history rows without a URL) vanished without a trace.
  const droppedRows = []
  const isBitwarden = detected.dialect === 'bitwarden-csv'
  const isHistory = detected.dialect === 'history-csv'
  const typeIdx = isBitwarden ? rows[0].findIndex(c => String(c || '').trim().toLowerCase() === 'type') : -1
  const isFirefox = detected.dialect === 'firefox-csv'
  const loginUrlAliases = isFirefox ? ['url'] : null // Firefox login URL is `url`

  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r]
    if (cells.every(c => String(c || '').trim() === '')) continue

    // History CSV rows — R90 §2.2: file-based history import is RETIRED.
    // Every row is skipped with the typed pointer to the direct date-range
    // import; nothing from a history file is ever silently dropped.
    if (isHistory) {
      droppedRows.push({ row: r + 1, reason: 'File-based history import retired — use Import Center → "Import browsing history from this browser" (7/30/90 days, preview before write).' })
      continue
    }

    const category = typeIdx >= 0 ? String(cells[typeIdx] || '').trim().toLowerCase() : 'login'

    if (isBitwarden && category === 'note') {
      items.push(item('note', {
        title: get(cells, 'name'),
        note: get(cells, 'note'),
        username: get(cells, 'username') || undefined,
        password: get(cells, 'password') || undefined,
        fields: parseFieldsCell(get(cells, 'fields')),
      }))
      continue
    }

    if (isBitwarden && category === 'card') {
      const gc = (name) => extra[name] === undefined ? '' : cleanStr(cells[extra[name]])
      items.push(item('card', {
        title: get(cells, 'name') || 'Payment card',
        note: get(cells, 'note'),
        card: {
          holder: trunc(gc('card_cardholdername'), 200),
          brand: trunc(gc('card_brand'), 60),
          number: trunc(gc('card_number').replace(/[\s-]/g, ''), 32),
          expMonth: trunc(gc('card_expmonth'), 4),
          expYear: trunc(gc('card_expyear'), 8),
          code: trunc(gc('card_code'), 8),
        },
      }))
      continue
    }

    if (isBitwarden && category === 'identity') {
      const gi = (name) => extra[name] === undefined ? '' : decodeEntities(cleanStr(cells[extra[name]]))
      items.push(item('address', {
        title: get(cells, 'name') || 'Identity',
        note: get(cells, 'note'),
        address: {
          name: trunc([gi('identity_firstname'), gi('identity_middlename'), gi('identity_lastname')].filter(Boolean).join(' '), 200),
          email: trunc(gi('identity_email'), 320),
          phone: trunc(gi('identity_phone'), 60),
          org: trunc(gi('identity_company'), 200),
          street: trunc(gi('identity_address1'), 200),
          city: trunc(gi('identity_city'), 120),
          state: trunc(gi('identity_state'), 120),
          zip: trunc(gi('identity_postalcode'), 20),
          country: trunc(gi('identity_country'), 120),
          ssn: trunc(gi('identity_ssn'), 32),
        },
      }))
      continue
    }

    // login-ish row (all remaining dialects)
    const urlRaw = get(cells, 'url') || (loginUrlAliases ? '' : '')
    const domain = csvDomain(urlRaw)
    const note = get(cells, 'note')
    const totpRaw = get(cells, 'totp') || (note ? (note.match(/otpauth:\/\/[^\s"']+/i) || [])[0] || '' : '')
    const totp = totpRaw ? parseTotpSecret(totpRaw) : null
    // v2.42.5 — R69 (F-R69-IMP-1): a present-but-invalid seed is REPORTED
    // (review list) and never stored — the login itself still imports.
    if (totpRaw && !totp) {
      droppedRows.push({
        row: r + 1,
        reason: 'TOTP seed present but invalid (not base32/otpauth) — imported without it; the raw string was not stored',
      })
    }

    if (isFirefox && !domain) {
      // Firefox httpRealm entries (server auth realms) have no page URL —
      // still worth keeping as a login against the hostname when parseable.
      const realm = cleanStr(cells[map.url] || '')
      if (realm) {
        const m = realm.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i)
        const host = m ? m[1].replace(/^www\./i, '').toLowerCase() : (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(realm) ? realm.toLowerCase() : '')
        if (host && cleanStr(cells[map.password] || '')) {
          items.push(item('login', {
            domain: host,
            username: get(cells, 'username'),
            password: cleanStr(cells[map.password] || ''),
            title: get(cells, 'name'),
            note: `Firefox realm: ${cleanStr(cells[map.url] || '')}`.slice(0, 200),
          }))
        }
      }
      continue
    }

    if (isBitwarden && (category === 'login' || category === '')) {
      const fields = parseFieldsCell(get(cells, 'fields'))
      items.push(item('login', {
        domain,
        username: get(cells, 'username'),
        password: get(cells, 'password'),
        title: get(cells, 'name'),
        url: urlRaw,
        note,
        totp,
        fields,
      }))
      if (!totp && note) { /* otpauth already attempted above */ }
      continue
    }

    // generic/other dialects — one row = one login (+ optional TOTP seed)
    const pw = get(cells, 'password')
    const title = get(cells, 'name')
    const username = get(cells, 'username')
    const folder = get(cells, 'folder')
    const fields = detected.dialect === 'roboform' || detected.dialect === 'keepassxc' || detected.dialect === 'keepass'
      ? parseFieldsCell(get(cells, 'fields'))
      : null
    if (domain && pw) {
      items.push(item('login', { domain, username, password: pw, title, url: urlRaw, note, totp, fields, meta: folder ? { folder } : null }))
    } else if (totp) {
      // A row with a seed but no password → standalone token
      items.push(item('totp', { title: title || username || domain, totp }))
    } else if (!urlRaw && (username || pw)) {
      // KeePass/KeePassXC entries WITHOUT any URL are effectively secure
      // notes with credentials inside — keep the content (nothing lost).
      items.push(item('note', {
        title: title || username || 'Imported note',
        username, password: pw,
        note: [note].filter(Boolean).join('\n'),
        fields,
      }))
    } else if (urlRaw && (username || pw)) {
      // A URL was present but unusable (android:// app, chrome:// page, …):
      // emit an invalid login so the plan reports WHY it was skipped instead
      // of silently dropping credentials.
      items.push(item('login', { domain: '', username, password: pw, title, url: urlRaw, note }))
    } else {
      // v2.18.0 — R27-F11: the previously-silent fall-through. A row with
      // neither a usable URL nor a password (and no TOTP seed) cannot become
      // any entry — report the row instead of losing it without a trace.
      droppedRows.push({ row: r + 1, reason: 'no usable web address and no password' })
    }
  }
  return { items, droppedRows }
}

function parseFieldsCell(cell) {
  const s = cleanStr(cell)
  if (!s) return null
  const out = []
  for (const line of s.split('\n')) {
    const t = line.trim()
    if (!t) continue
    // RoboForm Rf-Fields style "Name:Value" (semicolon-separated chains too)
    if (t.includes(';') && !t.includes(',')) {
      for (const seg of t.split(';')) {
        const m = seg.match(/^([^:]{1,100}):\s*(.*)$/)
        if (m && m[1].trim()) out.push({ name: cleanStr(m[1]), value: trunc(m[2], LIMITS.MAX_LEN.field) })
      }
      continue
    }
    if (!t.includes(',') && t.includes(':')) {
      const m = t.match(/^([^:]{1,100}):\s*(.*)$/)
      if (m && m[1].trim()) { out.push({ name: cleanStr(m[1]), value: trunc(m[2], LIMITS.MAX_LEN.field) }) ; continue }
    }
    // Bitwarden CSV style: name,value(,type) — the trailing type token
    // (0=visible/1=hidden) is stripped; values containing commas arrive whole
    // when the cell was quoted, otherwise split (best effort, lossless for
    // real exports).
    const parts = t.split(',')
    if (parts.length >= 2) {
      const name = cleanStr(parts[0])
      let value = parts.slice(1).join(',')
      value = value.replace(/,(0|1)$/i, '')
      if (name) out.push({ name, value: trunc(value, LIMITS.MAX_LEN.field) })
    }
  }
  return out.length ? out : null
}

function firefoxJsonItems(text) {
  try {
    const data = JSON.parse(text)
    const logins = Array.isArray(data?.logins) ? data.logins : []
    const items = []
    // v2.18.0 — R27-F11: unrepresentable Firefox-JSON rows are reported too.
    const droppedRows = []
    logins.forEach((l, i) => {
      if (!l || typeof l !== 'object') return
      const host = cleanStr(l.hostname)
      const pw = String(l.password ?? '')
      if (!host || !pw) {
        droppedRows.push({ row: i + 1, reason: !host ? 'login without a hostname' : 'login with an empty password' })
        return
      }
      const domain = csvDomain(host) || (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(host) ? host.toLowerCase() : '')
      if (!domain) {
        droppedRows.push({ row: i + 1, reason: `hostname is not a plain domain (${String(host).slice(0, 40)})` })
        return
      }
      items.push(item('login', {
        domain,
        username: String(l.username ?? ''),
        password: pw,
        title: '',
        url: host,
        note: l.formSubmitURL ? `Firefox formSubmitURL: ${l.formSubmitURL}` : '',
        meta: { visitedAt: Number(l.timePasswordChanged) || 0 },
      }))
    })
    return { items, droppedRows }
  } catch (e) {
    return { error: 'Not a valid Firefox JSON export — expected {logins:[…]}' }
  }
}

function bitwardenJsonItems(text) {
  try {
    const data = JSON.parse(text)
    const arr = Array.isArray(data?.items) ? data.items : []
    const items = []
    // v2.42.5 — R69 (F-R69-IMP-1): malformed seeds are REPORTED, never
    // silently dropped — the login still imports, the raw seed string is
    // never stored, and the review list names the exact reason.
    const seedSkips = []
    for (const it of arr) {
      if (!it || typeof it !== 'object') continue
      const base = {
        title: it.name,
        note: it.notes || '',
        fields: Array.isArray(it.fields)
          ? it.fields.map(f => ({ name: f?.name, value: f?.value }))
          : null,
      }
      if (it.type === 1 && it.login) {
        // v2.17.0 — R26-B1: collect ALL uris — the R25 alias-domains feature
        // gives every login additive URIs, and Bitwarden exports them; the
        // old code read only uri[0] and silently dropped the rest.
        const uriList = Array.isArray(it.login.uris)
          ? it.login.uris.map(u => String(u?.uri || '')).filter(Boolean)
          : []
        const uri = uriList[0] || ''
        const totpRaw = typeof it.login.totp === 'string' ? it.login.totp : ''
        const totp = totpRaw ? parseTotpSecret(totpRaw) : null
        if (totpRaw && !totp) {
          seedSkips.push({
            title: it.name || 'login',
            reason: 'TOTP seed present but invalid (not base32/otpauth) — imported without it; the raw string was not stored',
          })
        }
        const domain = csvDomain(uri)
        if (domain && it.login.password) {
          items.push(item('login', {
            ...base, domain, url: uri, uris: uriList,
            username: it.login.username || '',
            password: it.login.password || '',
            totp,
          }))
        } else if (totp) {
          // v2.42.5 — R69 (F-R69-IMP-1): the seed is preserved as a
          // standalone token in EVERY path. Rows without a usable URL used
          // to keep ONLY the token here, silently dropping the password —
          // the credentials now ride the secure note (the note entry model
          // keys identity by title, so structured account fields would have
          // no stable home; recorded as F-R69-IMP-2 for the next round).
          const credNote = [
            base.note,
            uri && `URL: ${uri}`,
            it.login.username && `Username: ${it.login.username}`,
            it.login.password && `Password: ${it.login.password}`,
          ].filter(Boolean).join('\n')
          if (credNote) items.push(item('note', { ...base, note: credNote }))
          items.push(item('totp', { title: it.name || 'Imported token', totp }))
        } else if (it.login?.password) {
          // v2.42.5 — R69: same fidelity rule for the no-usable-URL fallback
          // — credentials land in the note text instead of being dropped by
          // the note conversion (F-R69-IMP-2 documents the structured gap).
          const credNote = [
            base.note,
            uri && `URL: ${uri}`,
            it.login.username && `Username: ${it.login.username}`,
            it.login.password && `Password: ${it.login.password}`,
          ].filter(Boolean).join('\n')
          items.push(item('note', { ...base, note: credNote }))
        }
      } else if (it.type === 2) {
        items.push(item('note', base))
      } else if (it.type === 3 && it.card) {
        items.push(item('card', {
          ...base,
          card: {
            holder: it.card.cardholderName || '',
            brand: it.card.brand || '',
            number: String(it.card.number || '').replace(/[\s-]/g, ''),
            expMonth: String(it.card.expMonth || ''),
            expYear: String(it.card.expYear || ''),
            code: String(it.card.code || ''),
          },
        }))
      } else if (it.type === 4 && it.identity) {
        const id = it.identity
        // v2.18.0 — R27: real Bitwarden exports nest the postal address under
        // identity.address ({address1…3, city, state, postalCode, country});
        // the flat id.address1/id.city fallbacks stay for hand-made files.
        const addr = id.address && typeof id.address === 'object' ? id.address : {}
        items.push(item('address', {
          ...base,
          address: {
            name: [id.firstName, id.middleName, id.lastName].filter(Boolean).join(' '),
            email: id.email || '', phone: id.phone || '', org: id.company || '',
            street: addr.address1 || id.address1 || '',
            city: addr.city || id.city || '', state: addr.state || id.state || '',
            zip: addr.postalCode || id.postalCode || '',
            country: addr.country || id.country || '', ssn: id.ssn || '',
          },
        }))
      }
    }
    return { items, droppedRows: seedSkips }
  } catch {
    return { error: 'Not a valid Bitwarden JSON export — expected {items:[…]}' }
  }
}

const BOOKMARK_SKIP_RE = /^(javascript|place|data|blob|about|chrome|edge|brave|vivaldi|opera|moz-extension|chrome-extension):/i

/** Netscape bookmarks HTML (Chrome/Edge/Firefox/Brave/Vivaldi "Export bookmarks"). */
export function parseBookmarksHtml(text) {
  const items = []
  const folderStack = []
  const dtA = /<dt>\s*<a\s+[^>]*href\s*=\s*"([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi
  const dtH3 = /<dt>\s*<h3[^>]*>([\s\S]*?)<\/h3>/i
  let depth = 0
  const lines = text.split(/\r?\n/i)
  for (const lineRaw of lines) {
    const line = lineRaw
    if (/<dl/i.test(line)) {
      depth++
      // A folder header seen just above this DL is the folder we enter.
      const h3 = lineRaw.match(dtH3) || (folderStack.length ? null : null)
      continue
    }
    if (/<\/dl/i.test(line)) { depth--; if (folderStack.length > depth) folderStack.pop(); continue }
    const h3 = line.match(dtH3)
    if (h3) { folderStack.push(decodeEntities(h3[1]).replace(/<[^>]*>/g, '').trim().slice(0, 200)); continue }
    let m
    dtA.lastIndex = 0
    while ((m = dtA.exec(line)) !== null) {
      const url = decodeEntities(m[1]).trim()
      const title = decodeEntities(m[2].replace(/<[^>]*>/g, '')).trim()
      if (!url || BOOKMARK_SKIP_RE.test(url)) continue
      const addDate = /add_date\s*=\s*"(\d{10,13})"/i.exec(line)
      const ts = addDate ? Number(addDate[1]) : 0
      items.push(item('bookmark', {
        title: title || url,
        url,
        domain: csvDomain(url) || '',
        meta: {
          folder: folderStack.join('/'),
          visitedAt: ts > 0 ? (ts < 100000000000 ? ts * 1000 : ts) : 0,
        },
      }))
    }
  }
  return items
}

function historyItems(text, detected) {
  // R90 §2.2 — file-based history import is RETIRED. History arrives ONLY
  // through the direct browser import (date-range selector, cap 20,000,
  // preview before write). A dropped history export is never silently
  // ignored: every row is reported as skipped with the typed pointer to the
  // replacement surface. (Bookmarks/CSV logins and every other category are
  // unaffected.)
  const HIST_RETIRE = 'File-based history import retired — use Import Center → "Import browsing history from this browser" (7/30/90 days, preview before write).'
  if (detected.kind === 'json') {
    try {
      const data = JSON.parse(text)
      const arr = Array.isArray(data) ? data : []
      const droppedRows = []
      if (arr.length) {
        // One typed skipped entry PER FILE — the retirement is a policy about
        // the file type, not individual rows; the report stays readable.
        droppedRows.push({ row: 1, count: arr.length, reason: HIST_RETIRE })
      }
      return { items: [], droppedRows }
    } catch {
      return { error: 'Not a valid history JSON export — expected an array of {url, title, …}' }
    }
  }
  // CSV — detected as history-csv but every row is skipped (see above)
  return { items: [], droppedRows: [{ row: 1, reason: HIST_RETIRE }] }
}

/** Unified entry point: text → {ok, items, dialect, label, warning?, error?} */
export function parseImportFile(text) {
  const detected = detectFormat(text)
  if (detected.kind === 'unknown' || detected.dialect === 'encrypted' || detected.dialect === 'unknown-json') {
    return {
      ok: false,
      error: detected.dialect === 'encrypted'
        ? 'This export is password-protected/encrypted. Export again in an UNENCRYPTED format (Bitwarden: JSON/CSV without "password protected"; Dashlane: CSV; Firefox: CSV or JSON).'
        : `Unrecognized file format — ${detected.label}. Export a passwords CSV/JSON or a bookmarks HTML file from your browser.`,
      detected,
    }
  }

  let res
  if (detected.dialect === 'bookmarks') {
    res = { items: parseBookmarksHtml(text) }
  } else if (detected.dialect === 'firefox-json') {
    res = firefoxJsonItems(text)
  } else if (detected.dialect === 'bitwarden-json') {
    res = bitwardenJsonItems(text)
  } else if (detected.dialect === 'dashlane-json') {
    return {
      ok: false,
      error: 'Dashlane "secured file" exports are encrypted. In Dashlane use My account → Settings → Export data → Export to CSV (unencrypted), then import that file.',
      detected,
    }
  } else if (detected.dialect === 'history-json' || detected.dialect === 'history-csv') {
    res = historyItems(text, detected)
  } else {
    res = csvItems(text, detected)
  }

  if (res.error) return { ok: false, error: res.error, detected }

  // Enforce caps + within-file normalization
  const capped = capItems(res.items || [], res.droppedRows || [])
  if (capped.error) return { ok: false, error: capped.error, detected }
  return { ok: true, items: capped.items, warnings: capped.warnings, droppedRows: capped.droppedRows, detected }
}

const CAT_CAPS = [
  ['login', 'MAX_LOGINS'], ['totp', 'MAX_TOTP'], ['note', 'MAX_NOTES'],
  ['card', 'MAX_CARDS'], ['address', 'MAX_ADDRESSES'], ['bookmark', 'MAX_BOOKMARKS'],
  // R90 §2.2 — history is absent: file-based history import is retired in
  // favor of the direct date-range selector (no cap entry left behind).
  ['form', 'MAX_FORMS'],
]

function capItems(items, droppedRows = []) {
  const warnings = []
  const counts = {}
  for (const it of items) counts[it.category] = (counts[it.category] || 0) + 1

  if (items.length > LIMITS.MAX_ITEMS) {
    return { items: [], warnings: [], droppedRows: [], error: `Refusing to import more than ${LIMITS.MAX_ITEMS} items at once (file has ${items.length}). Split the export and import in batches.` }
  }
  const byCat = {}
  const kept = []
  for (const it of items) {
    byCat[it.category] = (byCat[it.category] || 0) + 1
    const capKey = CAT_CAPS.find(([c]) => c === it.category)?.[1]
    const cap = capKey ? LIMITS[capKey] : LIMITS.MAX_ITEMS
    const soFar = kept.filter(k => k.category === it.category).length
    if (soFar >= cap) continue
    kept.push(it)
  }
  for (const [cat, capKey] of CAT_CAPS) {
    if (byCat[cat] > LIMITS[capKey]) {
      // v2.18.0 — R27-F12 (audit): the leading "${LIMITS[capKey]}: " capKey
      // leak recorded by R26 never actually shipped — the warning still read
      // "1000: more than 1000 note items…". Cleaned copy:
      warnings.push(`More than ${LIMITS[capKey]} ${cat} items in the file — only the first ${LIMITS[capKey]} were kept`)
    }
  }
  // v2.18.0 — R27-F11: dropped rows survive the capping and reach the plan.
  return { items: kept, warnings, droppedRows: Array.isArray(droppedRows) ? droppedRows.slice(0, 500) : [] }
}

// --- Plan builder (classify against the current vault) -----------------------

const CATEGORIES = ['login', 'totp', 'note', 'card', 'address', 'bookmark', 'history', 'form']

function itemKey(it) {
  switch (it.category) {
    case 'login': return `${it.domain}::${it.username || ''}`
    case 'totp': return `${it.totp?.label || it.title || 'Imported token'}`
    case 'note': return `${PSEUDO_DOMAIN.note}::${it.title}`
    case 'card': return `${PSEUDO_DOMAIN.card}::${it.card?.holder || it.title}::${(it.card?.number || '').slice(-4)}`
    case 'address': return `${PSEUDO_DOMAIN.address}::${it.address?.name || it.title}`
    case 'bookmark': return `${PSEUDO_DOMAIN.bookmark}::${it.url}`
    case 'history': return `${PSEUDO_DOMAIN.history}::${it.url}`
    case 'form': return `${PSEUDO_DOMAIN.form}::${it.url}::${it.title}`
    default: return `${it.category}::${it.title}`
  }
}

function itemSecret(it) {
  switch (it.category) {
    case 'login': return it.password
    case 'totp': return it.totp?.secret || ''
    case 'note': return it.note
    case 'card': return JSON.stringify(it.card || {})
    case 'address': return JSON.stringify(it.address || {})
    case 'bookmark': return it.title
    case 'history': return `${it.title}::${it.meta?.visitCount || 0}`
    case 'form': return JSON.stringify(it.fields || [])
    default: return it.note
  }
}

/**
 * Vault-side counterpart of itemKey() — MUST produce byte-identical keys.
 * v2.7.0 round-16 harness caught a key-format drift here ('login::' prefix on
 * one side only) that silently disabled the never-overwrite classification.
 */
function vaultEntryKey(e) {
  if (!e || e.domain == null) return null
  const type = e.type || 'login'
  switch (type) {
    case 'login': return `${e.domain}::${e.username || ''}`
    case 'totp': return `${e.username || ''}`
    case 'note': return `${PSEUDO_DOMAIN.note}::${e.username || ''}`
    case 'card': return `${PSEUDO_DOMAIN.card}::${e.username || ''}::${String(e.card?.number || '').slice(-4)}`
    case 'address': return `${PSEUDO_DOMAIN.address}::${e.username || ''}`
    case 'bookmark': return `${PSEUDO_DOMAIN.bookmark}::${e.meta?.url || ''}`
    case 'history': return `${PSEUDO_DOMAIN.history}::${e.meta?.url || ''}`
    case 'form': return `${PSEUDO_DOMAIN.form}::${e.meta?.url || ''}::${e.username || ''}`
    default: return `${e.domain}::${e.username || ''}`
  }
}

function vaultEntrySecret(e) {
  switch (e?.type) {
    case 'totp': return e.totp?.secret || ''
    case 'note': return e.note || ''
    case 'card': return JSON.stringify({
      holder: e.card?.holder || e.username || '', brand: e.card?.brand || '',
      number: e.card?.number || '', expMonth: e.card?.expMonth || '',
      expYear: e.card?.expYear || '', code: e.card?.code || '',
    })
    case 'address': return JSON.stringify(e.address || {})
    case 'bookmark': return e.username || ''
    case 'history': return `${e.username || ''}::${e.meta?.visitCount || 0}`
    case 'form': return JSON.stringify(e.fields || [])
    default: return e.password || ''
  }
}

/**
 * ═══════════════════════════════════════════════════════════════════════
 * R90 §2.2 — DIRECT browser-history import law (pure, unit tested).
 *
 * The date-range selector REPLACES the retired whole-file/MAX_HISTORY=5000
 * behavior. The lawful shape:
 *   - picker values 7 / 30 / 90 days; DEFAULT 30 when anything else arrives
 *   - hard cap 20,000 rows per import
 *   - ONE explicit chrome.history.search({ text:'', startTime, endTime,
 *     maxResults }) — no incremental scanning, never any deletion
 *   - entries shaped exactly like the file pipeline's history entries
 *     (pseudo-domain __history__, meta.url/visitedAt/visitCount)
 * The chrome.* calls and the DOM stay in options.js — everything that can
 * be decided without a browser is here.
 * ═══════════════════════════════════════════════════════════════════════
 */
export const HISTORY_LAW = { ranges: [7, 30, 90], defaultDays: 30, cap: 20000 }

/** Pure: clamp a requested range to the lawful picker values. */
export function historyRangeOrDefault(days) {
  const n = Math.round(Number(days))
  return HISTORY_LAW.ranges.includes(n) ? n : HISTORY_LAW.defaultDays
}

/** Pure: raw chrome.history.search items → IMPORT_ENTRIES vault entries. */
export function historyItemsToEntries(items) {
  const out = []
  for (const it of Array.isArray(items) ? items : []) {
    if (!it || !it.url) continue
    out.push(itemToVaultEntry({
      category: 'history',
      title: String(it.title || '').slice(0, LIMITS.MAX_LEN.title),
      url: String(it.url).slice(0, LIMITS.MAX_LEN.url),
      meta: {
        visitedAt: Number(it.lastVisitTime) || 0,
        visitCount: Math.max(0, Math.min(999999, Number(it.visitCount) || 0)),
      },
    }))
  }
  return out
}

/** Pure: the typed preview summary (shown BEFORE any write). */
export function historyPreviewSummary(entries, { truncated = false } = {}) {
  if (truncated) {
    return {
      truncated: true,
      message: `This range holds more than ${HISTORY_LAW.cap} pages — narrow the range or import in parts. Nothing was written.`,
    }
  }
  if (!entries.length) {
    return { truncated: false, count: 0, message: 'No visited pages found in this range.' }
  }
  const times = entries.map(e => (e.meta && e.meta.visitedAt) || 0).filter(Boolean)
  const oldest = times.length ? Math.min(...times) : 0
  const newest = times.length ? Math.max(...times) : 0
  return {
    truncated: false,
    count: entries.length,
    oldest,
    newest,
    message: `${entries.length} pages found`,
  }
}

/** Convert a normalized item into the vault entry shape it will be saved as. */
export function itemToVaultEntry(it, now = Date.now()) {
  const ts = now
  switch (it.category) {
    case 'login':
      // v2.9.0 — DATA-LOSS FIX: Bitwarden/LastPass/1Password logins carry a
      // note, custom fields and a folder; the old mapping dropped them all.
      // v2.17.0 — R26-B1: multi-URI logins forward their alias list too.
      // v2.42.7 — R70 (F-R70-MODEL-1, "One Authenticator"): the login entry
      // NEVER persists a TOTP secret copy. The seed lives in exactly ONE
      // canonical standalone type:'totp' entry — produced by the
      // buildFullPlan expansion below with linkedLoginKey association
      // metadata. (The R69 bridge model kept an attached copy on the login;
      // two persisted copies risked drift, duplicate codes, inconsistent
      // deletion and merge divergence — superseded by this canonical model.)
      return {
        domain: it.domain, username: it.username, password: it.password,
        uris: (Array.isArray(it.uris) && it.uris.length) ? it.uris : undefined,
        note: it.note || undefined,
        fields: (Array.isArray(it.fields) && it.fields.length) ? it.fields : undefined,
        meta: (it.meta && (it.meta.folder || it.meta.url)) ? { folder: it.meta.folder || '', url: it.meta.url || '' } : undefined,
        createdAt: ts, updatedAt: ts,
      }
    case 'totp':
      // v2.42.7 — R70 §2.2: the canonical token entry. The block is clamped
      // (defense in depth — validated base32 shape, digits 6–10, period
      // 15–120, algorithm whitelist) exactly as the R69 login path did; the
      // validation moved WITH the secret to its single canonical home.
      return {
        domain: '__totp__',
        username: (it.totp.label || it.title || 'Imported token').slice(0, 64),
        password: '',
        type: 'totp',
        totp: clampImportTotp(it.totp),
        // v2.42.7 — R70 §2.2: the deterministic nonsecret login association.
        linkedLoginKey: it.linkedLoginKey || undefined,
        createdAt: ts, updatedAt: ts,
      }
    case 'note':
      return {
        domain: PSEUDO_DOMAIN.note, username: it.title || 'Untitled note', password: '',
        type: 'note', note: it.note, fields: it.fields || undefined,
        createdAt: ts, updatedAt: ts,
      }
    case 'card':
      return {
        domain: PSEUDO_DOMAIN.card, username: it.card.holder || it.title || 'Payment card', password: '',
        type: 'card', card: it.card, note: it.note || undefined, createdAt: ts, updatedAt: ts,
      }
    case 'address':
      return {
        domain: PSEUDO_DOMAIN.address, username: it.address.name || it.title || 'Identity', password: '',
        type: 'address', address: it.address, note: it.note || undefined, createdAt: ts, updatedAt: ts,
      }
    case 'bookmark':
      return {
        domain: PSEUDO_DOMAIN.bookmark, username: it.title || it.url, password: '',
        type: 'bookmark', meta: { url: it.url, folder: it.meta?.folder || '', visitedAt: it.meta?.visitedAt || 0 },
        createdAt: ts, updatedAt: ts,
      }
    case 'history':
      return {
        domain: PSEUDO_DOMAIN.history, username: it.title || it.url, password: '',
        type: 'history', meta: { url: it.url, visitedAt: it.meta?.visitedAt || 0, visitCount: it.meta?.visitCount || 0 },
        createdAt: ts, updatedAt: ts,
      }
    case 'form':
      // Form data lives under the pseudo-domain so it can never surface in
      // autofill queries for a real site; the site URL rides in meta.url.
      return {
        domain: PSEUDO_DOMAIN.form, username: it.title || it.username || 'Form data', password: '',
        type: 'form', fields: it.fields || [], meta: { url: it.url, ...(it.meta || {}) },
        note: it.note || undefined, createdAt: ts, updatedAt: ts,
      }
    default:
      return null
  }
}

/**
 * v2.42.5 — R69 (F-R69-IMP-1): storage-shape clamp for import-provided TOTP
 * params — the SAME rules as saveTotpToken/saveEntriesBatch in vault.js
 * (digits 6–10, period 15–120s, algorithm whitelist, default SHA-1) so an
 * imported seed can never store parameters the runtime would reject.
 */
function clampImportTotp(t) {
  const num = (v, min, max, fb) => {
    const x = Math.round(Number(v))
    return Number.isFinite(x) ? Math.min(max, Math.max(min, x)) : fb
  }
  return {
    secret: String(t.secret || '').toUpperCase().replace(/[\s-]/g, ''),
    issuer: String(t.issuer || '').slice(0, 64),
    digits: num(t.digits, 6, 10, 6),
    period: num(t.period, 15, 120, 30),
    algorithm: normTotpAlgorithm(t.algorithm),
  }
}

/**
 * Build the full import plan. Pure — no chrome.*, no I/O.
 *
 * @param {Array}  items            normalized items from parseImportFile()
 * @param {Array}  existingEntries  current vault entries
 * @param {Object} opts             { categories: {login:true, …} } — selection
 * @returns {ok, additions, stats, conflicts, skipped, invalid}
 */
export function buildFullPlan(items, existingEntries, opts = {}) {
  const existing = Array.isArray(existingEntries) ? existingEntries : []
  const selection = opts.categories || null
  const vaultMap = new Map()
  for (const e of existing) {
    const k = vaultEntryKey(e)
    if (k) vaultMap.set(k, e)
  }
  // v2.42.5 — R69 (F-R69-IMP-1): seed→token-owner map — an IDENTICAL seed is
  // a duplicate/no-op regardless of how its label is spelled.
  const vaultSeed = new Map()
  for (const e of existing) {
    if (e?.type === 'totp' && e.totp?.secret) vaultSeed.set(e.totp.secret, e.username || '')
  }

  // v2.42.5 — R69 (F-R69-IMP-1): EXPANSION — every login item carrying a
  // VALID seed also yields a standalone authenticator item.
  // v2.42.7 — R70 (F-R70-MODEL-1, "One Authenticator"): the expansion is now
  // the ONLY persistence the seed gets — the standalone type:'totp' entry is
  // the canonical secret holder and carries linkedLoginKey = the login's
  // deterministic nonsecret key (same format as the vault's entryKey). The
  // login entry itself persists NO totp copy (itemToVaultEntry 'login').
  // Both categories report exactly: "N logins, N authenticators".
  const loginEntryKey = (domain, username) => `${String(domain)}\u0000${String(username)}`
  const expanded = []
  for (const it of (Array.isArray(items) ? items : [])) {
    expanded.push(it)
    if (it?.category === 'login' && it.totp?.secret) {
      const base = it.totp.issuer || it.totp.label || it.title || it.domain || 'Imported token'
      const label = it.username && !String(base).toLowerCase().includes(String(it.username).toLowerCase())
        ? `${base} — ${it.username}`
        : base
      expanded.push(item('totp', {
        title: String(label).slice(0, 64),
        totp: it.totp,
        linkedLoginKey: loginEntryKey(it.domain, it.username),
      }))
    }
  }

  const additions = []
  const conflicts = []
  const skipped = []
  const stats = {
    total: 0, added: 0, duplicates: 0, conflicts: 0, invalid: 0,
    byCategory: Object.fromEntries(CATEGORIES.map(c => [c, { total: 0, added: 0, duplicates: 0, conflicts: 0, invalid: 0 }])),
  }
  const seen = new Map() // within-file dedupe: itemKey → secret
  const seenSeed = new Map() // v2.42.5 — R69: within-file seed dedupe

  for (const it of expanded) {
    if (!it || !it.category || !CATEGORIES.includes(it.category)) continue
    const cat = stats.byCategory[it.category]
    cat.total++
    stats.total++

    // Selection filter
    if (selection && selection[it.category] === false) {
      skipped.push({ title: it.title || it.username || it.url || it.category, reason: `${it.category} category deselected` })
      continue
    }

    // Validate minimally
    let invalidReason = ''
    if (it.category === 'login' && (!it.domain || !it.password)) invalidReason = !it.domain ? 'no usable web address' : 'empty password'
    if (it.category === 'totp' && !(it.totp && it.totp.secret)) invalidReason = 'missing TOTP secret'
    if (it.category === 'note' && !it.note && !(it.fields && it.fields.length)) invalidReason = 'empty note'
    if (it.category === 'card' && !(it.card && it.card.number)) invalidReason = 'missing card number'
    if (it.category === 'address' && !(it.address && (it.address.name || it.address.email))) invalidReason = 'empty identity'
    if (it.category === 'bookmark' && !it.url) invalidReason = 'missing URL'
    if (it.category === 'history' && !it.url) invalidReason = 'missing URL'
    if (it.category === 'form' && !(it.fields && it.fields.length)) invalidReason = 'no form fields'
    if (invalidReason) {
      stats.invalid++
      cat.invalid++
      skipped.push({ title: it.title || it.username || it.url || it.category, reason: invalidReason })
      continue
    }

    const key = itemKey(it)
    const secret = itemSecret(it)

    // v2.42.5 — R69 (F-R69-IMP-1): an IDENTICAL seed already in the vault or
    // earlier in this file is a duplicate (no-op) — never a second token
    // carrying the same secret under a different label.
    if (it.category === 'totp' && secret) {
      const owner = vaultSeed.get(secret)
      if (owner !== undefined) {
        stats.duplicates++
        cat.duplicates++
        skipped.push({ title: it.title || 'authenticator', reason: `identical authenticator seed is already in the vault (token "${owner}") — nothing changed` })
        continue
      }
      if (seenSeed.has(secret)) {
        stats.duplicates++
        cat.duplicates++
        skipped.push({ title: it.title || 'authenticator', reason: 'identical authenticator seed appears earlier in this file — first occurrence kept' })
        continue
      }
      seenSeed.set(secret, key)
    }

    const inVault = vaultMap.get(key)
    const inFile = seen.get(key)

    if ((inVault && vaultEntrySecret(inVault) === secret) || (inFile === secret)) {
      stats.duplicates++
      cat.duplicates++
      continue
    }
    if (inVault || inFile !== undefined) {
      stats.conflicts++
      cat.conflicts++
      conflicts.push({
        category: it.category,
        title: it.title || it.username || it.url || it.domain,
        detail: inVault
          ? 'already in the vault with different content — the vault copy is kept'
          : 'appears twice in this file with different content — first occurrence kept',
      })
      continue
    }

    seen.set(key, secret)
    const entry = itemToVaultEntry(it)
    if (!entry) continue
    additions.push({ item: it, entry })
    stats.added++
    cat.added++
  }

  // v2.18.0 — R27-F11: rows the parsers could not represent (no usable URL
  // AND no password; history rows without a URL; hostless Firefox logins)
  // used to vanish without a trace. They ride into the plan as skipped rows
  // (marked dropped:true) so the existing "Review (N)" report lists them.
  // They intentionally do NOT count into stats.invalid — they were never
  // parsed into items, so the category stats stay truthful.
  const dropped = Array.isArray(opts.droppedRows) ? opts.droppedRows : []
  for (const d of dropped.slice(0, 500)) {
    skipped.push({
      title: d.title || (d.row != null ? `Row ${d.row}` : 'row'),
      reason: d.reason || 'row could not be represented as an entry',
      dropped: true,
    })
  }

  return { ok: true, additions, stats, conflicts, skipped }
}

/** Friendly one-line summary of the plan stats (used by the report UI). */
export function planSummary(stats) {
  const parts = []
  for (const c of CATEGORIES) {
    const s = stats.byCategory[c]
    if (s && s.added > 0) parts.push(`${s.added} ${c}${s.added === 1 ? '' : 's'}`)
  }
  return parts.length ? parts.join(', ') : 'nothing new'
}

// ═══════════════════════════════════════════════════════════════════════════
// R101 §3 — THE MIGRATION WIZARD (S3, "Take your stuff with you" — the CEO's
// commanded first-run surface). PURE decisions only: the chrome.* calls are
// wired in options.js (the R90 pattern — the testable decision lives here).
//
// The law of the wizard:
//   - ORCHESTRATION of proven engines in one flow — NO new import paths
//     (the standing law): bookmarks ride the bookmark item shape, history
//     rides the HISTORY_LAW engine, passwords ride the CSV parser.
//   - the typed password truth: browsers do NOT let extensions read saved
//     passwords — the wizard says so, deep-links the browser's own export
//     page, takes the CSV, and REMINDS the user to delete the CSV after.
//   - what the platform honestly allows, per browser, never more.
// ═══════════════════════════════════════════════════════════════════════════

/** The per-browser honest offer. `passwords` is ALWAYS the typed truth (an
 * extension cannot read browser password stores — no silent pretending);
 * `exportPath` is the browser's own settings deep link. */
export const MIGRATION_BROWSERS = {
  chrome: { name: 'Google Chrome', bookmarks: true, history: true, passwordsExport: 'chrome://settings/passwords' },
  edge: { name: 'Microsoft Edge', bookmarks: true, history: true, passwordsExport: 'edge://settings/passwords' },
  brave: { name: 'Brave', bookmarks: true, history: true, passwordsExport: 'brave://settings/passwords' },
  opera: { name: 'Opera', bookmarks: true, history: true, passwordsExport: 'opera://settings/passwords' },
  vivaldi: { name: 'Vivaldi', bookmarks: true, history: true, passwordsExport: 'vivaldi://settings/passwords' },
  firefox: { name: 'Firefox', bookmarks: true, history: false, passwordsExport: 'about:logins' },
  safari: { name: 'Safari', bookmarks: true, history: false, passwordsExport: '' },
}

/** The wizard's browser list (the detection's universe — the same ids the
 * Import Center's override select offers). */
export const MIGRATION_BROWSER_IDS = ['chrome', 'edge', 'brave', 'opera', 'vivaldi', 'firefox', 'safari']

/** The typed passwords truth, per browser (never an empty promise: a Safari
 * row points at the System Settings path because it has no deep link). */
export function passwordsExportLink(browserId) {
  const b = MIGRATION_BROWSERS[browserId]
  if (!b) return { link: '', note: 'settings' }
  if (browserId === 'safari') {
    return { link: '', note: 'System Settings → Passwords (Safari keeps them outside the browser)' }
  }
  return { link: b.passwordsExport, note: '' }
}

/** Flatten a live chrome.bookmarks tree into import items (the SAME bookmark
 * item shape the HTML parser emits: category 'bookmark', the folder path in
 * meta.folder). Skips folders (no url) and javascript:/chrome:// rows — the
 * same skip class the file parser applies. The tree's own roots ("Bookmarks
 * bar", "Other bookmarks") are not folders the user created — their names
 * are dropped from the path; a real folder inside them starts the path. */
export function flattenBookmarkTree(nodes, { skipRe = /^(javascript:|chrome:|edge:|brave:|about:)/i } = {}) {
  const items = []
  const BUILTIN_ROOTS = new Set(['Bookmarks bar', 'Other bookmarks', 'Mobile bookmarks', 'Synced bookmarks'])
  const walk = (list, pathParts) => {
    for (const n of Array.isArray(list) ? list : []) {
      if (!n || typeof n !== 'object') continue
      if (n.url) {
        const url = String(n.url || '').trim()
        if (!url || skipRe.test(url)) continue
        const folder = pathParts.filter(Boolean).join('/')
        items.push(item('bookmark', {
          title: String(n.title || '').trim() || url,
          url,
          domain: csvDomain(url) || '',
          meta: { folder, visitedAt: 0, visitCount: 0 },
        }))
      } else if (Array.isArray(n.children)) {
        const name = String(n.title || '').trim()
        const next = (pathParts.length === 0 && (!name || BUILTIN_ROOTS.has(name))) ? pathParts : [...pathParts, name].filter(Boolean)
        walk(n.children, next)
      }
    }
  }
  walk(nodes, [])
  return items
}
