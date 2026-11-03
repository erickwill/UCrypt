/**
 * UCrypt — Per-site save exceptions (v2.9.0).
 *
 * Brave/Chrome parity: "Never save passwords for this site". Until now the
 * save prompt only offered "Not now" — a per-page-load dismissal — so users
 * browsing sites where passwords are managed by SSO/other tools were re-prompted
 * on every single sign-in. The site list is DEVICE-LOCAL UI state (stored in
 * chrome.storage.local, NOT in the encrypted vault, NOT synced):
 *
 *   - Brave does not sync its NeverSavePasswordList either — syncing a
 *     "suppress the save prompt" rule through an encrypted blob shared with
 *     strangers' devices would surprise more than it helps.
 *   - It never touches autofill: like Chrome, a never-save site still gets
 *     saved-logins autofill; only the SAVE PROMPT is suppressed.
 *
 * This module is the single source of truth for the list and its matching
 * rules; background/content/options only call in. Pure helpers are exported
 * for direct unit testing (tests/round18-test.mjs).
 */

const NEVER_SAVE_KEY = 'ucrypt:neverSave'
export const NEVER_SAVE_MAX = 500
// R85 (§6): per-site NEVER-FILL exceptions — the autofill counterpart of the
// never-save list. A listed site never receives an automatic fill OR a
// suggestion; the user fills it manually by explicit choice.
const NEVER_FILL_KEY = 'ucrypt:neverFill'
export const NEVER_FILL_MAX = 500

/**
 * Normalize a domain for storage/matching: lowercase, strip a leading "www.",
 * trim, and reject anything that does not look like a hostname.
 * @returns {string} normalized domain, or '' when unusable
 */
export function normalizeSite(domain) {
  let d = String(domain || '').trim().toLowerCase()
  if (!d) return ''
  // Tolerate a pasted URL — users will paste "https://x.com/login"
  if (d.includes('://') || d.includes('/')) {
    try {
      const u = new URL(d.includes('://') ? d : 'https://' + d)
      d = u.hostname
    } catch {
      return ''
    }
  }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(d)) return ''
  if (d.startsWith('www.')) d = d.slice(4)
  // v2.9.0 (QA finding): a save prompt CAN appear on localhost (local apps,
  // dev servers) — the exception list must accept it too. Multi-label guard
  // below stays strict for everything else.
  if (d === 'localhost') return d
  if (!d.includes('.') || d.length > 253) return ''
  return d
}

/**
 * eTLD+1 approximation (the "site key" used for domain-proximity matching).
 * A pragmatic second-level suffix table covers the common cases (co.uk,
 * com.au, …) without shipping the full Public Suffix List into every page.
 *
 *   siteKeyOf('mail.google.com')  → 'google.com'
 *   siteKeyOf('www.bbc.co.uk')    → 'bbc.co.uk'
 *   siteKeyOf('example.com')      → 'example.com'
 */
const MULTIPART_SUFFIXES = new Set([
  // uk
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  // australia
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  // japan / brazil / india / mexico / others
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'com.mx', 'com.tr', 'com.cn', 'com.tw', 'com.hk', 'com.sg',
  'co.nz', 'net.nz', 'org.nz', 'org.cn', 'co.za', 'com.ar', 'com.pl',
])

export function siteKeyOf(domain) {
  const d = normalizeSite(domain)
  if (!d) return ''
  const labels = d.split('.')
  if (labels.length <= 2) return d
  const lastTwo = labels.slice(-2).join('.')
  if (MULTIPART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.')
  }
  return lastTwo
}

/**
 * Match a page domain against the exception list:
 *   - the page domain itself is listed, OR
 *   - the page's eTLD+1 (site key) is listed → the exception covers every
 *     subdomain of that site (login.example.com covers example.com sign-ins).
 * Pure — list comes in, no chrome access — so tests can hammer it.
 */
export function shouldNeverSave(domain, list) {
  const d = normalizeSite(domain)
  if (!d || !Array.isArray(list) || list.length === 0) return false
  if (list.includes(d)) return true
  const key = siteKeyOf(d)
  return !!key && list.includes(key)
}

/** R85 (§6): identical matching semantics for the never-FILL list. */
export const shouldNeverFill = shouldNeverSave

// --- Async CRUD (chrome.storage.local is the backing store) -----------------

export async function getNeverSaveSites() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(NEVER_SAVE_KEY, (r) => {
        const v = r && r[NEVER_SAVE_KEY]
        resolve(Array.isArray(v) ? v.filter(x => typeof x === 'string') : [])
      })
    } catch {
      resolve([])
    }
  })
}

export async function addNeverSaveSite(domain) {
  const site = normalizeSite(domain)
  if (!site) return { ok: false, error: 'That does not look like a website address' }
  const list = await getNeverSaveSites()
  if (list.includes(site)) return { ok: true, sites: list, already: true }
  if (list.length >= NEVER_SAVE_MAX) {
    return { ok: false, error: `The never-save list is full (${NEVER_SAVE_MAX} sites)` }
  }
  const next = [...list, site].sort()
  await new Promise((resolve) => chrome.storage.local.set({ [NEVER_SAVE_KEY]: next }, resolve))
  return { ok: true, sites: next, added: site }
}

export async function removeNeverSaveSite(domain) {
  const site = normalizeSite(domain)
  if (!site) return { ok: false, error: 'Invalid site' }
  const list = await getNeverSaveSites()
  if (!list.includes(site)) return { ok: true, sites: list, already: true }
  const next = list.filter(s => s !== site)
  await new Promise((resolve) => chrome.storage.local.set({ [NEVER_SAVE_KEY]: next }, resolve))
  return { ok: true, sites: next, removed: site }
}


// --- R85 (§6): never-fill CRUD (mirror of the never-save CRUD above) ---------

export async function getNeverFillSites() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(NEVER_FILL_KEY, (r) => {
        const v = r && r[NEVER_FILL_KEY]
        resolve(Array.isArray(v) ? v.filter(x => typeof x === 'string') : [])
      })
    } catch {
      resolve([])
    }
  })
}

export async function addNeverFillSite(domain) {
  const site = normalizeSite(domain)
  if (!site) return { ok: false, error: 'That does not look like a website address' }
  const list = await getNeverFillSites()
  if (list.includes(site)) return { ok: true, sites: list, already: true }
  if (list.length >= NEVER_FILL_MAX) {
    return { ok: false, error: `The never-fill list is full (${NEVER_FILL_MAX} sites)` }
  }
  const next = [...list, site].sort()
  await new Promise((resolve) => chrome.storage.local.set({ [NEVER_FILL_KEY]: next }, resolve))
  return { ok: true, sites: next, added: site }
}

export async function removeNeverFillSite(domain) {
  const site = normalizeSite(domain)
  if (!site) return { ok: false, error: 'Invalid site' }
  const list = await getNeverFillSites()
  const next = list.filter((x) => x !== site)
  await new Promise((resolve) => chrome.storage.local.set({ [NEVER_FILL_KEY]: next }, resolve))
  return { ok: true, sites: next, removed: site }
}
