/**
 * UCrypt — chrome.i18n foundation (v2.10.0).
 *
 * Brave/Chrome ship their UI in dozens of languages; UCrypt shipped EN-only
 * through v2.9.0. This module is the localization FOUNDATION:
 *
 *   - Messages live in _locales/<locale>/messages.json (Chrome's standard
 *     layout). `default_locale: "en"` in the manifest makes any missing key
 *     in a partial locale fall back to English automatically.
 *   - Manifest-level strings (name, description, command titles) reference
 *     __MSG_extName__ etc., so the browser itself localizes them in
 *     chrome://extensions, the shortcuts page and the store listing.
 *   - background.js localizes context-menu titles and notifications through
 *     getMessage() below.
 *   - Static UI in popup.html / options.html carries data-i18n attributes;
 *     applyI18n() swaps the text at startup when a translation exists. The
 *     English text stays in the HTML as the source of truth, so a page is
 *     fully usable (and every test/wiring tripwire still passes) even when
 *     chrome.i18n is absent — e.g. under QA stubs.
 *
 *     data-i18n              → el.textContent
 *     data-i18n-placeholder  → el.placeholder
 *     data-i18n-title        → el.title
 *     data-i18n-aria         → el.setAttribute('aria-label', …)
 *
 * Scope (v2.10.0): manifest + context menus + notifications + the full
 * popup + the options navigation chrome. Deep body copy (Import Center
 * step-by-step cards, long help paragraphs) is tracked for v2.11+.
 */

/**
 * Look up a localized message with a hard fallback.
 *
 * Never throws: when chrome.i18n is missing (QA stubs, exotic embeds) or the
 * key has no translation, `fallback` is returned. Chrome returns '' for
 * unknown keys, which would otherwise wipe UI text.
 *
 * @param {string} key       message name in the _locales message catalogs
 * @param {string[]} [subs]  $1/$2… substitutions (chrome.i18n semantics)
 * @param {string} [fallback] English source string
 * @returns {string}
 */
/**
 * R79 (F-R78-7): when the locale catalog is missing (or the key is absent),
 * the fallback is interpolated with the SAME positional substitutions the
 * locale message would have received — a missing key can no longer render
 * literal "$PLACEHOLDER$" markers to the user. Both marker styles are
 * handled: numeric ($1$, $2$…) and named ($TIME$…, mapped to subs in
 * first-occurrence order — the exact convention every caller uses).
 */
function interpolateFallback(fallback, subs) {
  if (subs === undefined || subs === null || !Array.isArray(subs) || !subs.length) return fallback
  let text = String(fallback)
  const named = []
  text = text.replace(/\$([A-Z_][A-Z0-9_]*)\$/g, (whole, name) => {
    if (!named.includes(name)) named.push(name)
    return `\u0000${name}\u0000`
  })
  const lookup = (token) => {
    const n = Number(token)
    if (Number.isInteger(n)) return n >= 1 && n <= subs.length ? String(subs[n - 1]) : token
    const idx = named.indexOf(token)
    return idx >= 0 && idx < subs.length ? String(subs[idx]) : token
  }
  text = text.replace(/\u0000([A-Z_][A-Z0-9_]*)\u0000/g, (w, name) => lookup(name))
  text = text.replace(/\$(\d+)\$/g, (whole, n) => lookup(n))
  return text
}

export function getMessage(key, subs = undefined, fallback = '') {
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n &&
        typeof chrome.i18n.getMessage === 'function') {
      const s = subs !== undefined ? chrome.i18n.getMessage(key, subs)
                                   : chrome.i18n.getMessage(key)
      if (s) return s
    }
  } catch { /* stubbed or unavailable — fall through */ }
  return interpolateFallback(fallback, subs)
}

/** True when at least one data-i18n* attribute actually replaced text. */
let _applied = 0

/**
 * Localize every marked element under `root` (default: the document).
 * Safe to call more than once; safe when chrome.i18n is missing (it then
 * leaves the English HTML content untouched and returns 0).
 *
 * @param {Document|Element} [root]
 * @returns {number} number of replacements performed
 */
export function applyI18n(root = (typeof document !== 'undefined' ? document : undefined)) {
  _applied = 0
  if (!root || typeof root.querySelectorAll !== 'function') return 0
  const swap = (el, value) => {
    if (!value) return
    _applied++
  }
  // textContent
  for (const el of root.querySelectorAll('[data-i18n]')) {
    const s = getMessage(el.getAttribute('data-i18n'), undefined, '')
    if (s) { el.textContent = s; swap(el, s) }
  }
  // placeholder
  for (const el of root.querySelectorAll('[data-i18n-placeholder]')) {
    const s = getMessage(el.getAttribute('data-i18n-placeholder'), undefined, '')
    if (s) { el.setAttribute('placeholder', s); swap(el, s) }
  }
  // title tooltip
  for (const el of root.querySelectorAll('[data-i18n-title]')) {
    const s = getMessage(el.getAttribute('data-i18n-title'), undefined, '')
    if (s) { el.setAttribute('title', s); swap(el, s) }
  }
  // aria-label
  for (const el of root.querySelectorAll('[data-i18n-aria]')) {
    const s = getMessage(el.getAttribute('data-i18n-aria'), undefined, '')
    if (s) { el.setAttribute('aria-label', s); swap(el, s) }
  }
  // v2.18.0 — R27: alt text (e.g. the sync-code QR image)
  for (const el of root.querySelectorAll('[data-i18n-alt]')) {
    const s = getMessage(el.getAttribute('data-i18n-alt'), undefined, '')
    if (s) { el.setAttribute('alt', s); swap(el, s) }
  }
  return _applied
}
