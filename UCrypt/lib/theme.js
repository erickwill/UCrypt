/**
 * UCrypt — R142 §6 — THE THEME LAW (both themes, every page, one truth).
 *
 * THE F-3 ROOT CAUSE (published in r142-claims-audit.json): the theme is the
 * `data-theme` ATTRIBUTE on <html> (options.js:435 sets it, style.css:46
 * `[data-theme="dark"]` consumes it) — but the transfer page lives INSIDE AN
 * IFRAME (options.html:1825) whose document NEVER received the attribute.
 * The iframe rendered light forever inside the dark shell — exactly the
 * owner's capture.
 *
 * THE CURE: every page (the options page AND every iframe/page document)
 * resolves the theme from the SAME persisted preference at boot, applies it
 * to its own documentElement, and WATCHES for changes (the toggle re-themes
 * every surface live). prefers-color-scheme is honored when no preference is
 * persisted (§6.2). The six token roles (bg, fg, panel, border, accent,
 * danger) resolve from style.css in BOTH themes — G94 asserts the derivation.
 *
 * The storage is injectable so the battery pins every branch headlessly.
 */

export const THEME_KEY = 'ucrypt:theme'

export function themeError(code, message) {
  const e = new Error(message)
  e.code = `THEME_${code}`
  return e
}

/** Read the persisted preference (chrome.storage-shaped, injectable). */
export async function readStoredTheme(storage) {
  try {
    const got = await storage.local.get(THEME_KEY)
    const t = got && got[THEME_KEY]
    if (t === 'light' || t === 'dark') return t
    return null
  } catch {
    return null
  }
}

/** The resolution order: the persisted choice FIRST, then the OS preference. */
export function resolveThemeSync(stored, { prefersDark = false } = {}) {
  if (stored === 'light' || stored === 'dark') return stored
  return prefersDark ? 'dark' : 'light'
}

export async function resolveTheme(storage, { prefersDark = typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches } = {}) {
  return resolveThemeSync(await readStoredTheme(storage), { prefersDark })
}

/** Apply the theme to ONE document (the page's own documentElement). */
export function applyThemeToDocument(doc, theme) {
  if (theme !== 'light' && theme !== 'dark') throw themeError('SHAPE', `the theme is light or dark (${String(theme)})`)
  doc.documentElement.setAttribute('data-theme', theme)
  doc.documentElement.style.colorScheme = theme
  return theme
}

/**
 * THE BOOT LAW: resolve + apply + watch. Every registered page calls this at
 * module load (before first paint of the themed surfaces). The watcher keeps
 * the iframe and its host in lockstep — toggling dark in the shell re-themes
 * the transfer card the same second.
 */
export async function bootTheme({ storage, doc = document, media = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null } = {}) {
  if (!storage) throw themeError('SHAPE', 'bootTheme needs the storage')
  const theme = resolveThemeSync(await readStoredTheme(storage), { prefersDark: !!(media && media.matches) })
  applyThemeToDocument(doc, theme)
  try {
    storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes && changes[THEME_KEY]) {
        const t = changes[THEME_KEY].newValue
        if (t === 'light' || t === 'dark') applyThemeToDocument(doc, t)
      }
    })
  } catch { /* the watcher is best-effort; the boot application stands */ }
  return theme
}

/** The registered pages (G94's matrix — every page × both themes × 6 roles). */
export const REGISTERED_THEME_PAGES = Object.freeze([
  'options.html',
  'popup.html',
  'transfer.html',
])

/** The six token roles (§6.2) and the style.css custom properties that carry them. */
export const TOKEN_ROLES = Object.freeze({
  bg: '--bg',
  fg: '--text',
  panel: '--card',
  border: '--border',
  accent: '--accent',
  danger: '--danger',
})
