/**
 * UCrypt — R145 §5.2 — THE EMBED GUARD (G-1, the shell must never swallow
 * itself).
 *
 * THE FIELD DISEASE (capture A2, pinned): in a Helium-class browser the
 * Device Transfer tab's iframe loaded the ENTIRE options shell inside
 * itself — two headers, two tab bars in one viewport. The root cause is
 * the class the contract outlaws: the embed surface resolved from a
 * RELATIVE path that a fork may resolve against the wrong base, and the
 * embed MODE was decided only by a query parameter a fork may strip.
 *
 * THE CURE IS STRUCTURAL (three independent walls):
 *   1. ABSOLUTE SRC — the iframe's source is always built by
 *      absoluteTransferUrl(chrome.runtime.getURL) — never a relative path.
 *   2. FRAMING FORCES EMBED MODE — embedMode() reads window.self !==
 *      window.top FIRST (a query is only the secondary signal). A framed
 *      document renders the bare surface even if every param was stripped.
 *   3. THE SHELL REFUSES FRAMING — options.html booted inside a frame
 *      REPLACES itself with the bare transfer surface (assertOptionsNotFramed
 *      returns the escape URL). Nesting is structurally impossible: the
 *      shell cannot render framed, and the bare surface cannot render a
 *      shell.
 *
 * PURE (window injected) — battery-pinned (tests/r145-round.test.mjs, the
 * Helium-class fixture: the query stripped, the framing alone decides).
 */

/** The bare transfer surface's path (the ONLY lawful embed target). */
export const TRANSFER_SURFACE_PATH = 'transfer.html'

/** The embed params the devices-mode embed rides (kept stable for the
 * worker's roster wiring). */
export const TRANSFER_EMBED_PARAMS = 'embed=1&mode=devices'

/**
 * WALL 1 — the absolute embed URL. Built from the injected resolver so the
 * battery can drive it without chrome.*. Returns null when the resolver is
 * unavailable (the caller then hides the frame — never a relative guess).
 *
 * @param {(() => string) | null} getURL  e.g. () => chrome.runtime.getURL('')
 * @param {string} [mode]  'devices' (default) or 'share'
 * @returns {string | null}
 */
export function absoluteTransferUrl(getURL, mode = 'devices') {
  if (typeof getURL !== 'function') return null
  try {
    const base = String(getURL(''))
    if (!base) return null
    const u = new URL(TRANSFER_SURFACE_PATH, base)
    u.search = `?${TRANSFER_EMBED_PARAMS}&mode=${encodeURIComponent(mode)}`
    // normalize the doubled embed params: rebuild cleanly
    u.search = `?embed=1&mode=${encodeURIComponent(mode)}`
    return u.href
  } catch {
    return null
  }
}

/**
 * WALL 2 — FRAMING FORCES EMBED MODE. Framing is detected structurally
 * (self vs top); the query param is only the secondary signal. Either
 * signal — or both — yields embed mode.
 *
 * @param {{ self?: object, top?: object, parent?: object }} win  a window-like
 * @param {URLSearchParams | string} [params]  the document's query
 * @returns {{ framed: boolean, paramEmbed: boolean, embed: boolean }}
 */
export function embedMode(win, params = '') {
  let framed = false
  try {
    const w = win || {}
    // self !== top means framed; a cross-origin throw means framed too
    framed = !!(w.self && w.top && w.self !== w.top)
  } catch {
    framed = true // an inaccessible window.top is itself the framing proof
  }
  let paramEmbed = false
  try {
    const sp = params instanceof URLSearchParams ? params : new URLSearchParams(String(params || ''))
    paramEmbed = sp.get('embed') === '1'
  } catch {
    paramEmbed = false
  }
  return { framed, paramEmbed, embed: framed || paramEmbed }
}

/**
 * WALL 3 — THE SHELL REFUSES FRAMING. Called at the very top of the
 * options page boot: if the shell document is framed, the boot REPLACES
 * the frame with the bare transfer surface (the escape URL). The shell
 * rendering inside a shell is unrepresentable after this runs.
 *
 * @param {{ self?: object, top?: object }} win
 * @param {(() => string) | null} getURL
 * @returns {{ framed: boolean, escapeUrl: string | null }}
 */
export function assertOptionsNotFramed(win, getURL) {
  let framed = false
  try {
    const w = win || {}
    framed = !!(w.self && w.top && w.self !== w.top)
  } catch {
    framed = true
  }
  if (!framed) return { framed: false, escapeUrl: null }
  return { framed: true, escapeUrl: absoluteTransferUrl(getURL, 'devices') }
}
