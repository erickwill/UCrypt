/**
 * UCrypt — lib/ladder-illustrations.js
 *
 * R120 §2.1 — THE ILLUSTRATED WALKTHROUGHS (Gap 1 — the CEO's explicit ask):
 * each transport's guided walkthrough gains its two annotated console screens.
 *
 * LAW 0.17 (vetted-vendor): EVERY illustration here is SELF-DRAWN — hand-
 * authored inline SVG facsimiles of the real console layouts. No screenshot
 * of Google's / GitHub's / Dropbox's UI ships raw, no <image>, no external
 * asset, no third-party code. The drawings point at the real console and say
 * what to do — UCrypt showing the way, drawn by UCrypt itself.
 *
 * THEME LAW: every fill/stroke rides a CSS variable (var(--card) /
 * var(--bg-soft) / var(--border) / var(--text) / var(--muted) /
 * var(--accent)) — the illustrations follow BOTH themes automatically, the
 * same law the ladder styles obey. Zero raw hex colors.
 *
 * THE ANNOTATION LAW: exactly ONE boxed click-target per illustration (the
 * accent box), one caption line beneath (i18n, ×3 locales), one honest
 * what-you-are-looking-at alt line (i18n).
 *
 * PURE data + string builders: no chrome.* calls, no DOM, no network — the
 * battery drives the strings directly; ladder-ui.js renders them.
 */

/** The shared SVG prologue: viewBox, role, the aria wiring, the responsive width. */
function svgDoc(inner, altKey, ctx) {
  return [
    '<svg viewBox="0 0 560 340" xmlns="http://www.w3.org/2000/svg" role="img" data-alt="' + altKey + '"',
    ' preserveAspectRatio="xMidYMid meet" class="ladder-illu-svg" data-redirect="' + esc(String((ctx && ctx.redirect) || '')) + '">',
    inner,
    '</svg>',
  ].join('')
}

/** Attribute-safe escaping for dynamic strings (the redirect URI) inside SVG. */
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;')
}

/** The browser-chrome frame every facsimile sits in: bar + three dots + an address pill. */
function chromeFrame(address) {
  return [
    '<rect x="4" y="4" width="552" height="332" rx="10" style="fill:var(--bg-soft)" stroke="var(--border)" stroke-width="1.5"/>',
    '<rect x="4" y="4" width="552" height="34" rx="10" style="fill:var(--card)" stroke="var(--border)" stroke-width="1"/>',
    '<rect x="4" y="30" width="552" height="8" style="fill:var(--card)" stroke="none"/>',
    '<circle cx="24" cy="21" r="5" style="fill:var(--muted)" opacity="0.55"/>',
    '<circle cx="40" cy="21" r="5" style="fill:var(--muted)" opacity="0.35"/>',
    '<circle cx="56" cy="21" r="5" style="fill:var(--muted)" opacity="0.2"/>',
    '<rect x="76" y="11" width="360" height="20" rx="10" style="fill:var(--bg-soft)" stroke="var(--border)" stroke-width="1"/>',
    '<text x="90" y="25" font-family="ui-monospace,monospace" font-size="10" style="fill:var(--muted)">' + esc(address) + '</text>',
  ].join('')
}

/** The ONE accent box: the click-target annotation (the illustration's only highlight). */
function accentBox(x, y, w, h) {
  return '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="7" style="fill:var(--accent)" fill-opacity="0.10" stroke="var(--accent)" stroke-width="2.5"/>'
}

function label(x, y, text, opts) {
  const o = opts || {}
  return '<text x="' + x + '" y="' + y + '" font-family="system-ui,sans-serif" font-size="' + (o.size || 12) + '" font-weight="' + (o.weight || 400) + '" style="fill:' + (o.color || 'var(--text)') + '">' + esc(text) + '</text>'
}

function fieldPill(x, y, w, h, value, mono) {
  return [
    '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="5" style="fill:var(--card)" stroke="var(--border)" stroke-width="1"/>',
    '<text x="' + (x + 10) + '" y="' + (y + h / 2 + 4) + '" font-family="' + (mono ? 'ui-monospace,monospace' : 'system-ui,sans-serif') + '" font-size="' + (mono ? 9.5 : 11) + '" style="fill:var(--text)">' + esc(value) + '</text>',
  ].join('')
}

/** A left mini-sidebar (the Google console's navigation rail). */
function gdriveSidebar(activeLabel) {
  const items = ['APIs & Services', 'OAuth consent screen', 'Credentials']
  let out = '<rect x="20" y="54" width="150" height="266" rx="8" style="fill:var(--card)" stroke="var(--border)" stroke-width="1"/>'
  items.forEach((it, i) => {
    const y = 78 + i * 30
    const active = it === activeLabel
    if (active) out += '<rect x="28" y="' + (y - 14) + '" width="134" height="22" rx="5" style="fill:var(--accent)" fill-opacity="0.12"/>'
    out += label(38, y, it, { size: 11, weight: active ? 600 : 400, color: active ? 'var(--text)' : 'var(--muted)' })
  })
  return out
}

// ── GDRIVE illustration 1 — the OAuth consent screen, Publish app boxed ────
function gdriveConsent(ctx) {
  const inner = [
    chromeFrame('console.cloud.google.com/apis/credentials/consent'),
    gdriveSidebar('OAuth consent screen'),
    // the page title + the publishing state
    label(192, 82, 'OAuth consent screen', { size: 15, weight: 600 }),
    // the Publishing status row
    label(192, 116, 'Publishing status', { size: 11, color: 'var(--muted)' }),
    fieldPill(192, 126, 110, 24, 'Testing', false),
    // THE CLICK TARGET: the Publish app button, boxed
    accentBox(318, 116, 158, 44),
    '<rect x="330" y="126" width="134" height="26" rx="6" style="fill:var(--accent)" fill-opacity="0.9"/>',
    label(341, 143, 'PUBLISH APP', { size: 11.5, weight: 700, color: 'var(--card)' }),
    label(192, 182, 'Press Publish app so your key never', { size: 11, color: 'var(--muted)' }),
    label(192, 198, 'expires after 7 days of testing.', { size: 11, color: 'var(--muted)' }),
    // the app-name row (grayed context, not the target)
    label(192, 232, 'Application name', { size: 11, color: 'var(--muted)' }),
    fieldPill(192, 240, 220, 26, 'UCrypt', false),
    label(192, 296, 'Scopes · Test users', { size: 11, color: 'var(--muted)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluGConsentAlt', ctx), capKey: 'ladderIlluGConsentCap', altKey: 'ladderIlluGConsentAlt' }
}

// ── GDRIVE illustration 2 — the client form, Authorized redirect URIs boxed ─
function gdriveRedirect(ctx) {
  const redirect = String((ctx && ctx.redirect) || '')
  const shown = redirect.length > 46 ? redirect.slice(0, 45) + '…' : redirect
  const inner = [
    chromeFrame('console.cloud.google.com/apis/credentials'),
    gdriveSidebar('Credentials'),
    label(192, 82, 'Create OAuth client ID', { size: 15, weight: 600 }),
    label(192, 112, 'Application type', { size: 11, color: 'var(--muted)' }),
    fieldPill(192, 120, 200, 26, 'Chrome App', false),
    label(192, 168, 'Application ID', { size: 11, color: 'var(--muted)' }),
    fieldPill(192, 176, 300, 26, 'paste UCrypt\'s extension ID here', true),
    // THE CLICK TARGET: the Authorized redirect URIs field, boxed, our URI inside
    accentBox(186, 218, 340, 48),
    label(192, 234, 'Authorized redirect URIs', { size: 11, weight: 600 }),
    fieldPill(192, 240, 326, 20, shown, true),
    // the create button (context)
    '<rect x="420" y="290" width="100" height="26" rx="6" style="fill:var(--accent)" fill-opacity="0.85"/>',
    label(440, 307, 'Create', { size: 11.5, weight: 700, color: 'var(--card)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluGRedirectAlt', ctx), capKey: 'ladderIlluGRedirectCap', altKey: 'ladderIlluGRedirectAlt' }
}

// ── GITHUB illustration 1 — the registration form, callback URL boxed ──────
function githubForm(ctx) {
  const redirect = String((ctx && ctx.redirect) || '')
  const shown = redirect.length > 44 ? redirect.slice(0, 43) + '…' : redirect
  const inner = [
    chromeFrame('github.com/settings/developers/new'),
    label(24, 82, 'Register a new OAuth application', { size: 15, weight: 600 }),
    label(24, 116, 'Application name', { size: 11, color: 'var(--muted)' }),
    fieldPill(24, 124, 300, 26, 'UCrypt', false),
    label(24, 172, 'Homepage URL', { size: 11, color: 'var(--muted)' }),
    fieldPill(24, 180, 300, 26, 'https://example.com', false),
    // THE CLICK TARGET: the Authorization callback URL field, boxed
    accentBox(18, 220, 380, 50),
    label(24, 238, 'Authorization callback URL', { size: 11, weight: 600 }),
    fieldPill(24, 244, 366, 20, shown, true),
    // the register button (context)
    '<rect x="24" y="292" width="170" height="28" rx="6" style="fill:var(--accent)" fill-opacity="0.85"/>',
    label(46, 310, 'Register application', { size: 11.5, weight: 700, color: 'var(--card)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluHFormAlt', ctx), capKey: 'ladderIlluHFormCap', altKey: 'ladderIlluHFormAlt' }
}

// ── GITHUB illustration 2 — the app page, Enable Device Flow boxed ─────────
function githubDevice(ctx) {
  const inner = [
    chromeFrame('github.com/settings/developers'),
    label(24, 82, 'OAuth Apps › UCrypt', { size: 15, weight: 600 }),
    // the device-flow checkbox row — THE CLICK TARGET
    accentBox(18, 104, 340, 54),
    '<rect x="34" y="120" width="18" height="18" rx="4" style="fill:var(--accent)"/>',
    '<path d="M38 129 l5 5 l9 -11" stroke="var(--card)" stroke-width="2.5" fill="none" stroke-linecap="round"/>',
    label(62, 134, 'Enable Device Flow', { size: 12.5, weight: 700 }),
    label(34, 168, 'Turn this on so one-click sign-in works —', { size: 11, color: 'var(--muted)' }),
    label(34, 184, 'no callback round-trip is needed for it.', { size: 11, color: 'var(--muted)' }),
    // context: the client id row
    label(24, 226, 'Client ID', { size: 11, color: 'var(--muted)' }),
    fieldPill(24, 234, 260, 26, 'copy this into UCrypt', true),
    // the update button (context)
    '<rect x="24" y="290" width="190" height="28" rx="6" style="fill:var(--accent)" fill-opacity="0.85"/>',
    label(56, 308, 'Update application', { size: 11.5, weight: 700, color: 'var(--card)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluHDeviceAlt', ctx), capKey: 'ladderIlluHDeviceCap', altKey: 'ladderIlluHDeviceAlt' }
}

// ── DROPBOX illustration 1 — the Create app form, the two choices boxed ────
function dropboxCreate(ctx) {
  function radio(x, y, on, text) {
    return [
      '<circle cx="' + x + '" cy="' + y + '" r="7" style="fill:var(--card)" stroke="var(--border)" stroke-width="1.5"/>',
      on ? '<circle cx="' + x + '" cy="' + y + '" r="3.5" style="fill:var(--accent)"/>' : '',
      label(x + 14, y + 4, text, { size: 11.5, weight: on ? 600 : 400, color: on ? 'var(--text)' : 'var(--muted)' }),
    ].join('')
  }
  const inner = [
    chromeFrame('www.dropbox.com/developers/apps/create'),
    label(24, 82, 'Create app', { size: 15, weight: 600 }),
    label(24, 112, '1. Choose an API', { size: 11, color: 'var(--muted)' }),
    radio(34, 130, true, 'Scoped access'),
    radio(200, 130, false, 'Full Dropbox'),
    label(24, 166, '2. Choose the type of access', { size: 11, color: 'var(--muted)' }),
    radio(34, 184, true, 'App folder'),
    radio(200, 184, false, 'Full Dropbox'),
    // THE CLICK TARGET: the two choices boxed together (one decision path)
    accentBox(18, 116, 380, 82),
    label(24, 226, '3. Name your app', { size: 11, color: 'var(--muted)' }),
    fieldPill(24, 234, 240, 26, 'UCrypt', false),
    '<rect x="24" y="292" width="130" height="28" rx="6" style="fill:var(--accent)" fill-opacity="0.85"/>',
    label(56, 310, 'Create app', { size: 11.5, weight: 700, color: 'var(--card)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluDCreateAlt', ctx), capKey: 'ladderIlluDCreateCap', altKey: 'ladderIlluDCreateAlt' }
}

// ── DROPBOX illustration 2 — the Settings tab, Redirect URIs boxed ─────────
function dropboxSettings(ctx) {
  const redirect = String((ctx && ctx.redirect) || '')
  const shown = redirect.length > 42 ? redirect.slice(0, 41) + '…' : redirect
  const inner = [
    chromeFrame('www.dropbox.com/developers/apps → UCrypt'),
    label(24, 82, 'UCrypt — Settings', { size: 15, weight: 600 }),
    // tabs
    label(24, 106, 'Settings', { size: 11, weight: 700 }),
    label(100, 106, 'Permissions', { size: 11, color: 'var(--muted)' }),
    '<line x1="24" y1="114" x2="66" y2="114" stroke="var(--accent)" stroke-width="2"/>',
    // THE CLICK TARGET: the Redirect URIs field, boxed
    accentBox(18, 130, 380, 56),
    label(24, 150, 'Redirect URIs', { size: 11, weight: 600 }),
    fieldPill(24, 156, 366, 22, shown, true),
    label(24, 212, 'Paste the exact URI — one click above copies it.', { size: 11, color: 'var(--muted)' }),
    // the PKCE row (context — the public-client mode, no secret)
    label(24, 248, 'App key', { size: 11, color: 'var(--muted)' }),
    fieldPill(24, 256, 220, 26, 'copy this into UCrypt', true),
    label(24, 310, 'PKCE — no secret needed', { size: 11, weight: 600, color: 'var(--muted)' }),
  ].join('')
  return { svg: svgDoc(inner, 'ladderIlluDSettingsAlt', ctx), capKey: 'ladderIlluDSettingsCap', altKey: 'ladderIlluDSettingsAlt' }
}

/**
 * The illustration registry (R120 §2.1): per transport, the two annotated
 * console screens, keyed by the walkthrough step's `illu` marker.
 * ctx: { redirect } — the dynamic strings ride INSIDE the drawing.
 */
export function ladderIllustration(transportId, name, ctx = {}) {
  const tid = String(transportId || '')
  const n = String(name || '')
  if (tid === 'gdrive' && n === 'consent') return gdriveConsent(ctx)
  if (tid === 'gdrive' && n === 'redirect') return gdriveRedirect(ctx)
  if (tid === 'github' && n === 'form') return githubForm(ctx)
  if (tid === 'github' && n === 'device') return githubDevice(ctx)
  if (tid === 'dropbox' && n === 'create') return dropboxCreate(ctx)
  if (tid === 'dropbox' && n === 'settings') return dropboxSettings(ctx)
  return null
}

/** The registry's own shape — the battery asserts it (nothing extra, nothing missing). */
export const LADDER_ILLUSTRATIONS = {
  gdrive: ['consent', 'redirect'],
  github: ['form', 'device'],
  dropbox: ['create', 'settings'],
}
