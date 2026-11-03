/**
 * UCrypt — THE SIGN-IN LADDER UI (R119 — law 0.32, order §3.5).
 *
 * The renderer half of lib/ladder.js (the engine stays UI-free). This module
 * draws the ladder inside the transport wizard:
 *
 *   1. FAST   — rendered ONLY when detectFastRung(transportId).available.
 *               When the rung is absent it renders NOTHING — not even a
 *               disabled card; the guided rung is the card's face (§3.7,
 *               the graceful absence). Every fast card carries its ONE-LINE
 *               honest label and the blast-radius sentence (degraded mode
 *               never death): the user's own key always works below.
 *   2. GUIDED — always present. The existing guided setup; the rung card
 *               offers the in-product "Show me how" walkthrough.
 *   3. MANUAL — always present, visually demoted: the existing Advanced/PAT
 *               fields, one click away.
 *
 * Behaviors pinned by the round order:
 *   - gdrive fast: t.connectFast(config) when the transport provides it,
 *     else the non-interactive probeGdriveFast(); ok → persist
 *     { authMode:'fast', signinMode:'fast' } through the wizard's own save
 *     path; typed failure → the typed card + the one-click "Use your own
 *     key instead →" that routes to the guided rung (law 0.29).
 *   - github fast: the DEVICE-FLOW sub-view INSIDE the wizard overlay —
 *     the 8-char user code large (monospace, letter-spaced), Copy (the code
 *     is not a secret — plain clipboard write), "Open github.com/login/device"
 *     (chrome.tabs.create), the honest waiting/slow-down lines, the typed
 *     terminals (expired/denied/throttled/error) with Try again, the visible
 *     Cancel wired to isCanceled, restore on cancel — NO auto-dismiss
 *     anywhere (law 0.8).
 *   - dropbox fast: t.connectPkce(config) when the transport provides it,
 *     else the SAME launch seam the guided flow uses (launchOAuthFlow via
 *     chrome.identity.launchWebAuthFlow) + pkcePair/dropboxExchangeCode
 *     from the engine; ok → persist { refreshToken, signinMode:'fast' }.
 *   - Every connect button rides the R115 state machine: disabled +
 *     honestly labelled while it runs, restored in finally.
 *   - The walkthrough (law 0.30): renders into the provided overlay host —
 *     the visible ✕ close button and the focus return live on the overlay
 *     itself (options.js owns openSyncOverlay/closeSyncOverlay); every step
 *     names the exact menu item, carries the copy-buttons for the exact
 *     strings (one click, never mistyped) and the what-you-should-see line.
 *
 * This module is a RENDERER: it never touches vault state, never logs, and
 * every secret-shaped value it receives (the device-flow grant) goes
 * straight into the persist callback — never into the DOM, never into a log.
 */

import { getMessage } from './i18n.js'
import { SettledHouse } from './settled-house.js'
// R120 §2.1 — the SELF-DRAWN console facsimiles (law 0.17): the walkthroughs
// gain their two annotated screens per transport — UCrypt pointing at the
// console, saying what to do.
import { ladderIllustration } from './ladder-illustrations.js'
import {
  detectFastRung,
  sharedClientId,
  probeGdriveFast,
  githubDeviceFlow,
  GITHUB_DEVICE_FLOW,
  pkcePair,
  dropboxAuthUrl,
  dropboxExchangeCode,
  rungRingRecord,
} from './ladder.js'
import { recordRing } from './egrings.js'
import { launchOAuthFlow, identityRedirect } from './transports/gdrive-oauth-help.js'
// R165 Arc A — THE HONEST PENDING: the CTA's await is bounded (5 s visible
// ticks, a NAMED timeout verdict) and every failure names its DOMAIN
// (CODEBASE / CONSOLE / CONSENT / TIMEOUT) — a button that cannot be silent.
import { withHonestPending, failureDomain, PENDING_VERDICTS } from './pending.js'
// R168 — THE BOUND-COHERENCE LAW: the fast rung's UI pending bound is
// DERIVED from the machinery's own lawful legs, never a second opinion.
// The field spoke (the owner's R168 evidence): the old 60 s UI bound fired
// WHILE Google's window waited (the window's own bound was 120 s), so the
// UI painted TIMEOUT and the window's later typed settle — the honest
// CONSOLE redirect_uri_mismatch row — was dropped by the abandon guard.
// The mask is dead BY CONSTRUCTION: the UI bound now outlives every inner
// leg, and the card prints the SAME number the machinery runs.
import { WEB_AUTH_TIMEOUT_MS } from './webauth-fallback.js'
import { FAST_PROBE_BOUND_MS } from './transports/gdrive.js'
// R174 — THE OAUTH SELF-CHECK: the runtime identity (version/ID/redirect) +
// the ZERO-WINDOW probe (Google's token endpoint validates the client and
// the redirect before the grant, so one bogus-code POST names the defect).
import { runtimeIdentity, oauthSelfCheck, isRetiredClientId } from './cloud/oauth-selfcheck.js'

/** The fast rung's UI pending bound = the human window (300 s) + the probe
 * (2.5 s) + the about-hint leg (10 s) + the persist/seal margin (17.5 s)
 * = 330 s. A UI verdict may only fire when EVERY lawful inner leg is
 * already over — never against a live leg, never against a person. */
export const FAST_UI_PENDING_BOUND_MS = WEB_AUTH_TIMEOUT_MS + FAST_PROBE_BOUND_MS + 27500

const LADDER_TRANSPORTS = ['gdrive', 'github', 'dropbox']

// ── small DOM helpers --------------------------------------------------------

function el(tag, cls, text) {
  const n = document.createElement(tag)
  if (cls) n.className = cls
  if (text !== undefined && text !== null) n.textContent = text
  return n
}

/** The R115 button state machine: disabled + honestly labelled while `fn`
 *  runs, restored in finally — a double-click can never fire a second
 *  authorization window, and no failure leaves a stuck label (0.26).
 *  R165 Arc A — the FAST CTA now rides the BOUNDED honest-pending wrapper
 *  (withHonestPending) on top of this discipline: 5 s visible ticks, a named
 *  timeout verdict (R168: DERIVED from the machinery's own legs — the UI can
 *  never abandon a live inner leg), and the raw service text never swallowed.
 *  This helper stays for the flows that own their own bounded outcome. */
async function withBusy(btn, busyText, fn) {
  if (!btn) return fn()
  const prevLabel = btn.textContent
  btn.disabled = true
  btn.textContent = busyText
  try {
    return await fn()
  } finally {
    btn.disabled = false
    btn.textContent = prevLabel
  }
}

/** Copy a NON-SECRET string (the user code, the redirect URI, the extension
 *  ID — identifiers, never credentials) with the honest 2.4 s label swap. */
async function copyPlain(btn, text, copiedKey, copyLabel) {
  try {
    await navigator.clipboard.writeText(String(text || ''))
    btn.textContent = getMessage(copiedKey, undefined, 'Copied ✓')
  } catch {
    btn.textContent = getMessage('twGdriveCopyFail', undefined, 'Select & copy the URI above')
  }
  setTimeout(() => { btn.textContent = copyLabel }, 2400)
}

// ── R165 ARC A — the verdict card + the honest pending on the CTA ───────────

/**
 * The verdict card (complete / failed-with-reason / timed-out-with-reason):
 * the title names the outcome, the body names the DOMAIN and its fix, and
 * the raw service text (chrome.runtime.lastError) prints VERBATIM — the
 * fingerprint that names the domain, never swallowed, never prettified
 * into nothing. Retry is ONE explicit click on the card's button.
 */
function renderVerdictCard(host, { titleKey, titleFallback, body, raw, domain, fix, onRetry, retryLabel }) {
  if (!host) return
  host.innerHTML = ''
  const card = el('div', 'ladder-card ladder-card-fail')
  card.setAttribute('role', 'alert')
  card.appendChild(el('strong', 'ladder-card-title', getMessage(titleKey, undefined, titleFallback)))
  if (body) card.appendChild(el('p', 'card-help ladder-card-line', String(body).slice(0, 300)))
  if (raw) card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastRawLabel', undefined, 'The service said:') + ' ' + String(raw).slice(0, 240)))
  if (domain) {
    const dkey = { CODEBASE: 'ladderDomainCodebase', CONSOLE: 'ladderDomainConsole', CONSENT: 'ladderDomainConsent', TIMEOUT: 'ladderDomainTimeout' }[domain]
    card.appendChild(el('p', 'card-help ladder-card-domain', getMessage(dkey, undefined, `What owns the fix: ${domain}.`) + (fix ? ' ' + fix : '')))
  }
  const row = el('div', 'btn-row')
  row.style.margin = '6px 0 0'
  if (typeof onRetry === 'function') {
    const retry = el('button', 'btn btn-primary btn-sm')
    retry.type = 'button'
    retry.textContent = retryLabel || getMessage('ladderDfRetry', undefined, 'Try again')
    retry.addEventListener('click', onRetry)
    row.appendChild(retry)
  }
  const own = el('button', 'btn btn-outline btn-sm')
  own.type = 'button'
  own.textContent = getMessage('ladderProbeFailUseOwnKey', undefined, 'Use your own key instead →')
  own.addEventListener('click', () => {
    const evt = new CustomEvent('ucrypt:go-guided', { bubbles: true })
    card.dispatchEvent(evt)
  })
  row.appendChild(own)
  card.appendChild(row)
  host.appendChild(card)
  return card
}

// ── the typed probe-failure card (law 0.29 — the fix names the failure) ─────

function probeFailKey(kind) {
  switch (String(kind || '')) {
    case 'oauth-client-missing': return 'ladderProbeFailOauthClientMissing'
    case 'no-google-session': return 'ladderProbeFailNoGoogleSession'
    case 'client-id-absent': return 'ladderProbeFailClientIdAbsent'
    case 'getAuthToken-unavailable': return 'ladderProbeFailGetAuthTokenUnavailable'
    // R120 §2.5 — the multi-account refusal (the sync surface's typed card
    // for a token that answers for a different Google account).
    case 'account-switched': return 'ladderProbeFailAccountSwitched'
    default: return 'ladderProbeFailProbeFailed'
  }
}

// ── R167 — the CONSOLE row's letter-exact companion: the runtime ID ──────────
// The E-13 field verdict (redirect_uri_mismatch sold as CODEBASE) taught the
// ladder WHY the console row exists: the OAuth client's Item ID must equal
// the extension's own ID LETTER-EXACT, and the owner cannot compare letters
// against an ID they cannot see. When the runtime exposes its ID, the CONSOLE
// domain's row prints it inline — the comparison happens ON the row.
function runtimeIdSuffix(domain) {
  if (domain !== 'CONSOLE') return ''
  try {
    const id = String((typeof chrome !== 'undefined' && chrome && chrome.runtime && chrome.runtime.id) || '')
    return id ? ` (Your extension ID: ${id} — compare letter-exact.)` : ''
  } catch { return '' }
}

// ── R174 — the self-check helpers (the stamps + the copy-redirect row) ──────

/** Clipboard with the execCommand fallback (extension pages may veto the
 * async clipboard in some contexts — the fallback keeps the button honest). */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch { /* fall through to the legacy path */ }
  try {
    const ta = document.createElement('textarea')
    ta.value = String(text || '')
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch { return false }
}

/** The runtime stamp — every failure card names WHICH build + WHICH identity
 * rode, so a stale build (the field's sixth word: the error page rode the
 * retired client) is self-evident on the card itself. */
function appendRuntimeStamp(card) {
  try {
    const id = runtimeIdentity()
    if (!id.version && !id.extId) return
    const p = el('p', 'card-help ladder-stamp-row')
    const v = id.version || '?'
    const i = id.extId || '?'
    p.textContent = getMessage('ladderSelfCheckStamp', [v, i], `UCrypt ${v} — this extension's ID: ${i}`)
    p.style.opacity = '0.85'
    card.appendChild(p)
  } catch { /* the stamp never blocks the card */ }
}

/** The copy-redirect row — the CONSOLE card's zero-typo cure: the EXACT
 * derived redirect (chrome.identity.getRedirectURL(), trailing slash
 * included) rides the clipboard, ready for Console → Authorized redirect
 * URIs. Never hand-built — the derived value is the only lawful one. */
function appendCopyRedirectRow(card) {
  try {
    const id = runtimeIdentity()
    if (!id.redirect) return
    const row = el('div', 'btn-row')
    row.style.margin = '6px 0 0'
    const btn = el('button', 'btn btn-outline btn-sm')
    btn.type = 'button'
    btn.textContent = getMessage('ladderSelfCheckCopy', undefined, 'Copy redirect URI')
    btn.addEventListener('click', async () => {
      const ok = await copyText(id.redirect)
      btn.textContent = ok
        ? getMessage('ladderSelfCheckCopied', undefined, 'Copied.')
        : id.redirect
    })
    row.appendChild(btn)
    card.appendChild(row)
  } catch { /* the row never blocks the card */ }
}

/**
 * The typed card for a failed fast connect: the title names the failure
 * kind, the one-click "Use your own key instead →" routes to the guided
 * rung (the fallback visually demoted — 0.29). Rendered into `host`,
 * replacing any card that was there before (one card at a time).
 * R165 Arc A — opts.raw prints the service's OWN words verbatim, and the
 * failure's DOMAIN (CODEBASE/CONSOLE/CONSENT) names what owns the fix.
 * R167 — CONSOLE rows carry the runtime extension ID inline (the E-13 cure:
 * the letter-exact Item-ID comparison happens on the row itself).
 */
function renderProbeFailCard(host, kind, detail, { onOwnKey, onBack, raw, fix, laneCTried } = {}) {
  if (!host) return
  host.innerHTML = ''
  const card = el('div', 'ladder-card ladder-card-fail')
  card.setAttribute('role', 'alert')
  card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderProbeFailTitle', undefined, 'The one-click sign-in is not available right now.')))
  card.appendChild(el('p', 'card-help ladder-card-line', getMessage(probeFailKey(kind), undefined, 'Use your own key below — it always works.')))
  // R169 O-2 — the lane-C honesty: when the Chrome silent lane was tried
  // before this refusal, the card says so (never a hidden lane, never a
  // silent accelerator).
  if (laneCTried) {
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderLaneCTriedNote', undefined, 'Chrome\u2019s own silent sign-in was tried first and is not available on this browser — the Google window ran instead.')))
  }
  if (raw) {
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastRawLabel', undefined, 'The service said:') + ' ' + String(raw).slice(0, 240)))
    const dom = failureDomain({ verdict: PENDING_VERDICTS.LAST_ERROR, kind: String(kind || ''), raw: String(raw) })
    const dkey = { CODEBASE: 'ladderDomainCodebase', CONSOLE: 'ladderDomainConsole', CONSENT: 'ladderDomainConsent', TIMEOUT: 'ladderDomainTimeout' }[dom.domain]
    card.appendChild(el('p', 'card-help ladder-card-domain', getMessage(dkey, undefined, `What owns the fix: ${dom.domain}.`) + ' ' + (fix || dom.fix) + runtimeIdSuffix(dom.domain)))
    // R174 — the stamp + the CONSOLE copy-redirect row: the card now carries
    // the build/identity truth and the zero-typo Console cure.
    appendRuntimeStamp(card)
    if (dom.domain === 'CONSOLE') appendCopyRedirectRow(card)
  }
  if (detail) {
    const d = el('p', 'card-help ladder-card-detail', String(detail).slice(0, 220))
    card.appendChild(d)
  }
  const row = el('div', 'btn-row')
  row.style.margin = '6px 0 0'
  const own = el('button', 'btn btn-primary btn-sm')
  own.type = 'button'
  own.textContent = getMessage('ladderProbeFailUseOwnKey', undefined, 'Use your own key instead →')
  own.addEventListener('click', () => { if (typeof onOwnKey === 'function') onOwnKey() })
  row.appendChild(own)
  if (typeof onBack === 'function') {
    const back = el('button', 'btn btn-ghost btn-sm')
    back.type = 'button'
    back.textContent = getMessage('ladderDfBack', undefined, 'Back')
    back.addEventListener('click', onBack)
    row.appendChild(back)
  }
  card.appendChild(row)
  host.appendChild(card)
}

/**
 * R171 — THE WINDOW-TRUTH CARD (the display law's dedicated renderer):
 * the web-auth window OPENED and settled without completing (the user
 * closed it — most often AFTER reading Google's own red "Access blocked —
 * Error 400: redirect_uri_mismatch" page). The probe sentences ("not
 * available right now", "no Google sign-in") are FALSE here and must
 * never render; the CODEBASE verdict is FALSE here and must never render.
 * The card tells the window's truth: it opened, nothing was exchanged,
 * the field-proven page routes CONSOLE (the Item-ID cure, the runtime ID
 * inline for the letter-compare), and an honest caveat for a self-closed
 * window. Try again re-presses the rung's own CTA — one explicit click.
 */
function renderWindowUnmatchedCard(host, res, { onOwnKey, onBack, laneCTried } = {}) {
  if (!host) return
  host.innerHTML = ''
  const card = el('div', 'ladder-card ladder-card-fail')
  card.setAttribute('role', 'alert')
  card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderWindowUnmatchedTitle', undefined, 'The sign-in window opened — but the sign-in did not finish.')))
  // R169 O-3 — the E-14 cure's copy, verbatim in the law's words: the window
  // opened, the reason rides above, and the own-key door is named IN the body.
  card.appendChild(el('p', 'card-help ladder-card-line', getMessage('ladderWindowUnmatchedBody', undefined, 'Google\u2019s window opened but the sign-in did not complete. The reason is named above. Nothing was exchanged — your own key below always works.')))
  const raw = String((res && res.raw) || '')
  if (raw) card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastRawLabel', undefined, 'The service said:') + ' ' + raw.slice(0, 240)))
  // R169 O-2 — the lane-C honesty note (the silent accelerator is never hidden).
  if (laneCTried) {
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderLaneCTriedNote', undefined, 'Chrome\u2019s own silent sign-in was tried first and is not available on this browser — the Google window ran instead.')))
  }
  const dom = failureDomain({ verdict: 'web-auth-unmatched', kind: 'auth-window-unmatched', raw })
  const dkey = { CODEBASE: 'ladderDomainCodebase', CONSOLE: 'ladderDomainConsole', CONSENT: 'ladderDomainConsent', TIMEOUT: 'ladderDomainTimeout' }[dom.domain]
  card.appendChild(el('p', 'card-help ladder-card-domain', getMessage(dkey, undefined, `What owns the fix: ${dom.domain}.`) + ' ' + dom.fix + runtimeIdSuffix(dom.domain)))
  card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderWindowUnmatchedCaveat', undefined, 'If you closed the window yourself, just press Try again.')))
  // R174 — the stamp + the copy-redirect row: the window-truth card carries
  // the build/identity truth and the exact derived redirect for the Console.
  appendRuntimeStamp(card)
  appendCopyRedirectRow(card)
  const row = el('div', 'btn-row')
  row.style.margin = '6px 0 0'
  const retry = el('button', 'btn btn-primary btn-sm')
  retry.type = 'button'
  retry.textContent = getMessage('ladderDfRetry', undefined, 'Try again')
  retry.addEventListener('click', () => {
    // the rung's own CTA is the one explicit retry — re-press it, never a
    // second authorization window from inside the card
    try {
      const rung = card.closest('.ladder-rung-fast')
      const cta2 = rung && rung.querySelector('.ladder-fast-cta')
      if (cta2 && !cta2.disabled) cta2.click()
    } catch { /* best-effort — the CTA itself always works */ }
  })
  row.appendChild(retry)
  const own = el('button', 'btn btn-outline btn-sm')
  own.type = 'button'
  own.textContent = getMessage('ladderProbeFailUseOwnKey', undefined, 'Use your own key instead →')
  own.addEventListener('click', () => { if (typeof onOwnKey === 'function') onOwnKey() })
  row.appendChild(own)
  if (typeof onBack === 'function') {
    const back = el('button', 'btn btn-ghost btn-sm')
    back.type = 'button'
    back.textContent = getMessage('ladderDfBack', undefined, 'Back')
    back.addEventListener('click', onBack)
    row.appendChild(back)
  }
  card.appendChild(row)
  host.appendChild(card)
}

/** The success card — visible until the user moves on (0.8: no auto-dismiss).
 * R169 O-2 — THE LANE LABELS: the card prints WHICH lane served —
 * "signed in with Chrome's own connection" (Lane C, the silent accelerator;
 * reboot-persistent while Chrome's session lives) versus "signed in with
 * Google's window" (Lane U). The implicit lane's session-grade honesty
 * (R-169.4a): "signed in for this session — sign in again after a full
 * restart" rides its card ×3 locales.
 * R174 — THE UNDYING CUSTODY FORECAST (R-174.3, the owner's loudest demand):
 * the card names HOW LONG the fire burns — the new truth (a refresh token
 * banked: the connection survives restarts, renewed silently forever) or
 * the honest forecast (no custody: Google's access tokens live about an
 * hour, renewed by one click) + the ONE Console row that makes it forever.
 * Never a lie in either branch.
 * R176 — R-176.1b THE BURN CLOCK ON THE ✓ CARD: when the mint banked an
 * access token, the card carries the TRUE remaining life ("key burns in
 * ~NN min — one click renews") derived from the banked exp — the same
 * clock every lane reads (the living bank's own display truth). The clock
 * rides only on a VERIFIED save (persistFast's read-back — R-176.1a). */
function renderFastOkCard(host, transportName, opts = {}) {
  if (!host) return
  host.innerHTML = ''
  const card = el('div', 'ladder-card ladder-card-ok')
  card.setAttribute('role', 'status')
  card.appendChild(el('strong', 'ladder-card-title', '✓ ' + getMessage('ladderFastOkTitle', undefined, 'Signed in — one key, silently renewed.')))
  card.appendChild(el('p', 'card-help ladder-card-line', getMessage('ladderFastOkBody', [String(transportName || '')], 'Connected. Your encrypted vault now syncs through $1$ — press Sync now for the first push.')))
  const lane = String((opts && opts.lane) || '')
  const via = String((opts && opts.via) || '')
  const banked = !!(opts && opts.bankedRefresh)
  if (lane === 'S') {
    // R171 — THE SPINE PROMISE (the one-last-window truth, in the owner's
    // words' seat): the connection now survives every browser restart.
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastOkSpine', undefined, 'One last window — after this, UCrypt reconnects by itself, even after a restart.')))
  } else if (lane === 'C') {
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastOkLaneC', undefined, 'Signed in with Chrome\u2019s own connection — silent, no window, and it stays signed in across browser restarts.')))
  } else if (lane === 'U' && banked) {
    // R174 — THE FOREVER TRUTH (R-174.3): a refresh token was BANKED (the
    // code lane's exchange answered — access_type=offline rode the grant).
    // The card names the new truth: the connection survives restarts, the
    // renewal is silent, no limit of time.
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastOkForever', undefined, 'Connected for good — the refresh grant rides this device\u2019s sealed storage, so UCrypt renews its own sign-in silently, even after a restart. No limit of time.')))
  } else if (lane === 'U' && via === 'web-auth-flow') {
    // R174 — THE HONEST FORECAST (R-174.3, the E-30 cure): no refresh
    // custody was banked (Google's confidential-client rule refused the
    // secret-less exchange for this client — the implicit lane served).
    // The card speaks the truthful horizon — about an hour, renewed by one
    // click — and names the ONE Console row that makes it forever.
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastOkForecast', undefined, 'One key, kept in this browser\u2019s own locked storage. It renews the connection silently. Sign out burns it. The ONE Console row (Self-check → Persistent sign-in) makes the renewal permanent: silent, automatic, no limit of time.')))
  } else if (lane === 'U') {
    card.appendChild(el('p', 'card-help ladder-card-detail', getMessage('ladderFastOkLaneU', undefined, 'Signed in with Google\u2019s window — the refresh grant rides this device\u2019s sealed storage.')))
  }
  // R176 — R-176.1b THE BURN CLOCK: the ✓ card carries the banked key's true
  // remaining life. The clock rides ONLY on a verified save (the caller
  // computes it from the banked exp — the same arithmetic the lanes read).
  const burn = Number(opts && opts.burnMinutes)
  if (Number.isFinite(burn) && burn >= 0) {
    card.appendChild(el('p', 'card-help ladder-card-detail ladder-burn-clock', getMessage('bankBurnClock', [String(Math.floor(burn))], `Key burns in ~${Math.floor(burn)} min — the connection renews itself silently when it can; one click when it cannot.`)))
  }
  const autoSync = (opts && opts.autoSync && typeof opts.autoSync === 'object') ? opts.autoSync : null
  if (autoSync && autoSync.detail) {
    const syncLine = el(
      'p',
      'card-help ladder-card-detail ladder-card-autosync',
      (autoSync.ok ? '✓ Automatic sync: ' : 'ℹ Automatic sync: ') + String(autoSync.detail)
    )
    card.appendChild(syncLine)
  }
  host.appendChild(card)
}

/** The honest locked/failed-save card: nothing pretends to be configured. */
function renderSaveFailCard(host, errText) {
  if (!host) return
  host.innerHTML = ''
  const card = el('div', 'ladder-card ladder-card-fail')
  card.setAttribute('role', 'alert')
  card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderFastSaveLockedTitle', undefined, 'The sign-in succeeded, but the vault is locked — the connection is not saved yet.')))
  card.appendChild(el('p', 'card-help ladder-card-line', String(errText || getMessage('ladderFastSaveLocked', undefined, 'Unlock the vault, then press the fast sign-in again to finish (the grant is not kept — every retry starts clean).')).slice(0, 260)))
  host.appendChild(card)
}

// ── the rung record (law 0.28) — page-side rows for the in-page fallbacks ───
//
// When the transport module's own connect method exists (2-a's fast rungs)
// the ring is recorded there. When this renderer drives the engine directly
// (the fallback paths), it records the rung row itself — fire-and-forget.

function ringRung(transportId, rung, extra = {}) {
  try {
    const entry = rungRingRecord(transportId, rung, extra)
    entry.outcome = extra.outcome || 'ok'
    recordRing(entry).catch(() => {})
  } catch { /* the ring never throws into its caller */ }
}

// ── persistence (the wizard's own save path — TRANSPORT_SAVE) ───────────────

async function persistFast(ctx, extraFields) {
  const base = { ...((typeof ctx.collectConfig === 'function') ? (ctx.collectConfig() || {}) : {}) }
  // Strip any prior session's fast custody tokens from base so a newly minted
  // sign-in (or Lane C silent sign-in) never inherits a stale/expired webToken.
  delete base.webToken
  delete base.refreshToken
  delete base.oauthAccessToken
  const config = { ...base, ...extraFields, signinMode: 'fast' }
  const r = await ctx.persist(config)
  return r && r.ok
    ? { ok: true, autoSync: r.autoSync || null }
    : { ok: false, error: (r && r.error) || '' }
}

// R172 — THE PURE-PANEL BUTTON SETS (R-172.4, the E-27 cure): every panel
// owns its own actions — the global bottom row is replaced for the ladder
// transports. Fast: [one-click CTA] + [Test connection] (NO Save transport —
// one click connects, saves, and answers; a Save button here would name an
// action the panel never needs). The others: their own honest set.
// R176 — R-176.5 THE ANSWERING LABEL-CLASS: the rows render into the PANEL'S
// OWN VISIBLE VERDICT SEAT — created adjacent to the panel's own buttons,
// unhidden at press, scrolled into view. The old shared seat (#twResult) is
// the dead-seat class the field proved (E-35: the modal's own Test answered
// into a seat the summary mode itself hides and the fold itself buries —
// the press ran, the answer landed, the eye saw nothing). Every label that
// promises a verdict writes one WHERE THE PRESSER CAN SEE IT.
function panelResultEl(row) {
  // The panel's own seat: one per panel, created on first press, living
  // DIRECTLY under the button row (the presser's own visible context).
  // R177 — R-177.5 THE ONCE-SPOKEN FRAME: the reuse key is ANY descendant
  // `.panel-test-result` of the panel host (never `:scope >` only) — a
  // structural re-render (a wrap, a moved row) must never orphan a seat and
  // answer twice in one frame (the E-38 twice-spoken class). Every verdict
  // write in the family is a REPLACE (`textContent =` — pinned by the
  // render-twice battery pin: a double press renders the answer EXACTLY
  // once).
  try {
    const host = row && row.parentElement
    if (!host) return document.getElementById('twResult') // pre-R176 callers (no panel row) keep the legacy seat
    let out = host.querySelector('.panel-test-result')
    if (!out) {
      out = document.createElement('p')
      out.className = 'sync-test-result panel-test-result'
      out.setAttribute('role', 'status')
      out.hidden = true
      if (row.nextSibling) host.insertBefore(out, row.nextSibling)
      else host.appendChild(out)
    }
    return out
  } catch { return document.getElementById('twResult') }
}
function wirePanelActions(row, ctx, { test = true, save = true, cancel = true } = {}) {
  if (!row) return
  if (test) {
    const tb = el('button', 'btn btn-outline btn-sm panel-test-btn')
    tb.type = 'button'
    tb.textContent = getMessage('twTestBtn', undefined, 'Test connection')
    tb.addEventListener('click', () => {
      // R-176.5 — the verdict lands in the panel's OWN visible seat, unhidden
      // at the journey's start and scrolled to the presser's eyes.
      const out = panelResultEl(row)
      if (out) {
        out.hidden = false
        try { out.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) } catch { /* the scroll never blocks the test */ }
      }
      if (typeof ctx.testConnection === 'function') ctx.testConnection(out)
    })
    row.appendChild(tb)
  }
  if (save) {
    const sb = el('button', 'btn btn-primary btn-sm panel-save-btn')
    sb.type = 'button'
    sb.textContent = getMessage('twSaveBtn', undefined, 'Save transport')
    sb.addEventListener('click', async () => {
      if (typeof ctx.saveTransport === 'function') await ctx.saveTransport()
    })
    row.appendChild(sb)
  }
  if (cancel) {
    const cb = el('button', 'btn btn-ghost btn-sm panel-cancel-btn')
    cb.type = 'button'
    cb.textContent = getMessage('twCancelBtn', undefined, 'Cancel')
    cb.addEventListener('click', () => {
      if (typeof ctx.cancelPanel === 'function') ctx.cancelPanel(row.closest('details, section'))
    })
    row.appendChild(cb)
  }
}

// ── the fast rung: gdrive ────────────────────────────────────────────────────

async function fastGdrive(ctx, surface, isAbandoned = () => false) {
  const t = ctx.transport || {}
  ringRung('gdrive', 'fast', { stage: 'probe', message: 'the gdrive fast rung was pressed' })
  let res
  if (typeof t.connectFast === 'function') {
    // 2-a's transport fast rung: the ring + the typed errors live there.
    try {
      const cfg = (typeof ctx.collectConfig === 'function') ? (ctx.collectConfig() || {}) : {}
      const r = await t.connectFast(cfg)
      res = r && (r.ok !== false) ? { ok: true, result: r } : { ok: false, kind: (r && r.kind) || 'probe-failed', detail: (r && (r.userMessage || r.message)) || '', raw: (r && r.raw) || '' }
    } catch (e) {
      res = { ok: false, kind: /client.?id/i.test(String((e && (e.userMessage || e.message)) || '')) ? 'client-id-absent' : ((e && e.probeKind) || 'probe-failed'), detail: (e && (e.userMessage || e.message)) || '', raw: (e && e.raw) || '', timedOut: !!(e && e.timedOut), laneCTried: !!(e && e.laneCTried), laneCReason: String((e && e.laneCReason) || '') }
    }
  } else {
    // The engine fallback: the NON-interactive probe (never opens a window).
    const probe = await probeGdriveFast()
    res = probe.ok ? { ok: true, result: probe } : { ok: false, kind: probe.kind, detail: '', raw: probe.raw || '' }
  }
  if (isAbandoned()) return // a late settle after the bounded verdict — the ring keeps the truth, the UI stays settled
  if (!res.ok) {
    ringRung('gdrive', 'fast', { stage: 'probe', outcome: 'fail', error: String(res.kind || '').slice(0, 48), message: 'the gdrive fast probe refused — routed to the guided rung' })
    const laneFlags = { laneCTried: !!(res.laneCTried || (res.rawDetail && res.rawDetail.laneCTried)) }
    if (typeof ctx.onConnectFailed === 'function') {
      try { ctx.onConnectFailed({ transportId: 'gdrive', transportName: ctx.transportName, kind: res.kind, detail: res.detail || res.raw || 'Google sign-in did not complete.' }) } catch { /* best-effort */ }
    }
    // R171 — THE DISPLAY LAW: the "not available right now" card is for
    // PRE-WINDOW failures only. When the window OPENED and settled
    // unmatched (the user closed Google's own error page), the dedicated
    // window-truth card renders — never the probe's sentences, never
    // CODEBASE, never "the window failed to open".
    if (res.kind === 'auth-window-unmatched') {
      renderWindowUnmatchedCard(surface, res, {
        laneCTried: laneFlags.laneCTried,
        onOwnKey: () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() },
        onBack: () => { if (typeof ctx.restore === 'function') ctx.restore() },
      })
      return
    }
    renderProbeFailCard(surface, res.kind, res.detail, {
      raw: res.raw,
      laneCTried: laneFlags.laneCTried,
      onOwnKey: () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() },
    })
    return
  }
  // R166 Arc B — the fallback's webToken rides the persist path: connectFast
  // returns the config; when the second machinery minted, its webToken is
  // SEALED with the envelope (the sync legs and the 401 wrapper live on it).
  // R172 — THE FAST-INHERIT SEAL: the record carries the client that
  // ACTUALLY rode (connectFast returns it — env seam, the owner's own
  // wired client, or the shared manifest ID). Never a second opinion.
  const extra = {
    authMode: 'fast',
    signinMode: 'fast',
    clientId: (res.result && res.result.clientId) || sharedClientId('gdrive'),
    ...(res.result && res.result.lane ? { lane: res.result.lane } : {}),
    ...(res.result && res.result.via ? { via: res.result.via } : {}),
    ...(res.result && res.result.accountHint ? { accountHint: res.result.accountHint } : {}),
  }
  if (res.result && res.result.webToken) extra.webToken = res.result.webToken
  // R174b — THE OFFLINE CUSTODY: the code lane's refresh token rides the
  // SAME sealed envelope (device-only ciphertext — the R85 law byte-true);
  // the sync's silent refresh leg lives in gdrive.ensureAccessToken.
  if (res.result && res.result.refreshToken) extra.refreshToken = res.result.refreshToken
  const saved = await persistFast(ctx, extra)
  if (isAbandoned()) return
  if (!saved.ok) {
    renderSaveFailCard(surface, saved.error)
    if (typeof ctx.onConnectFailed === 'function') {
      try { ctx.onConnectFailed({ transportId: 'gdrive', transportName: ctx.transportName, kind: 'save-failed', detail: saved.error || 'Could not save Google Drive connection.' }) } catch { /* best-effort */ }
    }
    return
  }
  ringRung('gdrive', 'fast', { stage: 'seal', message: 'the gdrive fast connection was sealed (authMode fast, lane ' + String((res.result && res.result.lane) || 'U') + ')' })
  // R174 — THE FORECAST FACTS (R-174.3): the custody outcome rides the card —
  // a banked refresh token speaks the forever truth; an implicit-lane mint
  // speaks the honest about-an-hour forecast + the Console row.
  // R176 — R-176.1b: the BURN CLOCK rides the ✓ card — the banked webToken's
  // true remaining life (the mint's own exp, the lanes' arithmetic).
  const _wt = (res.result && res.result.webToken && typeof res.result.webToken === 'object') ? res.result.webToken : null
  const _burnMinutes = (_wt && Number.isFinite(Number(_wt.exp)))
    ? Math.max(0, Math.floor((Number(_wt.exp) - Date.now()) / 60000))
    : null
  const okOpts = {
    lane: res.result && res.result.lane,
    via: res.result && res.result.via,
    bankedRefresh: !!(res.result && res.result.refreshToken),
    ...(_burnMinutes !== null ? { burnMinutes: _burnMinutes } : {}),
    ...(saved.autoSync ? { autoSync: saved.autoSync } : {}),
  }
  renderFastOkCard(surface, ctx.transportName, okOpts)
  if (typeof ctx.onConfigured === 'function') {
    await ctx.onConfigured({ ok: true, transportId: 'gdrive', transportName: ctx.transportName, autoSync: saved.autoSync || null, burnMinutes: _burnMinutes })
  }
  if (ctx && ctx.host && !ctx.host.contains(surface)) {
    const liveFast = ctx.host.querySelector('.ladder-rung-fast') || ctx.host
    liveFast.querySelectorAll('.ladder-fast-surface').forEach((n) => n.remove())
    const liveSurface = el('div', 'ladder-fast-surface')
    liveFast.appendChild(liveSurface)
    renderFastOkCard(liveSurface, ctx.transportName, okOpts)
  }
}

// ── the fast rung: dropbox ───────────────────────────────────────────────────

async function fastDropbox(ctx, surface) {
  const t = ctx.transport || {}
  const appKey = sharedClientId('dropbox')
  ringRung('dropbox', 'fast', { stage: 'code', message: 'the dropbox fast rung was pressed' })
  let refreshToken = ''
  let failDetail = ''
  try {
    if (typeof t.connectPkce === 'function') {
      // 2-a's transport PKCE path (the ring + the typed window errors live there).
      const cfg = (typeof ctx.collectConfig === 'function') ? (ctx.collectConfig() || {}) : {}
      const r = await t.connectPkce(cfg)
      refreshToken = String((r && (r.refreshToken || (r.config && r.config.refreshToken))) || '')
      if (!refreshToken) failDetail = (r && (r.userMessage || r.message)) || ''
    } else {
      // The engine fallback: the SAME launch seam the guided flow uses
      // (chrome.identity.launchWebAuthFlow via launchOAuthFlow), the PKCE
      // pair from the engine, the exchange typed.
      const redirect = identityRedirect()
      const { verifier, challenge } = await pkcePair()
      const url = dropboxAuthUrl({ appKey, challenge, redirect })
      const finalUrl = await launchOAuthFlow(url)
      const ru = new URL(finalUrl)
      const code = ru.searchParams.get('code')
      if (!code) throw new Error('dropbox_fast_no_code')
      const ex = await dropboxExchangeCode({ appKey, code, verifier, redirect, fetchImpl: fetch })
      refreshToken = ex.refreshToken
    }
  } catch (e) {
    failDetail = failDetail || String((e && (e.userMessage || e.message)) || e)
  }
  if (!refreshToken) {
    ringRung('dropbox', 'fast', { stage: 'code', outcome: 'fail', error: 'dropbox_fast_refused', message: 'the dropbox fast connect refused — routed to the guided rung' })
    if (typeof ctx.onConnectFailed === 'function') {
      try { ctx.onConnectFailed({ transportId: 'dropbox', transportName: ctx.transportName, kind: 'probe-failed', detail: failDetail || 'Dropbox sign-in did not complete.' }) } catch { /* best-effort */ }
    }
    renderProbeFailCard(surface, 'probe-failed', failDetail, {
      onOwnKey: () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() },
    })
    return
  }
  const saved = await persistFast(ctx, { appKey, refreshToken })
  if (!saved.ok) {
    renderSaveFailCard(surface, saved.error)
    if (typeof ctx.onConnectFailed === 'function') {
      try { ctx.onConnectFailed({ transportId: 'dropbox', transportName: ctx.transportName, kind: 'save-failed', detail: saved.error || 'Could not save Dropbox connection.' }) } catch { /* best-effort */ }
    }
    return
  }
  ringRung('dropbox', 'fast', { stage: 'seal', message: 'the dropbox fast connection was sealed (refresh token, device-only)' })
  const okOpts = saved.autoSync ? { autoSync: saved.autoSync } : {}
  renderFastOkCard(surface, ctx.transportName, okOpts)
  if (typeof ctx.onConfigured === 'function') {
    await ctx.onConfigured({ ok: true, transportId: 'dropbox', transportName: ctx.transportName, autoSync: saved.autoSync || null })
  }
  if (ctx && ctx.host && !ctx.host.contains(surface)) {
    const liveFast = ctx.host.querySelector('.ladder-rung-fast') || ctx.host
    liveFast.querySelectorAll('.ladder-fast-surface').forEach((n) => n.remove())
    const liveSurface = el('div', 'ladder-fast-surface')
    liveFast.appendChild(liveSurface)
    renderFastOkCard(liveSurface, ctx.transportName, okOpts)
  }
}

// ── the fast rung: github — the DEVICE-FLOW sub-view ─────────────────────────

/**
 * The 8-character user code AS THE USER SEES IT (R120 §2.4): grouped
 * XXXX-XXXX — one glance, never mistyped. Pure and EXPORTED (the battery
 * drives it). A lowercase code is uppercased (GitHub's codes are uppercase
 * — be graceful); a code that is not exactly 8 alphanumeric characters
 * after normalization is returned UNCHANGED (GitHub may deliver the code
 * already grouped "XXXX-XXXX" — never mangle a shape we did not expect).
 */
export function formatDeviceCode(code) {
  const raw = String(code == null ? '' : code).trim()
  const up = raw.toUpperCase()
  return /^[A-Z0-9]{8}$/.test(up) ? `${up.slice(0, 4)}-${up.slice(4)}` : raw
}

function renderDfEnter(view, st) {
  const { surface } = view
  surface.innerHTML = ''
  const shownCode = formatDeviceCode((st && (st.userCode || st.code)) || '')
  const card = el('div', 'ladder-card ladder-card-df')
  card.setAttribute('role', 'status')
  card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderDfStepTitle', undefined, 'Sign in with GitHub')))
  card.appendChild(el('p', 'card-help ladder-card-line', getMessage('ladderDfEnterAt', undefined, 'On the GitHub page, enter this one-time code:')))
  const codeRow = el('div', 'ladder-code-row')
  const codeEl = el('span', 'ladder-code', shownCode)
  codeEl.setAttribute('aria-label', getMessage('ladderDfCodeAria', [shownCode], 'The one-time GitHub code: $1'))
  codeRow.appendChild(codeEl)
  const codeBtns = el('div', 'btn-row ladder-code-btns')
  codeBtns.style.margin = '0'
  const copyBtn = el('button', 'btn btn-outline btn-sm')
  copyBtn.type = 'button'
  copyBtn.textContent = getMessage('ladderDfCopyCode', undefined, 'Copy code')
  // the copied value is EXACTLY what the screen shows (the grouped form —
  // github.com/login/device normalizes its own display shape)
  copyBtn.addEventListener('click', () => copyPlain(copyBtn, shownCode, 'ladderWtCopied', getMessage('ladderDfCopyCode', undefined, 'Copy code')))
  const openBtn = el('button', 'btn btn-primary btn-sm')
  openBtn.type = 'button'
  openBtn.textContent = getMessage('ladderDfOpenGithub', undefined, 'Open github.com/login/device')
  openBtn.addEventListener('click', () => {
    try { chrome.tabs.create({ url: String((st && st.verifyUrl) || GITHUB_DEVICE_FLOW.verifyUrl) }) } catch { /* the card stays */ }
  })
  codeBtns.appendChild(copyBtn)
  codeBtns.appendChild(openBtn)
  codeRow.appendChild(codeBtns)
  card.appendChild(codeRow)
  view.startCountdown() // R120 §2.4 — the live expiry countdown (idempotent)
  card.appendChild(view.expiresLine)
  card.appendChild(view.waitLine)
  card.appendChild(buildDfFooter(view))
  surface.appendChild(card)
  view.codeEl = codeEl
}

function buildDfFooter(view) {
  const footer = el('div', 'btn-row')
  footer.style.margin = '8px 0 0'
  const cancel = el('button', 'btn btn-ghost btn-sm')
  cancel.type = 'button'
  cancel.textContent = getMessage('ladderDfCancel', undefined, 'Cancel')
  cancel.addEventListener('click', () => {
    // R120 §2.4 — Cancel is a teardown: the countdown stops the moment the
    // user backs out (the restore itself lands when the flow returns)
    view.canceled = true
    if (typeof view.clearCountdown === 'function') view.clearCountdown()
  })
  footer.appendChild(cancel)
  return footer
}

/**
 * The device-flow sub-view, INSIDE the wizard overlay. Replaces the ladder
 * block's content while the flow runs; 'canceled' restores the ladder view.
 * Every state renders honestly and NOTHING auto-dismisses (law 0.8): the
 * terminals (expired/denied/throttled/error) stay until the user acts.
 */
function openGithubDeviceView(ctx, surface) {
  const view = {
    ctx, surface,
    canceled: false,
    // the honest waiting line — updated by the poll states, never removed by
    // a timer (no auto-dismiss; the flow's states own it)
    waitLine: el('p', 'card-help ladder-df-wait', ''),
    // R120 §2.4 — the live expiry countdown: ONE interval per view, stored
    // here and cleared on EVERY teardown (cancel, terminal, success, retry,
    // a detached surface) — no stale timers (0.33). The countdown is a
    // DISPLAY parallel to the engine's own typed expiry (ladder.js emits
    // 'expired'); on zero, if the state is still awaiting, the typed expired
    // terminal renders locally too (and a LATER real grant still seals —
    // the user's authorization is never dropped).
    expiresLine: el('p', 'card-help ladder-df-expires', ''),
    countdownTimer: null,
    countdownLeft: 0,
    ended: false,      // a terminal / success / cancel took the surface
    superseded: false, // Try again built a new view — this view's flow is retired
  }

  // -- the live expiry countdown (R120 §2.4) --------------------------------
  const clearCountdown = () => {
    if (view.countdownTimer) { clearInterval(view.countdownTimer); view.countdownTimer = null }
  }
  view.clearCountdown = clearCountdown // the Cancel button's teardown seam
  const endView = () => { clearCountdown(); view.ended = true }
  const expiresText = (left) => {
    const mm = String(Math.floor(left / 60)).padStart(2, '0')
    const ss = String(left % 60).padStart(2, '0')
    return getMessage('ladderDfExpiresIn', [`${mm}:${ss}`], 'Expires in $1$')
  }
  view.startCountdown = () => {
    if (view.countdownTimer || view.ended) return // already ticking / retired — a re-render never resets it
    view.countdownLeft = Math.max(1, Number(GITHUB_DEVICE_FLOW.codeExpiry) || 900)
    view.expiresLine.textContent = expiresText(view.countdownLeft)
    view.countdownTimer = setInterval(() => {
      if (view.ended || !view.surface.isConnected) { clearCountdown(); return }
      view.countdownLeft -= 1
      if (view.countdownLeft <= 0) {
        clearCountdown()
        view.countdownLeft = 0
        view.expiresLine.textContent = expiresText(0)
        // zero with the state still awaiting: the typed expired terminal,
        // locally — the engine's own 'expired' emit is respected either way
        endView()
        showTerminal('ladderDfExpired', 'The sign-in code expired.', '')
        return
      }
      view.expiresLine.textContent = expiresText(view.countdownLeft)
    }, 1000)
  }

  const showEnter = (st) => renderDfEnter(view, st)

  const showTerminal = (titleKey, titleFallback, detailText) => {
    const { surface } = view
    endView() // a terminal takes the surface — the countdown stops here
    surface.innerHTML = ''
    const card = el('div', 'ladder-card ladder-card-fail')
    card.setAttribute('role', 'alert')
    card.appendChild(el('strong', 'ladder-card-title', getMessage(titleKey, undefined, titleFallback)))
    if (detailText) card.appendChild(el('p', 'card-help ladder-card-detail', String(detailText).slice(0, 220)))
    const row = el('div', 'btn-row')
    row.style.margin = '6px 0 0'
    const retry = el('button', 'btn btn-primary btn-sm')
    retry.type = 'button'
    retry.textContent = getMessage('ladderDfTryAgain', undefined, 'Try again')
    retry.addEventListener('click', () => {
      // R120: the old flow is RETIRED — its late results never render over
      // the new view, its countdown never outlives the view (0.33)
      view.superseded = true
      view.canceled = true
      endView()
      openGithubDeviceView(ctx, surface)
    })
    row.appendChild(retry)
    const own = el('button', 'btn btn-outline btn-sm')
    own.type = 'button'
    own.textContent = getMessage('ladderProbeFailUseOwnKey', undefined, 'Use your own key instead →')
    own.addEventListener('click', () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() })
    row.appendChild(own)
    card.appendChild(row)
    surface.appendChild(card)
  }

  const showThrottled = (detailText) => {
    const { surface } = view
    endView() // the throttle card is terminal-class — the countdown stops
    surface.innerHTML = ''
    const card = el('div', 'ladder-card ladder-card-fail')
    card.setAttribute('role', 'alert')
    card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderDfThrottledTitle', undefined, "GitHub's shared sign-in is unavailable right now.")))
    card.appendChild(el('p', 'card-help ladder-card-line', getMessage('ladderDfThrottledText', undefined, 'GitHub refused the device-code request — your own key (the guided rung below) always works.')))
    if (detailText) card.appendChild(el('p', 'card-help ladder-card-detail', String(detailText).slice(0, 220)))
    const row = el('div', 'btn-row')
    row.style.margin = '6px 0 0'
    const own = el('button', 'btn btn-primary btn-sm')
    own.type = 'button'
    own.textContent = getMessage('ladderProbeFailUseOwnKey', undefined, 'Use your own key instead →')
    own.addEventListener('click', () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() })
    row.appendChild(own)
    const back = el('button', 'btn btn-ghost btn-sm')
    back.type = 'button'
    back.textContent = getMessage('ladderDfBack', undefined, 'Back')
    back.addEventListener('click', () => { if (typeof ctx.restore === 'function') ctx.restore() })
    row.appendChild(back)
    card.appendChild(row)
    surface.appendChild(card)
  }

  const onState = (st) => {
    const s = String((st && st.state) || '')
    if (view.ended) return // a retired view never re-renders over its terminal (0.8/0.33)
    if (s === 'code-requested' || s === 'awaiting-user') { showEnter(st); return }
    if (s === 'polling') {
      view.waitLine.textContent = getMessage('ladderDfWaiting', undefined, 'Waiting for you to authorize…')
      return
    }
    if (s === 'slow-down') {
      const iv = Number((st && st.interval) || 0)
      view.waitLine.textContent = getMessage('ladderDfSlowDown', [String(iv || GITHUB_DEVICE_FLOW.intervalMin)], `GitHub asked for a slower pace — still waiting (checking every $1$ seconds).`)
      return
    }
    if (s === 'expired') { showTerminal('ladderDfExpired', 'The sign-in code expired.', (st && st.message) || ''); return }
    if (s === 'denied') { showTerminal('ladderDfDenied', 'Sign-in was refused on github.com.', (st && st.message) || ''); return }
    if (s === 'throttled') { showThrottled((st && st.message) || ''); return }
    if (s === 'error') { showTerminal('ladderDfErrorTitle', 'The GitHub sign-in could not finish.', (st && st.message) || ''); return }
    // 'canceled' is handled by the flow's result below (restore + no card).
  }

  ringRung('github', 'fast', { stage: 'code', message: 'the github device flow was opened' })
  githubDeviceFlow({
    clientId: sharedClientId('github'),
    onState,
    isCanceled: () => view.canceled,
    fetchImpl: fetch,
    sleepImpl: (ms) => new Promise((r) => setTimeout(r, ms)),
  }).then(async (res) => {
    clearCountdown() // every flow end clears the countdown — no stale timers (0.33)
    if (view.superseded) return // the retired flow says nothing (a newer view owns the surface)
    if (res && res.ok) {
      // a real grant always seals — even one that lands after the display
      // countdown reached zero (the user DID authorize; we never drop it)
      endView()
      const saved = await persistFast(ctx, { oauthAccessToken: String(res.accessToken || '') })
      if (!saved.ok) {
        renderSaveFailCard(surface, saved.error)
        if (typeof ctx.onConnectFailed === 'function') {
          try { ctx.onConnectFailed({ transportId: 'github', transportName: ctx.transportName, kind: 'save-failed', detail: saved.error || 'Could not save GitHub connection.' }) } catch { /* best-effort */ }
        }
        return
      }
      ringRung('github', 'fast', { stage: 'seal', message: 'the github device-flow grant was sealed (device-only)' })
      const okOpts = saved.autoSync ? { autoSync: saved.autoSync } : {}
      renderFastOkCard(surface, ctx.transportName, okOpts)
      if (typeof ctx.onConfigured === 'function') {
        await ctx.onConfigured({ ok: true, transportId: 'github', transportName: ctx.transportName, autoSync: saved.autoSync || null })
      }
      if (ctx && ctx.host && !ctx.host.contains(surface)) {
        const liveFast = ctx.host.querySelector('.ladder-rung-fast') || ctx.host
        liveFast.querySelectorAll('.ladder-fast-surface').forEach((n) => n.remove())
        const liveSurface = el('div', 'ladder-fast-surface')
        liveFast.appendChild(liveSurface)
        renderFastOkCard(liveSurface, ctx.transportName, okOpts)
      }
      return
    }
    const s = String((res && res.state) || '')
    if (s === 'canceled') {
      // the user's Cancel — the ladder view returns, nothing was stored
      if (view.ended) return // never restore over a terminal or a newer view
      if (typeof ctx.restore === 'function') ctx.restore()
      return
    }
    if (s === 'throttled') { if (!view.ended) showThrottled((res && res.message) || ''); return }
    if (s === 'expired') { if (!view.ended) showTerminal('ladderDfExpired', 'The sign-in code expired.', (res && res.message) || ''); return }
    if (s === 'denied') { if (!view.ended) showTerminal('ladderDfDenied', 'Sign-in was refused on github.com.', (res && res.message) || ''); return }
    showTerminal('ladderDfErrorTitle', 'The GitHub sign-in could not finish.', (res && res.message) || '')
    ringRung('github', 'fast', { stage: 'poll', outcome: 'fail', error: String((res && res.kind) || '').slice(0, 48), message: 'the github device flow ended without a grant' })
  }).catch(() => {
    clearCountdown()
    if (view.superseded || view.ended) return
    showTerminal('ladderDfErrorTitle', 'The GitHub sign-in could not finish.', '')
  })
}

// ── the ladder block ─────────────────────────────────────────────────────────

function fastCtaKey(tid) {
  return tid === 'gdrive' ? 'ladderFastCtaGdrive'
    : tid === 'github' ? 'ladderFastCtaGithub'
      : 'ladderFastCtaDropbox'
}

const FAST_CTA_FALLBACK = {
  gdrive: 'Sign in with Google — one click',
  github: 'Sign in with GitHub — enter a short code',
  dropbox: 'Sign in with Dropbox',
}

/**
 * Render THE LADDER BLOCK into `opts.host` (the wizard's ladder container).
 * One click switches rungs: each rung's button focuses its surface.
 *
 * opts: {
 *   transportId, transport, transportName,
 *   collectConfig,  () => the form config (the wizard's collector)
 *   persist,        (config) => Promise<{ok, error?}> — the wizard's save path
 *   onConfigured,   () => void — the completion side-effects (grid, checklist)
 *   goToGuided,     () => void — focus the guided (client-ID) surface
 *   goManual,       () => void — focus the manual/advanced surface
 *   openWalkthrough,() => void — open the in-product walkthrough overlay
 *   restore,        () => void — re-render the ladder (the device view's exit)
 * }
 */
export function renderLadderBlock(opts) {
  const host = opts && opts.host
  const transportId = String((opts && opts.transportId) || '')
  if (!host) return null
  if (!LADDER_TRANSPORTS.includes(transportId)) {
    host.innerHTML = ''
    host.classList.add('hidden')
    return null
  }
  host.classList.remove('hidden')
  host.innerHTML = ''
  const ctx = { ...opts, restore: () => renderLadderBlock(opts) }

  const block = el('div', 'ladder-block')

  // 1. FAST — only when detection says so; absence renders NOTHING (§3.7)
  const det = detectFastRung(transportId)
  if (det.available) {
    const fast = el('section', 'ladder-rung ladder-rung-fast')
    fast.dataset.rung = 'fast' // the machine-checkable rung shape (the harness/battery selector)
    fast.appendChild(el('span', 'ladder-rung-name', getMessage('ladderRungFastName', undefined, 'Fast')))
    fast.appendChild(el('p', 'ladder-rung-label', getMessage('ladderRungFastLabel', undefined, 'One click with UCrypt\'s shared sign-in. Nothing to create, nothing to paste.')))
    // R177 — R-177.1/R-177.3 THE CONNECTED-ERA LINE AT THE REOPEN: the
    // panel is no longer state-blind. When the record's bank holds custody,
    // the era renders WHERE THE CTA LIVES — the owner reads connected (with
    // the burn clock when the key is alive), never a first-run face over a
    // living bank (the E-38 owner note's "it says that I need to sign in
    // again" is structurally unreachable). The CTA below stays the renewal
    // affordance it always was; the era is the panel's headline truth.
    const era = (ctx && ctx.custodyEra && typeof ctx.custodyEra === 'object') ? ctx.custodyEra : null
    if (era && era.banked) {
      const clock = (era.alive && Number.isFinite(Number(era.burnMinutes)))
        ? ' ' + getMessage('bankBurnClock', [String(Math.floor(Number(era.burnMinutes)))], `Key burns in ~${Math.floor(Number(era.burnMinutes))} min — the connection renews itself silently when it can; one click when it cannot.`)
        : ''
      // R-177.3 THE AGREEING FRAMES: the era's words name the lock state —
      // locked renders the unlock-is-the-one-step truth (the bank is lock-
      // independent; the frame never says "sign in again"), unlocked renders
      // the surviving-mint truth. One era, its own evidence, no second face.
      // R179 — THE SPENT-BANK TRUTH: a bank whose exp is in the past can no
      // longer say "survives closing this window" — with a sealed refresh
      // grant the words name the silent renewal; without one they name the
      // one-click renewal honestly. The old line lied in the exact shape the
      // field reported ("connected" over a dead clock).
      const diedAt = (!era.alive && Number.isFinite(Number(era.expAt))) ? new Date(Number(era.expAt)) : null
      const hhmm = diedAt ? diedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
      let words
      let eraTone = 'ladder-fast-era-ok'
      if (era.locked) {
        words = getMessage('twFastEraLocked', undefined, 'Connected — unlock the vault once and sync resumes; the sign-in is kept.')
      } else if (era.alive) {
        words = getMessage('twFastConnectedEra', undefined, 'Connected — the one-click sign-in is saved on this device and survives closing this window.')
      } else if (era.hasRefresh) {
        eraTone = 'ladder-fast-era-spent'
        words = hhmm
          ? getMessage('twFastEraSpentRenew', [hhmm], `Connected — the key expired at ${hhmm}; the saved grant renews it silently on the next sync (or press Connect to renew right now).`)
          : getMessage('pSyncCustodyRenewable', undefined, 'Key spent — renews itself on the next sync')
      } else {
        eraTone = 'ladder-fast-era-spent'
        words = hhmm
          ? getMessage('twFastEraSpent', [hhmm], `Connected earlier — the key expired at ${hhmm}. Press Connect — one click signs you back in.`)
          : getMessage('pSyncCustodyExpired', undefined, 'Key expired — press Connect (Set up sync)')
      }
      fast.appendChild(el('p', 'card-help ladder-fast-era ' + eraTone, words + clock))
    }
    const cta = el('button', 'btn btn-primary ladder-fast-cta')
    cta.type = 'button'
    cta.textContent = getMessage(fastCtaKey(transportId), undefined, FAST_CTA_FALLBACK[transportId])
    cta.addEventListener('click', () => {
      // the R115 state machine: disabled + honestly labelled while the flow
      // runs, restored in finally — a double-click can never fire a second
      // authorization window. The typed cards render into `surface` (below
      // the CTA for gdrive/dropbox; the github flow REPLACES the block with
      // its sub-view, so its CTA cannot fire twice by construction).
      const surface = el('div', 'ladder-fast-surface')
      // R165 ARC A — THE HONEST PENDING: the await is BOUNDED (the map's row
      // 0.1 — H-16's UI root). No user-facing state may spin past 5 seconds
      // without a visible state change (the tick updates the button's label)
      // and past the DERIVED bound (R168: 330 s — outlives every inner leg)
      // without a timeout verdict (the card below). The window's own typed
      // settle therefore always wins the race — the honest CONSOLE row can
      // never again be masked by a premature UI TIMEOUT.
      // Retry is ONE explicit click — never automatic.
      let abandoned = false
      const isAbandoned = () => abandoned
      const prevLabel = cta.textContent
      const runFlow = async () => {
        try {
          if (transportId === 'github') {
            // the DEVICE-FLOW sub-view takes over the block inside the
            // wizard overlay; Cancel/Back restore the ladder view
            host.innerHTML = ''
            host.appendChild(surface)
            openGithubDeviceView(ctx, surface)
          } else {
            fast.querySelectorAll('.ladder-fast-surface').forEach((n) => n.remove())
            fast.appendChild(surface)
            if (transportId === 'gdrive') await fastGdrive(ctx, surface, isAbandoned)
            else if (transportId === 'dropbox') await fastDropbox(ctx, surface)
          }
        } catch (e) {
          renderProbeFailCard(surface, 'probe-failed', (e && (e.userMessage || e.message)) || '', {
            onOwnKey: () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() },
            onBack: () => ctx.restore(),
          })
        }
      }
      cta.disabled = true
      cta.textContent = getMessage('ladderFastBusy', undefined, 'Connecting…')
      withHonestPending(getMessage('ladderFastBusy', undefined, 'Connecting…'), runFlow, {
        tickMs: 5000,
        timeoutMs: FAST_UI_PENDING_BOUND_MS,
        onTick: (ms) => {
          // the visible state change — never silence past 5 seconds
          try { cta.textContent = getMessage('ladderFastStill', [String(Math.round(ms / 1000))], 'Still connecting — $1$ s…') } catch { cta.textContent = 'Still connecting…' }
        },
      }).then((verdict) => {
        if (!verdict || verdict.ok) {
          cta.disabled = false
          cta.textContent = prevLabel
          return
        }
        abandoned = true // a late settle must never repaint the settled UI
        cta.disabled = false
        cta.textContent = prevLabel
        fast.querySelectorAll('.ladder-fast-surface').forEach((n) => n.remove())
        fast.appendChild(surface)
        renderVerdictCard(surface, {
          titleKey: 'ladderPendingTimeoutTitle',
          titleFallback: 'The sign-in took too long and was abandoned.',
          body: getMessage('ladderPendingTimeoutBody', [String(Math.round(FAST_UI_PENDING_BOUND_MS / 1000))], `The flow was bounded at ${Math.round(FAST_UI_PENDING_BOUND_MS / 1000)} seconds — nothing was exchanged and nothing was written. If Google's window is still open, close it after reading; then press the button once to retry. If it repeats, press Copy connection receipt (in Sync Doctor) and send it to support.`),
          raw: '',
          domain: 'TIMEOUT',
          fix: '',
          onRetry: () => { try { cta.click() } catch { /* the button is the one explicit retry */ } },
          retryLabel: getMessage('ladderDfRetry', undefined, 'Try again'),
        })
      })
    })
    fast.appendChild(cta)
    // R172 — THE FAST PANEL'S OWN SET (R-172.4): [one-click CTA] +
    // [Test connection]. NO "Save transport" — the one click connects,
    // saves, and answers with a typed success card; the Fast lane never
    // asks for a Save (the field's E-27 question dies here).
    const fastActions = el('div', 'btn-row ladder-fast-actions')
    fastActions.style.margin = '6px 0 0'
    wirePanelActions(fastActions, ctx, { test: true, save: false, cancel: false })
    fast.appendChild(fastActions)
    fast.appendChild(el('p', 'card-help ladder-fast-blast', getMessage('ladderFastBlastRadius', undefined, 'Uses UCrypt\'s shared sign-in — if it ever breaks, your own key (below) always works.')))
    if (transportId === 'gdrive') {
      fast.appendChild(el('p', 'card-help ladder-fast-device-local', getMessage('ladderFastDeviceLocal', undefined, 'This connection lives in this browser\'s own Google account — nothing is stored by UCrypt.')))
      // R165 ARC F — THE CONSENT PRE-WARNING (the contract's verbatim
      // sentence, ×3 locales): the app must TELL the user what Google will
      // show BEFORE the window opens — the honest any-user answer.
      fast.appendChild(el('p', 'card-help ladder-fast-consent-note', getMessage('ladderFastConsentNote', undefined, 'Google will show an "unverified app" warning the first time — choose Advanced → "Go to UCrypt". This is normal while UCrypt is new.')))
      // R166 Arc E — THE SECOND MACHINERY, NAMED BEFORE THE PRESS: the fast
      // rung now carries a fallback inside the SAME one-click press; the
      // honest copy says so (the promise never narrows silently).
      fast.appendChild(el('p', 'card-help ladder-fast-fallback-note', getMessage('ladderFastFallbackNote', undefined, 'If Chrome\u2019s own sign-in cannot answer, UCrypt opens Google\u2019s own consent window instead — still one click, still nothing to create or paste.')))
    }
    block.appendChild(fast)
  }

  // 2. GUIDED — always (the existing guided setup is this rung's surface).
  // R170 §A2 (E-20) — THE SETTLED HOUSE: the alternative rungs collapse
  // under titled, hinted disclosures (the owner's note: used only when the
  // preferred one fails); Fast above stays expanded. The open/closed choice
  // persists per area (lib/settled-house.js); the machine-checkable
  // data-rung shape is preserved.
  const guided = el('details', 'ladder-rung ladder-rung-guided settled-area')
  guided.dataset.rung = 'guided' // the machine-checkable rung shape
  const guidedSummary = el('summary', 'settled-summary')
  guidedSummary.appendChild(el('span', 'ladder-rung-name', getMessage('ladderRungGuidedName', undefined, 'Guided — your own key')))
  guidedSummary.appendChild(el('span', 'settled-hint card-help', getMessage('ladderRungGuidedWhen', undefined, 'When to use this: Fast is unavailable or failed — create your own key with a walkthrough.')))
  guided.appendChild(guidedSummary)
  const guidedBody = el('div', 'settled-body')
  guidedBody.appendChild(el('p', 'ladder-rung-label', getMessage('ladderRungGuidedLabel', undefined, 'Your own key — the walkthrough creates it with you, about five minutes, one time.')))
  const grow = el('div', 'btn-row')
  grow.style.margin = '0'
  const guidedBtn = el('button', 'btn btn-outline btn-sm')
  guidedBtn.type = 'button'
  guidedBtn.textContent = getMessage('ladderRungGuidedBtn', undefined, 'Take me there')
  guidedBtn.addEventListener('click', () => { if (typeof ctx.goToGuided === 'function') ctx.goToGuided() })
  const howBtn = el('button', 'btn btn-ghost btn-sm ladder-wt-open')
  howBtn.type = 'button'
  howBtn.textContent = getMessage('ladderWtOpen', undefined, 'Show me how')
  howBtn.addEventListener('click', () => { if (typeof ctx.openWalkthrough === 'function') ctx.openWalkthrough() })
  grow.appendChild(guidedBtn)
  grow.appendChild(howBtn)
  guidedBody.appendChild(grow)
  // R172 — the guided panel's own set (R-172.4): its own [Test connection]
  // [Save transport] [Cancel] — the panel is self-sufficient; the buttons
  // act on THIS panel's fields.
  const guidedActions = el('div', 'btn-row ladder-guided-actions')
  guidedActions.style.margin = '6px 0 0'
  wirePanelActions(guidedActions, ctx, { test: true, save: true, cancel: true })
  guidedBody.appendChild(guidedActions)
  guided.appendChild(guidedBody)
  try { SettledHouse.apply('ladder-guided', guided) } catch { /* the defaults still apply without storage */ }
  block.appendChild(guided)

  // 2b. R174 — SELF-CHECK: the facts + the zero-window probe (the field's
  // sixth word demanded the end of guessing: WHICH build, WHICH identity,
  // WHICH client rides — and whether Google accepts the pair — visible IN
  // the product, before any Console trip). R170 §A2 — collapsed under a
  // titled, hinted disclosure; A FAILING VERDICT AUTO-OPENS it (the fire
  // exception — no card hides a fire).
  const self = el('details', 'ladder-rung ladder-selfcheck settled-area')
  self.dataset.rung = 'selfcheck' // the machine-checkable rung shape
  const selfSummary = el('summary', 'settled-summary')
  selfSummary.appendChild(el('span', 'ladder-rung-name', getMessage('ladderSelfCheckName', undefined, 'Self-check')))
  selfSummary.appendChild(el('span', 'settled-hint card-help', getMessage('ladderSelfCheckWhen', undefined, 'When to use this: before a Console trip — see exactly what this browser sends and whether Google accepts it.')))
  self.appendChild(selfSummary)
  const selfBody = el('div', 'settled-body')
  selfBody.appendChild(el('p', 'ladder-rung-label', getMessage('ladderSelfCheckLabel', undefined, 'See exactly what this browser sends — and whether Google accepts it — before you touch the Console.')))
  self.appendChild(selfBody)
  try { SettledHouse.apply('ladder-selfcheck', self) } catch { /* the defaults still apply without storage */ }
  const ident = (typeof runtimeIdentity === 'function') ? runtimeIdentity() : { version: '', extId: '', redirect: '', manifestClientId: '' }
  const stampP = el('p', 'card-help ladder-selfcheck-stamp')
  const stampV = ident.version || '?'
  const stampI = ident.extId || '?'
  stampP.textContent = getMessage('ladderSelfCheckStamp', [stampV, stampI], `UCrypt ${stampV} — this extension's ID: ${stampI}`)
  selfBody.appendChild(stampP)
  if (ident.redirect) {
    const redP = el('p', 'card-help ladder-selfcheck-redirect')
    redP.textContent = getMessage('ladderSelfCheckRedirect', [ident.redirect], `Redirect URI: ${ident.redirect}`)
    selfBody.appendChild(redP)
    const copyRow = el('div', 'btn-row')
    copyRow.style.margin = '0'
    const copyBtn = el('button', 'btn btn-outline btn-sm')
    copyBtn.type = 'button'
    copyBtn.textContent = getMessage('ladderSelfCheckCopy', undefined, 'Copy redirect URI')
    copyBtn.addEventListener('click', async () => {
      const ok = await copyText(ident.redirect)
      copyBtn.textContent = ok ? getMessage('ladderSelfCheckCopied', undefined, 'Copied.') : ident.redirect
    })
    copyRow.appendChild(copyBtn)
    selfBody.appendChild(copyRow)
  }
  const verdict = el('p', 'card-help ladder-selfcheck-verdict')
  verdict.hidden = true
  verdict.setAttribute('role', 'status')
  const showVerdict = (r, label) => {
    verdict.hidden = false
    // R170 — THE FIRE EXCEPTION (R-170.1): a failing self-check verdict is
    // an active warning — the collapsed area must auto-reveal it, never
    // hide it. (A healthy verdict keeps the user's chosen open/closed state.)
    if (r && r.ok !== 'healthy') {
      try { self.open = true } catch { /* detached — the verdict still paints */ }
      self.setAttribute('data-fire-revealed', 'true')
    }
    const key = {
      healthy: 'ladderSelfCheckHealthy',
      mismatch: 'ladderSelfCheckMismatch',
      'client-missing': 'ladderSelfCheckClientMissing',
      'wrong-type': 'ladderSelfCheckWrongType',
      offline: 'ladderSelfCheckOffline',
      untyped: 'ladderSelfCheckUntyped',
    }[r.ok]
    const subs = r.ok === 'mismatch' ? [ident.redirect || r.raw] : r.ok === 'untyped' ? [String(r.raw || '').slice(0, 160)] : undefined
    const title = key ? getMessage(key, subs, r.title) : r.title
    verdict.textContent = `${label ? label + ' — ' : ''}${title}${r.detail ? ' ' + r.detail : ''}`
    verdict.className = 'card-help ladder-selfcheck-verdict ' + (r.ok === 'healthy' ? 'ladder-selfcheck-ok' : (r.ok === 'offline' || r.ok === 'bad-input') ? '' : 'ladder-selfcheck-bad')
  }
  const busyRow = el('div', 'btn-row')
  busyRow.style.margin = '0'
  let selfAbandoned = false
  const isAbandonedSelf = () => selfAbandoned
  const runProbe = async (clientId, btn, verdictLabel) => {
    const orig = btn.textContent
    btn.disabled = true
    btn.textContent = getMessage('ladderSelfCheckTesting', undefined, 'Testing…')
    try {
      const r = await oauthSelfCheck({ clientId, redirect: ident.redirect })
      if (!isAbandonedSelf()) showVerdict(r, verdictLabel)
    } catch (e) {
      if (!isAbandonedSelf()) showVerdict({ ok: 'untyped', title: '', detail: '', raw: String((e && e.message) || e) }, verdictLabel)
    }
    btn.disabled = false
    btn.textContent = orig
  }
  if (ident.laneUClientId && ident.redirect) {
    const factoryBtn = el('button', 'btn btn-outline btn-sm')
    factoryBtn.type = 'button'
    // R169 — the "factory sign-in" probe rides the LANE U client (the
    // universal lane's Web-application client — the client the one-click
    // window actually sends).
    factoryBtn.textContent = getMessage('ladderSelfCheckTestFactory', undefined, 'Test the factory sign-in')
    factoryBtn.addEventListener('click', () => { runProbe(ident.laneUClientId, factoryBtn, '') })
    busyRow.appendChild(factoryBtn)
  }
  // R169 — THE LANE C ROW: the Chrome silent lane's client (the manifest's
  // Chrome-Extension client) gets its own zero-window probe — the verdict
  // names whether the client exists (its Item-ID correctness is judged by
  // the silent try itself, never by this probe).
  if (ident.manifestClientId && ident.redirect) {
    const laneCBtn = el('button', 'btn btn-ghost btn-sm')
    laneCBtn.type = 'button'
    laneCBtn.textContent = getMessage('ladderSelfCheckTestLaneC', undefined, 'Test Chrome\u2019s silent-lane client')
    laneCBtn.addEventListener('click', () => { runProbe(ident.manifestClientId, laneCBtn, getMessage('ladderSelfCheckLaneCLabel', undefined, 'Chrome silent lane')) })
    busyRow.appendChild(laneCBtn)
  }
  // the saved client (the guided lane's own key) — best-effort, additive
  let savedClient = ''
  try {
    const cfg = (typeof ctx.collectConfig === 'function') ? (ctx.collectConfig() || {}) : {}
    savedClient = String((cfg && cfg.clientId) || '').trim()
  } catch { /* the saved client never blocks the card */ }
  if (savedClient && savedClient !== ident.manifestClientId && savedClient !== ident.laneUClientId) {
    if (isRetiredClientId(savedClient)) {
      const retiredP = el('p', 'card-help ladder-selfcheck-retired')
      retiredP.textContent = getMessage('ladderSelfCheckSavedRetired', undefined, 'Your saved key is the RETIRED client UCrypt no longer trusts (the dead first client) — the factory sign-in rides instead.')
      selfBody.appendChild(retiredP)
    } else if (savedClient === ident.laneCClientId) {
      // R169 — the saved key IS the Lane C client (a silent-lane press rode
      // last): honest note, and the probe button stays available.
      const laneCP = el('p', 'card-help ladder-selfcheck-retired')
      laneCP.textContent = getMessage('ladderSelfCheckSavedLaneC', undefined, 'Your saved key is Chrome\u2019s silent-lane client — it serves the silent sign-in; the Google-window lane rides its own client.')
      selfBody.appendChild(laneCP)
    } else if (ident.redirect) {
      const savedBtn = el('button', 'btn btn-ghost btn-sm')
      savedBtn.type = 'button'
      savedBtn.textContent = getMessage('ladderSelfCheckTestSaved', undefined, 'Test my saved key')
      savedBtn.addEventListener('click', () => { runProbe(savedClient, savedBtn, '') })
      busyRow.appendChild(savedBtn)
    }
  }
  selfBody.appendChild(busyRow)
  selfBody.appendChild(verdict)
  // R172 — the self-check panel's own set: the probes above ARE its test;
  // the Cancel closes the panel. (No Save — a read-only probe panel that
  // offered "Save transport" would name an action it never performs — the
  // referenced-affordance law R-172.5 forbids the lie.)
  const selfActions = el('div', 'btn-row ladder-selfcheck-actions')
  selfActions.style.margin = '6px 0 0'
  wirePanelActions(selfActions, ctx, { test: false, save: false, cancel: true })
  selfBody.appendChild(selfActions)
  block.appendChild(self)

  // 3. MANUAL — always, visually demoted (the Advanced/PAT fields).
  // R170 §A2 — collapsed under a titled, hinted disclosure like its
  // siblings; the machine-checkable data-rung shape is preserved.
  const manual = el('details', 'ladder-rung ladder-rung-manual settled-area')
  manual.dataset.rung = 'manual' // the machine-checkable rung shape
  const manualSummary = el('summary', 'settled-summary')
  manualSummary.appendChild(el('span', 'ladder-rung-name', getMessage('ladderRungManualName', undefined, 'Manual')))
  manualSummary.appendChild(el('span', 'settled-hint card-help', getMessage('ladderRungManualWhen', undefined, 'When to use this: you already hold a token or your own client ID — paste it directly.')))
  manual.appendChild(manualSummary)
  const manualBody = el('div', 'settled-body')
  manualBody.appendChild(el('p', 'ladder-rung-label', getMessage('ladderRungManualLabel', undefined, 'Advanced: paste an existing token or connect without a browser window.')))
  const manualBtn = el('button', 'btn btn-ghost btn-sm')
  manualBtn.type = 'button'
  manualBtn.textContent = getMessage('ladderRungManualBtn', undefined, 'Open the advanced fields')
  manualBtn.addEventListener('click', () => { if (typeof ctx.goManual === 'function') ctx.goManual() })
  manualBody.appendChild(manualBtn)
  // R172 — the manual panel's own set (R-172.4).
  const manualActions = el('div', 'btn-row ladder-manual-actions')
  manualActions.style.margin = '6px 0 0'
  wirePanelActions(manualActions, ctx, { test: true, save: true, cancel: true })
  manualBody.appendChild(manualActions)
  manual.appendChild(manualBody)
  try { SettledHouse.apply('ladder-manual', manual) } catch { /* the defaults still apply without storage */ }
  block.appendChild(manual)

  // R170 §A3 — the fast-availability stamp: options.js reads it to decide
  // the alternative-configuration area's default (collapsed when Fast is
  // present, expanded when Fast is absent — the alternative becomes the
  // primary and the defaults follow the settled-house law).
  host.dataset.fastAvailable = det.available ? '1' : '0'
  // R172 — THE ONE-OPEN ACCORDION DISCIPLINE (R-172.4, the E-27 law):
  // exactly ONE method panel expanded at a time. When one opens, its
  // siblings close (the owner's words: "Once one area is uncollapsed, all
  // the other areas must to remain collapsed"). The persisted choice
  // (SettledHouse) still decides the DEFAULTS; the runtime enforces the
  // one-open truth on every toggle.
  const panels = [...block.querySelectorAll('details.settled-area')]
  for (const p of panels) {
    p.addEventListener('toggle', () => {
      if (!p.open) return
      for (const sib of panels) {
        if (sib !== p && sib.open) {
          try { sib.open = false } catch { /* the sibling's own toggle runs */ }
        }
      }
      // the Alternative setup panel counts as a sibling (the same law)
      try {
        const adv = document.getElementById('twAdvancedConfig')
        if (adv && adv.open) adv.open = false
      } catch { /* detached — nothing to close */ }
    })
  }
  host.appendChild(block)
  return block
}

/**
 * The guided rung's PREFLIGHT PING (§3.4): a typed inline card anchored ON
 * the field — a stale/malformed client ID says so BEFORE any auth window
 * opens. `result` is preflightClientId()'s { ok, kind, expected? }.
 */
export function renderPreflightCard(fieldEl, result, { onShowHow } = {}) {
  if (!fieldEl || !result || result.ok) return
  const row = fieldEl.closest('.form-group') || fieldEl.parentElement
  if (!row) return
  const prev = row.querySelector('.ladder-preflight-card')
  if (prev) prev.remove()
  const card = el('div', 'ladder-card ladder-card-fail ladder-preflight-card')
  card.setAttribute('role', 'alert')
  card.appendChild(el('strong', 'ladder-card-title', getMessage('ladderPreFailTitle', undefined, 'Check your client ID before the sign-in window opens:')))
  const msgKey = result.kind === 'empty' ? 'ladderPreEmpty'
    : String(result.transportId) === 'github' ? 'ladderPreFormatGithub'
      : 'ladderPreFormatGdrive'
  card.appendChild(el('p', 'card-help ladder-card-line', getMessage(msgKey, undefined, 'The value in this field does not look right — re-copy it from the console.')))
  if (typeof onShowHow === 'function') {
    const rowBtns = el('div', 'btn-row')
    rowBtns.style.margin = '6px 0 0'
    const how = el('button', 'btn btn-outline btn-sm')
    how.type = 'button'
    how.textContent = getMessage('ladderWtOpen', undefined, 'Show me how')
    how.addEventListener('click', onShowHow)
    rowBtns.appendChild(how)
    card.appendChild(rowBtns)
  }
  // the card lives directly under the field it names (the 0.29 surface)
  const help = row.querySelector('.card-help')
  if (help && help.parentElement === row) row.insertBefore(card, help.nextSibling)
  else row.appendChild(card)
}

// ── THE GUIDED WALKTHROUGH (§3.4 — the CEO's explicit ask) ──────────────────

const DROPBOX_APP_FOLDER_SUGGESTION = 'UCrypt'

/**
 * The per-transport step data. Every step: the exact menu item to click
 * (title + text), the copy-buttons for the exact strings (one click, never
 * mistyped), and the what-you-should-see line (one sentence).
 * ctx: { extensionId, redirect }
 */
export function walkthroughSteps(transportId, ctx = {}) {
  const tid = String(transportId || '')
  if (tid === 'gdrive') {
    return [
      { t: 'ladderWtG1Title', x: 'ladderWtG1Text', see: 'ladderWtG1See', link: 'https://console.cloud.google.com/' },
      { t: 'ladderWtG2Title', x: 'ladderWtG2Text', see: 'ladderWtG2See', link: 'https://console.cloud.google.com/apis/library/drive.googleapis.com' },
      { t: 'ladderWtG3Title', x: 'ladderWtG3Text', see: 'ladderWtG3See', link: 'https://console.cloud.google.com/apis/credentials/consent' },
      { t: 'ladderWtG4Title', x: 'ladderWtG4Text', see: 'ladderWtG4See', illu: 'consent' },
      { t: 'ladderWtG5Title', x: 'ladderWtG5Text', see: 'ladderWtG5See', link: 'https://console.cloud.google.com/apis/credentials' },
      { t: 'ladderWtG6Title', x: 'ladderWtG6Text', see: 'ladderWtG6See', copy: String(ctx.extensionId || '') },
      { t: 'ladderWtG7Title', x: 'ladderWtG7Text', see: 'ladderWtG7See', copy: String(ctx.redirect || ''), illu: 'redirect' },
      { t: 'ladderWtG8Title', x: 'ladderWtG8Text', see: 'ladderWtG8See', goField: 'clientId' },
    ]
  }
  if (tid === 'github') {
    return [
      { t: 'ladderWtH1Title', x: 'ladderWtH1Text', see: 'ladderWtH1See', link: 'https://github.com/settings/developers' },
      { t: 'ladderWtH2Title', x: 'ladderWtH2Text', see: 'ladderWtH2See' },
      { t: 'ladderWtH3Title', x: 'ladderWtH3Text', see: 'ladderWtH3See', copy: String(ctx.redirect || ''), illu: 'form' },
      { t: 'ladderWtH4Title', x: 'ladderWtH4Text', see: 'ladderWtH4See', illu: 'device' },
      { t: 'ladderWtH5Title', x: 'ladderWtH5Text', see: 'ladderWtH5See', goField: 'oauthClientId' },
    ]
  }
  if (tid === 'dropbox') {
    return [
      { t: 'ladderWtD1Title', x: 'ladderWtD1Text', see: 'ladderWtD1See', link: 'https://www.dropbox.com/developers/apps' },
      { t: 'ladderWtD2Title', x: 'ladderWtD2Text', see: 'ladderWtD2See', copy: DROPBOX_APP_FOLDER_SUGGESTION, illu: 'create' },
      { t: 'ladderWtD3Title', x: 'ladderWtD3Text', see: 'ladderWtD3See' },
      { t: 'ladderWtD4Title', x: 'ladderWtD4Text', see: 'ladderWtD4See', copy: String(ctx.redirect || ''), illu: 'settings' },
      { t: 'ladderWtD5Title', x: 'ladderWtD5Text', see: 'ladderWtD5See', goField: 'appKey' },
    ]
  }
  return []
}

const WHY_KEY = { gdrive: 'ladderWtWhyGdrive', github: 'ladderWtWhyGithub', dropbox: 'ladderWtWhyDropbox' }

/**
 * Render the walkthrough INTO the overlay host (options.html's
 * #walkthroughHost — the overlay itself carries the visible ✕ close button
 * and the focus return, law 0.30). The typed error cards close the loop:
 * a disabled client already renders the production-publishing checklist
 * (the R116 verification) — this footer LINKS to it, never duplicates.
 *
 * opts: { transportId, host, extensionId?, redirect?, onGoField(fieldKey) }
 */
export function renderWalkthrough(opts) {
  const host = opts && opts.host
  const transportId = String((opts && opts.transportId) || '')
  if (!host) return
  host.innerHTML = ''
  const ctx = {
    extensionId: opts.extensionId !== undefined ? opts.extensionId : (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) || '',
    redirect: opts.redirect !== undefined ? opts.redirect : identityRedirect(),
  }
  const head = el('div', 'ladder-wt-head')
  head.appendChild(el('h3', 'ladder-wt-title', getMessage('ladderWtTitle', undefined, 'Show me how — step by step')))
  head.appendChild(el('p', 'card-help', getMessage(WHY_KEY[transportId] || 'ladderWtWhyGdrive', undefined, 'Your own key keeps the cloud provably yours — five minutes, one time.')))
  host.appendChild(head)

  const ol = el('ol', 'ladder-wt-steps')
  const steps = walkthroughSteps(transportId, ctx)
  steps.forEach((s) => {
    const li = el('li', 'ladder-wt-step')
    li.appendChild(el('strong', null, getMessage(s.t, undefined, '')))
    li.appendChild(el('p', 'card-help ladder-wt-text', getMessage(s.x, undefined, '')))
    // R120 §2.1 — the annotated console screen rides the step it describes:
    // the self-drawn facsimile + ONE caption line (i18n ×3) + the alt text.
    if (s.illu) {
      const illu = ladderIllustration(transportId, s.illu, ctx)
      if (illu) {
        const fig = el('figure', 'ladder-illu')
        const holder = el('div', 'ladder-illu-frame')
        holder.innerHTML = illu.svg
        const svgEl = holder.querySelector('svg')
        if (svgEl) {
          svgEl.setAttribute('aria-label', getMessage(illu.altKey || '', undefined, ''))
          fig.appendChild(svgEl)
        }
        fig.appendChild(el('figcaption', 'card-help ladder-illu-cap', getMessage(illu.capKey, undefined, '')))
        li.appendChild(fig)
      }
    }
    if (s.copy) {
      const copyRow = el('div', 'ladder-wt-copyrow')
      const val = el('span', 'ladder-wt-copyval', s.copy)
      val.style.userSelect = 'all'
      copyRow.appendChild(val)
      const btn = el('button', 'btn btn-ghost btn-sm ladder-wt-copybtn')
      btn.type = 'button'
      const copyLabel = getMessage('ladderWtCopy', undefined, 'Copy')
      btn.textContent = copyLabel
      btn.addEventListener('click', () => copyPlain(btn, s.copy, 'ladderWtCopied', copyLabel))
      copyRow.appendChild(btn)
      li.appendChild(copyRow)
    }
    if (s.goField && typeof opts.onGoField === 'function') {
      const goRow = el('div', 'btn-row')
      goRow.style.margin = '4px 0 0'
      const go = el('button', 'btn btn-outline btn-sm')
      go.type = 'button'
      go.textContent = getMessage('ladderWtGoField', undefined, 'Take me to the field')
      go.addEventListener('click', () => opts.onGoField(s.goField))
      goRow.appendChild(go)
      li.appendChild(goRow)
    }
    if (s.link) {
      const a = el('a', 'ladder-wt-link', getMessage('twStepOpen', undefined, 'Open ↗'))
      a.href = s.link
      a.target = '_blank'
      a.rel = 'noreferrer noopener'
      li.appendChild(a)
    }
    li.appendChild(el('p', 'card-help ladder-wt-see', getMessage('ladderWtSee', undefined, 'You should see:') + ' ' + getMessage(s.see, undefined, '')))
    ol.appendChild(li)
  })
  host.appendChild(ol)

  if (transportId === 'github') {
    host.appendChild(el('p', 'card-help ladder-wt-note', getMessage('ladderWtGithubNote', undefined, 'Note: your OWN app with the callback URL above works today — no approval needed.')))
  }
  host.appendChild(el('p', 'card-help ladder-wt-note', getMessage('ladderWtChecklistNote', undefined, 'If Google ever calls your client disabled or testing-only, UCrypt shows its own fix card with the publishing checklist — press Connect and it appears at the words.')))
}
