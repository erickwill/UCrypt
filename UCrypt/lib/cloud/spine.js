/**
 * ════════════════════════════════════════════════════════════════════════
 * R171 — THE UNBROKEN SPINE (lib/cloud/spine.js — the persistent sign-in).
 *
 * THE FIELD LAW (the owner's own words): "Google's one-click sign-in EXPIRED
 * after I closed and reopened the browser! The sign-in must PERSIST!" — and
 * the feature-operations north: the connection with the cloud service must
 * KEEP WORKING even when the browser is closed and reopened — STABLE.
 *
 * THE ROOT CAUSE (typed by the CSA, machine evidence on file): the window
 * lane rides the confidential Web-application client, whose secretless
 * exchange Google refuses — so the machine falls back to the implicit flow,
 * which mints an ACCESS TOKEN ONLY, no refresh token, ~1-hour life, dead
 * with the browser process. Every browser restart therefore ends the session
 * by Google's own rules.
 *
 * THE CURE IS ARCHITECTURAL: UCrypt mints and keeps a REFRESH TOKEN from a
 * PUBLIC client — the Chrome-extension-class spine client
 * (lib/cloud/oauth-clients.js SPINE_CLIENT_ID, the same client the manifest
 * pins for Lane C — one client, both lanes, no manifest re-pin):
 *
 *   (b) THE SPINE PROBE (zero-window, no red page ever): the service worker
 *       fetches the spine client's authorization URL (redirect_uri = the
 *       derived https://<ext-id>.chromiumapp.org/) under the manifest host
 *       permission for accounts.google.com; the fetch follows Google's
 *       redirect and reads response.url — Google's sign-in page = ARMED;
 *       the error page carrying the authError blob = UNARMED (the blob is
 *       DECODED, never guessed). No window opens for the probe.
 *   (c) THE SPINE CONNECT: when the probe says ARMED, the connect flow
 *       opens Google's window ONCE with the spine client — response_type=
 *       code, PKCE S256, access_type=offline, prompt=consent — and performs
 *       the SECRETLESS code exchange (a public installed-class client needs
 *       no secret; Google grants access_token AND refresh_token). The copy
 *       says it plainly: "one last window — after this, UCrypt reconnects
 *       by itself, even after a restart." When the probe says UNARMED, the
 *       flow rides the R171-floor web-client path byte-true.
 *   (d) THE SPINE CUSTODY: the refresh token rides the SEALED transport
 *       envelope (the vault-derived key custody pattern, chrome.storage.local
 *       ciphertext — lib/vault.js). It never appears in logs, telemetry,
 *       i18n strings, or cards. On every service-worker start and before
 *       every sync: if the access token is missing or expired, the machine
 *       mints silently via the refresh grant — no window, no user action.
 *       On invalid_grant: clear the stored grant and raise the typed
 *       one-click reconnect card.
 *   (e) THE SPINE REVOKE: Disconnect revokes the token server-side (Google's
 *       revocation endpoint) AND clears local custody — then re-connect
 *       re-mints fresh. Disconnect leaves nothing alive behind it.
 *
 * ENGINE-ONLY: no DOM; every chrome/fetch read is injectable so the battery
 * drives every branch without a browser. No token value ever rides a ring
 * row, a card, or an i18n string (the no-secret law now names the
 * refresh-token shape too).
 * ════════════════════════════════════════════════════════════════════════
 */

import { SPINE_CLIENT_ID, SPARE_SPINE_CLIENT_ID } from './oauth-clients.js'

export { SPINE_CLIENT_ID, SPARE_SPINE_CLIENT_ID }

/** Google's authorization endpoint (the probe's and the connect's seat). */
export const OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
/** Google's token revocation endpoint (the spine revoke's seat). */
export const OAUTH_REVOKE_URL = 'https://oauth2.googleapis.com/revoke'
/** The probe's scope (the Drive appdata scope the fast rung rides — the
 * value only shapes the URL; the probe never completes a grant). */
export const SPINE_PROBE_SCOPE = 'https://www.googleapis.com/auth/drive.appdata'

/**
 * The spine's authorization URL — PURE, exported for the battery.
 * URLSearchParams only (never hand-concatenation — the double-encode law).
 * The probe rides the minimal shape; the connect adds PKCE + state via the
 * established code-lane builder (lib/webauth-fallback.js gdriveWebAuthCodeUrl).
 * @param {{clientId: string, redirect: string, scope?: string}} facts
 */
export function spineAuthUrl(facts) {
  const clientId = String((facts && facts.clientId) || '').trim()
  const redirect = String((facts && facts.redirect) || '').trim()
  if (!clientId) throw Object.assign(new Error('the spine client id is absent — the probe has nothing to test'), { kind: 'spine-client-absent' })
  if (!redirect) throw Object.assign(new Error('the derived redirect is absent — chrome.identity.getRedirectURL() is the only lawful redirect, never hand-built'), { kind: 'spine-redirect-absent' })
  const u = new URL(OAUTH_AUTH_URL)
  u.searchParams.set('client_id', clientId)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('redirect_uri', redirect)
  u.searchParams.set('scope', String((facts && facts.scope) || SPINE_PROBE_SCOPE))
  return u.toString()
}

/**
 * Decode Google's authError blob (the UNARMED page's own evidence) — PURE.
 * The blob rides the error URL's `authError` query field as base64url JSON
 * ({code, uri, …}). Decode, never guess: the decoded code names the defect.
 * @param {string} url the final response URL
 * @returns {{ ok: boolean, code: string, raw: string }}
 */
export function decodeAuthErrorBlob(url) {
  const raw = String(url || '')
  let u = null
  try { u = new URL(raw) } catch { return { ok: false, code: '', raw: '' } }
  const blob = u.searchParams.get('authError') || ''
  if (!blob) return { ok: false, code: '', raw: '' }
  try {
    const b64 = blob.replace(/-/g, '+').replace(/_/g, '/')
    const pad = b64.length % 4 ? b64 + '='.repeat(4 - (b64.length % 4)) : b64
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(pad), (c) => c.charCodeAt(0))))
    return { ok: true, code: String((json && json.code) || ''), raw: raw.slice(0, 240) }
  } catch { return { ok: false, code: '', raw: raw.slice(0, 240) } }
}

/** Is this final URL Google's sign-in page (the ARMED terminus)? PURE. */
export function isGoogleSignInTerminus(url) {
  let u = null
  try { u = new URL(String(url || '')) } catch { return false }
  const host = String(u.hostname || '').toLowerCase()
  if (host !== 'accounts.google.com' && !host.endsWith('.google.com')) return false
  const p = String(u.pathname || '')
  const flow = String(u.searchParams.get('flowName') || '')
  const hasErrorBlob = u.searchParams.has('authError') || String(u.searchParams.get('error') || '') !== ''
  if (hasErrorBlob) return false
  return /^\/(v3\/signin|signin|o\/oauth2)/.test(p) || /GeneralOAuthLite|OAuthConsent|SignOAuth/i.test(flow)
}

/** Is this final URL the extension's own redirect terminus (the derived
 * https://<ext-id>.chromiumapp.org/ shape)? The ALREADY-CONSENTED probe
 * ride: when the browser session is signed in and the consent was granted
 * previously, Google redirects the probe fetch ALL THE WAY BACK to the
 * redirect with a code — the strongest ARMED evidence there is. PURE.
 * @param {string} url the final response URL
 * @param {string} redirect the derived redirect (chrome.identity.getRedirectURL())
 * @returns {{ hit: boolean, consented: boolean }}
 */
export function isRedirectTerminus(url, redirect) {
  const target = String(redirect || '').trim()
  if (!target) return { hit: false, consented: false }
  let u = null
  try { u = new URL(String(url || '')) } catch { return { hit: false, consented: false } }
  let t = null
  try { t = new URL(target) } catch { return { hit: false, consented: false } }
  // the host + the extension path prefix must match the derived redirect
  if (String(u.hostname || '').toLowerCase() !== String(t.hostname || '').toLowerCase()) return { hit: false, consented: false }
  if (!String(u.pathname || '').startsWith(String(t.pathname || ''))) return { hit: false, consented: false }
  // a code (or an error) rode back — the pair client+redirect is LIVE
  const hasCode = String(u.searchParams.get('code') || '') !== ''
  const hasError = String(u.searchParams.get('error') || '') !== ''
  return { hit: hasCode || hasError, consented: hasCode }
}

/**
 * THE SPINE PROBE — ZERO WINDOW, no user data, no red page ever.
 *
 * The service worker fetches the spine client's authorization URL; Google
 * decides where the BROWSER would land and the fetch follows that redirect:
 *   ARMED   → the redirect lands on Google's sign-in page (the pair client+
 *             redirect is registered — the Console Item-ID row is live);
 *   ARMED   → the redirect lands on the extension's OWN chromiumapp.org
 *             terminus with a code (R179: the already-consented ride — the
 *             consent was granted previously and Google answered with the
 *             grant immediately; the strongest armed evidence);
 *   UNARMED → the error page carrying the authError blob / the typed error
 *             param / the 400 body markers (R179: the error page can be
 *             served AT the auth URL itself — URL shape alone cannot
 *             separate it from the consent page, so the bounded body read
 *             decides; the old URL-only probe misread the 400 page as
 *             ARMED and opened a doomed window, then fell through);
 *   offline → the network refused;
 *   untyped → Google answered with an unexpected shape (the raw rides).
 *
 * @param {{clientId?: string, redirect: string, fetchImpl?: typeof fetch}} facts
 * @returns {Promise<{ok: 'armed'|'unarmed'|'offline'|'bad-input'|'untyped',
 *                     title: string, detail: string, blobCode: string, raw: string,
 *                     consented?: boolean}>}
 */
export async function spineProbe(facts) {
  const clientId = String((facts && facts.clientId) || SPINE_CLIENT_ID).trim()
  const redirect = String((facts && facts.redirect) || '').trim()
  const fetchImpl = (facts && facts.fetchImpl) || (typeof fetch === 'function' ? fetch : null)
  if (!clientId || !redirect || !fetchImpl) {
    return {
      ok: 'bad-input',
      title: 'The spine probe has nothing to test yet — the client or the redirect is absent in this browser context.',
      detail: '',
      blobCode: '',
      raw: '',
    }
  }
  let url = ''
  try { url = spineAuthUrl({ clientId, redirect }) } catch (e) {
    return { ok: 'bad-input', title: String((e && e.message) || e), detail: '', blobCode: '', raw: '' }
  }
  let res = null
  try {
    res = await fetchImpl(url, { method: 'GET', redirect: 'follow', credentials: 'omit' })
  } catch (e) {
    return {
      ok: 'offline',
      title: 'The spine probe could not reach Google — the network is offline or blocked.',
      detail: String((e && e.message) || e).slice(0, 200),
      blobCode: '',
      raw: '',
    }
  }
  const finalUrl = res && res.url ? String(res.url) : ''
  if (!finalUrl) {
    return { ok: 'untyped', title: 'Google answered without a final URL — the probe cannot judge the redirect row.', detail: '', blobCode: '', raw: '' }
  }
  // R179 — THE ALREADY-CONSENTED RIDE FIRST: Google answered the probe by
  // redirecting straight back to the extension's own terminus with a code —
  // the Console row is live AND the consent is already granted (the connect
  // window will be the one-click confirm at most).
  const terminus = isRedirectTerminus(finalUrl, redirect)
  if (terminus.hit) {
    if (terminus.consented) {
      return {
        ok: 'armed',
        title: 'ARMED — Google accepts the spine client and this extension\u2019s redirect (the consent is already granted).',
        detail: 'The persistent sign-in is available and ALREADY GRANTED: press Connect and the window confirms in one click — after that UCrypt reconnects by itself, even after a browser restart. (The Console Item-ID row is live.)',
        blobCode: '',
        raw: finalUrl.slice(0, 240),
        consented: true,
      }
    }
    // the terminus answered with an error param — the typed code rides
    const errCode = (() => { try { return new URL(finalUrl).searchParams.get('error') || 'redirect_error' } catch { return 'redirect_error' } })()
    return {
      ok: 'unarmed',
      title: 'UNARMED — the spine redirect answered with an error (' + errCode + ').',
      detail: 'Google Cloud Console \u2192 APIs & Services \u2192 Credentials \u2192 the client ' + clientId + ' \u2192 confirm its edit page reads "Chrome extension" \u2192 set Item ID, letter-exact, to this extension\u2019s own ID (shown on the Self-check card) \u2192 Save. Console changes can take Google five minutes to a few hours to take effect. Until then Connect rides today\u2019s one-click path unchanged.',
      blobCode: String(errCode).slice(0, 80),
      raw: finalUrl.slice(0, 240),
    }
  }
  // R179 — THE BOUNDED BODY READ FIRST (the 400-page cure): the UNARMED
  // error page can be served AT the auth URL itself (no redirect, same
  // response.url) — its pathname matches the auth-endpoint shape, so a
  // URL-only sign-in check would misread it as ARMED (the doomed-window
  // lie). Google's own error words in the page body decide BEFORE any
  // URL-shape verdict, never a guess.
  const bodySniff = await (async () => {
    try {
      if (!res || typeof res.text !== 'function') return ''
      const txt = await Promise.race([
        res.text(),
        new Promise((resolve) => setTimeout(() => resolve(''), 3000)),
      ])
      return String(txt || '').slice(0, 4096)
    } catch { return '' }
  })()
  const blob = decodeAuthErrorBlob(finalUrl)
  const errParam = (() => { try { return new URL(finalUrl).searchParams.get('error') || '' } catch { return '' } })()
  const bodyError = /redirect_uri_mismatch|deleted_client|invalid_client|access_blocked|Error 400[:\s]|40[03]\s*:\s*/i.test(bodySniff)
  if (blob.ok || errParam || bodyError || /\/oauth\/error|authError/i.test(finalUrl)) {
    const code = blob.code || errParam || (bodyError ? 'body_error_page' : 'redirect_error')
    return {
      ok: 'unarmed',
      title: 'UNARMED — the spine client\u2019s redirect row is not live yet (' + code + ').',
      detail: 'Google Cloud Console \u2192 APIs & Services \u2192 Credentials \u2192 the client ' + clientId + ' \u2192 confirm its edit page reads "Chrome extension" \u2192 set Item ID, letter-exact, to this extension\u2019s own ID (shown on the Self-check card) \u2192 Save. Console changes can take Google five minutes to a few hours to take effect. Until then Connect rides today\u2019s one-click path unchanged.',
      blobCode: String(code).slice(0, 80),
      raw: (finalUrl + (bodySniff ? ' \u00b7 body: ' + bodySniff.replace(/\s+/g, ' ').slice(0, 120) : '')).slice(0, 240),
    }
  }
  // The ARMED terminus (the sign-in page — its body carried no error words).
  if (isGoogleSignInTerminus(finalUrl)) {
    return {
      ok: 'armed',
      title: 'ARMED — Google accepts the spine client and this extension\u2019s redirect.',
      detail: 'The persistent sign-in is available: press Connect and one last window mints the refresh token — after that UCrypt reconnects by itself, even after a browser restart. (The Console Item-ID row is live: Item ID must equal this extension\u2019s own ID.)',
      blobCode: '',
      raw: finalUrl.slice(0, 240),
    }
  }
  // R179 — the honest default for a 200 answer on Google's own domain with
  // NO error markers anywhere: Google served the consent / sign-in UI (at
  // the auth URL — the modern shape). The pair is registered: ARMED.
  let host = ''
  try { host = String(new URL(finalUrl).hostname || '').toLowerCase() } catch { host = '' }
  if (host === 'accounts.google.com' || host.endsWith('.google.com')) {
    return {
      ok: 'armed',
      title: 'ARMED — Google accepts the spine client and this extension\u2019s redirect.',
      detail: 'The persistent sign-in is available: press Connect and one last window mints the refresh token — after that UCrypt reconnects by itself, even after a browser restart. (The Console Item-ID row is live: Item ID must equal this extension\u2019s own ID.)',
      blobCode: '',
      raw: finalUrl.slice(0, 240),
    }
  }
  return {
    ok: 'untyped',
    title: 'Google answered with an unexpected shape — the raw answer rides for the receipt.',
    detail: '',
    blobCode: '',
    raw: finalUrl.slice(0, 240),
  }
}

/**
 * THE SPINE CUSTODY SANITIZER — the refresh token's custody hygiene (PURE).
 * The token rides the sealed envelope only; this helper is the ONE seat the
 * workers/cards/rings use when they must SPEAK ABOUT the custody without
 * ever speaking its value.
 * @param {{clientId?: string, refreshToken?: string, webToken?: object}} config
 * @returns {{ spineArmed: boolean, hasRefreshCustody: boolean, clientTail: string }}
 */
export function spineCustodyFacts(config) {
  const cfg = config && typeof config === 'object' ? config : {}
  const clientId = String(cfg.clientId || '').trim()
  const rt = String(cfg.refreshToken || '').trim()
  const webToken = cfg.webToken && typeof cfg.webToken === 'object' ? cfg.webToken : null
  return {
    spineArmed: clientId === SPINE_CLIENT_ID,
    hasRefreshCustody: rt.length > 0,
    hasWebToken: !!(webToken && typeof webToken.token === 'string' && webToken.token.length > 0),
    clientTail: clientId ? '…' + clientId.slice(-12) : '',
  }
}

/**
 * THE LANE-AWARE RECONNECT CARD (the E-24 cure's copy machine) — PURE.
 * The expired/reconnect card names the LANE THAT ACTUALLY SERVED, or speaks
 * neutrally; and once the spine custody exists, the card reflects the new
 * truth: the reconnection is silent and automatic, and the card appears only
 * when even the refresh grant failed.
 *
 * R176 — R-176.2 THE HONEST EXPIRY: the card now routes through the
 * three-state custody verdict (authCustodyVerdict below) whenever custody
 * evidence rides. The word "expired" may ONLY mean: a banked expiresAt is
 * truly in the past. An empty bank says NO KEY; a refused renewal says MINT
 * REFUSED (with the typed reason). The six-minute lie — E-36's "expired"
 * for a token minted minutes earlier — is structurally unreachable through
 * this machine.
 *
 * @param {{servedLane?: 'C'|'U'|'S'|'', browserIsChrome?: boolean,
 *           hasRefreshCustody?: boolean, googleWords?: string,
 *           webToken?: {token?:string, exp?:number, at?:number},
 *           mintRefusedReason?: string, now?: number}} facts
 * @returns {string} the user-facing sentence (English canonical; the i18n
 *   layer carries the ×3 pinned equivalents — keys r171Reconnect*).
 */
export function fastReconnectCardWords(facts = null) {
  const f = facts && typeof facts === 'object' ? facts : {}
  // R-176.2 — THE THREE-STATE VERDICT FIRST: when custody evidence rides
  // (a webToken shape or an explicit refusal reason), the honest expiry
  // machine speaks — the lane-aware prose below stays for the callers that
  // predate custody evidence (the refresh custody's own words, R171).
  const hasCustodyEvidence = !!(f.webToken && typeof f.webToken === 'object') ||
    (typeof f.mintRefusedReason === 'string' && f.mintRefusedReason.trim() !== '')
  if (hasCustodyEvidence && !(f.hasRefreshCustody && f.webToken == null)) {
    const v = authCustodyVerdict(f)
    if (v && v.words) return v.words
  }
  const spine = !!f.hasRefreshCustody
  const lane = String(f.servedLane || '').trim()
  const google = String(f.googleWords || '').trim()
  const suffix = google ? ' (Google\u2019s answer: ' + google.slice(0, 140) + ')' : ''
  if (spine) {
    // THE SPINE TRUTH: the automatic reconnection ran and was refused —
    // this card is the last resort, and it says so. R-176.2: this is the
    // MINT REFUSED state's words (never the word "expired") — the refusal
    // reason rides when Google named one.
    return 'Your saved Google sign-in could not be refreshed automatically — even the automatic reconnection was refused' + suffix + '. Press Connect to sign in once more (one last window); UCrypt saves the connection and reconnects by itself afterwards.'
  }
  if (lane === 'C') {
    return 'Your browser\u2019s one-click sign-in expired. Press Connect — one click signs you back in. Your own key (the guided rung) always works too.'
  }
  // Lane U or unknown: speak NEUTRALLY — the machine may have ridden the
  // window lane in Helium/Brave, where "Chrome's one-click" is a lie.
  return 'Your one-click sign-in expired. Press Connect — one click signs you back in. Your own key (the guided rung) always works too.'
}

// ══════════════════════════════════════════════════════════════════════
// R176 — R-176.2 THE HONEST EXPIRY (the three-state custody verdict) and
// R-176.1b THE BURN CLOCK (the banked key's true remaining life). The auth
// family speaks exactly three states, each with its own words and its own
// evidence. "Expired" reached by any other path is a banned word-shape.
// PURE — the battery drives every branch on plain shapes.
// ══════════════════════════════════════════════════════════════════════

/** The burn clock (R-176.1b) — the banked access custody's true remaining
 * life, derived from the banked exp. PURE, total, never throws.
 * @param {{token?:string, exp?:number, at?:number}|null|undefined} webToken
 * @param {number} [now] the evaluation instant (defaults Date.now())
 * @returns {{ banked: boolean, alive: boolean, minutesLeft: number|null,
 *             expiredAt: number|null }} alive = a banked token whose exp is
 *   still in the future (beyond the 30 s service margin the lanes use);
 *   minutesLeft = floor((exp − now)/60000) when alive, else null.
 */
export function bankBurnClock(webToken, now = Date.now()) {
  const w = webToken && typeof webToken === 'object' ? webToken : null
  const banked = !!(w && typeof w.token === 'string' && w.token.length > 0)
  const exp = banked && Number.isFinite(Number(w.exp)) ? Number(w.exp) : null
  if (!banked) return { banked: false, alive: false, minutesLeft: null, expiredAt: null }
  if (exp === null) return { banked: true, alive: false, minutesLeft: null, expiredAt: null }
  const alive = exp > now + 30000
  return {
    banked: true,
    alive,
    minutesLeft: alive ? Math.max(0, Math.floor((exp - now) / 60000)) : null,
    expiredAt: alive ? null : exp,
  }
}

/**
 * THE HONEST EXPIRY VERDICT (R-176.2) — the auth family's three states.
 *   NO_KEY_BANKED  — no token is banked (the bank is empty — never "expired")
 *   EXPIRED_AT     — a banked exp is TRULY in the past, naming the hour it died
 *   MINT_REFUSED   — the renewal attempt was refused, with the typed reason
 * An ALIVE banked token can reach NONE of the three states through a lane
 * refusal — an alive token is USED (R-176.1c), so a refusal while the clock
 * runs is the MINT REFUSED state with the alive-key fact riding beside it.
 *
 * R179 — THE CUSTODY-AWARE WORDS: when a sealed REFRESH GRANT exists, a
 * spent bank is NOT a dead connection — the machine renews it silently on
 * the next sync leg (and the R179 custody clock renews it before it even
 * dies). The EXPIRED_AT words say so instead of panicking the owner into a
 * re-sign-in the machine was about to do for them.
 *
 * @param {{webToken?: {token?:string, exp?:number, at?:number}|null,
 *           mintRefusedReason?: string, hasRefreshCustody?: boolean, now?: number}} facts
 * @returns {{ state: 'NO_KEY_BANKED'|'EXPIRED_AT'|'MINT_REFUSED',
 *             words: string, minutesLeft: number|null, expiredAt: number|null }}
 */
export function authCustodyVerdict(facts = null) {
  const f = facts && typeof facts === 'object' ? facts : {}
  const now = Number.isFinite(Number(f.now)) ? Number(f.now) : Date.now()
  const clock = bankBurnClock(f.webToken, now)
  const refusal = String(f.mintRefusedReason || '').trim()
  const hasGrant = !!f.hasRefreshCustody
  // 1. THE ALIVE KEY: a banked token with life left — no refusal may be
  //    named "expired". If a refusal still arrived, the machine names the
  //    refusal and SPEAKS THE CLOCK (the six-minute lie's cure: the words
  //    carry the alive-key fact so the surface can never contradict it).
  if (clock.alive) {
    if (refusal) {
      return {
        state: 'MINT_REFUSED',
        words: 'The renewal was refused while your banked key is still alive (' + clock.minutesLeft + ' min left) — Google said: ' + refusal.slice(0, 140) + '. Press Connect to sign in again; nothing was lost.',
        minutesLeft: clock.minutesLeft,
        expiredAt: null,
      }
    }
    // The alive key's own state words (the ✓ custody — the burn clock truth).
    return {
      state: 'MINT_REFUSED',
      words: 'Your banked key is alive — about ' + clock.minutesLeft + ' min of burn left. One click renews it when the time comes.',
      minutesLeft: clock.minutesLeft,
      expiredAt: null,
    }
  }
  // 2. THE REFUSED MINT: a renewal was attempted and refused (the typed
  //    reason rides) — NEVER the word "expired" unless a real expiry rode.
  if (refusal && !clock.banked) {
    return {
      state: 'MINT_REFUSED',
      words: 'The sign-in renewal was refused — Google said: ' + refusal.slice(0, 140) + '. No key is banked on this device yet — press Connect; one click signs you in.',
      minutesLeft: null,
      expiredAt: null,
    }
  }
  if (refusal) {
    return {
      state: 'MINT_REFUSED',
      words: 'The sign-in renewal was refused — Google said: ' + refusal.slice(0, 140) + '. Press Connect to sign in once more; your own key (the guided rung) always works too.',
      minutesLeft: null,
      expiredAt: clock.expiredAt,
    }
  }
  // 3. THE TRUE EXPIRY: a banked token whose exp is REALLY in the past —
  //    the ONLY lawful path to the word "expired", naming the hour it died.
  //    R179 — with a sealed refresh grant the words name the SILENT renewal
  //    (the next sync leg mints fresh; the custody clock renews it first) —
  //    "press Connect" stays, but as the immediate-renewal option it is,
  //    never as the only cure.
  if (clock.banked && clock.expiredAt !== null) {
    const diedAt = new Date(clock.expiredAt)
    const hhmm = diedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    return {
      state: 'EXPIRED_AT',
      words: hasGrant
        ? 'Your one-click sign-in\u2019s key expired at ' + hhmm + ' — the saved grant renews it silently on the next sync (or press Connect to renew right now).'
        : 'Your one-click sign-in\u2019s key expired at ' + hhmm + ' — press Connect; one click signs you back in. Your own key (the guided rung) always works too.',
      minutesLeft: null,
      expiredAt: clock.expiredAt,
    }
  }
  // 4. NO KEY BANKED: the bank is empty — the honest first-run words
  //    (never "expired"; nothing ever died because nothing was ever banked).
  return {
    state: 'NO_KEY_BANKED',
    words: 'No key is banked yet — press Connect; one click signs you in. Your own key (the guided rung) always works too.',
    minutesLeft: null,
    expiredAt: null,
  }
}

/** The spine connect's promise copy (the one-last-window sentence). */
export const SPINE_CONNECT_PROMISE = 'One last window — after this, UCrypt reconnects by itself, even after a restart.'
