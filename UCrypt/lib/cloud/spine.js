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

/**
 * THE SPINE PROBE — ZERO WINDOW, no user data, no red page ever.
 *
 * The service worker fetches the spine client's authorization URL; Google
 * decides where the BROWSER would land and the fetch follows that redirect:
 *   ARMED   → the redirect lands on Google's sign-in page (the pair client+
 *             redirect is registered — the Console Item-ID row is live);
 *   UNARMED → the redirect lands on Google's error page with the authError
 *             blob (decoded: the exact code, typically redirect_uri_mismatch);
 *   offline → the network refused;
 *   untyped → Google answered with an unexpected shape (the raw rides).
 *
 * @param {{clientId?: string, redirect: string, fetchImpl?: typeof fetch}} facts
 * @returns {Promise<{ok: 'armed'|'unarmed'|'offline'|'bad-input'|'untyped',
 *                     title: string, detail: string, blobCode: string, raw: string}>}
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
  // The ARMED terminus first (the sign-in page — never an error shape).
  if (isGoogleSignInTerminus(finalUrl)) {
    return {
      ok: 'armed',
      title: 'ARMED — Google accepts the spine client and this extension\u2019s redirect.',
      detail: 'The persistent sign-in is available: press Connect and one last window mints the refresh token — after that UCrypt reconnects by itself, even after a browser restart. (The Console Item-ID row is live: Item ID must equal this extension\u2019s own ID.)',
      blobCode: '',
      raw: finalUrl.slice(0, 240),
    }
  }
  // The UNARMED terminus — decode the blob, never guess.
  const blob = decodeAuthErrorBlob(finalUrl)
  const errParam = (() => { try { return new URL(finalUrl).searchParams.get('error') || '' } catch { return '' } })()
  if (blob.ok || errParam || /\/oauth\/error|authError|error/i.test(finalUrl)) {
    const code = blob.code || errParam || 'redirect_error'
    return {
      ok: 'unarmed',
      title: 'UNARMED — the spine client\u2019s redirect row is not live yet (' + code + ').',
      detail: 'Google Cloud Console → APIs & Services → Credentials → the client ' + clientId + ' → confirm its edit page reads "Chrome extension" → set Item ID, letter-exact, to this extension\u2019s own ID (shown on the Self-check card) → Save. Console changes can take Google five minutes to a few hours to take effect. Until then Connect rides today\u2019s one-click path unchanged.',
      blobCode: String(code).slice(0, 80),
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
  if (!banked) return { banked: false, alive: false, persistentSession: false, minutesLeft: null, expiredAt: null }
  const explicitlyRevoked = w && w.revokedByProvider === true
  if (explicitlyRevoked) {
    return {
      banked: true,
      alive: false,
      persistentSession: false,
      minutesLeft: null,
      expiredAt: exp || now,
    }
  }
  // UCRYPT-22: Banked sign-in stays permanently alive across window closes and
  // browser restarts unless Google explicitly revokes the grant or the user
  // disconnects. When exp is in the past, UCrypt silently renews or continues
  // using the banked session without ever expiring the user's connection locally.
  const persistent = w.persistentSession !== false
  const futureExp = exp !== null && exp > now + 30000
  const alive = persistent || futureExp
  return {
    banked: true,
    alive,
    persistentSession: persistent,
    minutesLeft: futureExp ? Math.max(1, Math.floor((exp - now) / 60000)) : (alive ? 60 : null),
    expiredAt: alive ? null : exp,
  }
}

/**
 * THE HONEST EXPIRY VERDICT (R-176.2 / UCRYPT-22) — the auth family's states.
 *   NO_KEY_BANKED  — no token is banked (the bank is empty — never "expired")
 *   EXPIRED_AT     — a banked token was explicitly revoked by Google
 *   MINT_REFUSED   — a renewal attempt was refused, or the banked key is permanently alive
 *
 * @param {{webToken?: {token?:string, exp?:number, at?:number, persistentSession?:boolean, revokedByProvider?:boolean}|null,
 *           mintRefusedReason?: string, now?: number}} facts
 * @returns {{ state: 'NO_KEY_BANKED'|'EXPIRED_AT'|'MINT_REFUSED',
 *             words: string, minutesLeft: number|null, expiredAt: number|null }}
 */
export function authCustodyVerdict(facts = null) {
  const f = facts && typeof facts === 'object' ? facts : {}
  const now = Number.isFinite(Number(f.now)) ? Number(f.now) : Date.now()
  const wt = f.webToken || (f.config && typeof f.config === 'object' ? f.config.webToken : null)
  const clock = bankBurnClock(wt, now)
  const refusal = String(f.mintRefusedReason || '').trim()
  if (clock.alive) {
    if (refusal) {
      return {
        state: 'MINT_REFUSED',
        alive: true,
        words: 'The renewal was refused while your sign-in is still active — Google said: ' + refusal.slice(0, 140) + '. Press Connect to sign in again; nothing was lost.',
        minutesLeft: clock.minutesLeft,
        expiredAt: null,
      }
    }
    return {
      state: 'MINT_REFUSED',
      alive: true,
      words: 'Signed in permanently — your Google sign-in is active and persistent. UCrypt keeps you signed in across window restarts and renews silently in the background unless you disconnect or Google revokes access.',
      minutesLeft: clock.minutesLeft,
      expiredAt: null,
    }
  }
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
  if (clock.banked && clock.expiredAt !== null) {
    const diedAt = new Date(clock.expiredAt)
    const hhmm = diedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    return {
      state: 'EXPIRED_AT',
      words: 'Your Google sign-in was revoked by Google at ' + hhmm + ' — press Connect; one click signs you back in.',
      minutesLeft: null,
      expiredAt: clock.expiredAt,
    }
  }
  return {
    state: 'NO_KEY_BANKED',
    words: 'No key is banked yet — press Connect; one click signs you in. Your own key (the guided rung) always works too.',
    minutesLeft: null,
    expiredAt: null,
  }
}

/** The spine connect's promise copy (the one-last-window sentence). */
export const SPINE_CONNECT_PROMISE = 'One last window — after this, UCrypt reconnects by itself, even after a restart.'
