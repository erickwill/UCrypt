/**
 * ════════════════════════════════════════════════════════════════════════
 * R166 ARC A — THE SECOND MACHINERY (the web-auth fallback rung).
 *
 * The field spoke twice (E-11 the freeze, E-12 the verdict): on the owner's
 * machine chrome.identity.getAuthToken's callback NEVER fires — both the
 * non-interactive probe and the interactive native picker abandoned at the
 * 20 s bound (the R165 verdict ladder proved it honestly — H-16 stays dead).
 * The SAME machine's guided rung signs in fine — proof that
 * chrome.identity.launchWebAuthFlow (the machinery the guided rung and the
 * dropbox fast rung ride) is ALIVE where the native machinery is not.
 *
 * The cure: the fast rung learns the SECOND machinery — the SAME shared
 * client (the manifest's pinned ID), the SAME scope pin (drive.appdata),
 * the SAME derived redirect — via the implicit flow (response_type=token),
 * the exact protocol getAuthToken itself performs, minus the wedged native
 * layer. "One click, nothing to create, nothing to paste" stays true: the
 * consent window is Google's own, pre-warned by the R165 consent note.
 *
 * The verdicts (the H-16 alphabet — every shape a NAME):
 *   ok              → { ok: true, token, expiresIn, via: 'web-auth-flow' }
 *   WEB_AUTH_CANCELED  the user closed the window / refused the consent (CONSENT)
 *   WEB_AUTH_TIMEOUT   the window never returned within the bound (TIMEOUT)
 *   LAST_ERROR         the launcher or Google refused — raw rides VERBATIM
 *
 * The token-custody law: the implicit flow has NO refresh token — the
 * access token (~1 h) rides back to the caller, which stores it ONLY as
 * webToken {token, exp, at} inside the transport's SEALED envelope. Nothing
 * rides the ring rows or the receipt (the G194 strip covers the shape).
 *
 * ENGINE-ONLY: no DOM, no chrome.i18n. The chrome seam, the launcher, the
 * clock, and the random source are injectable — the battery drives every
 * failure shape without a browser.
 * ════════════════════════════════════════════════════════════════════════
 */

import { PENDING_VERDICTS } from './pending.js'
import { launchOAuthFlow } from './transports/gdrive-oauth-help.js'

/** The fallback window's bound: a HUMAN consent window — longer than the
 * identity callback's 20 s, still bounded (no await is allowed to be silent).
 * R168 — THE HUMAN-LEG LAW: 300 s (five minutes). The field spoke (the
 * owner's R168 evidence): a human must be able to READ Google's pages
 * (including Google's own error page), decide, even fix the Console and
 * come back — 120 s abandoned the human mid-read. The window is the
 * user's: the bound exists so no await is silent, never to race a person. */
export const WEB_AUTH_TIMEOUT_MS = 300000

/** The fallback's scope pin — byte-equal to the manifest's ONLY lawful
 * fast-rung scope (the battery asserts the equality with the ladder's pin). */
export const FAST_WEB_SCOPE = 'https://www.googleapis.com/auth/drive.appdata'

/** The typed verdict kinds this module adds (additive — the R165 alphabet grows).
 * R171 — UNMATCHED joins: the window OPENED and settled without completing
 * (the user closed it — most often after reading Google's own red
 * "Access blocked — Error 400: redirect_uri_mismatch" page). The shape has
 * its OWN verdict so no caller can sell it as a probe failure, a cancel,
 * or a CODEBASE bug.
 * R169 O-3 — THE VERDICT-SCOPE KINDS, NAMED: the E-14 field defect was two
 * realities sharing one wrong message. The two kinds are now FIRST-CLASS
 * names (the battery pins the mapping):
 *   WINDOW_OPENED_THEN_FAILED → 'auth-window-unmatched' (the R171 window-
 *     truth card renders — never the could-not-open copy, never CODEBASE)
 *   WINDOW_UNAVAILABLE        → 'launchWebAuthFlow-unavailable' (the
 *     pre-window probe refusal — the could-not-open family, honestly). */
export const VERDICT_SCOPE_KINDS = Object.freeze({
  WINDOW_OPENED_THEN_FAILED: 'auth-window-unmatched',
  WINDOW_UNAVAILABLE: 'launchWebAuthFlow-unavailable',
})
export const WEB_AUTH_VERDICTS = Object.freeze({
  CANCELED: 'web-auth-canceled',
  TIMEOUT: 'web-auth-timeout',
  UNMATCHED: 'web-auth-unmatched',
})

function b64url(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The CSRF state nonce (12 random bytes, url-safe). Injectable for the battery. */
export function webAuthState(randomImpl = null) {
  const bytes = randomImpl ? randomImpl(12) : crypto.getRandomValues(new Uint8Array(12))
  return b64url(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
}

/**
 * Build the authorization URL — PURE, exported for the battery.
 * The implicit flow (response_type=token): the access token rides the
 * redirect fragment; no exchange, no secret (the Chrome-Extension client
 * type has none — R-164.4). prompt=select_account: the user's own choice,
 * one click, even when several accounts live in the browser.
 * @param {{clientId: string, scope?: string, redirect: string, state: string}} facts
 * @returns {string} the authorization URL
 */
export function gdriveWebAuthUrl(facts) {
  const clientId = String((facts && facts.clientId) || '').trim()
  const redirect = String((facts && facts.redirect) || '').trim()
  const state = String((facts && facts.state) || '').trim()
  if (!clientId) throw Object.assign(new Error('the shared client id is absent — the fallback has nothing to sign in with'), { kind: 'web-client-id-absent' })
  if (!redirect) throw Object.assign(new Error('the derived redirect is absent — chrome.identity.getRedirectURL() is the only lawful redirect, never hand-built'), { kind: 'web-redirect-absent' })
  if (!state) throw Object.assign(new Error('the CSRF state nonce is absent — the fallback never mints without it'), { kind: 'web-state-absent' })
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth')
  u.searchParams.set('client_id', clientId)
  u.searchParams.set('response_type', 'token')
  u.searchParams.set('scope', String((facts && facts.scope) || FAST_WEB_SCOPE))
  u.searchParams.set('redirect_uri', redirect)
  u.searchParams.set('state', state)
  u.searchParams.set('prompt', 'select_account')
  return u.toString()
}

/**
 * Parse the FINAL redirect URL — PURE, exported for the battery.
 * The state nonce MUST match ours (the CSRF law): a redirect without our
 * state is a window that closed early — never a mint.
 * @param {string} url  the final URL launchWebAuthFlow resolved with
 * @param {string} state  the nonce we sent
 * @returns {{ok: true, token: string, expiresIn: number}
 *           | {ok: false, verdict: string, kind: string, raw: string}}
 */
export function parseWebAuthRedirect(url, state) {
  const want = String(state || '')
  let u = null
  try { u = new URL(String(url || '')) } catch { u = null }
  if (!u) {
    return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw: 'the web-auth window closed without completing the sign-in (no redirect came back)' }
  }
  const frag = u.hash && u.hash.length > 1 ? new URLSearchParams(u.hash.slice(1)) : new URLSearchParams()
  const st = u.searchParams.get('state') || frag.get('state') || ''
  const err = u.searchParams.get('error') || frag.get('error') || ''
  if (st !== want) {
    // R167 — THE TYPED ERROR-PAGE LANE (the E-13 field cure, part 2): when
    // the window resolved on GOOGLE'S OWN PAGE (accounts.google.com, none
    // of our state), the flow never redirected — Google showed its own
    // error page INSIDE the authorization window (the redirect_uri_mismatch
    // class the owner's field verdict captured). The URL rides VERBATIM as
    // the raw — its base64 blobs (the error page's protobuf request
    // details) are decoded by the classifier's decoder, so the verdict
    // NAMES the error and routes to the domain that owns the fix. Never a
    // mint, never a bare window-closed shrug.
    const host = String(u.hostname || '').toLowerCase()
    const isGooglePage = host === 'accounts.google.com' || host.endsWith('.google.com')
    if (isGooglePage) {
      return {
        ok: false,
        verdict: PENDING_VERDICTS.LAST_ERROR,
        kind: 'google-error-page',
        raw: `Google showed its own error page in the authorization window: ${String(url).slice(0, 240)}`,
      }
    }
    // our state never came back — the flow did not complete; never mint
    return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw: 'the web-auth window closed without completing the sign-in (the redirect carried none of our state)' }
  }
  if (err) {
    const raw = `Google refused the sign-in: ${err}${frag.get('error_description') ? ` (${frag.get('error_description')})` : ''}`
    return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: err === 'access_denied' ? 'consent-denied' : 'web-refused', raw }
  }
  const token = frag.get('access_token') || u.searchParams.get('access_token') || ''
  if (!token) {
    return { ok: false, verdict: PENDING_VERDICTS.NO_TOKEN, kind: 'empty-token', raw: 'the redirect carried our state but no access token — nothing was minted' }
  }
  const expiresIn = Number(frag.get('expires_in')) || 3600
  return { ok: true, token: String(token), expiresIn: Math.max(60, Math.min(86400, expiresIn)) }
}

/**
 * THE BOUNDED WEB-AUTH FALLBACK MINT (the second machinery, product-grade).
 *
 * @param {{chromeLike?: object, clientId: string, scope?: string,
 *          timeoutMs?: number, launchImpl?: (url: string) => Promise<string>,
 *          stateImpl?: () => string,
 *          now?: () => number, setTimer?: Function, clearTimer?: Function}} env
 * @returns {Promise<{ok: true, token: string, expiresIn: number, via: 'web-auth-flow', state: string}
 *                    | {ok: false, verdict: string, kind: string, raw: string}>}
 *   NEVER throws for the bounded shapes — the caller renders the verdict.
 */
export async function webAuthFastToken(env = {}) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  const clientId = String((env && env.clientId) || '').trim()
  const timeoutMs = Math.max(1, Number((env && env.timeoutMs) ?? WEB_AUTH_TIMEOUT_MS))
  const now = (env && env.now) || (() => Date.now())
  const setTimer = (env && env.setTimer) || ((f, ms) => setTimeout(f, ms))
  const clearTimer = (env && env.clearTimer) || ((t) => { try { clearTimeout(t) } catch { /* the clock never throws */ } })
  const t0 = now()

  // F-2 — the URL facts resolve FIRST (typed refusals before any window):
  const redirect = (chromeLike && chromeLike.identity && typeof chromeLike.identity.getRedirectURL === 'function')
    ? String(chromeLike.identity.getRedirectURL() || '')
    : ''
  const state = (env && env.stateImpl) ? env.stateImpl() : webAuthState()
  let url = ''
  try {
    url = gdriveWebAuthUrl({ clientId, scope: (env && env.scope) || FAST_WEB_SCOPE, redirect, state })
  } catch (e) {
    return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: String((e && e.kind) || 'web-url-failed'), raw: String((e && e.message) || e) }
  }

  // F-3/F-4 — the REAL window, raced against the bound; the flow's own
  // settle always wins (the honest-pending law, Arc A of R165).
  const launch = (env && env.launchImpl) || ((u) => launchOAuthFlow(u))
  let settled = false
  let clearTimeoutHandle = null
  let settleOuter = null
  const finish = (r) => {
    if (settled) return
    settled = true
    if (clearTimeoutHandle) clearTimer(clearTimeoutHandle)
    if (settleOuter) settleOuter(r)
    return r
  }
  const timeoutPromise = new Promise((resolve) => {
    settleOuter = resolve
    clearTimeoutHandle = setTimer(() => {
      settleOuter({
        ok: false,
        verdict: WEB_AUTH_VERDICTS.TIMEOUT,
        kind: 'web-auth-timeout',
        raw: `chrome.identity.launchWebAuthFlow never returned within ${timeoutMs} ms — the fallback window was abandoned with no state written`,
      })
      settled = true
      settleOuter = null
    }, timeoutMs)
  })
  const work = (async () => {
    let finalUrl = ''
    try {
      finalUrl = await launch(url)
    } catch (e) {
      const raw = String((e && e.message) || e)
      // launchOAuthFlow's typed window tags map to the verdict alphabet:
      // R171 — the settled-unmatched shape rides FIRST: the window opened
      // and was closed before completing. The verdict rests on the ENGINE'S
      // OWN WORDS ("The user did not approve access.") — the tag OR the
      // bare Chrome message both classify, so a launcher that forgets to
      // tag can never sell this shape as a probe refusal or CODEBASE.
      if (/auth_window_settled_unmatched/i.test(raw) || /did not approve/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.UNMATCHED, kind: 'auth-window-unmatched', raw }
      if (/auth_window_closed/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw }
      if (/auth_window_timeout/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.TIMEOUT, kind: 'web-auth-timeout', raw }
      return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'web-launch-refused', raw }
    }
    return parseWebAuthRedirect(finalUrl, state)
  })()
  const guard = work.then(
    (r) => { finish(r); return r },
    (e) => {
      const r = { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'web-flow-threw', raw: String((e && e.message) || e) }
      finish(r)
      return r
    },
  )
  const result = await Promise.race([guard, timeoutPromise])
  if (result && result.ok) {
    return { ok: true, token: result.token, expiresIn: result.expiresIn, via: 'web-auth-flow', state, elapsedMs: now() - t0 }
  }
  return { ok: false, verdict: result.verdict, kind: result.kind, raw: result.raw, elapsedMs: now() - t0 }
}

/**
 * The webToken custody shape (the sealed-envelope citizen): the access
 * token with its own expiry (a 60 s safety margin so a token at the edge
 * of its life is never trusted on a sync leg).
 * @param {{ok: true, token: string, expiresIn: number}} mint
 * @param {{now?: () => number}} [opts]
 */
export function webTokenFromMint(mint, opts = {}) {
  const now = (opts && opts.now) || (() => Date.now())
  return { token: String(mint.token), exp: now() + (Number(mint.expiresIn) - 60) * 1000, at: now(), via: 'web-auth-flow' }
}

/** The freshness check (pure): a webToken is rideable only when it has more
 * than the 30 s margin of life left. */
export function webTokenFresh(webToken, now = Date.now()) {
  const w = webToken || {}
  return !!(w.token && Number(w.exp) > now + 30000)
}

// ══════════════════════════════════════════════════════════════════════════
// R174b — THE CODE LANE (the corrected CSA order's PRIMARY machinery).
//
// The corrected order names the ONLY lawful sign-in design:
//   chrome.identity.launchWebAuthFlow + a Google "Web application" client,
//   response_type=code with PKCE (S256), access_type=offline so Drive sync
//   survives the browser restart, the refresh token stored ONLY in the
//   existing encrypted store (the sealed ucrypt:transport envelope — the
//   same custody the guided rung's grant rides since R85). The native
//   getAuthToken machinery is RETIRED (Brave/Helium and every de-Googled
//   Chromium have no browser Google session for it — the portability law).
//
// The exchange rides PUBLIC-CLIENT rules: client_id + code + code_verifier,
// NEVER a client_secret (the corrected order forbids one in the package;
// the pack gate proves it statically). Google's typed exchange errors name
// the defect exactly (the same alphabet the R174 self-check probes):
//   deleted_client           → the client was deleted in the Console
//   invalid_client           → Google does not accept this client unauthenticated
//   unauthorized_client      → the client's type cannot serve the flow
//   redirect_uri_mismatch    → the redirect is not registered on the client
//   invalid_grant            → the code expired/was consumed
//
// The window shapes reuse the token lane's verdicts byte-true (CANCELED,
// TIMEOUT, UNMATCHED, LAST_ERROR) so every caller's typed card keeps working.
// ENGINE-ONLY, injectable seams — the battery drives every branch.
// ══════════════════════════════════════════════════════════════════════════

/** The PKCE pair for the code lane (PURE, exported for the battery): a 32-byte
 * url-safe verifier and its S256 challenge. */
export async function pkcePairWebAuth(randomImpl = null) {
  const bytes = randomImpl ? randomImpl(32) : crypto.getRandomValues(new Uint8Array(32))
  const verifier = b64url(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return { verifier, challenge: b64url(digest) }
}

/**
 * Build the CODE-lane authorization URL — PURE, exported for the battery.
 * URLSearchParams only (never hand-concatenation — the double-encode law).
 * access_type=offline + prompt='consent select_account': the refresh token
 * arrives on the FIRST grant and the account choice stays the user's.
 * R171 (additive): `prompt` is an injectable fact — the spine connect passes
 * its own prompt per the round contract; the default stays BYTE-TRUE
 * ('consent select_account') for every existing caller.
 * @param {{clientId: string, scope?: string, redirect: string, state: string, challenge: string, prompt?: string}} facts
 * @returns {string} the authorization URL
 */
export function gdriveWebAuthCodeUrl(facts) {
  const clientId = String((facts && facts.clientId) || '').trim()
  const redirect = String((facts && facts.redirect) || '').trim()
  const state = String((facts && facts.state) || '').trim()
  const challenge = String((facts && facts.challenge) || '').trim()
  if (!clientId) throw Object.assign(new Error('the shared client id is absent — the code lane has nothing to sign in with'), { kind: 'web-client-id-absent' })
  if (!redirect) throw Object.assign(new Error('the derived redirect is absent — chrome.identity.getRedirectURL() is the only lawful redirect, never hand-built'), { kind: 'web-redirect-absent' })
  if (!state) throw Object.assign(new Error('the CSRF state nonce is absent — the code lane never mints without it'), { kind: 'web-state-absent' })
  if (!challenge) throw Object.assign(new Error('the PKCE code_challenge is absent — the code lane never rides without S256'), { kind: 'web-challenge-absent' })
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth')
  u.searchParams.set('client_id', clientId)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('scope', String((facts && facts.scope) || FAST_WEB_SCOPE))
  u.searchParams.set('redirect_uri', redirect)
  u.searchParams.set('state', state)
  u.searchParams.set('access_type', 'offline')
  u.searchParams.set('prompt', String((facts && facts.prompt) || 'consent select_account'))
  u.searchParams.set('code_challenge', challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  return u.toString()
}

/**
 * Parse the CODE lane's FINAL redirect URL — PURE, exported for the battery.
 * THE STATE NONCE IS VERIFIED FIRST (before any other parameter is read —
 * the corrected order's explicit rule). For response_type=code Google
 * returns the code and the errors in the QUERY string; the fragment is
 * tolerated additively (never trusted ahead of the query).
 */
export function parseWebAuthCodeRedirect(url, state) {
  const want = String(state || '')
  let u = null
  try { u = new URL(String(url || '')) } catch { u = null }
  if (!u) {
    return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw: 'the authorization window closed without completing the sign-in (no redirect came back)' }
  }
  const frag = u.hash && u.hash.length > 1 ? new URLSearchParams(u.hash.slice(1)) : new URLSearchParams()
  // THE CSRF LAW — state first, nothing else is read before it matches:
  const st = u.searchParams.get('state') || frag.get('state') || ''
  if (st !== want) {
    const host = String(u.hostname || '').toLowerCase()
    const isGooglePage = host === 'accounts.google.com' || host.endsWith('.google.com')
    if (isGooglePage) {
      return {
        ok: false,
        verdict: PENDING_VERDICTS.LAST_ERROR,
        kind: 'google-error-page',
        raw: `Google showed its own error page in the authorization window: ${String(url).slice(0, 240)}`,
      }
    }
    return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw: 'the authorization window closed without completing the sign-in (the redirect carried none of our state)' }
  }
  const err = u.searchParams.get('error') || frag.get('error') || ''
  if (err) {
    const raw = `Google refused the sign-in: ${err}${(u.searchParams.get('error_description') || frag.get('error_description')) ? ` (${u.searchParams.get('error_description') || frag.get('error_description')})` : ''}`
    return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: err === 'access_denied' ? 'consent-denied' : 'web-refused', raw }
  }
  const code = u.searchParams.get('code') || frag.get('code') || ''
  if (!code) {
    return { ok: false, verdict: PENDING_VERDICTS.NO_TOKEN, kind: 'empty-code', raw: 'the redirect carried our state but no authorization code — nothing was exchanged' }
  }
  return { ok: true, code: String(code) }
}

/** The typed exchange-error alphabet → the machine kind. The description
 * rides so Google's OWN secret-rule words name the web-client class. */
export function classifyExchangeError(error, description = '') {
  const e = String(error || '').toLowerCase()
  const d = String(description || '')
  if (e === 'deleted_client') return 'client-deleted'
  if (e === 'invalid_client') return 'exchange-invalid-client'
  if (e === 'unauthorized_client') return 'exchange-wrong-type'
  if (e === 'redirect_uri_mismatch') return 'exchange-redirect-mismatch'
  if (e === 'invalid_grant') return 'exchange-invalid-grant'
  // R174b — GOOGLE'S CONFIDENTIAL-CLIENT RULE, machine-proven (the field
  // probe): a "web"-type client's token exchange REFUSES the secret-less
  // public-client form — `invalid_request: client_secret is missing` —
  // BEFORE the redirect is even validated. The kind names the rule so the
  // card can carry the honest trade-off (the implicit lane completes the
  // sign-in; the offline refresh would need a Console-side client change).
  if (e === 'invalid_request' && /client_secret/i.test(d)) return 'exchange-secret-required'
  if (e === 'invalid_request' && /redirect/i.test(d)) return 'exchange-redirect-mismatch'
  return 'exchange-refused'
}

/**
 * The token exchange — PUBLIC CLIENT, PKCE, NO SECRET (the corrected order:
 * "Exchange the code for tokens from the extension as a public client").
 * The body is URLSearchParams-built; a client_secret can never ride (the
 * body is assembled here and the pack gate proves the absence statically).
 * @param {{clientId: string, code: string, verifier: string, redirect: string,
 *           fetchImpl?: typeof fetch}} env
 * @returns {Promise<{ok: true, token: string, expiresIn: number, refreshToken: string}
 *                    | {ok: false, kind: string, raw: string}>}
 */
export async function exchangeWebAuthCode(env = {}) {
  const clientId = String((env && env.clientId) || '').trim()
  const code = String((env && env.code) || '').trim()
  const verifier = String((env && env.verifier) || '').trim()
  const redirect = String((env && env.redirect) || '').trim()
  const fetchImpl = (env && env.fetchImpl) || (typeof fetch === 'function' ? fetch : null)
  if (!clientId || !code || !verifier || !redirect || !fetchImpl) {
    return { ok: false, kind: 'exchange-bad-input', raw: 'the exchange is missing its inputs (client/code/verifier/redirect) — nothing was sent' }
  }
  const body = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: verifier,
    redirect_uri: redirect,
    grant_type: 'authorization_code',
  })
  let res = null
  let rawText = ''
  try {
    res = await fetchImpl('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    rawText = await res.text().catch(() => '')
  } catch (e) {
    return { ok: false, kind: 'exchange-offline', raw: String((e && e.message) || e).slice(0, 200) }
  }
  let j = null
  try { j = JSON.parse(rawText) } catch { j = null }
  if (!res.ok || !j || j.error || !j.access_token) {
    const errName = String((j && j.error) || `http-${res && res.status}`)
    const desc = String((j && j.error_description) || '')
    return {
      ok: false,
      kind: classifyExchangeError(errName, desc),
      raw: (`${errName}${desc ? ` — ${desc}` : ''}`).slice(0, 240),
    }
  }
  return {
    ok: true,
    token: String(j.access_token),
    expiresIn: Math.max(60, Math.min(86400, Number(j.expires_in) || 3600)),
    refreshToken: String(j.refresh_token || ''),
  }
}

/** The exchange-rule refusals the IMPLICIT lane can still survive (the
 * client-rule classes — the window/consent part of the flow already proved
 * itself when the code arrived). Every other failure keeps its typed card
 * (a cancellation NEVER falls back — the structured cancellation surfaces). */
export const EXCHANGE_FALLBACK_KINDS = Object.freeze([
  'client-deleted',
  'exchange-invalid-client',
  'exchange-wrong-type',
  'exchange-secret-required',
])

/**
 * THE BOUNDED CODE-LANE MINT (the corrected order's primary machinery).
 * launchWebAuthFlow({url, interactive:true}) → state-verified parse →
 * public-client PKCE exchange → { token, expiresIn, refreshToken }.
 *
 * @param {{chromeLike?: object, clientId: string, scope?: string,
 *          timeoutMs?: number, launchImpl?: (url: string) => Promise<string>,
 *          stateImpl?: () => string, randomImpl?: (n: number) => Uint8Array,
 *          fetchImpl?: typeof fetch,
 *          now?: () => number, setTimer?: Function, clearTimer?: Function}} env
 * @returns {Promise<{ok: true, token: string, expiresIn: number, refreshToken: string,
 *                     via: 'web-auth-code', state: string, elapsedMs: number}
 *                    | {ok: false, verdict: string, kind: string, raw: string, elapsedMs: number}>}
 *   NEVER throws for the bounded shapes — the caller renders the verdict.
 */
export async function webAuthCodeMint(env = {}) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  const clientId = String((env && env.clientId) || '').trim()
  const timeoutMs = Math.max(1, Number((env && env.timeoutMs) ?? WEB_AUTH_TIMEOUT_MS))
  const now = (env && env.now) || (() => Date.now())
  const setTimer = (env && env.setTimer) || ((f, ms) => setTimeout(f, ms))
  const clearTimer = (env && env.clearTimer) || ((t) => { try { clearTimeout(t) } catch { /* the clock never throws */ } })
  const t0 = now()

  // F-2 — the URL facts resolve FIRST (typed refusals before any window):
  const redirect = (chromeLike && chromeLike.identity && typeof chromeLike.identity.getRedirectURL === 'function')
    ? String(chromeLike.identity.getRedirectURL() || '')
    : ''
  const state = (env && env.stateImpl) ? env.stateImpl() : webAuthState()
  let pkce = null
  try { pkce = await pkcePairWebAuth(env && env.randomImpl) } catch { pkce = null }
  let url = ''
  try {
    if (!pkce) throw Object.assign(new Error('the PKCE pair could not be minted in this context'), { kind: 'web-challenge-absent' })
    url = gdriveWebAuthCodeUrl({ clientId, scope: (env && env.scope) || FAST_WEB_SCOPE, redirect, state, challenge: pkce.challenge, prompt: (env && env.prompt) || undefined })
  } catch (e) {
    return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: String((e && e.kind) || 'web-url-failed'), raw: String((e && e.message) || e), elapsedMs: now() - t0 }
  }

  // F-3/F-4 — the REAL window, raced against the bound (the honest-pending law):
  const launch = (env && env.launchImpl) || ((u) => launchOAuthFlow(u))
  let settled = false
  let clearTimeoutHandle = null
  let settleOuter = null
  const finish = (r) => {
    if (settled) return
    settled = true
    if (clearTimeoutHandle) clearTimer(clearTimeoutHandle)
    if (settleOuter) settleOuter(r)
    return r
  }
  const timeoutPromise = new Promise((resolve) => {
    settleOuter = resolve
    clearTimeoutHandle = setTimer(() => {
      settleOuter({
        ok: false,
        verdict: WEB_AUTH_VERDICTS.TIMEOUT,
        kind: 'web-auth-timeout',
        raw: `chrome.identity.launchWebAuthFlow never returned within ${timeoutMs} ms — the code-lane window was abandoned with no state written`,
      })
      settled = true
      settleOuter = null
    }, timeoutMs)
  })
  const work = (async () => {
    let finalUrl = ''
    try {
      finalUrl = await launch(url)
    } catch (e) {
      const raw = String((e && e.message) || e)
      if (/auth_window_settled_unmatched/i.test(raw) || /did not approve/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.UNMATCHED, kind: 'auth-window-unmatched', raw }
      if (/auth_window_closed/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.CANCELED, kind: 'window-closed', raw }
      if (/auth_window_timeout/i.test(raw)) return { ok: false, verdict: WEB_AUTH_VERDICTS.TIMEOUT, kind: 'web-auth-timeout', raw }
      return { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'web-launch-refused', raw }
    }
    const parsed = parseWebAuthCodeRedirect(finalUrl, state)
    if (!parsed.ok) return parsed
    return exchangeWebAuthCode({
      clientId, code: parsed.code, verifier: pkce.verifier, redirect,
      fetchImpl: env && env.fetchImpl,
    })
  })()
  const guard = work.then(
    (r) => { finish(r); return r },
    (e) => {
      const r = { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'web-flow-threw', raw: String((e && e.message) || e) }
      finish(r)
      return r
    },
  )
  const result = await Promise.race([guard, timeoutPromise])
  if (result && result.ok) {
    return {
      ok: true, token: result.token, expiresIn: result.expiresIn,
      refreshToken: String(result.refreshToken || ''),
      via: 'web-auth-code', state, elapsedMs: now() - t0,
    }
  }
  return { ok: false, verdict: result.verdict, kind: result.kind, raw: result.raw, elapsedMs: now() - t0 }
}
