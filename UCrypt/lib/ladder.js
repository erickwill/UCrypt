/**
 * UCrypt — THE SIGN-IN LADDER ENGINE (R119 — law 0.32, D-law S10).
 *
 * THE CEO-ARCHITECTED DESIGN, MADE CANONICAL: every cloud transport presents
 * its sign-in as a LADDER OF RUNGS, rendered in order:
 *
 *   1. FAST   — secret-free, one-click-class. Offered ONLY where feature
 *               detection confirms the platform supports it. Absence is
 *               graceful and honest — never a dead button, never a dead end.
 *   2. GUIDED — bring-your-own-client, with the in-product illustrated
 *               walkthrough (console deep links, copy-buttons for the exact
 *               strings, what-you-should-see per step).
 *   3. MANUAL — the bridge/PAT paths; demoted, NEVER removed. Helium-class
 *               browsers retain full functionality through the lower rungs.
 *
 * No rung is ever removed. Degradation between rungs is typed and visible.
 * The user chooses the rung that makes sense to him.
 *
 * WHAT LIVES HERE (the protocol engine — UI-free, injection-seamed):
 *   - the constants: the three PUBLIC client IDs (law 0.15: owner-supplied,
 *     owner-attributed, public by design — a shared web-client SECRET is
 *     forbidden by law 0.14; these IDs ship openly and carry no secret),
 *     the pinned scopes, the pinned endpoints;
 *   - the feature-detection map (detectRung): what each rung needs, checked
 *     against the real runtime — a failed probe routes to the guided rung
 *     with a TYPED card, never a dead button (§3.1);
 *   - the GitHub device flow (§3.2): POST /login/device/code → the 8-char
 *     user code → poll the token endpoint at the mandated interval → typed
 *     expiry / denial / throttle / cancel / slow-down states. Public-client
 *     by protocol — no secret ever exists to ship;
 *   - the Dropbox PKCE path (§3.3): verifier/challenge (S256), the auth URL,
 *     the exchange, the refresh — Dropbox's official public-client mode;
 *   - the Google fast rung (§3.1, R169 TWO-LANE LAW): the machine is TWO
 *     lanes now. LANE C — the Chrome silent accelerator: getAuthToken
 *     {interactive:false} + the manifest's Chrome-Extension client, Chrome
 *     only, zero-window, bounded, and it falls through the moment it is
 *     unavailable (the R169 CSA amendment typed openly against the R174b
 *     ban — the ban's motive is cross-browser and inside Chrome it does not
 *     apply; the CEO's reboot-persistence requirement rides this lane).
 *     LANE U — the universal lane (primary, EVERY Chromium):
 *     launchWebAuthFlow + the Web-application client (the code+PKCE lane is
 *     primary, the implicit lane is the canonical fallback). A FAST press
 *     tries Lane C silently first and falls through to Lane U; the card
 *     names WHICH lane served. Brave/Helium never see a dead press.
 *   - the token accessors (accessTokenFor): fast → Chrome-managed / the
 *     stored grant; guided/manual → the sealed grant + the refresh endpoint;
 *   - the rung RECORD: every flow records rung:"fast"|"guided"|"manual" into
 *     the evidence ring (law 0.28 — the ladder's flows record their rungs).
 *
 * THIS MODULE IS ENGINE-ONLY: no DOM, no chrome.i18n, no options.js. The
 * network seam is injectable (fetchImpl) so the battery drives the real
 * state machines against protocol-faithful fakes, and the live harness can
 * point at the real endpoints.
 */

// R174b — the getAuthToken retirement removed the last bounded identity call
// from this module (the token accessors ride the sealed webToken; the code
// lane's window races its own bound in webauth-fallback.js). R169 — THE
// TWO-LANE AMENDMENT: pending.js returns as the bound seat for the ONE
// lawful Lane C call (boundedIdentityCall, interactive:false only) — the
// silent accelerator the R169 command retained for Chrome, never the sign-in
// path's primary.
import { webTokenFresh, webTokenFromMint } from './webauth-fallback.js'
import { boundedIdentityCall } from './pending.js'
import { LANE_U_CLIENT_ID, LANE_C_CLIENT_ID, isDeadClientId, isLaneCClientId } from './cloud/oauth-clients.js'

/** The identity-callback bound (the verdict must land long before the UI's
 * 60 s pending verdict; the battery overrides it through env.identityTimeoutMs). */
export const IDENTITY_CALLBACK_TIMEOUT_MS = 20000

/** R169 — the Lane C SILENT bound: a healthy silent mint answers in ~1–3 s;
 * a wedged de-Googled build NEVER answers (the R165 field shape), so the
 * silent try yields to the Lane U window after 8 s — the press is never
 * hostage to a lane that cannot speak. Battery-seamed (env.laneCTimeoutMs). */
export const LANE_C_SILENT_TIMEOUT_MS = 8000

// ── R169 — THE TWO-LANE CLIENT REGISTRY (re-exported for the consumers) ────
// The one seat is lib/cloud/oauth-clients.js (a leaf — no cycles); these
// re-exports keep the ladder's public surface the single import for callers.
export { LANE_U_CLIENT_ID, LANE_C_CLIENT_ID, isDeadClientId, isLaneCClientId }

// The Lane C session memo (the wedge memory): once the silent lane refuses,
// times out, or errors on this browser, it is not retried until the next
// service-worker lifetime — a wedged lane never stalls the sync twice.
const _laneCMemo = { settled: false, ok: false, reason: '' }

/** Reset the Lane C session memo (the battery seam — never used at runtime). */
export function _resetLaneCMemoForTest() { _laneCMemo.settled = false; _laneCMemo.ok = false; _laneCMemo.reason = '' }

/**
 * R169 — THE LANE C SILENT MINT (the Chrome silent accelerator, O-2).
 * ONE bounded, non-interactive getAuthToken call against the manifest's
 * oauth2 client (the Chrome-Extension client — the ONLY client getAuthToken
 * may ride). ZERO windows, zero secrets. The verdicts are typed and the
 * session memo remembers a refusal so a wedged lane never stalls twice.
 *
 * @param {{chromeLike?: object, timeoutMs?: number, force?: boolean,
 *           now?: () => number, setTimer?: Function, clearTimer?: Function}} [env]
 * @returns {Promise<{ok: true, token: string, via: 'chrome-lane-c'}
 *                    | {ok: false, reason: string, raw: string}>}
 *   NEVER throws — the caller renders/rings the verdict.
 */
export async function mintGdriveLaneCToken(env = {}) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  // the manifest covenant: Lane C rides the manifest's Chrome-Extension
  // client letter-exact — a drifted manifest is a typed skip, never a guess
  const man = manifestOauth2()
  const manId = String((man && man.client_id) || '').trim()
  if (!manId || manId !== LANE_C_CLIENT_ID) {
    _laneCMemo.settled = true; _laneCMemo.ok = false; _laneCMemo.reason = 'manifest-drift'
    return { ok: false, reason: 'lane-c-manifest-drift', raw: 'the manifest oauth2 client is not the Lane C client — the silent lane is skipped (the binding rung names the drift)' }
  }
  if (!env.force && _laneCMemo.settled && !_laneCMemo.ok) {
    return { ok: false, reason: 'lane-c-' + String(_laneCMemo.reason || 'refused'), raw: 'the silent lane already refused this session (the wedge memory — never a second stall)' }
  }
  const r = await boundedIdentityCall(chromeLike, 'getAuthToken', { interactive: false }, {
    timeoutMs: Math.max(1, Number((env && env.timeoutMs) ?? LANE_C_SILENT_TIMEOUT_MS)),
    setTimer: env && env.setTimer, clearTimer: env && env.clearTimer,
  })
  _laneCMemo.settled = true
  if (r && r.ok && r.token) {
    _laneCMemo.ok = true; _laneCMemo.reason = ''
    return { ok: true, token: String(r.token), via: 'chrome-lane-c' }
  }
  _laneCMemo.ok = false
  _laneCMemo.reason = String((r && r.kind) || 'lane-c-refused')
  return { ok: false, reason: 'lane-c-' + String((r && r.kind) || 'refused'), raw: String((r && r.raw) || '') }
}

// ── The owner-pinned constants (law 0.15) ──────────────────────────────────
//
// THE OWNER'S THREE REGISTRATIONS (§3.7 — documented in-product and in the
// protocol): the three public client IDs are OWNER-SUPPLIED, owner-
// attributed, and PUBLIC BY DESIGN — a public client ID is an identifier,
// not a credential (the R110 platform fact; the blast-radius veto). Until
// the owner lands them, the constants ship EMPTY and the fast rungs render
// NOTHING (the graceful absence — §3.7): the guided rung is the card's
// face. The IDs arrive → one seal lights every fast rung on Earth.
export const LADDER_CLIENT_IDS = {
  gdrive: '',   // Google Chrome App client (Console → Credentials → OAuth client → Chrome App → the pinned extension ID; scope drive.file)
  github: '',   // GitHub OAuth App with the device flow enabled (github.com/settings/developers)
  dropbox: '',  // Dropbox app with PKCE (dropbox.com/developers/apps)
}

// The pinned scopes (law 0.15: measured, flagged, never changed unilaterally).
export const LADDER_SCOPES = {
  gdrive: ['https://www.googleapis.com/auth/drive.file'],
  github: ['gist'],
  dropbox: [],
}

// The pinned endpoints (protocol constants, not secrets).
export const GITHUB_DEVICE_FLOW = {
  codeUrl: 'https://github.com/login/device/code',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  verifyUrl: 'https://github.com/login/device',
  intervalMin: 5,      // GitHub's mandated poll interval (seconds)
  slowDownStep: 5,     // slow_down adds 5 s — the protocol's own backoff
  codeExpiry: 900,     // expires_in (seconds) — typed expiry when absent
}

export const DROPBOX_OAUTH = {
  authUrl: 'https://www.dropbox.com/oauth2/authorize',
  tokenUrl: 'https://www.dropbox.com/oauth2/token',
}

export const GOOGLE_TOKEN_URLS = {
  // the fast rung never touches these (Chrome mints and refreshes); they are
  // named here for the typed degradation card's honest wording
  token: 'https://oauth2.googleapis.com/token',
}

// ── The rung model ─────────────────────────────────────────────────────────
export const RUNG_ORDER = ['fast', 'guided', 'manual']

export const RUNG_LABEL_KEYS = {
  fast: 'ladderRungFastLabel',     // what it needs, what it costs, what it owns
  guided: 'ladderRungGuidedLabel',
  manual: 'ladderRungManualLabel',
}

/** The modes a transport's saved connection may carry (v1.5 payload law). */
export const SIGNIN_MODES = ['fast', 'guided', 'manual']

/**
 * Is `mode` a lawful signin mode? (The /k/ v1.5 parser's allowlist.)
 */
export function isSigninMode(mode) {
  return SIGNIN_MODES.includes(mode)
}

// ── The feature-detection map (§3.1/§3.3/§3.5 — the fast rung's gate) ──────
//
// THE DETECTION TABLE — the fast rung exists ONLY when every row passes:
//
//   gdrive  chrome.identity.launchWebAuthFlow IS a function (EVERY Chromium —
//           Chrome, Brave, Helium, every fork; the R174b portability law:
//           the native getAuthToken machinery is RETIRED because de-Googled
//           Chromium builds carry no browser Google session for it)
//           AND the manifest oauth2 client_id is present (the graceful
//           absence until the owner's ID lands — §3.7)
//           The sign-in itself is the WEB-AUTH window (Google's own consent
//           page) — no browser session is consulted, no probe gates the
//           button: the window is the probe.
//
//   github  ALWAYS (the device flow is protocol-public: it needs only a
//           browser to open github.com/login/device — works everywhere,
//           Helium included) — gated on the owner's client ID landing
//
//   dropbox chrome.identity.launchWebAuthFlow IS a function (the standard
//           Chromium OAuth roundtrip — every Chromium, Helium included)
//           AND the owner's app key has landed
//
// Detection is SYNCHRONOUS except the gdrive probe; detectFastRung returns
// { available, reason, probe } where probe is the async confirmation step
// the UI runs on click (never blocking first paint).

let MANIFEST_OAUTH2 = (() => {
  // the manifest is read ONCE; in the battery (node/bun) the import runs
  // without chrome — read the file relative to this module instead
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest) {
      return chrome.runtime.getManifest().oauth2 || null
    }
  } catch { /* non-extension context */ }
  return null
})()

/** The manifest oauth2 section (or null). Public by design — no secret. */
export function manifestOauth2() {
  return MANIFEST_OAUTH2
}

/** R174 battery seam (additive): pin the captured manifest read so the
 * battery can prove the retired-client guard's FACTORY substitution
 * end-to-end (the dead client in the saved config → the factory client on
 * the wire) without a browser. The extension runtime never calls it. */
export function setManifestOauth2ForTest(m) {
  MANIFEST_OAUTH2 = m
}

/**
 * The pinned client ID for a transport.
 * R169 — THE TWO-LANE RE-SEAT (named correction of the R174b factory law):
 * the manifest oauth2.client_id now carries the LANE C client (getAuthToken's
 * only lawful source), so the gdrive answer is the LANE U constant — the
 * Web-application client every launchWebAuthFlow lane rides. The manifest is
 * still read (manifestOauth2()) — it is Lane C's source and the binding
 * rung's covenant row. Both IDs are public identifiers (law 0.15).
 */
export function sharedClientId(transportId) {
  const t = String(transportId || '')
  if (t === 'gdrive') {
    return LANE_U_CLIENT_ID
  }
  return String(LADDER_CLIENT_IDS[t] || '').trim()
}

/**
 * The feature-detection map — is the FAST rung available for a transport?
 * @param {string} transportId 'gdrive' | 'github' | 'dropbox'
 * @param {object} [env] test seam: { chromeLike } overrides the runtime probe
 * @returns {{ available: boolean, reason: string, needsProbe: boolean }}
 */
export function detectFastRung(transportId, env = null) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  const cid = sharedClientId(transportId)
  if (!cid) return { available: false, reason: 'client-id-absent', needsProbe: false }
  const t = String(transportId || '')
  if (t === 'gdrive') {
    // R169 — the DETECTION gate stays launchWebAuthFlow-only on purpose: the
    // button must light on EVERY Chromium (the R174b portability truth —
    // never again a rung that vanishes on de-Googled builds). Lane C is an
    // accelerator INSIDE the press (mintGdriveLaneCToken), never a gate.
    const ok = !!(chromeLike && chromeLike.identity && typeof chromeLike.identity.launchWebAuthFlow === 'function')
    if (!ok) return { available: false, reason: 'launchWebAuthFlow-unavailable', needsProbe: false }
    return { available: true, reason: 'detected', needsProbe: false }
  }
  if (t === 'github') {
    // the device flow: protocol-public, works everywhere (Helium included)
    return { available: true, reason: 'detected', needsProbe: false }
  }
  if (t === 'dropbox') {
    const ok = !!(chromeLike && chromeLike.identity && typeof chromeLike.identity.launchWebAuthFlow === 'function')
    if (!ok) return { available: false, reason: 'launchWebAuthFlow-unavailable', needsProbe: false }
    return { available: true, reason: 'detected', needsProbe: false }
  }
  return { available: false, reason: 'no-fast-rung', needsProbe: false }
}

/**
 * The gdrive probe (§3.1, R174b-corrected): an AVAILABILITY probe only —
 * it opens NO window, touches NO session, and never calls getAuthToken.
 * It answers one question: can this browser run the fast rung at all
 * (launchWebAuthFlow present + the factory client pinned)? The sign-in
 * itself is Google's own window — the window is the probe.
 * @returns {Promise<{ ok: boolean, kind: string, raw?: string }>}
 */
export async function probeGdriveFast(env = null) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  if (!chromeLike || !chromeLike.identity || typeof chromeLike.identity.launchWebAuthFlow !== 'function') {
    return { ok: false, kind: 'launchWebAuthFlow-unavailable' }
  }
  // R165 battery seam (additive): env.clientId overrides the captured manifest
  // read (the battery runs without chrome.runtime.getManifest).
  const cid = (env && env.clientId != null) ? String(env.clientId) : sharedClientId('gdrive')
  if (!cid) return { ok: false, kind: 'client-id-absent' }
  return { ok: true, kind: 'web-auth-ready' }
}

// ── The GitHub device flow (§3.2) — the typed state machine ────────────────
//
//   idle → code-requested → awaiting-user → polling → authorized
//                              │            │
//                              │            ├→ slow-down (interval += 5 s, keeps polling)
//                              │            ├→ expired   (the typed terminal; Try again restarts)
//                              │            ├→ denied    (the user pressed the app's X on GitHub)
//                              │            └→ error     (typed network failure)
//   (any state) → canceled     (the user's Cancel — one click, always)
//   code-request refuses    → throttled (GitHub's per-IP rate limit — the
//                              honest card routes to the guided rung)

export const DEVICE_FLOW_STATES = [
  'idle', 'code-requested', 'awaiting-user', 'polling', 'slow-down',
  'authorized', 'expired', 'denied', 'throttled', 'canceled', 'error',
]

/**
 * Run the GitHub device flow to completion (or a typed terminal).
 *
 * @param {object} opts
 * @param {string} opts.clientId   the owner's public OAuth App client ID
 * @param {(state: object) => void} [opts.onState]  every state change, typed
 * @param {() => boolean} [opts.isCanceled]  polled between steps — one-click cancel
 * @param {typeof fetch} [opts.fetchImpl]   the network seam (tests inject fakes)
 * @param {(ms: number) => Promise<void>} [opts.sleepImpl]  the clock seam
 * @param {object} [opts.timing]   { interval, expiry } overrides for tests
 * @returns {Promise<{ ok: true, accessToken: string } | { ok: false, state: string, kind: string, message: string }>}
 */
export async function githubDeviceFlow(opts) {
  const clientId = String((opts && opts.clientId) || '').trim()
  const fetchImpl = (opts && opts.fetchImpl) || fetch
  const sleepImpl = (opts && opts.sleepImpl) || ((ms) => new Promise((r) => setTimeout(r, ms)))
  const onState = (opts && opts.onState) || (() => {})
  const isCanceled = (opts && opts.isCanceled) || (() => false)
  const timing = (opts && opts.timing) || {}
  let interval = Math.max(1, Number(timing.interval ?? GITHUB_DEVICE_FLOW.intervalMin))
  const expiry = Math.max(1, Number(timing.expiry ?? GITHUB_DEVICE_FLOW.codeExpiry))
  // the minimum expiry floor: 30 s protects a real user from a bogus
  // expires_in:0; the floor is OVERRIDABLE through timing.expiryFloor so the
  // battery drives the same state machine against short windows (never a
  // production path — the shipped default stands at 30).
  const expiryFloor = Math.max(0.05, Number(timing.expiryFloor ?? 30))

  if (!clientId) {
    const out = { ok: false, state: 'error', kind: 'client-id-absent', message: 'The GitHub device flow needs the shared client ID — it has not landed yet; use the guided rung.' }
    onState(out); return out
  }

  const emit = (state, extra = {}) => onState({ state, ...extra })

  // 1. the code request
  emit('idle')
  let codeResp
  try {
    codeResp = await fetchImpl(GITHUB_DEVICE_FLOW.codeUrl, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, scope: LADDER_SCOPES.github.join(' ') }),
    })
  } catch (e) {
    const out = { ok: false, state: 'error', kind: 'network', message: `GitHub's device-code endpoint could not be reached — ${String((e && e.message) || e)}` }
    onState(out); return out
  }
  // GitHub's typed throttles arrive as 401/403/429 with a message, and the
  // wrong client_id as 404 — ALL route to the guided rung, honestly.
  if (!codeResp.ok) {
    const out = { ok: false, state: 'throttled', kind: `http-${codeResp.status}`, message: `GitHub refused the device-code request (HTTP ${codeResp.status}) — the shared sign-in is unavailable right now. The guided rung (your own client) always works.` }
    onState(out); return out
  }
  const codeBody = await codeResp.json().catch(() => null)
  if (!codeBody || codeBody.error === 'unsupported' || !codeBody.device_code || !codeBody.user_code) {
    const out = { ok: false, state: 'throttled', kind: String((codeBody && codeBody.error) || 'bad-code-response'), message: 'GitHub did not issue a device code — the shared sign-in is unavailable right now. The guided rung always works.' }
    onState(out); return out
  }
  const expiresAt = Date.now() + Math.max(expiryFloor, Number(codeBody.expires_in || expiry)) * 1000
  if (codeBody.interval) interval = Math.max(interval, Number(codeBody.interval))
  emit('code-requested', { userCode: codeBody.user_code, verifyUrl: codeBody.verification_uri || GITHUB_DEVICE_FLOW.verifyUrl, interval })
  emit('awaiting-user', { userCode: codeBody.user_code, verifyUrl: codeBody.verification_uri || GITHUB_DEVICE_FLOW.verifyUrl })

  // 2. the poll loop — the mandated interval, typed expiry, one-click cancel
  while (Date.now() < expiresAt) {
    if (isCanceled()) {
      const out = { ok: false, state: 'canceled', kind: 'canceled', message: 'Sign-in canceled — nothing was stored.' }
      onState(out); return out
    }
    await sleepImpl(interval * 1000)
    if (isCanceled()) {
      const out = { ok: false, state: 'canceled', kind: 'canceled', message: 'Sign-in canceled — nothing was stored.' }
      onState(out); return out
    }
    let tokResp
    try {
      tokResp = await fetchImpl(GITHUB_DEVICE_FLOW.tokenUrl, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId, device_code: codeBody.device_code, grant_type: 'urn:ietf:params:oauth:grant-type:device_code' }),
      })
    } catch (e) {
      emit('polling', { transient: `network: ${String((e && e.message) || e)}` })
      continue // a transient poll failure is retried until expiry — never fatal
    }
    const tok = await tokResp.json().catch(() => null)
    if (tok && tok.access_token) {
      emit('authorized', { userCode: codeBody.user_code })
      return { ok: true, accessToken: String(tok.access_token) }
    }
    const err = (tok && tok.error) || 'unknown'
    if (err === 'authorization_pending') { emit('polling'); continue }
    if (err === 'slow_down') { interval += GITHUB_DEVICE_FLOW.slowDownStep; emit('slow-down', { interval }); continue }
    if (err === 'expired_token') {
      const out = { ok: false, state: 'expired', kind: 'expired_token', message: 'The sign-in code expired — press Try again for a fresh code.' }
      onState(out); return out
    }
    if (err === 'access_denied') {
      const out = { ok: false, state: 'denied', kind: 'access_denied', message: 'Sign-in was refused on github.com — press Try again when you are ready.' }
      onState(out); return out
    }
    const out = { ok: false, state: 'error', kind: String(err), message: `GitHub's token endpoint answered with an unexpected answer (${String(err)}) — the guided rung always works.` }
    onState(out); return out
  }
  const out = { ok: false, state: 'expired', kind: 'expired_token', message: 'The sign-in code expired — press Try again for a fresh code.' }
  onState(out); return out
}

// ── The Dropbox PKCE path (§3.3) — S256, the official public-client mode ───

/** b64url (no padding) for the PKCE pair. */
function b64url(bytes) {
  let bin = ''
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * The PKCE pair: verifier (48 random bytes, b64url) + challenge (S256).
 * @param {{randomImpl?: (n: number) => Uint8Array, digestImpl?: (algo: string, data: ArrayBuffer) => Promise<ArrayBuffer>}} [env]
 */
export async function pkcePair(env = null) {
  const randomImpl = (env && env.randomImpl) || ((n) => crypto.getRandomValues(new Uint8Array(n)))
  const digestImpl = (env && env.digestImpl) || ((algo, data) => crypto.subtle.digest(algo, data))
  const verifier = b64url(randomImpl(48))
  const digest = await digestImpl('SHA-256', new TextEncoder().encode(verifier))
  const challenge = b64url(digest)
  return { verifier, challenge, method: 'S256' }
}

/** The Dropbox authorize URL (code_challenge rides; no secret exists). */
export function dropboxAuthUrl({ appKey, challenge, redirect, tokenAccess = 'offline' }) {
  const u = new URL(DROPBOX_OAUTH.authUrl)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('client_id', String(appKey || ''))
  u.searchParams.set('code_challenge', String(challenge || ''))
  u.searchParams.set('code_challenge_method', 'S256')
  u.searchParams.set('token_access_type', tokenAccess)
  u.searchParams.set('redirect_uri', String(redirect || ''))
  return u.toString()
}

/**
 * The Dropbox token exchange (code → { refresh_token, access_token }).
 * Public-client by protocol: only the app key rides — never a secret.
 */
export async function dropboxExchangeCode({ appKey, code, verifier, redirect, fetchImpl = fetch }) {
  const body = new URLSearchParams({
    code: String(code || ''),
    grant_type: 'authorization_code',
    client_id: String(appKey || ''),
    code_verifier: String(verifier || ''),
    redirect_uri: String(redirect || ''),
  })
  const resp = await fetchImpl(DROPBOX_OAUTH.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  })
  const data = await resp.json().catch(() => null)
  if (!resp.ok || !data || !data.refresh_token) {
    const kind = data && data.error ? String(data.error) : `http-${resp.status}`
    throw new Error(`dropbox_exchange_failed:${kind}`)
  }
  return { refreshToken: String(data.refresh_token), accessToken: String(data.access_token || '') }
}

/** The Dropbox refresh (the guided and the fast rung share the endpoint). */
export async function dropboxRefresh({ appKey, refreshToken, fetchImpl = fetch }) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: String(refreshToken || ''),
    client_id: String(appKey || ''),
  })
  const resp = await fetchImpl(DROPBOX_OAUTH.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  })
  const data = await resp.json().catch(() => null)
  if (!resp.ok || !data || !data.access_token) {
    const kind = data && data.error ? String(data.error) : `http-${resp.status}`
    throw new Error(`dropbox_refresh_failed:${kind}`)
  }
  return String(data.access_token)
}

// ── The token accessors (§3.1 — the lifecycle branch) ──────────────────────
//
// The transport's saved config carries signinMode ('fast' | 'guided' |
// 'manual' — v1.5). The accessor branches:
//   fast + gdrive   → the SEALED webToken from the last connect (the code
//                     lane's or the implicit lane's mint); the access token
//                     is UCrypt-custodied — the refresh leg (the R174b
//                     offline law) lives in gdrive.ensureAccessToken, the
//                     ONE token seam. getAuthToken is RETIRED (R174b).
//   fast + github   → the stored device-flow token (GitHub tokens do not
//                     expire; it is sealed per-device like every grant)
//   fast + dropbox  → the stored refresh token → the refresh endpoint
//   guided/manual   → the stored grant + the transport's own refresh path
//                     (unchanged from the pre-ladder rounds)

/**
 * Resolve an access token for a fast-mode connection.
 * @returns {Promise<string>} the access token
 */
export async function fastAccessToken(transportId, config, env = null) {
  const t = String(transportId || '')
  if (t === 'gdrive') {
    // R169 — THE TWO-LANE ACCESSOR (named correction of the R174b
    // retirement): 1) the SEALED webToken (the one-click connect's mint)
    // serves first; 2) the LANE C silent mint answers second — Chrome's own
    // cached connection, zero windows, THE reboot-persistence lane (after a
    // browser restart the silent mint re-serves without any UI); 3) the
    // typed refusal — gdrive.ensureAccessToken owns the refresh leg and the
    // typed reconnect card that follow it. The refusal message prefix
    // (gdrive_fast_token_refused:<raw>) stays byte-true for the existing
    // typed-refusal classifier.
    const wt = (config && config.webToken) || null
    if (webTokenFresh(wt)) return String(wt.token)
    const laneC = await mintGdriveLaneCToken((env && env.laneC) || (env ? { chromeLike: env.chromeLike, timeoutMs: env.laneCTimeoutMs, setTimer: env.setTimer, clearTimer: env.clearTimer } : {}))
    if (laneC && laneC.ok) {
      // R179 — THE LANE C BANK (the silent mint is CUSTODY too): the silent
      // lane's access token banks into the record's webToken shape (the same
      // custody every lane rides) so the caller's write-back persists it —
      // before this line the silent mint evaporated with the call frame, the
      // stored bank read dead on every surface, and every reopen paid the
      // silent bound again. Chrome re-mints silently; the bank just spares
      // the round-trip and lets the custody era speak the truth.
      try {
        config.webToken = webTokenFromMint({ ok: true, token: String(laneC.token), expiresIn: 3600 })
        if (config.webToken) config.webToken.via = 'chrome-lane-c'
      } catch { /* the bank is best-effort — the mint's answer stands */ }
      return String(laneC.token)
    }
    throw new Error('gdrive_fast_token_refused:lane-c-' + String((laneC && laneC.reason) || 'refused') + ' — press Connect; the web-auth window mints fresh (the sealed webToken expired or is absent, and the Chrome silent lane is unavailable on this browser)')
  }
  if (t === 'github') {
    const tok = String((config && (config.oauthAccessToken || config.token)) || '').trim()
    if (!tok) throw new Error('github_fast_no_token')
    return tok
  }
  if (t === 'dropbox') {
    const appKey = sharedClientId('dropbox')
    const rt = String((config && config.refreshToken) || '').trim()
    if (!rt || !appKey) throw new Error('dropbox_fast_no_grant')
    return dropboxRefresh({ appKey, refreshToken: rt, fetchImpl: (env && env.fetchImpl) || fetch })
  }
  throw new Error(`fast_access_token_no_transport:${t}`)
}

// ── The ring record (law 0.28 — the ladder's flows record their rungs) ─────

/**
 * The typed rung record for the evidence ring. Every connect — fast,
 * guided, manual — calls this once at its start so the owner's diagnostics
 * paste names the rung and the stage.
 */
export function rungRingRecord(transportId, rung, extra = {}) {
  return {
    flow: 'connect',
    transport: String(transportId || ''),
    stage: 'rung',
    rung: String(rung || ''),
    outcome: 'ok',
    httpKind: 'ladder',
    message: extra.message || `the ${rungSafe(rung)} rung was chosen`,
    ...extra,
  }
}

function rungSafe(r) { return String(r || '') === 'fast' || r === 'guided' || r === 'manual' ? r : 'guided' }

// ── The preflight ping (§3.4 — the guided rung rides the client-ID probe) ──

/**
 * The guided rung's preflight: is the user's own client ID (format-valid)
 * enabled? Google's token endpoint answers a typed refusal to a disabled
 * client BEFORE any auth window opens — a stale client says so immediately.
 * This is a FORMAT probe only (network is optional): the full enabled-check
 * rides the connect flow's first leg (the R116 cause-class gate's tier).
 */
export function preflightClientId(transportId, clientId) {
  const id = String(clientId || '').trim()
  if (!id) return { ok: false, kind: 'empty' }
  if (transportId === 'gdrive' && !/^[0-9A-Za-z_-]+\.apps\.googleusercontent\.com$/.test(id)) {
    return { ok: false, kind: 'format', expected: '<random>.apps.googleusercontent.com' }
  }
  if (transportId === 'github' && !/^(Ov23li|Iv1)[A-Za-z0-9]{8,}$/.test(id)) {
    return { ok: false, kind: 'format', expected: 'Ov23li… / Iv1…' }
  }
  return { ok: true, kind: 'format-ok' }
}

// ════════════════════════════════════════════════════════════════════════════
// R120 — THE RUNG LIFECYCLE (law 0.33) — the engine + the pure audit layer.
//
// LAW 0.33 THE RUNG-LIFECYCLE LAW: a connection's rung is switchable at any
// time, and every switch cleans the prior rung's state completely — no orphan
// tokens, no half-grants, no stale refresh timers; the disconnect per rung
// clears exactly that rung's material; the card's state line always tells
// the truth about which rung is live.
//
// THREE PURE FUNCTIONS live here (no DOM, no chrome, no network — the battery
// drives them directly on plain stored records; options.js EXECUTES the plan
// through the seams that already exist: the wizard's own fields, the
// TRANSPORT_SAVE envelope replacement, the Disconnect path's TRANSPORT_CLEAR):
//
//   rungMaterial(mode, stored)        — what a rung's live connection HOLDS:
//                                       the ACTUAL config key names (the real
//                                       field names the transports use today:
//                                       refreshToken / oauthAccessToken /
//                                       signinMode / the sealed-grant keys the
//                                       guided flows fill) plus the pinned
//                                       material classes.
//   planRungSwitch(from, to, stored)  — the typed switch plan: { ok, from, to,
//                                       cleanup: [typed steps], keep: [] }.
//                                       Switching to the SAME rung →
//                                       { ok:false, reason:'same-rung' };
//                                       unknown modes → 'unknown-mode'; a
//                                       rung-less 'none' from → 'no-live-rung'.
//                                       A step names KEY NAMES and material
//                                       CLASSES only — NEVER a value (law
//                                       0.14: no secret in any string, any
//                                       log, any ring row).
//   describeRungState(stored)         — the ONE truthful state-line mode
//                                       ('fast' | 'guided' | 'manual' |
//                                       'none') the UI state line reads.
//
// THE GDRIVE DISPATCHER RULE: gdrive's config.authMode IS the live dispatcher
// (the transport branches on it — gdrive.js ensureAccessToken / isApiMode /
// canArchive), so for gdrive the dispatcher's answer is the live rung's truth
// even where a stale recorded signinMode disagrees. github/dropbox carry no
// dispatcher field; there the recorded signinMode wins (it names the rung the
// connection was won at), and the accessors' own preference (the sealed grant
// before a pasted PAT — github.js's oauthAccessToken || token) orders the
// legacy inference.
//
// THE FAST RUNG'S BROWSER-HELD MATERIAL: the gdrive fast bearer lives in
// Chrome's own token cache (chrome.identity.getAuthToken) — UCrypt never
// stores it, so no UCrypt storage step can or must drop it; the plan NAMES
// the material class (the 'chrome-token-cache' step) and the page-side
// executor leaves it browser-managed. The accessor binding (accessorBinding)
// is the routing wire the mode write rebinds at the save — named as material,
// never as a drop step.
// ════════════════════════════════════════════════════════════════════════════

/**
 * The config key NAMES each rung's live connection owns, per transport — the
 * REAL field names the transports declare today (gdrive.js fields: authMode /
 * clientId / clientSecret / refreshToken / scriptUrl / secret; github.js:
 * oauthClientId / oauthClientSecret / oauthAccessToken / token / apiBase;
 * dropbox.js: appKey / appSecret / refreshToken / token / apiBase) plus the
 * signinMode record the save path carries. '_any' covers a record whose
 * transport id is absent — the union, filtered by presence.
 */
const RUNG_LIFECYCLE_KEYS = {
  gdrive: {
    fast: ['authMode', 'clientId', 'signinMode'], // Chrome holds the bearer; the shared ID rides openly (0.15)
    guided: ['authMode', 'clientId', 'clientSecret', 'refreshToken', 'signinMode'],
    manual: ['authMode', 'scriptUrl', 'secret', 'signinMode'], // the Bridge: script + its secret
  },
  github: {
    fast: ['oauthAccessToken', 'signinMode'], // the device-flow token, sealed device-only
    guided: ['oauthAccessToken', 'oauthClientId', 'oauthClientSecret', 'signinMode'],
    manual: ['apiBase', 'signinMode', 'token'], // the PAT (Advanced)
  },
  dropbox: {
    fast: ['appKey', 'refreshToken', 'signinMode'], // the PKCE grant, sealed device-only
    guided: ['appKey', 'appSecret', 'refreshToken', 'signinMode'],
    manual: ['apiBase', 'signinMode', 'token'], // the pasted access token (Advanced)
  },
  _any: {
    fast: ['oauthAccessToken', 'refreshToken', 'signinMode'],
    guided: ['appKey', 'appSecret', 'clientId', 'clientSecret', 'oauthAccessToken', 'oauthClientId', 'oauthClientSecret', 'refreshToken', 'signinMode'],
    manual: ['apiBase', 'scriptUrl', 'secret', 'signinMode', 'token'],
  },
}

/** The material CLASS of each key (what a cleanup step names — never a value). */
const RUNG_KEY_CLASSES = {
  apiBase: 'address',
  appKey: 'identifier', // public by design (law 0.15) — an identifier, not a credential
  appSecret: 'ownSecret',
  authMode: 'mode',
  clientId: 'identifier',
  clientSecret: 'ownSecret',
  oauthAccessToken: 'grantSealed',
  oauthClientId: 'identifier',
  oauthClientSecret: 'ownSecret',
  refreshToken: 'refreshToken',
  scriptUrl: 'address',
  secret: 'patOrBridge', // the Bridge secret — the manual rung's own material
  signinMode: 'mode',
  token: 'patOrBridge',
}

/** The sealed-grant class keys (a guided record's grant material). */
const RUNG_GRANT_CLASS_KEYS = ['oauthAccessToken', 'refreshToken']

/** The plain config object of a stored record: { id, config } or a flat config. */
function lifecycleConfigOf(stored) {
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return {}
  if (stored.config && typeof stored.config === 'object' && !Array.isArray(stored.config)) return stored.config
  return stored
}

/** The transport id: the record's own hint first, then the field shapes. */
function lifecycleTransportIdOf(stored, cfg) {
  const hinted = String((stored && (stored.id || stored.transportId)) || '').trim().toLowerCase()
  if (hinted) return hinted
  if (lifecycleKeyPresent(cfg, 'authMode') || lifecycleKeyPresent(cfg, 'scriptUrl') || lifecycleKeyPresent(cfg, 'secret')) return 'gdrive'
  if (lifecycleKeyPresent(cfg, 'oauthClientId') || lifecycleKeyPresent(cfg, 'oauthAccessToken')) return 'github'
  if (lifecycleKeyPresent(cfg, 'appKey') || lifecycleKeyPresent(cfg, 'appSecret')) return 'dropbox'
  return ''
}

/** Presence, not value: a key holds material when it is set and non-empty
 * (sealed envelope strings count — the page sees PRESENCE, never the value). */
function lifecycleKeyPresent(cfg, key) {
  if (!cfg || typeof cfg !== 'object') return false
  const v = cfg[key]
  return v !== undefined && v !== null && String(v) !== ''
}

/**
 * What a rung's live connection holds, given the stored transport record.
 * PURE: read-only inspection of a plain object — nothing is mutated, nothing
 * is decrypted, no value ever leaves the record (only key NAMES ride).
 *
 * @param {string} mode 'fast' | 'guided' | 'manual'
 * @param {object} [stored] the stored record ({ id, config } shape or a flat config)
 * @returns {{ mode: string, transportId: string, keys: string[], keyClasses: Object<string,string>, material: object }}
 *   - keys:        the rung's owned key names PRESENT in the record (sorted) —
 *                  nothing extra, nothing missing
 *   - keyClasses:  key → material class ('mode' | 'identifier' | 'ownSecret' |
 *                  'refreshToken' | 'grantSealed' | 'patOrBridge' | 'address')
 *   - material:    the pinned classes — fast: { accessorBinding:true,
 *                  chromeTokenCache: gdrive? }; guided: { grantSealed,
 *                  refreshToken:true }; manual: { patOrBridge:true }
 */
export function rungMaterial(mode, stored) {
  const m = String(mode || '').trim().toLowerCase()
  const cfg = lifecycleConfigOf(stored)
  const transportId = lifecycleTransportIdOf(stored, cfg)
  const table = RUNG_LIFECYCLE_KEYS[transportId] || RUNG_LIFECYCLE_KEYS._any
  const owned = Array.isArray(table[m]) ? table[m] : []
  const keys = []
  const keyClasses = {}
  for (const k of owned) {
    if (!lifecycleKeyPresent(cfg, k)) continue
    keys.push(k)
    keyClasses[k] = RUNG_KEY_CLASSES[k] || 'unknown'
  }
  keys.sort()
  const material = {}
  if (m === 'fast') {
    material.accessorBinding = true
    material.chromeTokenCache = transportId === 'gdrive'
  } else if (m === 'guided') {
    material.grantSealed = RUNG_GRANT_CLASS_KEYS.some((k) => lifecycleKeyPresent(cfg, k))
    material.refreshToken = true
  } else if (m === 'manual') {
    material.patOrBridge = true
  }
  return { mode: m, transportId, keys, keyClasses, material }
}

/**
 * The typed switch plan (law 0.33). PURE: same inputs → the same plan, the
 * stored record is never touched, and no step ever names a VALUE — only key
 * NAMES and material CLASSES (law 0.14). Cleanup is COMPLETE: every material
 * class the from-rung holds is named (each held key as a 'drop-field' step,
 * plus the gdrive fast rung's browser-held bearer as the 'chrome-token-cache'
 * step). keep is the material that survives — empty for every lawful
 * direction (a switch keeps nothing of the prior rung).
 *
 * @param {string} fromMode the live rung (describeRungState's answer) or 'none'
 * @param {string} toMode the rung the caller is about to start
 * @param {object} [stored] the stored record ({ id, config } or flat)
 * @returns {{ ok: boolean, reason?: string, from: string, to: string, cleanup: Array<{kind:string,key:string,materialClass:string}>, keep: Array<object> }}
 *   refusals (ok:false): 'same-rung' | 'unknown-mode' | 'no-live-rung'
 */
export function planRungSwitch(fromMode, toMode, stored) {
  const from = String(fromMode || '').trim().toLowerCase()
  const to = String(toMode || '').trim().toLowerCase()
  if (!isSigninMode(to)) {
    return { ok: false, reason: 'unknown-mode', from, to, cleanup: [], keep: [] }
  }
  if (from === '' || from === 'none') {
    return { ok: false, reason: 'no-live-rung', from, to, cleanup: [], keep: [] }
  }
  if (!isSigninMode(from)) {
    return { ok: false, reason: 'unknown-mode', from, to, cleanup: [], keep: [] }
  }
  if (from === to) {
    return { ok: false, reason: 'same-rung', from, to, cleanup: [], keep: [] }
  }
  const mat = rungMaterial(from, stored)
  const cleanup = mat.keys.map((key) => ({ kind: 'drop-field', key, materialClass: mat.keyClasses[key] || 'unknown' }))
  if (mat.material.chromeTokenCache) {
    cleanup.push({ kind: 'chrome-token-cache', key: 'chrome.identity.getAuthToken', materialClass: 'chromeTokenCache' })
  }
  return { ok: true, from, to, cleanup, keep: [] }
}

/**
 * The ONE truthful state-line mode for a stored record ('fast' | 'guided' |
 * 'manual' | 'none') — the single source the UI state line reads (law 0.33:
 * the card's state line always tells the truth about which rung is live).
 * PURE, read-only.
 *
 *   - a record with no live material → 'none' (absent grant + absent token);
 *   - gdrive: the authMode dispatcher answers (fast / bridge / oauth+grant);
 *     a legacy authMode-less record infers from the material it holds;
 *   - github/dropbox (no dispatcher field): the recorded signinMode wins,
 *     else the accessors' own preference — the sealed grant before a PAT.
 *
 * @param {object} [stored] the stored record ({ id, config } or flat)
 * @returns {string} 'fast' | 'guided' | 'manual' | 'none'
 */
export function describeRungState(stored) {
  const cfg = lifecycleConfigOf(stored)
  const anyMaterial = Object.keys(cfg).some((k) => lifecycleKeyPresent(cfg, k))
  if (!anyMaterial) return 'none'
  const transportId = lifecycleTransportIdOf(stored, cfg)
  // gdrive — the dispatcher (authMode) is the live rung's truth:
  if (transportId === 'gdrive' || (transportId === '' && (cfg.authMode === 'fast' || cfg.authMode === 'bridge' || cfg.authMode === 'oauth'))) {
    if (cfg.authMode === 'fast') return 'fast'
    if (cfg.authMode === 'bridge') return 'manual'
    if (cfg.authMode === 'oauth') return lifecycleKeyPresent(cfg, 'refreshToken') ? 'guided' : 'none'
    // a legacy gdrive record without authMode: infer from the material
    if (lifecycleKeyPresent(cfg, 'scriptUrl') || lifecycleKeyPresent(cfg, 'secret')) return 'manual'
    if (lifecycleKeyPresent(cfg, 'refreshToken')) return 'guided'
    return 'none'
  }
  // github / dropbox / no hint — the recorded rung wins (it names the rung
  // the connection was won at; the fast rungs record it at the seal):
  const explicit = String(cfg.signinMode || '').trim().toLowerCase()
  if (isSigninMode(explicit)) return explicit
  if (transportId === 'github') {
    if (lifecycleKeyPresent(cfg, 'oauthAccessToken')) return 'guided' // the accessors prefer the grant
    if (lifecycleKeyPresent(cfg, 'token')) return 'manual'
    return 'none'
  }
  if (transportId === 'dropbox') {
    if (lifecycleKeyPresent(cfg, 'refreshToken')) return 'guided'
    if (lifecycleKeyPresent(cfg, 'token')) return 'manual'
    return 'none'
  }
  // a flat record with no id hint: the accessors' own preference orders it
  if (lifecycleKeyPresent(cfg, 'oauthAccessToken') || lifecycleKeyPresent(cfg, 'refreshToken')) return 'guided'
  if (lifecycleKeyPresent(cfg, 'token') || lifecycleKeyPresent(cfg, 'scriptUrl') || lifecycleKeyPresent(cfg, 'secret')) return 'manual'
  return 'none'
}
