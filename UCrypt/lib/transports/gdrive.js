/**
 * Google Drive transport (v2.2.0) — via a Google Apps Script bridge.
 * R124: the async pickup's hold rides this transport's OAuth/fast rungs (D13, law 0.38) — the exported ensureAccessToken/isApiMode are the bridge's ONE token discipline (no parallel credential logic anywhere); the bridge rung is honestly absent for holds.
 * R123: the revoked-grant ring signature (§2.2) — the refresh failure records the typed ring row (stage: refresh + the recovery kind), machine-verifiable in the diagnostics export.
 * R122: the acceptance walkthrough's ladder step (§2.2 (2)) routes here — the rung
 * state the walkthrough shows is the same Sign-In Ladder this transport climbs.
 *
 * AUDIT VERDICT ON v2.1.0: the previous implementation PATCHed the Drive API
 * anonymously, claiming "the share link IS the auth". That is false — every
 * Drive API write requires an OAuth2 bearer token, so uploads ALWAYS failed
 * with 401/403 (audit finding #3). Sharing a file link only grants access
 * through Google's own web/app clients, never to anonymous API callers.
 *
 * The v2.2.0 design keeps the "no OAuth in the extension" property AND works
 * for real: the user deploys a ~30-line Google Apps Script bound to their own
 * Drive (copy-paste, ~3 minutes, guided in the UI). The script exposes:
 *
 *   GET  <execUrl>?action=ping            → { ok: true }
 *   GET  <execUrl>?action=read&secret=…   → raw blob text (or null)
 *   POST <execUrl>  body { secret, content } → writes the blob
 *
 * Access is protected by a user-chosen secret (transmitted over HTTPS and
 * checked by the script). The stored content is always AES-GCM ciphertext
 * encrypted with the sync code — Google never sees plaintext.
 *
 * v2.3.0: timeout + retry + classified errors via the shared http.js helper.
 * v2.16.0 — R25-F1 (audit finding, HIGH): this file IMPORTED the shared
 * helpers but called raw fetch() — the ONLY transport family without the
 * deadline/retry/classification hardening (a hanging bridge left an
 * unbounded await inside the fire-and-forget push). All three methods are
 * routed through fetchWithRetry + classifySyncError now.
 *
 * R121 (v2.79.0) — THE LIVE PROOF: the fast rung's live rows landed on the final bytes (the probe rings, the native picker window opened live, the typed refusal posture); the self-check's rung rows read this transport's truth (presence-only, the probe snapshotted at run start).
 * R120 (v2.78.0) — THE LADDER CLIMBED: the multi-account guard (the picker's choice respected — the accountHint learned at connect, a different account typed-refused, never a silent wrong-account sync), the native-picker fallback (a consent-only refusal is ONE interactive call, not a dead end), the typed one-click re-consent card for a non-interactive refusal.
 * R119 (v2.77.0) — THE SIGN-IN LADDER (law 0.32): the FAST rung joins as
 * authMode 'fast' — Chrome mints and refreshes the bearer token
 * (chrome.identity.getAuthToken) and UCrypt never stores it, never refreshes
 * it, and never needs a clientId/refreshToken of its own for it. The bridge
 * mode and the guided OAuth mode behave EXACTLY as before.
 *
 * NOTE on the bridge protocol: GET ping/read carry the secret in the query
 * string (the Apps Script side reads e.parameter.secret — changing that
 * would break every deployed bridge). The POST upload correctly keeps the
 * secret in the body. Only the ciphertext's SYNC KEY protects the content;
 * the bridge secret is a light anti-enumeration measure.
 *
 * APPS SCRIPT SOURCE (also offered with a copy button in the options UI):
 * ------------------------------------------------------------------ 
 * const FILE_NAME = 'ucrypt-vault.enc'
 * const SECRET = 'change-me-to-a-long-random-string'
 *
 * function doGet(e) {
 *   const p = e.parameter || {}
 *   if (SECRET && p.secret !== SECRET) return json_({ ok: false, error: 'bad secret' })
 *   if (p.action === 'ping') return json_({ ok: true, file: FILE_NAME })
 *   if (p.action === 'read') {
 *     const it = DriveApp.getFilesByName(FILE_NAME)
 *     return json_({ ok: true, content: it.hasNext() ? it.next().getBlob().getDataAsString() : null })
 *   }
 *   return json_({ ok: false, error: 'unknown action' })
 * }
 *
 * function doPost(e) {
 *   const body = JSON.parse(e.postData.contents)
 *   if (SECRET && body.secret !== SECRET) return json_({ ok: false, error: 'bad secret' })
 *   const it = DriveApp.getFilesByName(FILE_NAME)
 *   if (it.hasNext()) it.next().setContent(body.content)
 *   else DriveApp.createFile(Utilities.newBlob(body.content, 'application/octet-stream', FILE_NAME))
 *   return json_({ ok: true })
 * }
 *
 * function json_(obj) {
 *   return ContentService.createTextOutput(JSON.stringify(obj))
 *     .setMimeType(ContentService.MimeType.JSON)
 * }
 */

import { fetchWithRetry, classifySyncError, looksLikeVaultEnvelope, SYNC_ERROR_KINDS, SyncError, responseToSyncError } from './http.js'
import { typedGoogleError, validateClientIdFormat, CLIENT_ID_GUIDE, NEEDS_CLIENT_ID_STATUS, OWN_SECRET_HELP } from './gdrive-oauth-help.js'
// R160 ARC A′ — the proactive Testing-expiry card's Layer-1 classifier
// (the refresh hook below persists the typed evidence it reads).
import { classifyTestingEvidence, TESTING_EVIDENCE_KEY } from '../cloud/testing-card.js'
// R149 §6.6 — ONE CLASS MACHINE WRITES EVERY CLOUD SENTENCE (LAW #14): the transport
// no longer carries its own ad-hoc copy — the no-url sentence IS the
// BRIDGE_URL_MISSING verdict class's words (lib/cloud/cred.js), so the
// wizard's line and the cred banner's line can never disagree.
import { CRED_VERDICT_CLASSES } from '../cloud/cred.js'
import { runConnectFlow, launchWindowTyped } from '../connect-flow.js'
// R119 §3.1 (law 0.32) — the fast rung's engine: Chrome-minted tokens and
// the non-interactive probe live in the ladder module. The ring primitive
// rides too so the fast-token stage names its rung (law 0.28).
import { fastAccessToken, probeGdriveFast, sharedClientId, mintGdriveLaneCToken, LANE_C_CLIENT_ID } from '../ladder.js'
import { webAuthFastToken, webAuthCodeMint, webTokenFromMint, webTokenFresh, FAST_WEB_SCOPE, EXCHANGE_FALLBACK_KINDS } from '../webauth-fallback.js'
import { isLaneCClientId, isDeadClientId, isSpineClientId, isLaneUClientId, SPINE_CLIENT_ID } from '../cloud/oauth-clients.js'
import { spineProbe, spineCustodyFacts, fastReconnectCardWords, bankBurnClock, authCustodyVerdict, SPINE_CONNECT_PROMISE } from '../cloud/spine.js'
import { materializeUserText, carry } from '../honest-error.js'
import { recordRing } from '../egrings.js'
// R178 — R-178.2 THE RENEWAL WRITE-BACK: the leaf hook (the vault registers
// the writer; gdrive notifies — no import cycle).
import { notifyCustodyWriteBack } from '../cloud/custody-writeback.js'

// R167 — THE FAST PROBE'S BOUND (the E-13 clinical order, part 2): the
// non-interactive probe answers in milliseconds when the browser holds a
// session and refuses in milliseconds when it does not — the ONLY shape
// that outlives 2.5 s is the wedged never-fires callback (E-11). The bound
// is therefore 2.5 s: the fast rung NEVER makes the owner wait 20–30 s
// before Google's own window opens. (The env seam overrides — the battery
// drives shorter/longer bounds deterministically.)
export const FAST_PROBE_BOUND_MS = 2500

// R92 §1.4 — the bridge contract version. The PRE-FILLED script below embeds
// BRIDGE_SCRIPT_VERSION and echoes it in every JSON answer (`v`). When the
// deployed script answers WITHOUT `v` (or older), the setup warns truthfully:
// "Your deployed script is older than the current one — re-paste and
// redeploy". A real candidate cause of a working-looking bridge that
// misbehaves (the CEO's S3/S4) is a STALE script version — now named.
export const BRIDGE_SCRIPT_VERSION = 2

// R149 §6.6 (THE TWO-TRUTHS SWEEP): the sentence is WRITTEN BY THE CLASS
// MACHINE — the old hand-rolled 'Add your Apps Script Web App URL first
// (Sync settings → Google Drive).' carried a second, contradictory
// affordance next to the cred banner's reselect words; both surfaces now
// speak the ONE BRIDGE_URL_MISSING sentence.
const NO_URL_USER_MSG = CRED_VERDICT_CLASSES.BRIDGE_URL_MISSING.words

// v2.17.0 — R26-F3: HTTPS is MANDATORY. The old _url()/upload() accepted
// http:// (proven: a POST body + the secret in a ?secret=… query went to a
// plaintext origin). The Apps Script /exec URL is always https, so anything
// else is a mis-paste worth refusing loudly.
function validatedScriptUrl(config) {
  const raw = String((config && (config.scriptUrl || config.url)) || '').trim()
  if (!raw) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive transport: no Apps Script URL configured', { userMessage: NO_URL_USER_MSG })
  }
  let u
  try {
    u = new URL(raw)
  } catch {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive transport: the Apps Script URL is not a valid URL', {
      userMessage: 'The Apps Script URL is not a valid URL — copy the full /exec link from the deployment dialog.',
    })
  }
  if (u.protocol !== 'https:') {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, `Google Drive transport: refusing a non-HTTPS bridge URL (${u.protocol})`, {
      userMessage: 'The bridge URL must be HTTPS — re-copy the /exec link (it always starts with https://script.google.com/…).',
    })
  }
  return u
}

// v2.17.0 — R26-F2: the bridge contract is JSON {ok: …}. When a deployment's
// "access: Anyone" grant lapses, the /exec URL 302-redirects to a Google
// sign-in page that answers 200 text/html — the old code JSON.parse()d it,
// got null, and RESOLVED the upload as success (proven). An HTML answer is
// never a success; every method now enforces the contract.
//
// R92 §1.4 — THE BRIDGE HTML CLASSIFIER (the CEO's S3/S4 order): an HTML
// answer is classified into the EXACT cause (one of the four classic
// misconfigurations), and a /edit or /dev URL yields a one-click corrected
// /exec suggestion. Never again "answered with an HTML page" alone.
export function classifyBridgeAnswer(text) {
  const raw = String(text || '')
  if (!/<html[\s>]|<!doctype html/i.test(raw)) return null // not HTML — caller parses JSON
  const head = raw.slice(0, 6000)
  const lowered = head.toLowerCase()
  // Cause 1 — the deployment is not public: Google answers with a sign-in page.
  if (lowered.includes('accounts.google.com') || lowered.includes('sign in') || lowered.includes('sign-in')) {
    return {
      cause: 'not-public',
      why: "The Web App is not public. Redeploy with 'Who has access: Anyone' (Apps Script → Deploy → Manage deployments → edit → Access: Anyone).",
    }
  }
  // Cause 2 — the EDITOR page, not the deployment: /edit URLs render the
  // Apps Script editor chrome for anyone with edit access.
  if (/script\.google\.com\/macros\/s\/[^/]+\/(edit|dev)\b/i.test(head) || (lowered.includes('apps script') && lowered.includes('editor'))) {
    return {
      cause: 'editor-url',
      why: 'This is the editor URL. Use the /exec URL from Deploy → Manage deployments.',
      correctedUrl: correctedExecUrl(head),
    }
  }
  // Cause 4 — an appspot / googleusercontent landing page without JSON: the
  // deployment itself errored (the classic "script threw" page).
  if (lowered.includes('googleusercontent.com') || lowered.includes('appspot.com') || lowered.includes('apps script')) {
    return {
      cause: 'deploy-errored',
      why: "The deployment errored — check the script's execution log (Apps Script → Executions), fix the error, and re-test.",
    }
  }
  return {
    cause: 'html-unknown',
    why: 'The bridge answered with an HTML page instead of the JSON contract — re-deploy the Web App (Execute as "Me", access "Anyone") and paste the fresh /exec URL.',
    correctedUrl: correctedExecUrl(head),
  }
}

/** R92 §1.4 — URL auto-correct: a pasted /edit or /dev URL becomes the
 * /exec deployment URL (same script ID), offered as a one-click fix. */
export function correctedExecUrl(text) {
  const m = String(text || '').match(/https:\/\/script\.google\.com\/macros\/s\/([A-Za-z0-9_-]+)\/(?:edit|dev)(?:[^\s"'<>]*)?/i)
  return m ? `https://script.google.com/macros/s/${m[1]}/exec` : null
}

function assertBridgeJson(text, { context }) {
  const classified = classifyBridgeAnswer(text)
  if (classified) {
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `${context}: the bridge answered with an HTML page, not the JSON contract`, {
      userMessage: classified.why,
      bridge: classified,
    })
  }
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/** R92 §1.4 — the version-echo check: a deployed script OLDER than the
 * current pre-filled one yields the typed warning (a stale script version is
 * a real candidate cause of the CEO's bridge failure and must be covered). */
export function bridgeVersionWarning(data) {
  if (!data || typeof data !== 'object' || data.ok !== true) return null
  const v = Number(data.v)
  if (!Number.isFinite(v)) {
    return 'Your deployed script is older than the current one — re-paste and redeploy (the current script reports version ' + BRIDGE_SCRIPT_VERSION + '; yours did not report one).'
  }
  if (v < BRIDGE_SCRIPT_VERSION) {
    return `Your deployed script is older than the current one — re-paste and redeploy (deployed v${v}, current v${BRIDGE_SCRIPT_VERSION}).`
  }
  return null
}

/**
 * R85 (§4): stage-by-stage bridge verification for the wizard's Verify button.
 * Returns { stage, ok, message } per step — a failed setup names the EXACT
 * failing step instead of a generic error.
 */
export async function verifyBridgeStages(config) {
  const out = []
  // Stage 1 — client-side URL validation (R92 §1.4: a /edit or /dev paste is
  // classified AND auto-corrected — the row carries the one-click /exec fix).
  const raw = String((config && config.scriptUrl) || '').trim()
  let u = null
  try { u = raw ? new URL(raw) : null } catch { u = null }
  if (!raw) out.push({ stage: 'url', ok: false, message: 'No URL yet — paste the /exec link from Apps Script → Deploy → New deployment → Web app.' })
  else if (!u || u.protocol !== 'https:') out.push({ stage: 'url', ok: false, message: 'The URL must be HTTPS (the /exec link always is).' })
  else if (!/script\.google\.com/.test(u.hostname)) out.push({ stage: 'url', ok: false, message: 'This does not look like an Apps Script deployment URL.' })
  else if (!/\/exec$/.test(u.pathname)) {
    const corrected = correctedExecUrl(raw)
    out.push({
      stage: 'url',
      ok: false,
      message: corrected
        ? 'This is the editor (/edit) or /dev test URL. Use the /exec URL from Deploy → Manage deployments — the corrected URL is ready below (one click).'
        : 'This is not a /exec deployment URL — copy the /exec link from Deploy → Manage deployments.',
      correctedUrl: corrected || undefined,
    })
  } else out.push({ stage: 'url', ok: true, message: 'URL shape looks right (/exec deployment).' })
  if (out.length && !out[0].ok) return out
  // Stage 2 — ping (transport reachability + access grant).
  try {
    const msg = await gdrive.testConnection(config)
    out.push({ stage: 'ping', ok: true, message: msg })
  } catch (e) {
    out.push({ stage: 'ping', ok: false, message: (e && e.userMessage) || (e && e.message) || 'The bridge did not answer the ping.' })
    return out
  }
  // Stage 2b — R92 §1.4: the SCRIPT VERSION echo. A deployed script older
  // than the current pre-filled one (or one that does not report a version
  // at all — every pre-R92 bridge) yields the typed re-paste warning. This
  // is a WARNING, never a failure: an older contract still works.
  try {
    const res = await fetchWithRetry(gdrive._url(config, { action: 'ping' }), { redirect: 'follow' }, { context: 'Google Drive version check', retries: 0 })
    const text = await res.text()
    const data = assertBridgeJson(text, { context: 'Google Drive version check' })
    const warn = bridgeVersionWarning(data)
    if (warn) out.push({ stage: 'version', ok: true, warning: true, message: warn })
    else out.push({ stage: 'version', ok: true, message: `Script version current (v${BRIDGE_SCRIPT_VERSION}).` })
  } catch { /* the ping already verified reachability; a version-check hiccup must not dead-end the wizard */ out.push({ stage: 'version', ok: true, message: 'Version check skipped (the ping already proved the contract).' }) }
  // Stage 3 — read contract (the vault file; absence is FINE and stated).
  try {
    const blob = await gdrive.download(config)
    out.push({ stage: 'read', ok: true, message: blob ? 'Read contract OK — a vault envelope is present.' : 'Read contract OK — no vault uploaded yet (the first sync creates it).' })
  } catch (e) {
    out.push({ stage: 'read', ok: false, message: (e && e.userMessage) || (e && e.message) || 'The read step failed.' })
  }
  return out
}

// --- R85 (§4): OAuth 2.0 authorization-code + PKCE (the primary Drive path) ----
// Owner rules (R42): authorization-code + PKCE (S256), redirect = chrome
// .identity.getRedirectURL(), scope drive.file, access_type=offline +
// prompt=consent on first connect, NO client secret in the package, refresh
// token encrypted device-only (it lives inside the sealed ucrypt:transport
// envelope — chrome.storage.local ciphertext keyed to THIS vault). The login
// is NEVER getAuthToken — launchWebAuthFlow only.

const OAUTH = {
  authBase: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenBase: 'https://oauth2.googleapis.com/token',
  driveBase: 'https://www.googleapis.com/drive/v3',
  uploadBase: 'https://www.googleapis.com/upload/drive/v3',
  scope: 'https://www.googleapis.com/auth/drive.file',
  vaultName: 'ucrypt-vault.enc',
}

function b64url(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return { verifier, challenge: b64url(digest) }
}

function oauthConfig(config) {
  const clientId = String((config && config.clientId) || '').trim()
  if (!clientId) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive transport: no OAuth client id configured', {
      userMessage: NEEDS_CLIENT_ID_STATUS,
    })
  }
  // R87 (§2.1d): pre-flight format validation — paste errors are caught
  // BEFORE any network round-trip, with a typed, actionable reason.
  const pre = validateClientIdFormat(clientId)
  if (!pre.ok) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, `Google Drive transport: client id rejected (${pre.reason})`, {
      userMessage: pre.message,
      recovery: { kind: `client_id_${pre.reason}`, title: pre.message, expectedRedirect: '', causes: [], fix: 'Step 2 of the card shows the exact shape of a Google OAuth client ID.' },
    })
  }
  const refreshToken = String((config && config.refreshToken) || '').trim()
  // R92 §1.2 — OWN-SECRET OAUTH MODE (CEO-directed mitigation): the user's
  // own client secret enables DIRECT sign-in on Google's confidential-client
  // rule. Security treatment: the field is a TRANSPORT_SECRET_FIELD (sealed
  // under the vault key at TRANSPORT_SAVE, device-only), it exists in worker
  // memory only during use (openTransportConfig transient copy), it is
  // dropped on lock (the credential key dies with the vault), it is cleared
  // on Disconnect (TRANSPORT_CLEAR removes the whole envelope), it is masked
  // input (type password), and it is excluded from every export by
  // construction (exports carry only ucrypt:vault + salt). The secret is
  // sent ONLY to Google's token endpoint over TLS. NO secret ships in the
  // package (the pack gate proves it statically).
  const clientSecret = String((config && config.clientSecret) || '').trim()
  return { clientId, refreshToken, clientSecret }
}

// R115 (the glitch hunt) — the clinical audit's typed ring contract:
// beginOAuth records its stage ladder (auth-window → code → exchange →
// probe → seal) through runConnectFlow's ring; a second Connect press while
// one window is open REUSES that window (single-flight) instead of firing a
// second launchWebAuthFlow Chrome would refuse — the intermittent wedge the
// owner saw is dead by construction.
async function beginOAuth(config, ring) {
  const { clientId } = oauthConfig(config)
  if (!chrome?.identity?.launchWebAuthFlow || !chrome.identity.getRedirectURL) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive transport: the identity flow API is unavailable', {
      userMessage: 'This browser does not expose chrome.identity.launchWebAuthFlow — use the bridge fallback (Advanced).',
    })
  }
  const redirect = chrome.identity.getRedirectURL()
  const { verifier, challenge } = await pkcePair()
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)))
  const u = new URL(OAUTH.authBase)
  u.searchParams.set('client_id', clientId)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('redirect_uri', redirect)
  u.searchParams.set('scope', OAUTH.scope)
  u.searchParams.set('access_type', 'offline')
  // S4 (the CEO's brief): THE ACCOUNT CHOOSER IS EXPLICIT — prompt carries
  // select_account next to consent, so Google ALWAYS offers the account
  // choice instead of silently using a previously-signed-in default.
  u.searchParams.set('prompt', 'consent select_account')
  u.searchParams.set('code_challenge', challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  u.searchParams.set('state', state)
  // R115 (the audit's suspect (a)): the window launch is TYPED — a window
  // loss/cancel/popup-block maps to auth_window_failed / auth_window_closed
  // with the one-click retry wording, and the stage lands on the evidence
  // ring. The raw engine string never reaches the user again.
  const finalUrl = await launchWindowTyped(
    () => chrome.identity.launchWebAuthFlow({ url: u.toString(), interactive: true }),
    { transport: 'gdrive', label: 'Google Drive' },
  )
  if (!finalUrl) {
    ring('code', { outcome: 'fail', error: 'auth_window_closed', message: 'The authorization window was closed before Google finished.' })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive transport: the authorization window closed', { userMessage: 'The authorization window was closed before Google finished — nothing was exchanged. Press Connect again (every retry starts clean).' })
  }
  const ru = new URL(finalUrl)
  if (ru.searchParams.get('state') !== state) {
    ring('code', { outcome: 'fail', error: 'state_mismatch', message: 'The authorization answer did not match the request (state mismatch) — nothing was exchanged.' })
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive transport: OAuth state mismatch', { userMessage: 'The authorization answer did not match the request (state mismatch) — nothing was exchanged. Press Connect again (every retry starts clean).' })
  }
  const err = ru.searchParams.get('error')
  if (err) {
    // R87 (§2.1c): TYPED Google error mapping — Google's own 400s become an
    // actionable recovery card (expected redirect URI, ranked causes, next
    // action). Never a raw error string.
    const recovery = typedGoogleError({ error: err, errorDescription: ru.searchParams.get('error_description') || '', redirect })
    ring('code', { outcome: 'fail', error: recovery.kind, message: recovery.title })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive transport: authorization refused (${recovery.kind})`, { userMessage: recovery.title, recovery })
  }
  const code = ru.searchParams.get('code')
  if (!code) {
    ring('code', { outcome: 'fail', error: 'no_code', message: 'Google did not return an authorization code.' })
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive transport: no authorization code in the answer', { userMessage: 'Google did not return an authorization code — retry the connection.' })
  }
  ring('code', { outcome: 'ok', error: '', message: 'Authorization code received.' })
  // R92 §1.2: the own-secret path — when the user supplied their client
  // secret it rides the token exchange (Google's confidential-client rule).
  // Without it Google answers invalid_request: client_secret is missing →
  // the typed two-path card (§1.3) names BOTH sanctioned paths inline.
  const { clientSecret } = oauthConfig(config)
  const body = new URLSearchParams({ client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect, grant_type: 'authorization_code' })
  if (clientSecret) body.set('client_secret', clientSecret)
  const res = await fetchWithRetry(OAUTH.tokenBase, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }, { context: 'Google OAuth token exchange', retries: 1, ring: { flow: 'connect', transport: 'gdrive', stage: 'exchange' }, okStatuses: [400, 401, 403] })
  const tok = await res.json().catch(() => null)
  if (!tok || tok.error) {
    // R87 (§2.1c): the token-exchange 400s get the same typed recovery card
    // as the front-of-flow errors. R92 §1.3: the error_description is passed
    // THROUGH so "client_secret is missing" lands on the dedicated two-path
    // card instead of the generic invalid_request fallback.
    const why = tok && (tok.error_description || tok.error)
    const recovery = typedGoogleError({ error: tok && tok.error, errorDescription: why, status: res.status, redirect })
    // R160 ARC A′ — the EXCHANGE-side evidence hook: the consent shape
    // (access_denied naming the unverified/Testing state) is the risk class
    // the proactive card rides. Same discipline as the refresh hook — typed,
    // non-blocking, never alters the recovery card.
    try {
      const cls = classifyTestingEvidence({
        error: (tok && tok.error) || '',
        errorDescription: why || '',
        status: res.status,
        stage: 'exchange',
      })
      if (cls) {
        await chrome.storage.local.set({
          [TESTING_EVIDENCE_KEY]: {
            at: Date.now(), stage: 'exchange', cls: cls.cls,
            error: String((tok && tok.error) || ''),
            errorDescription: String(why || '').slice(0, 2048),
            status: Number.isFinite(res.status) ? res.status : null,
          },
        })
      }
    } catch { /* the evidence hook never blocks the recovery path */ }
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive transport: token exchange failed (${why || res.status})`, {
      userMessage: recovery.title,
      recovery,
    })
  }
  if (!tok.refresh_token) {
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive transport: no refresh token in the answer', {
      userMessage: 'Google did not grant a refresh token — disconnect the app at myaccount.google.com/permissions and reconnect (UCrypt always asks with prompt=consent).',
    })
  }
  return { refreshToken: tok.refresh_token, redirect }
}

// R115 — the refresh SINGLE-FLIGHT (the audit's suspect (b)): two concurrent
// sync legs (the 15-min pull racing a manual push) used to fire two refresh
// POSTs against the same grant; Google answers both but a rate-limit window
// opens for nothing. The dedupe shares one flight per grant.
let _refreshFlight = { key: '', promise: null }

async function _refreshAccessToken(config, clientId, refreshToken, clientSecret) {
  const t0 = Date.now()
  const body = new URLSearchParams({ client_id: clientId, refresh_token: refreshToken, grant_type: 'refresh_token' })
  if (clientSecret) body.set('client_secret', clientSecret)
  try {
    const res = await fetchWithRetry(OAUTH.tokenBase, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    }, { context: 'Google OAuth refresh', retries: 1, ring: { flow: 'connect', transport: 'gdrive', stage: 'refresh' }, okStatuses: [400, 401, 403] })
    const tok = await res.json().catch(() => null)
    if (!tok || !tok.access_token) {
      const why = tok && (tok.error_description || tok.error)
      // R116 §2.1 (the refresh-path completion; the CEO's S2): the refresh
      // used to pass the error DESCRIPTION as the ERROR token — the typed
      // mapper then saw "the oauth client was disabled." as a bare kind and
      // fell to the untyped card, and the raw engine line rendered where a
      // typed card belongs. Both fields ride now, so Google's own words
      // land on the precise card (client_disabled / invalid_grant / …).
      // Cause-class precision (0.26): a disabled client NEVER renders as
      // "expired login" — each Google error word maps to its distinct card.
      const recovery = typedGoogleError({
        error: (tok && tok.error) || '',
        errorDescription: (tok && tok.error_description) || why || '',
        status: res.status,
        redirect: (chrome?.identity?.getRedirectURL) ? chrome.identity.getRedirectURL() : '',
      })
      const userMessage = /invalid_grant/i.test(String((tok && tok.error) || '') + ' ' + String((tok && tok.error_description) || ''))
        ? 'The saved Google grant expired or was revoked — reconnect Google Drive (the Connect button runs a fresh authorization; nothing else was changed).'
        : recovery.title
      // R123 §2.2 (the CEO's S2 — the glitch's signature, machine-verifiable):
      // the HTTP leg's own ring row carries only the status; the TYPED ring
      // row below names WHAT Google said — stage:'refresh' + the recovery
      // kind ('invalid_grant' / 'client_disabled' / …) in the diagnostics
      // export is the owner's S2 signature, provable without any console.
      try {
        await recordRing({
          flow: 'connect',
          transport: 'gdrive',
          stage: 'refresh',
          outcome: 'fail',
          httpKind: 'POST',
          status: Number.isFinite(res.status) ? res.status : null,
          elapsedMs: null,
          retryTier: 0,
          error: (recovery && recovery.kind) || (tok && tok.error) || 'auth',
          message: `Google refused the saved grant (${(tok && tok.error) || 'unknown error'}) — the recovery card names the fix.`,
        })
      } catch { /* the ring never perturbs the flow it observes */ }
      // R160 ARC A′ — THE TESTING-EVIDENCE HOOK (the proactive card's Layer-1
      // feed; lib/cloud/testing-card.js classifies, never throws). The raw
      // Google words persist ONCE per death so the card fires BEFORE the
      // next silent day-7 Testing death instead of after it. The hook rides
      // the recovery path and can never block or alter it.
      try {
        const cls = classifyTestingEvidence({
          error: (tok && tok.error) || '',
          errorDescription: (tok && tok.error_description) || why || '',
          status: res.status,
          stage: 'refresh',
        })
        if (cls) {
          await chrome.storage.local.set({
            [TESTING_EVIDENCE_KEY]: {
              at: Date.now(), stage: 'refresh', cls: cls.cls,
              error: String((tok && tok.error) || ''),
              errorDescription: String((tok && tok.error_description) || why || '').slice(0, 2048),
              status: Number.isFinite(res.status) ? res.status : null,
            },
          })
        }
      } catch { /* the evidence hook never blocks the recovery path */ }
      // R171 — the dead grant never serves from memory either: the caches
      // keyed to it die with it (the next mint starts clean).
      if (_isCustodyDeadGrant({ recovery, message: `Google Drive transport: token refresh failed (${why || res.status})` })) {
        _accessCache = { token: null, exp: 0, clientId: '', rt: '' }
        _fastAccountMemo.token = ''
        _fastAccountMemo.email = ''
      }
      throw Object.assign(new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive transport: token refresh failed (${why || res.status})`, {
        userMessage,
        recovery,
      }), { custodyDead: _isCustodyDeadGrant({ recovery, message: `Google Drive transport: token refresh failed (${why || res.status})` }) })
    }
    _accessCache = { token: tok.access_token, exp: Date.now() + (Number(tok.expires_in) || 3600) * 1000, clientId, rt: refreshToken }
    // R178 — R-178.2 THE RENEWAL WRITE-BACK: every silent refresh rewrites
    // the record's webToken (the ONE custody truth — one clock; the twin
    // clocks of E-42 die at the root). Fire-and-forget: the write-back never
    // breaks the refresh; the vault's writer proves the record identity
    // (transport id + the owning grant) BEFORE writing (fail-closed).
    try {
      notifyCustodyWriteBack({
        transportId: 'gdrive',
        token: String(tok.access_token),
        exp: Date.now() + (Number(tok.expires_in) || 3600) * 1000,
        via: 'offline-refresh',
        clientId,
        refreshToken,
      })
    } catch { /* the write-back never breaks the refresh */ }
    return _accessCache.token
  } finally {
    // the flight clears on settle — the next refresh starts clean
    _refreshFlight = { key: '', promise: null }
  }
}

// R124 §2 (D13) — exported for the pickup bridge (lib/transports/pickup-links.js):
// the hold uploads under the SAME token discipline the vault legs ride —
// one mint path, no parallel credential logic anywhere.
export async function ensureAccessToken(config, env = null) {
  // R119 §3.1 (law 0.32) — THE FAST RUNG AT THE ONE TOKEN SEAM: every API
  // leg (upload/download/test/delete/archive) resolves its bearer token
  // HERE. R174b — THE OFFLINE LAW (the corrected order's token choice):
  // the code lane's refresh token rides the SEALED envelope, so the sync
  // mints SILENTLY (no window, no secret, no browser session) — first the
  // fresh sealed webToken, then the offline refresh leg. getAuthToken is
  // RETIRED (the portability law — Brave/Helium have no browser Google
  // session). The refresh single-flight and the guard sit above the
  // oauthConfig() CONFIG refusal — the fast rung never fires it.
  //
  // R172 — THE CUSTODY-PRIORITY GATE (R-172.1, the one-truth law at the
  // mint): the fast leg answers for MORE than the authMode field — it
  // answers for LIVE CUSTODY. A record whose authMode was demoted by the
  // wizard's legacy select (the field's poison seat — docs/R172-CLOUD-MAP.md
  // P1) but whose sealed webToken/refreshToken still lives rides the SAME
  // fast legs: the mint consults (a) the live custody FIRST, (b) the stored
  // evidence, (c) the transport kind — never the pasted field alone. The
  // bridge mode is excluded (its legs never mint here).
  const _custodyPriority = !!(config && (
    String((config.webToken && config.webToken.token) || '').trim() ||
    String(config.refreshToken || '').trim()))
  if (isFastOrAppDataMode(config) || (_custodyPriority && !(config && config.authMode === 'bridge'))) {
    let tok = ''
    const prevWebTok = config && config.webToken && config.webToken.token
    const prevWebExp = config && config.webToken && Number(config.webToken.exp || 0)
    if (isFastOrAppDataMode(config) || !(config && config.clientSecret)) {
      try {
        // R166 (additive seam): env rides to the mint (the battery bounds the
        // window legs); the runtime callers pass no env — byte-true.
        tok = await fastAccessToken('gdrive', config, env)
        const nextWebTok = config && config.webToken && config.webToken.token
        const nextWebExp = config && config.webToken && Number(config.webToken.exp || 0)
        if (tok && config && config.webToken && nextWebTok && (nextWebTok !== prevWebTok || nextWebExp !== prevWebExp)) {
          try {
            notifyCustodyWriteBack({
              transportId: 'gdrive',
              token: String(nextWebTok),
              exp: Number(nextWebExp || (Date.now() + 3600 * 1000)),
              via: String(config.webToken.via || 'fast-silent-renew'),
              clientId: String(config.clientId || ''),
              refreshToken: String(config.refreshToken || ''),
              persistentSession: true,
              webToken: config.webToken,
            })
          } catch { /* writeback never blocks */ }
        }
      } catch { /* the sealed webToken expired or is absent — the offline leg answers next */ }
    }
    if (!tok) {
      // R174b — THE OFFLINE REFRESH LEG (the code lane's custody): the
      // refresh token lives in the sealed envelope (device-only ciphertext
      // keyed to THIS vault — the R85 law byte-true), the exchange rides the
      // public-client rule (client_id + refresh_token, NO secret) or the
      // guided clientSecret when present, and single-flight dedupes.
      const rt = String((config && config.refreshToken) || '').trim()
      const clientId = String((config && config.clientId) || '').trim() || sharedClientId('gdrive')
      const clientSecret = String((config && config.clientSecret) || '').trim()
      if (rt && clientId) {
        const key = clientId + '|' + rt
        if (_accessCache.token && Date.now() < _accessCache.exp - 30000 && _accessCache.clientId === clientId && _accessCache.rt === rt) {
          tok = _accessCache.token
          try {
            await recordRing({
              flow: 'connect', transport: 'gdrive', stage: 'fast-token',
              outcome: 'ok', httpKind: 'ladder', error: '',
              message: 'the offline custody served the cached access token (no window, no secret, no browser session)',
              rung: 'fast',
            })
          } catch { /* the ring never perturbs the flow it observes */ }
        } else {
          if (_refreshFlight.promise && _refreshFlight.key === key) {
            tok = await _refreshFlight.promise
          } else {
            const p = _refreshAccessToken(config, clientId, rt, clientSecret).catch(async (e) => {
              try {
                await recordRing({
                  flow: 'connect', transport: 'gdrive', stage: 'fast-token',
                  outcome: 'fail', httpKind: 'ladder', error: 'fast_token_refused',
                  message: 'the offline refresh was refused (' + String((e && e.message) || e).slice(0, 140) + ') — the web-auth window mints fresh on the next Connect (the honest limit: Google\u2019s web-client rule demands a shipped secret or a native client, both forbidden by the corrected order)',
                  rung: 'fast',
                })
              } catch { /* the ring never perturbs the flow it observes */ }
              // R176 — R-176.3 THE TYPED JOURNEY: the wrapped refusal rides
              // carry() — the original error's kind/userMessage/fingerprint
              // travel ON the wrapper (cause + carriedFrom + the carried
              // fingerprint), so the type that was born at the refresh leg
              // reaches every reader with its evidence intact. ONE
              // materialization, many readers.
              throw carry(Object.assign(new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive transport: the fast sign-in needs you again', {
                userMessage: materializeUserText(fastReconnectCard(config, String((e && e.message) || e))),
                recovery: (e && e.recovery) || undefined,
              }), { custodyDead: _isCustodyDeadGrant(e) }), { from: 'gdrive.ensureAccessToken.refresh-flight' })
            })
            _refreshFlight = { key, promise: p }
            tok = await p
            // the ok row rides AFTER the flight settles — the ring never
            // claims a success before the mint answers (the honest-telemetry
            // law: a refused leg records the refusal, never a premature ok).
            try {
              await recordRing({
                flow: 'connect', transport: 'gdrive', stage: 'fast-token',
                outcome: 'ok', httpKind: 'ladder', error: '',
                message: 'the sealed refresh token minted silently (the R174b offline law — no window, no secret)',
                rung: 'fast',
              })
            } catch { /* the ring never perturbs the flow it observes */ }
          }
        }
      }
    }
    if (!tok) {
      // R120 §2.5 — the typed reconnect card: the one-click fix (the web-auth
      // window mints fresh) and the guided fallback named — never a raw
      // engine error string on the sync surface (0.26/0.29). law 0.28 — the
      // typed refusal is evidence too.
      await recordRing({
        flow: 'connect', transport: 'gdrive', stage: 'fast-token',
        outcome: 'fail', httpKind: 'ladder', error: 'fast_token_refused',
        message: 'the sealed webToken is stale and the offline refresh refused — the web-auth window mints fresh on the next Connect', rung: 'fast',
      })
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive transport: the fast sign-in needs you again', {
        userMessage: fastReconnectCard(config),
      })
    }
    // R120 §2.5 — the multi-account guard: a token for a DIFFERENT account
    // than the connection's hint routes to the typed re-consent card.
    await fastAccountGuard(config, tok, env)
    // No token value ever rides a ring row — only the fact of the mint.
    await recordRing({
      flow: 'connect', transport: 'gdrive', stage: 'fast-token',
      outcome: 'ok', httpKind: 'ladder', error: '',
      message: 'the fast rung minted the token (the web-auth custody — the sealed webToken or the offline refresh)',
      rung: 'fast',
    })
    return tok
  }
  // R172 — THE ONE-TRUTH EVIDENCE GATE (R-172.1 at the guided refusal):
  // the guided-setup copy (NEEDS_CLIENT_ID_STATUS) is the LAST resort,
  // lawful ONLY for a config with NO OAuth evidence at all (a genuinely
  // empty guided form mid-setup). Every OAuth-evidence shape (an authMode,
  // a client id, a grant, a web token, the recorded rung —
  // looksLikeOAuthConfig) rides the ACTIVE method's typed card instead —
  // the connected-OAuth record can never hear guided-setup words again
  // (the field's E-26 defect class dies at the write, not at the render).
  if (looksLikeOAuthConfig(config)) {
    try {
      await recordRing({
        flow: 'connect', transport: 'gdrive', stage: 'token-gate',
        outcome: 'fail', httpKind: 'ladder', error: 'oauth_evidence_guided_refusal_refused',
        message: 'the guided-setup refusal was refused — the record carries OAuth evidence (the one-truth gate); the active method\u2019s typed card rides instead',
        rung: 'oauth',
      })
    } catch { /* the ring never perturbs the flow it observes */ }
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive transport: the saved sign-in needs you again', {
      userMessage: materializeUserText(fastReconnectCard(config)),
    })
  }
  const { clientId, refreshToken } = oauthConfig(config)
  if (!refreshToken) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive transport: no OAuth connection yet', {
      userMessage: 'Connect Google Drive first (the Connect button runs the authorization).',
    })
  }
  if (_accessCache.token && Date.now() < _accessCache.exp - 30000 && _accessCache.clientId === clientId && _accessCache.rt === refreshToken) {
    return _accessCache.token
  }
  // R115 — the single-flight refresh: a concurrent caller shares the flight.
  const { clientSecret } = oauthConfig(config)
  const key = clientId + '|' + refreshToken
  if (_refreshFlight.promise && _refreshFlight.key === key) return _refreshFlight.promise
  const p = _refreshAccessToken(config, clientId, refreshToken, clientSecret)
  _refreshFlight = { key, promise: p }
  return p
}

let _accessCache = { token: null, exp: 0, clientId: '', rt: '' }

// ── R137 §9 (the G72 extension — the Drive forensic battery) ─────────────
//
// The connect-path hardening the fixtures proved missing, added at the root:
//
//   driveApiFetch      — ONE authenticated-leg seam: the bearer rides here,
//                        a mid-session 401 (Google revoked the access token
//                        before its expiry) replays ONCE through the
//                        single-flight refresh — never a storm, never a dead
//                        card (fixture F2).
//   driveBodyPrefix    — a bounded (4 KB) body read so the provider's OWN
//                        reason words type the failure.
//   driveApiError      — the typed body classification: a 403 whose body
//                        names the storage quota is a QUOTA error with the
//                        provider-console card (F3); a 403 naming
//                        insufficient permissions is the SCOPE card (F7);
//                        451 keeps the region card (F11, in http.js);
//                        everything else falls through the SAME generic
//                        builder — the wording never drifts.
//   driveCapacityPrecheck — the pre-flight capacity refusal BEFORE a write
//                        (F12).
//   _resetGdriveAuthForTest — the battery seam (never used at runtime).

/** Read at most a 4 KB prefix of the response body (the bounded read). */
async function driveBodyPrefix(res) {
  try {
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader()
      const chunks = []
      let received = 0
      while (received < 4096) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
        received += value.length
      }
      let body = ''
      try { body = chunks.length ? new TextDecoder().decode(concatU8(chunks, received)) : '' } catch { body = '' }
      if (received >= 4096) try { await reader.cancel() } catch { /* stream done */ }
      if (body) return body
    }
    return (await res.text()) || ''
  } catch { return '' }
}

function concatU8(chunks, total) {
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) { out.set(c, off); off += c.length }
  return out
}

/** The typed 403 card: the provider's storage quota is exhausted (F3). */
const DRIVE_QUOTA_CARD = {
  kind: 'quota_exceeded',
  title: "The provider's storage quota is exhausted (the provider refused the write).",
  causes: [
    'The Drive account is at its storage limit — the write was refused, nothing was corrupted.',
    'The queue keeps every pending write until space is freed.',
  ],
  fix: 'Free space at the provider (the button opens the provider storage console), then press Retry now — the sync continues where it stopped.',
  consoleLink: 'https://one.google.com/storage/management',
  consoleLabel: 'Open provider storage console',
  retryLabel: 'Retry now',
}

/** The typed 403 card: the grant lacks the scope this write needs (F7). */
const DRIVE_SCOPE_CARD = {
  kind: 'scope_insufficient',
  title: 'The connection is missing a Google permission (the grant was issued with a narrower scope).',
  causes: [
    'The saved grant covers fewer permissions than this write needs (a scope downgrade — an account/policy change on the provider side).',
    'Nothing was written — the vault is intact and no partial state exists.',
  ],
  fix: 'Press Connect to re-authorize with the full permission set (the drive.file scope — one click; UCrypt always asks with consent so the new grant is complete).',
  scope: 'https://www.googleapis.com/auth/drive.file',
  retryLabel: 'Re-authorize',
}

/** Map one API-leg response to its TYPED SyncError (the fall-through rides
 * the shared builder so the generic wording stays identical).
 * R178 — R-178.1 THE THENABLE'S BIRTHPLACE DIES HERE (the map's Adjudication
 * 1, machine-proven by tests/r178-ring-probe.mjs V4 — the field's exact words
 * reproduced with real legs; the ring's frame chain testified): these two
 * seats were the ONLY `throw <async-call>` seats in the tree —
 * `responseToSyncError` returns a PROMISE (statusToSyncError is async), so
 * `throw responseToSyncError(...)` rejected the awaiting lane with the
 * PROMISE itself and the typed card (Google's own words + the recovery
 * buttons) rode inside the never-awaited promise, unreachable. The field's
 * every terminal Drive failure (E-37/E-43/E-44's "a thenable (Promise)
 * arrived where words belong") was born HERE. The await-cure: the builder
 * is awaited FIRST, then the REAL SyncError is thrown — the typed verdict
 * reaches the eye, and a promise can never again ride a rejection from
 * this house's own hand. */
async function driveApiError(res, context, op = '') {
  if (res.status === 403) {
    const body = await driveBodyPrefix(res)
    if (/storageQuotaExceeded|quotaExceeded|storage\.?quota/i.test(body)) {
      throw new SyncError(SYNC_ERROR_KINDS.QUOTA, `${context} failed: 403 — the provider storage quota is exceeded`, {
        status: 403,
        userMessage: DRIVE_QUOTA_CARD.title + ' Free space (or switch transports) — the queue keeps every write.',
        recovery: DRIVE_QUOTA_CARD,
      })
    }
    if (/insufficientPermissions|insufficientFilePermissions|appNotAuthorizedToFile|domainPolicy/i.test(body)) {
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, `${context} failed: 403 — the grant lacks the scope this operation needs`, {
        status: 403,
        userMessage: DRIVE_SCOPE_CARD.title + ' Press Connect to re-authorize with the full permission set — nothing was written.',
        recovery: DRIVE_SCOPE_CARD,
      })
    }
    throw await responseToSyncError(res, context, op, body)
  }
  throw await responseToSyncError(res, context, op)
}

/**
 * THE authenticated Drive-API leg (R137 §9 — F1/F2 at the root): every
 * api-mode leg resolves its bearer HERE; a mid-session 401 replays ONCE
 * through the single-flight refresh. The statuses the body classifier owns
 * (401/403/451) arrive response-shaped so the typed card is built from the
 * provider's own words; every other terminal status keeps the generic
 * builder's exact behavior.
 */
/**
 * R174b — THE FAST 401-RECOVERY WRAPPER (corrected): the native
 * clear-and-reprompt wrapper is RETIRED (the portability law). The ONE
 * bounded recovery: the sealed refresh token re-mints the bearer silently
 * (no window, no secret) — one leg; the implicit lane's fresh webToken
 * replays ONCE (the exactly-once law holds: driveApiFetch replays only when
 * token2 differs from the failed token). Bounded by construction: one
 * re-mint, one replay — never a storm.
 */
async function fast401Recover(config, failedToken = '') {
  // Invalidate any cached webToken if it is the exact token that just 401'd
  if (config && config.webToken && failedToken && String(config.webToken.token || '') === String(failedToken)) {
    config.webToken = { ...config.webToken, exp: 0 }
  }
  const rt = String((config && config.refreshToken) || '').trim()
  const clientId = String((config && config.clientId) || '').trim() || sharedClientId('gdrive')
  const clientSecret = String((config && config.clientSecret) || '').trim()
  if (rt && clientId) {
    try {
      const tok = await _refreshAccessToken(config, clientId, rt, clientSecret)
      try {
        await recordRing({
          flow: 'sync', transport: 'gdrive', stage: 'fast-401-recover',
          outcome: 'ok', httpKind: 'identity', status: 401, retryTier: 1,
          error: 'token_recovered_once',
          message: 'the sealed refresh token re-minted the bearer (the R174b offline custody — one leg, no window, no secret)',
        })
      } catch { /* the ring never perturbs the flow it observes */ }
      return tok
    } catch {
      try {
        await recordRing({
          flow: 'sync', transport: 'gdrive', stage: 'fast-401-recover',
          outcome: 'fail', httpKind: 'identity', status: 401, retryTier: 1,
          error: 'offline-refresh-refused',
          message: 'the offline re-mint refused — the webToken replay is the last leg (the exactly-once law)',
        })
      } catch { /* the ring never perturbs the flow it observes */ }
    }
  }
  if (config && webTokenFresh(config.webToken) && String(config.webToken.token || '') !== String(failedToken || '')) {
    try {
      await recordRing({
        flow: 'sync', transport: 'gdrive', stage: 'fast-401-recover',
        outcome: 'ok', httpKind: 'identity', status: 401, retryTier: 1,
        error: 'web_token_replay',
        message: 'the fresh web-auth token rides the ONE replay (the second machinery; bounded, exactly once)',
      })
    } catch { /* the ring never perturbs the flow it observes */ }
    return String(config.webToken.token)
  }
  // Evict stale Chrome identity token if applicable and attempt silent Lane C re-mint
  try {
    if (failedToken && typeof chrome !== 'undefined' && chrome.identity && typeof chrome.identity.removeCachedAuthToken === 'function') {
      await new Promise((resolve) => {
        try { chrome.identity.removeCachedAuthToken({ token: failedToken }, () => resolve()) } catch { resolve() }
      })
    }
    const mint = await mintGdriveLaneCToken({ force: true })
    if (mint && mint.ok && mint.token && String(mint.token) !== String(failedToken || '')) {
      const freshWt = webTokenFromMint({ token: mint.token, expiresIn: 3600 })
      if (config && typeof config === 'object' && freshWt) {
        config.webToken = freshWt
        try { notifyCustodyWriteBack({ webToken: freshWt }) } catch { /* writeback never blocks */ }
      }
      try {
        await recordRing({
          flow: 'sync', transport: 'gdrive', stage: 'fast-401-recover',
          outcome: 'ok', httpKind: 'identity', status: 401, retryTier: 1,
          error: 'lane_c_remint',
          message: 'silent Lane C re-minted a fresh bearer after evicting the revoked 401 token',
        })
      } catch { /* the ring never perturbs the flow it observes */ }
      return String(mint.token)
    }
  } catch { /* Lane C unavailable or refused */ }
  try {
    await recordRing({
      flow: 'sync', transport: 'gdrive', stage: 'fast-401-recover',
      outcome: 'fail', httpKind: 'identity', status: 401, retryTier: 1,
      error: 'no-recovery-leg',
      message: 'no recovery leg answered (the offline re-mint refused, no fresh webToken) — the request fails with its typed verdict, never an unsigned retry',
    })
  } catch { /* the ring never perturbs the flow it observes */ }
  return ''
}

async function driveApiFetch(config, url, init = {}, cfg = {}) {
  const cfg2 = { ...cfg, okStatuses: [...(Array.isArray(cfg.okStatuses) ? cfg.okStatuses : []), 401, 403, 451] }
  const token = await ensureAccessToken(config)
  let res = await fetchWithRetry(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` } }, cfg2)
  if (res && res.status === 401) {
    // F2 — the access token died before its expiry. Invalidate, refresh
    // (single-flight), replay ONCE. Audit row rides the ring (law 0.28).
    _accessCache = { token: null, exp: 0, clientId: '', rt: '' }
    let token2 = ''
    if (isFastOrAppDataMode(config)) {
      token2 = await fast401Recover(config, token)
    } else {
      if (config && config.webToken && String(config.webToken.token || '') === String(token)) {
        config.webToken = { ...config.webToken, exp: 0 }
      }
      try { token2 = await ensureAccessToken(config) } catch (e) { throw e }
    }
    try {
      await recordRing({
        flow: 'sync', transport: 'gdrive', stage: 'replay-401',
        outcome: token2 && token2 !== token ? 'ok' : 'fail', httpKind: String(init.method || 'GET'),
        status: 401, retryTier: 1,
        error: 'token_replayed_once',
        message: 'a mid-session 401 was replayed once through the single-flight refresh (bounded — never a storm)',
      })
    } catch { /* the ring never perturbs the flow it observes */ }
    if (token2 && token2 !== token) {
      res = await fetchWithRetry(url, { ...init, headers: { ...(init.headers || {}), Authorization: `Bearer ${token2}` } }, cfg2)
    }
  }
  if (!res.ok) await driveApiError(res, cfg.context || 'Google Drive request', cfg.op || '')
  return res
}

/**
 * R164 Arc E — THE DRIVE SMOKE (the lab half of S128): connect (the fast
 * token seam resolves the bearer) → write a test file INSIDE appDataFolder
 * → read it back → byte-compare → delete → the receipt. Every leg rides
 * driveApiFetch (the bearer seam + the R164 401 wrapper). The receipt
 * carries NO token and NO personal data — the honest, printable proof.
 */
export async function driveSmokeTest(config, { now = () => new Date().toISOString() } = {}) {
  const cfg = (config && config.authMode) ? config : { authMode: 'fast' }
  const at = String(now())
  const name = 'ucrypt-smoke-' + at.replace(/[^0-9A-Za-z]/g, '').slice(0, 20) + '.json'
  const body = JSON.stringify({ kind: 'ucrypt-drive-smoke', at, note: 'UCrypt private-folder smoke test' })
  // R165 Arc E — the receipt carries every HTTP status (the ladder's Rung 4
  // prints them; the fields ride ADDITIVELY — the R164 receipt shape stays).
  const receipt = { name, wrote: false, bytes: body.length, readBack: '', match: false, deleted: false, at, statuses: { write: null, read: null, delete: null } }
  const boundary = 'ucrypt-smoke-' + b64url(crypto.getRandomValues(new Uint8Array(12)))
  const meta = JSON.stringify({ name, parents: ['appDataFolder'] })
  const multipart = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n${body}\r\n--${boundary}--`
  const up = await driveApiFetch(cfg, `${OAUTH.uploadBase}/files?uploadType=multipart&fields=id`, {
    method: 'POST',
    headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
    body: multipart,
  }, { context: 'Google Drive smoke write', retries: 1, op: 'smoke-write' })
  const upJson = await up.json().catch(() => null)
  const fileId = upJson && upJson.id
  receipt.wrote = !!(up.ok && fileId)
  receipt.statuses.write = up ? up.status : null
  if (fileId) {
    const back = await driveApiFetch(cfg, `${OAUTH.driveBase}/files/${fileId}?alt=media`, {}, { context: 'Google Drive smoke read', retries: 1, op: 'smoke-read' })
    receipt.statuses.read = back ? back.status : null
    receipt.readBack = await back.text().catch(() => '')
    receipt.match = receipt.readBack === body
    const del = await driveApiFetch(cfg, `${OAUTH.driveBase}/files/${fileId}`, { method: 'DELETE' }, { context: 'Google Drive smoke delete', retries: 1, op: 'smoke-delete' })
    receipt.deleted = !!(del && (del.status === 204 || del.ok))
    receipt.statuses.delete = del ? del.status : null
  }
  return receipt
}

/**
 * F12 — THE CAPACITY PRE-FLIGHT: when the provider REPORTS its quota, a
 * push that would not fit is refused HERE — before any write — with the
 * typed storage_full card. A pre-flight that cannot READ the quota never
 * blocks a lawful push (best-effort by contract).
 */
export async function driveCapacityPrecheck(config, { fetchImpl = null, incomingBytes = 0 } = {}) {
  const f = fetchImpl || fetchWithRetry
  let j = null
  try {
    const token = await ensureAccessToken(config)
    const res = await f(OAUTH.driveBase + '/about?fields=storageQuota', { headers: { Authorization: `Bearer ${token}` } }, { context: 'Google Drive capacity pre-flight', retries: 0 })
    if (res && res.ok) j = await res.json().catch(() => null)
  } catch { j = null } // a pre-flight hiccup must never dead-end the sync
  const q = (j && j.storageQuota) || null
  const limit = Number(q && q.limit) || 0
  const usage = Number(q && (q.usageInDrive != null ? q.usageInDrive : q.usage)) || 0
  if (!limit) return { ok: true, checked: false } // the provider named no limit — nothing to refuse on
  if (usage + Math.max(0, Number(incomingBytes) || 0) > limit) {
    throw new SyncError(SYNC_ERROR_KINDS.QUOTA, `Google Drive storage is full (pre-flight: ${usage} of ${limit} bytes used, ${Math.max(0, Number(incomingBytes) || 0)} incoming)`, {
      status: 403,
      userMessage: "The provider's storage is full — the vault was NOT written. Free space at the provider (or pick another transport); the queue keeps every write.",
      recovery: {
        kind: 'storage_full',
        title: "The provider's storage is full (refused before the write — pre-flight).",
        causes: [
          'The Drive account is at its storage limit — a push would fail mid-write.',
          'Nothing was written and nothing was lost — the local vault is intact.',
        ],
        fix: 'Free space at the provider (the button opens Google storage management), or switch transports — then press Sync again.',
        consoleLink: 'https://one.google.com/storage/management',
        consoleLabel: 'Manage provider storage',
        retryLabel: 'Retry now',
      },
    })
  }
  return { ok: true, checked: true, usage, limit }
}

/** R137 §9 battery seam — a fresh auth state per battery case (additive;
 * the extension runtime never calls it). */
export function _resetGdriveAuthForTest() {
  _accessCache = { token: null, exp: 0, clientId: '', rt: '' }
  _refreshFlight = { key: '', promise: null }
  _fastAccountMemo.token = ''
  _fastAccountMemo.email = ''
}

// R119 §3.1 — the fast rung drives the SAME Drive API legs as the oauth
// mode (the only seam that differs is token resolution — ensureAccessToken
// branches on the mode above). 'bridge' and the legacy authMode-less
// configs keep the bridge path EXACTLY as it was.
// R124 §2 (D13) — exported for the pickup bridge: the hold exists on the
// OAuth/fast rungs only; the bridge rung is honestly unsupported there.
export function isFastOrAppDataMode(config) {
  if (!config || typeof config !== 'object') return false
  if (config.authMode === 'bridge') return false
  if (config.authMode === 'fast' || String(config.signinMode || '').trim() === 'fast') return true
  if (config.webToken && typeof config.webToken === 'object' && String(config.webToken.token || '').trim()) return true
  const lane = String(config.lane || '').trim()
  if (lane === 'U' || lane === 'C' || lane === 'S') return true
  const cid = String(config.clientId || '').trim()
  if (cid && (isLaneUClientId(cid) || isLaneCClientId(cid) || isSpineClientId(cid))) return true
  return false
}

export function isApiMode(config) {
  if (!config || typeof config !== 'object') return false
  const m = config.authMode
  if (m === 'bridge') return false
  return m === 'oauth' || m === 'fast' || looksLikeOAuthConfig(config)
}

export function looksLikeOAuthConfig(config) {
  if (!config || typeof config !== 'object') return false
  if (config.authMode === 'bridge') return false
  if (config.authMode === 'oauth' || config.authMode === 'fast') return true
  const sig = String(config.signinMode || '').trim()
  if (sig === 'fast' || sig === 'guided') return true
  const hasClient = String(config.clientId || '').trim().length > 0
  const hasGrant = String(config.refreshToken || '').trim().length > 0
  const hasWebToken = !!(config.webToken && typeof config.webToken === 'object' && String(config.webToken.token || '').trim())
  return hasClient || hasGrant || hasWebToken
}

// R169 — THE RETIRED-CLIENT GUARD, TWO-LANE AWARE (the fast-inherit law's
// ONE refusal, amended): the inheritance NEVER resurrects a probe-proven
// dead client (the dead TWO: 816184664980-d8sooe… deleted, 849241523153-…
// deleted), AND it never lets the LANE C client (1047722433028-…, the
// Chrome silent lane's own seat) ride the WINDOW lane — each lane keeps its
// own client (O-1/O-2). A dead or wrong-lane saved client is dropped with a
// typed ring row and the LANE U client rides instead.
function resolveFastClient(config, ring) {
  const saved = String((config && config.clientId) || '').trim()
  if (saved && (isDeadClientId(saved) || isLaneCClientId(saved))) {
    try {
      ring('web-fallback', {
        rung: 'fast',
        outcome: 'ok',
        message: isDeadClientId(saved)
          ? 'the saved client was RETIRED (the R174 guard — probe-proven deleted) — the Lane U client rides instead'
          : 'the saved client is the LANE C client (the Chrome silent lane\u2019s own seat) — it cannot ride the window lane; the Lane U client rides instead',
      })
    } catch { /* the ring never blocks the flow */ }
    return sharedClientId('gdrive')
  }
  return saved || sharedClientId('gdrive')
}

// R119 §3.1 — the fast probe's typed refusal cards: each names the honest
// route to the guided rung — never a dead end, never a raw error string.
const FAST_PROBE_CARDS = {
  'client-id-absent': 'The shared Google sign-in is not configured on this build yet — the guided rung (your own OAuth app) always works.',
  'launchWebAuthFlow-unavailable': 'This browser does not expose chrome.identity.launchWebAuthFlow — the guided rung (your own OAuth app) always works.',
}

// R120 §2.5 — the typed card for a non-interactive refresh refusal: the
// one-click interactive re-consent (the Connect button) is the fix, and the
// guided rung is the fallback that always works (0.29 — the fix button on
// the surface that named the problem).
// R171 — THE LANE-AWARE + SPINE-AWARE CURE (the E-24 law): the card is no
// longer a constant. (1) LANE-AWARE: it names the lane that actually served
// or speaks neutrally — never "Chrome's one-click" when the machine rode
// the window lane in Helium/Brave. (2) SPINE-AWARE: once the refresh
// custody exists, the card reflects the new truth — the reconnection is
// silent and automatic, and this card appears ONLY when even the refresh
// grant failed. The words live in lib/cloud/spine.js (fastReconnectCardWords)
// so the battery pins them and the i18n layer carries the ×3 equivalents.
// R176 — R-176.2 THE HONEST EXPIRY: the card rides the three-state custody
// verdict — the bank's OWN webToken evidence (the same custody the lanes
// read, never a form's shadow) decides between NO KEY BANKED / EXPIRED AT
// HH:MM / MINT REFUSED. The six-minute lie (E-36: "expired" for a token
// minted minutes earlier) is structurally unreachable from this seat.
function fastReconnectCard(config, googleWords = '') {
  const facts = spineCustodyFacts(config)
  const wt = (config && config.webToken && typeof config.webToken === 'object') ? config.webToken : null
  return fastReconnectCardWords({
    servedLane: String((config && config.lane) || ''),
    hasRefreshCustody: facts.hasRefreshCustody && facts.spineArmed,
    googleWords,
    // R-176.2 — the bank's own evidence rides: the webToken custody facts
    // and the mint refusal's typed reason (when the caller carried one in
    // googleWords' typed prefix, the verdict machine reads it separately).
    ...(wt ? { webToken: { token: typeof wt.token === 'string' ? wt.token : '', exp: Number(wt.exp), at: Number(wt.at) } } : {}),
    ...(googleWords && /refus|invalid|denied|expired_grant|revoked/i.test(String(googleWords)) ? { mintRefusedReason: String(googleWords).slice(0, 140) } : {}),
  })
}

// R171 — THE CUSTODY-DEATH TEST (the invalid_grant contract): Google's
// refresh endpoint answered invalid_grant — the stored grant is DEAD (it
// can never mint again). The caller (the worker's sync paths) reads this
// typed flag off the thrown SyncError and clears the stored custody
// (lib/vault.js clearTransportGrants) — the dead grant never lingers, and
// the typed one-click reconnect card rides (never a silent dead grant).
function _isCustodyDeadGrant(e) {
  const recoveryKind = String((e && e.recovery && e.recovery.kind) || '')
  const words = String((e && e.message) || '') + ' ' + String((e && (e.userMessage) || ''))
  return /invalid_grant/i.test(recoveryKind) || /invalid_grant/i.test(words)
}

// ── R120 §2.5 — THE MULTI-ACCOUNT GUARD (the fast rung, gdrive) ────────────
//
// LAW (order §2.5): the picker's account choice is respected — at connect the
// chosen account is LEARNED (the accountHint, a device-local non-secret
// email the user's own choice produced) and mid-life a token minted for a
// DIFFERENT account routes to the typed re-consent card — never a silent
// wrong-account sync. The guard verifies each freshly minted token's account
// against the hint and MEMOIZES by token string (one small about-call per
// fresh mint — Chrome's re-mints carry a new token, its cached tokens skip).
//
// PURE-DEGREE: env = { fetchImpl, ring } injects the seams (the battery
// drives the guard directly); defaults ride the module's own fetch/recordRing.
const _fastAccountMemo = { token: '', email: '' }

export async function fastAccountGuard(config, token, env = null) {
  const fetchImpl = (env && env.fetchImpl) || fetchWithRetry
  const ring = (env && env.ring) || recordRing
  const tok = String(token || '')
  if (!tok) return
  if (_fastAccountMemo.token === tok) return // this exact token was already verified
  try {
    const u = OAUTH.driveBase + '/about?fields=user'
    const res = await fetchImpl(u, { headers: { Authorization: `Bearer ${tok}` } }, { context: 'Google Drive about', retries: 0 })
    if (!res || !res.ok) return // the API legs type their own failures — the guard never invents one
    const j = await res.json().catch(() => null)
    const email = String((j && j.user && j.user.emailAddress) || '').trim().toLowerCase()
    if (!email) return
    _fastAccountMemo.token = tok
    _fastAccountMemo.email = email
    const hint = String((config && config.accountHint) || '').trim().toLowerCase()
    if (hint && hint !== email) {
      // law 0.28 — the ring names the rung AND the stage; no account value rides.
      try {
        await ring({
          flow: 'connect', transport: 'gdrive', stage: 'fast-account',
          outcome: 'fail', httpKind: 'ladder', error: 'account-switched',
          message: 'the fast token answers for a different Google account than the connection was won with — the typed re-consent card routes instead of a silent wrong-account sync',
          rung: 'fast',
        })
      } catch { /* the ring never throws into its caller */ }
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive transport: the fast sign-in answered for a different Google account', {
        userMessage: FAST_ACCOUNT_SWITCHED_CARD,
      })
    }
  } catch (e) {
    if (e instanceof SyncError) throw e
    // network/parse trouble is NOT an account switch — the guard stays silent
    // and the actual API leg types its own failure.
  }
}

const FAST_ACCOUNT_SWITCHED_CARD = 'Chrome signed you in with a different Google account than before. Press Connect to sign in with the account this connection uses (one click) — or reconnect with the account you want.'

async function driveFindVaultFile(config) {
  // R137 §9: the list rides driveApiFetch (the bearer seam + the one-shot
  // 401 replay + the typed 403/451 cards) — the success contract is
  // unchanged (first file or null).
  const u = new URL(OAUTH.driveBase + '/files')
  u.searchParams.set('q', `name = '${OAUTH.vaultName}' and trashed = false`)
  u.searchParams.set('fields', 'files(id,name,size,modifiedTime)')
  u.searchParams.set('pageSize', '5')
  // R164 Arc B (G183's map, the folder seam): the FAST rung's scope is
  // drive.appdata — it can only see the appDataFolder space. The guided
  // rung keeps its visible-space semantics byte-true.
  if (isFastOrAppDataMode(config)) u.searchParams.set('spaces', 'appDataFolder')
  const res = await driveApiFetch(config, u.toString(), {}, { context: 'Google Drive list', retries: 1 })
  const j = await res.json().catch(() => null)
  return j && Array.isArray(j.files) && j.files.length ? j.files[0] : null
}

export const gdrive = {
  name: 'Google Drive',
  // R164 Arc E — the smoke leg rides the transport object (the UI seam).
  _smoke: driveSmokeTest,
  fields: [
    { key: 'authMode', label: 'Connection type', type: 'select', options: ['fast', 'oauth', 'bridge'], default: 'oauth', help: 'Direct sign-in (paste your secret) or the no-secret Bridge. OAuth connects with your Google account via PKCE; Bridge (Advanced) uses a user-deployed Apps Script web app instead.' },
    // R172 — THE RECREATE-CONSOLE TRUTH (the CEO's decree: recreate the Console
    // part + a new extension ID): the FIRST-CLASS client type is "Chrome
    // extension" with the Item ID equal to this extension's own ID — Google
    // pairs the chromiumapp.org redirect automatically and treats the client
    // as public (no secret, no bridge). The Web-application type stays
    // sanctioned (its redirect URI + optional secret ride below).
    { key: 'clientId', label: 'Google OAuth client ID', type: 'text', placeholder: '1234567890-abc.apps.googleusercontent.com', oauthField: true, help: 'From Google Cloud Console → APIs & Services → Credentials → Create credentials → OAuth client ID (type: Chrome extension, Item ID = this extension\u2019s own ID — shown on the Connect card and in chrome://extensions). A "Web application" client with the redirect URI shown below when you connect also works.' },
    // R92 §1.2 — OWN-SECRET MODE: the exact honesty the CEO ordered. The
    // secret is sealed in the vault on this device, never synced, never
    // logged, never exported, cleared on Disconnect; without it the typed
    // two-path card explains the Bridge alternative.
    // R109 §3.2(c) — the CEO's S2: popup ENTRY (law 0.24) — the guided setup
    // never renders this as a fixed inline password field; a button opens
    // the credential popup with its one-sentence why.
    { key: 'clientSecret', label: 'Your client secret (for direct sign-in — optional)', type: 'password', placeholder: 'GOCSPX-… (paste ONLY if you choose direct sign-in)', oauthField: true, popupEntry: true, help: OWN_SECRET_HELP },
    { key: 'refreshToken', label: 'Google grant (stored sealed, device-only)', type: 'password', oauthField: true, help: 'Filled by the Connect button. Sealed inside the transport envelope — it never leaves this device in plaintext.' },
    { key: 'scriptUrl', label: 'Apps Script Web App URL (Advanced — bridge fallback)', type: 'url', placeholder: 'https://script.google.com/macros/s/AKfy…/exec', bridgeField: true, help: 'From Apps Script → Deploy → New deployment → Web app. Copy the /exec URL.' },
    { key: 'secret', label: 'Bridge secret (Advanced — bridge fallback)', type: 'password', placeholder: 'a long random string', bridgeField: true, help: 'Must match the SECRET inside your script. Sent over HTTPS, checked by the script.' },
  ],

  _url(config, params) {
    const u = validatedScriptUrl(config)
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v)
    if (config.secret) u.searchParams.set('secret', config.secret)
    return u.toString()
  },

  async connectOAuth(config) {
    // R115 — the connect single-flight + the evidence-ring stage ladder
    // (auth-window → code → exchange → seal). A second press while a window
    // is open shares that window instead of firing a second flow.
    const res = await runConnectFlow('gdrive', (ring) => beginOAuth(config, ring))
    // A fresh grant invalidates the cached access token (the cache is keyed
    // by the refresh token, so this is belt-and-braces hygiene — the audit's
    // suspect (b) tail: no stale token ever rides a new grant).
    _accessCache = { token: null, exp: 0, clientId: '', rt: '' }
    return res
  },

  // R119 §3.1 (law 0.32) — THE FAST RUNG'S CONNECT (R169 — THE TWO-LANE
  // PRESS): LEG 0 the CHROME SILENT LANE (getAuthToken {interactive:false},
  // bounded, zero windows — the CEO's reboot-persistence lane; retained by
  // the R169 CSA amendment typed openly against the R174b ban), falling
  // through THE MOMENT it is unavailable (a wedged lane is bounded at 8 s —
  // never a dead press, never a hostage press). LEG 1 the UNIVERSAL LANE's
  // code mint (launchWebAuthFlow + the Web-application client,
  // response_type=code, PKCE S256, access_type=offline,
  // prompt=consent select_account — the refresh token arrives on the first
  // grant and rides the SEALED envelope). LEG 2 the canonical IMPLICIT lane
  // rides ONCE — and ONLY for the exchange-rule refusals (the client-rule
  // classes), never for a cancellation, a timeout, or a mismatch: those
  // keep their typed cards. The result NAMES the lane that served
  // (lane:'C' | 'U', via:'chrome-silent' | 'web-auth-code' |
  // 'web-auth-flow') so the card prints the truth. env (the battery seam):
  // { chromeLike, clientId, webAuthTimeoutMs, launchImpl, stateImpl,
  //   randomImpl, fetchImpl, setTimer, clearTimer, now, laneCDisabled,
  //   laneCImpl, laneCTimeoutMs, laneCForce }.
  async connectFast(config, env = null) {
    return runConnectFlow('gdrive', async (ring) => {
      // law 0.28 — the ladder's flows record their rungs.
      ring('rung', { rung: 'fast' })
      const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
      // R174b — the availability probe (no window, no session, NO
      // getAuthToken): the web-auth machinery + the factory client pinned.
      let probe = await probeGdriveFast((env && (env.chromeLike || env.clientId != null))
        ? { chromeLike: env && env.chromeLike, clientId: env && env.clientId }
        : {})
      ring('probe', {
        rung: 'fast',
        outcome: probe.ok ? 'ok' : 'fail',
        error: probe.ok ? '' : String(probe.kind || '').slice(0, 48),
        message: probe.ok
          ? 'the web-auth machinery is present — the fast rung lights'
          : 'the fast rung is unavailable: ' + String(probe.kind),
      })
      // R174 — THE RESOLUTION IS HOISTED (one seat, every consumer): the fast
      // rung's client resolves ONCE per press — env (the battery seam) first,
      // then the OWNER'S OWN wired client (THE FAST-INHERIT LAW — the R172
      // law: once the owner pastes their own client, one-click inherits it —
      // no re-seal, no Console dance repeated) MINUS the retired list (the
      // R174 guard below), then the factory manifest ID. The ring records
      // the CLASS, never the value.
      const fastClientId = (env && env.clientId != null)
        ? String(env.clientId)
        : resolveFastClient(config, ring)
      ring('web-fallback', {
        rung: 'fast',
        outcome: 'ok',
        message: (env && env.clientId != null)
          ? 'the battery\u2019s env client rides (the seam)'
          : (String((config && config.clientId) || '').trim() && !isDeadClientId(String((config && config.clientId) || '').trim()) && !isLaneCClientId(String((config && config.clientId) || '').trim())
            ? 'the OWNER\u2019S own client rides the fast rung (the fast-inherit law — no re-seal needed)'
            : 'the Lane U client rides the fast rung (the two-lane guard retired the dead client or re-seated the Lane C client if one was saved)'),
      })
      if (!probe.ok) {
        throw Object.assign(new SyncError(SYNC_ERROR_KINDS.CONFIG, `Google Drive transport: the fast rung is unavailable (${probe.kind})`, {
          userMessage: FAST_PROBE_CARDS[probe.kind] || 'The browser does not have the web-auth machinery available right now — the guided rung (your own OAuth app) always works.',
        }), { probeKind: String(probe.kind || '') })
      }
      // ══ R171 — THE SPINE LEG (LEG 0.5, the unbroken spine) ═══════════════
      // THE ACTIVATION PROMISE: when the ZERO-WINDOW spine probe says the
      // spine client's Console redirect row is ARMED, this press opens
      // Google's window ONCE with the SPINE client (the Chrome-extension-
      // class PUBLIC client — response_type=code, PKCE S256,
      // access_type=offline, prompt=consent, the derived redirect) and the
      // SECRETLESS exchange mints access_token AND refresh_token. The
      // refresh token rides the SEALED envelope — after this, UCrypt
      // reconnects by itself, even after a restart (no window, no user
      // action — the refresh grant answers before every sync).
      // When the probe says UNARMED (or offline/untyped), this leg is
      // BYTE-ABSENT: today's ladder rides untouched (no extra window, no
      // red page — the probe-gated law). The battery seams: spineProbeImpl
      // injects the probe; spineDisabled turns the leg off; spineFetchImpl
      // bounds the probe's fetch.
      if (!(env && env.spineDisabled)) {
        const derivedRedirect = (chromeLike && chromeLike.identity && typeof chromeLike.identity.getRedirectURL === 'function')
          ? String(chromeLike.identity.getRedirectURL() || '')
          : ''
        const spine = (env && typeof env.spineProbeImpl === 'function')
          ? await env.spineProbeImpl({ redirect: derivedRedirect, fetchImpl: env && env.spineFetchImpl })
          : await spineProbe({ redirect: derivedRedirect, fetchImpl: env && env.spineFetchImpl })
        ring('spine-probe', {
          rung: 'fast',
          outcome: spine.ok === 'armed' ? 'ok' : (spine.ok === 'unarmed' ? 'fail' : 'fail'),
          error: spine.ok === 'armed' ? '' : String(spine.ok).slice(0, 48),
          message: spine.ok === 'armed'
            ? 'the spine probe says ARMED — the next window is the last one: the refresh custody mints and the connection survives every restart'
            : 'the spine probe says ' + String(spine.ok).toUpperCase() + ' (' + String(spine.blobCode || '').slice(0, 48) + ') — the press rides today\u2019s path byte-true (no extra window, no red page)',
        })
        if (spine.ok === 'armed') {
          const spineMint = await webAuthCodeMint({
            chromeLike,
            clientId: SPINE_CLIENT_ID,
            scope: FAST_WEB_SCOPE,
            prompt: 'consent',
            timeoutMs: (env && env.webAuthTimeoutMs) || undefined,
            launchImpl: (env && env.launchImpl) || undefined,
            stateImpl: (env && env.stateImpl) || undefined,
            randomImpl: (env && env.randomImpl) || undefined,
            fetchImpl: (env && env.fetchImpl) || undefined,
            setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
          })
          ring('spine-connect', {
            rung: 'fast',
            outcome: spineMint.ok ? 'ok' : 'fail',
            error: spineMint.ok ? '' : String(spineMint.kind || '').slice(0, 48),
            message: spineMint.ok
              ? 'THE SPINE SERVED — the window rode the spine client once, the secretless exchange minted the refresh custody, and the connection now survives every browser restart'
              : 'the spine connect refused (' + String(spineMint.kind || '') + '): ' + String(spineMint.raw || '').slice(0, 160),
          })
          if (spineMint.ok) {
            // THE CUSTODY (the same sealed envelope — the R85 law
            // byte-true): the spine's refresh token rides config.refreshToken;
            // the account hint is learned bounded (the multi-account guard).
            let accountHint = ''
            try {
              const aboutRes = await fetchWithRetry(OAUTH.driveBase + '/about?fields=user', { headers: { Authorization: `Bearer ${spineMint.token}` }, signal: AbortSignal.timeout(10000) }, { context: 'Google Drive about', retries: 0 })
              if (aboutRes && aboutRes.ok) {
                const aj = await aboutRes.json().catch(() => null)
                accountHint = String((aj && aj.user && aj.user.emailAddress) || '').trim()
              }
            } catch { /* the hint is best-effort — its bound never blocks the connect */ }
            const webToken = webTokenFromMint({ ok: true, token: spineMint.token, expiresIn: spineMint.expiresIn })
            return {
              authMode: 'fast', signinMode: 'fast',
              lane: 'S', via: 'web-auth-code-spine',
              clientId: SPINE_CLIENT_ID,
              ...(accountHint ? { accountHint } : {}),
              webToken,
              ...(spineMint.refreshToken ? { refreshToken: String(spineMint.refreshToken) } : {}),
            }
          }
          // THE ARMED-MISMATCH HONESTY: the probe said ARMED but the window
          // answered the redirect-mismatch class (Console propagation can
          // lag the probe by minutes) — the typed spine card rides AND the
          // press falls through to TODAY'S byte-true ladder (the Lane U
          // client's row is probe-proven healthy; the owner still connects
          // today). Every other spine failure keeps its typed card — a
          // cancellation NEVER opens a second window (the established law).
          const mismatchClass = /mismatch/i.test(String(spineMint.kind || ''))
          if (!mismatchClass) {
            const unmatched = /auth_window_settled_unmatched/i.test(String((spineMint && spineMint.raw) || ''))
              || String((spineMint && spineMint.kind) || '') === 'auth-window-unmatched'
              || String((spineMint && spineMint.kind) || '') === 'google-error-page'
            throw Object.assign(new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive transport: the spine sign-in refused (${(spineMint && spineMint.kind) || 'refused'})`, {
              userMessage: unmatched
                ? 'The Google sign-in window opened, but the sign-in did not complete before the window closed. Nothing was exchanged. The spine row was ARMED moments ago — wait a minute and press Connect again (Console changes can take Google five minutes to a few hours).'
                : ((spineMint && spineMint.kind) === 'consent-denied'
                  ? 'The sign-in was canceled before Google finished — nothing was exchanged. Press Connect again when ready.'
                  : 'The persistent sign-in did not complete (' + String((spineMint && spineMint.kind) || 'refused') + '). Nothing was exchanged. Press Connect again, or use your own key below (the guided rung always works).'),
            }), {
              probeKind: unmatched ? 'auth-window-unmatched' : String((spineMint && spineMint.kind) || ''),
              raw: String((spineMint && spineMint.raw) || ''),
              laneCTried: false,
              laneCReason: '',
            })
          }
          ring('spine-fallthrough', {
            rung: 'fast',
            outcome: 'ok',
            message: 'the spine window met the mismatch class despite the ARMED probe (Console propagation lag) — the press falls through to today\u2019s byte-true ladder so the owner still connects today',
          })
        }
      }
      // R169 — LEG 0, THE CHROME SILENT LANE (the O-2 accelerator): ONE
      // bounded, non-interactive getAuthToken call against the manifest's
      // Chrome-Extension client. ZERO windows, zero secrets. Unavailable →
      // the typed row and the fall-through (Brave/Helium and every
      // de-Googled build land here in milliseconds; a wedged Chrome is cut
      // loose at the 8 s silent bound — the press never waits on a lane
      // that cannot speak). The battery seams: laneCDisabled turns the leg
      // off; laneCImpl injects the mint; laneCTimeoutMs re-bounds it.
      let laneCTried = false
      let laneCReason = ''
      if (!(env && env.laneCDisabled)) {
        const laneC = (env && typeof env.laneCImpl === 'function')
          ? await env.laneCImpl({ chromeLike, timeoutMs: env && env.laneCTimeoutMs, setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now })
          : await mintGdriveLaneCToken({
              chromeLike,
              timeoutMs: (env && env.laneCTimeoutMs) || undefined,
              force: !!(env && env.laneCForce),
              setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
            })
        laneCTried = true
        ring('lane-c', {
          rung: 'fast',
          outcome: (laneC && laneC.ok) ? 'ok' : 'fail',
          error: (laneC && laneC.ok) ? '' : String((laneC && laneC.reason) || '').slice(0, 48),
          message: (laneC && laneC.ok)
            ? 'the Chrome silent lane served the sign-in (zero windows — Chrome\u2019s own connection, the reboot-persistence lane)'
            : 'the Chrome silent lane is unavailable (' + String((laneC && laneC.reason) || '') + ') — the press falls through to the universal lane (never a dead press)',
        })
        if (laneC && laneC.ok) {
          // R120 §2.5 — the picker's choice is LEARNED here too (the same
          // bounded about-call the window lane runs — the hint is
          // best-effort and never blocks the connect).
          let accountHint = ''
          try {
            const aboutRes = await fetchWithRetry(OAUTH.driveBase + '/about?fields=user', { headers: { Authorization: `Bearer ${laneC.token}` }, signal: AbortSignal.timeout(10000) }, { context: 'Google Drive about', retries: 0 })
            if (aboutRes && aboutRes.ok) {
              const aj = await aboutRes.json().catch(() => null)
              accountHint = String((aj && aj.user && aj.user.emailAddress) || '').trim()
            }
          } catch { /* the hint is best-effort — its bound never blocks the connect */ }
          // THE LANE C CUSTODY: Chrome's own token cache owns this bearer —
          // UCrypt stores NO token and NO refresh (nothing to leak, nothing
          // to clean); fastAccessToken re-mints it silently on every sync
          // leg, across browser restarts, while Chrome's session lives.
          const laneCWebToken = webTokenFromMint({
            ok: true,
            token: laneC.token,
            expiresIn: 3600,
            via: 'chrome-silent',
          })
          return {
            authMode: 'fast', signinMode: 'fast',
            lane: 'C', via: 'chrome-silent',
            clientId: LANE_C_CLIENT_ID,
            persistentSession: true,
            autoRenew: true,
            webToken: laneCWebToken,
            ...(accountHint ? { accountHint } : {}),
          }
        }
        laneCReason = String((laneC && laneC.reason) || '')
      }
      // R174b — LEG 1, THE CODE LANE (the primary mint): the window is
      // Google's own consent (prompt=consent select_account — the account
      // choice stays the user's), the state nonce is verified BEFORE anything
      // else is read (the CSRF law), and the exchange rides the PUBLIC-CLIENT
      // rule (client_id + code + code_verifier — NO client_secret can ever
      // ride; the pack gate proves the absence statically).
      //
      // R178 — R-178.5 THE CLIENT MAP GATES THE LANE (D4's twice-opened
      // chooser dies structurally — the map's Adjudication 3): for the
      // machine-proven CONFIDENTIAL Web-application client (Lane U — the
      // R174c wire rule: its secret-less exchange refuses before any
      // redirect validation with `invalid_request: client_secret is
      // missing`), a code-lane window could only ever end in the implicit
      // lane's SECOND window (E-45's field proof: the chooser popped twice
      // before login). So for a KNOWN-confidential client the code mint is
      // SKIPPED — the implicit lane rides FIRST: ONE window, ONE consent,
      // the skip named in the ring and in the verdict. For every OTHER
      // client (the spine's installed-class client, the owner's own wired
      // client) the code lane keeps its primary seat — a refresh token can
      // only ever arrive through a code exchange — and the implicit lane
      // may fire ONLY on the exchange-rule refusals, STATED in the verdict.
      // A cancellation never opens a second window (the standing law).
      const clientLaneKnown = isLaneUClientId(fastClientId)
      let codeMint = null
      let webMint = null
      if (clientLaneKnown) {
        ring('code-lane', {
          rung: 'fast', outcome: 'ok', error: '',
          message: 'the code lane is SKIPPED by the client map — this client is the machine-proven CONFIDENTIAL Web-application client (the R174c wire rule), so a code window could only end in the implicit lane\u2019s second window (E-45\u2019s twice-opened chooser); the implicit lane rides FIRST — one window, one consent',
        })
        webMint = await webAuthFastToken({
          chromeLike,
          clientId: fastClientId,
          scope: FAST_WEB_SCOPE,
          timeoutMs: (env && env.webAuthTimeoutMs) || undefined,
          launchImpl: (env && env.launchImpl) || undefined,
          stateImpl: (env && env.stateImpl) || undefined,
          setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
        })
        ring('web-fallback', {
          rung: 'fast',
          outcome: webMint.ok ? 'ok' : 'fail',
          error: webMint.ok ? '' : String(webMint.kind || '').slice(0, 48),
          // NO token value ever rides a ring row — only the machinery's name.
          message: webMint.ok
            ? 'the implicit lane completed the sign-in (ONE window — the client-map lane choice; the access-token custody rides the sealed envelope, never the ring)'
            : 'the implicit lane refused (' + String(webMint.kind || '') + '): ' + String(webMint.raw || '').slice(0, 160),
        })
      } else {
        codeMint = await webAuthCodeMint({
          chromeLike,
          clientId: fastClientId,
          scope: FAST_WEB_SCOPE,
          timeoutMs: (env && env.webAuthTimeoutMs) || undefined,
          launchImpl: (env && env.launchImpl) || undefined,
          stateImpl: (env && env.stateImpl) || undefined,
          randomImpl: (env && env.randomImpl) || undefined,
          fetchImpl: (env && env.fetchImpl) || undefined,
          setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
        })
        ring('code-lane', {
          rung: 'fast',
          outcome: codeMint.ok ? 'ok' : 'fail',
          error: codeMint.ok ? '' : String(codeMint.kind || '').slice(0, 48),
          message: codeMint.ok
            ? 'the code lane completed the sign-in (the PKCE exchange answered — the refresh token rides the sealed envelope, never the ring)'
            : 'the code lane refused (' + String(codeMint.kind || '') + '): ' + String(codeMint.raw || '').slice(0, 160),
        })
        // R174b — LEG 2, THE IMPLICIT LANE (the canonical R166 machinery): ONE
        // attempt, and ONLY for the exchange-rule refusals (the client-rule
        // classes — the window/consent part already proved itself when the code
        // arrived). A cancellation, a timeout, or a redirect mismatch keeps
        // its typed card — never a silent second window. R178 — the fallback
        // STATES itself in the verdict (R-178.5: the fallback may fire only
        // when the first flow failed, and the words say so).
        if (!codeMint.ok && EXCHANGE_FALLBACK_KINDS.includes(String(codeMint.kind || ''))) {
          ring('web-fallback', {
            rung: 'fast',
            outcome: 'ok',
            message: 'the code lane\u2019s exchange was refused on the client rules (' + String(codeMint.kind || '') + ') — ONE implicit-lane attempt rides (the canonical R166 machinery; the sign-in stays real, the card names the exchange refusal)',
          })
          webMint = await webAuthFastToken({
            chromeLike,
            clientId: fastClientId,
            scope: FAST_WEB_SCOPE,
            timeoutMs: (env && env.webAuthTimeoutMs) || undefined,
            launchImpl: (env && env.launchImpl) || undefined,
            stateImpl: (env && env.stateImpl) || undefined,
            setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
          })
          ring('web-fallback', {
            rung: 'fast',
            outcome: webMint.ok ? 'ok' : 'fail',
            error: webMint.ok ? '' : String(webMint.kind || '').slice(0, 48),
            // NO token value ever rides a ring row — only the machinery's name.
            message: webMint.ok
              ? 'the implicit lane completed the sign-in AFTER the code lane\u2019s exchange was refused (' + String(codeMint.kind || '') + ') — the second machinery is STATED in the verdict (R-178.5)'
              : 'the implicit lane refused too (' + String(webMint.kind || '') + '): ' + String(webMint.raw || '').slice(0, 160),
          })
        }
      }
      const mint = (codeMint && codeMint.ok) ? codeMint : (webMint && webMint.ok ? webMint : null)
      if (!mint) {
        const fail = (codeMint && !codeMint.ok) ? codeMint : (webMint && !webMint.ok ? webMint : null)
        const unmatched = /auth_window_settled_unmatched/i.test(String((fail && fail.raw) || ''))
          || String((fail && fail.kind) || '') === 'auth-window-unmatched'
          || String((fail && fail.kind) || '') === 'google-error-page'
        throw Object.assign(new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive transport: the fast sign-in refused (${(fail && fail.kind) || 'refused'})`, {
          userMessage: unmatched
            ? 'The Google sign-in window opened, but the sign-in did not complete before the window closed. Nothing was exchanged — the reason is named above, and your own key below always works. If the window showed Google\u2019s red "Access blocked \u2014 Error 400: redirect_uri_mismatch" page (or the deleted-client error page), the fix lives in Google Cloud Console: add this extension\u2019s exact redirect (shown on the Self-check card — the trailing slash is part of the value) to the Web-application client\u2019s Authorized redirect URIs, then press Connect again (Console changes can take Google five minutes to a few hours to take effect).'
            : ((fail && fail.kind) === 'consent-denied'
              ? 'The sign-in was canceled before Google finished — nothing was exchanged. Press Connect again when ready.'
              : 'The fast sign-in did not complete (' + String((fail && fail.kind) || 'refused') + '). Nothing was exchanged. Press Connect again, or use your own key below (the guided rung always works).'),
        }), {
          probeKind: unmatched ? 'auth-window-unmatched' : String((fail && fail.kind) || ''),
          raw: String((fail && fail.raw) || ''),
          verdict: unmatched ? 'web-auth-unmatched' : String((fail && fail.verdict) || ''),
          laneCTried,
          laneCReason,
        })
      }
      // R120 §2.5 — the picker's choice is LEARNED once at connect: the
      // account this token answers for becomes the connection's hint (a
      // device-local, non-secret email — the user's own choice on their own
      // device). The guard uses it to refuse a silent wrong-account sync.
      // Best-effort: a hiccup here never blocks the connect (the guard runs
      // hint-less and the API legs type their own failures).
      let accountHint = ''
      try {
        // R167 — the hint leg is BOUNDED (AbortSignal.timeout(10000)): the
        // unbounded fetch here was the "Still connecting — 7715 s…" hang's
        // exact seat (the E-13 printscreen 1: the seconds counter climbed
        // for two hours with no verdict). Every fast-path await is now
        // bounded — the window 300 s, the hint 10 s.
        const aboutRes = await fetchWithRetry(OAUTH.driveBase + '/about?fields=user', { headers: { Authorization: `Bearer ${mint.token}` }, signal: AbortSignal.timeout(10000) }, { context: 'Google Drive about', retries: 0 })
        if (aboutRes && aboutRes.ok) {
          const aj = await aboutRes.json().catch(() => null)
          accountHint = String((aj && aj.user && aj.user.emailAddress) || '').trim()
        }
      } catch { /* the hint is best-effort — its bound never blocks the connect */ }
      // R174b — THE CUSTODY (the corrected order's token choice): the code
      // lane's refresh token rides the SEALED envelope (device-only
      // ciphertext keyed to THIS vault — the R85 law byte-true); the implicit
      // lane's mint rides as webToken only (no refresh exists on the
      // implicit flow — a browser restart reconnects with one click).
      const webToken = webTokenFromMint({ ok: true, token: mint.token, expiresIn: mint.expiresIn })
      const refreshToken = String((mint && mint.refreshToken) || '').trim()
      return {
        authMode: 'fast', signinMode: 'fast',
        // R169 — the result NAMES the lane that served: 'U' (the universal
        // lane — the code mint or the implicit fallback) — the Lane C leg
        // returned earlier with lane:'C'. The card prints the truth.
        lane: 'U',
        // R172 — the client that ACTUALLY rode: env (the battery seam), the
        // owner's own wired client (the fast-inherit law, two-lane-guarded),
        // else the pinned LANE U client. The hoisted resolution is the
        // single seat — the record cannot disagree.
        clientId: fastClientId,
        via: mint.via,
        persistentSession: true,
        autoRenew: true,
        ...(accountHint ? { accountHint } : {}),
        webToken,
        ...(refreshToken ? { refreshToken } : {}),
      }
    })
  },

  async upload(encryptedBlob, config) {
    if (isApiMode(config)) {
      const existing = await driveFindVaultFile(config)
      const boundary = 'ucrypt-' + b64url(crypto.getRandomValues(new Uint8Array(12)))
      // Google Drive API v3 strictly forbids `parents` in PATCH update requests
      // (returns 403/400 fieldNotWritable). Include parents: ['appDataFolder']
      // ONLY on initial POST file creation when using fast/appDataFolder mode.
      const useAppData = isFastOrAppDataMode(config)
      const metadata = JSON.stringify((!existing && useAppData) ? { name: OAUTH.vaultName, parents: ['appDataFolder'] } : { name: OAUTH.vaultName })
      const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n${encryptedBlob}\r\n--${boundary}--`
      const url = existing
        ? `${OAUTH.uploadBase}/files/${existing.id}?uploadType=multipart&fields=id`
        : `${OAUTH.uploadBase}/files?uploadType=multipart&fields=id`
      const res = await driveApiFetch(config, url, {
        method: existing ? 'PATCH' : 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      }, { context: 'Google Drive upload', retries: 1, op: 'upload' })
      const meta = await res.json().catch(() => null)
      return { ok: true, id: String((meta && meta.id) || (existing && existing.id) || '') }
    }
    const url = validatedScriptUrl(config)
    try {
      const res = await fetchWithRetry(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify({ secret: config.secret || '', content: encryptedBlob }),
        redirect: 'follow',
      }, { context: 'Google Drive upload', op: 'upload' })
      const text = await res.text()
      const data = assertBridgeJson(text, { context: 'Google Drive upload' })
      if (!data || data.ok !== true) {
        const why = data && data.error ? ` — bridge said: ${data.error}` : ''
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `Google Drive upload: bridge did not confirm the write${why}`, {
          userMessage: 'The bridge did not confirm the upload' + why +
            ' Verify the secret matches the one inside your script and that the deployment is still active.',
        })
      }
      return true
    } catch (e) {
      throw classifySyncError(e, { context: 'Google Drive upload' })
    }
  },

  async download(config) {
    // R85 (§4): OAuth path — Drive API v3 read; a missing file is a CONFIRMED
    // absence (null), the same contract the bridge's content:null honors.
    // R119: the fast rung rides the same legs (isApiMode — the token seam
    // branches).
    if (isApiMode(config)) {
      const existing = await driveFindVaultFile(config)
      if (!existing) return null
      // R137 §9: the read rides driveApiFetch (bearer seam + one-shot 401
      // replay + typed 403/451 cards). The absence contract is unchanged.
      const res = await driveApiFetch(config, `${OAUTH.driveBase}/files/${existing.id}?alt=media`, {}, { context: 'Google Drive download', retries: 1, op: 'download' })
      const content = await res.text()
      if (!content || !looksLikeVaultEnvelope(content)) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive download: the stored file is not a vault envelope', {
          userMessage: 'The stored vault file is unreadable — push again from a device that still holds the vault.',
        })
      }
      return content
    }
    try {
      const res = await fetchWithRetry(this._url(config, { action: 'read' }), { redirect: 'follow' }, { context: 'Google Drive download', retries: 1, op: 'download' })
      const text = await res.text()
      const data = assertBridgeJson(text, { context: 'Google Drive download' })
      if (data && typeof data.ok === 'boolean') {
        if (data.ok !== true) {
          throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Google Drive download: bridge rejected the read (${data.error || 'unknown'})`, {
            userMessage: `The bridge refused the read (${data.error || 'unknown'}) — check the bridge secret in the sync settings.`,
          })
        }
        // ok:true + content:null is a CONFIRMED absence (the bridge
        // positively reports the file does not exist) — the only legitimate
        // null here (R26-F7). v2.18.0 — R27-F3 (audit): an EMPTY STRING
        // content is NOT an absence — it is a 0-byte stored file, i.e. a
        // lost write; coercing it to null advertised a writable remote that
        // actually holds a husk. Report it truthfully instead.
        if (data.content == null) return null
        if (data.content === '') {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive download: the stored bridge file is empty', {
            userMessage: 'The stored vault file is empty — the last upload may have been interrupted. Push again from a device that still holds the vault.',
          })
        }
        return data.content
      }
      // Tolerate an old bridge that streams the file raw — but ONLY a
      // plausible vault envelope (R26-F2: HTML/garbage must never masquerade
      // as the stored vault).
      const raw = (text || '').trim()
      if (looksLikeVaultEnvelope(raw)) return raw
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive download: the answer is neither the bridge JSON contract nor a vault blob', {
        userMessage: 'The bridge answered with something UCrypt does not understand — re-deploy the Web App and test the connection in the sync settings.',
      })
    } catch (e) {
      throw classifySyncError(e, { context: 'Google Drive download' })
    }
  },

  // R178 — R-178.3 THE PULL NAMES WHAT IT READ: the evidence-returning read
  // (the SAME legs, byte-true) — file id + byte count + modified time ride
  // beside the blob so the pull row can carry the remote's OWN evidence
  // (never a bare "the cloud copy was read" when only the first hop
  // answered). A transport without the seam falls back to download() with
  // evidence null (the registry's rule). The absence contract is unchanged:
  // null blob + evidence null = a positively-observed empty remote.
  async downloadWithEvidence(config) {
    if (isApiMode(config)) {
      const existing = await driveFindVaultFile(config)
      if (!existing) return { blob: null, evidence: null }
      const res = await driveApiFetch(config, `${OAUTH.driveBase}/files/${existing.id}?alt=media`, {}, { context: 'Google Drive download', retries: 1, op: 'download' })
      const content = await res.text()
      if (!content || !looksLikeVaultEnvelope(content)) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive download: the stored file is not a vault envelope', {
          userMessage: 'The stored vault file is unreadable — push again from a device that still holds the vault.',
        })
      }
      return {
        blob: content,
        evidence: {
          fileId: String(existing.id || ''),
          bytes: content.length,
          modifiedTime: String(existing.modifiedTime || '') || null,
          at: Date.now(),
        },
      }
    }
    const blob = await this.download(config)
    return { blob, evidence: blob ? { fileId: 'bridge', bytes: String(blob).length, modifiedTime: null, at: Date.now() } : null }
  },

  // R85 (§5): honest refusal — the bridge cannot be trusted to delete (it is
  // user-deployed); OAuth CAN delete via the Drive API.
  async deleteVault(config) {
    if (isApiMode(config)) {
      const existing = await driveFindVaultFile(config)
      if (!existing) return true
      const token = await ensureAccessToken(config)
      const res = await fetchWithRetry(`${OAUTH.driveBase}/files/${existing.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      }, { context: 'Google Drive delete', retries: 0 })
      return res.ok || res.status === 404
    }
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive bridge cannot delete the cloud copy', {
      userMessage: 'The bridge transport cannot prove deletion — remove ucrypt-vault.enc from your Google Drive (or reconfigure this transport as OAuth) and try again.',
    })
  },

  // R112 §3.1 (law 0.26) — the safe reseed's archive leg. OAuth: the old
  // bytes are copied to a NEW Drive file named <vaultName>.<archiveName>
  // (rename, never delete) BEFORE the fresh envelope overwrites the primary.
  // Bridge: the bridge script exposes read/write of ONE fixed name only —
  // it cannot archive — so the capability is honestly absent (the resolution
  // surface routes the bridge's unreadable cause to Edit setup instead).
  // R119: the fast rung CAN archive (the same Drive API legs, a Chrome-
  // minted token) — the capability rides the api-mode gate.
  canArchive(config) { return isApiMode(config) },
  // R172 — THE ROAD-HOME METADATA READ (R-172.3): the fork's danger-zone
  // double-confirm shows the remote copy's date/size BEFORE the owner
  // commits. Names and numbers only — never the content, never a secret.
  // A transport that cannot answer (the bridge's fixed-name contract)
  // returns { present: null } and the confirm says so honestly.
  async remoteVaultInfo(config) {
    if (!isApiMode(config)) return { present: null, size: null, modifiedTime: null }
    try {
      // driveFindVaultFile's list call already fetches fields(id,name,size,
      // modifiedTime) — the metadata read reuses it (one seat, one truth).
      const existing = await driveFindVaultFile(config)
      if (!existing) return { present: false, size: null, modifiedTime: null }
      return {
        present: true,
        size: Number.isFinite(Number(existing.size)) ? Number(existing.size) : null,
        modifiedTime: String(existing.modifiedTime || '') || null,
      }
    } catch {
      return { present: null, size: null, modifiedTime: null }
    }
  },
  async archiveUpload(rawContent, config, archiveName) {
    if (!this.canArchive(config)) {
      throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Google Drive bridge transport cannot archive the cloud copy', {
        userMessage: 'The bridge transport cannot archive the old copy — reconnect Google Drive as OAuth (Edit setup) to enable the safe reseed.',
      })
    }
    const boundary = 'ucrypt-' + b64url(crypto.getRandomValues(new Uint8Array(12)))
    const useAppData = isFastOrAppDataMode(config)
    const metadata = JSON.stringify(useAppData
      ? { name: OAUTH.vaultName + '.' + archiveName, parents: ['appDataFolder'] }
      : { name: OAUTH.vaultName + '.' + archiveName })
    const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n${rawContent}\r\n--${boundary}--`
    try {
      const res = await driveApiFetch(config, `${OAUTH.uploadBase}/files?uploadType=multipart&fields=id,name`, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      }, { context: 'Google Drive archive upload', retries: 1, op: 'upload' })
      let meta = null
      try { meta = await res.json() } catch { meta = null }
      return (meta && meta.name) || OAUTH.vaultName + '.' + archiveName
    } catch (e) {
      if (e instanceof SyncError) throw e
      throw classifySyncError(e, { context: 'Google Drive archive upload' })
    }
  },

  async testConnection(config) {
    // R85 (§4): OAuth path — the connection is the token refresh itself.
    // R119: the fast rung rides the same legs; its test names its rung.
    // R171 — THE TRANSPORT-TRUTH MODE GATE: an OAuth-evidence config rides
    // the API legs even without its authMode field — the bridge demand
    // ("Add your Apps Script Web App URL first") is unreachable for it.
    if (isApiMode(config) || looksLikeOAuthConfig(config)) {
      const token = await ensureAccessToken(config)
      if (!token) throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Google Drive test: no access token', { userMessage: 'The Google grant could not be refreshed — reconnect.' })
      const existing = await driveFindVaultFile(config).catch(() => null)
      const label = isFastOrAppDataMode(config) ? 'fast sign-in' : 'OAuth'
      return existing
        ? `Google Drive connected (${label}) — vault envelope present.`
        : `Google Drive connected (${label}) — vault not created yet (the first sync will create it).`
    }
    const url = validatedScriptUrl(config)
    try {
      const res = await fetchWithRetry(this._url(config, { action: 'ping' }), { redirect: 'follow' }, { context: 'Google Drive test', retries: 0 })
      const text = await res.text()
      const data = assertBridgeJson(text, { context: 'Google Drive test' })
      if (data && data.ok) {
        // R92 §1.4: a deployed script older than the current one is named
        // truthfully in the test result itself (the CEO's S3 candidate cause).
        const warn = bridgeVersionWarning(data)
        const base = `Bridge OK — file "${data.file || 'ucrypt-vault.enc'}" ready`
        return warn ? `${base} — ${warn}` : base
      }
      if (data) throw new Error(data.error || 'Bridge answered but rejected the secret')
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Google Drive test: the answer is not the bridge JSON contract', {
        userMessage: 'Unexpected response — did you deploy the script as a Web app (access "Anyone")?',
      })
    } catch (e) {
      throw classifySyncError(e, { context: 'Google Drive test' })
    }
  },
}

/** The exact script text offered in the setup wizard (with the secret prefilled).
 * R92 §1.4: the script carries BRIDGE_SCRIPT_VERSION and echoes it (`v`) in
 * every JSON answer — the UI warns truthfully when a deployed script is
 * older than this one (a stale version is a real failure cause, now named). */
export function gdriveBridgeScript(secret) {
  const s = (secret || 'change-me-to-a-long-random-string').replace(/'/g, "\\'")
  return `const FILE_NAME = 'ucrypt-vault.enc'
const SECRET = '${s}'
const BRIDGE_VERSION = ${BRIDGE_SCRIPT_VERSION}

function doGet(e) {
  const p = e.parameter || {}
  if (SECRET && p.secret !== SECRET) return json_({ ok: false, error: 'bad secret', v: BRIDGE_VERSION })
  if (p.action === 'ping') return json_({ ok: true, file: FILE_NAME, v: BRIDGE_VERSION })
  if (p.action === 'read') {
    const it = DriveApp.getFilesByName(FILE_NAME)
    return json_({ ok: true, content: it.hasNext() ? it.next().getBlob().getDataAsString() : null, v: BRIDGE_VERSION })
  }
  return json_({ ok: false, error: 'unknown action', v: BRIDGE_VERSION })
}

function doPost(e) {
  const body = JSON.parse(e.postData.contents)
  if (SECRET && body.secret !== SECRET) return json_({ ok: false, error: 'bad secret', v: BRIDGE_VERSION })
  const it = DriveApp.getFilesByName(FILE_NAME)
  if (it.hasNext()) it.next().setContent(body.content)
  else DriveApp.createFile(Utilities.newBlob(body.content, 'application/octet-stream', FILE_NAME))
  return json_({ ok: true, v: BRIDGE_VERSION })
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON)
}`
}
