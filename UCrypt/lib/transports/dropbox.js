/**
 * Dropbox transport (v2.3.0) — stores the encrypted vault blob in the user's Dropbox.
 *
 * Setup (user does this once):
 * 1. Go to https://www.dropbox.com/developers/apps
 * 2. Click "Create app" → choose "Scoped access" → "Full Dropbox" (or app folder)
 * 3. Name it "UCrypt"
 * 4. Under "OAuth 2" → "Generated access token" → click "Generate"
 * 5. Copy the token → paste into UCrypt → done
 *
 * The token is stored in chrome.storage.local on this device (extension-
 * local, never carried by the browser's profile sync). It is plaintext at
 * rest inside the extension's sandboxed storage — the previous comment
 * claiming "stored encrypted" was FALSE and is corrected here (audit
 * finding F7). Dropbox only ever sees the encrypted vault blob.
 *
 * v2.3.0: timeout + retry + classified errors via the shared http.js helper.
 * v2.16.0: upload responses are sanity-checked (a captive-portal HTML page
 * after a 2xx PUT is NOT a successful push), dead unreachable blocks removed.
 *
 * R119 (v2.77.0) — THE SIGN-IN LADDER (law 0.32): the FAST rung joins as
 * connectPkce() — the shared Dropbox app's PKCE connect (Dropbox's official
 * public-client mode: only the app key rides the wire, no secret ever
 * exists to ship, 0.14). The guided connectOAuth and the Advanced pasted-
 * token path stay EXACTLY as they are — no rung is ever removed.
 */

import { fetchWithRetry, classifySyncError, kindForStatus, SYNC_ERROR_KINDS, SyncError } from './http.js'
import { b64url, pkcePair, identityRedirect, launchOAuthFlow, typedGoogleError } from './gdrive-oauth-help.js'
import { runConnectFlow, launchWindowTyped } from '../connect-flow.js'
// R119 §3.3 (law 0.32) — the fast rung's protocol pieces live in the ladder
// module (the pinned auth URL + the exchange, UI-free and injection-seamed).
// The PKCE pair itself rides the file's own existing pkcePair seam above —
// one PKCE primitive per file.
import { dropboxAuthUrl, dropboxExchangeCode, sharedClientId } from '../ladder.js'

const DROPBOX_API = 'https://api.dropboxapi.com'
const DROPBOX_CONTENT = 'https://content.dropboxapi.com'
const DROPBOX_AUTHORIZE = 'https://www.dropbox.com/oauth2/authorize'
const DROPBOX_TOKEN = 'https://api.dropboxapi.com/oauth2/token'
const VAULT_PATH = '/ucrypt-vault.enc'

// R87 (§2.3): the Connect flow's in-memory access-token cache.
let _dbxCached = { token: null, exp: 0, rt: '' }

// v2.17.0 — R26-F6: Dropbox's generated access tokens are SHORT-LIVED
// (~4 hours). A 401 must not read as a generic auth failure — the user needs
// the "re-generate the token" instruction, in every method.
function dropboxTokenHint(e) {
  if (e instanceof SyncError && e.status === 401) {
    // R87 (§2.3): with a refresh token the 401 is NOT a reconnect — the
    // refresh path rotates the access token automatically. Only a pasted
    // token (no refresh token) needs the manual regenerate instruction.
    e.userMessage = 'Dropbox rejected the token (401). With a connected grant (refresh token) UCrypt refreshes it automatically — check your connection. With a pasted token, generate a fresh one at dropbox.com/developers/apps and paste it again.'
  }
  return e
}

// --- R87 (§2.3): OAuth PKCE connect + silent refresh (no forced reconnects) --
// Owner canonical law: refresh-token path; NO scope widening (no `scope`
// parameter is sent — Dropbox uses the app's own configured permission set);
// no forced reconnects (the refresh token rotates access tokens silently);
// no client secret (PKCE); the refresh token is sealed device-only inside
// the transport envelope.

/** Resolve a working access token: the user's pasted token, or a silent
 * refresh-token exchange (cached until 60 s before expiry).
 * R124 §2 (D13) — exported for the pickup bridge (lib/transports/pickup-links.js):
 * the hold rides the SAME token resolution — no parallel credential logic. */
export function _resetDropboxCacheForTest() {
  _dbxCached = { token: null, exp: 0, rt: '' }
}

export async function _accessToken(config, { forceRefresh = false } = {}) {
  const rt = String((config && config.refreshToken) || '').trim()
  if (!rt) {
    const t = String((config && config.token) || '').trim()
    if (!t) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Dropbox transport: no token or grant configured', {
      userMessage: 'Connect Dropbox (Connect button — PKCE, no secret) or paste an access token under Advanced.',
    })
    return t
  }
  if (forceRefresh) {
    _dbxCached = { token: null, exp: 0, rt: '' }
  }
  if (!forceRefresh && _dbxCached.token && Date.now() < _dbxCached.exp - 60000 && _dbxCached.rt === rt) return _dbxCached.token
  const appKey = String((config && config.appKey) || '').trim() || (config && config.signinMode === 'fast' ? sharedClientId('dropbox') : '') || sharedClientId('dropbox')
  if (!appKey) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Dropbox transport: refresh token present but the app key is missing', {
      userMessage: 'Enter the Dropbox app key (step 2 of the card) so the stored grant can refresh.',
    })
  }
  // R92 §1.2: the own-secret path — a user-supplied app secret rides the
  // refresh exchange when present (Dropbox app configs may require it).
  const appSecret = String((config && config.appSecret) || '').trim()
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: appKey })
  if (appSecret) body.set('client_secret', appSecret)
  const res = await fetchWithRetry(DROPBOX_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }, { context: 'Dropbox token refresh', retries: 1, okStatuses: [400, 401, 403], ring: { flow: 'connect', transport: 'dropbox', stage: 'refresh' } })
  const tok = await res.json().catch(() => null)
  if (!tok || !tok.access_token) {
    const why = tok && (tok.error_description || tok.error)
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Dropbox token refresh failed (${why || res.status})`, {
      userMessage: /invalid_refresh_token/i.test(String(why || ''))
        ? 'The stored Dropbox grant was revoked — press Connect to authorize again (this is the only case that needs a reconnect).'
        : `The Dropbox token refresh failed (${why || res.status}). Check the app key and the connection.`,
    })
  }
  _dbxCached = { token: tok.access_token, exp: Date.now() + (Number(tok.expires_in) || 14400) * 1000, rt }
  return _dbxCached.token
}

async function _withDropboxAuth(config, opFn) {
  const accessToken = await _accessToken(config)
  try {
    return await opFn(accessToken)
  } catch (err) {
    const hasRefresh = Boolean(String((config && config.refreshToken) || '').trim())
    const is401 = (err && err.status === 401) || /\b401\b/i.test(String((err && err.message) || ''))
    if (hasRefresh && is401) {
      const freshToken = await _accessToken(config, { forceRefresh: true })
      return await opFn(freshToken)
    }
    throw err
  }
}

/** PKCE connect — returns { refreshToken, redirect }; the refresh token is
 * sealed device-only by the transport-envelope save path.
 * R115 — the connect single-flight + the evidence-ring stage ladder: a
 * second Connect press while the Dropbox window is open SHARES that window,
 * and every stage lands on the ring. */
async function connectOAuth(config) {
  return runConnectFlow('dropbox', (ring) => _connectFlow(config, ring))
}

async function _connectFlow(config, ring) {
  const appKey = String((config && config.appKey) || '').trim()
  if (!appKey) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Dropbox transport: no app key configured', {
      userMessage: 'Create a Dropbox app (step 1 of the card) and paste its app key in step 2, then press Connect.',
    })
  }
  const redirect = identityRedirect()
  const { verifier, challenge } = await pkcePair()
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)))
  const u = new URL(DROPBOX_AUTHORIZE)
  u.searchParams.set('client_id', appKey)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('redirect_uri', redirect)
  u.searchParams.set('code_challenge', challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  u.searchParams.set('token_access_type', 'offline')
  u.searchParams.set('state', state)
  // R127 §3.1 (the CEO's S1/S4 — the account chooser is NEVER skipped): the
  // account-choice parameter rides EVERY OAuth authorization URL. Google
  // honors prompt=select_account natively (gdrive.js); Dropbox's authorize
  // page offers its account switcher in-page and ignores unknown params —
  // the parameter rides anyway per the owner's binding order, so the
  // intent is uniform on every transport and a future honoring costs
  // nothing. GitHub needs no chooser (the device flow types a code on
  // github.com — the account choice happens there, on the page itself).
  u.searchParams.set('prompt', 'select_account')
  // NO `scope` parameter — no scope widening, ever (the app's configured
  // permission set governs).
  // R115 (the audit's suspect (a)) — the typed window launcher: a window
  // loss/cancel/popup-block is a typed card + a ring row, never a raw
  // engine string.
  const finalUrl = await launchWindowTyped(() => launchOAuthFlow(u.toString()), { transport: 'dropbox', label: 'Dropbox' })
  if (!finalUrl) {
    ring('code', { outcome: 'fail', error: 'auth_window_closed', message: 'The authorization window was closed before Dropbox finished.' })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Dropbox transport: the authorization window was closed', {
      userMessage: 'The authorization window was closed before Dropbox finished — nothing was exchanged. Press Connect again (every retry starts clean).',
    })
  }
  const ru = new URL(finalUrl)
  if (ru.searchParams.get('state') !== state) {
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox transport: OAuth state mismatch', {
      userMessage: 'The authorization answer did not match the request (state mismatch) — nothing was exchanged.',
    })
  }
  const err = ru.searchParams.get('error')
  if (err) {
    const recovery = typedGoogleError({ error: err, errorDescription: ru.searchParams.get('error_description') || '', redirect })
    ring('code', { outcome: 'fail', error: recovery.kind, message: recovery.title })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Dropbox transport: authorization refused (${recovery.kind})`, { userMessage: recovery.title, recovery })
  }
  const code = ru.searchParams.get('code')
  if (!code) {
    ring('code', { outcome: 'fail', error: 'no_code', message: 'Dropbox did not return an authorization code.' })
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox transport: no authorization code in the answer', {
      userMessage: 'Dropbox did not return an authorization code — retry the connection.',
    })
  }
  ring('code', { outcome: 'ok', error: '', message: 'Authorization code received.' })
  // R92 §1.2: the own-secret path — a user-supplied app secret rides the
  // exchange when present; absent, PKCE alone remains the default.
  const appSecret = String((config && config.appSecret) || '').trim()
  const body = new URLSearchParams({ code, grant_type: 'authorization_code', code_verifier: verifier, redirect_uri: redirect, client_id: appKey })
  if (appSecret) body.set('client_secret', appSecret)
  const res = await fetchWithRetry(DROPBOX_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }, { context: 'Dropbox OAuth token exchange', retries: 1, ring: { flow: 'connect', transport: 'dropbox', stage: 'exchange' }, okStatuses: [400, 401, 403] })
  const tok = await res.json().catch(() => null)
  if (!tok || tok.error || !tok.access_token) {
    const why = tok && (tok.error_description || tok.error)
    // R92 §1.3: the description passes through so the dedicated typed cards
    // fire instead of the generic fallback.
    const recovery = typedGoogleError({ error: tok && tok.error, errorDescription: why, status: res.status, redirect })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Dropbox transport: token exchange failed (${why || res.status})`, {
      userMessage: recovery.title,
      recovery,
    })
  }
  if (!tok.refresh_token) {
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox transport: no refresh token in the answer', {
      userMessage: 'Dropbox did not grant a refresh token — the app must allow offline access (token_access_type=offline is always sent). Press Connect again.',
    })
  }
  _dbxCached = { token: tok.access_token, exp: Date.now() + (Number(tok.expires_in) || 14400) * 1000, rt: tok.refresh_token }
  return { refreshToken: tok.refresh_token, redirect }
}

// R119 §3.3 (law 0.32) — THE FAST RUNG: the shared Dropbox app's PKCE
// connect. Dropbox's official public-client mode — the app key (an
// identifier, not a credential; 0.15) rides openly, the verifier never
// leaves this device, and NO secret exists to ship. Until the owner's app
// key lands, this rung refuses honestly and routes to the guided rung —
// never a dead button, never a fabricated key. The guided connectOAuth
// above stays exactly as it is.
async function connectPkce(config) {
  // the connect single-flight (R115) is shared with connectOAuth — one
  // sign-in at a time per transport, every retry starts clean.
  return runConnectFlow('dropbox', (ring) => _pkceFlow(config, ring))
}

async function _pkceFlow(config, ring) {
  // law 0.28 — the ladder's flows record their rungs.
  ring('rung', { rung: 'fast' })
  const appKey = sharedClientId('dropbox')
  if (!appKey) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Dropbox transport: the shared app key has not landed in this build', {
      userMessage: 'The shared Dropbox sign-in is not available on this build yet — the guided rung (your own Dropbox app) always works.',
    })
  }
  const { verifier, challenge } = await pkcePair()
  ring('pkce-pair', { rung: 'fast', outcome: 'ok', error: '', message: 'PKCE verifier/challenge minted (S256) — the verifier never leaves this device.' })
  // THE FILE'S OWN LAUNCH SEAM (the guided flow's, unchanged): the pinned
  // redirect URI + the typed window launcher — a window loss/cancel/popup-
  // block is a typed card + a ring row, never a raw engine string.
  const redirect = identityRedirect()
  const url = dropboxAuthUrl({ appKey, challenge, redirect })
  const finalUrl = await launchWindowTyped(() => launchOAuthFlow(url), { transport: 'dropbox', label: 'Dropbox' })
  if (!finalUrl) {
    ring('code', { rung: 'fast', outcome: 'fail', error: 'auth_window_closed', message: 'The authorization window was closed before Dropbox finished.' })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'Dropbox transport: the authorization window was closed', {
      userMessage: 'The authorization window was closed before Dropbox finished — nothing was exchanged. Press Connect again (every retry starts clean).',
    })
  }
  ring('auth-window', { rung: 'fast', outcome: 'ok', error: '', message: 'The shared sign-in window completed.' })
  const code = new URL(finalUrl).searchParams.get('code')
  if (!code) {
    ring('code', { rung: 'fast', outcome: 'fail', error: 'no_code', message: 'Dropbox did not return an authorization code.' })
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox transport: no authorization code in the answer', {
      userMessage: 'Dropbox did not return an authorization code — retry the connection.',
    })
  }
  ring('code', { rung: 'fast', outcome: 'ok', error: '', message: 'Authorization code received.' })
  // The exchange is public-client by protocol: app key + code + verifier —
  // never a secret (0.14). The verifier binds the code to THIS flow.
  let ex
  try {
    ex = await dropboxExchangeCode({ appKey, code, verifier, redirect })
  } catch (e) {
    ring('exchange', { rung: 'fast', outcome: 'fail', error: 'exchange_failed', message: String((e && e.message) || e) })
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `Dropbox transport: the shared sign-in's token exchange failed (${String((e && e.message) || e)})`, {
      userMessage: 'The Dropbox sign-in could not be completed — the guided rung (your own Dropbox app) always works.',
    })
  }
  ring('exchange', { rung: 'fast', outcome: 'ok', error: '', message: 'The grant was exchanged (refresh token issued).' })
  // The SAME grant field names the guided flow returns — plus the rung the
  // connection was won at (the v1.5 signinMode field).
  return { refreshToken: ex.refreshToken, accessToken: ex.accessToken, appKey, signinMode: 'fast' }
}

export const dropbox = {
  name: 'Dropbox',
  fields: [
    { key: 'appKey', label: 'Dropbox app key', type: 'text', placeholder: 'the app key from dropbox.com/developers/apps', oauthField: true, help: 'From dropbox.com/developers/apps → your app → Settings → App key. No secret is needed — UCrypt connects with PKCE.' },
    // R92 §1.2 — OWN-SECRET MODE: Dropbox app configs may require the app
    // secret at the token endpoint; pasting it (optional) sends it only to
    // Dropbox's token endpoint over TLS. Sealed, device-only, never exported.
    { key: 'appSecret', label: 'Your app secret (optional — own-secret sign-in)', type: 'password', placeholder: 'paste ONLY if your app requires it', oauthField: true, help: 'Optional: if your Dropbox app requires the app secret at the token endpoint, paste it here. It is sealed in your vault on this device — never synced, never logged, never exported.' },
    { key: 'refreshToken', label: 'Dropbox grant (stored sealed, device-only)', type: 'password', oauthField: true, help: 'Filled by the Connect button. Sealed inside the transport envelope — never leaves this device in plaintext.' },
    { key: 'token', label: 'Pasted access token (Advanced)', type: 'password', placeholder: 'sl.Bxxxxxxxxxxxxxxx...', advancedField: true, help: 'Advanced: a generated token from the app console (expires in ~4 hours). Prefer Connect — the grant refreshes itself and never forces a reconnect.' },
    { key: 'apiBase', label: 'API base URL (advanced, optional)', type: 'url', optional: true, placeholder: 'https://dropbox-gateway.example.com', help: 'Leave empty for the real Dropbox. Advanced: point at a gateway/proxy you control that mirrors the Dropbox REST API — the token is sent only to this host.' },
  ],

  async connectOAuth(config) {
    return connectOAuth(config)
  },

  // R119 §3.3 (law 0.32) — the fast rung (the shared app's PKCE connect).
  async connectPkce(config) {
    return connectPkce(config)
  },

  // v2.15.0 — R24-F2: optional API base override. Defaults stay the real
  // Dropbox endpoints; a user-configured base (self-hosted gateway, regional
  // proxy, test harness) replaces both hosts. Trailing slashes are trimmed.
  _apiBase(config) {
    const b = String(config?.apiBase || '').trim().replace(/\/+$/, '')
    return b || DROPBOX_API
  },

  _contentBase(config) {
    const b = String(config?.apiBase || '').trim().replace(/\/+$/, '')
    return b || DROPBOX_CONTENT
  },

  async upload(encryptedBlob, config) {
    try {
      return await _withDropboxAuth(config, async (accessToken) => {
        const res = await fetchWithRetry(`${this._contentBase(config)}/2/files/upload`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Dropbox-API-Arg': JSON.stringify({ path: VAULT_PATH, mode: 'overwrite', mute: true }),
            'Content-Type': 'application/octet-stream',
          },
          body: encryptedBlob,
        }, { context: 'Dropbox upload', op: 'upload' })
        // v2.16.0 — R25-F8: "success" used to be any 2xx with the body unread.
        // The real API answers JSON metadata; a captive portal / intercepting
        // proxy answering 200 with an HTML page would have counted as a pushed
        // vault and only surfaced at pull time. Fail truthfully now.
        const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
        if (ct.includes('text/html')) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox upload answered with HTML, not the API', {
            userMessage: 'The upload was answered by a web page instead of the Dropbox API (captive portal or proxy?) — the vault was NOT stored.',
          })
        }
        // v2.17.0 — R26-F2: the upload contract is JSON metadata. Anything else
        // (a 200 empty body from an intercepting proxy) is not a success.
        let meta = null
        try { meta = await res.json() } catch { meta = null }
        if (!meta || typeof meta !== 'object' || !meta.path_display) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox upload did not return the file metadata contract', {
            userMessage: 'The Dropbox API did not confirm the upload (no file metadata came back) — the vault was NOT stored. Check the connection/proxy and try again.',
          })
        }
        return true
      })
    } catch (e) {
      throw dropboxTokenHint(classifySyncError(e, { context: 'Dropbox upload' }))
    }
  },

  async download(config) {
    try {
      return await _withDropboxAuth(config, async (accessToken) => {
        const res = await fetchWithRetry(`${this._contentBase(config)}/2/files/download`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Dropbox-API-Arg': JSON.stringify({ path: VAULT_PATH }),
          },
        }, { context: 'Dropbox download', retries: 1, op: 'download' })
        // v2.17.0 — R26-F2/F7: an HTML answer is a captive portal, never the
        // vault; an EMPTY stored file is a lost write, not "nothing stored".
        const text = await res.text()
        const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
        if (ct.includes('text/html')) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox download answered with HTML, not the API', {
            userMessage: 'The download was answered by a web page instead of the Dropbox API (captive portal or proxy?) — nothing was read.',
          })
        }
        if (!text || !text.trim()) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox download: the stored file is empty', {
            userMessage: 'The stored vault file is empty — the last upload may have been interrupted. Push again from a device that still holds the vault.',
          })
        }
        return text
      })
    } catch (e) {
      // A missing file is a normal state for a first device — not an error.
      // v2.18.0 — R27-F5 (audit): only a path/not_found-family 409 is a
      // CONFIRMED absence. The download endpoint answers other 409 tags too
      // (restricted_content, malformed_path…) — treating those as "nothing
      // stored" would license a first-device push over a blob we merely
      // failed to read. The statusToSyncError message embeds the body
      // snippet, which carries the error_summary tag.
      if (e instanceof SyncError && e.status === 409 && /path\/not_found|lookup_failed\/not_found/i.test(String(e.message))) return null
      if (e instanceof SyncError && e.status === 409) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `Dropbox download refused: 409 without the not_found tag (${String(e.message).slice(0, 160)})`, {
          cause: e,
          userMessage: 'Dropbox refused the read in an unexpected way — check the app permissions for this token in the sync settings.',
        })
      }
      throw dropboxTokenHint(classifySyncError(e, { context: 'Dropbox download' }))
    }
  },

  // R112 §3.1 (law 0.26) — the safe reseed's archive leg: the old bytes are
  // written to a sibling path (<vault path>.<archiveName>) BEFORE the fresh
  // envelope overwrites the primary — rename, never delete.
  canArchive() { return true },
  async archiveUpload(rawContent, config, archiveName) {
    try {
      return await _withDropboxAuth(config, async (accessToken) => {
        const res = await fetchWithRetry(`${this._contentBase(config)}/2/files/upload`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Dropbox-API-Arg': JSON.stringify({ path: VAULT_PATH + '.' + archiveName, mode: 'overwrite', mute: true }),
            'Content-Type': 'application/octet-stream',
          },
          body: rawContent,
        }, { context: 'Dropbox archive upload', op: 'upload' })
        let meta = null
        try { meta = await res.json() } catch { meta = null }
        if (!meta || typeof meta !== 'object' || !meta.path_display) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Dropbox archive upload did not return the file metadata contract', {
            userMessage: 'The archive copy could not be confirmed — nothing was overwritten.',
          })
        }
        return meta.path_display
      })
    } catch (e) {
      if (e instanceof SyncError) throw e
      throw dropboxTokenHint(classifySyncError(e, { context: 'Dropbox archive upload' }))
    }
  },

  async testConnection(config) {
    try {
      return await _withDropboxAuth(config, async (accessToken) => {
        const res = await fetchWithRetry(`${this._apiBase(config)}/2/users/get_current_account`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${accessToken}` },
        }, { context: 'Dropbox test', retries: 0 })
        // v2.18.0 — R27-F6 (audit): every non-ok status used to read as
        // "Invalid Dropbox token" — a 5xx outage lied about the token. The
        // status now picks the kind (401/403 → AUTH, 5xx → SERVER, …); the
        // 401 case still gains the ~4h token hint below.
        if (!res.ok) {
          throw new SyncError(kindForStatus(res.status), `Dropbox test failed: ${res.status}`, { status: res.status })
        }
        const data = await res.json()
        return `Connected as ${data.name?.display_name || data.email || 'unknown'}`
      })
    } catch (e) {
      throw dropboxTokenHint(classifySyncError(e, { context: 'Dropbox test' }))
    }
  },
}
