/**
 * UCrypt Gist transport (v2.3.0) — stores the encrypted vault as a SECRET Gist.
 *
 * v2.1.0 flaw (audit finding #7): the gist ID was cached in chrome.storage.local,
 * so a second device with the same sync code created a NEW gist and the two
 * devices diverged (split-brain). Fixed: on a cache miss the transport now
 * lists the account's gists and adopts the existing UCrypt gist; only creates
 * one when none exists.
 *
 * Setup (guided in the options UI):
 * 1. github.com/settings/tokens → "Generate new token (classic)"
 * 2. Scope: "gist" only
 * 3. Paste the token below — the gist is created/adopted automatically.
 *
 * GitHub only ever sees AES-GCM ciphertext. The token lives in local
 * extension storage (not synced) — plaintext on this device, sent only to
 * the GitHub API host.
 *
 * v2.3.0: timeout + retry + classified errors via the shared http.js helper.
 * v2.16.0: gist-truthful uploads (truncated-flag detection), safe JSON
 * parsing in gist creation, dead unreachable blocks removed.
 *
 * R119 (v2.77.0) — THE SIGN-IN LADDER (law 0.32): the FAST rung joins as
 * connectDeviceFlow() — the shared GitHub device flow (public-client by
 * protocol, 0.14: no secret ever exists to ship). The guided PKCE
 * connectOAuth and the Advanced PAT path stay EXACTLY as they are — no rung
 * is ever removed, nothing is demoted further.
 */

import { fetchWithRetry, classifySyncError, kindForStatus, SYNC_ERROR_KINDS, SyncError } from './http.js'
import { b64url, pkcePair, identityRedirect, launchOAuthFlow, typedGoogleError } from './gdrive-oauth-help.js'
import { runConnectFlow, launchWindowTyped } from '../connect-flow.js'
// R119 §3.2 (law 0.32) — the fast rung's protocol engine (the typed device
// flow lives in the ladder module, UI-free and injection-seamed).
import { githubDeviceFlow, sharedClientId } from '../ladder.js'

const GITHUB_API = 'https://api.github.com'

// R124 §2 (D13) — the exported mirrors the pickup bridge consumes
// (lib/transports/pickup-links.js). ONE body each — the object's own
// methods delegate, so the resolution can never drift apart.
export function authTokenFor(config) {
  return String((config && config.oauthAccessToken) || '').trim() || String((config && config.token) || '').trim()
}

export function apiBaseFor(config) {
  const b = String((config && config.apiBase) || '').trim().replace(/\/+$/, '')
  return b || GITHUB_API
}

const GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize'
const GITHUB_TOKEN = 'https://github.com/login/oauth/access_token'
const GIST_DESCRIPTION = 'UCrypt (encrypted)'
const GIST_FILENAME = 'ucrypt-vault.enc'
const INIT_MARKER = '__UCRYPT_INIT__'
// v2.17.0 — R26-F12: the Gist API silently truncates content over ~1 MB.
// Detecting it only AFTER a full PATCH round-trip wastes the upload and can
// leave a truncated (unreadable) blob in place — refuse BEFORE the wire.
const GIST_MAX_CHARS = 900_000

export const github = {
  name: 'GitHub Gist',
  fields: [
    { key: 'oauthClientId', label: 'GitHub OAuth app client ID', type: 'text', placeholder: 'Ov23li… or Iv1…', oauthField: true, help: 'From github.com/settings/developers → your OAuth app. UCrypt connects with code + PKCE (no client secret) and requests the "gist" scope only.' },
    // R92 §1.2 — OWN-SECRET MODE: GitHub apps can also be created with a
    // secret; pasting it (optional) sends it only to GitHub's token endpoint
    // over TLS. Sealed in the vault, device-only, never exported.
    { key: 'oauthClientSecret', label: 'Your client secret (optional — own-secret sign-in)', type: 'password', placeholder: 'paste ONLY if your app has a secret', oauthField: true, help: 'Optional: if your GitHub OAuth app has a client secret, paste it here for direct sign-in. It is sealed in your vault on this device — never synced, never logged, never exported.' },
    { key: 'oauthAccessToken', label: 'GitHub grant (stored sealed, device-only)', type: 'password', oauthField: true, help: 'Filled by the Connect button. Sealed inside the transport envelope — never leaves this device in plaintext.' },
    { key: 'token', label: 'Personal access token (Advanced)', type: 'password', placeholder: 'ghp_… or github_pat_…', advancedField: true, help: 'Advanced: a classic/fine-grained PAT with the "gist" scope only. Prefer Connect — the OAuth grant never needs manual rotation.' },
    { key: 'apiBase', label: 'API base URL (advanced, optional)', type: 'url', optional: true, placeholder: 'https://github-gateway.example.com', help: 'Leave empty for the real GitHub. Advanced: point at a gateway/proxy you control that mirrors the GitHub REST API — the token is sent only to this host.' },
  ],

  // R87 (§2.3): PKCE connect (code + S256 challenge, NO client secret),
  // scope "gist" only. Returns { refreshToken?, accessToken, redirect }.
  // R115 — the connect single-flight + the evidence-ring stage ladder: a
  // second Connect press while the GitHub window is open SHARES that window
  // (never a second launchWebAuthFlow), and every stage lands on the ring.
  async connectOAuth(config) {
    return runConnectFlow('github', (ring) => this._connectFlow(config, ring))
  },

  async _connectFlow(config, ring) {
    const clientId = String((config && config.oauthClientId) || '').trim()
    if (!clientId) {
      throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'GitHub transport: no OAuth app client id configured', {
        userMessage: 'Create a GitHub OAuth app (github.com/settings/developers → New OAuth App), paste its client ID in step 2, register the redirect URI from step 1, then press Connect.',
      })
    }
    const redirect = identityRedirect()
    const { verifier, challenge } = await pkcePair()
    const state = b64url(crypto.getRandomValues(new Uint8Array(16)))
    const u = new URL(GITHUB_AUTHORIZE)
    u.searchParams.set('client_id', clientId)
    u.searchParams.set('redirect_uri', redirect)
    u.searchParams.set('scope', 'gist') // scope narrowing: gist ONLY
    u.searchParams.set('state', state)
    u.searchParams.set('code_challenge', challenge)
    u.searchParams.set('code_challenge_method', 'S256')
    // R115 (the audit's suspect (a)) — the typed window launcher: a window
    // loss/cancel/popup-block is a typed card + a ring row, never a raw
    // engine string.
    const finalUrl = await launchWindowTyped(() => launchOAuthFlow(u.toString()), { transport: 'github', label: 'GitHub' })
    if (!finalUrl) {
      ring('code', { outcome: 'fail', error: 'auth_window_closed', message: 'The authorization window was closed before GitHub finished.' })
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, 'GitHub transport: the authorization window was closed', {
        userMessage: 'The authorization window was closed before GitHub finished — nothing was exchanged. Press Connect again (every retry starts clean).',
      })
    }
    const ru = new URL(finalUrl)
    if (ru.searchParams.get('state') !== state) {
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub transport: OAuth state mismatch', {
        userMessage: 'The authorization answer did not match the request (state mismatch) — nothing was exchanged.',
      })
    }
    const err = ru.searchParams.get('error')
    if (err) {
      const recovery = typedGoogleError({ error: err, errorDescription: ru.searchParams.get('error_description') || '', redirect })
      ring('code', { outcome: 'fail', error: recovery.kind, message: recovery.title })
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, `GitHub transport: authorization refused (${recovery.kind})`, { userMessage: recovery.title, recovery })
    }
    const code = ru.searchParams.get('code')
    if (!code) {
      ring('code', { outcome: 'fail', error: 'no_code', message: 'GitHub did not return an authorization code.' })
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub transport: no authorization code in the answer', {
        userMessage: 'GitHub did not return an authorization code — retry the connection.',
      })
    }
    ring('code', { outcome: 'ok', error: '', message: 'Authorization code received.' })
    // R92 §1.2: the own-secret path — a user-supplied client secret rides
    // the exchange (GitHub app configs may require it); absent, PKCE alone
    // remains the default. The secret goes ONLY to GitHub's token endpoint.
    const clientSecret = String((config && config.oauthClientSecret) || '').trim()
    const body = new URLSearchParams({ client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect })
    if (clientSecret) body.set('client_secret', clientSecret)
    const res = await fetchWithRetry(GITHUB_TOKEN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString(),
    }, { context: 'GitHub OAuth token exchange', retries: 1, ring: { flow: 'connect', transport: 'github', stage: 'exchange' }, okStatuses: [400, 401, 403] })
    const tok = await res.json().catch(() => null)
    if (!tok || tok.error || !tok.access_token) {
      const why = tok && (tok.error_description || tok.error)
      // R92 §1.3: the description passes through so the dedicated typed cards
      // (client_secret missing / bad credentials) fire instead of the fallback.
      const recovery = typedGoogleError({ error: tok && tok.error, errorDescription: why, status: res.status, redirect })
      throw new SyncError(SYNC_ERROR_KINDS.AUTH, `GitHub transport: token exchange failed (${why || res.status})`, {
        userMessage: recovery.title,
        recovery,
      })
    }
    // Expiring-token apps return a refresh token too — keep it so the grant
    // can rotate without a reconnect; non-expiring apps omit it (equally fine).
    return { accessToken: tok.access_token, refreshToken: tok.refresh_token || '', redirect }
  },

  // R119 §3.2 (law 0.32) — THE FAST RUNG: the GitHub device flow. Public-
  // client by protocol (0.14) — no secret exists to ship; the flow needs
  // only a browser tab on github.com/login/device, so it works on every
  // Chromium (Helium included). The shared client ID is OWNER-SUPPLIED
  // (0.15): until it lands this rung refuses honestly and routes to the
  // guided rung — never a dead button, never a fabricated ID. The guided
  // connectOAuth above and the Advanced PAT path stay exactly as they are.
  async connectDeviceFlow(config) {
    // the connect single-flight (R115) is shared with connectOAuth — one
    // sign-in at a time per transport, every retry starts clean.
    return runConnectFlow('github', (ring) => this._deviceFlow(config, ring))
  },

  async _deviceFlow(config, ring) {
    // law 0.28 — the ladder's flows record their rungs.
    ring('rung', { rung: 'fast' })
    const cid = sharedClientId('github')
    if (!cid) {
      throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'GitHub transport: the shared device-flow client ID has not landed in this build', {
        userMessage: 'The shared GitHub sign-in is not available on this build yet — the guided rung (your own OAuth app) always works.',
      })
    }
    // Every typed device-flow state lands on the ring with its rung named
    // (device-code-requested → device-awaiting-user → device-polling →
    // device-authorized, or the typed terminals). The state objects carry
    // the USER code (meant to be read aloud) — the access token never rides
    // a ring extra; only the fact of the grant ever lands.
    const res = await githubDeviceFlow({
      clientId: cid,
      onState: (s) => ring('device-' + s.state, { rung: 'fast' }),
    })
    if (!res.ok) {
      // The machine state rides beside the kind (0.26's typed degradation):
      // throttled/expired/denied route to their own cards, never a generic
      // failure face. No token value is ever carried or logged.
      const kind = res.state === 'throttled' ? SYNC_ERROR_KINDS.RATE_LIMIT : SYNC_ERROR_KINDS.AUTH
      throw Object.assign(new SyncError(kind, `GitHub transport: the device flow stopped (${res.state}: ${res.kind})`, {
        userMessage: res.message,
      }), { ladderState: res.state })
    }
    // The SAME grant shape the wizard already maps for connectOAuth — plus
    // the rung the connection was won at (the v1.5 signinMode field).
    return { accessToken: res.accessToken, signinMode: 'fast' }
  },

  // v2.15.0 — R24-F2: optional API base override (see dropbox.js). Defaults
  // stay the real GitHub REST API.
  _apiBase(config) {
    const b = String(config?.apiBase || '').trim().replace(/\/+$/, '')
    return b || GITHUB_API
  },

  // R124 §2 (D13) — the bridge consumes the exported mirrors below; the
  // method delegates so the credential resolution has ONE body (no drift).

  // R87 (§2.3): the credential resolver — the Connect grant (OAuth) first,
  // the pasted Advanced token second. No secrets in the package, ever.
  _authToken(config) {
    return authTokenFor(config)
  },

  async _getGistId(config) {
    if (!this._authToken(config)) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'GitHub transport: no token configured', { userMessage: 'Connect GitHub (Connect button — PKCE, gist scope only) or paste a token under Advanced.' })
    // 1. Use the cached ID when present and still valid
    const existing = await chrome.storage.local.get('ucrypt:gistId')
    if (existing['ucrypt:gistId']) {
      const ok = await this._gistExists(existing['ucrypt:gistId'], config)
      if (ok) return existing['ucrypt:gistId']
    }

    // 2. v2.2.0 cross-device discovery: adopt the existing UCrypt gist so a
    //    second device does not fork the vault.
    // v2.17.0 — R26-F4: discovery is now THREE-STATE. The old code collapsed
    // "no gist exists" and "the listing could not be read" into the same
    // null — and a transient listing failure (or >100 gists, page 1 only)
    // fell through to CREATE, forking a second vault that the first device
    // never sees. Creation now happens ONLY after a positively observed
    // empty listing.
    const found = await this._discoverGist(config)
    if (found.state === 'found') {
      await chrome.storage.local.set({ 'ucrypt:gistId': found.id })
      return found.id
    }
    if (found.state === 'unknown') {
      throw new SyncError(SYNC_ERROR_KINDS.NETWORK, 'GitHub gist discovery could not be completed — refusing to create a possibly-duplicate gist', {
        cause: found.error,
        userMessage: 'UCrypt could not verify whether your account already holds a vault gist (a listing request failed). Creating a second one would split your devices — check the connection/token and sync again.',
      })
    }

    // 3. Create a new secret gist — reached only when the listing was read
    //    and positively contained no vault gist.
    let res
    try {
      res = await fetchWithRetry(`${this._apiBase(config)}/gists`, {
        method: 'POST',
        headers: {
          'Authorization': `token ${this._authToken(config)}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          description: GIST_DESCRIPTION,
          public: false,
          files: { [GIST_FILENAME]: { content: INIT_MARKER } },
        }),
      }, { context: 'GitHub gist create' })
    } catch (e) {
      throw classifySyncError(e, { context: 'GitHub gist create' })
    }
    // v2.16.0 — R25-F9: the parse used to sit OUTSIDE the try (a 200-with-HTML
    // body crashed with an uncaught SyntaxError) and data.id was cached
    // unchecked — a weird payload stored `gistId: undefined` and every later
    // PATCH 404'd, misreported as "Nothing stored there yet".
    let data = null
    try { data = await res.json() } catch { data = null }
    if (!data || typeof data.id !== 'string' || !data.id) {
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub gist create returned no gist id', {
        userMessage: 'GitHub answered unexpectedly when creating the gist — check the token scope ("gist") and try again.',
      })
    }
    await chrome.storage.local.set({ 'ucrypt:gistId': data.id })
    return data.id
  },

  async _gistExists(id, config) {
    try {
      const res = await fetchWithRetry(`${this._apiBase(config)}/gists/${id}`, {
        headers: { 'Authorization': `token ${this._authToken(config)}` },
      }, { context: 'GitHub gist check', retries: 0 })
      return res.ok
    } catch { return false }
  },

  /**
   * v2.17.0 — R26-F4: three-state gist discovery.
   *   { state:'found', id }   — a vault gist positively exists → adopt it
   *   { state:'none' }        — the listing was read; no vault gist present
   *   { state:'unknown', error } — the listing could NOT be read (network,
   *                              rate limit, unexpected payload) → callers
   *                              must NOT create a gist.
   * Paginates up to 3 pages of 100; exhausting the cap leaves uncertainty →
   * unknown (an account with >300 gists cannot be positively cleared).
   */
  async _discoverGist(config) {
    for (let page = 1; page <= 3; page++) {
      let res
      try {
        res = await fetchWithRetry(`${this._apiBase(config)}/gists?per_page=100&page=${page}`, {
          headers: { 'Authorization': `token ${this._authToken(config)}` },
        }, { context: 'GitHub gist discover', retries: 0 })
      } catch (e) {
        return { state: 'unknown', error: e }
      }
      if (!res.ok) return { state: 'unknown', error: new Error(`listing failed: ${res.status}`) }
      let gists
      try { gists = await res.json() } catch (e) { return { state: 'unknown', error: e } }
      if (!Array.isArray(gists)) return { state: 'unknown', error: new Error('listing was not an array') }
      for (const g of gists) {
        if (g.files && g.files[GIST_FILENAME]) {
          const desc = g.description || ''
          if (desc === GIST_DESCRIPTION || desc === '') return { state: 'found', id: g.id }
        }
      }
      if (gists.length < 100) return { state: 'none' }
    }
    return { state: 'unknown', error: new Error('gist listing exhausted the 3-page cap') }
  },

  async upload(encryptedBlob, config) {
    // v2.17.0 — R26-F12: fail fast BEFORE the wire when the blob cannot fit
    // in a gist (the API silently truncates over ~1 MB).
    if (typeof encryptedBlob === 'string' && encryptedBlob.length > GIST_MAX_CHARS) {
      throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `GitHub gist upload refused: blob is ${encryptedBlob.length} chars (gist cap ~1 MB)`, {
        userMessage: 'The vault is too large for a GitHub gist — the upload was refused before sending. Use WebDAV, Dropbox or a Custom URL for big vaults.',
      })
    }
    const gistId = await this._getGistId(config)
    try {
      const res = await fetchWithRetry(`${this._apiBase(config)}/gists/${gistId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `token ${this._authToken(config)}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          files: { [GIST_FILENAME]: { content: encryptedBlob } },
        }),
      }, { context: 'GitHub gist update', op: 'upload' })
      // v2.16.0 — R25-F5: the Gist API silently TRUNCATES file content over
      // ~1 MB (`truncated: true`) — a pushed blob that big would read back
      // corrupt and fail GCM with the useless "No readable remote vault".
      // The upload now fails truthfully instead.
      // v2.18.0 — R27-F7 (audit): the files contract is REQUIRED — a 200
      // whose body is not the gist JSON (intercepting proxy, weird gateway)
      // used to return true with the write never confirmed.
      let data = null
      try { data = await res.json() } catch { data = null }
      const f = data?.files?.[GIST_FILENAME]
      if (!f) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub gist update did not return the files contract', {
          userMessage: 'GitHub answered unexpectedly after the upload (no file confirmation came back) — the vault may NOT be stored. Check the connection and try again.',
        })
      }
      if (f.truncated) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub truncated the gist content (API cap)', {
          userMessage: 'The vault is too large for a GitHub gist — the upload was truncated. Use WebDAV, Dropbox or a Custom URL for big vaults.',
        })
      }
      return true
    } catch (e) {
      throw classifySyncError(e, { context: 'GitHub gist update' })
    }
  },

  async download(config) {
    const gistId = await this._getGistId(config)
    try {
      const res = await fetchWithRetry(`${this._apiBase(config)}/gists/${gistId}`, {
        headers: { 'Authorization': `token ${this._authToken(config)}` },
      }, { context: 'GitHub gist download', retries: 1, op: 'download' })
      // v2.18.0 — R27-F7: a non-JSON 200 (proxy/HTML) must read as a
      // protocol error with guidance, not a raw SyntaxError.
      let data = null
      try { data = await res.json() } catch { data = null }
      if (!data || typeof data !== 'object') {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub gist download did not return the JSON contract', {
          userMessage: 'GitHub answered with something UCrypt does not understand — check the connection/proxy and try again.',
        })
      }
      const f = data?.files?.[GIST_FILENAME]
      // v2.16.0 — R25-F5: a truncated read-back can never decrypt — say so.
      if (f?.truncated) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'the stored gist was truncated (content over the API cap)', {
          userMessage: 'The stored gist is incomplete (GitHub truncates large content) — re-push from the device that holds the full vault.',
        })
      }
      // v2.17.0 — R26-F7: an EMPTY stored file is not the same as "no vault
      // yet" — a lost/truncated write left an empty husk behind. Say so.
      const content = typeof f?.content === 'string' && f.content.length ? f.content : null
      if (!content && f && !f.truncated) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'the stored gist file is empty', {
          userMessage: 'The stored vault file is empty — the last upload may have been interrupted. Push again from a device that still holds the vault.',
        })
      }
      return content === INIT_MARKER ? null : content
    } catch (e) {
      if (e instanceof SyncError && e.status === 404) return null
      throw classifySyncError(e, { context: 'GitHub gist download' })
    }
  },

  // R112 §3.1 (law 0.26) — the safe reseed's archive leg: the old bytes are
  // added to the SAME gist under a sibling filename (<vault>.<archiveName>)
  // BEFORE the primary file is re-uploaded — rename, never delete. (A gist
  // PATCH that adds a file never touches the existing files.)
  canArchive() { return true },
  async archiveUpload(rawContent, config, archiveName) {
    const gistId = await this._getGistId(config)
    try {
      const res = await fetchWithRetry(`${this._apiBase(config)}/gists/${gistId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `token ${this._authToken(config)}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          files: { [GIST_FILENAME + '.' + archiveName]: { content: rawContent } },
        }),
      }, { context: 'GitHub gist archive', op: 'upload' })
      let data = null
      try { data = await res.json() } catch { data = null }
      const f = data?.files?.[GIST_FILENAME + '.' + archiveName]
      if (!f) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub gist archive did not return the files contract', {
          userMessage: 'The archive copy could not be confirmed — nothing was overwritten.',
        })
      }
      if (f.truncated) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'GitHub gist archive content truncated', {
          userMessage: 'The archive copy would be truncated by GitHub — nothing was overwritten.',
        })
      }
      return GIST_FILENAME + '.' + archiveName
    } catch (e) {
      if (e instanceof SyncError) throw e
      throw classifySyncError(e, { context: 'GitHub gist archive' })
    }
  },

  async testConnection(config) {
    if (!this._authToken(config)) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'GitHub transport: no token configured', { userMessage: 'Connect GitHub (Connect button — PKCE, gist scope only) or paste a token under Advanced.' })
    try {
      const res = await fetchWithRetry(`${this._apiBase(config)}/user`, {
        headers: { 'Authorization': `token ${this._authToken(config)}` },
      }, { context: 'GitHub test', retries: 0 })
      // v2.18.0 — R27-F6 (audit): every non-ok status used to read as
      // "Invalid GitHub token" — a 5xx outage is not a token problem. The
      // status picks the kind (401/403 → AUTH, 5xx → SERVER, …).
      if (!res.ok) {
        throw new SyncError(kindForStatus(res.status), `GitHub test failed: ${res.status}`, { status: res.status })
      }
      const data = await res.json()
      return `Connected as ${data.login || 'unknown'}`
    } catch (e) {
      throw classifySyncError(e, { context: 'GitHub test' })
    }
  },
}
