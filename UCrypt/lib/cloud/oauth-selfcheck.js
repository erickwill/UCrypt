/**
 * ════════════════════════════════════════════════════════════════════════
 * R174 — THE OAUTH SELF-CHECK (the field's sixth word, the end of guessing).
 *
 * The field spoke a sixth time: the owner pressed the one-click sign-in on
 * what they believed was the latest build and Google answered with the red
 * "Access blocked — Error 400: redirect_uri_mismatch" page — and the error
 * page's own URL proved the request had ridden the RETIRED client
 * 1047722433028-… (client_id=1047722433028-8c3c65c55a3go… in the address
 * bar) — a build older than the factory rewiring. Two truths had to become
 * visible IN the product, before any window opens:
 *
 *   1. WHICH client and WHICH redirect this exact browser build sends
 *      (the runtime identity: UCrypt version, the extension's own ID,
 *      chrome.identity.getRedirectURL()).
 *   2. WHETHER Google accepts that client + redirect pair — answerable
 *      with ZERO windows and ZERO user data: Google's token endpoint
 *      validates the client and the redirect BEFORE the grant. A POST
 *      with a deliberately bogus authorization code returns a typed
 *      error that names the exact defect:
 *        invalid_grant          → the client EXISTS and the redirect IS
 *                                 registered — the pair is HEALTHY
 *        redirect_uri_mismatch  → the redirect is not registered on the
 *                                 client (the exact cure: register it or
 *                                 fix the Item ID)
 *        invalid_client         → Google does not recognize the client
 *                                 (deleted / another project)
 *        unauthorized_client    → the client's TYPE cannot serve the flow
 *                                 (Desktop/Android/TV) — recreate as
 *                                 Chrome extension / Web application
 *
 * THE RETIRED-CLIENT LIST also lives here — R169 UPDATE (the named
 * correction): the list is now the DEAD TWO (probe-proven deleted_client at
 * R174c — T2 and T4). The FIRST client 1047722433028-… REVIVED as the LANE C
 * client (the R169 CSA amendment — the Chrome silent accelerator; the owner
 * fixes its Item ID Console-side), so it left the dead list and rides the
 * manifest. Lane membership lives in lib/cloud/oauth-clients.js (the
 * two-lane registry) and is re-exported here under the established names.
 *
 * ENGINE-ONLY: no DOM, no chrome.i18n; the chrome seam and fetch are
 * injectable so the battery drives every branch without a browser.
 * ════════════════════════════════════════════════════════════════════════
 */

import { LANE_U_CLIENT_ID, LANE_C_CLIENT_ID, DEAD_GDRIVE_CLIENTS, isDeadClientId, isLaneUClientId, isLaneCClientId, laneForClientId } from './oauth-clients.js'

export { LANE_U_CLIENT_ID, LANE_C_CLIENT_ID, isLaneUClientId, isLaneCClientId, laneForClientId }

/** Google's OAuth 2.0 token endpoint (the probe's seat — CORS-open, and the
 * manifest's host_permissions already carry https://oauth2.googleapis.com/*). */
export const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token'

/** The RETIRED clients — probe-proven dead (deleted_client, R174c T2/T4),
 * never ride ANY lane again. (Name kept for the established consumers.) */
export const RETIRED_GDRIVE_CLIENTS = DEAD_GDRIVE_CLIENTS

/** Is this client ID retired (probe-proven deleted)? (the guard's pure seat) */
export function isRetiredClientId(clientId) {
  return isDeadClientId(clientId)
}

/** The printable tail of a client ID (…last-12) — IDs are public values;
 * the tail keeps cards compact while staying letter-comparable. */
export function clientTail(clientId) {
  const s = String(clientId || '').trim()
  return s.length > 16 ? '…' + s.slice(-12) : s
}

/**
 * The runtime identity (the facts the field must be able to SEE in-product):
 * { version, extId, redirect, manifestClientId, laneUClientId, laneCClientId }.
 * R169 — the TWO clients ride the card: the manifest client (Lane C's seat)
 * AND the universal-lane constant (Lane U's seat) so the letter-compares
 * happen on the card, not in a Console tab. Engine-only: every chrome read
 * is guarded, so the battery (no chrome) gets honest empties.
 */
export function runtimeIdentity(chromeLike = null) {
  const c = chromeLike || (typeof chrome !== 'undefined' ? chrome : null)
  let version = ''
  let manifestClientId = ''
  try {
    const m = c && c.runtime && typeof c.runtime.getManifest === 'function' ? c.runtime.getManifest() : null
    version = String((m && m.version) || '')
    manifestClientId = String((m && m.oauth2 && m.oauth2.client_id) || '')
  } catch { /* non-extension context — honest empties */ }
  let extId = ''
  let redirect = ''
  try {
    extId = String((c && c.runtime && c.runtime.id) || '')
    redirect = (c && c.identity && typeof c.identity.getRedirectURL === 'function')
      ? String(c.identity.getRedirectURL() || '')
      : ''
  } catch { /* non-extension context — honest empties */ }
  return { version, extId, redirect, manifestClientId, laneUClientId: LANE_U_CLIENT_ID, laneCClientId: LANE_C_CLIENT_ID }
}

/**
 * THE SELF-CHECK PROBE — one POST, no window, no user data.
 *
 * The probe sends a deliberately bogus authorization code with the client
 * and redirect under test. Google's contract: it validates the client and
 * the registered redirect BEFORE the grant, so the typed error NAMES the
 * defect. Nothing secret rides (public clients carry no secret), nothing
 * user-owned rides (the code is a random nonce), and the response is one
 * of Google's typed OAuth errors.
 *
 * @param {{clientId: string, redirect: string, fetchImpl?: typeof fetch,
 *           now?: () => number}} facts
 * @returns {Promise<{ok: 'healthy'|'mismatch'|'client-missing'|'wrong-type'
 *                     |'client-deleted'|'web-secret-rule'
 *                     |'untyped'|'offline'|'bad-input',
 *                     title: string, detail: string, raw: string}>}
 */
export async function oauthSelfCheck(facts) {
  const clientId = String((facts && facts.clientId) || '').trim()
  const redirect = String((facts && facts.redirect) || '').trim()
  const fetchImpl = (facts && facts.fetchImpl) || (typeof fetch === 'function' ? fetch : null)
  if (!clientId || !redirect || !fetchImpl) {
    return {
      ok: 'bad-input',
      title: 'The self-check has nothing to test yet — the client or the redirect is absent in this browser context.',
      detail: '',
      raw: '',
    }
  }
  const nonceBytes = new Uint8Array(12)
  try { crypto.getRandomValues(nonceBytes) } catch { nonceBytes.fill(7) }
  const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  const body = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirect,
    grant_type: 'authorization_code',
    code: 'ucrypt-selfcheck-' + nonce,
  })
  let res = null
  let rawText = ''
  try {
    res = await fetchImpl(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    rawText = await res.text().catch(() => '')
  } catch (e) {
    return {
      ok: 'offline',
      title: 'The self-check could not reach Google — the network is offline or blocked.',
      detail: String((e && e.message) || e).slice(0, 200),
      raw: '',
    }
  }
  let j = null
  try { j = JSON.parse(rawText) } catch { j = null }
  const err = String((j && j.error) || '').toLowerCase()
  const desc = String((j && j.error_description) || '')
  if (err === 'invalid_grant') {
    return {
      ok: 'healthy',
      title: 'HEALTHY — Google recognizes the client AND accepted this exchange pair.',
      detail: 'Google checked the client BEFORE the grant and refused only the deliberately-bogus code — the healthy answer. For a Web-application (confidential) client this also proves the redirect registration; for public client types (installed/native) Google can answer invalid_grant before validating the redirect, so the sign-in window stays the judge there. If the sign-in window still shows an error, read the code on Google\u2019s page and press the sign-in again after the Console fix (changes can take Google five minutes to a few hours to take effect).',
      raw: desc.slice(0, 200),
    }
  }
  if (err === 'redirect_uri_mismatch') {
    return {
      ok: 'mismatch',
      title: 'MISMATCH — this redirect URI is NOT registered on that client (the Error 400 cause).',
      detail: 'Google Cloud Console → APIs & Services → Credentials → this client → EITHER set the Chrome-extension client\u2019s Item ID to this extension\u2019s own ID letter-exact, OR (Web-application type) add this EXACT redirect URI to Authorized redirect URIs: ' + redirect + ' (the trailing slash is part of the value) → Save. Then wait a few minutes and press the sign-in again.',
      raw: desc.slice(0, 200),
    }
  }
  if (err === 'deleted_client') {
    return {
      ok: 'client-deleted',
      title: 'DELETED CLIENT — this OAuth client was deleted in the Google Cloud Console.',
      detail: 'Create the replacement "Web application" client (Cloud Console → APIs & Services → Credentials → Create credentials → OAuth client ID → Web application) with the EXACT redirect URIs from the card above (the trailing slash is part of the value), then connect with the NEW client ID. Console changes can take Google five minutes to a few hours to take effect.',
      raw: desc.slice(0, 200),
    }
  }
  if (err === 'invalid_request' && /client_secret/i.test(desc)) {
    return {
      ok: 'web-secret-rule',
      title: 'THE CLIENT EXISTS — Google enforced the Web-application confidential-client rule at the exchange.',
      detail: 'Google refused the secret-less probe with its OWN rule words (client_secret is missing) BEFORE validating the redirect — this client type cannot be probed deeper from here, but it is NOT deleted and NOT unknown. The sign-in window is the judge for the redirect registration: press Connect and read the window; if Google shows redirect_uri_mismatch there, add the EXACT redirect URI from the card above to this client\u2019s Authorized redirect URIs (the trailing slash is part of the value).',
      raw: desc.slice(0, 200),
    }
  }
  if (err === 'invalid_client') {
    return {
      ok: 'client-missing',
      title: 'CLIENT MISSING — Google does not recognize this client ID (deleted, disabled, or from another project).',
      detail: 'Google Cloud Console → APIs & Services → Credentials → confirm the client exists in the SAME project and is Enabled; re-copy its client ID if needed.',
      raw: desc.slice(0, 200),
    }
  }
  if (err === 'unauthorized_client') {
    return {
      ok: 'wrong-type',
      title: 'WRONG TYPE — the client\u2019s application type cannot serve this flow (Desktop/Android/TV cannot take a chromiumapp.org redirect).',
      detail: 'Create a NEW client of type "Web application" (Cloud Console → APIs & Services → Credentials → Create credentials → OAuth client ID → Web application) and add this EXACT redirect URI to its Authorized redirect URIs: ' + redirect + ' (the trailing slash is part of the value) — then connect with the NEW client ID. The corrected order retires the native/Chrome-extension class from the sign-in path.',
      raw: desc.slice(0, 200),
    }
  }
  return {
    ok: 'untyped',
    title: 'Google answered with an unexpected shape — the raw answer rides for the receipt.',
    detail: '',
    raw: (rawText || '').slice(0, 240),
  }
}
