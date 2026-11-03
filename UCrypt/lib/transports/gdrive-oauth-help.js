/**
 * UCrypt — Google Drive OAuth typed-recovery helpers (R87 §2.1).
 *
 * The CEO's S7 blocker: driving the OAuth flow to Google produced Google's
 * raw "Error 400: redirect_uri_mismatch" with no recovery path in-product.
 * R87 law: Google's failures are mapped to TYPED, actionable recovery cards —
 * the exact redirect URI to register, the likely causes ranked, and the next
 * action — never a raw error string, never "Failed to fetch".
 *
 * Pure module (no chrome.* imports) so the unit battery can exercise every
 * branch; the UI renders whatever this returns verbatim.
 */

/** The client-ID shape Google issues for OAuth 2.0 client IDs
 * (Web application / Desktop / TV formats all share this suffix). */
const CLIENT_ID_RE = /^[0-9]{8,20}-[a-z0-9]{8,64}\.apps\.googleusercontent\.com$/

// R116 §2.2 — THE OWNER CHECKLIST, in-product (the CEO's S2/S3 words made
// law 0.29's content): the two-sentence fix a disabled / testing-mode client
// needs, at 13-year-old reading level, exported so the battery pins the
// exact wording and the i18n gate pins the ×3 locale keys.
export const GOOGLE_CONSOLE_CREDENTIALS_URL = 'https://console.cloud.google.com/apis/credentials'
export const GOOGLE_CLIENT_DISABLED_FIX =
  'Your Google OAuth client is disabled or in testing mode. ' +
  'Cloud Console → OAuth consent screen → Publish to production, then Credentials → confirm the client is Enabled — then Connect again.'

/**
 * Pre-flight: client ID format validation (§2.1d) — catches paste errors
 * (truncated IDs, client secrets pasted by mistake, IDs from other fields)
 * BEFORE any network round-trip.
 */
export function validateClientIdFormat(clientId) {
  const id = String(clientId || '').trim()
  if (!id) {
    return { ok: false, reason: 'empty', message: 'No client ID yet — complete step 2 (or open the guide below if you do not have one).' }
  }
  if (/\.apps\.googleusercontent\.com$/i.test(id) && !CLIENT_ID_RE.test(id)) {
    return { ok: false, reason: 'malformed', message: 'This looks like a Google client ID but the format is off — re-copy the whole value from Google Cloud Console → Credentials (it ends in .apps.googleusercontent.com).' }
  }
  if (/^GOCSPX-/i.test(id) || /client[-_ ]?secret/i.test(id)) {
    return { ok: false, reason: 'secret-pasted', message: 'That looks like a client SECRET, not a client ID. UCrypt never needs a secret — paste the client ID (it ends in .apps.googleusercontent.com).' }
  }
  if (!CLIENT_ID_RE.test(id)) {
    return { ok: false, reason: 'not-a-client-id', message: 'This does not look like a Google OAuth client ID — it should end in .apps.googleusercontent.com.' }
  }
  return { ok: true, reason: 'valid', message: 'Client ID format OK.' }
}

/**
 * Typed Google error mapping (§2.1c). Returns a recovery card:
 * { kind, title, expectedRedirect, causes: [..], fix } — never a raw error.
 */
export function typedGoogleError({ error, errorDescription, status, redirect } = {}) {
  const err = String(error || (errorDescription || '').split(/[\s,(]/)[0] || '').toLowerCase()
  const desc = String(errorDescription || '')
  const redirectUri = String(redirect || '(the redirect URI shown in the card above)')
  // R172 — THE RECREATE-CONSOLE TRUTH (the CEO's decree + the field verdict:
  // the "installed"-type receipt could never serve a chromiumapp.org
  // redirect — the Item-ID edit had no seat). The FIRST-CLASS cure is a
  // client of type "Chrome extension" whose Item ID equals the extension's
  // own ID: Google pairs the redirect automatically and the client is
  // public (no secret). The Web-application type stays sanctioned.
  const causes3 = [
    `The Authorized redirect URI registered in the Google client differs from the one UCrypt shows — it must be EXACTLY ${redirectUri} (no trailing slash, no http, no localhost).`,
    'The client ID belongs to a different OAuth client than the one with the redirect URI registered (each client has its own URI list).',
    'The client was created with type "Desktop", "Android", "TV" or "Chrome app" — create a NEW client of type "Chrome extension" (Item ID = this extension\u2019s own ID) or use a "Web application" client with the redirect URI above.',
  ]
  if (err === 'redirect_uri_mismatch' || /redirect_uri_mismatch/i.test(desc)) {
    return {
      kind: 'redirect_uri_mismatch',
      title: 'Google rejected the redirect URI (Error 400: redirect_uri_mismatch).',
      expectedRedirect: redirectUri,
      causes: causes3,
      fix: `RECREATE THE CLIENT (the R172 cure, about two minutes): Google Cloud Console → APIs & Services → Credentials → Create credentials → OAuth client ID → type "Chrome extension" → Item ID = this extension\u2019s own ID (${redirectUri.replace(/\.chromiumapp\.org\/$/, '')}) → Create → copy the NEW client ID → paste it in step 2 here → Connect. (In-place alternative for a "Web application" client: Authorized redirect URIs → add exactly ${redirectUri} → Save, wait a few minutes.)`,
    }
  }
  // R116 §2.1/§2.2 (the refresh-path completion; the CEO's S2) — THE
  // DISABLED-CLIENT CARD, the cause-class precision law: a disabled or
  // testing-mode OAuth client must NEVER render as "expired login" (that
  // was the S2 regression's exact harm — the wrong card sends the user to
  // re-sign-in when the cure lives in the Cloud Console). Google's own
  // words: error invalid_client + description "The OAuth client was
  // disabled." The card carries THE OWNER CHECKLIST (two sentences, ×3
  // locales, 13-year-old level) and the console deep link.
  if (
    (err === 'invalid_client' || /invalid[_ ]client/i.test(desc)) &&
    (/disabl|deactivat|not enabled|inactive/i.test(desc) || /disabl/i.test(err))
  ) {
    return {
      kind: 'client_disabled',
      title: 'Your Google OAuth client is disabled or in testing mode (invalid_client).',
      expectedRedirect: redirectUri,
      consoleUrl: GOOGLE_CONSOLE_CREDENTIALS_URL,
      causes: [
        'The OAuth consent screen is in "Testing" mode — Google then expires every grant after 7 idle days and some account types are refused.',
        'The OAuth client itself is disabled in the Google project (Google said so in its own words).',
        'Nothing on this device caused it — the vault, the grant and the secrets are untouched.',
      ],
      fix: GOOGLE_CLIENT_DISABLED_FIX,
    }
  }
  if (err === 'invalid_client' || /invalid[_ ]client/i.test(desc)) {
    return {
      kind: 'invalid_client',
      title: 'Google does not recognize this client ID (invalid_client).',
      expectedRedirect: redirectUri,
      consoleUrl: GOOGLE_CONSOLE_CREDENTIALS_URL,
      causes: [
        'The client ID was pasted incompletely (a truncated copy keeps only part of the value).',
        'The OAuth client was deleted, or it belongs to a different Google project.',
      ],
      fix: 'Re-copy the full client ID from Google Cloud Console → APIs & Services → Credentials (it ends in .apps.googleusercontent.com) into step 2, then press Connect again.',
    }
  }
  if (err === 'access_denied' || /access[_ ]denied/i.test(desc)) {
    return {
      kind: 'access_denied',
      title: 'The Google authorization was not granted (access_denied).',
      expectedRedirect: redirectUri,
      causes: [
        'Cancel was pressed inside the Google window.',
        'The Google Workspace administrator blocks this app for the account (see the org-policy row below).',
      ],
      fix: 'Press Connect again and choose Allow on the Google consent screen. If your account is managed and the app is blocked, register the app with your administrator or use a personal account.',
    }
  }
  if (err === 'unauthorized_client' || /unauthorized[_ ]client/i.test(desc)) {
    return {
      kind: 'unauthorized_client',
      title: 'Google refuses this client type (unauthorized_client).',
      expectedRedirect: redirectUri,
      causes: [
        'The client was created with a type that cannot use this flow (Desktop/Android/TV instead of "Chrome extension" or "Web application").',
        'An organization policy (Google Workspace admin) disallows this client for OAuth grants.',
      ],
      fix: 'Recreate the OAuth client as type "Chrome extension" (Item ID = this extension\u2019s own ID — the R172 cure), or as "Web application" with the redirect URI above, or register the client with your Workspace administrator.',
    }
  }
  if (err === 'admin_policy_enforced' || /admin[_ ]policy|org[- ]?policy|disallowed/i.test(desc)) {
    return {
      kind: 'admin_policy_enforced',
      title: 'A Google organization policy blocked the authorization (admin_policy_enforced).',
      expectedRedirect: redirectUri,
      causes: [
        'The account is managed and the admin has not allow-listed UCrypt\'s OAuth client.',
        'The configured app access level ("In use by third-party services") excludes this client.',
      ],
      fix: 'Ask the Workspace administrator to allow-list the client ID under Security → API controls → App access control, or use a personal Google account.',
    }
  }
  if (err === 'invalid_grant' || /invalid[_ ]grant/i.test(desc)) {
    return {
      kind: 'invalid_grant',
      title: 'The Google grant is no longer valid (invalid_grant).',
      expectedRedirect: redirectUri,
      consoleUrl: GOOGLE_CONSOLE_CREDENTIALS_URL,
      causes: [
        'The grant was revoked (myaccount.google.com/permissions) or expired after 7 idle days on a Testing-mode client.',
        'The device clock drifted more than a few minutes.',
      ],
      fix: 'Press Connect to run a fresh authorization (UCrypt always re-asks with consent so a new refresh token is issued). If this keeps happening every few days, the client is in Testing mode — publish the consent screen to production so grants stop expiring.',
    }
  }
  // R92 §1.1/§1.3 — THE CEO'S LIVE EMPIRICAL FINDING, now a typed card.
  // R172 CORRECTION — the card's old second cause claimed "no public-client
  // option exists for chromiumapp.org redirects". THE FIELD FALSIFIED IT:
  // a client of type "Chrome extension" (Item ID = the extension's own ID)
  // IS the public-client path — no secret, no bridge, the redirect paired
  // by Google. The card now names all THREE sanctioned paths honestly.
  if (err === 'invalid_request' && /client_secret/i.test(desc)) {
    return {
      kind: 'client_secret_missing',
      title: 'Google requires your client secret for direct sign-in (invalid_request: client_secret is missing).',
      expectedRedirect: redirectUri,
      causes: [
        'Google treats "Web application" clients as CONFIDENTIAL: the token exchange demands the client secret even with PKCE. This is a Google platform rule — nothing was misconfigured on your side.',
        'THE NO-SECRET PATH EXISTS: a client of type "Chrome extension" (Item ID = this extension\u2019s own ID) is public — paste its client ID, leave the secret empty, press Connect.',
        'The no-secret Bridge (Advanced) stays sanctioned: a user-deployed Apps Script web app.',
      ],
      fix: 'Choose ONE of the three paths Google permits: (1) THE R172 CURE — recreate the client as type "Chrome extension" (Item ID = this extension\u2019s own ID), paste its client ID in step 2, NO secret, press Connect; (2) Direct sign-in — paste your own client secret in the field below (it is sealed in your vault on this device — never synced, never logged, never exported); or (3) the no-secret Bridge (Advanced). All are first-class paths.',
    }
  }
  if (err === 'origin_mismatch' || /origin[_ ]mismatch/i.test(desc)) {
    return {
      kind: 'origin_mismatch',
      title: 'The request origin is not allowed for this client (origin_mismatch).',
      expectedRedirect: redirectUri,
      causes: [
        'The client is a "Web application" whose JavaScript origins list does not include this browser origin.',
      ],
      fix: 'In Google Cloud Console → Credentials → your client, either add the origin shown in the error or use the redirect URI flow (Web application type with the redirect URI above).',
    }
  }
  // Fallback — still typed, still actionable, never a bare "Failed to fetch".
  return {
    kind: 'google_error_untyped',
    title: `Google refused the authorization${err ? ` (${err})` : (status ? ` (HTTP ${status})` : '')}.`,
    expectedRedirect: redirectUri,
    causes: [
      desc ? `Google said: ${desc.slice(0, 240)}` : 'Google closed the authorization window without an answer.',
      'The client configuration (type, redirect URI, or test-user list) may not match what UCrypt sends.',
    ],
    fix: `Verify the client in Google Cloud Console allows redirect URI ${redirectUri}, the client type is "Web application", and (for Testing-mode consent screens) your Google account is listed under Test users — then press Connect again.`,
  }
}

/** The honest 3-step "get a client ID" guide (§2.1d empty state).
 * R92 §1.2: step 3 now states the two-path law truthfully — Google's
 * confidential-client rule means direct sign-in uses YOUR secret (sealed in
 * your vault, device-only), or you deploy the no-secret Bridge instead. */
export const CLIENT_ID_GUIDE = [
  'Open console.cloud.google.com → create (or pick) a project → APIs & Services → OAuth consent screen → External (or Internal for Workspace) → add yourself as a Test user while in Testing.',
  'APIs & Services → Library → enable "Google Drive API" for the project (the drive.file scope needs it).',
  'APIs & Services → Credentials → Create credentials → OAuth client ID → type "Chrome extension" → Item ID: paste this extension\u2019s own ID (the card shows it; also in chrome://extensions) → Create → copy the client ID here — NO secret needed (the Chrome-extension client is public). Then choose your path: the no-secret connection (just Connect), Direct sign-in (a "Web application" client + your secret below — sealed in your vault on this device), or the no-secret Bridge (Advanced).',
]

/**
 * R92 §1.2 — the one-sentence choice the card's primary copy carries:
 * "Direct sign-in (paste your secret) or the no-secret Bridge."
 * Exported so the battery can pin the exact wording ×3 locales' source.
 */
export const TWO_PATH_CHOICE = 'Direct sign-in (paste your secret) or the no-secret Bridge.'

/** The own-secret honesty line (the Advanced secret field's help text). */
export const OWN_SECRET_HELP = 'Google requires your client secret for direct sign-in. It is sealed in your vault on this device — never synced, never logged, never exported. Or skip it and use the no-secret Bridge (Advanced).'

/** The compact status line shown when the owner has not supplied a client ID. */
export const NEEDS_CLIENT_ID_STATUS = 'Google Drive OAuth requires a client ID from the owner — steps 1–3 above create it in about two minutes. Nothing is sent anywhere until you press Connect.'

// --- R87 (§2.3): shared OAuth PKCE primitives for the GitHub/Dropbox cards ---

export function b64url(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return { verifier, challenge: b64url(digest) }
}

/** The pinned, stable redirect URI (manifest key ⇒ deterministic id). */
export function identityRedirect() {
  return (chrome?.identity?.getRedirectURL) ? chrome.identity.getRedirectURL() : ''
}

/**
 * Run an OAuth authorization through chrome.identity.launchWebAuthFlow
 * (NEVER getAuthToken) and return the redirect URL for code parsing.
 *
 * S4 (the CEO's brief — R126): the window's failure shapes are TYPED here
 * too — the fast rung's window (the dropbox PKCE, the gdrive probe) names
 * its cause with a machine tag so the card layer maps it without parsing
 * raw engine strings: [auth_window_closed] / [auth_window_timeout] /
 * [auth_window_blocked] / [auth_window_failed]. The tag rides the error
 * message's head; the transport layer's catch maps it to the same four
 * recovery cards the guided flow renders.
 *
 * R171 — THE SETTLED-UNMATCHED HONESTY (the owner's R171 field verdict:
 * the window OPENED onto Google's own red "Access blocked — Error 400:
 * redirect_uri_mismatch" page and the user closed it after reading —
 * Chrome's own words for exactly that shape are "The user did not approve
 * access.", which the old classifier tagged auth_window_failed — "the
 * window failed to open" — A LIE that then fell through to CODEBASE). The
 * shape gets its OWN tag, checked FIRST: [auth_window_settled_unmatched]
 * — the window opened and settled without completing. Never again a
 * "failed to open" claim about a window that lived.
 */
export async function launchOAuthFlow(authorizeUrl) {
  if (!chrome?.identity?.launchWebAuthFlow || !chrome.identity.getRedirectURL) {
    throw new Error('[auth_window_failed] This browser does not expose chrome.identity.launchWebAuthFlow.')
  }
  try {
    return await chrome.identity.launchWebAuthFlow({ url: authorizeUrl, interactive: true })
  } catch (e) {
    const raw = String((e && e.message) || e)
    // R171 — the settled-unmatched shape is checked FIRST: Chrome's "The
    // user did not approve access." means the window OPENED and was closed
    // before completing — never "failed to open", never CODEBASE.
    const tag = /did not approve|not approve access/i.test(raw)
      ? 'auth_window_settled_unmatched'
      : /cancel|dismiss|denied|closed by the user/i.test(raw)
        ? 'auth_window_closed'
        : (/timeout|timed out/i.test(raw)
          ? 'auth_window_timeout'
          : (/could not be loaded|popup|blocked|window/i.test(raw)
            ? 'auth_window_blocked'
            : 'auth_window_failed'))
    const wrapped = new Error(`[${tag}] ${raw}`)
    wrapped.cause = e
    throw wrapped
  }
}
