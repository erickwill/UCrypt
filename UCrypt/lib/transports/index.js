/**
 * UCrypt Transport registry (v2.2.0) — all sync transports in one place.
 *
 * AUDIT NOTE (v2.1.0): this registry existed but was NEVER imported by any UI
 * (finding #1) — the "5 transports + guided wizard" were unreachable dead
 * code. v2.2.0 wires it into the options Sync tab for real.
 *
 * Each transport implements the same interface:
 *   .id            — unique identifier
 *   .name          — display name
 *   .fields        — array of { key, label, type, placeholder, help }
 *   .setupSteps    — array of { step, title, text, link } for the guided wizard
 *   .upload(blob, config)   — store the encrypted blob → Promise<true>
 *   .download(config)       — retrieve the encrypted blob → Promise<string|null>
 *   .testConnection(config) — verify credentials → Promise<string>
 *
 * Honesty table (what each transport does to your data):
 *   Google Drive — ciphertext goes to YOUR Drive via YOUR Apps Script bridge.
 *   Dropbox      — ciphertext to your Dropbox via official API + token.
 *   GitHub Gist  — ciphertext as a SECRET gist on your account.
 *   WebDAV       — ciphertext to your own server (Nextcloud, Synology…).
 *   Custom URL   — ciphertext to any PUT/GET endpoint you control.
 *   Manual       — no network at all: encrypted export file you move yourself.
 */

export { dropbox } from './dropbox.js'
export { github } from './github.js'
// F-R91-VERIFYBRIDGE-DEADPATH (P2): verifyBridgeStages must be reachable
// from the worker's transport module — without this re-export the
// TRANSPORT_GDRIVE_VERIFY handler's `typeof t.verifyBridgeStages ===
// 'function'` guard failed, and EVERY bridge-mode verification silently
// ran the OAuth stage list instead (a dead path the R91 matrix caught
// live: a /dev bridge URL reported 'client-id: ✗' instead of the url/ping/
// read stages).
export { gdrive, gdriveBridgeScript, verifyBridgeStages } from './gdrive.js'
export { webdav } from './webdav.js'
export { custom } from './custom.js'

import { dropbox } from './dropbox.js'
import { github } from './github.js'
import { gdrive } from './gdrive.js'
import { webdav } from './webdav.js'
import { custom } from './custom.js'
import { SyncError, SYNC_ERROR_KINDS } from './http.js'

/**
 * All registered transports. R45-B MODE 2 ORDER: the working self-hosted
 * paths lead (WebDAV, Custom URL), the user-deployed Drive bridge follows,
 * and the two developer-console transports (GitHub PAT, Dropbox token) are
 * explicitly Advanced and last — no disabled-OAuth card is ever the primary
 * recommendation, and no card claims a consumer sign-in that does not exist.
 *
 * Honesty table (what each transport does to your data):
 *   WebDAV       — ciphertext to your own server (Nextcloud, Synology…).
 *   Custom URL   — ciphertext to any PUT/GET endpoint you control.
 *   Google Drive — ciphertext to YOUR Drive via a bridge script YOU deploy.
 *   GitHub Gist  — ciphertext as a SECRET gist on your account (PAT, Advanced).
 *   Dropbox      — ciphertext to your Dropbox via a token YOU generate (Advanced).
 *   Manual       — no network at all: encrypted export file you move yourself.
 */
export const transports = [
  {
    id: 'webdav',
    ...webdav,
    icon: '🌐',
    difficulty: 1,
    description: 'Use your own WebDAV server (Nextcloud, Synology, ownCloud…). Maximum control — the blob lives on hardware you own.',
    setupSteps: [
      { step: 1, title: 'Find your WebDAV URL', text: 'Nextcloud: Settings → look for the WebDAV URL. Synology: Control Panel → File Services → WebDAV. Example: https://cloud.example.com/remote.php/dav/files/yourname/', link: '' },
      { step: 2, title: 'Add a filename', text: 'Append a filename to the URL, e.g. …/yourname/ucrypt-vault.enc', link: '' },
      { step: 3, title: 'Enter credentials (if needed)', text: 'If your server requires a username/password, enter them below. UCrypt uses Basic auth over HTTPS.', link: '' },
      { step: 4, title: 'Test the connection', text: 'Paste the URL below and click "Test connection". Upload uses PUT, download uses GET.', link: '' },
    ],
  },
  {
    id: 'custom',
    ...custom,
    icon: '⚙️',
    difficulty: 2,
    description: 'Any HTTP endpoint that accepts PUT (upload) and GET (download). For advanced users — S3 presigned URLs, REST stores, self-hosted scripts.',
    setupSteps: [
      { step: 1, title: 'Prepare your endpoint', text: 'Any server that accepts HTTP PUT (to store) and GET (to retrieve) works — S3 presigned URLs, a tiny script of your own, any REST key-value API.', link: '' },
      { step: 2, title: 'Paste the URL below', text: 'Auth tokens can be embedded in the URL path or query string. The URL is stored ENCRYPTED (R45 credential envelope) and redacted in the UI.', link: '' },
      { step: 3, title: 'Test the connection', text: 'Click "Test connection" to verify UCrypt can reach your endpoint.', link: '' },
    ],
  },
  {
    id: 'gdrive',
    ...gdrive,
    icon: '📁',
    difficulty: 3,
    // R91 (S-A/S-E label-truth): the description renders TRUE state — OAuth
    // is the PRIMARY mode since R85; the bridge is the Advanced alternative.
    description: 'Store the encrypted vault in your Google Drive. Recommended: sign in with your Google account (OAuth). Advanced: a small bridge script you deploy once (copy-paste, ~3 minutes).',
    // R90 §1.2 — CLINICALLY VERIFIED step texts (verified live this round:
    // script.google.com walked in the stage browser — a signed-out visit
    // lands on the developer landing, so step 1 names the sign-in — and the
    // deployment-dialog shape verified against Google's CURRENT Apps Script
    // docs fetched this run (developers.google.com/apps-script/guides/web:
    // "Deploy > New deployment" → "Select type" → "Web app" → "Deployment
    // configuration" fields; the /dev-vs-/exec trap is Google's own
    // documented wording). The two classic traps are IN the instructions:
    // access "Anyone" (the extension's fetch is not signed in) and the
    // /exec URL (a /dev link only works for the owner; /edit is never a
    // deployment URL). The authorize chain names what the user actually
    // sees: the unverified-app screen (Advanced → "Go to project (unsafe)")
    // — the step that used to stop people with a scary warning.
    setupSteps: [
      { step: 1, title: 'Open Google Apps Script', text: 'Sign in at script.google.com, then click "New project" and delete the placeholder code.', link: 'https://script.google.com' },
      { step: 2, title: 'Paste the UCrypt bridge script', text: 'Copy the pre-filled script below (it already contains your secret) and paste it into the editor, replacing everything.', link: '' },
      { step: 3, title: 'Deploy as Web app', text: 'Click Deploy → "New deployment" → under "Select type" choose "Web app" → set Execute as "Me" and Who has access "Anyone" (the bridge must be reachable without a Google sign-in) → Deploy, then authorize when asked (Advanced → "Go to project (unsafe)" → Allow).', link: '' },
      { step: 4, title: 'Copy the /exec URL', text: 'Copy the Web app URL — it ends in /exec; a /dev link only works for you — paste it below, then click "Test connection".', link: '' },
    ],
  },
  {
    id: 'github',
    ...github,
    icon: '🐙',
    difficulty: 4,
    advanced: true,
    // R91 (S-A/S-E): OAuth (gist scope only) is primary; the token is the
    // Advanced path. The stale no-OAuth claim of the previous card text is gone.
    description: 'Store the encrypted vault as a secret GitHub Gist. Recommended: sign in with GitHub (OAuth, gist scope only). Advanced: paste a personal access token. Second devices adopt the same gist automatically.',
    setupSteps: [
      { step: 1, title: 'Go to GitHub token settings', text: 'Open github.com/settings/tokens → "Generate new token" → "Generate new token (classic)".', link: 'https://github.com/settings/tokens' },
      { step: 2, title: 'Configure the token', text: 'Name it "UCrypt". Select ONLY the "gist" scope (uncheck everything else). Click "Generate token".', link: '' },
      { step: 3, title: 'Copy the token', text: 'Copy the token that appears (starts with "ghp_"). You won\'t be able to see it again.', link: '' },
      { step: 4, title: 'Paste it below', text: 'Paste the token into the field below. UCrypt creates (or adopts) a secret Gist automatically.', link: '' },
    ],
  },
  {
    id: 'dropbox',
    ...dropbox,
    icon: '📦',
    difficulty: 4,
    advanced: true,
    // R91 (S-A/S-E): the OAuth app-key connect is primary; the console token
    // is the Advanced path.
    description: 'Store the encrypted vault in your Dropbox. Recommended: sign in with Dropbox (OAuth). Advanced: paste an access token from the developer console.',
    setupSteps: [
      { step: 1, title: 'Go to Dropbox Developer Apps', text: 'Open dropbox.com/developers/apps → click "Create app".', link: 'https://www.dropbox.com/developers/apps' },
      { step: 2, title: 'Create the app', text: 'Choose "Scoped access" → "Full Dropbox access" → name it "UCrypt". Click "Create app".', link: '' },
      { step: 3, title: 'Generate an access token', text: 'Scroll to "OAuth 2" → "Generated access token" → click "Generate". Copy the token that appears (~4 h validity — regenerate when it expires).', link: '' },
      { step: 4, title: 'Paste it below', text: 'Paste the access token into the field below, then click "Test connection" to verify.', link: '' },
    ],
  },
]

/** Get a transport by ID. Unknown ids are a TYPED refusal (R137 §9 — the
 * connect-button contract: every connect-path failure is a SyncError with a
 * user-facing why + next, never an untyped throw). */
export function getTransport(id) {
  const t = transports.find((tr) => tr.id === id) || null
  if (!t) {
    throw new SyncError(SYNC_ERROR_KINDS.CONFIG, `Unknown transport: ${id}`, {
      userMessage: 'This cloud transport is not available in this build — pick one of the listed transports in the sync settings.',
      recovery: { kind: 'transport_unknown', title: 'That cloud transport does not exist.', causes: ['The transport id came from an older build or a foreign config.'], fix: 'Open Sync settings and choose a listed transport, then press Connect.' },
    })
  }
  return t
}

/** Upload the encrypted blob through the configured transport. */
export async function syncUpload(encryptedBlob, transportId, config) {
  const transport = getTransport(transportId)
  return transport.upload(encryptedBlob, config)
}

/** Download the encrypted blob through the configured transport. */
export async function syncDownload(transportId, config) {
  const transport = getTransport(transportId)
  return transport.download(config)
}

/** R178 — R-178.3 THE EVIDENCE SEAM: download WITH the remote's own evidence
 * (file id + byte count + modified time) when the transport offers it. A
 * transport without the seam rides the plain download (evidence null — the
 * honest absence, never a guess). The pull row carries this evidence, so
 * "the cloud copy was read" can never again mean "only the first hop
 * answered" (the map's Adjudication 5). */
export async function syncDownloadWithEvidence(transportId, config) {
  const transport = getTransport(transportId)
  if (typeof transport.downloadWithEvidence === 'function') {
    return transport.downloadWithEvidence(config)
  }
  const blob = await transport.download(config)
  return { blob, evidence: null }
}

/** Test a transport connection (verify credentials/endpoints). */
export async function testTransport(transportId, config) {
  const transport = getTransport(transportId)
  return transport.testConnection(config)
}
