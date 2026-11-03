/**
 * UCrypt — R124 §2 (D13) — THE PICKUP TRANSPORT BRIDGE.
 *
 * The hold uploads the sealed pickup blob to the SENDER'S OWN cloud and
 * creates a native shared link the receiver can fetch WITHOUT credentials,
 * NO account, NO grant. The honest-support table (law 0.38):
 *
 *   gdrive   OAuth/fast rungs  — SUPPORTED: a NEW Drive file (never the vault
 *                                file) + the anyone-with-link reader
 *                                permission → the anonymous download link.
 *                                The BRIDGE rung (an Apps Script web app) has
 *                                no link mechanism — honestly unsupported.
 *   dropbox  any connection    — SUPPORTED: a NEW /ucrypt-pickup-*.bin file +
 *                                sharing_create_shared_link_with_settings
 *                                (public) → the dl=1 direct link.
 *   github   any connection    — SUPPORTED: a NEW SECRET GIST (never the vault
 *                                gist) whose raw_url is anonymously
 *                                fetchable; the envelope is text so it rides
 *                                a gist verbatim.
 *   webdav   — NOT SUPPORTED (no link mechanism). Custom URL — NOT SUPPORTED.
 *              The label says so; the LIVE share still works when both are
 *              online (the honest absence, never a dead end).
 *
 * THE CLEANUP LAW: every hold carries a cleanupRef; pickupCancel removes the
 * uploaded artifact (the sender's "Cancel the hold" button deletes the
 * ciphertext from their cloud — the hold dies on cancel, on expiry sweep, or
 * on manual deletion; nothing persists that could outlive the TTL).
 *
 * THE NO-VAULT LAW: this file NEVER imports vault.js/sync.js and NEVER
 * touches the vault file, the vault gist, or the vault path — the pickup
 * artifacts are new, named, and removable (the separation law 0.27 holds).
 */

import { fetchWithRetry, SyncError, SYNC_ERROR_KINDS } from './http.js'
import { ensureAccessToken, isApiMode, isFastOrAppDataMode } from './gdrive.js'
import { _accessToken } from './dropbox.js'
import { authTokenFor, apiBaseFor } from './github.js'
import { PICKUP_CLOUD_NAME } from '../pickup.js'

const DRIVE_UPLOAD_BASE = 'https://www.googleapis.com/upload/drive/v3'
const DRIVE_BASE = 'https://www.googleapis.com/drive/v3'
const DRIVE_WEB_LINK = 'https://drive.google.com/uc?export=download&id='
const DROPBOX_CONTENT = 'https://content.dropboxapi.com'
const DROPBOX_API = 'https://api.dropboxapi.com'

/** The honest-support table (0.38). Reason strings are stable (the battery pins them). */
export function pickupSupport(providerId, config) {
  switch (providerId) {
    case 'gdrive':
      if (isApiMode(config)) return { supported: true, label: 'Google Drive' }
      return { supported: false, reason: 'bridge-mode', label: 'Google Drive' }
    case 'dropbox':
      return { supported: true, label: 'Dropbox' }
    case 'github':
      return { supported: true, label: 'GitHub' }
    case 'webdav':
      return { supported: false, reason: 'transport', label: 'WebDAV' }
    case 'custom':
      return { supported: false, reason: 'transport', label: 'Custom URL' }
    default:
      return { supported: false, reason: 'unknown', label: '' }
  }
}

function pickupError(kind, message, userMessage) {
  return new SyncError(kind, message, { userMessage })
}

function bytesToText(bytes) {
  return new TextDecoder().decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
}

function randSuffix() {
  const b = crypto.getRandomValues(new Uint8Array(6))
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('')
}

/**
 * Upload ONE pickup blob and mint its shared link.
 * Returns { link, cleanupRef, provider } — the caller builds the notice.
 * cleanupRef is OPAQUE to the caller; pickupCancel is its only consumer.
 */
export async function pickupUploadAndLink(providerId, config, blobBytes) {
  const support = pickupSupport(providerId, config)
  if (!support.supported) {
    throw pickupError(
      SYNC_ERROR_KINDS.CONFIG,
      `Pickup transport ${providerId} does not support holds (${support.reason})`,
      'This transport cannot hold a pickup — the live share still works when both devices are online.',
    )
  }
  const body = bytesToText(blobBytes)
  if (providerId === 'gdrive') return gdriveHold(config, body)
  if (providerId === 'dropbox') return dropboxHold(config, body)
  if (providerId === 'github') return githubHold(config, body)
  throw pickupError(SYNC_ERROR_KINDS.CONFIG, `Pickup transport ${providerId} unhandled`, 'This transport cannot hold a pickup.')
}

// ── Google Drive (the OAuth/fast rungs) ─────────────────────────────────────

async function gdriveHold(config, blobText) {
  const token = await ensureAccessToken(config)
  const boundary = 'ucrypt-pickup-' + randSuffix()
  const metadata = JSON.stringify({ name: PICKUP_CLOUD_NAME, mimeType: 'application/octet-stream' })
  const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n${blobText}\r\n--${boundary}--`
  let up
  try {
    up = await fetchWithRetry(`${DRIVE_UPLOAD_BASE}/files?uploadType=multipart&fields=id`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
      body,
    }, { context: 'Pickup upload (Drive)', retries: 1, ring: { flow: 'pickup', transport: 'gdrive', stage: 'hold-upload' } })
  } catch (e) {
    if (e && e.status === 403 && isFastOrAppDataMode(config)) {
      throw pickupError(
        SYNC_ERROR_KINDS.AUTH,
        'Pickup upload (Drive) requires drive.file permission for public share links',
        'Public pickup links require visible Drive file permissions (Guided OAuth with drive.file) — or use the Transfer tab’s direct Mailbox / off-road .ucrypt-transfer file, which works with Fast Sign-In (drive.appdata).',
      )
    }
    throw e
  }
  if (!up.ok) throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Pickup upload (Drive) failed: ${up.status}`, { status: up.status })
  const meta = await up.json()
  const id = meta && meta.id
  if (!id) throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Pickup upload (Drive): no file id in the answer', {})
  // THE LINK: the file's own anyone-with-link reader permission — it grants
  // ONLY this file's ciphertext (never the vault, never the folder).
  // F-R124-HOLD-LITTER-1: fetchWithRetry THROWS on a refused status (it does
  // not return a response for the caller to inspect) — the cleanup must ride
  // the catch too, or a failed link litters the cloud with an unshared husk.
  const cleanup = async () => {
    try { await fetch(`${DRIVE_BASE}/files/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }) } catch { /* best effort */ }
  }
  let perm
  try {
    perm = await fetchWithRetry(`${DRIVE_BASE}/files/${id}/permissions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'reader', type: 'anyone', withLink: true }),
    }, { context: 'Pickup link (Drive)', retries: 1, ring: { flow: 'pickup', transport: 'gdrive', stage: 'hold-link' } })
  } catch (e) {
    await cleanup()
    throw e
  }
  if (!perm.ok) {
    await cleanup()
    throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Pickup link (Drive) failed: ${perm.status}`, { status: perm.status })
  }
  return { link: DRIVE_WEB_LINK + id + '&confirm=t', cleanupRef: { kind: 'gdrive', id }, provider: 'gdrive' }
}

// ── Dropbox ──────────────────────────────────────────────────────────────────

async function dropboxHold(config, blobText) {
  const accessToken = await _accessToken(config)
  const apiBase = String(config?.apiBase || '').trim().replace(/\/+$/, '') || DROPBOX_API
  const contentBase = String(config?.apiBase || '').trim().replace(/\/+$/, '') || DROPBOX_CONTENT
  const path = `/ucrypt-pickup-${randSuffix()}.bin`
  const up = await fetchWithRetry(`${contentBase}/2/files/upload`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Dropbox-API-Arg': JSON.stringify({ path, mode: 'overwrite', mute: true }),
      'Content-Type': 'application/octet-stream',
    },
    body: blobText,
  }, { context: 'Pickup upload (Dropbox)', retries: 1, ring: { flow: 'pickup', transport: 'dropbox', stage: 'hold-upload' } })
  if (!up.ok) throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Pickup upload (Dropbox) failed: ${up.status}`, { status: up.status })
  const linkRes = await fetchWithRetry(`${apiBase}/2/sharing/create_shared_link_with_settings`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, settings: { requested_visibility: 'public', audience: 'public', access: 'viewer' } }),
  }, { context: 'Pickup link (Dropbox)', retries: 1, ring: { flow: 'pickup', transport: 'dropbox', stage: 'hold-link' }, okStatuses: [200, 409] })
  const linkBody = await linkRes.json().catch(() => null)
  let link = linkBody && linkBody.url
  if (!link) {
    // A link already exists for this path (409 shared_link_already_exists) —
    // list it instead of failing (the retry/idempotent face).
    const listRes = await fetchWithRetry(`${apiBase}/2/sharing/list_shared_links`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, direct_only: true }),
    }, { context: 'Pickup link list (Dropbox)', retries: 1 })
    const listBody = await listRes.json().catch(() => null)
    link = listBody && Array.isArray(listBody.links) && listBody.links[0] && listBody.links[0].url
  }
  if (!link) throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Pickup link (Dropbox): no link in the answer', {})
  // THE DIRECT FACE: dl.dropboxusercontent.com answers bytes, not the viewer page.
  const direct = link.replace('www.dropbox.com', 'dl.dropboxusercontent.com')
  return { link: direct, cleanupRef: { kind: 'dropbox', path }, provider: 'dropbox' }
}

// ── GitHub (a NEW secret gist — never the vault gist) ───────────────────────

async function githubHold(config, blobText) {
  const token = authTokenFor(config)
  if (!token) throw pickupError(SYNC_ERROR_KINDS.CONFIG, 'Pickup (GitHub): no token configured', 'Connect GitHub or paste a token first — then the hold can use your cloud.')
  const base = apiBaseFor(config)
  const res = await fetchWithRetry(`${base}/gists`, {
    method: 'POST',
    headers: { Authorization: `token ${token}`, 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' },
    body: JSON.stringify({
      description: 'UCrypt pickup',
      public: false,
      files: { [PICKUP_CLOUD_NAME]: { content: blobText } },
    }),
  }, { context: 'Pickup upload (GitHub)', retries: 1, ring: { flow: 'pickup', transport: 'github', stage: 'hold-upload' } })
  if (!res.ok) throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Pickup upload (GitHub) failed: ${res.status}`, { status: res.status })
  const gist = await res.json()
  const raw = gist && gist.files && gist.files[PICKUP_CLOUD_NAME] && (gist.files[PICKUP_CLOUD_NAME].raw_url || gist.files[PICKUP_CLOUD_NAME].rawURL)
  if (!gist.id || !raw) throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Pickup upload (GitHub): no raw url in the answer', {})
  // The secret gist's raw_url is anonymously fetchable — the link grants ONLY
  // this file (the vault gist is never touched, never linked).
  return { link: raw, cleanupRef: { kind: 'github', id: gist.id }, provider: 'github' }
}

// ── The cancel (the hold dies on demand — the ciphertext leaves the cloud) ──

/**
 * Delete the held artifact. Best-effort truth: the answer names whether the
 * cloud confirmed the removal; a network hiccup returns { ok:false } and the
 * surface says so — never a silent "probably gone".
 */
export async function pickupCancel(providerId, config, cleanupRef) {
  try {
    if (!cleanupRef || !cleanupRef.kind) return { ok: false, code: 'no_ref' }
    if (cleanupRef.kind === 'gdrive') {
      const token = await ensureAccessToken(config)
      const res = await fetch(`${DRIVE_BASE}/files/${cleanupRef.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
      return { ok: res.ok || res.status === 404, code: res.ok ? 'deleted' : (res.status === 404 ? 'already-gone' : 'cloud_error') }
    }
    if (cleanupRef.kind === 'dropbox') {
      const accessToken = await _accessToken(config)
      const apiBase = String(config?.apiBase || '').trim().replace(/\/+$/, '') || DROPBOX_API
      const res = await fetch(`${apiBase}/2/files/delete_v2`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: cleanupRef.path }),
      })
      return { ok: res.ok || res.status === 409, code: res.ok ? 'deleted' : (res.status === 409 ? 'already-gone' : 'cloud_error') }
    }
    if (cleanupRef.kind === 'github') {
      const token = authTokenFor(config)
      const res = await fetch(`${apiBaseFor(config)}/gists/${cleanupRef.id}`, {
        method: 'DELETE',
        headers: { Authorization: `token ${token}` },
      })
      return { ok: res.ok || res.status === 404, code: res.ok ? 'deleted' : (res.status === 404 ? 'already-gone' : 'cloud_error') }
    }
    return { ok: false, code: 'no_ref' }
  } catch (e) {
    return { ok: false, code: 'network', error: String((e && e.message) || e).slice(0, 120) }
  }
}
