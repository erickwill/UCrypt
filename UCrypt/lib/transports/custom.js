/**
 * Custom URL transport (v2.3.0) — the most generic option.
 * Works with ANY HTTP endpoint that accepts PUT (upload) and GET (download).
 *
 * Examples of what this supports:
 * - A simple server you run yourself (e.g. `python -m http.server` with PUT)
 * - Amazon S3 presigned URLs
 * - Any REST API that stores key-value pairs
 * - A webhook that stores data
 *
 * The user just pastes a URL. The extension uploads via PUT, downloads via GET.
 * The URL can include auth tokens in the path or query string.
 *
 * v2.3.0: timeout + retry + classified errors via the shared http.js helper.
 */

import { fetchWithRetry, classifySyncError, SYNC_ERROR_KINDS, SyncError } from './http.js'

export const custom = {
  name: 'Custom URL',
  fields: [
    { key: 'url', label: 'URL (accepts PUT + GET)', type: 'url', placeholder: 'https://your-server.com/ucrypt', help: 'Any HTTP endpoint that accepts PUT (upload) and GET (download). Auth tokens can be in the URL.' },
  ],

  async upload(encryptedBlob, config) {
    if (!config.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Custom URL transport: no url configured')
    try {
      // v2.17.0 — R26-F13: an HTML answer to a PUT (captive portal, a
      // mis-pasted URL hitting a website) is NOT a successful write — the
      // other transports check this since v2.16.0; this one had no check.
      const res = await fetchWithRetry(config.url, {
        method: 'PUT',
        redirect: 'manual', // a PUT answered by a 3xx is re-issued as a GET — that 200 lies about the write
        headers: { 'Content-Type': 'application/octet-stream' },
        body: encryptedBlob,
      }, { context: 'Custom URL upload', op: 'upload' })
      const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
      if (ct.includes('text/html')) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Custom URL upload answered with HTML', {
          userMessage: 'The endpoint answered the upload with a web page, not a storage response — the vault was NOT stored. Check the URL.',
        })
      }
      return true
    } catch (e) {
      // v2.18.0 — R27-F8 (audit): the redirect refusal used to sit AFTER the
      // fetchWithRetry call — unreachable, because a non-ok response throws
      // inside the helper before the caller ever sees it. The catch now
      // maps the opaque-redirect failure to the same truthful guidance
      // (webdav.js has had this since R26-F8).
      if (e instanceof SyncError && e.status === 0) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Custom URL upload was redirected (status 0 / opaque redirect)', {
          cause: e,
          userMessage: 'The endpoint answered the upload with a redirect — PUT must go to the FINAL URL. Follow the redirect once and paste the final address.',
        })
      }
      throw classifySyncError(e, { context: 'Custom URL upload' })
    }
  },

  async download(config) {
    if (!config.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Custom URL transport: no url configured')
    try {
      const res = await fetchWithRetry(config.url, {}, { context: 'Custom URL download', retries: 1, op: 'download' })
      // v2.17.0 — R26-F2/F7: HTML is never the vault; an EMPTY stored file is
      // a lost write, not "nothing stored yet".
      const text = await res.text()
      const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
      if (ct.includes('text/html')) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Custom URL download answered with HTML', {
          userMessage: 'The endpoint answered with a web page instead of the vault — check the URL.',
        })
      }
      if (!text || !text.trim()) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'Custom URL download: the stored file is empty', {
          userMessage: 'The stored vault file is empty — the last upload may have been interrupted. Push again from a device that still holds the vault.',
        })
      }
      return text
    } catch (e) {
      if (e instanceof SyncError && e.status === 404) return null
      throw classifySyncError(e, { context: 'Custom URL download' })
    }
  },

  // R112 §3.1 (law 0.26) — the safe reseed's archive leg (sibling write to
  // <vault URL>.<archiveName>; the old bytes survive, the primary is then
  // re-uploaded fresh; nothing is ever deleted).
  canArchive() { return true },
  async archiveUpload(rawContent, config, archiveName) {
    if (!config.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Custom URL transport: no url configured')
    const archiveUrl = config.url + '.' + archiveName
    try {
      const res = await fetchWithRetry(archiveUrl, {
        method: 'PUT',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: rawContent,
      }, { context: 'Custom URL archive', retries: 1, op: 'upload' })
      if (!res.ok) {
        throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Custom URL archive write failed: ${res.status}`, {
          status: res.status,
          userMessage: 'The archive copy could not be written next to the vault file — nothing was overwritten.',
        })
      }
      return archiveUrl
    } catch (e) {
      if (e instanceof SyncError) throw e
      throw classifySyncError(e, { context: 'Custom URL archive' })
    }
  },

  async testConnection(config) {
    if (!config.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'Custom URL transport: no url configured')
    try {
      // F-R91-TEST404 (same class as the WebDAV fix): 404 is a caller-owned
      // terminal outcome here too — the R85-era "no vault yet" success
      // branches were unreachable dead code behind fetchWithRetry's
      // terminal non-ok throw.
      // Try a HEAD request (cheap)
      const res = await fetchWithRetry(config.url, { method: 'HEAD' }, { context: 'Custom URL test', retries: 0, okStatuses: [404] })
      if (res.ok) return 'Server reachable'
      if (res.status === 404) return 'Server reachable (no vault yet)'
      // HEAD might not work — try GET (404 is OK, means server is up but no data yet)
      const res2 = await fetchWithRetry(config.url, {}, { context: 'Custom URL test', retries: 0, okStatuses: [404] })
      if (res2.status === 404) return 'Server reachable (no vault yet)'
      if (res2.ok) return 'Server reachable (vault found)'
      throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Connection failed: ${res2.status}`, { status: res2.status })
    } catch (e) {
      throw classifySyncError(e, { context: 'Custom URL test' })
    }
  },
}
