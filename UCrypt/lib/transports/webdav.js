/**
 * WebDAV transport (v2.3.0) — stores the encrypted vault on the user's server.
 *
 * v2.1.0 fix (audit finding #12): Basic auth used btoa(user + ':' + pass),
 * which throws on non-Latin1 credentials. Now encodes UTF-8 properly.
 *
 * v2.3.0: every request goes through fetchWithRetry — 15s deadline, bounded
 * exponential backoff on transient failures, and classified SyncErrors
 * instead of raw fetch strings.
 */

import { bytesToBase64 } from '../crypto.js'
import { fetchWithRetry, classifySyncError, SYNC_ERROR_KINDS, SyncError } from './http.js'

const NO_URL_USER_MSG = 'Add your WebDAV URL first — the full URL to the vault file on your server.'
// v2.17.0 — R26-F8: optimistic concurrency. The ETag of the last GET is kept
// in local storage and replayed as If-Match on PUT, so two devices writing
// simultaneously produce a truthful 412 ("remote changed — pull first")
// instead of a silent file-level last-write-wins.
// v2.18.0 — R27-F1 (audit): the stored ETag must track the LAST WRITE too —
// after a successful PUT the old download-ETag went stale and every OTHER
// push ate a spurious 412 until an intermediate pull refreshed it. The PUT
// response now refreshes the stored ETag (or invalidates it when the server
// returns none), so If-Match always carries the version we know is current.
// Weak etags (W/"…") are never captured nor replayed: If-Match requires the
// STRONG comparison (RFC 7232 §3.1).
const ETAG_KEY = 'ucrypt:webdav:etag'
const WEAK_ETAG_RE = /^W\//i

function strongEtag(raw) {
  const t = String(raw || '').trim()
  return t && !WEAK_ETAG_RE.test(t) ? t : null
}

export const webdav = {
  name: 'WebDAV',
  fields: [
    { key: 'url', label: 'WebDAV URL', type: 'url', placeholder: 'https://cloud.example.com/path/ucrypt.enc', help: 'Full URL to your WebDAV server (Nextcloud, Synology, etc.)' },
    { key: 'user', label: 'Username (optional)', type: 'text', placeholder: 'username', help: 'If your WebDAV server requires auth' },
    { key: 'pass', label: 'Password (optional)', type: 'password', placeholder: 'password', help: 'If your WebDAV server requires auth' },
  ],

  _headers(config) {
    const headers = {}
    if (config.user && config.pass) {
      const bytes = new TextEncoder().encode(config.user + ':' + config.pass)
      headers['Authorization'] = 'Basic ' + bytesToBase64(bytes)
    }
    return headers
  },

  async upload(encryptedBlob, config) {
    // v2.16.0 — R25-F10: this transport was missing the CONFIG guard the
    // others have, so a missing URL surfaced as a generic network error.
    if (!config?.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'WebDAV transport: no url configured', { userMessage: NO_URL_USER_MSG })
    try {
      // v2.17.0 — R26-F8: If-Match replay (when an ETag is known) +
      // redirect:'manual'. Browsers re-issue a PUT answered by a 301/302 as
      // a GET — that 200 used to count as a successful write while NOTHING
      // was stored. A manual redirect surfaces as status 0 and is refused
      // truthfully below.
      const headers = { 'Content-Type': 'application/octet-stream', ...this._headers(config) }
      let etag = null
      try {
        if (typeof chrome !== 'undefined' && chrome.storage?.local) {
          etag = strongEtag((await chrome.storage.local.get(ETAG_KEY))[ETAG_KEY]) // weak → never replayed
        }
      } catch { /* storage unavailable — proceed without If-Match */ }
      if (etag) headers['If-Match'] = etag
      const res = await fetchWithRetry(config.url, {
        method: 'PUT',
        redirect: 'manual',
        headers,
        body: encryptedBlob,
      }, { context: 'WebDAV upload', op: 'upload' })
      // v2.16.0 — R25-F8: an HTML page in answer to a PUT is the signature of
      // a captive portal / a wrong URL (a login page, not the WebDAV file).
      const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
      if (ct.includes('text/html')) {
        let head = ''
        try {
          head = ((await res.text()) || '').slice(0, 120).replace(/[\u0000-\u001f]+/g, ' ').trim()
        } catch { /* body unreadable */ }
        if (/<html[\s>]/i.test(head)) {
          throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `WebDAV upload answered with HTML (${head})`, {
            userMessage: 'The server answered the upload with a web page, not a WebDAV response — check that the URL points at a WebDAV FILE path.',
          })
        }
      }
      // v2.18.0 — R27-F1: the write SUCCEEDED — make the stored ETag reflect
      // the content we just wrote. Servers usually echo the new ETag on a
      // 200/201/204 PUT; when they don't, the stored value is stale by
      // definition and must be INVALIDATED (the next push then goes without
      // If-Match instead of failing a precondition it can never satisfy).
      try {
        const newEtag = strongEtag(res.headers?.get?.('etag'))
        if (typeof chrome !== 'undefined' && chrome.storage?.local) {
          if (newEtag) await chrome.storage.local.set({ [ETAG_KEY]: newEtag })
          else await chrome.storage.local.remove(ETAG_KEY)
        }
      } catch { /* best effort — worst case the next push 412s truthfully */ }
      return true
    } catch (e) {
      // v2.17.0 — R26-F8: two truthful special cases.
      if (e instanceof SyncError && e.status === 0) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'WebDAV upload was redirected (status 0 / opaque redirect)', {
          cause: e,
          userMessage: 'The server answered the upload with a redirect — WebDAV writes must go to the FINAL file URL. Open the URL once in a browser, copy where it ends up, and use that address.',
        })
      }
      if (e instanceof SyncError && e.status === 412) {
        // R137 §9: the typed refusal now carries its status on the wire too
        // (the doctor's mapper reads e.status; the card text is unchanged).
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'WebDAV upload rejected by If-Match (412 precondition failed)', {
          cause: e,
          status: 412,
          userMessage: 'The remote vault changed on the server since the last pull — pull from the cloud first to merge, then push again.',
        })
      }
      throw classifySyncError(e, { context: 'WebDAV upload' })
    }
  },

  async download(config) {
    if (!config?.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'WebDAV transport: no url configured', { userMessage: NO_URL_USER_MSG })
    try {
      const res = await fetchWithRetry(config.url, { headers: this._headers(config) }, { context: 'WebDAV download', retries: 1, op: 'download' })
      // v2.17.0 — R26-F8: remember the server's ETag so the next PUT can
      // protect against a concurrent overwrite. v2.18.0 — R27-F1: weak etags
      // are never stored (If-Match cannot carry them).
      const etag = strongEtag(res.headers?.get?.('etag'))
      if (etag && typeof chrome !== 'undefined' && chrome.storage?.local) {
        try { await chrome.storage.local.set({ [ETAG_KEY]: etag }) } catch { /* best effort */ }
      }
      const text = await res.text()
      // v2.17.0 — R26-F2/F7: an HTML answer is a portal/login page, never the
      // vault; an EMPTY stored file is a lost write, not "nothing stored".
      const ct = String(res.headers?.get?.('content-type') || '').toLowerCase()
      if (ct.includes('text/html')) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'WebDAV download answered with HTML', {
          userMessage: 'The server answered with a web page instead of the vault file — check that the URL points at a WebDAV FILE path.',
        })
      }
      if (!text || !text.trim()) {
        throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, 'WebDAV download: the stored file is empty', {
          userMessage: 'The stored vault file is empty — the last upload may have been interrupted. Push again from a device that still holds the vault.',
        })
      }
      return text
    } catch (e) {
      // A missing file is a normal state for a first device — not an error.
      if (e instanceof SyncError && e.status === 404) {
        // v2.19.0 — R28-F1 (audit 28a-1): the stored ETag belongs to a file
        // that NO LONGER EXISTS. Keeping it would replay a dead If-Match on
        // the recovery push — and per RFC 7232 an If-Match against a
        // non-existent resource 412s — bricking every push forever while the
        // 404 download kept "confirming" the file is absent. Clear it so the
        // next PUT creates the file unconditionally.
        try {
          if (typeof chrome !== 'undefined' && chrome.storage?.local) {
            await chrome.storage.local.remove(ETAG_KEY)
          }
        } catch { /* best effort */ }
        return null
      }
      throw classifySyncError(e, { context: 'WebDAV download' })
    }
  },

  // R85 (§5): real cloud-copy delete — DELETE the envelope resource.
  async deleteVault(config) {
    if (!config?.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'WebDAV transport: no url configured', { userMessage: NO_URL_USER_MSG })
    try {
      const res = await fetchWithRetry(config.url, { method: 'DELETE', headers: this._headers(config) }, { context: 'WebDAV delete', retries: 0 })
      return res.ok || res.status === 404
    } catch (e) {
      return e instanceof SyncError && e.status === 404
    }
  },

  // R112 §3.1 (law 0.26) — THE SAFE RESEED'S ARCHIVE LEG. The unreadable
  // cloud copy is preserved under a sibling name ("rename — never delete"):
  // the old bytes land at <vault URL>.<archiveName> BEFORE anything
  // overwrites the primary. No If-Match replay (this is a sibling write,
  // not a concurrency-controlled overwrite) and no ETag bookkeeping — the
  // primary's concurrency state stays exactly as it was.
  canArchive() { return true },
  async archiveUpload(rawContent, config, archiveName) {
    if (!config?.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'WebDAV transport: no url configured', { userMessage: NO_URL_USER_MSG })
    const archiveUrl = config.url + '.' + archiveName
    try {
      const res = await fetchWithRetry(archiveUrl, {
        method: 'PUT',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/octet-stream', ...this._headers(config) },
        body: rawContent,
      }, { context: 'WebDAV archive', retries: 1, op: 'upload' })
      if (!res.ok) {
        throw new SyncError(SYNC_ERROR_KINDS.SERVER, `WebDAV archive write failed: ${res.status}`, {
          status: res.status,
          userMessage: 'The archive copy could not be written next to the vault file — nothing was overwritten.',
        })
      }
      return archiveUrl
    } catch (e) {
      if (e instanceof SyncError) throw e
      throw classifySyncError(e, { context: 'WebDAV archive' })
    }
  },

  async testConnection(config) {
    if (!config?.url) throw new SyncError(SYNC_ERROR_KINDS.CONFIG, 'WebDAV transport: no url configured', { userMessage: NO_URL_USER_MSG })
    try {
      // F-R91-TEST404 (P2, found LIVE by the R91 matrix): fetchWithRetry
      // throws a terminal SyncError for any non-ok status not in
      // okStatuses — which made BOTH probes throw on a 404 long before the
      // R85 empty-endpoint success branch could run (dead code; a fresh
      // first-device setup read as "✗ WebDAV test failed: 404" — a false
      // failure for the MOST COMMON first-run state). 404 is now a
      // caller-owned terminal outcome on both probes: the server answered
      // and the vault file simply does not exist yet.
      // Try a HEAD (cheap) first — many WebDAV servers support it.
      const res = await fetchWithRetry(config.url, { method: 'HEAD', headers: this._headers(config) }, { context: 'WebDAV test', retries: 0, okStatuses: [404] })
      if (res.ok) return 'WebDAV server reachable'
      if (res.status === 404) return 'Transport OK — vault not created yet (the first sync will create it)'
      // HEAD might not be supported — fall back to a GET (404 is still "reachable").
      const res2 = await fetchWithRetry(config.url, { headers: this._headers(config) }, { context: 'WebDAV test', retries: 0, okStatuses: [404] })
      if (res2.ok) return 'WebDAV server reachable'
      // R85 (F-R84-T4): an EMPTY endpoint is a SUCCESS, not a failure — the
      // server answered, the credentials were accepted, and the vault file
      // simply does not exist yet (first push creates it). The message says
      // exactly that so a fresh setup never reads as a dead end.
      if (res2.status === 404) return 'Transport OK — vault not created yet (the first sync will create it)'
      throw new SyncError(SYNC_ERROR_KINDS.SERVER, `WebDAV connection failed: ${res2.status}`, { status: res2.status })
    } catch (e) {
      throw classifySyncError(e, { context: 'WebDAV test' })
    }
  },
}
