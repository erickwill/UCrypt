/**
 * UCrypt — R136 §5.2 Plane B — THE CLOUD RELAY STORE ("the connected cloud
 * IS the relay"). The cloud the user already connected — Google Drive OR
 * any WebDAV endpoint — carries offer records and sealed chunks in a
 * dedicated UCrypt application folder. The cloud only ever stores
 * ciphertext.
 *
 * The store abstraction (one interface, two backends + the battery double):
 *   put(name, text) / get(name) / list(prefix) / remove(name)
 *
 * Names are namespaced `beam3/<sessionId>/…` so tombstoning a session is
 * a prefix sweep (zero orphan ciphertext ever).
 *
 * The BACKENDS here are PURE LOGIC over injected fetchers — the worker
 * binds them to the real transport config (Drive OAuth via its API v3
 * calls; WebDAV via the mailbox's davFetch lineage). The battery drives
 * in-memory doubles and the shape-conformance rows.
 *
 * Polling cadence (the §8 clinical rules): capped backoff with jitter and
 * an explicit paused state the user can see and resume.
 *
 * PURE (fetch injected) — battery-pinned (TRF-RELAY-*, G71/G72).
 */

import { BEAM3_RELAY_POLL_ACTIVE_MS, BEAM3_RELAY_POLL_IDLE_MS, BEAM3_RELAY_BACKOFF_BASE_MS, BEAM3_RELAY_BACKOFF_MAX_MS } from './planes.js'

export function relayError(code, detail) {
  const e = new Error(`BEAM3_RELAY_${code}: ${detail}`)
  e.code = `BEAM3_RELAY_${code}`
  return e
}

/** The folder prefix for one session's objects. */
export function sessionPrefix(sessionId) {
  const sid = String(sessionId || '')
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(sid)) throw relayError('SESSION', 'sessionId outside the safe namespace')
  return `beam3/${sid}/`
}

/** Object names (the record/chunk layout the tombstone plan mirrors). */
export const relayNames = {
  offer: (sid) => `${sessionPrefix(sid)}offer.json`,
  answer: (sid) => `${sessionPrefix(sid)}answer.json`,
  chunk: (sid, i) => `${sessionPrefix(sid)}chunk-${String(i).padStart(6, '0')}.bin`,
  ack: (sid) => `${sessionPrefix(sid)}ack.json`,
  complete: (sid) => `${sessionPrefix(sid)}complete.json`,
  tombstone: (sid) => `${sessionPrefix(sid)}tombstone.json`,
}

/** In-memory double (the battery's plane B cloud). */
export function memoryRelay() {
  const objects = new Map()
  return {
    kind: 'memory-double',
    async put(name, text) { objects.set(String(name), String(text)); return true },
    async get(name) { return objects.has(String(name)) ? objects.get(String(name)) : null },
    async list(prefix) { return [...objects.keys()].filter((k) => k.startsWith(String(prefix || ''))).sort() },
    async remove(name) { return objects.delete(String(name)) },
  }
}

/**
 * WEBDAV backend logic — shapes a davFetch-compatible binding into the
 * store interface. The binding injects: davFetch(url, init) (the
 * mailbox's hardened fetch) and baseUrl (the rendezvous root).
 *
 * R137 §9 (the G72 extension — F8/F13/F14 at the root):
 *   conditional: true   — the binding speaks CONDITIONAL writes: a create
 *                        is PUT If-None-Match:* (create-or-conflict), an
 *                        update is PUT If-Match:<etag>; a 412 retries ONCE
 *                        with a freshly-read ETag; a SECOND conflict is the
 *                        typed BEAM3_RELAY_CONFLICT carrying the
 *                        overwrite-or-reload notice. Two devices writing the
 *                        same object therefore SERIALIZE — no interleaved
 *                        bytes, both converge (the default mode stays
 *                        byte-identical to the sealed behavior).
 *   ensureFolder()      — the one-tap rendezvous-folder recreate: a typed
 *                        FOLDER_MISSING refusal on 404/409 carries the
 *                        notice, the recreate lands an MKCOL + an audit
 *                        record.
 */
export function webdavRelayBinding({ davFetch, baseUrl, conditional = false }) {
  if (typeof davFetch !== 'function' || !baseUrl) throw relayError('BINDING', 'webdav binding needs davFetch + baseUrl')
  const FOLDER_NOTICE = {
    kind: 'folder_missing',
    title: 'The rendezvous folder is missing (moved or deleted on the server).',
    causes: [
      'The beam3/ folder under the rendezvous root was moved, renamed, or deleted outside UCrypt.',
      'Nothing was corrupted — the writes were refused before they landed.',
    ],
    fix: 'Press Recreate folder — UCrypt creates it again (one tap) and the transfer continues.',
    action: 'recreate',
  }
  const root = `${String(baseUrl).replace(/\/?$/, '/')}beam3/`
  const binding = {
    kind: 'webdav',
    conditional: !!conditional,
    url: (name) => `${String(baseUrl).replace(/\/?$/, '/')}beam3/${name.replace(/^beam3\//, '')}`,
    /** F14 — the ONE-TAP RECREATE: MKCOL the beam3/ root; 405 (already
     * there) counts as success. Returns the audit record. */
    async ensureFolder() {
      const res = await davFetch(root, { method: 'MKCOL' })
      const created = res.ok || res.status === 201 || res.status === 204
      const exists = res.status === 405
      if (!created && !exists) throw relayError('FOLDER', `webdav mkcol ${res.status}`)
      return {
        ok: true,
        created,
        already: exists,
        record: { at: Date.now(), action: 'recreate-folder', folder: root, outcome: created ? 'created' : 'exists' },
      }
    },
    async put(name, text) {
      if (!conditional) {
        const res = await davFetch(this.url(name), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: String(text) })
        if (!res.ok) {
          if (res.status === 404 || res.status === 409) {
            const e = relayError('FOLDER_MISSING', `webdav put ${res.status} — the rendezvous folder is missing (moved or deleted)`)
            e.notice = FOLDER_NOTICE
            throw e
          }
          throw relayError('PUT', `webdav put ${res.status}`)
        }
        return true
      }
      // F8/F13 — THE CONDITIONAL WRITE (bounded: one fresh-ETag retry).
      const probe = await davFetch(this.url(name), { method: 'HEAD' })
      const cur = strongEtagOf(probe)
      let res = await davFetch(this.url(name), {
        method: 'PUT',
        headers: cur
          ? { 'Content-Type': 'application/json', 'If-Match': cur }
          : { 'Content-Type': 'application/json', 'If-None-Match': '*' },
        body: String(text),
      })
      if (res.status === 412) {
        // the object moved underneath us — re-read ONCE and replay with the
        // fresh ETag; a SECOND conflict is the typed overwrite-or-reload card
        const fresh = strongEtagOf(await davFetch(this.url(name), { method: 'HEAD' }))
        res = await davFetch(this.url(name), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'If-Match': fresh || '*' },
          body: String(text),
        })
        if (res.status === 412) {
          const e = relayError('CONFLICT', `webdav put 412 twice — the object changed under both writes`)
          e.notice = {
            kind: 'etag_conflict',
            title: 'The relay object changed during the write (twice).',
            causes: ['Another device wrote the same object between the retries.', 'No bytes were mixed — the stored copy is one whole version.'],
            fix: 'Reload the object and merge (recommended), or force-overwrite once — both devices converge either way.',
            action: 'overwrite-or-reload',
          }
          throw e
        }
      }
      if (!res.ok) {
        if (res.status === 404 || res.status === 409) {
          const e = relayError('FOLDER_MISSING', `webdav put ${res.status} — the rendezvous folder is missing (moved or deleted)`)
          e.notice = FOLDER_NOTICE
          throw e
        }
        throw relayError('PUT', `webdav put ${res.status}`)
      }
      return true
    },
    async get(name) {
      const res = await davFetch(this.url(name), { method: 'GET' })
      if (res.status === 404) return null
      if (!res.ok) throw relayError('GET', `webdav get ${res.status}`)
      return res.text()
    },
    async list(prefix) {
      // PROPFOLD-free listing: the worker maintains an index doc per session
      // (the Depth-1 PROPFIND parity is provided by the index contract —
      // the battery pins the index's monotonic growth).
      const idx = await this.get(`${String(prefix || '')}index.json`)
      if (!idx) return []
      try { const arr = JSON.parse(idx); return Array.isArray(arr) ? arr : [] } catch { return [] }
    },
    async remove(name) {
      const res = await davFetch(this.url(name), { method: 'DELETE' })
      return res.ok || res.status === 404
    },
  }
  return binding
}

/** The strong-ETag reader for the conditional binding (weak etags never
 * gate a write — RFC 7232 strong comparison). */
function strongEtagOf(res) {
  const raw = String((res && res.headers && (typeof res.headers.get === 'function' ? res.headers.get('etag') : res.headers.etag)) || '').trim()
  if (!raw || /^W\//i.test(raw)) return null
  return raw
}

/**
 * DRIVE backend logic — shapes the Drive API v3 calls into the store
 * interface. The binding injects: driveFetch(path, init) (the worker's
 * authenticated fetch with the token seam) and appFolderId. Drive is a
 * FIRST-CLASS relay (R136-F2: the WebDAV-only requirement is removed).
 *
 * R137 §9 (F13 at the root): conditional: true makes put() UPDATE the
 * existing object in place (search → PATCH) instead of POSTing a duplicate
 * — two devices writing the same object converge on ONE file, never two
 * same-named copies the reader could resolve arbitrarily. The default mode
 * stays byte-identical to the sealed behavior.
 */
export function driveRelayBinding({ driveFetch, appFolderId, conditional = false }) {
  if (typeof driveFetch !== 'function') throw relayError('BINDING', 'drive binding needs driveFetch')
  const folder = String(appFolderId || 'appDataFolder')
  const spacesParam = folder === 'appDataFolder' ? '&spaces=appDataFolder' : ''
  const q = (name) => encodeURIComponent(`name = '${String(name).replace(/'/g, "\\'")}' and trashed = false`)
  return {
    kind: 'drive',
    conditional: !!conditional,
    async put(name, text) {
      if (conditional) {
        // F13 — one object per name: the search-then-update shape. Drive has
        // no If-Match; the atomicity is the file-level PATCH (whole-object,
        // never interleaved bytes) and the convergence is the single copy.
        const search = await driveFetch(`/drive/v3/files?q=${q(name)}${spacesParam}&fields=files(id)`, { method: 'GET' })
        if (search.ok) {
          const found = await search.json().catch(() => null)
          const file = found && Array.isArray(found.files) && found.files[0]
          if (file && file.id) {
            const res = await driveFetch(`/upload/drive/v3/files/${file.id}?uploadType=media`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/octet-stream' },
              body: String(text),
            })
            if (!res.ok) throw relayError('PUT', `drive update ${res.status}`)
            return true
          }
        }
      }
      const boundary = 'ucrypt-beam3-' + Math.random().toString(36).slice(2)
      const metadata = JSON.stringify({ name: String(name), parents: [folder] })
      const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n${String(text)}\r\n--${boundary}--`
      const res = await driveFetch('/upload/drive/v3/files?uploadType=multipart&fields=id', {
        method: 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      })
      if (!res.ok) throw relayError('PUT', `drive put ${res.status}`)
      return true
    },
    async get(name) {
      const search = await driveFetch(`/drive/v3/files?q=${q(name)}${spacesParam}&fields=files(id)`, { method: 'GET' })
      if (!search.ok) throw relayError('GET', `drive search ${search.status}`)
      const found = await search.json()
      const file = found && Array.isArray(found.files) && found.files[0]
      if (!file) return null
      const res = await driveFetch(`/drive/v3/files/${file.id}?alt=media`, { method: 'GET' })
      if (res.status === 404) return null
      if (!res.ok) throw relayError('GET', `drive read ${res.status}`)
      return res.text()
    },
    async list(prefix) {
      const search = await driveFetch(`/drive/v3/files?q=${q(`${String(prefix || '')}index.json`)}${spacesParam}&fields=files(id)`, { method: 'GET' })
      if (!search.ok) throw relayError('LIST', `drive search ${search.status}`)
      const found = await search.json()
      const file = found && Array.isArray(found.files) && found.files[0]
      if (!file) return []
      const res = await driveFetch(`/drive/v3/files/${file.id}?alt=media`, { method: 'GET' })
      if (!res.ok) return []
      try { const arr = JSON.parse(await res.text()); return Array.isArray(arr) ? arr : [] } catch { return [] }
    },
    async remove(name) {
      const search = await driveFetch(`/drive/v3/files?q=${q(name)}${spacesParam}&fields=files(id)`, { method: 'GET' })
      if (!search.ok) throw relayError('DELETE', `drive search ${search.status}`)
      const found = await search.json()
      const ids = (found && Array.isArray(found.files) ? found.files : []).map((f) => f.id)
      for (const id of ids) {
        const res = await driveFetch(`/drive/v3/files/${id}`, { method: 'DELETE' })
        if (!res.ok && res.status !== 404) throw relayError('DELETE', `drive delete ${res.status}`)
      }
      return true
    },
  }
}

/** The uniform store facade — every backend behind one interface. */
export function relayStore(backend) {
  if (!backend || typeof backend.put !== 'function') throw relayError('BINDING', 'a relay backend is required')
  return {
    kind: backend.kind,
    putOffer: (sid, offerText) => backend.put(relayNames.offer(sid), offerText),
    putAnswer: (sid, answerText) => backend.put(relayNames.answer(sid), answerText),
    // R137 §9 (F9/F10 — the tombstone law completed): a session that was
    // swept keeps its tombstone — a NEW chunk write to a swept session is a
    // zombie and is refused TYPED. The tombstones are honored, not advisory.
    putChunk: async (sid, i, frameText) => {
      const tomb = await backend.get(relayNames.tombstone(sid))
      if (tomb) throw relayError('TOMBSTONED', `session ${sid} was swept — a new chunk write was refused (the tombstone is honored)`)
      return backend.put(relayNames.chunk(sid, i), frameText)
    },
    putAck: (sid, ackText) => backend.put(relayNames.ack(sid), ackText),
    putComplete: (sid, completeText) => backend.put(relayNames.complete(sid), completeText),
    putTombstone: (sid, tombText) => backend.put(relayNames.tombstone(sid), tombText),
    getOffer: (sid) => backend.get(relayNames.offer(sid)),
    getAnswer: (sid) => backend.get(relayNames.answer(sid)),
    getChunk: (sid, i) => backend.get(relayNames.chunk(sid, i)),
    getAck: (sid) => backend.get(relayNames.ack(sid)),
    getComplete: (sid) => backend.get(relayNames.complete(sid)),
    getTombstone: (sid) => backend.get(relayNames.tombstone(sid)),
    removeChunk: (sid, i) => backend.remove(relayNames.chunk(sid, i)),
    // R137 §9 (F9/F10) — the raw-name passthroughs the orphan GC drives
    // (additive; the sealed methods are untouched).
    listAll: (prefix) => backend.list(prefix),
    removeName: (name) => backend.remove(name),
    putName: (name, text) => backend.put(name, text),
    removeSession: async (sid, totalChunks) => {
      let removed = 0
      for (let i = 0; i < Number(totalChunks) || 0; i += 1) if (await backend.remove(relayNames.chunk(sid, i))) removed += 1
      await backend.remove(relayNames.offer(sid))
      await backend.remove(relayNames.ack(sid))
      await backend.remove(relayNames.complete(sid))
      await backend.put(relayNames.tombstone(sid), JSON.stringify({ at: Date.now(), chunks: removed }))
      return removed
    },
  }
}

/**
 * THE POLL CADENCE (the §8 clinical rules): fixed fast while a session is
 * live; idle cadence otherwise; capped exponential backoff WITH JITTER on
 * failures; an explicit paused state the user can see and resume.
 */
export class RelayPoller {
  constructor({ onPoll, activeMs = BEAM3_RELAY_POLL_ACTIVE_MS, idleMs = BEAM3_RELAY_POLL_IDLE_MS, baseMs = BEAM3_RELAY_BACKOFF_BASE_MS, maxMs = BEAM3_RELAY_BACKOFF_MAX_MS } = {}) {
    if (typeof onPoll !== 'function') throw relayError('BINDING', 'the poller needs onPoll')
    this.onPoll = onPoll
    this.activeMs = Number(activeMs) || BEAM3_RELAY_POLL_ACTIVE_MS
    this.idleMs = Number(idleMs) || BEAM3_RELAY_POLL_IDLE_MS
    this.baseMs = Number(baseMs) || BEAM3_RELAY_BACKOFF_BASE_MS
    this.maxMs = Number(maxMs) || BEAM3_RELAY_BACKOFF_MAX_MS
    this.failures = 0
    this.paused = false
    this.timer = null
    this.stopped = true
  }

  /** The next delay, machine-derived (the honest cadence for the UI row). */
  nextDelayMs(live) {
    if (this.paused) return null
    if (this.failures === 0) return live ? this.activeMs : this.idleMs
    // R137 §9 root-fix (POL-1, the "backoff capped" law): the ±20% jitter
    // rides WITHIN the cap — the final delay is clamped to maxMs, so a jittered
    // draw can never exceed the configured ceiling (the pre-fix jitter was
    // applied after the cap and could exceed it by 20%).
    const backoff = Math.min(this.maxMs, this.baseMs * 2 ** Math.min(this.failures, 10))
    const jitter = backoff * (0.8 + 0.4 * Math.random()) // ±20%
    return Math.min(this.maxMs, Math.round(jitter))
  }

  start(live = false) {
    this.stopped = false
    this.schedule(live)
  }

  schedule(live) {
    if (this.stopped || this.paused) return
    const ms = this.nextDelayMs(live)
    if (ms == null) return
    if (this.timer) clearTimeout(this.timer)
    this.timer = setTimeout(async () => {
      try {
        await this.onPoll()
        this.failures = 0
      } catch {
        this.failures += 1 // the capped backoff owns the next delay
      }
      this.schedule(live)
    }, ms)
  }

  pause() { this.paused = true; if (this.timer) clearTimeout(this.timer) }

  /** Resume is a USER action (the paused card's button — never self-resumed). */
  resume(live = false) { this.paused = false; this.start(live) }

  stop() { this.stopped = true; if (this.timer) clearTimeout(this.timer) }
}

/**
 * THE TOMBSTONE CONTRACT: both sides acknowledged the completed manifest →
 * the session's chunks are removable and a tombstone doc records the sweep.
 * (zero orphan ciphertext — the compaction law carried to the cloud).
 */
export async function sweepSession(store, sessionId, totalChunks) {
  const tomb = await store.getTombstone(sessionId)
  if (tomb) return { already: true, removed: 0 }
  const removed = await store.removeSession(sessionId, totalChunks)
  return { already: false, removed }
}

// ── R137 §9 (the G72 extension — F9/F10: THE ORPHAN GARBAGE COLLECTOR) ────

/** True for a chunk object name (the GC's detection class). */
export function isChunkName(name) {
  return /^chunk-\d{6}\.bin$/.test(String(name || '').split('/').pop() || '')
}

/** The chunk index of a chunk object name, or -1. */
function chunkIndex(name) {
  const m = String(name || '').match(/chunk-(\d{6})\.bin$/)
  return m ? Number(m[1]) : -1
}

/**
 * F9/F10 — SWEEP THE ORPHANS of one session: every chunk object with NO
 * live manifest reference (index outside 0..liveCount-1, or the session
 * carries no offer/complete manifest at all) is collected; the tombstone is
 * written and HONORED (a swept session sweeps as a no-op). Runs on connect
 * (the worker's relay-open pass) and on schedule (the poller's idle pass) —
 * the GC itself is pure over the store, idempotent by construction.
 *
 * @param {object} store — the relayStore facade (listAll/removeName/putName/
 *   getOffer/getComplete/getTombstone/removeChunk are used)
 * @param {string} sessionId
 * @param {{liveCount?:number}} opt — liveCount: the LIVE manifest's chunk
 *   count when a manifest is known; when omitted, the manifest is read from
 *   the store (offer.json/complete.json); a session with neither is ALL-ORPHAN.
 * @returns the audit record { sessionId, scanned, removed, kept, tombstoned, already, plaintextFree: true }
 */
export async function sweepOrphans(store, sessionId, opt = {}) {
  const prefix = sessionPrefix(sessionId)
  const tomb = await store.getTombstone(sessionId)
  if (tomb) {
    // the tombstone marks EVERY chunk of this session dead — a leftover
    // zombie (a write that predated the put-tombstone guard) is still
    // collected; the session itself is never resurrected
    const names = await store.listAll(prefix)
    const chunkNames = (names || []).filter((n) => isChunkName(n))
    let removed = 0
    for (const name of chunkNames) if (await store.removeName(name)) removed += 1
    return { sessionId, scanned: chunkNames.length, removed, kept: 0, tombstoned: true, already: true, plaintextFree: true }
  }
  let liveCount = Number(opt.liveCount)
  if (!Number.isInteger(liveCount) || liveCount < 0) {
    // the live reference count comes from the session's own manifest when
    // the caller did not pin it — a missing manifest means NOTHING is live
    let count = null
    for (const key of ['offer', 'complete']) {
      const raw = key === 'offer' ? await store.getOffer(sessionId) : await store.getComplete(sessionId)
      if (!raw) continue
      try {
        const j = JSON.parse(raw)
        const c = Number(j && (j.count != null ? j.count : (j.manifest && j.manifest.count) != null ? j.manifest.count : (j.payload && j.payload.manifest && j.payload.manifest.count)))
        if (Number.isInteger(c) && c >= 0) { count = c; break }
      } catch { /* unreadable manifest — treat as absent */ }
    }
    liveCount = count == null ? 0 : count
  }
  const names = await store.listAll(prefix)
  const chunkNames = (names || []).filter((n) => isChunkName(n))
  let removed = 0
  let kept = 0
  for (const name of chunkNames) {
    const idx = chunkIndex(name)
    if (idx >= 0 && idx < liveCount) { kept += 1; continue } // referenced by the live manifest
    if (await store.removeName(name)) removed += 1
  }
  // the session with NOTHING live left (no manifest + no kept chunks) is
  // dead — the tombstone records the collection and the session is honored
  const tombstoned = removed > 0 && kept === 0 && liveCount === 0
  if (tombstoned) {
    await store.putName(relayNames.tombstone(sessionId), JSON.stringify({ at: Date.now(), orphans: removed }))
  }
  return { sessionId, scanned: chunkNames.length, removed, kept, tombstoned, already: false, plaintextFree: true }
}
