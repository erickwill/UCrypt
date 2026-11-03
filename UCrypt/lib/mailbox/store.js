/**
 * UCrypt — R141 §7.1/§7.3 — THE MAILBOX STORE (the one road's storage).
 *
 * The store abstraction re-typed for the clean room (nothing imported from
 * the retired transport): put/get/list/remove over INJECTED fetchers, with
 * the two real bindings the chain's configured endpoint speaks — WebDAV
 * (PUT/GET/MKCOL/DELETE with ETags + conditional writes) and Google Drive
 * (the API v3 the vault sync's own bridge uses). The backend stores opaque
 * ciphertext; it never sees plaintext or names beyond the envelope's.
 *
 * The ONE address algebra (the autopsy's H1 answer): the mailbox lives under
 * the chain's ALREADY-CONFIGURED endpoint — the same config vault sync uses —
 * so two profiles on one machine and two machines on one chain share one road
 * in every account topology. No per-account divergence is representable.
 *
 * PURE (fetch + config injected) — battery-pinned (G91).
 */

import { mailboxLayout, mailboxError } from './protocol.js'

/** The in-memory double (the battery's mailbox cloud). */
export function memoryMailboxStore() {
  const objects = new Map()
  const etags = new Map()
  return {
    kind: 'memory-double',
    async put(name, text, { ifMatch = null, ifNoneMatch = false } = {}) {
      const cur = objects.has(name)
      if (ifNoneMatch && cur) throw mailboxError('CONFLICT', `create-conflict on ${name}`)
      if (ifMatch && etags.get(name) !== ifMatch) throw mailboxError('CONFLICT', `etag mismatch on ${name}`)
      objects.set(String(name), String(text))
      etags.set(String(name), `"${objects.size}-${Date.now()}"`)
      return { ok: true, etag: etags.get(String(name)) }
    },
    async get(name) {
      return objects.has(String(name)) ? { ok: true, text: objects.get(String(name)), etag: etags.get(String(name)) } : { ok: false, status: 404 }
    },
    async list(prefix) {
      return [...objects.keys()].filter((k) => k.startsWith(String(prefix || ''))).sort()
    },
    async remove(name) {
      objects.delete(String(name)); etags.delete(String(name))
      return { ok: true }
    },
  }
}

/** Shape conformance — every binding speaks the same five verbs. */
export function assertStoreConformance(store) {
  for (const m of ['put', 'get', 'list', 'remove']) {
    if (typeof store[m] !== 'function') throw mailboxError('STORE', `the binding lacks ${m}()`)
  }
  return true
}

/** Conditional put with ONE fresh-etag retry (the serialization law: two
 * writers to one index converge, never interleave). */
export async function mergeWrite(store, name, merge, { retries = 2 } = {}) {
  let cur = null
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const got = await store.get(name)
      cur = got && got.ok ? got : null
      const next = merge(cur && cur.ok ? JSON.parse(cur.text) : null)
      const payload = JSON.stringify(next)
      const res = await store.put(name, payload, cur && cur.ok ? { ifMatch: cur.etag } : { ifNoneMatch: true })
      return { ok: true, value: next, etag: res.etag }
    } catch (e) {
      if (e && e.code === 'MAILBOX_CONFLICT' && attempt < retries) continue
      throw e
    }
  }
  throw mailboxError('CONFLICT', `the write to ${name} stayed conflicted after ${retries} retries`)
}

/** WEBDAV binding — re-typed from the field-proven conditional-write law:
 * a create is PUT If-None-Match:*, an update is PUT If-Match:<etag>, a 412
 * retries ONCE with a freshly-read ETag. The binding injects davFetch(url,
 * init) → {ok, status, headers, text?} and baseUrl (the chain endpoint root). */
export function webdavMailboxBinding({ davFetch, baseUrl }) {
  if (typeof davFetch !== 'function' || !baseUrl) throw mailboxError('BINDING', 'the webdav binding needs davFetch + baseUrl')
  const root = `${String(baseUrl).replace(/\/?$/, '/')}`
  const urlOf = (name) => root + String(name).split('/').map(encodeURIComponent).join('/')
  return {
    kind: 'webdav',
    async put(name, text, opts = {}) {
      const headers = { 'Content-Type': 'application/json' }
      if (opts.ifMatch) headers['If-Match'] = opts.ifMatch
      if (opts.ifNoneMatch) headers['If-None-Match'] = '*'
      const res = await davFetch(urlOf(name), { method: 'PUT', headers, body: String(text) })
      if (res.status === 412) throw mailboxError('CONFLICT', `etag conflict on ${name}`)
      if (res.status === 404 || res.status === 409) throw mailboxError('FOLDER_MISSING', `the mailbox folder is missing (${res.status})`)
      if (!(res.ok || res.status === 201 || res.status === 204)) throw mailboxError('PUT', `webdav put ${res.status}`)
      return { ok: true, etag: (res.headers && res.headers.get && res.headers.get('etag')) || '' }
    },
    async get(name) {
      const res = await davFetch(urlOf(name), { method: 'GET' })
      if (res.status === 404) return { ok: false, status: 404 }
      if (!res.ok) throw mailboxError('GET', `webdav get ${res.status}`)
      const text = typeof res.text === 'string' ? res.text : await res.text()
      return { ok: true, text, etag: (res.headers && res.headers.get && res.headers.get('etag')) || '' }
    },
    async list(prefix) {
      // PROPFIND one level under the prefix's directory; the harness and the
      // real server answer 207 multistatus. Names are decoded hrefs.
      const dir = prefix.includes('/') ? prefix.slice(0, prefix.lastIndexOf('/') + 1) : ''
      const res = await davFetch(urlOf(dir), { method: 'PROPFIND', headers: { Depth: '1' } })
      if (res.status === 404) return []
      if (!res.ok && res.status !== 207) throw mailboxError('LIST', `webdav propfind ${res.status}`)
      const text = typeof res.text === 'string' ? res.text : await res.text()
      const names = []
      const re = /<D?:?href[^>]*>([^<]+)<\/D?:?href>/gi
      let m
      while ((m = re.exec(text))) {
        const href = decodeURIComponent(m[1])
        const rel = href.startsWith('/') ? href.slice(1) : href
        const full = (dir + rel).replace(/\/+$/, '')
        if (full.startsWith(String(prefix)) && full !== String(prefix).replace(/\/+$/, '')) names.push(full)
      }
      return names.sort()
    },
    async remove(name) {
      const res = await davFetch(urlOf(name), { method: 'DELETE' })
      if (!(res.ok || res.status === 204 || res.status === 404)) throw mailboxError('REMOVE', `webdav delete ${res.status}`)
      return { ok: true }
    },
  }
}

/** DRIVE binding — the same five verbs over the API v3 the vault sync's own
 * bridge speaks; the binding injects driveFetch(path, init). Folder ids are
 * resolved lazily and cached per name-prefix (create-or-find). */
export function driveMailboxBinding({ driveFetch, useAppData = false }) {
  if (typeof driveFetch !== 'function') throw mailboxError('BINDING', 'the drive binding needs driveFetch')
  const folderCache = {}
  const rootParent = useAppData ? 'appDataFolder' : 'root'
  const spacesParam = useAppData ? '&spaces=appDataFolder' : ''
  async function ensureFolders(name) {
    const parts = String(name).split('/')
    let parentId = rootParent
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts.slice(0, i + 1).join('/')
      if (folderCache[seg]) { parentId = folderCache[seg]; continue }
      const parentClause = parentId && parentId !== 'root' ? ` and '${parentId}' in parents` : ''
      const q = encodeURIComponent(`name='${parts[i]}' and mimeType='application/vnd.google-apps.folder'${parentClause} and trashed=false`)
      const list = await driveFetch(`/drive/v3/files?q=${q}${spacesParam}&fields=files(id,name)`)
      let id = list && list.files && list.files[0] && list.files[0].id
      if (!id) {
        const folderMeta = parentId && parentId !== 'root'
          ? { name: parts[i], mimeType: 'application/vnd.google-apps.folder', parents: [parentId] }
          : { name: parts[i], mimeType: 'application/vnd.google-apps.folder' }
        const created = await driveFetch('/drive/v3/files', { method: 'POST', body: JSON.stringify(folderMeta) })
        id = created && created.id
      }
      folderCache[seg] = id
      parentId = id
    }
    return folderCache
  }
  return {
    kind: 'drive',
    async put(name, text, opts = {}) {
      const ids = await ensureFolders(name)
      const fileName = String(name).split('/').pop()
      const parentFolder = ids[String(name).split('/').slice(0, -1).join('/')] || rootParent
      const parentClause = parentFolder && parentFolder !== 'root' ? ` and '${parentFolder}' in parents` : ''
      const q = encodeURIComponent(`name='${fileName}'${parentClause} and trashed=false`)
      const found = await driveFetch(`/drive/v3/files?q=${q}${spacesParam}&fields=files(id,name)`)
      const existing = found && found.files && found.files[0]
      if (existing) {
        const res = await driveFetch(`/upload/drive/v3/files/${existing.id}?uploadType=media`, { method: 'PATCH', body: String(text) })
        if (!res || !res.id) throw mailboxError('PUT', 'drive patch failed')
        return { ok: true, etag: String(res.id) }
      }
      const boundary = 'ucrypt-mailbox-v1'
      const meta = JSON.stringify({ name: fileName, parents: [parentFolder] })
      const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n${String(text)}\r\n--${boundary}--`
      const res = await driveFetch('/upload/drive/v3/files?uploadType=multipart', {
        method: 'POST',
        contentType: `multipart/related; boundary=${boundary}`,
        body,
      })
      if (!res || !res.id) throw mailboxError('PUT', 'drive create failed')
      return { ok: true, etag: String(res.id) }
    },
    async get(name) {
      const ids = await ensureFolders(name)
      const fileName = String(name).split('/').pop()
      const parentFolder = ids[String(name).split('/').slice(0, -1).join('/')] || rootParent
      const parentClause = parentFolder && parentFolder !== 'root' ? ` and '${parentFolder}' in parents` : ''
      const q = encodeURIComponent(`name='${fileName}'${parentClause} and trashed=false`)
      const found = await driveFetch(`/drive/v3/files?q=${q}${spacesParam}&fields=files(id,name)`)
      const f = found && found.files && found.files[0]
      if (!f) return { ok: false, status: 404 }
      const res = await driveFetch(`/drive/v3/files/${f.id}?alt=media`)
      return { ok: true, text: typeof res === 'string' ? res : JSON.stringify(res), etag: String(f.id) }
    },
    async list(prefix) {
      const dirName = String(prefix).split('/').slice(0, -1).join('/')
      const ids = await ensureFolders(dirName + '/x.json')
      const folderId = ids[dirName]
      if (!folderId) return []
      const res = await driveFetch(`/drive/v3/files?q=${encodeURIComponent(`'${folderId}' in parents and trashed=false`)}${spacesParam}&fields=files(id,name)`)
      return ((res && res.files) || []).map((f) => `${dirName}/${f.name}`).sort()
    },
    async remove(name) {
      const ids = await ensureFolders(name)
      const fileName = String(name).split('/').pop()
      const parentFolder = ids[String(name).split('/').slice(0, -1).join('/')] || rootParent
      const parentClause = parentFolder && parentFolder !== 'root' ? ` and '${parentFolder}' in parents` : ''
      const q = encodeURIComponent(`name='${fileName}'${parentClause} and trashed=false`)
      const found = await driveFetch(`/drive/v3/files?q=${q}${spacesParam}&fields=files(id,name)`)
      const f = found && found.files && found.files[0]
      if (f) await driveFetch(`/drive/v3/files/${f.id}`, { method: 'DELETE' })
      return { ok: true }
    },
  }
}

/* ── The mailbox operations (the sender/receiver verbs over any binding) ── */

/** The SENDER's write: offer.json + chunks into the RECIPIENT's inbox, the
 * index merge-write, then the receipt seed under the SENDER's receipts. */
export async function deliverOffer(store, { envelope, chunks, senderMemberId }) {
  assertStoreConformance(store)
  const to = envelope.toMemberId
  await store.put(mailboxLayout.inboxOffer(to, envelope.offerId), JSON.stringify(envelope))
  for (let i = 0; i < envelope.chunkCount; i++) {
    if (chunks[i] === undefined) throw mailboxError('CHUNK_MISSING', `chunk ${i} was not supplied`)
    await store.put(mailboxLayout.inboxChunk(to, envelope.offerId, i), chunks[i])
  }
  const idxName = mailboxLayout.inboxIndex(to)
  const merged = await mergeWrite(store, idxName, (cur) => {
    const base = cur && Array.isArray(cur.offers) ? cur : { v: 1, memberId: to, offers: [], lastPrunedAt: 0, prunedCount: 0 }
    if (base.offers.some((o) => o.offerId === envelope.offerId)) return base
    base.offers.push({ offerId: envelope.offerId, fileName: envelope.fileName, size: envelope.size, fromMemberId: envelope.fromMemberId, fromName: envelope.fromName, createdAt: envelope.createdAt, expiresAt: envelope.expiresAt, verifyCode: envelope.verifyCode })
    return base
  })
  await store.put(mailboxLayout.receipt(senderMemberId, envelope.offerId), JSON.stringify({ v: 1, offerId: envelope.offerId, state: 'written', at: Date.now() }))
  return { ok: true, indexCount: merged.value.offers.length, etag: merged.etag }
}

/** The RECEIVER's poll: read the index, prune expired, return the waiting
 * offers (the manifest rows — the envelopes themselves stay on the backend). */
export async function readInbox(store, { memberId, now = Date.now() }) {
  assertStoreConformance(store)
  const idxName = mailboxLayout.inboxIndex(memberId)
  const got = await store.get(idxName)
  if (!got || !got.ok) return { ok: true, offers: [], pruned: 0 }
  let idx
  try { idx = JSON.parse(got.text) } catch { return { ok: true, offers: [], pruned: 0 } }
  if (!idx || !Array.isArray(idx.offers)) return { ok: true, offers: [], pruned: 0 }
  const live = idx.offers.filter((o) => Number(o.expiresAt) > now)
  const pruned = idx.offers.length - live.length
  if (pruned > 0) {
    await store.put(idxName, JSON.stringify({ ...idx, offers: live, lastPrunedAt: now, prunedCount: (Number(idx.prunedCount) || 0) + pruned }))
  }
  return { ok: true, offers: live, pruned }
}

/** Fetch one offer's envelope + chunks; the fingerprint auto-checks at the end. */
export async function fetchOffer(store, { memberId, offerId, expectSha256, digestFn }) {
  const gotEnv = await store.get(mailboxLayout.inboxOffer(memberId, offerId))
  if (!gotEnv || !gotEnv.ok) throw mailboxError('OFFER_MISSING', 'the offer is no longer in the mailbox')
  const envelope = JSON.parse(gotEnv.text)
  const chunks = []
  for (let i = 0; i < Number(envelope.chunkCount); i++) {
    const c = await store.get(mailboxLayout.inboxChunk(memberId, offerId, i))
    if (!c || !c.ok) throw mailboxError('CHUNK_MISSING', `chunk ${i} could not be fetched`)
    chunks.push(c.text)
  }
  const actual = await digestFn(chunks)
  if (String(actual).toLowerCase() !== String(expectSha256 || envelope.sha256).toLowerCase()) {
    throw mailboxError('DAMAGED', 'the offer is damaged (fingerprint mismatch)')
  }
  return { envelope, chunks }
}

/** The RECEIVER's receipt write (the sender reads it to update the card). */
export async function writeReceipt(store, { senderMemberId, receipt }) {
  await store.put(mailboxLayout.receipt(senderMemberId, receipt.offerId), JSON.stringify(receipt))
  return { ok: true }
}

/** The SENDER's receipt read — the honest card's source of truth. */
export async function readReceipt(store, { senderMemberId, offerId }) {
  const got = await store.get(mailboxLayout.receipt(senderMemberId, offerId))
  if (!got || !got.ok) return null
  try { return JSON.parse(got.text) } catch { return null }
}

/* ── R142 §5.2-b2(a) — the BRIDGE SIGNALS (the relay signaling layer) ────── */

/**
 * Deliver one BRIDGE signal envelope to a peer's session: the envelope object
 * lands under the session, and ONE index row per session carries the manifest
 * (swept on close or expiry — the sweep laws live in sweepSessionSignals).
 */
export async function deliverSignal(store, { toMemberId, envelope }) {
  assertStoreConformance(store)
  if (!envelope || envelope.type !== 'BRIDGE' || !envelope.sessionId) {
    throw mailboxError('SIGNAL_SHAPE', 'the signal envelope is not a BRIDGE envelope')
  }
  const sessionId = envelope.sessionId
  const signalId = `${envelope.kind}-${envelope.issuedAt}`.replace(/[^a-z0-9-]/gi, '')
  await store.put(mailboxLayout.signalObject(toMemberId, sessionId, signalId), JSON.stringify(envelope))
  const merged = await mergeWrite(store, mailboxLayout.signalIndex(toMemberId, sessionId), (cur) => {
    const base = cur && Array.isArray(cur.signals) ? cur : { v: 1, sessionId, signals: [], createdAt: envelope.issuedAt }
    if (base.signals.some((s) => s.signalId === signalId)) return base
    base.signals.push({ signalId, kind: envelope.kind, issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt })
    return base
  })
  return { ok: true, signalId, indexCount: merged.value.signals.length }
}

/**
 * Read a member's signals — ALL sessions (or one), expired rows pruned for
 * real (the sweep law), consumed signals never returned.
 */
export async function readSignals(store, { memberId, now = Date.now() }) {
  assertStoreConformance(store)
  const sessions = (await store.list(`ucrypt-mailbox-v1/signals/${memberId}/`)).filter((n) => n.endsWith('/index.json'))
  const out = []
  for (const idxName of sessions) {
    const got = await store.get(idxName)
    if (!got || !got.ok) continue
    let idx
    try { idx = JSON.parse(got.text) } catch { continue }
    if (!idx || !Array.isArray(idx.signals)) continue
    const sessionId = idx.sessionId || idxName.split('/')[3]
    const live = idx.signals.filter((s) => Number(s.expiresAt) > now)
    if (live.length !== idx.signals.length) {
      await store.put(idxName, JSON.stringify({ ...idx, signals: live, lastSweptAt: now }))
      for (const dead of idx.signals.filter((s) => Number(s.expiresAt) <= now)) {
        try { await store.remove(mailboxLayout.signalObject(memberId, sessionId, dead.signalId)) } catch { /* best-effort */ }
      }
    }
    for (const row of live) {
      const obj = await store.get(mailboxLayout.signalObject(memberId, sessionId, row.signalId))
      if (!obj || !obj.ok) continue
      try { out.push({ sessionId, signalId: row.signalId, envelope: JSON.parse(obj.text) }) } catch { continue }
    }
  }
  return { ok: true, signals: out }
}

/** Consume one signal (single-use) — and sweep the session when it drains. */
export async function consumeSignal(store, { memberId, sessionId, signalId }) {
  assertStoreConformance(store)
  const objName = mailboxLayout.signalObject(memberId, sessionId, signalId)
  const got = await store.get(objName)
  if (!got || !got.ok) throw mailboxError('SIGNAL_MISSING', 'the signal is gone')
  const env = JSON.parse(got.text)
  await store.put(objName, JSON.stringify({ ...env, consumedAt: Date.now() }))
  return { ok: true, envelope: env }
}

/** THE SWEEP LAW (§5.2-b2(a)): one index row per session, swept on close or
 * expiry — close calls this directly; expiry prunes in readSignals. */
export async function sweepSessionSignals(store, { memberId, sessionId }) {
  assertStoreConformance(store)
  const prefix = `ucrypt-mailbox-v1/signals/${memberId}/${sessionId}/`
  const names = await store.list(prefix)
  for (const n of names) { try { await store.remove(n) } catch { /* best-effort */ } }
  return { ok: true, swept: names.length }
}

/* ── R142 §5.2-b6 — presence rides the mailbox (the ≥ 15-minute TTL law) ─── */

/** Stamp THIS device's presence (idempotent; the cadence owns the stamp). */
export async function stampPresence(store, { memberId, now = Date.now(), extra = {} }) {
  await store.put(mailboxLayout.presence(memberId), JSON.stringify({ v: 1, memberId, lastSeen: now, ...extra }))
  return { ok: true }
}

/** Read the chain's presence stamps (best-effort — a dead road returns {} and
 * the roster stays FULL with honest unknown states, never blank). */
export async function readPresence(store, { memberIds = [], now = Date.now() }) {
  assertStoreConformance(store)
  const out = {}
  for (const id of memberIds) {
    const got = await store.get(mailboxLayout.presence(id))
    if (got && got.ok) {
      try { out[id] = JSON.parse(got.text) } catch { /* a malformed stamp is unknown */ }
    }
  }
  return out
}
