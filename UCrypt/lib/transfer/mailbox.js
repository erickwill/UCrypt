/**
 * UCrypt — R76 Part E "Secure Direct Device Transfer" — RENDEZVOUS MAILBOX
 * (WebDAV adapter + record envelopes + presence). New in v2.42.14.
 *
 * RENDEZVOUS PLANE. Temporary, encrypted presence/offer/answer records live in
 * a SEPARATE namespace directory on the user's EXISTING WebDAV storage — it
 * reuses the sync transport's configured account but NEVER touches the vault
 * envelope or its location semantics:
 *
 *   <directory of the configured WebDAV vault URL>/ucrypt-rendezvous-v1/
 *     ├─ <locator>.json          per-device mailbox (array of record envelopes)
 *     ├─ presence/index.json     array of deviceIds currently advertising
 *     └─ presence/<deviceId>.json one presence record per device
 *
 * NO UCrypt-operated server exists. No plaintext device labels, file names,
 * IP/ICE candidates, cloud URLs, tokens, recovery words or file metadata EVER
 * appear in a mailbox object: every sensitive value lives ONLY inside the
 * `payload` ciphertext (AES-256-GCM under the pairwise signal key; presence
 * payloads under the rendezvous-group key). `assertNoPlaintextLeaks()`
 * self-audits every envelope before it is PUT — a hard gate, enforced.
 *
 * HTTP layer: lib/transports/http.js is importable here without cycles, so
 * fetchWithRetry / SyncError / classifySyncError are REUSED (not replicated).
 * The ETag discipline mirrors lib/transports/webdav.js (If-Match on the last
 * seen STRONG etag; weak etags never stored nor replayed; bounded 412 retries
 * on the read-merge-write loop).
 */

import { encryptString, decryptString, isSealedEnvelope, base64ToBytes } from '../crypto.js'
import { fetchWithRetry, SyncError, classifySyncError, SYNC_ERROR_KINDS } from '../transports/http.js'
import { getTransportRecord } from '../vault.js'
import { pruneReplay } from './session.js'
import {
  evaluatePresenceRecord,
  applyPresenceHighWater,
  PRESENCE_STATES,
  PRESENCE_FRESH_THRESHOLD_MS,
} from './lifecycle.js'
import {
  mailboxLocator,
  canonicalRecordBytes,
  signRecord,
  verifyRecord,
  derivePairwiseSignalKey,
  sha256HexOfBytes,
  randomHex32,

  PEERS_STORAGE_KEY,
} from './core.js'

// --- Constants ------------------------------------------------------------------

/** Mirrors vault.js TRANSPORT_KEY — re-read from storage, private state never
 * imported. The value lives in the vault module; the KEY NAME is the contract. */
const TRANSPORT_KEY = 'ucrypt:transport'
/** Rendezvous namespace directory, created once per session (MKCOL). */
export const RENDEZVOUS_NS = 'ucrypt-rendezvous-v1'
/** Record kinds (owner order E4 — exact set). R85 (F-R84-XFER-3): 'decline'
 * is a first-class wire kind — the receiver's refusal reaches the sender as
 * its own T5 terminal record instead of masquerading as a cancel.
 * R98 (S8.4): 'join' is the Beam's first-contact record — a chain member's
 * request to join, sealed under the pairwise signal key with the joiner's
 * public keys riding the SIGNED envelope and a chain-proof inside the
 * payload (lib/beam.js is the only producer/consumer). */
export const RECORD_KINDS = ['offer', 'answer', 'ice', 'cancel', 'complete', 'decline', 'presence', 'join',
  // S8.9 (R99): the continuous direct-sync signaling kinds — additions-only
  // (law 0.4). They ride the SAME pairwise-sealed envelope, the SAME typed
  // gates and the SAME replay ledger as every other record kind.
  'sync-offer', 'sync-answer',
  // R134 (Beam 2): the ONE new kind the Beam 2 signaling rides — the typed
  // {v:2,...} control envelope (HELLO/CAPS/OFFER/ACCEPT/DECLINE/CANCEL/ACK/
  // PROGRESS/COMPLETE/BYE) lives INSIDE the sealed payload, so the mailbox
  // still sees only ciphertext. Additions-only (law 0.4); the legacy kinds
  // above are untouched (the legacy bridge keeps transferring).
  'beam2',
  // R135 (§4): the vault-sync lane — the per-type Chain Data Types bodies
  // (lib/chaindata.js is the only producer/consumer; the manifest rides
  // INSIDE the sealed payload). Additions-only, law 0.4. The lineage:
  // 8 (R98) → 10 (R99) → 11 (R134, beam2) → 12 (R135, sync).
  'sync']
/** Mailbox file cap: at most this many unexpired records per mailbox file. */
const MAILBOX_MAX_RECORDS = 50
/** R86 (T4 reconciliation): the sealed TOFU peer map holds at most 10 devices
 * — the same cap the owner spec gives the device roster. Learning an 11th
 * device evicts the STALEST lastSeen entry (never the freshest one just
 * learned); a removal via removePeer always frees the slot explicitly. */
export const PEER_MAP_CAP = 10
/** Presence index retry budget for the read-merge-write loop. */
const INDEX_RETRIES = 3
/** Default record time-to-live (offers/answers/ice/cancel/complete). */
export const RECORD_TTL_MS = 10 * 60 * 1000
/**
 * R81-F1: presence envelope TTL is BOUNDED (2 minutes) and refreshed every
 * 60 s while the window is open — a device that dies without withdrawal stops
 * advertising within ≤2 refresh intervals instead of the full window. The
 * payload's availableUntil keeps the USER-CHOSEN window end.
 */
export const PRESENCE_ENVELOPE_TTL_MS = 2 * 60 * 1000
/** R81-F1: tombstone (withdrawn) envelope TTL after an explicit withdrawal. */
export const PRESENCE_WITHDRAWN_TTL_MS = 5 * 60 * 1000
/** R81-F1: device-local monotonic presence sequence counter. */
const PRESENCE_SEQ_KEY = 'ucrypt:transfer:presence:seq'
/** R81-F1: device-local withdrawn high-water map { deviceId: newestWithdrawnSeq }. */
const PRESENCE_WITHDRAWN_KEY = 'ucrypt:transfer:presence:withdrawn'

const HEX64_RE = /^[0-9a-f]{64}$/
const HEX32_RE = /^[0-9a-f]{32}$/
const IPV4_RE_GLOBAL = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
const B64_RE = /^[A-Za-z0-9+/=]+$/

/** Typed failure with a stable code the worker maps to localized copy. */
export function transferError(code, message) {
  const e = new Error(message)
  e.code = code
  e.transferCode = code
  return e
}

// --- Leaks self-audit (hard gate; see the module header) --------------------------

/**
 * Walk the about-to-be-published envelope and refuse to write it when ANY
 * sensitive value from the plaintext payload appears in plaintext. Checked:
 * the peer device label, the file name, every IPv4-shaped substring found in
 * the payload (SDP/ICE candidates), and any http(s) URL carried by the payload
 * (cloud URLs and tokens never belong here — the adapter puts transport
 * credentials into Authorization headers only, never into records). Throws
 * 'plaintext_leak' on violation. Called before EVERY PUT.
 *
 * @param {object} rec the sealed record envelope about to be published
 * @param {object} payloadObj the DECRYPTED payload the envelope was built from
 */
export function assertNoPlaintextLeaks(rec, payloadObj) {
  const env = JSON.stringify(rec || {})
  const suspects = []
  const scanString = (v) => {
    if (typeof v !== 'string' || v.length < 5) return
    suspects.push(v)
  }
  scanString(payloadObj && (payloadObj.label || (payloadObj.file && payloadObj.file.name)))
  scanString(payloadObj && payloadObj.name)
  let payloadStr = ''
  try { payloadStr = JSON.stringify(payloadObj || {}) } catch { /* non-serializable — nothing to scan */ }
  if (payloadStr) {
    for (const m of payloadStr.match(IPV4_RE_GLOBAL) || []) suspects.push(m)
    for (const m of payloadStr.match(/https?:\/\/[^"\s]+/g) || []) suspects.push(m)
  }
  for (const s of suspects) {
    if (s && env.includes(s)) {
      throw transferError('plaintext_leak',
        'Refusing to publish: a sensitive payload value (label, file name, IP/ICE or URL) leaked into the envelope in plaintext')
    }
  }
}

/** Chain-tag gate: records from a foreign sync chain are refused up front. */
function chainTagGate(rec, expectedTag) {
  if (!rec || rec.chainTag !== expectedTag) {
    throw transferError('foreign_chain', 'Record carries a foreign chain tag — refusing before any decryption')
  }
}

// --- WebDAV base (reuses the user's EXISTING transport config) ---------------------

function strongEtag(raw) {
  const t = String(raw || '').trim()
  return t && !/^W\//i.test(t) ? t : null
}

function authHeaders(cfg) {
  const headers = {}
  if (cfg && cfg.user && cfg.pass) {
    const bytes = new TextEncoder().encode(`${cfg.user}:${cfg.pass}`)
    headers.Authorization = 'Basic ' + btoa(String.fromCharCode.apply(null, bytes))
  }
  return headers
}

/**
 * Resolve the user's EXISTING WebDAV transport config the same way vault.js
 * does: re-read chrome.storage.local key 'ucrypt:transport' (mirrored pattern —
 * no private state imported). Secret fields may be sealed credential
 * envelopes (R45-A); those are opened through the vault module's PUBLIC
 * getTransportRecord() — the same call the sync plane itself uses — which is
 * reachable only while the vault is unlocked (transfer requires that anyway).
 * Returns {url, user, pass} or null when WebDAV is not the configured transport.
 */
async function webdavConfig() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t || t.id !== 'webdav' || !t.config || !t.config.url) return null
  try {
    const rec = await getTransportRecord()
    if (rec && rec.id === 'webdav' && rec.config && rec.config.url) {
      return { url: rec.config.url, user: rec.config.user || '', pass: rec.config.pass || '' }
    }
  } catch (e) {
    // Vault locked (or credential envelopes unreadable): fall through and use
    // only the unsealed fields — an auth-free server still works; an
    // authenticated one will fail with a truthful 401 downstream.
    console.warn('[UCrypt] Rendezvous: transport secrets unavailable while locked:', e?.message || e)
    return {
      url: t.config.url,
      user: isSealedEnvelope(t.config.user) ? '' : (t.config.user || ''),
      pass: isSealedEnvelope(t.config.pass) ? '' : (t.config.pass || ''),
    }
  }
  return null
}

/**
 * The rendezvous namespace root: the DIRECTORY of the configured WebDAV vault
 * URL (the vault URL points at a FILE; its parent directory is used) plus
 * `/ucrypt-rendezvous-v1/`. The vault envelope itself is never read, written
 * or relocated by this module.
 */
export function rendezvousBaseFromVaultUrl(vaultUrl) {
  let u
  try {
    u = new URL(vaultUrl)
  } catch {
    return null
  }
  let path = u.pathname || '/'
  if (!path.endsWith('/')) {
    const slash = path.lastIndexOf('/')
    path = slash >= 0 ? path.slice(0, slash + 1) : '/'
  }
  return u.origin + path.replace(/\/+$/, '') + '/' + RENDEZVOUS_NS + '/'
}

// F-R114-MAILBOX-1 (R114 §1): the "once per session" memo is now BOUND to the
// session it belongs to — the resolved namespace BASE — and ends when the
// session ends. Two real defects close:
//   (a) base-blindness: switching the WebDAV transport (a different account
//       URL) within one MV3 worker lifetime never MKCOL'd the NEW namespace —
//       every rendezvous PUT 404'd until a worker recycle;
//   (b) the disable boundary: DISABLE ends the availability session (fresh
//       keys on the next enable are the R81 law) but the memo survived, so a
//       re-enable in the same lifetime skipped its own MKCOL proof — the
//       exact path the R85 tolerance fix exists for, now re-proven on every
//       session start (405 = exists is tolerated, never thrown).
let _mkcolBaseDoneFor = null
let _mkcolPresenceDoneFor = null

/** The session boundary: the transfer plane calls this when a session ENDS
 * (availability disable, lock) so the next session re-proves its namespace
 * from scratch. Cheap: a MKCOL on an existing namespace is a 405-tolerated
 * no-op on the wire. */
export function resetRendezvousSession() {
  _mkcolBaseDoneFor = null
  _mkcolPresenceDoneFor = null
}

/**
 * R85 (F-R84-XFER-1): the OK statuses of a rendezvous MKCOL. 201 = created,
 * 204 = OK (some servers), 405 = the collection ALREADY EXISTS — which is the
 * normal state after the first-ever session and after every MV3 worker wake.
 * Passed through fetchWithRetry's caller-declared okStatuses so the response
 * comes back response-shaped and the tolerance branches below execute as
 * designed (they were dead code behind the terminal 4xx throw — the defect).
 */
const MKCOL_OK_STATUSES = [201, 204, 405]

async function davFetch(url, opts, context, retries = 1, okStatuses = null) {
  const cfg = await webdavConfig()
  if (!cfg) {
    throw transferError('rendezvous_unavailable',
      'Direct transfer rendezvous needs the WebDAV transport configured (same storage as vault sync)')
  }
  try {
    return await fetchWithRetry(url, { redirect: 'manual', ...opts, headers: { ...authHeaders(cfg), ...(opts.headers || {}) } },
      { context, retries, op: opts.method === 'PUT' ? 'upload' : 'download', okStatuses: okStatuses || undefined })
  } catch (e) {
    // R79 (F-R78-4, P1): a 412 (If-Match precondition failed) is NOT a terminal
    // transport failure on the rendezvous conditional-write path — it is the
    // CAS conflict signal the etagMergeWrite loop MUST observe to perform its
    // bounded read-merge-write retry. fetchWithRetry classifies 4xx as terminal
    // and throws, which made the retry branch dead code (R78 finding). Surface
    // 412 as a response-shaped result INSTEAD of throwing — scoped strictly to
    // this rendezvous adapter; the vault sync plane's webdav.js is untouched.
    // R85 (F-R84-XFER-1): 405 on the MKCOL path is response-shaped the same
    // way (belt-and-braces — the okStatuses set above is the primary fix), so
    // a MKCOL on an existing collection can never again surface as a generic
    // 'Rendezvous MKCOL failed: 405 — exists' transport error.
    if (e instanceof SyncError && e.status === 412) {
      return { ok: false, status: 412, headers: { get: () => null } }
    }
    if (e instanceof SyncError && e.status === 405 && okStatuses && okStatuses.includes(405)) {
      return { ok: false, status: 405, headers: { get: () => null } }
    }
    if (e instanceof SyncError) throw e
    throw classifySyncError(e, { context })
  }
}

/** MKCOL the namespace once per SESSION (per resolved base; ends on disable/
 * lock — F-R114-MAILBOX-1); 405 (exists) counts as success. */
async function ensureNamespace() {
  const cfg = await webdavConfig()
  if (!cfg) {
    throw transferError('rendezvous_unavailable',
      'Direct transfer rendezvous needs the WebDAV transport configured (same storage as vault sync)')
  }
  const base = rendezvousBaseFromVaultUrl(cfg.url)
  if (!base) throw transferError('rendezvous_unavailable', 'WebDAV URL is not a usable rendezvous root')
  if (_mkcolBaseDoneFor !== base) {
    // R85 (F-R84-XFER-1): the MKCOL statuses are passed as caller-declared OK
    // statuses — a 405 (namespace exists) is returned response-shaped instead
    // of thrown, and this tolerance branch finally executes as designed.
    const res = await davFetch(base, { method: 'MKCOL' }, 'Rendezvous MKCOL', 0, MKCOL_OK_STATUSES)
    if (!(res.ok || res.status === 405 || res.status === 201 || res.status === 204)) {
      throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Rendezvous MKCOL failed: ${res.status}`, { status: res.status })
    }
    _mkcolBaseDoneFor = base
  }
  return base
}

async function ensurePresenceDir(base) {
  if (_mkcolPresenceDoneFor === base) return
  // R85 (F-R84-XFER-1): same caller-declared OK statuses as the base namespace.
  const res = await davFetch(base + 'presence/', { method: 'MKCOL' }, 'Rendezvous MKCOL presence', 0, MKCOL_OK_STATUSES)
  if (!(res.ok || res.status === 405 || res.status === 201 || res.status === 204)) {
    throw new SyncError(SYNC_ERROR_KINDS.SERVER, `Rendezvous MKCOL presence failed: ${res.status}`, { status: res.status })
  }
  _mkcolPresenceDoneFor = base
}

// --- Low-level JSON GET/PUT with the webdav.js ETag discipline ---------------------

async function davGetJson(url, context) {
  let res
  try {
    res = await davFetch(url, { method: 'GET' }, context)
  } catch (e) {
    if (e instanceof SyncError && (e.status === 404 || e.status === 410)) return null
    throw e
  }
  if (res.status === 404 || res.status === 410) return null
  const text = await res.text()
  if (!text || !text.trim()) return null
  try {
    return { json: JSON.parse(text), etag: strongEtag(res.headers && res.headers.get('etag')) }
  } catch {
    throw transferError('rendezvous_protocol', 'Rendezvous returned a non-JSON object')
  }
}

async function davPutJson(url, obj, etag, context) {
  const headers = { 'Content-Type': 'application/json' }
  if (etag) headers['If-Match'] = etag // weak etags are never replayed (strongEtag filter upstream)
  const res = await davFetch(url, { method: 'PUT', headers, body: JSON.stringify(obj) }, context)
  return { status: res.status, ok: res.ok || res.status === 201 || res.status === 204, etag: strongEtag(res.headers && res.headers.get('etag')) }
}

async function davDelete(url, context) {
  try {
    const res = await davFetch(url, { method: 'DELETE' }, context, 0)
    return res.ok || res.status === 404 || res.status === 405 || res.status === 204
  } catch (e) {
    return e instanceof SyncError && (e.status === 404 || e.status === 405)
  }
}

/**
 * Generic read-merge-write with If-Match + bounded 412 retries (webdav.js
 * discipline). R79 (F-R78-4): with 412 now surfaced by davFetch as a result
 * (not a throw), the retry loop is LIVE: on 412 the current mailbox is
 * re-read, the merge re-applied against the fresh ETag, and the PUT retried —
 * at most INDEX_RETRIES attempts, never overwriting another device's records
 * (the merge always works on the just-read remote state).
 */
async function etagMergeWrite(url, merge, context) {
  for (let attempt = 0; attempt < INDEX_RETRIES; attempt++) {
    const cur = await davGetJson(url, context)
    const next = merge(cur ? cur.json : null)
    const { status, ok, etag } = await davPutJson(url, next, cur ? cur.etag : null, context)
    if (ok) return { json: next, etag }
    if (status === 412 && attempt < INDEX_RETRIES - 1) continue // remote changed — re-read and re-merge
    if (status === 412) {
      // Bounded retries exhausted — a TYPED, honest busy signal: the UI must
      // show "signaling busy; retry", never attempt an unsafe transfer.
      throw transferError('rendezvous_busy', `${context}: the mailbox changed on every attempt (${status}) — retry the request`)
    }
    throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `${context}: write rejected (${status})`, { status })
  }
  throw new SyncError(SYNC_ERROR_KINDS.PROTOCOL, `${context}: write rejected after retries`, {})
}

// --- Replay protection (bounded, device-local) --------------------------------------

const REPLAY_KEY = 'ucrypt:transfer:replay'
const REPLAY_CAP = 400

async function readReplay() {
  const { [REPLAY_KEY]: list } = await chrome.storage.local.get(REPLAY_KEY)
  return Array.isArray(list) ? list : []
}

/**
 * True when this messageId was already accepted (replay). Called on EVERY
 * record accept path BEFORE any decryption work is trusted.
 */
export async function seenBefore(messageId) {
  const list = await readReplay()
  return list.some(e => e && e.m === messageId)
}

/** Record a messageId as accepted; bounded array, oldest entries dropped. */
export async function markSeen(messageId) {
  const list = pruneReplay(await readReplay())
  list.push({ m: messageId, t: Date.now() })
  while (list.length > REPLAY_CAP) list.shift()
  await chrome.storage.local.set({ [REPLAY_KEY]: list })
}

// --- Peer store (TOFU within the chain, sealed under the device-registry key) -------

/** R98 (S8.4): exported for lib/beam.js — the join refusal needs the learned
 * joiner's keys to seal the typed decline (additions-only export). */
export async function loadPeerMap(chainKeys) {
  const { [PEERS_STORAGE_KEY]: sealed } = await chrome.storage.local.get(PEERS_STORAGE_KEY)
  if (!sealed) return {}
  try {
    return JSON.parse(await decryptString(sealed, chainKeys.deviceRegistry)) || {}
  } catch {
    return {}
  }
}

/** R93 §5: read-only peer count for the setup self-check (sizes only). */
export async function countPeers(chainKeys) {
  const map = await loadPeerMap(chainKeys)
  return Object.keys(map || {}).length
}

async function savePeerMap(chainKeys, map) {
  // R86 (T4): enforce the 10-device cap — evict staled-lastSeen entries first.
  // The freshest entry (the one just learned/seen) always survives its own save.
  const entries = Object.entries(map || {})
  if (entries.length > PEER_MAP_CAP) {
    entries.sort((a, b) => (a[1].lastSeen || 0) - (b[1].lastSeen || 0))
    for (const [staleId] of entries.slice(0, entries.length - PEER_MAP_CAP)) delete map[staleId]
    console.warn(`[UCrypt] Transfer: peer map capped at ${PEER_MAP_CAP} — evicted stale device(s) ${entries.slice(0, entries.length - PEER_MAP_CAP).map(([id]) => id.slice(0, 8)).join(', ')}…`)
  }
  const sealed = await encryptString(JSON.stringify(map || {}), chainKeys.deviceRegistry)
  await chrome.storage.local.set({ [PEERS_STORAGE_KEY]: sealed })
}

/**
 * TOFU learn/upsert: a KNOWN deviceId presenting a DIFFERENT pubkey is an
 * incident — refuse with a precise error, never a silent update.
 */
/** R85 (§5): forget ONE device from the sealed TOFU map.
 *  R148 §6.5 (LAW #74 — the K-5 cure): a removal is NO LONGER a local
 *  forget — it commits a TOMBSTONE to this device's sealed peer map:
 *  { ...entry, removed: { at, by } }. The tombstone rides the roster
 *  augmenter into the synced envelope, so EVERY instance converges on the
 *  next pull (and every fresh open). The local-only forget survives as
 *  forgetPeer — the post-convergence cleanup the removed row's own button
 *  drives. The cloud-dead case: the tombstone commits locally and the
 *  roster-dirty marker queues it — it propagates when cloud revives. */
export async function removePeer(chainKeys, deviceId, { by = '' } = {}) {
  const map = await loadPeerMap(chainKeys)
  if (!map[deviceId]) return false
  if (!map[deviceId].removed) {
    map[deviceId] = { ...map[deviceId], removed: { at: Date.now(), by: String(by || '').slice(0, 80) } }
    await savePeerMap(chainKeys, map)
  }
  return true
}

/** R148 §6.5 — the local cleanup (the converged tombstone's final forget).
 *  The removed row's own button calls this AFTER the chain has seen the
 *  tombstone (the roster renders the converged state; the cleanup frees
 *  the TOFU slot). */
export async function forgetPeer(chainKeys, deviceId) {
  const map = await loadPeerMap(chainKeys)
  if (!map[deviceId]) return false
  delete map[deviceId]
  await savePeerMap(chainKeys, map)
  return true
}

export async function learnPeer(chainKeys, entry) {
  if (!entry || !entry.deviceId || !entry.signPubJwk || !entry.agrPubJwk) {
    throw transferError('peer_invalid', 'Refusing to learn an incomplete peer record')
  }
  const map = await loadPeerMap(chainKeys)
  const known = map[entry.deviceId]
  if (known) {
    const same = known.signPubJwk && entry.signPubJwk &&
      JSON.stringify(known.signPubJwk) === JSON.stringify(entry.signPubJwk) &&
      JSON.stringify(known.agrPubJwk) === JSON.stringify(entry.agrPubJwk)
    if (!same) {
      throw transferError('key_change',
        `Device ${entry.deviceId.slice(0, 8)}… presented a DIFFERENT key than the one stored on first contact — this is treated as an incident, not an update`)
    }
    // R148 §6.5 (LAW #74) — THE TOMBSTONE CONVERGES: an incoming removed
    // mark adopts under the last-writer law (by removed.at) — every device
    // (and every fresh open) converges to the current chain. A tombstone
    // can never be un-removed by an older alive row.
    const incRem = entry.removed && Number(entry.removed.at) || 0
    const locRem = known.removed && Number(known.removed.at) || 0
    if (incRem && incRem >= locRem) {
      known.removed = { at: incRem, by: String(entry.removed.by || '').slice(0, 80) }
    }
    // R108 §3.2 — the label merge is PER-ENTRY LAST-WRITER: the incoming
    // label wins only when its write time is NEWER than the local one (or
    // the local label was never set). lastSeen, the TOFU keys and the id are
    // untouched by the label merge — battery-pinned (the rename of one field
    // can never rewrite another).
    const incAt = Number(entry.labelSetAt) || 0
    const locAt = Number(known.labelSetAt) || 0
    if (entry.label && (incAt > locAt || !known.label)) {
      known.label = entry.label
      if (incAt) known.labelSetAt = incAt
    }
    known.lastSeen = Date.now()
    // R111 §3.1 — the living-sync telemetry rides with the roster: the peer's
    // SELF-DECLARED last sync (when + lane + entry count) refreshes whenever
    // the peer's newer stamp arrives (per-device self-report — one device
    // never writes another's line; the newest self-stamp wins by syncAt).
    const incSyncAt = Number(entry.syncAt) || 0
    if (incSyncAt && incSyncAt >= (Number(known.syncAt) || 0)) {
      known.syncAt = incSyncAt
      known.syncLane = entry.syncLane === 'direct' ? 'direct' : 'cloud'
      if (Number.isFinite(Number(entry.entryCount))) known.entryCount = Number(entry.entryCount)
    }
    // R113 §3.1 — the SELF-DECLARED device type rides the label law: the
    // incoming type wins only when its write time is NEWER (per-entry
    // last-writer; a device never types another — self-only declarations).
    const incTypeAt = Number(entry.typeSetAt) || 0
    if (entry.deviceType && (incTypeAt > (Number(known.typeSetAt) || 0) || !known.deviceType)) {
      known.deviceType = entry.deviceType
      if (incTypeAt) known.typeSetAt = incTypeAt
    }
  } else {
    map[entry.deviceId] = {
      deviceId: entry.deviceId,
      signPubJwk: entry.signPubJwk,
      agrPubJwk: entry.agrPubJwk,
      label: entry.label || '',
      labelSetAt: Number(entry.labelSetAt) || 0,
      lastSeen: Date.now(),
    }
    const incSyncAt = Number(entry.syncAt) || 0
    if (incSyncAt) {
      map[entry.deviceId].syncAt = incSyncAt
      map[entry.deviceId].syncLane = entry.syncLane === 'direct' ? 'direct' : 'cloud'
      if (Number.isFinite(Number(entry.entryCount))) map[entry.deviceId].entryCount = Number(entry.entryCount)
    }
    if (entry.deviceType) {
      map[entry.deviceId].deviceType = entry.deviceType
      map[entry.deviceId].typeSetAt = Number(entry.typeSetAt) || 0
    }
  }
  await savePeerMap(chainKeys, map)
  return map[entry.deviceId]
}

/** R108 §3.2 — MUTUAL RENAME: any device may rename any OTHER device. The
 * rename is a per-entry mutation of THIS device's sealed peer map with its
 * write time stamped; the roster augmenter carries it to the whole chain
 * with the next sync (the envelope carries it), and the last-writer law in
 * learnPeer merges it everywhere. Removal stays the R85 local forget — a
 * removed (absent) device has no entry to rename, so a name can never
 * resurrect it. */
export async function renamePeerLabel(chainKeys, deviceId, label) {
  const id = String(deviceId || '')
  if (!id) throw transferError('peer_invalid', 'Refusing to rename: no device id')
  const map = await loadPeerMap(chainKeys)
  const entry = map[id]
  if (!entry) throw transferError('peer_invalid', 'That device is not in this device\'s list — nothing to rename')
  entry.label = String(label || '')
  entry.labelSetAt = Date.now()
  await savePeerMap(chainKeys, map)
  return { deviceId: id, label: entry.label, labelSetAt: entry.labelSetAt }
}

/** Paired-device list for the UI (label + lastSeen only — non-secret surface).
 *  R148 §6.5 — the removed rows RIDE the projection (deviceId + label + the
 *  removed mark) so the renderer can show the converged truth: the ACTIVE
 *  list excludes them; the removed row renders "Removed · <date> · by <who>"
 *  with its local forget cleanup. */
export async function knownPeers(chainKeys) {
  const map = await loadPeerMap(chainKeys)
  // R111 §3.1 — the living-sync telemetry rides the projection (the per-device
  // sync line renders from exactly these fields; stripping them here silently
  // blinded the roster — caught by the live matrix).
  return Object.values(map).map(p => ({
    deviceId: p.deviceId,
    label: p.label || '',
    labelSetAt: Number(p.labelSetAt) || 0,
    deviceType: p.deviceType || '',
    lastSeen: p.lastSeen || 0,
    syncAt: Number(p.syncAt) || 0,
    syncLane: p.syncLane === 'direct' ? 'direct' : (p.syncLane === 'cloud' ? 'cloud' : ''),
    entryCount: Number.isFinite(Number(p.entryCount)) ? Number(p.entryCount) : null,
    removed: p.removed && Number(p.removed.at) ? { at: Number(p.removed.at), by: String(p.removed.by || '') } : null,
  }))
}

/**
 * R108 §3.2 — THE ROSTER AUGMENTER (pure; the worker wires it into the
 * sync-chain bridge): merge THIS device's peer map into the push roster
 * BEFORE the envelope leaves — a peer's newest label (per-entry last-writer
 * by labelSetAt) and any map device the snapshot does not yet carry ride the
 * next sync, so a rename made anywhere reaches everyone. The SELF entry is
 * never touched from the map (its own identity record is the truth); the
 * CHAIN_DEVICES_MAX cap holds; the TOFU keys come from the map verbatim.
 * Pure — roster is never mutated; failures return roster unchanged.
 */
export const CHAIN_ROSTER_MAX = 10 // the one cap, one law (sync.js's CHAIN_DEVICES_MAX)

export function augmentRosterFromMap(roster, map, selfId) {
  const base = Array.isArray(roster) ? roster : []
  const out = base.map((d) => ({ ...d }))
  const byId = new Map(out.map((d) => [String(d.deviceId), d]))
  const additions = []
  for (const p of Object.values(map || {})) {
    if (!p || !p.deviceId || String(p.deviceId) === String(selfId || '')) continue
    const ex = byId.get(String(p.deviceId))
    const incAt = Number(p.labelSetAt) || 0
    if (!ex) {
      if (out.length + additions.length >= CHAIN_ROSTER_MAX) continue
      const rec = {
        deviceId: p.deviceId,
        signPubJwk: p.signPubJwk,
        agrPubJwk: p.agrPubJwk,
        label: p.label || '',
        labelSetAt: incAt,
        deviceType: p.deviceType || '',
        typeSetAt: Number(p.typeSetAt) || 0,
      }
      // R148 §6.5 — the tombstone rides the envelope (the convergence law):
      // a removed member's row carries the mark so EVERY instance (and
      // every fresh open) reconciles to the current chain on the next pull.
      if (p.removed && Number(p.removed.at)) rec.removed = { at: Number(p.removed.at), by: String(p.removed.by || '') }
      additions.push(rec)
    } else {
      const exAt = Number(ex.labelSetAt) || 0
      if (p.label && (incAt > exAt || !ex.label)) { ex.label = p.label; ex.labelSetAt = incAt }
      // R113 §3.1 — the device type merges under the SAME per-entry
      // last-writer law (by typeSetAt) so a self-declaration made anywhere
      // reaches every roster with the next sync.
      const incTypeAt = Number(p.typeSetAt) || 0
      if (p.deviceType && (incTypeAt > (Number(ex.typeSetAt) || 0) || !ex.deviceType)) {
        ex.deviceType = p.deviceType
        ex.typeSetAt = incTypeAt
      }
      // R148 §6.5 — the tombstone converges through the envelope too (the
      // newest removed mark wins; an older alive row can never resurrect).
      const incRem = p.removed && Number(p.removed.at) || 0
      const exRem = ex.removed && Number(ex.removed.at) || 0
      if (incRem && incRem >= exRem) ex.removed = { at: incRem, by: String(p.removed.by || '') }
    }
  }
  return [...out, ...additions]
}

/**
 * Full peer entry (public keys included) for worker-internal peer resolution
 * — public JWKs are non-secret and never leave the worker boundary.
 */
export async function getPeerEntry(chainKeys, deviceId) {
  if (!deviceId) return null
  const map = await loadPeerMap(chainKeys)
  return map[deviceId] || null
}

// --- Record construction -------------------------------------------------------------

/** R98 (S8.4): the Beam's join-record gate reuses the E4 schema check on the
 * shared envelope shape — exported for lib/beam.js (additions-only export). */
export function isRecordStructurallyValid(rec) {
  return !!(rec && rec.v === 1 && RECORD_KINDS.includes(rec.kind) &&
    HEX64_RE.test(String(rec.messageId || '')) &&
    (rec.transferId === '' || HEX64_RE.test(String(rec.transferId))) &&
    HEX32_RE.test(String(rec.from || '')) &&
    (String(rec.to) === '*' || HEX32_RE.test(String(rec.to || ''))) &&
    typeof rec.expiresAt === 'string' && !Number.isNaN(Date.parse(rec.expiresAt)) &&
    Number.isInteger(rec.seq) && rec.seq >= 0 &&
    (rec.nonce === '' || HEX64_RE.test(String(rec.nonce))) &&
    typeof rec.chainTag === 'string' && rec.chainTag.length === 8 &&
    typeof rec.payload === 'string' && B64_RE.test(rec.payload) &&
    typeof rec.sig === 'string' && B64_RE.test(rec.sig))
}

function isExpired(rec, now = Date.now()) {
  const t = Date.parse(rec && rec.expiresAt)
  return !(t > now)
}

/**
 * Build + sign a record envelope (owner order E4 EXACT schema):
 * { v:1, kind, messageId(32-hex), transferId(32-hex|''), from, to, expiresAt,
 *   seq, nonce, chainTag, payload(sealed), sig }
 * PRESENCE payloads are sealed under the rendezvous-GROUP key and broadcast
 * (to:'*'); every other kind is sealed under the PAIRWISE signal key.
 * The offer's one-time nonce lives in the ENVELOPE; the answer echoes it
 * INSIDE its ciphertext payload (caller includes `echoNonce`).
 */
export async function sealForPeer(chainKeys, identity, peer, kind, payloadObj, { transferId = '', seq = 0, nonce = '', expiresAt = null } = {}) {
  if (!RECORD_KINDS.includes(kind)) throw transferError('bad_kind', `Unknown record kind: ${kind}`)
  const isPresence = kind === 'presence'
  // R79 (F-R78-9): a pairwise record without a resolvable peer agreement key
  // is a TYPED refusal — previously the ECDH import threw a raw DataError
  // that the router could not classify.
  if (!isPresence && (!peer || !peer.agrPubJwk || !peer.deviceId)) {
    throw transferError('peer_invalid', 'Cannot seal a pairwise record without a known peer (device id + agreement key)')
  }
  if (!identity || !identity.agrPrivJwk || !identity.signKeys || !identity.signKeys.privateKey) {
    throw transferError('internal', 'Sealing requires the authenticated local device identity')
  }
  const sealedKey = isPresence
    ? chainKeys.rendezvousGroup
    : await derivePairwiseSignalKey(identity.agrPrivJwk, peer && peer.agrPubJwk)
  const payload = await encryptString(JSON.stringify(payloadObj || {}), sealedKey)
  const rec = {
    v: 1,
    kind,
    messageId: randomHex32(),
    transferId: transferId || '',
    from: identity.deviceId,
    to: isPresence ? '*' : String((peer && peer.deviceId) || '*'),
    expiresAt: expiresAt || new Date(Date.now() + RECORD_TTL_MS).toISOString(),
    seq: Number.isInteger(seq) ? seq : 0,
    nonce: nonce || '',
    chainTag: chainKeys.chainTag,
    payload,
    sig: '',
  }
  rec.sig = await signRecord(identity.signKeys.privateKey, await canonicalRecordBytes(rec))
  if (!isRecordStructurallyValid(rec)) throw transferError('bad_record', 'Constructed record failed its own schema check')
  assertNoPlaintextLeaks(rec, payloadObj || {})
  // Self-audit the SEALED envelope one last time: the record must never
  // contain a plaintext file name, label, IP-shaped or URL-shaped string.
  return {
    record: rec,
    messageId: rec.messageId,
    payloadHashHex: await sha256HexOfBytes(base64ToBytes(payload)),
  }
}

/**
 * Open a record from a peer. Order of gates (hard): structural → group/chain
 * gate (chainTag match — fast foreign-chain rejection) → replay → expiry →
 * signature verify → decrypt → (answers) capability echo check.
 * PRESENCE records decrypt under the group key and TOFU-learn the peer; every
 * other kind requires the signer's KNOWN key (learned via presence first
 * contact, or supplied by the caller for an in-session peer).
 */
export async function openFromPeer(chainKeys, identity, rec, { expectedNonce = null, peer = null, skipReplay = false } = {}) {
  if (!isRecordStructurallyValid(rec)) throw transferError('bad_record', 'Record failed the E4 schema check')
  chainTagGate(rec, chainKeys.chainTag)
  if (isExpired(rec)) throw transferError('expired', 'Record expired before it was opened')
  // R77-C audit fix (F-R77-D2-1): PRESENCE records are idempotent
  // advertisements (refreshed every 60 s while a window is open), NOT
  // one-time signals — listing the same still-valid presence twice is the
  // NORMAL case, so the replay gate may be exempted for presence ONLY. Every
  // signaled kind (offer/answer/ice/cancel/complete) keeps the hard gate.
  const replayExempt = skipReplay === true && rec.kind === 'presence'
  if (!replayExempt && (await seenBefore(rec.messageId))) throw transferError('replay', 'Record was already accepted (replay protection)')

  let payloadObj = null
  let peerEntry = peer
  if (rec.kind === 'presence') {
    // Presence payload is sealed under K_rendezvous_group — NOT pairwise.
    try {
      payloadObj = JSON.parse(await decryptString(rec.payload, chainKeys.rendezvousGroup))
    } catch {
      throw transferError('decrypt_failed', 'Presence payload failed to open under the group key')
    }
    if (!payloadObj || payloadObj.deviceId !== rec.from || !payloadObj.signPubJwk || !payloadObj.agrPubJwk) {
      throw transferError('bad_record', 'Presence payload identity mismatch')
    }
    const ok = await verifyRecord(payloadObj.signPubJwk, rec.sig, await canonicalRecordBytes(rec))
    if (!ok) throw transferError('bad_signature', 'Presence record signature failed')
    // TOFU within the chain: first contact stores the peer's keys.
    peerEntry = await learnPeer(chainKeys, {
      deviceId: rec.from,
      signPubJwk: payloadObj.signPubJwk,
      agrPubJwk: payloadObj.agrPubJwk,
      label: payloadObj.label || '',
      // R113 §3.1 — the self-declared type rides the presence learn.
      deviceType: payloadObj.deviceType || '',
      typeSetAt: Number(payloadObj.typeSetAt) || 0,
    })
  } else {
    if (!peerEntry) {
      const map = await loadPeerMap(chainKeys)
      peerEntry = map[rec.from] || null
    }
    if (!peerEntry || !peerEntry.signPubJwk || !peerEntry.agrPubJwk) {
      throw transferError('unknown_sender', 'Sender device is not known — presence first contact is required before offers')
    }
    const ok = await verifyRecord(peerEntry.signPubJwk, rec.sig, await canonicalRecordBytes(rec))
    if (!ok) throw transferError('bad_signature', 'Record signature failed against the known device key')
    const pairwise = await derivePairwiseSignalKey(identity.agrPrivJwk, peerEntry.agrPubJwk)
    try {
      payloadObj = JSON.parse(await decryptString(rec.payload, pairwise))
    } catch {
      throw transferError('decrypt_failed', 'Record payload failed to open under the pairwise signal key')
    }
  }

  if (rec.kind === 'answer' && expectedNonce != null && String(payloadObj.echoNonce || '') !== String(expectedNonce)) {
    throw transferError('nonce_mismatch', 'Answer did not echo the offer capability nonce — refusing the transcript')
  }

  if (!replayExempt) await markSeen(rec.messageId)
  return {
    kind: rec.kind,
    messageId: rec.messageId,
    transferId: rec.transferId,
    from: rec.from,
    to: rec.to,
    seq: rec.seq,
    nonce: rec.nonce,
    expiresAt: rec.expiresAt,
    payloadHashHex: await sha256HexOfBytes(base64ToBytes(rec.payload)),
    payload: payloadObj,
    peer: {
      deviceId: rec.from,
      signPubJwk: peerEntry.signPubJwk,
      agrPubJwk: peerEntry.agrPubJwk,
      label: peerEntry.label || payloadObj.label || '',
    },
  }
}

// --- Presence (availability advertising, protocol v2 — R81-F1) -------------------------

/**
 * Issue the next device-local monotonic presence sequence. The counter is
 * persisted BEFORE the value is used, so a crash can leave a GAP (harmless —
 * the rule is "newer must be greater", gaps carry no semantics) but never a
 * REUSED sequence.
 */
export async function nextPresenceSequence() {
  const { [PRESENCE_SEQ_KEY]: cur } = await chrome.storage.local.get(PRESENCE_SEQ_KEY)
  const n = (cur && Number.isInteger(cur.n) ? cur.n : 0) + 1
  await chrome.storage.local.set({ [PRESENCE_SEQ_KEY]: { n } })
  return n
}

async function loadWithdrawnHighWater() {
  const { [PRESENCE_WITHDRAWN_KEY]: map } = await chrome.storage.local.get(PRESENCE_WITHDRAWN_KEY)
  return map && typeof map === 'object' ? map : {}
}

async function saveWithdrawnHighWater(map) {
  await chrome.storage.local.set({ [PRESENCE_WITHDRAWN_KEY]: map || {} })
}

/**
 * Publish this device's temporary availability: a signed presence record
 * sealed under the GROUP key, written to presence/<deviceId>.json and
 * registered in presence/index.json (read-merge-write, If-Match, 3 retries).
 * `label` is the USER-SET device label — it lives ONLY inside the ciphertext.
 *
 * R81-F1 protocol v2: the sealed payload now carries
 *   presenceState:'available', sequence (monotonic), publishedAt (freshness),
 *   availableUntil (the user-chosen window end — unchanged semantics),
 * while the ENVELOPE expiresAt is bounded to ≤ PRESENCE_ENVELOPE_TTL_MS so a
 * device that dies without withdrawing stops advertising quickly.
 */
/**
 * F-R99-1 (R99) — the SEAL half of publishPresence, split out so the enable
 * path can stage the hand-carry copy the instant the record exists (no
 * network waited on) and publish in the background. Contract:
 *   sealPresenceRecord(...)  → { record, availableUntil, sequence, envelopeExpires }
 *   publishSealedPresence(sealed, chainKeys, identity) → the cloud write
 *       (throws the SAME typed error as before, stagedManualB64 attached)
 * publishPresence(...) = seal + publish (unchanged behavior and return).
 */
export async function sealPresenceRecord(chainKeys, identity, label, durationMinutes = 10, { windowEnd = null, beam2Caps = null } = {}) {
  const minutes = Number(durationMinutes) > 0 ? Number(durationMinutes) : 10
  const now = Date.now()
  // R81-F1 refresh path: an explicit windowEnd keeps the USER-CHOSEN window
  // stable across 60 s refreshes (only the envelope TTL and publishedAt turn).
  const availableUntil = (windowEnd && Date.parse(windowEnd) > now)
    ? new Date(Date.parse(windowEnd)).toISOString()
    : new Date(now + minutes * 60 * 1000).toISOString()
  const envelopeExpires = new Date(Math.min(now + minutes * 60 * 1000, now + PRESENCE_ENVELOPE_TTL_MS)).toISOString()
  const sequence = await nextPresenceSequence()
  // R134 §2.B — LAW 0.46 RIDE-ALONG (Beam 2): the heartbeat now carries the
  // Beam 2 capabilities block (device ID, name, capabilities, TTL) — the
  // same non-secret, self-declared class as the label and device type above
  // it. Older readers ignore unknown ciphertext fields (additions-only).
  const caps = beam2Caps && typeof beam2Caps === 'object' ? beam2Caps : {}
  const payload = {
    deviceId: identity.deviceId,
    label: String(label || '').slice(0, 60),
    signPubJwk: identity.signPubJwk,
    agrPubJwk: identity.agrPubJwk,
    availableUntil,
    presenceState: PRESENCE_STATES.AVAILABLE,
    sequence,
    publishedAt: new Date(now).toISOString(),
    // R83-F1: non-secret capability list inside the ciphertext — the
    // presence payload documents WHAT the availability is for. The v1
    // product supports exactly one rendezvous capability: file transfer.
    // R134: Beam 2 extends the list (additions-only) with the new lanes.
    capabilities: ['file', ...(caps.beam2 ? ['beam2'] : []), ...(caps.webrtc ? ['webrtc'] : [])],
    // R134 §2.B — the Beam 2 capabilities block (Lane W/C advertisement +
    // the negotiated chunk ceiling + the protocol version HELLO carries).
    beam2Caps: {
      beam2: !!caps.beam2,
      webrtc: !!caps.webrtc,
      maxChunk: Number(caps.maxChunk) || 16384,
      protocolVersion: String(caps.protocolVersion || '2.91.0'),
    },
    // R113 §3.1 — the SELF-DECLARED device type rides the presence (the same
    // non-secret, self-declared class as the label above it): a peer that
    // learns this device from its availability stamp can render the roster's
    // icon + label without waiting for a chain sync.
    deviceType: (identity && typeof identity.deviceType === 'string' && ['phone', 'tablet', 'computer'].includes(identity.deviceType)) ? identity.deviceType : '',
    typeSetAt: Number(identity && identity.typeSetAt) || 0,
    // locator hint deliberately OMITTED: the mailbox locator is derivable.
  }
  const { record } = await sealForPeer(chainKeys, identity, null, 'presence', payload, {
    transferId: '', seq: sequence, nonce: '', expiresAt: envelopeExpires,
  })
  return { record, availableUntil, sequence, envelopeExpires }
}

/**
 * F-R99-1 (R99) — the WRITE half of publishPresence (see sealPresenceRecord).
 * The failure path is byte-identical to the pre-split contract: the typed
 * error carries the EXACT sealed record in its manual (base64) form.
 */
export async function publishSealedPresence(sealed, chainKeys, identity) {
  try {
    const base = await ensureNamespace()
    await ensurePresenceDir(base)
    await davPutJson(base + 'presence/' + identity.deviceId + '.json', sealed.record, null, 'Rendezvous presence write')
    await etagMergeWrite(base + 'presence/index.json', (cur) => {
      const ids = Array.isArray(cur) ? cur.filter(x => typeof x === 'string') : []
      if (!ids.includes(identity.deviceId)) ids.push(identity.deviceId)
      return ids
    }, 'Rendezvous presence index')
  } catch (e) {
    // R89 (F-R89-MANUAL-1): the sealed presence record EXISTS even when the
    // cloud write fails — the manual copy/paste fallback (T1/T2) must be able
    // to carry it by hand. The typed error carries the EXACT sealed record in
    // its manual (base64) form; no re-seal, no re-encode (same discipline as
    // the page-level stageManualSignal surface).
    const err = new Error(`presence publish failed: ${e?.code || e?.message || e}`)
    err.code = e?.code || 'presence_publish_failed'
    try { err.stagedManualB64 = recordToManual(sealed.record) } catch { /* staging is best-effort */ }
    throw err
  }
  return { availableUntil: sealed.availableUntil, sequence: sealed.sequence }
}

export async function publishPresence(chainKeys, identity, label, durationMinutes = 10, { windowEnd = null } = {}) {
  const sealed = await sealPresenceRecord(chainKeys, identity, label, durationMinutes, { windowEnd })
  return publishSealedPresence(sealed, chainKeys, identity)
}

/**
 * R107 (F-R107-CARRY-1) — THE MANUAL-CARRIER SEAL (the hand-carry channel).
 *
 * The CLOUD presence record deliberately carries the ≤2-minute envelope TTL
 * (R81-F1: a device that dies without withdrawing stops advertising within
 * ≤2 refresh ticks). That law is RIGHT for a record the 60-second cadence
 * constantly rewrites — and LETHAL for a record a HUMAN carries by hand:
 * the CEO's S9 forensic proved the staged carrier pasted at T+130 s is
 * refused 'expired' ("the connection between both instances are not
 * reliable"). The fix is a SECOND seal of the SAME presence payload whose
 * ENVELOPE lives to the availability window end (the user's own chosen
 * horizon): the manual carrier. Channel laws stay intact:
 *   - the CLOUD record keeps the 2-minute envelope law (unchanged);
 *   - the carrier is read ONCE by a peer (the manual open path) and still
 *     obeys the payload truth — presenceState, the monotonic sequence, the
 *     withdrawn high-water rules and payload.availableUntil all still bind
 *     the receiver, so a carried record can never out-live the window the
 *     user chose;
 *   - no secret rides it (the same sealed-envelope discipline as before —
 *     assertNoPlaintextLeaks runs inside sealForPeer for BOTH records).
 *
 * Returns the SAME shape as sealPresenceRecord, plus `record` being the
 * window-end ENVELOPE. `publishedAt` keeps the seal instant (freshness is
 * re-staged by the availability cadence, so a copy taken later is fresher).
 */
export async function sealPresenceCarrier(chainKeys, identity, label, durationMinutes = 10, { windowEnd = null } = {}) {
  const minutes = Number(durationMinutes) > 0 ? Number(durationMinutes) : 10
  const now = Date.now()
  const availableUntil = (windowEnd && Date.parse(windowEnd) > now)
    ? new Date(Date.parse(windowEnd)).toISOString()
    : new Date(now + minutes * 60 * 1000).toISOString()
  const sequence = await nextPresenceSequence()
  const payload = {
    deviceId: identity.deviceId,
    label: String(label || '').slice(0, 60),
    signPubJwk: identity.signPubJwk,
    agrPubJwk: identity.agrPubJwk,
    availableUntil,
    presenceState: PRESENCE_STATES.AVAILABLE,
    sequence,
    publishedAt: new Date(now).toISOString(),
    capabilities: ['file'],
    // R113 §3.1 — the hand-carried carrier seals the SAME self-declared type
    // (the ONE difference from the cloud record stays the envelope TTL only).
    deviceType: (identity && typeof identity.deviceType === 'string' && ['phone', 'tablet', 'computer'].includes(identity.deviceType)) ? identity.deviceType : '',
    typeSetAt: Number(identity && identity.typeSetAt) || 0,
  }
  // The ONE difference from the cloud record: the envelope expiresAt is the
  // window end, not min(window, 2 min). Every other byte of discipline is
  // the shared sealForPeer path (schema, signature, leak audit).
  const { record, messageId, payloadHashHex } = await sealForPeer(chainKeys, identity, null, 'presence', payload, {
    transferId: '', seq: sequence, nonce: '', expiresAt: availableUntil,
  })
  return { record, carrierRecord: record, availableUntil, sequence, envelopeExpires: availableUntil, messageId, payloadHashHex }
}

/**
 * R81-F1 — immediate presence withdrawal (the anti-ghost path).
 *
 * Writes a SIGNED ENCRYPTED TOMBSTONE (presenceState:'withdrawn', higher
 * sequence) over this device's presence file BEFORE attempting any deletion:
 *   - tombstone write OK  → peers that read the record see withdrawn and
 *     refuse to advertise this device even if the later DELETE never lands;
 *   - delete OK           → nothing remains (best case);
 *   - delete fails        → the tombstone remains ≤5 min, then expires; peers
 *     ALSO apply the withdrawn high-water rule device-locally, so the device
 *     cannot be resurrected by a replayed older 'available' record.
 * The envelope/payload availableUntil is set in the PAST so a LEGACY peer
 * (which does not know presenceState) filters the tombstone as expired rather
 * than advertising a withdrawn device.
 *
 * Never throws: withdrawal is best-effort by contract. The boolean result is
 * the truthful record for the caller — {tombstoneOk, indexOk, deleteOk} — and
 * a false value means "remote presence may remain visible until expiry".
 */
export async function withdrawPresence(chainKeys, identity) {
  const result = { tombstoneOk: false, indexOk: false, deleteOk: false, attempted: true }
  let base = null
  try {
    const cfg = await webdavConfig()
    if (!cfg || !cfg.url) return { ...result, attempted: false } // never configured — nothing to withdraw
    base = rendezvousBaseFromVaultUrl(cfg.url)
    if (!base) return { ...result, attempted: false }
    await ensurePresenceDir(base)
    const now = Date.now()
    const sequence = await nextPresenceSequence()
    const payload = {
      deviceId: identity.deviceId,
      label: '',
      signPubJwk: identity.signPubJwk,
      agrPubJwk: identity.agrPubJwk,
      // PAST availableUntil: legacy peers filter this record as expired.
      availableUntil: new Date(now - 1000).toISOString(),
      presenceState: PRESENCE_STATES.WITHDRAWN,
      sequence,
      publishedAt: new Date(now).toISOString(),
    }
    const { record } = await sealForPeer(chainKeys, identity, null, 'presence', payload, {
      transferId: '',
      seq: sequence,
      nonce: '',
      expiresAt: new Date(now + PRESENCE_WITHDRAWN_TTL_MS).toISOString(),
    })
    await davPutJson(base + 'presence/' + identity.deviceId + '.json', record, null, 'Rendezvous presence withdraw')
    result.tombstoneOk = true
    // Locally remember our own withdrawal so a replayed older 'available'
    // record (e.g. a stale cached copy surfacing later) is refused.
    try {
      const map = await loadWithdrawnHighWater()
      const applied = applyPresenceHighWater(map, { deviceId: identity.deviceId, state: PRESENCE_STATES.WITHDRAWN, sequence })
      await saveWithdrawnHighWater(applied.next)
    } catch { /* local memory is best-effort */ }
  } catch (e) {
    // Tombstone failed (cloud unreachable, CAS busy…) — say so truthfully.
    console.warn('[UCrypt] Rendezvous: presence tombstone failed (peers may see stale presence until expiry):', e?.code || e?.message || e)
    return result
  }
  try {
    await etagMergeWrite(base + 'presence/index.json', (cur) => {
      const ids = Array.isArray(cur) ? cur.filter(x => typeof x === 'string') : []
      return ids.filter(id => id !== identity.deviceId)
    }, 'Rendezvous presence index withdraw')
    result.indexOk = true
  } catch { /* tombstone still governs */ }
  try {
    result.deleteOk = await davDelete(base + 'presence/' + identity.deviceId + '.json', 'Rendezvous presence delete')
  } catch { /* tombstone still governs */ }
  return result
}

/** Withdraw availability (R81-F1 tombstone) — legacy alias kept for callers. */
export async function clearPresence(chainKeys, identity) {
  return withdrawPresence(chainKeys, identity)
}

/**
 * List devices currently advertising availability on this chain. Reads the
 * presence index, then each per-device record; filters expired; verifies each
 * signature after the group-key gate.
 *
 * R81-F1 rules applied here (in order):
 *   1. envelope expired                      → Offline (skipped, never available);
 *   2. payload presenceState 'withdrawn'     → tombstone wins (skipped) AND
 *     the withdrawn high-water map is updated device-locally;
 *   3. 'available' whose sequence is NOT strictly newer than the remembered
 *     withdrawn high-water for that device → stale resurrection, refused;
 *   4. available but publishedAt older than the freshness threshold → the
 *     peer is returned with stale:true — "advertised available, may be stale",
 *     never a live claim.
 * Returns [{deviceId, label, availableUntil, publishedAt, sequence, stale,
 *           signPubJwk, agrPubJwk}].
 */
export async function listAvailablePeers(chainKeys, now = Date.now()) {
  const base = await ensureNamespace()
  await ensurePresenceDir(base)
  const idx = await davGetJson(base + 'presence/index.json', 'Rendezvous presence index read')
  const ids = idx && Array.isArray(idx.json) ? idx.json.filter(x => typeof x === 'string' && HEX32_RE.test(x)) : []
  const peers = []
  let withdrawn = await loadWithdrawnHighWater()
  let withdrawnDirty = false
  for (const deviceId of ids) {
    let rec = null
    try {
      const file = await davGetJson(base + 'presence/' + deviceId + '.json', 'Rendezvous presence read')
      rec = file && file.json
    } catch (e) {
      console.warn('[UCrypt] Rendezvous: presence read failed for one device:', e?.message || e)
      continue
    }
    if (!isRecordStructurallyValid(rec)) continue
    if (rec.chainTag !== chainKeys.chainTag) continue // foreign chain — silent skip
    if (isExpired(rec, now)) continue // R81-F1: expired ⇒ Offline, never available
    let opened = null
    try {
      // Presence listing is repeatable (see the F-R77-D2-1 note in
      // openFromPeer) — the replay gate must not consume advertisements.
      opened = await openFromPeer(chainKeys, null, rec, { skipReplay: true })
    } catch (e) {
      // A record that fails replay/signature gates is skipped (and its
      // messageId already marked seen where applicable).
      console.warn('[UCrypt] Rendezvous: presence record refused:', e?.code || e?.message || e)
      continue
    }
    if (!opened || !opened.payload) continue
    const evald = evaluatePresenceRecord(opened.payload, { now })
    if (!evald.usable) continue
    const gate = applyPresenceHighWater(withdrawn, { deviceId: rec.from, state: evald.state, sequence: evald.sequence })
    withdrawn = gate.next
    if (gate.next !== undefined) withdrawnDirty = true
    if (!gate.accept) {
      console.warn('[UCrypt] Rendezvous: presence refused (stale resurrection):', rec.from.slice(0, 8))
      continue
    }
    if (evald.state === PRESENCE_STATES.WITHDRAWN) continue // tombstone wins — not available
    // The user-chosen window end still governs the advertisement horizon.
    if (Date.parse(opened.payload.availableUntil) <= now) continue
    peers.push({
      deviceId: rec.from,
      label: opened.payload.label || '',
      availableUntil: opened.payload.availableUntil,
      publishedAt: opened.payload.publishedAt || '',
      sequence: evald.sequence,
      stale: evald.stale,
      signPubJwk: opened.payload.signPubJwk,
      agrPubJwk: opened.payload.agrPubJwk,
    })
  }
  if (withdrawnDirty) {
    try { await saveWithdrawnHighWater(withdrawn) } catch { /* local memory best-effort */ }
  }
  return peers
}

/**
 * R79 (F-R78-3): report whether the CURRENT transport can host the rendezvous
 * plane. The worker includes this in every status/peers response so the UI
 * can say "Direct transfer unavailable for current storage" truthfully — it
 * must never fake a device list for a transport without rendezvous support.
 * Other transports expose direct transfer ONLY when they physically implement
 * this capability (the WebDAV RendezvousStore adapter is the first).
 */
export async function rendezvousCapability() {
  try {
    const cfg = await webdavConfig()
    if (!cfg || !cfg.url) return { available: false, transport: null }
    const base = rendezvousBaseFromVaultUrl(cfg.url)
    if (!base) return { available: false, transport: null }
    return { available: true, transport: 'webdav' }
  } catch {
    return { available: false, transport: null }
  }
}

// --- Mailbox send / receive --------------------------------------------------------------

export function ownLocator(chainKeys, identity) { // exported R100: the tick's honest trace names the file it reads
  return mailboxLocator(chainKeys, identity.deviceId)
}

function pruneMailbox(records, now = Date.now()) {
  const out = []
  for (const r of Array.isArray(records) ? records : []) {
    if (!isRecordStructurallyValid(r)) continue
    if (isExpired(r, now)) continue
    out.push(r)
  }
  while (out.length > MAILBOX_MAX_RECORDS) out.shift()
  return out
}

/**
 * Put a sealed record into a peer's mailbox file: read-merge-write with the
 * If-Match/412 discipline, expired records pruned when rewriting.
 * R79 (F-R78-5): the cap is applied BEFORE the push — the merge result can
 * never transiently exceed MAILBOX_MAX_RECORDS (push-then-prune held 51).
 * The OLDEST record yields its slot, exactly like the previous semantics.
 */
export async function putRecordToMailbox(chainKeys, identity, peerLocator, record) {
  const base = await ensureNamespace()
  const url = base + String(peerLocator) + '.json'
  return etagMergeWrite(url, (cur) => {
    const list = pruneMailbox(cur)
    while (list.length >= MAILBOX_MAX_RECORDS) list.shift()
    list.push(record)
    return list
  }, 'Rendezvous mailbox write')
}

/** Read MY mailbox (array of record envelopes; 404 → []). */
export async function readOwnMailbox(chainKeys, identity) {
  const base = await ensureNamespace()
  const file = await davGetJson(base + (await ownLocator(chainKeys, identity)) + '.json', 'Rendezvous mailbox read')
  return pruneMailbox(file ? file.json : [])
}

/** Convenience: base64url of a record envelope for the manual copy/paste path. */
export function recordToManual(record) {
  try {
    return btoa(JSON.stringify(record))
  } catch {
    return ''
  }
}

/** Parse a pasted manual signal back into a record envelope (or null). */
export function recordFromManual(text) {
  try {
    const json = atob(String(text || '').trim())
    const rec = JSON.parse(json)
    return isRecordStructurallyValid(rec) ? rec : null
  } catch {
    return null
  }
}


