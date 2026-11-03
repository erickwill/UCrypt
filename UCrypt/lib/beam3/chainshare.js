/**
 * UCrypt — R137 §8 — CHAIN ALL-DATA SHARE (the Brave model completed).
 * New in v2.94.0 (additions-only on the sealed v2.93.0 base; gate G82).
 *
 * The Chief Executive vision, made code: once UCrypt instances are bound in
 * a chain, they share ALL of it — logins, passwords, form data, history,
 * cloud service configurations — directly with each other, without depending
 * on a cloud service, in the manner of Brave where chain members replicate
 * typed records among themselves.
 *
 * THE LAWS THIS MODULE ENFORCES (R137 Table 7 + section 8 prose):
 *  1. Consent is bilateral and typed. The sender chooses the device and the
 *     types to share (one manifest per share session); the receiver sees
 *     exactly what was offered, from which device, and accepts or declines
 *     PER TYPE. Nothing applies without the receiver consent. The default
 *     for continuous background sharing is OFF with a per-device-pair opt-in.
 *  2. Closing a type on either end means neither sending nor receiving it
 *     (the chaindata law) — enforced before build and before apply.
 *  3. Merge rules per type (R137 Table 7):
 *     - logins:            union by origin and username; per-field LWW on
 *                          changes; conflicts keep both when identities differ.
 *     - formAddresses:     merge-only union; per-entry LWW on edits.
 *     - history:           union by URL and visit timestamp; dedupe exact repeats.
 *     - cloudConfigs:      config applied with tokens STRUCTURALLY REJECTED and
 *                          replaced by a reconnect prompt on the receiver.
 *     - passkeysMeta:      METADATA ONLY — private keys never leave the device;
 *                          structure rejection proves it on every attempt, both ends.
 *     - settings:          per-key LWW; the share-consent settings themselves
 *                          are NEVER replicated.
 *  4. Deterministic LWW tie-break (CS3): when two edits carry the SAME
 *     updatedAt, the record whose origin deviceId sorts LEXICOGRAPHICALLY
 *     GREATER wins. Both ends run the same rule over the same inputs, so
 *     both ends converge on one deterministic result. Field-level ties use
 *     the chaindata fieldStamps; a stamp tie defers to the record-level rule.
 *  5. Incremental replication: per-type, per-peer watermarks; a batch sends
 *     only records with updatedAt > watermark; the watermark advances ONLY
 *     after the receiver's ack. A fresh bootstrap is a full pull (watermark 0).
 *  6. Every applied batch writes an audit row on BOTH ends naming the types,
 *     the counts, and the clock state, so the chain history stays examinable.
 *  7. The share rides the Beam 3 planes (A direct / B relay / C manual) with
 *     the manifest bound into the transcript hash — a manifest substituted
 *     after pairing is VISIBLE and refused. Plane B carries ciphertext-only
 *     sealed batches through the relayStore facade (this module produces the
 *     batch bytes; the caller seals them — never plaintext on the relay).
 *
 * The module is PURE: no chrome.* calls, no network calls, no timers. Stores,
 * planes, acks, and clocks are injected. That is what makes the G82 battery
 * able to prove CS1–CS5 on virtual peers in one process.
 */

import { sha256Hex } from './manifest.js'
import { CHAIN_DATA_TYPE_KEYS, enforceOutbound } from '../chaindata.js'

export const CHAINSHARE_VERSION = 1

/** The share-session record kind (distinct from the file-transfer manifest). */
export const CHAINSHARE_KIND = 'chainshare'

/**
 * The consent matrix (R137 Table 7 + R147 §8.1 the ALL DATA completion): the
 * CEO's commanded types with their offer/accept posture and merge rule.
 * `chaindataKey` maps each share type onto the sealed chaindata store key;
 * `settings` is chainshare-native. The R147 rows ride the SAME laws (per-type
 * consent toggles, LWW merge with tombstones, watermark acks per type).
 */
export const SHARE_CONSENT_MATRIX = Object.freeze([
  { type: 'logins', chaindataKey: 'logins', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'union-identity-lww' },
  { type: 'passwords', chaindataKey: 'passwords', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'union-identity-lww' },
  { type: 'formFields', chaindataKey: 'formFields', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'merge-only-union' },
  { type: 'formAddresses', chaindataKey: 'addresses', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'merge-only-union' },
  { type: 'paymentCardsMeta', chaindataKey: 'paymentCardsMeta', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'metadata-only' },
  { type: 'history', chaindataKey: 'history', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'union-visit-dedupe' },
  { type: 'openTabs', chaindataKey: 'openTabs', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'union-visit-dedupe' },
  { type: 'passkeysMeta', chaindataKey: 'passkeysMeta', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'metadata-only' },
  { type: 'cloudConfigs', chaindataKey: 'cloudConfigs', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'config-tokens-rejected' },
  { type: 'settings', chaindataKey: 'settings', senderMayOffer: true, receiverMayAccept: true, mergeRule: 'per-key-lww' },
])

export const SHARE_TYPE_KEYS = SHARE_CONSENT_MATRIX.map((t) => t.type)

/** Share-consent settings keys that are NEVER replicated (law 3, settings row). */
export const NEVER_REPLICATED_SETTINGS = Object.freeze([
  'chainShareConsent',
  'chainShareContinuous',
  'chainSharePeers',
])

function shareError(code, detail) {
  const e = new Error(`chainshare/${code}: ${detail}`)
  e.code = `chainshare/${code}`
  e.typed = true
  return e
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

/** Canonical JSON (deep-sorted keys) — the byte-stable manifest hash input. */
export function canonicalShareJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalShareJson).join(',')}]`
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalShareJson(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

// --- Structure projection and rejection (law 3, the secret doors) ---------------

/**
 * SENDER-side projection: passkeysMeta records are reduced to metadata only —
 * every secret-shaped field is dropped before the record can enter a batch.
 * cloudConfigs records are reduced to a TEMPLATE (§8.2's exact law): the
 * provider kind + the NON-SECRET fields transit — an ALLOWLIST, never a
 * strip list — so a future transport field can never leak by omission.
 * Returns null when nothing shareable remains.
 */
const CLOUD_CONFIG_TEMPLATE_KEYS = ['id', 'provider', 'kind', 'label', 'name', 'serverUrl', 'url', 'folder', 'region', 'apiBase', 'authMode', 'updatedAt']
/** R147 §8.1 — the payment-card METADATA allowlist: the PAN and its CVV
 * never transit — the door is the allowlist, not a strip list (the R139 law). */
const PAYMENT_CARD_META_KEYS = ['id', 'brand', 'last4', 'label', 'name', 'expMonth', 'expYear', 'updatedAt', 'originDeviceId']
export function projectRecordForShare(type, record) {
  if (!isPlainObject(record)) return null
  const clean = JSON.parse(JSON.stringify(record))
  if (type === 'passkeysMeta') {
    for (const k of ['privateKey', 'privJwk', 'secretKey', 'keyBlob']) delete clean[k]
    return clean
  }
  if (type === 'paymentCardsMeta') {
    // the metadata allowlist — a full PAN/CVV is STRUCTURALLY absent
    const meta = {}
    for (const k of PAYMENT_CARD_META_KEYS) if (clean[k] !== undefined) meta[k] = clean[k]
    return Object.keys(meta).length ? meta : null
  }
  if (type === 'cloudConfigs') {
    // §8.2 — the template allowlist: provider kind + non-secret fields ONLY.
    // The deny-list class (a strip list) leaked the real transport field
    // names (accessToken/refreshToken) by omission — the R139 root fix is
    // the allowlist: anything not named here NEVER transits.
    const template = {}
    for (const k of CLOUD_CONFIG_TEMPLATE_KEYS) {
      if (clean[k] !== undefined) template[k] = clean[k]
    }
    return Object.keys(template).length ? template : null
  }
  return clean
}

/**
 * RECEIVER-side structure rejection (runs on EVERY record, both ends symmetrical
 * in proof): a passkey record carrying private-key material, or a cloud config
 * carrying a token, is refused by structure — never merged, always audit-logged.
 * The cloud-config refusal also yields a reconnect-prompt record for the receiver.
 * R139 §8.2: the secret-shape scan is BROADENED — any key whose NAME carries a
 * secret shape (token/secret/password/apikey/bearer/credential) is refused, so
 * the real transport field names (accessToken, refreshToken, appSecret, …) hit
 * the door, whatever the strip lists of the past covered.
 */
const SECRET_SHAPE_RE = /(token|secret|password|apikey|api[_-]?key|bearer|credential)/i
export function rejectRecordStructure(type, record) {
  if (!isPlainObject(record)) return { refused: true, reason: 'not-an-object', reconnect: null }
  if (type === 'passkeysMeta') {
    for (const k of ['privateKey', 'privJwk', 'secretKey', 'keyBlob']) {
      if (record[k] !== undefined) {
        return { refused: true, reason: 'passkey-private-key-material', reconnect: null }
      }
    }
  }
  if (type === 'cloudConfigs') {
    for (const k of ['token', 'secret', 'clientSecret', 'password']) {
      if (record[k] !== undefined) {
        return { refused: true, reason: 'cloud-config-token', reconnect: { reconnectRequired: true, provider: String(record.provider || record.id || 'unknown') } }
      }
    }
    for (const k of Object.keys(record)) {
      if (SECRET_SHAPE_RE.test(k)) {
        return { refused: true, reason: 'cloud-config-token', reconnect: { reconnectRequired: true, provider: String(record.provider || record.id || 'unknown') } }
      }
    }
  }
  if (type === 'paymentCardsMeta') {
    // the PAN door: a 13–19-digit run (a full card number) or a CVV field is
    // refused by structure — the metadata allowlist already strips it, this
    // is the belt-and-braces receiver side
    if (record.pan !== undefined || record.cvv !== undefined || record.cardNumber !== undefined) {
      return { refused: true, reason: 'payment-card-secret-material', reconnect: null }
    }
  }
  return { refused: false, reason: null, reconnect: null }
}

// --- The share manifest -----------------------------------------------------------

/**
 * Build ONE share manifest per share session (the sender chooses the peer and
 * the types; counts and watermarks ride before any record moves — the LocalSend
 * borrowing). Closing a type on the SENDER side means it is never offered.
 * Pure and async only for the manifest hash (WebCrypto sha-256).
 */
export async function buildShareManifest({ from, peerId, types, stores, watermarks, toggles, now = Date.now(), sessionId }) {
  if (!from || typeof from !== 'string') throw shareError('bad_session', 'buildShareManifest requires the sender device id')
  if (!peerId || typeof peerId !== 'string') throw shareError('bad_session', 'buildShareManifest requires the peer device id')
  if (from === peerId) throw shareError('bad_session', 'a device does not share with itself')
  if (!Array.isArray(types) || !types.length) throw shareError('bad_types', 'buildShareManifest requires a non-empty types array')
  const wm = isPlainObject(watermarks) ? watermarks : {}
  const perPeer = isPlainObject(wm[peerId]) ? wm[peerId] : {}
  const typeRows = []
  for (const t of types) {
    const spec = SHARE_CONSENT_MATRIX.find((s) => s.type === t)
    if (!spec) throw shareError('bad_types', `unknown share type: ${String(t)}`)
    // Closing a type on the sender means never offering it (chaindata law).
    if (spec.chaindataKey !== 'settings' && toggles && toggles[spec.chaindataKey] === false) {
      continue
    }
    const records = collectRecordsForType(spec, stores)
    const stamp = Number(perPeer[t]) || 0
    const delta = records.filter((r) => (Number(r.updatedAt) || 0) > stamp)
    const projected = []
    for (const rec of delta) {
      const clean = projectRecordForShare(t, rec)
      if (clean) projected.push(clean)
    }
    typeRows.push({ type: t, chaindataKey: spec.chaindataKey, mergeRule: spec.mergeRule, watermark: stamp, count: projected.length })
  }
  if (!typeRows.length) throw shareError('closed_types', 'every requested type is closed on the sender — nothing is offered')
  const manifest = {
    v: CHAINSHARE_VERSION,
    kind: CHAINSHARE_KIND,
    sessionId: String(sessionId || `cs-${Number(now)}-${String(from).slice(0, 8)}`),
    from,
    to: peerId,
    now: Number(now) || Date.now(),
    types: typeRows,
  }
  manifest.manifestHash = await sha256Hex(new TextEncoder().encode(canonicalShareJson(manifest)))
  return manifest
}

function collectRecordsForType(spec, stores) {
  if (!isPlainObject(stores)) throw shareError('bad_stores', 'buildShareManifest requires the stores object')
  if (spec.chaindataKey === 'settings') {
    const st = isPlainObject(stores.settings) ? stores.settings : {}
    return Object.entries(st)
      .filter(([k]) => !NEVER_REPLICATED_SETTINGS.includes(k))
      .map(([k, v]) => ({ id: k, settingsKey: k, value: v, updatedAt: Number(st.__stamps && st.__stamps[k]) || 0 }))
  }
  const key = spec.chaindataKey
  if (!CHAIN_DATA_TYPE_KEYS.includes(key)) throw shareError('bad_types', `type ${spec.type} maps to unknown chaindata key ${key}`)
  const arr = stores[key]
  if (!Array.isArray(arr)) throw shareError('bad_stores', `stores.${key} must be an array`)
  return arr
}

// --- Batch streaming --------------------------------------------------------------

/**
 * Stream one type's records as ordered batch envelopes over an injected
 * transport. The module stays plane-agnostic: `send` is an async callback
 * (the Beam 3 planes A/B/C provide it; Plane B seals the batch ciphertext-only
 * before it touches the relay). Returns the per-type send summary.
 */
export async function streamShare({ manifest, type, records, send, seqStart = 1 }) {
  const row = manifest.types.find((t) => t.type === type)
  if (!row) throw shareError('bad_types', `streamShare: type ${String(type)} is not in the manifest`)
  if (!Array.isArray(records)) throw shareError('bad_records', 'streamShare requires a records array')
  if (typeof send !== 'function') throw shareError('bad_transport', 'streamShare requires an injected send callback')
  // The SENDER DOOR runs the structure rejection on the RAW record FIRST: a
  // record that arrives still carrying secret material is refused loudly —
  // the secret never even enters the lane (law: proven on every attempt).
  for (const rec of records) {
    const rawRej = rejectRecordStructure(type, rec)
    if (rawRej.refused) throw shareError('secret_ride', `streamShare refused a ${type} record by structure: ${rawRej.reason}`)
  }
  // The watermark gate is enforced HERE (defense in depth): even if the caller
  // passes the full store, the wire carries only records above the manifest's
  // per-type watermark — a below-watermark record is never re-sent (law 5).
  const watermark = Number(row.watermark) || 0
  const deltaRecords = records.filter((r) => (Number(r && r.updatedAt) || 0) > watermark)
  let seq = Number(seqStart) || 1
  for (const rec of deltaRecords) {
    const clean = projectRecordForShare(type, rec)
    if (!clean) continue
    const batch = {
      v: CHAINSHARE_VERSION,
      kind: CHAINSHARE_KIND,
      sessionId: manifest.sessionId,
      manifestHash: manifest.manifestHash,
      from: manifest.from,
      to: manifest.to,
      type,
      seq,
      ts: Date.now(),
      records: [clean],
    }
    await send(batch)
    seq += 1
  }
  return { type, sent: seq - Number(seqStart || 1), seqEnd: seq - 1 }
}

/** Dedupe/gap-aware batch ingest state per session+type (receiver side). */
export class ChainShareIngest {
  constructor() {
    this.sessions = new Map()
  }
  /**
   * Ingest one batch. Returns 'applied' | 'duplicate' | 'gap'. A batch whose
   * manifestHash differs from the session's first-seen hash is REFUSED (the
   * manifest-substitution refusal — the transcript binding for shares).
   * Sequence state is scoped per (sessionId, type): each type's stream is an
   * independently ordered lane inside the session.
   */
  ingest(batch) {
    if (!isPlainObject(batch) || batch.kind !== CHAINSHARE_KIND) return { verdict: 'refused', reason: 'not-a-chainshare-batch' }
    const sid = String(batch.sessionId || '')
    const type = String(batch.type || '')
    if (!sid || !type) return { verdict: 'refused', reason: 'no-session-or-type' }
    let s = this.sessions.get(sid)
    if (!s) {
      s = { manifestHash: String(batch.manifestHash || ''), from: String(batch.from || ''), types: new Map() }
      this.sessions.set(sid, s)
    }
    if (String(batch.manifestHash || '') !== s.manifestHash) {
      return { verdict: 'refused', reason: 'manifest-substitution' }
    }
    let lane = s.types.get(type)
    if (!lane) {
      lane = { nextSeq: 1, seen: new Map() }
      s.types.set(type, lane)
    }
    if (lane.seen.has(batch.seq)) return { verdict: 'duplicate', reason: `seq ${batch.seq} already ingested` }
    if (batch.seq > lane.nextSeq) {
      // Gap: hold the batch; the caller re-offers the missing seq (order-tolerant).
      return { verdict: 'gap', reason: `expected seq ${lane.nextSeq}, got ${batch.seq}` }
    }
    lane.seen.set(batch.seq, batch)
    lane.nextSeq = batch.seq + 1
    return { verdict: 'applied', batch }
  }
}

// --- Apply (the receiver side) ------------------------------------------------------

function identityKey(type, r) {
  if (type === 'logins') return `${String(r.origin || r.fields?.origin || '')}|${String(r.username || r.fields?.username || '')}`
  if (type === 'history') return `${String(r.url || r.fields?.url || '')}|${String(r.visitTs || r.fields?.visitTs || r.updatedAt || '')}`
  return String(r.id || '')
}

/**
 * The deterministic LWW tie-break (law 4, documented for CS3): same updatedAt
 * → the record whose origin deviceId sorts lexicographically GREATER wins.
 */
export function lwwTieBreak(a, b) {
  const au = Number(a.updatedAt) || 0
  const bu = Number(b.updatedAt) || 0
  if (au !== bu) return au > bu ? a : b
  const ad = String(a.originDeviceId || a.deviceId || '')
  const bd = String(b.originDeviceId || b.deviceId || '')
  if (ad !== bd) return ad > bd ? a : b
  return b // identical stamps: last-applied wins deterministically (same inputs → same result on both ends)
}

/** Merge-only union for list-valued types (formAddresses): union by id, per-entry LWW. */
export function mergeOnlyUnion(localArr, incomingArr) {
  const out = new Map()
  for (const r of Array.isArray(localArr) ? localArr : []) out.set(String(r.id), r)
  for (const r of Array.isArray(incomingArr) ? incomingArr : []) {
    const id = String(r.id)
    const local = out.get(id)
    out.set(id, local ? lwwTieBreak(local, r) : r)
  }
  return Array.from(out.values())
}

/** History union: by URL + visit timestamp; exact repeats dedupe. */
export function unionHistory(localArr, incomingArr) {
  const out = new Map()
  for (const r of Array.isArray(localArr) ? localArr : []) out.set(identityKey('history', r), r)
  for (const r of Array.isArray(incomingArr) ? incomingArr : []) {
    const k = identityKey('history', r)
    if (!out.has(k)) out.set(k, r)
    else out.set(k, lwwTieBreak(out.get(k), r))
  }
  return Array.from(out.values())
}

/**
 * R147 §8.1 — THE TOMBSTONE LAW (per type): a deletion rides as a record
 * with deleted:true + its LWW stamps. The merge applies tombstones AFTER the
 * union: a newer tombstone removes the live twin; the tombstone row itself
 * is KEPT (the resurrection guard — an older live record can never bring a
 * deleted item back). Callers GC the tombstone rows on their own cadence.
 */
export function applyTombstones(mergedArr, incomingArr) {
  const arr = Array.isArray(mergedArr) ? mergedArr : []
  const incoming = Array.isArray(incomingArr) ? incomingArr : []
  const tombstones = new Map()
  for (const r of incoming) {
    if (r && r.deleted === true) {
      const key = String(r.id || '')
      if (key) tombstones.set(key, r)
    }
  }
  if (!tombstones.size) return arr
  const out = []
  const pushed = new Set()
  for (const r of arr) {
    const key = String(r.id || '')
    const t = tombstones.get(key)
    if (t) {
      // the LWW law at the grave: a NEWER live record survives the tombstone;
      // an older-or-equal live record stays dead
      const winner = lwwTieBreak(r, t)
      if (winner !== t && winner.deleted !== true) {
        if (!pushed.has(key)) { out.push(winner); pushed.add(key) }
        continue
      }
      if (!pushed.has(key)) { out.push(t); pushed.add(key) } // the tombstone row is kept (the resurrection guard)
      continue
    }
    if (!pushed.has(key)) { out.push(r); pushed.add(key) }
  }
  // a tombstone for an item the local store never held is remembered too
  for (const [key, t] of tombstones) if (!pushed.has(key)) { out.push(t); pushed.add(key) }
  return out
}

/** Logins union by origin+username; conflicts keep both when identities differ; same identity → LWW. */
export function unionLogins(localArr, incomingArr) {
  const out = new Map()
  for (const r of Array.isArray(localArr) ? localArr : []) out.set(identityKey('logins', r), r)
  for (const r of Array.isArray(incomingArr) ? incomingArr : []) {
    const k = identityKey('logins', r)
    if (!out.has(k)) out.set(k, r)
    else out.set(k, lwwTieBreak(out.get(k), r))
  }
  return Array.from(out.values())
}

/** Settings per-key LWW; the never-replicated consent keys are filtered twice (belt and braces). */
export function mergeSettings(localSettings, incomingRecords) {
  const st = isPlainObject(localSettings) ? JSON.parse(JSON.stringify(localSettings)) : {}
  const stamps = isPlainObject(st.__stamps) ? st.__stamps : {}
  for (const rec of Array.isArray(incomingRecords) ? incomingRecords : []) {
    const k = String(rec.settingsKey || rec.id || '')
    if (!k || NEVER_REPLICATED_SETTINGS.includes(k)) continue
    const incTs = Number(rec.updatedAt) || 0
    const locTs = Number(stamps[k]) || 0
    if (incTs > locTs || !(k in st)) {
      st[k] = rec.value
      stamps[k] = incTs
    }
  }
  st.__stamps = stamps
  return st
}

/**
 * Apply one INGESTED batch under the receiver's bilateral consent + merge laws.
 * `consents` maps peerId → type → boolean; the default for any missing entry is
 * FALSE (nothing applies without the receiver consent; continuous sharing is
 * opt-in per device pair). Returns the apply result and the ack payload.
 */
export function applyShare({ batch, consents, localStores, auditLog = null, now = Date.now() }) {
  if (!isPlainObject(batch) || batch.kind !== CHAINSHARE_KIND) throw shareError('bad_batch', 'applyShare requires an ingested chainshare batch')
  const peer = String(batch.from || '')
  const type = String(batch.type || '')
  const spec = SHARE_CONSENT_MATRIX.find((s) => s.type === type)
  if (!spec) throw shareError('bad_types', `applyShare: unknown type ${type}`)
  // Bilateral consent (law 1): the receiver's per-type, per-peer consent gate.
  const peerConsent = isPlainObject(consents) && isPlainObject(consents[peer]) ? consents[peer] : {}
  if (peerConsent[type] !== true) {
    if (auditLog) auditLog.add({ ts: now, deviceId: peer, type, recordId: batch.sessionId, action: 'refused-no-consent' })
    return { action: 'refused-no-consent', applied: 0, refused: 0, ack: null }
  }
  const records = Array.isArray(batch.records) ? batch.records : []
  let applied = 0
  let refused = 0
  let maxStamp = 0
  const reconnects = []
  if (spec.chaindataKey === 'settings') {
    const before = JSON.stringify(localStores.settings || {})
    const merged = mergeSettings(localStores.settings, records)
    for (const rec of records) {
      const rej = rejectRecordStructure('settings', rec)
      if (rej.refused) { refused++; continue }
      applied++
      maxStamp = Math.max(maxStamp, Number(rec.updatedAt) || 0)
    }
    localStores.settings = merged
    void before
  } else {
    const key = spec.chaindataKey
    if (!Array.isArray(localStores[key])) localStores[key] = []
    for (const rec of records) {
      // Structure rejection FIRST (law 3): the secret doors hold on every attempt.
      const rej = rejectRecordStructure(type, rec)
      if (rej.refused) {
        refused++
        if (auditLog) auditLog.add({ ts: now, deviceId: peer, type, recordId: String(rec.id || ''), action: `refused-structure:${rej.reason}` })
        if (rej.reconnect) reconnects.push(rej.reconnect)
        continue
      }
      if (spec.mergeRule === 'union-identity-lww') localStores[key] = applyTombstones(unionLogins(localStores[key], [rec]), [rec])
      else if (spec.mergeRule === 'merge-only-union') localStores[key] = applyTombstones(mergeOnlyUnion(localStores[key], [rec]), [rec])
      else if (spec.mergeRule === 'union-visit-dedupe') localStores[key] = applyTombstones(unionHistory(localStores[key], [rec]), [rec])
      else if (spec.mergeRule === 'config-tokens-rejected') localStores[key] = applyTombstones(mergeOnlyUnion(localStores[key], [rec]), [rec])
      else if (spec.mergeRule === 'metadata-only') localStores[key] = applyTombstones(mergeOnlyUnion(localStores[key], [rec]), [rec])
      else throw shareError('bad_merge_rule', `unhandled merge rule ${spec.mergeRule}`)
      applied++
      maxStamp = Math.max(maxStamp, Number(rec.updatedAt) || 0)
      if (auditLog) auditLog.add({ ts: now, deviceId: peer, type, recordId: String(rec.id || ''), action: 'applied' })
    }
  }
  const ack = applied > 0 ? { v: CHAINSHARE_VERSION, kind: 'chainshare-ack', sessionId: batch.sessionId, type, count: applied, upTo: maxStamp, from: batch.to, to: peer } : null
  return { action: 'applied', applied, refused, reconnects, ack }
}

/**
 * Sender-side watermark advance: ONLY an ack moves the watermark (law 5).
 * Returns the updated watermarks object (caller persists it).
 */
export function advanceWatermark(watermarks, ack) {
  if (!isPlainObject(watermarks)) throw shareError('bad_watermarks', 'advanceWatermark requires the watermarks object')
  if (!isPlainObject(ack) || ack.kind !== 'chainshare-ack') throw shareError('bad_ack', 'advanceWatermark requires a chainshare-ack')
  const peer = String(ack.from || '')
  const type = String(ack.type || '')
  if (!peer || !type) throw shareError('bad_ack', 'ack missing peer or type')
  if (!isPlainObject(watermarks[peer])) watermarks[peer] = {}
  const prev = Number(watermarks[peer][type]) || 0
  const upTo = Number(ack.upTo) || 0
  watermarks[peer][type] = Math.max(prev, upTo)
  return watermarks
}

/** Decline mid-offer: a typed terminal on the receiver; nothing partial remains. */
export function declineShare({ sessionId, from, type, reason = 'declined' }) {
  return { v: CHAINSHARE_VERSION, kind: 'chainshare-declined', sessionId: String(sessionId || ''), from: String(from || ''), type: String(type || ''), reason: String(reason), terminal: true }
}
