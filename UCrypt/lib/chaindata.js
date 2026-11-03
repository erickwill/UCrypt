/**
 * UCrypt — R135 §4 — CHAIN DATA TYPES (the Brave cherry-pick, native).
 * New in v2.92.0 (additions-only on the sealed v2.91.0 base).
 *
 * The owner's directive: adopt Brave Sync's principles natively, e2e
 * encrypted — "easy and simple, that just works." This module implements:
 *
 * 1. CHAIN DATA TYPES — seven toggleable types with owner-ordered defaults,
 *    each enforced at the ENGINE level: a type toggled OFF on a device
 *    neither SENDS nor RECEIVES updates for that type (Brave's semantics).
 *    It composes lib/chain-replicate.js (the sealed R133 engine): the
 *    replication classes map onto the owner's seven types; the toggles are
 *    the USER control surface the engine was missing.
 *
 * 2. MERGE SEMANTICS — per-field last-writer-wins with tombstones,
 *    collection membership merged additively, device-origin metadata in
 *    the audit log for every applied change, and tombstone revival refused
 *    STRUCTURALLY (a record deleted on one device must not resurrect from
 *    another device's queue).
 *
 * 3. VAULT-SYNC ENVELOPES — the additions-only record kind 'sync' on the
 *    Beam 2 lanes: the manifest travels INSIDE the sealed payload, nothing
 *    readable outside it, secrets never replicated (cloud configs replicate
 *    configuration only — each device re-authenticates itself).
 */

import { transferError } from './transfer/mailbox.js'

function terr(code, message) {
  return transferError(code, message)
}

/**
 * THE SEVEN CHAIN DATA TYPES (owner order §4, exact defaults):
 *  - logins: on (the core vault payload)
 *  - passkeysMeta: on (identifiers + metadata; PRIVATE KEY MATERIAL NEVER
 *    LEAVES THE DEVICE — enforced structurally below)
 *  - notes: on
 *  - addresses: on (form autofill addresses; payment card metadata is a
 *    separate, explicitly-consented OPTIONAL type)
 *  - paymentCardsMeta: off (explicit consent required)
 *  - history: off (privacy — opt-in per chain)
 *  - openTabs: off (opt-in per chain)
 *  - cloudConfigs: on (CONFIGURATION ONLY; secret tokens never replicated)
 */
export const CHAIN_DATA_TYPES = Object.freeze([
  { key: 'logins', defaultOn: true },
  { key: 'passkeysMeta', defaultOn: true },
  { key: 'notes', defaultOn: true },
  { key: 'addresses', defaultOn: true },
  { key: 'paymentCardsMeta', defaultOn: false },
  { key: 'history', defaultOn: false },
  { key: 'openTabs', defaultOn: false },
  { key: 'cloudConfigs', defaultOn: true },
])

export const CHAIN_DATA_TYPE_KEYS = CHAIN_DATA_TYPES.map((t) => t.key)

/** The owner-ordered defaults, as a plain map. */
export function defaultToggles() {
  const m = {}
  for (const t of CHAIN_DATA_TYPES) m[t.key] = t.defaultOn
  return m
}

/** Normalize any input (hostile, partial, wrong-typed) into the full map. */
export function normalizeToggles(input) {
  const src = input && typeof input === 'object' ? input : {}
  const out = defaultToggles()
  for (const t of CHAIN_DATA_TYPES) {
    if (typeof src[t.key] === 'boolean') out[t.key] = src[t.key]
  }
  return out
}

// --- Engine-level enforcement ---------------------------------------------------

/**
 * OUTBOUND gate: a type toggled OFF on this device is never SENT.
 * Returns the record when lawful, null when the type is toggled off.
 * ALSO structurally refuses private passkey material from ever entering
 * the replication path (the type replicates metadata only) and strips
 * secret-shaped fields from cloud configurations.
 */
export function enforceOutbound(type, record, toggles) {
  const map = normalizeToggles(toggles)
  if (!CHAIN_DATA_TYPE_KEYS.includes(String(type))) {
    throw terr('bad_kind', `Unknown chain data type: ${String(type)}`)
  }
  if (!map[type]) return null
  if (type === 'passkeysMeta' && record && typeof record === 'object') {
    // The structural refusal: private key material never leaves the device.
    if (record.privateKey || record.privJwk || record.secretKey || record.keyBlob) {
      throw terr('secret_ride', 'passkeysMeta replicates metadata only — private key material refused')
    }
  }
  if (type === 'cloudConfigs' && record && typeof record === 'object') {
    // Configuration only: any secret-shaped field is refused at the door.
    if (record.token || record.secret || record.clientSecret || record.password) {
      throw terr('secret_ride', 'cloudConfigs replicate configuration only — secret tokens refused')
    }
  }
  return record
}

/**
 * INBOUND gate: a type toggled OFF on this device is never APPLIED from a
 * peer's envelope. Returns 'apply' | 'skipped-toggle-off' | throws unknown.
 */
export function enforceInbound(type, toggles) {
  const map = normalizeToggles(toggles)
  if (!CHAIN_DATA_TYPE_KEYS.includes(String(type))) {
    throw terr('bad_kind', `Unknown chain data type: ${String(type)}`)
  }
  return map[type] ? 'apply' : 'skipped-toggle-off'
}

// --- Merge semantics -------------------------------------------------------------

/** One tombstone. A deleted record remembers who deleted it and when. */
export function tombstone(recordId, { deviceId, now = Date.now() } = {}) {
  return {
    id: String(recordId),
    deleted: true,
    deletedAt: Number(now) || Date.now(),
    deletedBy: String(deviceId || ''),
    updatedAt: Number(now) || Date.now(),
  }
}

/**
 * Per-field last-writer-wins merge of two record versions. Fields updated
 * more recently win; the tombstone ALWAYS wins over an older live version
 * and a deleted record can never be revived by an older remote copy
 * (structural refusal — the resurrection gate).
 */
export function mergeRecord(local, remote, { now = Date.now(), deviceId = '' } = {}) {
  if (!local || typeof local !== 'object' || !local.id) throw terr('bad_record', 'mergeRecord requires a local record with an id')
  if (!remote || typeof remote !== 'object' || remote.id !== local.id) throw terr('bad_record', 'mergeRecord requires a remote record with the SAME id')
  const audit = { ts: now, deviceId: String(deviceId || ''), recordId: String(local.id), action: 'applied' }

  // Tombstone revival refusal (structural, before any field compare).
  if (local.deleted && !remote.deleted) {
    const rAt = Number(remote.updatedAt) || 0
    const dAt = Number(local.deletedAt) || 0
    if (rAt <= dAt) {
      audit.action = 'refused-resurrection'
      return { merged: local, action: 'refused-resurrection', audit }
    }
    // A genuinely NEWER live edit after the deletion is honored (the owner
    // re-created the record on another device AFTER the delete).
  }

  // Deleted-vs-deleted or live-vs-live: per-field LWW by updatedAt.
  const lU = Number(local.updatedAt) || 0
  const rU = Number(remote.updatedAt) || 0
  if (remote.deleted && !local.deleted && rU > lU) {
    audit.action = 'applied'
    return { merged: { ...remote }, action: 'applied', audit }
  }
  if (rU > lU) {
    const mergedFields = {}
    const lf = local.fields && typeof local.fields === 'object' ? local.fields : {}
    const rf = remote.fields && typeof remote.fields === 'object' ? remote.fields : {}
    const stamps = (local.fieldStamps && typeof local.fieldStamps === 'object') ? local.fieldStamps : {}
    const rstamps = (remote.fieldStamps && typeof remote.fieldStamps === 'object') ? remote.fieldStamps : {}
    const keys = new Set([...Object.keys(lf), ...Object.keys(rf)])
    for (const k of keys) {
      const ls = Number(stamps[k]) || lU
      const rs = Number(rstamps[k]) || rU
      if (rs > ls) mergedFields[k] = rf[k]
      else if (k in lf) mergedFields[k] = lf[k]
      else mergedFields[k] = rf[k]
    }
    audit.action = 'applied'
    return {
      merged: { ...local, fields: mergedFields, updatedAt: Math.max(lU, rU), deleted: false },
      action: 'applied',
      audit,
    }
  }
  audit.action = 'kept-local'
  return { merged: local, action: 'kept-local', audit }
}

/**
 * Collection membership merge — ADDITIVE: the merged collection contains
 * the union of both sides' members (Brave's principle: toggles govern
 * types, membership never silently shrinks).
 */
export function mergeCollectionMembership(a, b) {
  const sa = Array.isArray(a) ? a.map(String) : []
  const sb = Array.isArray(b) ? b.map(String) : []
  return Array.from(new Set([...sa, ...sb])).sort()
}

/** The audit log appender (bounded — the last 200 entries are kept). */
export class ChainDataAuditLog {
  constructor(cap = 200) {
    this.cap = cap
    this.entries = []
  }
  add(entry) {
    if (!entry || typeof entry !== 'object') return false
    this.entries.push({
      ts: Number(entry.ts) || Date.now(),
      deviceId: String(entry.deviceId || ''),
      type: String(entry.type || ''),
      recordId: String(entry.recordId || ''),
      action: String(entry.action || ''),
    })
    while (this.entries.length > this.cap) this.entries.shift()
    return true
  }
}

// --- The vault-sync envelope (the Beam 2 record kind 'sync') ---------------------

/** The new record kind name (additions-only append to RECORD_KINDS). */
export const VAULT_SYNC_RECORD_KIND = 'sync'

/**
 * Build one vault-sync envelope BODY (the caller seals it via
 * sealForPeer(kind 'sync') — the manifest rides INSIDE the sealed payload;
 * nothing readable outside it). Pure.
 */
export function buildVaultSyncBody({ from, records, toggles, rev }) {
  if (!Array.isArray(records)) throw terr('bad_record', 'Vault-sync body requires a records array')
  const t = normalizeToggles(toggles)
  const manifest = records.map((r) => ({
    type: String((r && r.type) || ''),
    id: String((r && ((r.record && r.record.id) || r.id)) || ''),
    deleted: !!(r && (r.deleted || (r.record && r.record.deleted))),
  }))
  for (const m of manifest) {
    if (!CHAIN_DATA_TYPE_KEYS.includes(m.type)) {
      throw terr('bad_kind', `Vault-sync manifest carries an unknown type: ${m.type}`)
    }
    if (!t[m.type]) throw terr('toggle_off', `Vault-sync body includes type ${m.type} which is toggled OFF — the engine gate must run first`)
  }
  return {
    v: 1,
    kind: VAULT_SYNC_RECORD_KIND,
    from: String(from || ''),
    rev: Number.isInteger(rev) ? rev : 0,
    toggles: t,
    manifest,
    records: records.map((r) => ({ type: r.type, record: r.record !== undefined ? r.record : r })),
  }
}

/**
 * Apply one opened vault-sync body under the LOCAL toggles + merge laws.
 * Every applied change lands in the audit log with its device origin.
 */
export function applyVaultSyncBody(body, { localById, toggles, auditLog = null, deviceId = '', now = Date.now() } = {}) {
  if (!body || typeof body !== 'object' || body.kind !== VAULT_SYNC_RECORD_KIND) {
    throw terr('bad_record', 'applyVaultSyncBody requires an opened vault-sync body')
  }
  const results = []
  for (const entry of Array.isArray(body.records) ? body.records : []) {
    const type = String((entry && entry.type) || '')
    const gate = enforceInbound(type, toggles)
    const recId = String((entry && entry.record && entry.record.id) || '')
    if (gate !== 'apply') {
      results.push({ type, recordId: recId, action: gate })
      if (auditLog) auditLog.add({ ts: now, deviceId, type, recordId: recId, action: gate })
      continue
    }
    const rec = entry && entry.record
    const local = localById && localById.get(String(rec && rec.id))
    if (!local) {
      results.push({ type, recordId: String((rec && rec.id) || ''), action: 'created' })
      if (auditLog) auditLog.add({ ts: now, deviceId, type, recordId: (rec && rec.id) || '', action: 'created' })
      continue
    }
    const m = mergeRecord(local, rec, { now, deviceId })
    results.push({ type, recordId: String(local.id), action: m.action })
    if (auditLog) auditLog.add({ ts: now, deviceId, type, recordId: String(local.id), action: m.action })
  }
  return results
}
