/**
 * UCrypt — R153 §7 (S-2) — THE FULL-DATASET SHARE (the Brave-class merge).
 *
 * Once bound, any chain instance shares the COMPLETE vault dataset over ANY
 * road (direct or relay): the dataset export rides the existing file roads
 * (the transfer plane moves FILES; the dataset is one sealed file), and the
 * receiving side merges with the Brave-class policy:
 *   • newest-wins per item (the record's updatedAt decides, never arrival order)
 *   • per-item tombstones honored (a deletion travels and stays deleted)
 *   • conflicts become conflict COPIES — never a silent overwrite
 *   • every record is sha-verified on both ends (the envelope carries digests)
 *   • the merge SUMMARY (added / updated / conflicted counts) is shown to the
 *     user BEFORE it is committed
 *
 * S-3 typed honestly: browser-HISTORY sync is OUT OF SCOPE this round — it
 * requires the Web History permission class (restricted, store-risk, beyond a
 * password manager's least privilege). It is proposed for the CEO's explicit
 * R154 ruling, not smuggled in.
 *
 * PURE — no DOM, no chrome.*, no keys (the sealing of the dataset file stays
 * with the export/import machinery). Battery-pinned
 * (tests/r153-dataset-share.test.mjs — G122's round-trip rows).
 */

export const DATASET_SHARE_VERSION = 1
export const DATASET_KINDS = Object.freeze(['logins', 'identities', 'passkeys', 'notes', 'generator_config', 'cloud_provider_config'])

export function shareError(code, message) {
  const e = new Error(message)
  e.code = `DATASET_SHARE_${code}`
  return e
}

const sha256Hex = async (bytes) => {
  const buf = await crypto.subtle.digest('SHA-256', bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(String(bytes)))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Build the share envelope from the plaintext records (the caller seals the
 * WHOLE envelope as one file — the export/import machinery's law). Every
 * record's bytes are digested here so the receiving side verifies BEFORE any
 * merge touches its vault.
 * @param {{kind:string, id:string, updatedAt?:number, deleted?:boolean, data?:object}[]} records
 */
export async function buildDatasetEnvelope(records, { exportedAt = Date.now(), deviceId = 'unknown', name = '' } = {}) {
  const list = Array.isArray(records) ? records : []
  if (!list.length) throw shareError('EMPTY', 'nothing to share — the dataset is empty')
  for (const r of list) {
    if (!r || typeof r !== 'object') throw shareError('SHAPE', 'a record is malformed')
    if (!DATASET_KINDS.includes(r.kind)) throw shareError('KIND', `unknown record kind ${String(r.kind)}`)
    if (!r.id || typeof r.id !== 'string') throw shareError('SHAPE', 'a record needs a string id')
  }
  const sealed = []
  for (const r of list) {
    const bytes = new TextEncoder().encode(JSON.stringify(r.data ?? null))
    sealed.push({ kind: r.kind, id: r.id, updatedAt: Number(r.updatedAt || 0), deleted: !!r.deleted, digest: await sha256Hex(bytes), data: r.data ?? null })
  }
  return {
    v: DATASET_SHARE_VERSION,
    t: 'ucrypt-dataset-share',
    exportedAt,
    from: { deviceId: String(deviceId).slice(0, 80), name: String(name).slice(0, 80) },
    counts: { total: sealed.length, kinds: sealed.reduce((m, r) => { m[r.kind] = (m[r.kind] || 0) + 1; return m }, {}) },
    records: sealed,
  }
}

/** Verify every record's digest on the receiving side (BEFORE the merge). */
export async function verifyDatasetEnvelope(env) {
  if (!env || env.t !== 'ucrypt-dataset-share') throw shareError('TYPE', 'this is not a UCrypt dataset share')
  if (env.v !== DATASET_SHARE_VERSION) throw shareError('VERSION', 'the dataset share version is unknown')
  if (!Array.isArray(env.records) || !env.records.length) throw shareError('EMPTY', 'the dataset share carries no records')
  const bad = []
  for (const r of env.records) {
    const bytes = new TextEncoder().encode(JSON.stringify(r.data ?? null))
    if ((await sha256Hex(bytes)) !== r.digest) bad.push(`${r.kind}:${r.id}`)
  }
  if (bad.length) throw shareError('DIGEST', `the digest check failed for ${bad.length} record(s): ${bad.slice(0, 3).join(', ')}${bad.length > 3 ? '…' : ''}`)
  return true
}

/**
 * THE MERGE PLAN (shown to the user BEFORE it is committed):
 *   adds       — the incoming records this vault has never seen
 *   updates    — the incoming records that WIN (newer than the local twin)
 *   skipped    — the incoming records that LOSE (older than the local twin)
 *   conflicts  — same updatedAt, different content → the local row is kept
 *                as a conflict COPY (`<id>#conflict-<ts>`) and the incoming
 *                row takes the primary slot (never a silent overwrite, never
 *                a silent drop)
 *   tombstoned — the incoming deletions applied over live local rows
 */
export async function planDatasetMerge(localRecords, incomingRecords, { now = Date.now() } = {}) {
  const local = new Map()
  for (const r of Array.isArray(localRecords) ? localRecords : []) local.set(`${r.kind}:${r.id}`, r)
  const plan = { adds: [], updates: [], skipped: [], conflicts: [], tombstoned: [] }
  for (const inc of Array.isArray(incomingRecords) ? incomingRecords : []) {
    const key = `${inc.kind}:${inc.id}`
    const cur = local.get(key)
    if (inc.deleted) {
      if (cur && !cur.deleted) plan.tombstoned.push({ kind: inc.kind, id: inc.id })
      else if (!cur) plan.adds.push({ kind: inc.kind, id: inc.id, note: 'deletion for an unknown record — carried as a tombstone' })
      continue
    }
    if (!cur) { plan.adds.push({ kind: inc.kind, id: inc.id }); continue }
    const curT = Number(cur.updatedAt || 0)
    const incT = Number(inc.updatedAt || 0)
    if (incT > curT) plan.updates.push({ kind: inc.kind, id: inc.id, from: curT, to: incT })
    else if (incT < curT) plan.skipped.push({ kind: inc.kind, id: inc.id, localNewer: curT, incoming: incT })
    else {
      const same = JSON.stringify(cur.data ?? null) === JSON.stringify(inc.data ?? null)
      if (same) plan.skipped.push({ kind: inc.kind, id: inc.id, identical: true })
      else plan.conflicts.push({ kind: inc.kind, id: inc.id, conflictCopyId: `${inc.id}#conflict-${now}` })
    }
  }
  plan.summary = {
    added: plan.adds.length,
    updated: plan.updates.length,
    conflicted: plan.conflicts.length,
    tombstoned: plan.tombstoned.length,
    skipped: plan.skipped.length,
  }
  return plan
}

/**
 * Apply the plan (the commit step — called ONLY after the user has seen the
 * summary). Returns the merged dataset + the summary. Pure: the input arrays
 * are never mutated.
 */
export async function applyDatasetMerge(localRecords, incomingRecords, plan, { now = Date.now() } = {}) {
  if (!plan || !plan.summary) throw shareError('SHAPE', 'applyDatasetMerge needs the plan (the summary is shown first — the commit law)')
  const merged = (Array.isArray(localRecords) ? localRecords : []).map((r) => ({ ...r }))
  const byKey = new Map(merged.map((r) => [`${r.kind}:${r.id}`, r]))
  for (const inc of Array.isArray(incomingRecords) ? incomingRecords : []) {
    const key = `${inc.kind}:${inc.id}`
    const cur = byKey.get(key)
    if (inc.deleted) {
      if (cur) { cur.deleted = true; cur.updatedAt = Number(inc.updatedAt || now) }
      else merged.push({ ...inc, updatedAt: Number(inc.updatedAt || now) })
      continue
    }
    if (!cur) { merged.push({ ...inc }); byKey.set(key, merged[merged.length - 1]); continue }
    const incT = Number(inc.updatedAt || 0)
    const curT = Number(cur.updatedAt || 0)
    if (incT > curT) {
      cur.data = inc.data
      cur.updatedAt = incT
      cur.deleted = false
    } else if (incT === curT && JSON.stringify(cur.data ?? null) !== JSON.stringify(inc.data ?? null)) {
      // THE CONFLICT COPY: the local content is preserved under its own id —
      // nothing is silently overwritten, nothing silently dropped.
      const isCopy = String(cur.id || '').includes('#conflict-')
      if (!isCopy) merged.push({ ...cur, id: `${cur.id}#conflict-${now}`, updatedAt: now })
      cur.data = inc.data
      cur.updatedAt = incT
    }
  }
  return { merged, summary: plan.summary }
}
