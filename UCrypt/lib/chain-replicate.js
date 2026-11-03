/**
 * UCrypt — lib/chain-replicate.js (R133, §5.1 — THE BRAVE-GRADE SYNC)
 *
 * CHAIN FULL-DATA REPLICATION: "ALL DATA among members, direct,
 * most-recent wins" (the CEO's master directive). The pure, deterministic
 * engine the cloud lane (vault.js) and the direct lane (beamsync) both ride:
 *
 *   - DATA CLASSES (the replication envelope's whitelist):
 *       'logins'    — credentials (the vault's own lane; always)
 *       'forms'     — addresses + cards (OPT-IN — includeForms)
 *       'history'   — history items (OPT-IN, CAPPED, tombstoned — includeHistory)
 *       'config'    — transport configuration METADATA, the NON-SECRET parts
 *                     (provider id, envelope id, folder/bridge URLs, mode)
 *     NEVER RIDES (grep-gated on the sealed bytes, REPLIC-8):
 *       the 24-word code / the master passphrase / any OAuth token /
 *       any client secret / the bridge secret / any credential envelope.
 *       Each device authorizes its own cloud alone — secrets never ride.
 *
 *   - MERGE MODEL: per-record Lamport version stamp; MOST-RECENT-WINS with
 *     the device-id tiebreak (deterministic on every member); deletes are
 *     TOMBSTONES (a delete never resurrects from a lagging peer); every lost
 *     write lands in the CONFLICT LEDGER (visible to the user — never silent).
 *
 *   - PROPAGATION: the cloud envelope remains the mailbox (the record of
 *     truth); member-to-member point-to-point is the FAST LANE — when a
 *     rendezvous exists, synced members exchange deltas immediately and
 *     directly. The cloud bootstraps; the fast lane converges. buildDelta/
 *     applyDelta are lane-agnostic: both lanes carry the same delta shape.
 *
 * PURE MODULE — no browser-API anywhere; every function is deterministic and
 * battery-pinned (tests/r133-round.test.mjs REPLIC-1..8 + the G-lineage).
 */

// The never-rides set (REPLIC-8's grep gate reads THESE names on the sealed
// bytes — the engine refuses to carry them structurally, not just by polish).
export const NEVER_RIDE_KEYS = new Set([
  'mnemonic', 'words', 'syncCode', 'sync_code', 'masterKey', 'masterPassphrase',
  'refreshToken', 'clientSecret', 'accessToken', 'secret', 'bridgeSecret',
  'credentialKey',
  // R134 law 0.54 — the Beam 2 device key's private half NEVER rides the
  // replication envelope (the public key rides; the private key never
  // leaves the device — structural refusal, the engine throws):
  'devicePrivateKey', 'privateKey', 'signPriv', 'agrPriv', 'pkcs8',
])

// The data classes the engine knows (the whitelist).
export const REPLICATION_CLASSES = ['logins', 'forms', 'history', 'config']

// The history lane's default cap (items); a peer refusing the cap would
// balloon the envelope — the cap rides the class, not the caller's mood.
export const HISTORY_CAP_DEFAULT = 5000

// The conflict ledger's cap (surfaced rows — old resolutions fall off).
export const CONFLICT_LEDGER_CAP = 200

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

/** Structural refusal: a record carrying a never-ride key THROWS — the
 * engine cannot be coaxed into carrying secrets, even by a buggy caller.
 * R160 ARC C′ hardening (the array hole, found by the G164 battery): the
 * walk now descends into ARRAYS too — a class's record rows are arrays, so
 * `logins: [{clientSecret}]` used to ride the envelope unchecked. Arrays
 * are walked with index paths; the refusal is now structural at EVERY
 * nesting shape, matching the doc's promise ("even by a buggy caller"). */
export function assertNothingSecretRides(record) {
  const walk = (obj, path) => {
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) walk(obj[i], `${path}[${i}]`)
      return
    }
    if (!isPlainObject(obj)) return
    for (const [k, v] of Object.entries(obj)) {
      if (NEVER_RIDE_KEYS.has(k)) {
        throw new Error(`chain-replicate: refusing to carry a secret field (${path}.${k}) — secrets never ride the envelope`)
      }
      // R164 ARC C (R-164.4) — the member-SHAPE refusal: any key matching
      // /client_secret|private_key/i is refused by SHAPE, not by name —
      // the OAuth client JSON class (client_secret, client_secret_xxx,
      // private_key, private_key_id) can never ride the envelope in ANY
      // casing or suffix. The R160 array-descent stays intact below.
      if (/client_secret|private_key/i.test(k)) {
        throw new Error(`chain-replicate: refusing to carry a secret-shaped field (${path}.${k}) — the OAuth-client JSON class never rides (R-164.4)`)
      }
      if (isPlainObject(v) || Array.isArray(v)) walk(v, `${path}.${k}`)
    }
  }
  walk(record, 'record')
  return true
}

/** LAW — the replication envelope: ONLY whitelisted classes ride, opt-ins
 * honored, history capped, and the secret refusal runs on the result. */
export function replicationEnvelope(state, opts = {}) {
  if (!isPlainObject(state)) throw new Error('chain-replicate: state must be an object')
  // the loud refusal runs FIRST: a secret anywhere in the source config
  // throws (never silently dropped — silence would hide a caller bug).
  if (state.config) assertNothingSecretRides(state.config)
  const out = { v: 1, classes: [], lamport: Number(state.lamport) || 0, device: String(state.device || '') }
  const want = (cls) => (Array.isArray(opts.classes) ? opts.classes.includes(cls) : true)
  if (want('logins') && Array.isArray(state.logins)) {
    out.logins = state.logins.map((r) => (isPlainObject(r) ? { ...r } : r))
    out.classes.push('logins')
  }
  if (want('forms') && opts.includeForms && Array.isArray(state.forms)) {
    out.forms = state.forms.map((r) => (isPlainObject(r) ? { ...r } : r))
    out.classes.push('forms')
  }
  if (want('history') && opts.includeHistory && Array.isArray(state.history)) {
    out.history = capHistory(state.history, Number(opts.historyCap) || HISTORY_CAP_DEFAULT)
    out.classes.push('history')
  }
  if (want('config') && isPlainObject(state.config)) {
    // Only the NON-SECRET metadata keys ride config (the whitelist, not a
    // blacklist — an unknown config key stays device-local).
    const CONFIG_RIDE_KEYS = ['provider', 'envelopeId', 'folderUrl', 'bridgeUrl', 'authMode', 'setAt']
    const cfg = {}
    for (const k of CONFIG_RIDE_KEYS) {
      if (state.config[k] !== undefined) cfg[k] = state.config[k]
    }
    out.config = cfg
    out.classes.push('config')
  }
  assertNothingSecretRides(out)
  return out
}

/** The record's stable identity within a class (host+username for logins/
 * forms; the item id for history). */
export function recordKey(record, cls) {
  if (!isPlainObject(record)) return String(record ?? '')
  if (cls === 'history') return String(record.id || record.url || '')
  // a tombstone carries its key explicitly (the deleted record's fields are gone)
  if (record.__tombstone && record.key) return String(record.key)
  const host = String(record.domain || record.host || record.url || '').toLowerCase()
  const user = String(record.username || record.user || '').toLowerCase()
  return `${host}|${user}`
}

/** Stamp a record with the Lamport version ({__v: {lamport, device, at}}). */
export function stampRecord(record, device, lamport, at = Date.now()) {
  const out = { ...record }
  out.__v = { lamport: Number(lamport) || 0, device: String(device || ''), at: Number(at) || 0 }
  return out
}

/** MOST-RECENT-WINS: the higher lamport wins; the tie breaks on the device
 * id (lexicographic) — deterministic on every member, no clock needed. */
export function compareVersions(a, b) {
  const av = (a && a.__v && Number(a.__v.lamport)) || 0
  const bv = (b && b.__v && Number(b.__v.lamport)) || 0
  if (av !== bv) return av - bv
  const ad = String((a && a.__v && a.__v.device) || '')
  const bd = String((b && b.__v && b.__v.device) || '')
  if (ad !== bd) return ad < bd ? -1 : 1
  return 0
}

/** Merge ONE record pair. A tombstone always beats an older live record
 * (deletes never resurrect); equal versions keep local (no-op). Returns
 * { record, conflict } — conflict is non-null when the REMOTE lost a write. */
export function mergeRecord(local, remote, cls) {
  if (!remote) return { record: local, conflict: null }
  if (!local) return { record: remote, conflict: null }
  const cmp = compareVersions(local, remote)
  if (cmp > 0) {
    return {
      record: local,
      conflict: compareVersions(remote, local) < 0 && !(remote && remote.__tombstone) && !(local && local.__tombstone)
        ? { cls, key: recordKey(remote, cls), winner: 'local', loserDevice: (remote.__v && remote.__v.device) || '', lamport: (remote.__v && remote.__v.lamport) || 0 }
        : null,
    }
  }
  if (cmp < 0) {
    return {
      record: remote,
      conflict: !(local && local.__tombstone) && !(remote && remote.__tombstone)
        ? { cls, key: recordKey(local, cls), winner: 'remote', loserDevice: (local.__v && local.__v.device) || '', lamport: (local.__v && local.__v.lamport) || 0 }
        : null,
    }
  }
  return { record: local, conflict: null } // identical stamps — converged
}

/** TOMBSTONE a record: the delete marker rides the same merge rules. */
export function tombstoneRecord(record, device, lamport, at = Date.now()) {
  const out = stampRecord({ key: recordKey(record, 'logins') }, device, lamport, at)
  out.__tombstone = true
  return out
}

/** Merge a whole class. Tombstones prune their targets; every lost write
 * lands in the returned conflicts (the user-visible ledger's rows). */
export function mergeCollections(localArr, remoteArr, cls) {
  const locals = Array.isArray(localArr) ? localArr : []
  const remotes = Array.isArray(remoteArr) ? remoteArr : []
  const byKey = new Map()
  for (const r of locals) byKey.set(recordKey(r, cls), r)
  const conflicts = []
  let added = 0
  let updated = 0
  for (const r of remotes) {
    const key = recordKey(r, cls)
    const local = byKey.get(key)
    const { record, conflict } = mergeRecord(local, r, cls)
    if (conflict) conflicts.push(conflict)
    if (!local) {
      if (!record.__tombstone) {
        byKey.set(key, record)
        added++
      }
      // a remote tombstone for an unknown record: prune nothing, record nothing
    } else if (record !== local) {
      if (record.__tombstone) {
        byKey.delete(key) // the delete lands; the tombstone's work is done here
      } else {
        byKey.set(key, record)
      }
      updated++
    }
  }
  return { merged: Array.from(byKey.values()), conflicts, added, updated }
}

/** The Lamport clock: a member advances on every local mutation AND on every
 * merge that adopted a remote version (max(local, remote) + 1). */
export function lamportAdvance(current, observed) {
  const c = Number(current) || 0
  const o = Number(observed) || 0
  return Math.max(c, o) + (o > 0 ? 1 : 1)
}

/** Cap the history lane (oldest-dropped; the cap is the law, not a hint). */
export function capHistory(items, cap = HISTORY_CAP_DEFAULT) {
  const arr = Array.isArray(items) ? items : []
  const limit = Math.max(1, Number(cap) || HISTORY_CAP_DEFAULT)
  return arr.length <= limit ? arr : arr.slice(arr.length - limit)
}

/** THE DELTA (the fast lane's payload): the records where LOCAL is strictly
 * newer than what the peer last acknowledged (or the peer lacks entirely),
 * plus the tombstones. Lane-agnostic — the cloud mailbox and the direct
 * channel carry the SAME shape. */
export function buildDelta(state, peerWatermarks = {}, opts = {}) {
  const env = replicationEnvelope(state, opts)
  const delta = { v: 1, device: state.device || '', lamport: env.lamport, classes: [] }
  const watermark = (cls) => Number(peerWatermarks && peerWatermarks[cls]) || 0
  for (const cls of env.classes) {
    const arr = env[cls] || []
    const rows = []
    for (const r of arr) {
      const v = (r && r.__v && Number(r.__v.lamport)) || 0
      if (v > watermark(cls) || r.__tombstone) rows.push(r)
    }
    if (rows.length) {
      delta[cls] = rows
      delta.classes.push(cls)
    }
  }
  assertNothingSecretRides(delta)
  return delta
}

/** Apply a delta: merge per class, advance the clock, return the ledger
 * rows (the user-visible conflict ledger appends THESE). */
export function applyDelta(state, delta, opts = {}) {
  if (!isPlainObject(state)) throw new Error('chain-replicate: state must be an object')
  if (!isPlainObject(delta)) throw new Error('chain-replicate: delta must be an object')
  assertNothingSecretRides(delta)
  const out = { ...state }
  const conflicts = []
  const report = { applied: 0, added: 0, updated: 0, classes: [] }
  let maxLamport = Number(state.lamport) || 0
  for (const cls of REPLICATION_CLASSES) {
    const rows = delta[cls]
    if (!Array.isArray(rows)) continue
    const localArr = Array.isArray(state[cls]) ? state[cls] : []
    const { merged, conflicts: cs, added, updated } = mergeCollections(localArr, rows, cls)
    out[cls] = merged
    conflicts.push(...cs)
    report.applied += rows.length
    report.added += added
    report.updated += updated
    report.classes.push(cls)
    for (const r of rows) {
      const v = (r && r.__v && Number(r.__v.lamport)) || 0
      if (v > maxLamport) maxLamport = v
    }
  }
  out.lamport = lamportAdvance(maxLamport, maxLamport > (Number(state.lamport) || 0) ? maxLamport : 0)
  report.conflicts = conflicts
  return { state: out, report }
}

/** THE CONFLICT LEDGER (surfaced, capped — a lost write is never silent). */
export function appendConflictLedger(ledger, conflicts, cap = CONFLICT_LEDGER_CAP) {
  const list = Array.isArray(ledger) ? ledger.slice() : []
  const rows = Array.isArray(conflicts) ? conflicts : []
  for (const c of rows) {
    list.push({ ...c, at: Date.now() })
  }
  while (list.length > Math.max(1, Number(cap) || CONFLICT_LEDGER_CAP)) list.shift()
  return list
}

/** Deterministic convergence proof helper (the battery's REPLIC-2): merging
 * the same two states in BOTH orders must produce identical record sets. */
export function convergedSet(records) {
  return Array.from(records)
    .map((r) => recordKey(r, 'logins') + '@' + ((r && r.__v && r.__v.lamport) || 0))
    .sort()
    .join(',')
}
