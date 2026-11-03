/**
 * UCrypt — R141 §7.4/§7.6/§7.8 — THE MAILBOX PROTOCOL v1 (the clean room).
 *
 * The envelope contract for the ONE transfer road. Everything here is PURE:
 * no chrome.*, no fetch, no storage — the battery pins every rule and the
 * store/worker layers inject the world in. The design north (the contract):
 * sending a file must feel like email — address, attach, send, arrive.
 *
 *   protocolVersion 1 envelope:
 *   { protocolVersion, offerId, type, fromMemberId, fromName, toMemberId,
 *     verifyCode, fileName, size, sha256, chunkSize, chunkCount, createdAt,
 *     expiresAt }
 *
 * Laws this module owns:
 *   - TYPED REFUSALS: every hostile input is a typed error, never a throw-into-the-void
 *   - the verification code is FRESH PER TRANSFER, 6 digits, canonical "481 902",
 *     never reused within a session; the file hash is a FINGERPRINT the code
 *     auto-checks — a human never compares hashes (R141-F6's cure)
 *   - retention is in DAYS: 7-day offers, age not countdown (R141-F7's cure)
 *   - quota guard: max 20 pending offers / 200 MB per inbox; prune expired first
 *   - receipts are a state machine: written → accepted → verified | declined
 *     | expired — illegal transitions are typed refusals
 *   - the R142 Direct Share substrate rides the SAME typed road (VAULT_DELTA,
 *     FULL_SNAPSHOT, CLOUD_CONFIG_TEMPLATE — templates only, tokens never)
 *
 * PURE — battery-pinned (G91, tests/r141-mailbox.test.mjs).
 */

export const MAILBOX_PROTOCOL_VERSION = 1
export const MAILBOX_CHUNK_SIZE = 256 * 1024 // 256 KiB ciphertext chunks
export const MAILBOX_OFFER_TTL_DAYS = 7
export const MAILBOX_MAX_PENDING_OFFERS = 20
export const MAILBOX_MAX_INBOX_BYTES = 200 * 1024 * 1024 // 200 MB
export const MAILBOX_MAX_NAME_LENGTH = 240
export const MAILBOX_MAX_FILE_BYTES = 100 * 1024 * 1024 // the honest cap the page states

/** The typed envelope families. FILE is this round's journey; the three
 * Direct Share types are the R142 substrate (validators only this round). */
export const MAILBOX_ENVELOPE_TYPES = ['FILE', 'VAULT_DELTA', 'FULL_SNAPSHOT', 'CLOUD_CONFIG_TEMPLATE', 'BRIDGE']
export const MAILBOX_RECEIPT_TYPES = ['FILE'] // receipts exist only where payloads land this round

/** The typed protocol error. */
export function mailboxError(code, detail) {
  const e = new Error(`MAILBOX_${code}: ${detail}`)
  e.code = `MAILBOX_${code}`
  return e
}

/* ── The verification code (§7.6 — curing the hash-as-code class) ────────── */

/** Fresh 6 digits per transfer. The caller passes a session-seen Set; the
 * code is drawn until unused so no two offers in one session share a code. */
export function generateVerifyCode(seen = new Set(), rng = Math.random) {
  for (let i = 0; i < 64; i++) {
    const n = Math.floor(rng() * 1000000)
    const code = String(n).padStart(6, '0')
    if (!seen.has(code)) { seen.add(code); return code }
  }
  // 64 collisions is beyond improbable — a typed refusal keeps the law absolute
  throw mailboxError('CODE_SPACE', 'the session code space is exhausted')
}

/** The ONE canonical human format: "481 902" (3+3, one space). */
export function formatVerifyCode(code) {
  const c = String(code || '')
  if (!/^\d{6}$/.test(c)) throw mailboxError('CODE_SHAPE', 'the verification code must be exactly 6 digits')
  return `${c.slice(0, 3)} ${c.slice(3)}`
}

/** The codes match — the ONLY human comparison the flow ever asks for. */
export function verifyCodesMatch(a, b) {
  const norm = (s) => String(s || '').replace(/\s+/g, '')
  return /^\d{6}$/.test(norm(a)) && norm(a) === norm(b)
}

/* ── Chunk math (§7.3 — 256 KiB ciphertext chunks) ───────────────────────── */

export function chunkCountFor(size) {
  if (typeof size !== 'number') throw mailboxError('SIZE', `size must be a number (${typeof size} given)`)
  const n = Number(size)
  if (!Number.isInteger(n) || n < 1) throw mailboxError('SIZE', `size must be a positive integer (${n})`)
  if (n > MAILBOX_MAX_FILE_BYTES) throw mailboxError('SIZE_CAP', `file exceeds the honest cap (${MAILBOX_MAX_FILE_BYTES} bytes)`)
  return Math.ceil(n / MAILBOX_CHUNK_SIZE)
}

export function chunkIndexRange(size, index) {
  const count = chunkCountFor(size)
  if (!Number.isInteger(index) || index < 0 || index >= count) throw mailboxError('CHUNK_INDEX', `chunk ${index} outside 0..${count - 1}`)
  const start = index * MAILBOX_CHUNK_SIZE
  const end = Math.min(start + MAILBOX_CHUNK_SIZE, Number(size))
  return { start, end, bytes: end - start, isLast: index === count - 1 }
}

/* ── The envelope (§7.4) ─────────────────────────────────────────────────── */

const MEMBER_ID_RE = /^[0-9a-f]{32}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const OFFER_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function isMemberId(v) { return typeof v === 'string' && MEMBER_ID_RE.test(v) }

/** Random UUID v4 (the offerId). rng is injectable for the battery. */
export function newOfferId(rng = () => crypto.getRandomValues(new Uint8Array(16))) {
  const b = rng()
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

/** The name gate — the R136 fuzz classes at the new door. Returns {ok, code}. */
export function validateFileName(name) {
  const n = String(name ?? '')
  if (!n.length || !n.trim().length) return { ok: false, code: 'ERR_NAME_EMPTY' }
  if (n.length > MAILBOX_MAX_NAME_LENGTH) return { ok: false, code: 'ERR_NAME_TOO_LONG' }
  if (n.includes('/') || n.includes('\\')) return { ok: false, code: 'ERR_NAME_PATH' }
  if (n === '.' || n === '..') return { ok: false, code: 'ERR_NAME_PATH' }
  if (n.includes('\0')) return { ok: false, code: 'ERR_NAME_CONTROL' }
  for (const ch of n) {
    const c = ch.codePointAt(0)
    if (c < 32 || (c >= 0x200b && c <= 0x200f) || c === 0x202e) return { ok: false, code: 'ERR_NAME_CONTROL' }
  }
  return { ok: true, code: '' }
}

/**
 * Build a v1 FILE envelope. Refuses everything the wire cannot carry.
 * now/expiresAt are injectable for the battery (the 7-day retention law).
 */
export function buildFileEnvelope(input = {}) {
  const { fromMemberId, fromName, toMemberId, fileName, size, sha256, verifyCode, now = Date.now(), offerId } = input
  if (!isMemberId(fromMemberId)) throw mailboxError('FROM', 'fromMemberId is not a 32-hex member id')
  if (!isMemberId(toMemberId)) throw mailboxError('TO', 'toMemberId is not a 32-hex member id')
  if (fromMemberId === toMemberId) throw mailboxError('SELF', 'a device cannot mail itself')
  const name = String(fileName ?? '')
  const nameCheck = validateFileName(name)
  if (!nameCheck.ok) throw mailboxError('NAME', `the file name is refused (${nameCheck.code})`)
  if (typeof size !== 'number') throw mailboxError('SIZE', 'size must be a number on the wire')
  const n = Number(size)
  if (!Number.isInteger(n) || n < 1) throw mailboxError('SIZE', 'size must be a positive integer')
  if (n > MAILBOX_MAX_FILE_BYTES) throw mailboxError('SIZE_CAP', `file exceeds the honest cap (${MAILBOX_MAX_FILE_BYTES} bytes)`)
  if (!SHA256_RE.test(String(sha256 || ''))) throw mailboxError('SHA', 'sha256 must be a 64-hex fingerprint')
  if (!/^\d{6}$/.test(String(verifyCode || ''))) throw mailboxError('CODE', 'verifyCode must be 6 digits')
  if (typeof fromName !== 'string' || !fromName.trim() || /unnamed device/i.test(fromName)) {
    throw mailboxError('FROM_NAME', 'fromName is required — a device is never nameless')
  }
  const createdAt = Number(now)
  const expiresAt = createdAt + MAILBOX_OFFER_TTL_DAYS * 24 * 60 * 60 * 1000
  return {
    protocolVersion: MAILBOX_PROTOCOL_VERSION,
    offerId: offerId || newOfferId(),
    type: 'FILE',
    fromMemberId, fromName: fromName.slice(0, 60), toMemberId,
    verifyCode: String(verifyCode), fileName: name, size: n,
    sha256: String(sha256).toLowerCase(),
    chunkSize: MAILBOX_CHUNK_SIZE,
    chunkCount: chunkCountFor(n),
    createdAt, expiresAt,
  }
}

/** Parse + validate an envelope of any supported type. Typed refusals only. */
export function parseEnvelope(raw, { now = Date.now(), selfMemberId = null } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw mailboxError('SHAPE', 'the envelope is not an object')
  if (raw.protocolVersion !== MAILBOX_PROTOCOL_VERSION) {
    throw mailboxError('VERSION', `envelope protocol ${String(raw.protocolVersion)} is not v${MAILBOX_PROTOCOL_VERSION}`)
  }
  if (!MAILBOX_ENVELOPE_TYPES.includes(raw.type)) throw mailboxError('TYPE', `unknown envelope type ${String(raw.type)}`)
  if (!isMemberId(raw.fromMemberId)) throw mailboxError('FROM', 'the sender id is malformed')
  if (!isMemberId(raw.toMemberId)) throw mailboxError('TO', 'the recipient id is malformed')
  if (selfMemberId && raw.toMemberId !== selfMemberId) {
    throw mailboxError('WRONG_RECIPIENT', 'this offer is addressed to another device')
  }
  if (raw.fromMemberId === raw.toMemberId) throw mailboxError('SELF', 'a device cannot mail itself')
  if (typeof raw.fromName !== 'string' || !raw.fromName.trim()) throw mailboxError('FROM_NAME', 'the sender name is required')
  if (!OFFER_ID_RE.test(String(raw.offerId || ''))) throw mailboxError('OFFER_ID', 'the offerId is not a UUID v4')
  if (raw.type === 'FILE') {
    const nameCheck = validateFileName(raw.fileName)
    if (!nameCheck.ok) throw mailboxError('NAME', `the file name is refused (${nameCheck.code})`)
    const n = Number(raw.size)
    if (!Number.isInteger(n) || n < 1 || n > MAILBOX_MAX_FILE_BYTES) throw mailboxError('SIZE', 'the size is malformed')
    if (!SHA256_RE.test(String(raw.sha256 || ''))) throw mailboxError('SHA', 'the fingerprint is malformed')
    if (!/^\d{6}$/.test(String(raw.verifyCode || ''))) throw mailboxError('CODE', 'the verification code is malformed')
    if (!Number.isInteger(Number(raw.chunkCount)) || typeof raw.chunkCount !== 'number') throw mailboxError('CHUNK_COUNT', 'the chunk count must be a number on the wire')
    if (chunkCountFor(n) !== raw.chunkCount) throw mailboxError('CHUNK_COUNT', 'the chunk count disagrees with the size')
    if (typeof raw.chunkSize !== 'number' || raw.chunkSize !== MAILBOX_CHUNK_SIZE) throw mailboxError('CHUNK_SIZE', 'the chunk size is not the protocol chunk size')
  }
  const createdAt = raw.createdAt
  const expiresAt = raw.expiresAt
  if (typeof createdAt !== 'number' || typeof expiresAt !== 'number' || !Number.isFinite(createdAt) || !Number.isFinite(expiresAt) || expiresAt <= createdAt) {
    throw mailboxError('LIFE', 'the envelope lifetime is malformed')
  }
  if (isExpired({ expiresAt }, now)) throw mailboxError('EXPIRED', 'the offer has expired (retention is 7 days)')
  return raw
}

/* ── Retention (§7.8 — days, not minutes) ────────────────────────────────── */

export function isExpired(entry, now = Date.now()) {
  return Number(entry && entry.expiresAt) <= Number(now)
}

/** Human AGE — the sender's card shows how long an offer has waited, never a
 * countdown (R141-F7's cure: no transfer dies because the user stepped away). */
export function ageSentence(createdAt, now = Date.now()) {
  const s = Math.max(0, Math.floor((Number(now) - Number(createdAt)) / 1000))
  if (s < 90) return `waiting ${s}s`
  if (s < 90 * 60) return `waiting ${Math.round(s / 60)}m`
  if (s < 36 * 3600) return `waiting ${Math.round(s / 3600)}h`
  return `waiting ${Math.round(s / 86400)}d`
}

/** The inbox index — the manifest of waiting offers (small, cheap to poll). */
export function newIndex(memberId, now = Date.now()) {
  if (!isMemberId(memberId)) throw mailboxError('MEMBER', 'the inbox member id is malformed')
  return { v: 1, memberId, offers: [], lastPrunedAt: now, prunedCount: 0 }
}

/** Quota guard (§7.8): prune expired first, then refuse beyond the caps. */
export function quotaGuard(index, incomingSize = 0, now = Date.now()) {
  if (!index || !Array.isArray(index.offers)) throw mailboxError('INDEX', 'the inbox index is malformed')
  const kept = index.offers.filter((o) => !isExpired(o, now))
  const pruned = index.offers.length - kept.length
  const bytes = kept.reduce((acc, o) => acc + (Number(o.size) || 0), 0)
  if (kept.length >= MAILBOX_MAX_PENDING_OFFERS) throw mailboxError('QUOTA_OFFERS', `the inbox holds ${MAILBOX_MAX_PENDING_OFFERS} pending offers — the oldest must be collected or they expire`)
  if (bytes + Number(incomingSize) > MAILBOX_MAX_INBOX_BYTES) throw mailboxError('QUOTA_BYTES', 'the inbox is at its 200 MB guard — space frees when offers are collected or expire')
  return { offers: kept, pruned, bytes }
}

/** The prune order: expired first, then oldest (the poll prunes and records). */
export function pruneInbox(index, now = Date.now()) {
  if (!index || !Array.isArray(index.offers)) throw mailboxError('INDEX', 'the inbox index is malformed')
  const sorted = [...index.offers].sort((a, b) => Number(a.expiresAt) - Number(b.expiresAt))
  const kept = []
  let pruned = 0
  let bytes = 0
  for (const o of sorted) {
    const expired = isExpired(o, now)
    const overBytes = bytes + (Number(o.size) || 0) > MAILBOX_MAX_INBOX_BYTES
    const overCount = kept.length >= MAILBOX_MAX_PENDING_OFFERS
    if (expired || overBytes || overCount) { pruned++; continue }
    kept.push(o)
    bytes += Number(o.size) || 0
  }
  return { ...index, offers: kept, lastPrunedAt: now, prunedCount: (Number(index.prunedCount) || 0) + pruned }
}

/* ── Receipts (§7.5 — the sender's card updates from the RECEIVER's writes) ─ */

export const RECEIPT_STATES = ['written', 'accepted', 'verified', 'declined', 'expired']
const RECEIPT_EDGES = {
  written: ['accepted', 'declined', 'expired'],
  accepted: ['verified', 'expired'],
  verified: [],
  declined: [],
  expired: [],
}

export function newReceipt(offerId, fromMemberId, toMemberId, now = Date.now()) {
  if (!OFFER_ID_RE.test(String(offerId || ''))) throw mailboxError('OFFER_ID', 'the receipt offerId is malformed')
  return { v: 1, offerId, fromMemberId, toMemberId, state: 'written', at: now, history: [{ state: 'written', at: now }] }
}

export function transitionReceipt(receipt, to, now = Date.now()) {
  if (!receipt || !RECEIPT_STATES.includes(receipt.state)) throw mailboxError('RECEIPT_SHAPE', 'the receipt is malformed')
  if (!RECEIPT_STATES.includes(to)) throw mailboxError('RECEIPT_STATE', `unknown receipt state ${String(to)}`)
  if (!RECEIPT_EDGES[receipt.state].includes(to)) {
    throw mailboxError('RECEIPT_EDGE', `a ${receipt.state} receipt cannot become ${to}`)
  }
  return { ...receipt, state: to, at: now, history: [...receipt.history, { state: to, at: now }] }
}

/* ── The R142 Direct Share substrate (§7.11 — types + validators only) ───── */

/** The CLOUD_CONFIG_TEMPLATE ALLOWLIST — the §8.2 law: templates only, tokens
 * never. A template carrying any of these field names is REFUSED. */
export const CLOUD_CONFIG_FORBIDDEN_FIELDS = ['token', 'accessToken', 'refreshToken', 'password', 'secret', 'apiKey', 'clientSecret', 'pass']

export function validateDirectSharePayload(type, payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw mailboxError('SHARE_SHAPE', `the ${type} payload is not an object`)
  }
  if (type === 'VAULT_DELTA') {
    if (!Number.isInteger(payload.baseRev) || payload.baseRev < 0) throw mailboxError('SHARE_VAULT', 'VAULT_DELTA needs baseRev ≥ 0')
    if (!Array.isArray(payload.entries)) throw mailboxError('SHARE_VAULT', 'VAULT_DELTA needs an entries array')
    return true
  }
  if (type === 'FULL_SNAPSHOT') {
    if (!Number.isInteger(payload.rev) || payload.rev < 0) throw mailboxError('SHARE_SNAPSHOT', 'FULL_SNAPSHOT needs rev ≥ 0')
    if (!Array.isArray(payload.entries)) throw mailboxError('SHARE_SNAPSHOT', 'FULL_SNAPSHOT needs an entries array')
    return true
  }
  if (type === 'CLOUD_CONFIG_TEMPLATE') {
    for (const field of Object.keys(payload)) {
      if (CLOUD_CONFIG_FORBIDDEN_FIELDS.includes(field)) {
        throw mailboxError('SHARE_TOKEN', `a template may never carry "${field}" — tokens never ride the road (the ALLOWLIST law)`)
      }
    }
    if (typeof payload.transportId !== 'string' || !payload.transportId) throw mailboxError('SHARE_TEMPLATE', 'CLOUD_CONFIG_TEMPLATE needs a transportId')
    if (!payload.config || typeof payload.config !== 'object') throw mailboxError('SHARE_TEMPLATE', 'CLOUD_CONFIG_TEMPLATE needs a config object')
    for (const field of Object.keys(payload.config)) {
      if (CLOUD_CONFIG_FORBIDDEN_FIELDS.includes(field)) {
        throw mailboxError('SHARE_TOKEN', `the template config may never carry "${field}"`)
      }
    }
    return true
  }
  throw mailboxError('SHARE_TYPE', `unknown Direct Share type ${String(type)}`)
}

/** Tamper check — the fingerprint is AUTO-CHECKED at fetch (never user-compared). */
export function fingerprintMatches(expectedSha256, actualSha256) {
  return String(expectedSha256 || '').toLowerCase() === String(actualSha256 || '').toLowerCase()
}

/** The mailbox layout (§7.3) — the ONE address algebra: behind the SHARED chain
 * endpoint, so two profiles and two machines on one chain share one road. */
export const mailboxLayout = {
  inboxIndex: (memberId) => `ucrypt-mailbox-v1/inbox/${memberId}/index.json`,
  inboxOffer: (memberId, offerId) => `ucrypt-mailbox-v1/inbox/${memberId}/${offerId}/offer.json`,
  inboxChunk: (memberId, offerId, i) => `ucrypt-mailbox-v1/inbox/${memberId}/${offerId}/chunk-${String(i).padStart(6, '0')}.bin`,
  receipt: (senderMemberId, offerId) => `ucrypt-mailbox-v1/receipts/${senderMemberId}/${offerId}.json`,
  // R142 §5.2-b2(a) — the BRIDGE SIGNALS ride the same road: one index row per
  // session (swept on close or expiry), the envelopes beneath it.
  signalIndex: (memberId, sessionId) => `ucrypt-mailbox-v1/signals/${memberId}/${sessionId}/index.json`,
  signalObject: (memberId, sessionId, signalId) => `ucrypt-mailbox-v1/signals/${memberId}/${sessionId}/sig-${String(signalId).padStart(6, '0')}.json`,
  // R142 §5.2-b6 — presence rides the mailbox with the ≥ 15-minute TTL law:
  // each device stamps its OWN presence file on the poll cadence.
  presence: (memberId) => `ucrypt-mailbox-v1/presence/${memberId}.json`,
}
