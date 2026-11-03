/**
 * UCrypt — R112 §2 "Direct Share — the Handshake Is the Product" (D1–D10).
 *
 * THE PRODUCT: share ONE file (≤20 MB) with any UCrypt user — no chain, no
 * cloud, no account on either side — through any text messenger. The security
 * lives in the cryptography, never in the channel (D1).
 *
 * THE HANDSHAKE (D2–D4):
 *   invitation = 'UCRYPT-SHARE1:' + b64url(JSON{v,sid,t,epk,sdp,note?}) + '.' + 8 words
 *   reply      = 'UCRYPT-SHARE1R:' + b64url(JSON{v,sid,epk,sdp})
 *   session key = HKDF-SHA-256(salt 'ucrypt:share:v1',
 *                              info 'ucrypt:share:v1:session',
 *                              ikm  = ECDH(P-256, 256 bits) || utf8(shareCode))
 *   → AES-256-GCM, non-extractable — THE NINTH KEY in the hierarchy:
 *     ephemeral, one-time, destroyed on completion (D4).
 *   The messenger may read the whole invitation and the whole reply — it
 *   holds NEITHER ephemeral private key, so it cannot reach the ECDH secret;
 *   the share code alone (88 bits inside a 10-minute window) derives nothing
 *   without it (D4).
 *
 * THE SAFETY WORDS (D8): four BIP-39 words derived from HKDF(info
 * 'ucrypt:share:v1:safety', ikm = sha256(invitation ‖ '.' ‖ reply)).
 * Both screens show the same words; a modified reply ⇒ different transcript
 * ⇒ mismatch ⇒ typed refusal before any file moves.
 *
 * THE SEPARATION LAW (0.27 / D10): this module is cryptologically incapable
 * of becoming a chain relationship — it NEVER imports vault.js/sync.js, it
 * NEVER reads or writes vault, sync state, or the device identity, and the
 * share words die with the transfer. The only storage it touches is its own
 * bounded guard (rate-limit + one-time consumption — not a chain artifact).
 *
 * WIRE (D9): WebRTC data channel over free public STUN only — NAT discovery,
 * payload-blind, never a relay; NO TURN, ever. File frames ride the channel
 * as JSON strings sealed with the session key:
 *   { v:1, seq, iv:b64, ct:b64 } — AAD binds {protocol, version, shareId,
 *   chunkIndex, totalChunks, totalBytes, digest}; the nonce is deterministic
 *   (per-share HKDF prefix ‖ uint64be(index)) — the same discipline the
 *   transfer plane has carried since R79 (one schema, one builder).
 */

import { sha256, bytesToBase64, base64ToBytes } from './crypto.js'
import { bytesToBase64Url } from './transfer/core.js'
import { sanitizeFilename, executableOrArchiveWarning, chunkCountFor, CHUNK_SIZE, HARD_TRANSFER_CAP } from './transfer/session.js'
// R137 §10 — the INTERNAL chunk machinery Direct Share reuses (Beam 3's
// framing + bounded assembler, PURE modules only). Kept INVISIBLE by law:
// no Beam 3 name, state, storage key, or error code ever reaches a share
// surface — every Beam 3-domain error is translated below into the share
// domain's typed integrity refusal before it can escape.
import { BEAM3_CHUNK_SIZE } from './beam3/planes.js'
import { frameChunk as beam3FrameChunk, verifyFrame as beam3VerifyFrame, ChunkAssembler as Beam3ChunkAssembler, chunkCountFor as beam3ChunkCount } from './beam3/chunks.js'

// ── Pinned constants (0.15 — owner-attributed, measured, never changed unilaterally) ──
export const SHARE_PREFIX = 'UCRYPT-SHARE1:'
export const SHARE_REPLY_PREFIX = 'UCRYPT-SHARE1R:'
/** The Direct Share TTL = 10 minutes (0.15; aligned with the transfer plane's offer TTL). */
export const SHARE_TTL_MS = 10 * 60 * 1000
/** The file cap (D9): 20 MB — the transfer plane's default limit. */
export const SHARE_FILE_CAP = 20 * 1024 * 1024
/** The optional note's cap (D6) — one line. */
export const SHARE_NOTE_CAP = 200
/** The sender's optional display label cap (in-memory only; never a device identity). */
export const SHARE_LABEL_CAP = 40
/** Safety words: 4 × 11 bits (D8). */
export const SHARE_SAFETY_WORDS = 4
/** Share code: 8 × 11 bits = 88 bits (D2). */
export const SHARE_CODE_WORDS = 8
/** Data-channel protocol name (the share's own domain). */
export const SHARE_CHANNEL = 'ucrypt-share'
/** Ack window: chunks outstanding before the sender waits (backpressure, D9). */
export const SHARE_ACK_WINDOW = 8
/** Receiver guard: max Door-2 accepts per hour (D9 rate-limiting). */
export const SHARE_HOURLY_ACCEPTS = 10
/** Receiver guard: one-time consumption memory (replay-proof, D9). */
export const SHARE_CONSUMED_CAP = 50

// ── D12 — THE MULTI-FILE BATCH (R114, enters the law set) ────────────────
// ONE invitation, ONE handshake, ONE session key — a batch is still a SINGLE
// share session (the separation law 0.27 is untouched: one ephemeral
// identity, the words die with the whole batch, nothing touches a vault).
// The bounds (0.15-class, pinned by the R114 order, battery-pinned):
export const SHARE_BATCH_MAX = 5                    // at most 5 files per share
export const SHARE_SESSION_CAP = 50 * 1024 * 1024   // the session total ≤ 50 MB

// ── R137 §10 — DIRECT SHARE HARDENING (additive on the sealed base) ────────────

/** Human-scale expiry windows (the contract §10: an explicit expiry chosen
 * from human-scale windows; the sealed 10-minute default stands for
 * compatibility — new offers may choose a larger window explicitly). */
export const SHARE_TTL_WINDOWS = Object.freeze([
  { key: '10m', ms: 10 * 60 * 1000 },
  { key: '15m', ms: 15 * 60 * 1000 },
  { key: '1h', ms: 60 * 60 * 1000 },
  { key: '24h', ms: 24 * 60 * 60 * 1000 },
])
export const SHARE_TTL_MAX_MS = 24 * 60 * 60 * 1000

/** Bounded concurrent incoming offers per receiver (§10 abuse guard): offers
 * beyond the bound are refused with a truthful typed busy error, never
 * silently dropped. */
export const SHARE_INCOMING_OFFERS_CAP = 3
export function incomingOfferAllowed(activeCount) {
  const n = Number(activeCount)
  if (!Number.isFinite(n) || n < 0) return { ok: false, code: 'bad_count' }
  if (n >= SHARE_INCOMING_OFFERS_CAP) {
    return { ok: false, code: 'busy', why: `You already have ${n} incoming offers awaiting your answer.`, next: 'Accept or decline one of the open offers first — nothing was dropped.' }
  }
  return { ok: true }
}

/** The revoke token (§10): the sender can revoke an offer before acceptance;
 * the receiver learns it as a TYPED terminal (never silence). The token is a
 * signed-shaped record bound to the sid — parsing is local and total. */
export const SHARE_REVOKE_PREFIX = 'UCRYPT-SHARE1X:'
export function buildRevocation(sid) {
  if (typeof sid !== 'string' || !/^[0-9a-f]{32}$/.test(sid)) return { ok: false, code: 'malformed' }
  return { ok: true, token: SHARE_REVOKE_PREFIX + b64urlOfJson({ v: 1, sid, kind: 'revoked', t: Date.now() }) }
}
export function parseRevocation(text) {
  const raw = (typeof text === 'string' ? text : '').trim()
  if (!raw.startsWith(SHARE_REVOKE_PREFIX)) return { ok: false, code: 'not_revocation' }
  try {
    const payload = jsonOfB64url(raw.slice(SHARE_REVOKE_PREFIX.length))
    if (!payload || payload.v !== 1 || payload.kind !== 'revoked') return { ok: false, code: 'malformed' }
    if (typeof payload.sid !== 'string' || !/^[0-9a-f]{32}$/.test(payload.sid)) return { ok: false, code: 'malformed' }
    return { ok: true, sid: payload.sid, revokedAt: Number(payload.t) || 0, terminal: 'revoked' }
  } catch {
    return { ok: false, code: 'malformed' }
  }
}

/** The truthful surface distinction (§10 copy law — one sentence per concept;
 * the two features never confuse each other's wording or state). */
export const SHARE_SURFACE_COPY = Object.freeze({
  chain: 'Chain transfer moves files between the devices of your chain with the full trust of chain binding.',
  direct: 'Direct Share moves files to a specific UCrypt user with explicit consent on both ends.',
})
// The batch consent is ONE decision (Door 2 lists every file; Accept moves
// the whole batch, Decline refuses it whole — the silent decline still says
// nothing). Frames cross SEQUENTIALLY, file by file, every file sealed under
// the SAME session key with its own SHA-256 digest in the AAD; a batch is
// one session, one key, dying together.

const SHARE_GUARD_KEY = 'ucrypt:share:guard'
const SALT = 'ucrypt:share:v1'

// ── Small helpers ────────────────────────────────────────────────────────────────

const enc = (s) => new TextEncoder().encode(s)
const dec = (b) => new TextDecoder().decode(b)

function b64urlOfJson(obj) {
  return bytesToBase64Url(enc(JSON.stringify(obj)))
}

function jsonOfB64url(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 ? b64 + '='.repeat(4 - (b64.length % 4)) : b64
  return JSON.parse(dec(base64ToBytes(pad)))
}

async function randomBytes(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

async function randomHex(n) {
  return Array.from(await randomBytes(n)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function bip39Words() {
  const w = globalThis.CRYPTKEY_BIP39
  if (!Array.isArray(w) || w.length !== 2048) throw new Error('Direct Share: the wordlist is missing')
  return w
}

/** True when the string is a word from the pinned list (case-insensitive). */
function isWordlistWord(w) {
  return bip39Words().includes(String(w || '').toLowerCase())
}

/** 8 share words / 4 safety words — uniform, rejection-sampled 11-bit picks. */
function wordsFromBits(bits, count) {
  const list = bip39Words()
  const out = []
  for (let i = 0; i < count; i++) {
    let idx = 0
    for (let b = 0; b < 11; b++) idx = (idx << 1) | bits[i * 11 + b]
    out.push(list[idx])
  }
  return out
}

async function randomWords(count) {
  const bytes = await randomBytes(Math.ceil((count * 11) / 8))
  return wordsFromBits(bitsFromBytes(bytes), count)
}

/** Parse "word-word-…-word" against the pinned list; null when anything drifts. */
function parseWords(s, count) {
  const parts = String(s || '').trim().toLowerCase().split(/[-\s]+/).filter(Boolean)
  if (parts.length !== count) return null
  for (const p of parts) if (!isWordlistWord(p)) return null
  return parts
}

async function sha256Hex(bytes) {
  return Array.from(await sha256(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function hkdfBits(ikm, infoText, length) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc(SALT), info: enc(infoText) }, base, length
  ))
}

/** Bytes → the MSB-first bit array the wordlist indexer consumes. */
function bitsFromBytes(bytes) {
  const bits = []
  for (const byte of bytes) for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1)
  return bits
}

// ── The invitation / reply formats ───────────────────────────────────────────────

/**
 * Build the ONE pasteable invitation (D2): prefix + ephemeral public key +
 * ICE-bearing SDP + the 8-word share code — plus the OPTIONAL note (D6,
 * opt-in, the messenger will be able to read it) and the optional label
 * (rides the SEALED descriptor, never the visible string). The note is NOT
 * a secret and is not treated as one — the warning says exactly that.
 */
export async function createInvitation({ sdp, note = '', label = '', ttlMs = SHARE_TTL_MS }) {
  const words = await randomWords(SHARE_CODE_WORDS)
  const ttl = Number(ttlMs)
  // §10: the expiry is chosen from the human-scale windows — anything else is
  // refused typed (an unbounded or sub-minute offer is a hostile shape).
  if (!Number.isFinite(ttl) || ttl < 60 * 1000 || ttl > SHARE_TTL_MAX_MS) {
    throw new Error('share_ttl_window')
  }
  const payload = {
    v: 1,
    sid: await randomHex(16),
    t: Date.now(),
    epk: sdp.epk,
    sdp: sdp.sdp,
    exp: Date.now() + ttl,
  }
  const n = String(note || '').slice(0, SHARE_NOTE_CAP)
  if (n) payload.note = n
  return {
    shareCode: words.join('-'),
    words,
    sid: payload.sid,
    createdAt: payload.t,
    invitation: SHARE_PREFIX + b64urlOfJson(payload) + '.' + words.join('-'),
  }
}

/**
 * Parse + validate an invitation (the receiver's first touch). Every refusal
 * is typed (0.13): expired, replayed, malformed, or wrong version.
 */
export async function parseInvitation(text, { now = Date.now(), consumed = [] } = {}) {
  // R130 (FINDING R130-F1 — law 0.44): the async parsers are the WORSE crash
  // class — a throwing entry here escapes as an UNHANDLED REJECTION, not a
  // caught error. Same safe coercion as sync.parsePairingUri.
  const raw = (typeof text === 'string' ? text : text === null || text === undefined || typeof text !== 'object' ? String(text ?? '') : (() => { try { return String(text) } catch { return '' } })()).trim()
  if (!raw.startsWith(SHARE_PREFIX)) {
    return { ok: false, code: 'not_invitation' }
  }
  const rest = raw.slice(SHARE_PREFIX.length)
  const dot = rest.lastIndexOf('.')
  if (dot < 0) return { ok: false, code: 'malformed' }
  let payload
  try {
    payload = jsonOfB64url(rest.slice(0, dot))
  } catch {
    return { ok: false, code: 'malformed' }
  }
  const words = parseWords(rest.slice(dot + 1), SHARE_CODE_WORDS)
  if (!words) return { ok: false, code: 'bad_code' }
  if (!payload || payload.v !== 1) return { ok: false, code: 'version' }
  if (!payload.sid || typeof payload.sid !== 'string' || !/^[0-9a-f]{32}$/.test(payload.sid)) {
    return { ok: false, code: 'malformed' }
  }
  // §10: an explicit expiry (payload.exp) is authoritative when present — the
  // chosen human-scale window governs; the sealed 10-minute default governs
  // legacy offers that predate the windows (additive law, byte-compatible).
  if (Number.isFinite(Number(payload.exp))) {
    if (now > Number(payload.exp)) return { ok: false, code: 'expired' }
  } else if (!Number.isFinite(Number(payload.t)) || now - Number(payload.t) > SHARE_TTL_MS) {
    return { ok: false, code: 'expired' }
  }
  if (now < Number(payload.t) - 60 * 1000) return { ok: false, code: 'malformed' } // clock nonsense
  if (consumed.includes(payload.sid)) return { ok: false, code: 'replayed' }
  if (!payload.epk || !payload.sdp) return { ok: false, code: 'malformed' }
  return {
    ok: true,
    sid: payload.sid,
    createdAt: Number(payload.t),
    epk: payload.epk,
    sdp: String(payload.sdp),
    note: typeof payload.note === 'string' ? payload.note.slice(0, SHARE_NOTE_CAP) : '',
    words,
    shareCode: words.join('-'),
    expiresAt: Number.isFinite(Number(payload.exp)) ? Number(payload.exp) : Number(payload.t) + SHARE_TTL_MS,
    raw,
  }
}

/** Build the reply (D3): the receiver's ephemeral public key + the answer, bound to the invitation's sid. */
export async function createReply(sid, sdp) {
  const payload = { v: 1, sid: String(sid || ''), epk: sdp.epk, sdp: sdp.sdp }
  return SHARE_REPLY_PREFIX + b64urlOfJson(payload)
}

/** Parse + validate a reply (the sender's second touch). */
export async function parseReply(text, expectSid) {
  // R130 (FINDING R130-F1): the same entry-coercion law as parseInvitation —
  // a hostile object degrades to '' (the typed not_reply path), never throws.
  const raw = (typeof text === 'string' ? text : text === null || text === undefined || typeof text !== 'object' ? String(text ?? '') : (() => { try { return String(text) } catch { return '' } })()).trim()
  if (!raw.startsWith(SHARE_REPLY_PREFIX)) return { ok: false, code: 'not_reply' }
  let payload
  try {
    payload = jsonOfB64url(raw.slice(SHARE_REPLY_PREFIX.length))
  } catch {
    return { ok: false, code: 'malformed' }
  }
  if (!payload || payload.v !== 1) return { ok: false, code: 'version' }
  if (String(payload.sid || '') !== String(expectSid || '')) return { ok: false, code: 'foreign' }
  if (!payload.epk || !payload.sdp) return { ok: false, code: 'malformed' }
  return { ok: true, epk: payload.epk, sdp: String(payload.sdp) }
}

// ── Key agreement (D4) + safety words (D8) ──────────────────────────────────────

/** One ephemeral P-256 keypair per session. The private JWK lives only in memory. */
export async function generateShareKeys() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  return {
    crypto: pair,
    privJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
    pubJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
  }
}

/** THE NINTH KEY (D4): HKDF-SHA-256(ECDH ‖ share code) under the share's domain labels. */
export async function deriveSessionKey(myPrivJwk, peerPubJwk, shareCode) {
  const priv = await crypto.subtle.importKey('jwk', myPrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const pub = await crypto.subtle.importKey('jwk', peerPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: pub }, priv, 256))
  const ikm = new Uint8Array(shared.length + enc(String(shareCode || '')).length)
  ikm.set(shared, 0)
  ikm.set(enc(String(shareCode || '')), shared.length)
  const bits = await hkdfBits(ikm, 'ucrypt:share:v1:session', 256)
  const key = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonceBits = await hkdfBits(ikm, 'ucrypt:share:v1:nonce', 32)
  return { key, noncePrefix: nonceBits }
}

/** THE SAFETY WORDS (D8): 4 words over the handshake transcript. Both sides call
 * this with the FULL invitation string and the FULL reply string — same inputs,
 * same words. A modified reply code = different words = mismatch = typed refusal. */
export async function deriveSafetyWords(invitationText, replyText) {
  const transcript = await sha256(enc(String(invitationText || '') + '.' + String(replyText || '')))
  // HKDF needs a byte-aligned length — derive a whole byte ceil and slice the
  // 44 bits the four words consume.
  const bytes = await hkdfBits(transcript, 'ucrypt:share:v1:safety', Math.ceil((SHARE_SAFETY_WORDS * 11) / 8) * 8)
  return wordsFromBits(bitsFromBytes(bytes), SHARE_SAFETY_WORDS).join(' ')
}

// ── Sealed wire frames (the share's own schema — share-domain AAD, NO device ids) ──

function shareAad(f) {
  return enc(JSON.stringify({
    protocol: 'ucrypt-share',
    version: 1,
    shareId: String(f.shareId || ''),
    // D12: the file the chunk belongs to (0 for control frames and for the
    // single-file shape — both sides compute the SAME AAD or the frame dies).
    fileIndex: Number(f.fileIndex || 0),
    chunkIndex: Number(f.chunkIndex || 0),
    totalChunks: Number(f.totalChunks || 0),
    totalBytes: Number(f.totalBytes || 0),
    digest: String(f.digest || ''),
  }))
}

function shareNonce(noncePrefix, index) {
  const nonce = new Uint8Array(12)
  nonce.set(noncePrefix, 0)
  const bi = BigInt(Number(index) || 0)
  for (let i = 0; i < 8; i++) nonce[11 - i] = Number((bi >> BigInt(8 * i)) & 0xffn)
  return nonce
}

export async function sealShareFrame(key, meta, plainBytes) {
  const iv = shareNonce(meta.noncePrefix, meta.chunkIndex)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: shareAad(meta) }, key, plainBytes
  )
  // §10 chunk integrity: every frame carries the sha-256 of its PLAINTEXT —
  // the receiver verifies each chunk as it lands and the reassembly before
  // the completion card (a mismatch is a typed integrity terminal).
  const shaBytes = await crypto.subtle.digest('SHA-256', plainBytes)
  return { v: 1, seq: meta.chunkIndex, iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)), sha: bytesToBase64(new Uint8Array(shaBytes)) }
}

export async function openShareFrame(key, meta, frame) {
  if (!frame || frame.v !== 1) throw new Error('share_frame_version')
  if (Number(frame.seq) !== Number(meta.chunkIndex)) throw new Error('share_frame_seq')
  const iv = shareNonce(meta.noncePrefix, meta.chunkIndex)
  const given = base64ToBytes(String(frame.iv || ''))
  if (given.length !== iv.length || given.some((b, i) => b !== iv[i])) throw new Error('share_frame_nonce')
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: shareAad(meta) }, key, base64ToBytes(String(frame.ct || ''))
  )
  const out = new Uint8Array(plain)
  // §10: when the frame carries a plaintext sha (all R137 frames do), verify
  // it — a tampered or mis-assembled chunk is a typed integrity refusal.
  if (typeof frame.sha === 'string' && frame.sha.length > 0) {
    const shaBytes = await crypto.subtle.digest('SHA-256', out)
    const got = bytesToBase64(new Uint8Array(shaBytes))
    if (got !== frame.sha) throw new Error('share_frame_sha')
  }
  return out
}

// ── The receiver guard (D9: rate-limiting, per-sender backoff, replay-proof) ─────

export async function readShareGuard() {
  try {
    const g = (await chrome.storage.local.get(SHARE_GUARD_KEY))[SHARE_GUARD_KEY]
    return {
      accepted: Array.isArray(g && g.accepted) ? g.accepted : [],
      consumed: Array.isArray(g && g.consumed) ? g.consumed : [],
      senders: Array.isArray(g && g.senders) ? g.senders : [],
    }
  } catch {
    return { accepted: [], consumed: [], senders: [] }
  }
}

/** One-time consumption (D9 replay-proof): the sid can never open a second Door 1.
 * R130-F3: the read-modify-write is ONE serialized unit — a parallel replay
 * rush merges into the chain, the list never dupes, the cap holds. */
export function markConsumed(sid) {
  return _serializedGuard(async () => {
    const g = await readShareGuard()
    const consumed = [...g.consumed.filter((s) => s !== sid), String(sid)]
    while (consumed.length > SHARE_CONSUMED_CAP) consumed.shift()
    await chrome.storage.local.set({ [SHARE_GUARD_KEY]: { ...g, consumed } })
  })
}

/**
 * The Door-2 accept gate: hourly cap + per-sender backoff. `senderKey` is a
 * hash of the inviter's ephemeral PUBLIC key (an ephemeral identity, never a
 * device identity — the separation law holds).
 */
export async function acceptAllowed(senderKey, { now = Date.now() } = {}) {
  const g = await readShareGuard()
  const hourAgo = now - 60 * 60 * 1000
  const recent = g.accepted.filter((t) => Number(t) > hourAgo)
  if (recent.length >= SHARE_HOURLY_ACCEPTS) return { ok: false, code: 'hourly_cap' }
  const tenAgo = now - 10 * 60 * 1000
  const fromSame = g.senders.filter((s) => s.k === senderKey && Number(s.t) > tenAgo)
  if (fromSame.length >= 3) return { ok: false, code: 'sender_backoff' }
  return { ok: true }
}

export async function recordAccept(senderKey, { now = Date.now() } = {}) {
  const g = await readShareGuard()
  const accepted = [...g.accepted.filter((t) => Number(t) > now - 60 * 60 * 1000), now]
  const senders = [...g.senders.filter((s) => Number(s.t) > now - 10 * 60 * 1000), { k: String(senderKey || '').slice(0, 64), t: now }]
  while (senders.length > 100) senders.shift()
  await chrome.storage.local.set({ [SHARE_GUARD_KEY]: { ...g, accepted, senders } })
}

// ── R130 (FINDINGS R130-F2/F3 — the concurrency pass, law 0.44) ─────────────
// The guard's check-then-record (the Door-2 accept) and the replay memory's
// read-modify-write were two loose async steps: a parallel rush could
// interleave the reads and break the cap (the R114 ledger class, one layer
// up). Both are now SERIALIZED units on one in-module chain. The original
// exports stand unchanged (0.4 — nothing removed, nothing scoped down); the
// atomic door rides beside them and is the wired call site.
let _guardChain = Promise.resolve()
function _serializedGuard(fn) {
  const run = _guardChain.then(fn, fn)
  _guardChain = run.catch(() => {})
  return run
}

/** THE ATOMIC DOOR (R130-F2): check the guard and record the accept as ONE
 * serialized unit — a parallel rush of Door-2 accepts can no longer slip
 * past the hourly cap or the per-sender backoff. Same typed verdicts. */
export function acceptIfAllowed(senderKey, opts = {}) {
  return _serializedGuard(async () => {
    const verdict = await acceptAllowed(senderKey, opts)
    if (verdict && verdict.ok) await recordAccept(senderKey, opts)
    return verdict
  })
}

/** Stability for tests: a pure re-implementation of the guard's shape rules. */
export function pruneGuardShape(g, now = Date.now()) {
  return {
    accepted: (Array.isArray(g && g.accepted) ? g.accepted : []).filter((t) => Number(t) > now - 60 * 60 * 1000),
    consumed: (Array.isArray(g && g.consumed) ? g.consumed : []).slice(-SHARE_CONSUMED_CAP),
    senders: (Array.isArray(g && g.senders) ? g.senders : []).filter((s) => Number(s.t) > now - 10 * 60 * 1000),
  }
}

// ── The share ledger (D11 — R113: local-only, capped, identity-free, export-excluded) ──
//
// THE LAW (D11): the only history a Direct Share ever keeps. Entries ride the
// module's OWN storage key — never the vault, never the sync payload, never
// the chain state, never any export or backup (the 0.14 exclusion is pinned
// in the diagnostics gate). The frozen entry shape carries ONLY the file's
// name, size, the wall-clock time, and the direction — there is NO peer
// identity field because there is NO peer identity: the handshake was
// ephemeral by construction (0.27). The ring is capped at 30 (newest wins;
// the oldest fall off) — a history that never grows a profile.

/** The ledger's cap (0.15-attributed: the R113 order pins 30 entries). */
export const SHARE_LEDGER_CAP = 30

const SHARE_LEDGER_KEY = 'ucrypt:share:ledger'
const SHARE_LEDGER_ENTRY_KEYS = ['name', 'size', 'at', 'dir']
// R124 §2 (D13) — the pickup's entries ride the SAME frozen shape (the
// identity-free guarantee is untouched): 'held' = the sender's hold, 'pickedup'
// = the receiver's completed pickup. Additions-only; sent/received unchanged.
/** Exported for the battery (the additions-only proof). */
export const SHARE_LEDGER_DIRS = ['sent', 'received', 'held', 'pickedup']

/** Freeze ONE entry to the lawful shape: exactly { name, size, at, dir } —
 * anything else the caller passes (a label, a note, a peer key, an id) is
 * dropped HERE, so an identity field can never enter the ledger by accident. */
function ledgerEntry(entry) {
  const name = sanitizeFilename(String((entry && entry.name) || '')).slice(0, 200)
  const size = Number(entry && entry.size)
  const at = Number(entry && entry.at) || Date.now()
  const dir = SHARE_LEDGER_DIRS.includes(entry && entry.dir) ? entry.dir : null
  if (!name || !Number.isFinite(size) || size < 0 || !dir) return null
  return { name, size: Math.floor(size), at, dir }
}

// F-R114-LEDGER-RACE-1 (R114, P1 — found live by the 3-file batch): the
// append is a read-modify-write, and a BATCH fires several appends near-
// simultaneously (the sender's terminal appends one per file; the receiver's
// per-file gates append as each digest lands). Unsynchronized, every append
// read the SAME list and the last write won — 3 files, 1 ledger line. The
// appends now serialize through a page-local promise chain: each append's
// read starts only after the previous append's write resolved. Cross-context
// races (two pages at once) remain impossible by construction: only the
// options page ever appends, and one page runs one share at a time (the
// one-at-a-time queue law).
let _appendChain = Promise.resolve()

/** Append one entry (newest first); the cap drops the OLDEST. Refuses (and
 * drops) any entry that cannot be frozen to the lawful shape. */
export function shareLedgerAppend(entry) {
  const frozen = ledgerEntry(entry)
  if (!frozen) return Promise.resolve({ ok: false, code: 'invalid' })
  const run = _appendChain.then(async () => {
    const list = await shareLedgerList()
    const next = [frozen, ...list].slice(0, SHARE_LEDGER_CAP)
    await chrome.storage.local.set({ [SHARE_LEDGER_KEY]: next })
    return { ok: true, entry: frozen, kept: next.length }
  })
  // The chain never rejects (a failed append must not wedge the ledger) —
  // the failure is returned to THIS caller, the chain stays usable.
  _appendChain = run.then(() => undefined, () => undefined)
  return run
}

/** The ledger, newest first. Reads ONLY the ledger's own key. */
export async function shareLedgerList() {
  try {
    const g = (await chrome.storage.local.get(SHARE_LEDGER_KEY))[SHARE_LEDGER_KEY]
    if (!Array.isArray(g)) return []
    return g
      .map((e) => ledgerEntry(e))
      .filter(Boolean)
      .slice(0, SHARE_LEDGER_CAP)
  } catch {
    return []
  }
}

/** The frozen-shape law, exported for the battery: an entry can never carry
 * a key outside { name, size, at, dir } — the identity-free guarantee. */
export function shareLedgerShapeOk(entry) {
  if (!entry || typeof entry !== 'object') return false
  const keys = Object.keys(entry)
  return keys.length === SHARE_LEDGER_ENTRY_KEYS.length &&
    SHARE_LEDGER_ENTRY_KEYS.every((k) => keys.includes(k))
}

// ── The typed descriptor (D5, Door 2) ────────────────────────────────────────────

/** Build the sealed descriptor: label (typed by the sender, optional), name, size, digest. The note is NOT here — it rode the invitation (D6). */
export function buildDescriptor({ label, name, size, digest }) {
  return {
    kind: 'desc',
    label: String(label || '').slice(0, SHARE_LABEL_CAP),
    name: sanitizeFilename(name),
    size: Number(size) || 0,
    digest: String(digest || ''),
    mime: 'application/octet-stream', // a peer MIME is never trusted (the T6 treatment)
  }
}

export { sanitizeFilename, executableOrArchiveWarning, chunkCountFor, CHUNK_SIZE }

// ── D12 — the batch bounds (typed refusals BEFORE anything is created) ──────

/** Validate the sender's file selection against the D12 bounds. `files` is an
 * array of { name, size } — the raw pick, before any buffering. Every refusal
 * is typed (0.13) and fires BEFORE the invitation exists. */
export function validateBatch(files) {
  const list = Array.isArray(files) ? files : []
  if (!list.length) return { ok: false, code: 'empty' }
  if (list.length > SHARE_BATCH_MAX) {
    return { ok: false, code: 'too_many', have: list.length, max: SHARE_BATCH_MAX }
  }
  for (const f of list) {
    if (Number(f.size) > SHARE_FILE_CAP) {
      return { ok: false, code: 'file_too_big', name: String(f.name || ''), size: Number(f.size) }
    }
  }
  const total = list.reduce((a, f) => a + (Number(f.size) || 0), 0)
  if (total > SHARE_SESSION_CAP) {
    return { ok: false, code: 'session_too_big', total }
  }
  return { ok: true, count: list.length, total }
}

/** Build the sealed BATCH descriptor (D12, Door 2): every file's name, size
 * and digest, the honest total, and the per-file high-risk flag (a peer MIME
 * string is NEVER trusted — the T6 treatment — only the boolean the receiver
 * renders as the executable-or-archive warning). The count and the total ride
 * the descriptor so the receiver's Door 2 can state the WHOLE batch before
 * the ONE consent. */
export function buildBatchDescriptor({ label, files }) {
  const list = (Array.isArray(files) ? files : []).slice(0, SHARE_BATCH_MAX).map((f) => ({
    name: sanitizeFilename(f && f.name),
    size: Number(f && f.size) || 0,
    digest: String((f && f.digest) || ''),
    highRisk: !!(f && f.highRisk),
  }))
  return {
    kind: 'batch',
    label: String(label || '').slice(0, SHARE_LABEL_CAP),
    count: list.length,
    files: list,
    total: list.reduce((a, f) => a + f.size, 0),
  }
}

// ── The in-person QR (D3, first-class): the invitation in ordered frames ────

/** The per-frame payload cap — QR v15 at ECC M holds ~418 bytes; 300 keeps a
 * comfortable margin for the frame envelope. An invitation splits into ≤8
 * frames (a hard refusal beyond — the typed dead end names the fallback:
 * use the messenger paste). */
export const SHARE_QR_FRAME_CAP = 300
export const SHARE_QR_FRAME_MAX = 8

export function qrChunksOf(text) {
  const t = String(text || '')
  const parts = []
  for (let i = 0; i < t.length; i += SHARE_QR_FRAME_CAP) parts.push(t.slice(i, i + SHARE_QR_FRAME_CAP))
  if (parts.length > SHARE_QR_FRAME_MAX) return [] // the surface renders the typed fallback
  // The invitation text is pure ASCII (prefix + base64url + dash-joined
  // words), so the frames wrap it VERBATIM — no re-encoding inflation. Each
  // frame stays ≤ cap + 24 envelope chars, inside QR v15/M's ~418 bytes.
  const sid = String(t.length).padStart(6, '0')
  return parts.map((p, i) => `UCRYPT-SHAREQ1:${i + 1}/${parts.length}:${sid}:${p}`)
}

/** Reassemble scanned QR frames into the invitation text; typed refusals. */
export function qrJoinFrames(texts) {
  const list = (Array.isArray(texts) ? texts : []).filter(Boolean)
  if (!list.length) return { ok: false, code: 'none' }
  const parsed = []
  for (const t of list) {
    const m = /^UCRYPT-SHAREQ1:(\d+)\/(\d+):(\d{6}):([\s\S]*)$/.exec(String(t).trim())
    if (!m) return { ok: false, code: 'not_frame' }
    parsed.push({ idx: Number(m[1]), total: Number(m[2]), s: m[3], p: m[4] })
  }
  const total = parsed[0].total
  if (parsed.some((p) => p.total !== total)) return { ok: false, code: 'malformed' }
  if (total < 1 || total > SHARE_QR_FRAME_MAX) return { ok: false, code: 'malformed' }
  if (parsed.length !== total) return { ok: false, code: 'incomplete', have: parsed.length, total }
  if (new Set(parsed.map((p) => p.s)).size !== 1) return { ok: false, code: 'foreign' }
  const seen = new Set()
  for (const p of parsed) {
    if (p.idx < 1 || p.idx > total || seen.has(p.idx)) return { ok: false, code: 'malformed' }
    seen.add(p.idx)
  }
  parsed.sort((a, b) => a.idx - b.idx)
  return { ok: true, text: parsed.map((p) => p.p).join('') }
}

// ── WebRTC transport (D9: STUN for NAT discovery only, NEVER a TURN relay) ───────

/** Free public STUN — NAT discovery, payload-blind. No TURN is configured, ever. */
export const SHARE_ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }]

async function gatherIce(pc, capMs = 8000) {
  // R113 §2.5 (the soak's finding): the offer/answer SDPs are STATIC — the
  // only candidates a handshake will ever have are the ones sealed into
  // these strings. An under-sized gather cap truncated the candidate list
  // and the handshake died typed at both ends. 8 s waits for 'complete'
  // (usually ~100 ms on host candidates; the cap is a ceiling, not a wait).
  if (pc.iceGatheringState === 'complete') return
  await new Promise((resolve) => {
    const done = () => { try { pc.removeEventListener('icegatheringstatechange', onChange) } catch { /* noop */ } ; resolve() }
    const onChange = () => { if (pc.iceGatheringState === 'complete') done() }
    try { pc.addEventListener('icegatheringstatechange', onChange) } catch { /* noop */ }
    setTimeout(done, capMs)
  })
}

/** The sender's offer: an ephemeral PC + the data channel + gathered host/srflx candidates. */
export async function createOfferTransport() {
  const pc = new RTCPeerConnection({ iceServers: SHARE_ICE_SERVERS })
  const channel = pc.createDataChannel(SHARE_CHANNEL, { ordered: true })
  channel.binaryType = 'arraybuffer'
  const offer = await pc.createOffer()
  await pc.setLocalDescription(offer)
  await gatherIce(pc)
  return { pc, channel, sdp: pc.localDescription.sdp }
}

/** The receiver's answer: its own ephemeral PC bound to the invitation's offer. */
export async function createAnswerTransport(offerSdp) {
  const pc = new RTCPeerConnection({ iceServers: SHARE_ICE_SERVERS })
  pc.ondatachannel = () => { /* the channel arrives via the return value's promise below */ }
  await pc.setRemoteDescription({ type: 'offer', sdp: String(offerSdp || '') })
  const answer = await pc.createAnswer()
  await pc.setLocalDescription(answer)
  await gatherIce(pc)
  return { pc, sdp: pc.localDescription.sdp, channelPromise: new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('share_channel_timeout')), 30000)
    pc.ondatachannel = (e) => {
      if (!e.channel || e.channel.label !== SHARE_CHANNEL) return
      clearTimeout(t)
      e.channel.binaryType = 'arraybuffer'
      resolve(e.channel)
    }
  }) }
}

/** The sender binds the reply's answer. */
export async function acceptAnswer(pc, answerSdp) {
  await pc.setRemoteDescription({ type: 'answer', sdp: String(answerSdp || '') })
}

// ── Key destruction (D7/D10: the words die with the transfer) ────────────────────

/** Best-effort zeroization: the private JWK's secret fields are overwritten and
 * every reference dropped. Nothing was ever persisted — after this, neither
 * party can prove to a third party what was transferred, or that anything was. */
export function destroyKeys(session) {
  try {
    if (session && session.keys && session.keys.privJwk) {
      const jwk = session.keys.privJwk
      for (const f of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'x', 'y']) {
        if (typeof jwk[f] === 'string') {
          const zeros = new Uint8Array(jwk[f].length)
          jwk[f] = dec(zeros).slice(0, jwk[f].length)
        }
      }
    }
  } catch { /* best effort */ }
  try {
    if (session && session.sessionKey && session.sessionKey.key) {
      // Non-extractable AES keys die with the reference; drop it explicitly.
      session.sessionKey.key = null
      session.sessionKey.noncePrefix && session.sessionKey.noncePrefix.fill(0)
    }
  } catch { /* best effort */ }
  try {
    if (session && session.shareCodeWords) session.shareCodeWords.fill('')
  } catch { /* best effort */ }
}

// ═══════════════════════════════════════════════════════════════════════════
// ── R137 §10 — DIRECT SHARE HARDENING: THE OFFER MACHINERY ──────────────────
// ═══════════════════════════════════════════════════════════════════════════
//
// THE MIRROR, contract §10: Direct Share is the second transfer surface —
// files to any UCrypt user with NO chain membership required — hardened with
// the same clinical method as Beam 3. Everything in this section is ADDITIVE
// beside the R112 handshake (D1–D13): not one existing export, constant, or
// behavior above is changed (law 0.4).
//
// THE CONSENT-FIRST SEQUENCE (the RETAIN copy is pinned verbatim below):
//   the sender creates an offer (metadata only — names, sizes, digests; the
//   LocalSend borrowing) → the receiver sees a persistent card that never
//   auto-closes → NOTHING is received without the explicit Accept → received
//   files are NEVER opened automatically.
//
// LAWS THIS SECTION CARRIES (each battery-pinned in tests/r137-direct-share.test.mjs):
//   L1 CONSENT-FIRST — no bytes can move before the explicit Accept. The ONLY
//      receiver-side object that can accept a chunk is built on a receive
//      grant minted by acceptShareOffer alone, sealed with a module-private
//      Symbol no caller can forge. The offer envelope structurally carries no
//      bytes: byte-bearing fields a caller passes are dropped at creation.
//   L2 EXPIRY — the sender picks a human-scale window (15 min / 1 h / 24 h);
//      the default is ONE HOUR (never seconds). Expiry lands as a TYPED
//      terminal on BOTH ends, judged against an INJECTED `now` — never a
//      timer. Once the receiver Accepts, the consent window is closed: expiry
//      can no longer fire (the S3 law carried from Beam 3).
//   L3 REVOCATION — the sender can revoke before acceptance; the revocation
//      lands as a typed terminal on the receiver (REVOKED), never silence.
//      After acceptance a revoke still lands typed (INTERRUPTED) — never
//      silence on either side. The DECLINE stays SILENT at the wire (D7): no
//      decline signal exists in this module, and the sender's honest
//      knowledge remains the expiry.
//   L4 CHUNK INTEGRITY — every chunk carries its sha256 (the Beam 3 framing,
//      reused internally and kept invisible); the reassembly is hash-verified
//      against the offer's per-file digest BEFORE the completion card; a
//      mismatched chunk is refused and lands on the typed integrity terminal.
//      The ONLY machine path to COMPLETE runs the verified reassembly
//      (fireOfferEvent refuses an unverified CHUNKS_DONE).
//   L5 ABUSE GUARDS — a bounded number of concurrent incoming offers per
//      receiver (beyond the bound: a truthful typed BUSY refusal, never a
//      silent drop); a bounded offer size at the program's 100 MB transfer
//      budget (the owner-ordered HARD_TRANSFER_CAP number, reused verbatim —
//      the Beam 3 plane cap sits above it, so a Direct Share offer always
//      fits inside the Beam 3 budget too); and a refusal path for signals
//      that fail validation: malformed or pasted garbage lands typed, never
//      crashes.
//   L6 SURFACE TRUTH — the chain-transfer vs Direct Share distinction rides
//      as exported label constants the UI renders verbatim. The offer state
//      lives entirely in this module's share domain: no Beam 3 state keys,
//      no Beam 3 state names, no Beam 3 error codes on any share surface.
//   L7 NEVER-AUTO-CLOSE — no timer-driven exit anywhere in this state
//      machine: the card's only exits are the user's explicit Accept/Decline,
//      the sender's revoke signal, or the typed expiry judgment when the user
//      (or the UI's render loop) next asks. The two time-limited network
//      waits this module has always had are the transport seams (ICE gather
//      + the channel wait) — they resolve network promises and never touch
//      a card.

// ── L6: the two surfaces, stated truthfully (the UI renders these verbatim) ──

/** The chain-transfer surface, in one truthful sentence (contract §10). */
export const SHARE_SURFACE_CHAIN_LABEL = 'Chain transfer moves files between the devices of your chain, with the full trust of chain binding.'
/** The Direct Share surface, in one truthful sentence (contract §10). */
export const SHARE_SURFACE_DIRECT_LABEL = 'Direct Share moves files to a specific UCrypt user, with explicit consent on both ends.'
/** Both labels together, keyed for the surface row that renders one per concept. */
export const SHARE_SURFACE_LABELS = Object.freeze({ chain: SHARE_SURFACE_CHAIN_LABEL, direct: SHARE_SURFACE_DIRECT_LABEL })
/** THE RETAIN COPY (contract §10 → §3, pinned verbatim as a battery row). */
export const SHARE_RETAIN_COPY = 'Nothing is received without your explicit Accept. Received files are never opened automatically.'
/** The persistent-card promise (the never-auto-close law, in words). */
export const SHARE_CARD_PERSISTENCE_COPY = 'This card stays until you Accept or Decline, or the sender revokes — it never closes by itself.'
/** The completion card copy: verification first, reveal is the user's act. */
export const SHARE_COMPLETION_COPY = 'File verified. Reveal it in your downloads when you are ready — UCrypt never opens it for you.'

// ── L2: the human-scale expiry windows ──────────────────────────────────────

/** The offer envelope's schema version. */
export const SHARE_OFFER_VERSION = 1
/** The expiry windows (contract §10: human-scale; seconds are not offered). */
export const SHARE_OFFER_EXPIRY_WINDOWS = Object.freeze({
  m15: 15 * 60 * 1000,
  h1: 60 * 60 * 1000,
  h24: 24 * 60 * 60 * 1000,
})
/** The DEFAULT window: one hour — human-scale, never seconds. */
export const SHARE_OFFER_DEFAULT_WINDOW = 'h1'
export const SHARE_OFFER_DEFAULT_TTL_MS = SHARE_OFFER_EXPIRY_WINDOWS[SHARE_OFFER_DEFAULT_WINDOW]

// ── L5: the abuse-guard constants (0.15-class, pinned + battery-pinned) ─────

/** Bounded concurrent incoming offers per receiver; the bound-th is accepted,
 * bound+1 gets the truthful typed BUSY refusal (never a silent drop). */
export const SHARE_OFFER_INBOUND_BOUND = 3
/** The offer size cap — the program's 100 MB transfer budget, reused from the
 * owner-ordered HARD_TRANSFER_CAP (lib/transfer/session.js) so every surface
 * states the SAME number. The refusal fires AT the limit (the battery pins
 * limit-1 accepted / limit refused: the offer's own chunk framing must fit
 * inside the budget with it). Beam 3's plane cap (200 MiB) sits above this,
 * so a Direct Share offer always fits the Beam 3 budget too. */
export const SHARE_OFFER_MAX_BYTES = HARD_TRANSFER_CAP
/** The offer's file count rides the same bound as the D12 batch (5). */
export const SHARE_OFFER_MAX_FILES = SHARE_BATCH_MAX
/** Name length bound (aligned with the Beam 3 manifest law). */
export const SHARE_OFFER_MAX_NAME_LENGTH = 240
/** The offer's chunk frame size — the Beam 3 frame size, reused internally. */
export const SHARE_OFFER_CHUNK_SIZE = BEAM3_CHUNK_SIZE

// ── L1/L2/L3: the typed offer state machine (pure, timer-free) ──────────────

/** The card states. OFFERED is the persistent card; COMPLETE is the verified
 * success state (never a "terminal" — the user still acts from it). */
export const SHARE_OFFER_STATES = Object.freeze({
  OFFERED: 'OFFERED',
  ACCEPTED: 'ACCEPTED',
  RECEIVING: 'RECEIVING',
  COMPLETE: 'COMPLETE',
  DECLINED: 'DECLINED',
  REVOKED: 'REVOKED',
  EXPIRED: 'EXPIRED',
  BUSY_REFUSED: 'BUSY_REFUSED',
  OVERSIZED_REFUSED: 'OVERSIZED_REFUSED',
  INVALID_REFUSED: 'INVALID_REFUSED',
  INTEGRITY_FAILED: 'INTEGRITY_FAILED',
  INTERRUPTED: 'INTERRUPTED',
})

/** The eight typed terminals — every interrupt path lands on a named one. */
export const SHARE_OFFER_TERMINALS = Object.freeze({
  DECLINED: 'DECLINED',
  REVOKED: 'REVOKED',
  EXPIRED: 'EXPIRED',
  BUSY_REFUSED: 'BUSY_REFUSED',
  OVERSIZED_REFUSED: 'OVERSIZED_REFUSED',
  INVALID_REFUSED: 'INVALID_REFUSED',
  INTEGRITY_FAILED: 'INTEGRITY_FAILED',
  INTERRUPTED: 'INTERRUPTED',
})

/** The typed events. */
export const SHARE_OFFER_EVENTS = Object.freeze({
  ACCEPT: 'ACCEPT',
  DECLINE: 'DECLINE',
  REVOKE: 'REVOKE',
  EXPIRE: 'EXPIRE',
  REFUSE_BUSY: 'REFUSE_BUSY',
  REFUSE_SIZE: 'REFUSE_SIZE',
  REFUSE_INVALID: 'REFUSE_INVALID',
  BEGIN: 'BEGIN',
  CHUNKS_DONE: 'CHUNKS_DONE',
  INTEGRITY_FAIL: 'INTEGRITY_FAIL',
  NETWORK_FAIL: 'NETWORK_FAIL',
})

/** The transition table — every LEGAL edge (nothing else exists). */
export const SHARE_OFFER_TRANSITIONS = Object.freeze({
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.ACCEPT}`]: SHARE_OFFER_STATES.ACCEPTED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.DECLINE}`]: SHARE_OFFER_STATES.DECLINED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.REVOKE}`]: SHARE_OFFER_STATES.REVOKED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.EXPIRE}`]: SHARE_OFFER_STATES.EXPIRED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.REFUSE_BUSY}`]: SHARE_OFFER_STATES.BUSY_REFUSED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.REFUSE_SIZE}`]: SHARE_OFFER_STATES.OVERSIZED_REFUSED,
  [`${SHARE_OFFER_STATES.OFFERED}|${SHARE_OFFER_EVENTS.REFUSE_INVALID}`]: SHARE_OFFER_STATES.INVALID_REFUSED,
  [`${SHARE_OFFER_STATES.ACCEPTED}|${SHARE_OFFER_EVENTS.BEGIN}`]: SHARE_OFFER_STATES.RECEIVING,
  [`${SHARE_OFFER_STATES.ACCEPTED}|${SHARE_OFFER_EVENTS.REVOKE}`]: SHARE_OFFER_STATES.INTERRUPTED, // the sender stopped it — typed, never silence
  [`${SHARE_OFFER_STATES.ACCEPTED}|${SHARE_OFFER_EVENTS.NETWORK_FAIL}`]: SHARE_OFFER_STATES.INTERRUPTED,
  [`${SHARE_OFFER_STATES.ACCEPTED}|${SHARE_OFFER_EVENTS.INTEGRITY_FAIL}`]: SHARE_OFFER_STATES.INTEGRITY_FAILED,
  [`${SHARE_OFFER_STATES.RECEIVING}|${SHARE_OFFER_EVENTS.CHUNKS_DONE}`]: SHARE_OFFER_STATES.COMPLETE, // ONLY via the verified receipt (fireOfferEvent gate)
  [`${SHARE_OFFER_STATES.RECEIVING}|${SHARE_OFFER_EVENTS.REVOKE}`]: SHARE_OFFER_STATES.INTERRUPTED,
  [`${SHARE_OFFER_STATES.RECEIVING}|${SHARE_OFFER_EVENTS.NETWORK_FAIL}`]: SHARE_OFFER_STATES.INTERRUPTED,
  [`${SHARE_OFFER_STATES.RECEIVING}|${SHARE_OFFER_EVENTS.INTEGRITY_FAIL}`]: SHARE_OFFER_STATES.INTEGRITY_FAILED,
})

/** Every terminal carries its actionable next step (the UI renders it). */
export const SHARE_TERMINAL_NEXT = Object.freeze({
  DECLINED: 'You declined — nothing was received and nothing will be. Ask the sender for a new offer if you change your mind.',
  REVOKED: 'The sender revoked this offer — nothing was received. Ask the sender for a fresh offer if you still want the files.',
  EXPIRED: 'This offer expired before it was accepted — nothing was received. Ask the sender to share again with a fresh expiry window.',
  BUSY_REFUSED: 'You already have the maximum number of open offers — Accept or Decline one first, then ask the sender to resend.',
  OVERSIZED_REFUSED: 'This offer is over the 100 MB Direct Share limit — ask the sender to send fewer or smaller files.',
  INVALID_REFUSED: 'This offer is not a readable UCrypt Direct Share offer — ask the sender to copy and paste the whole offer again.',
  INTEGRITY_FAILED: 'A chunk failed its integrity check, so nothing was kept — ask the sender to resend the offer.',
  INTERRUPTED: 'The transfer stopped before it finished and nothing was kept — ask the sender for a fresh offer.',
})

/** The typed offer error (the share domain's own codes — never a Beam 3 code). */
function shareOfferError(code, detail) {
  const e = new Error(`SHARE_OFFER_${code}: ${detail}`)
  e.code = `SHARE_OFFER_${code}`
  return e
}

const SHARE_OFFER_OID_RE = /^[0-9a-f]{32}$/
const SHARE_OFFER_DIGEST_RE = /^[0-9a-f]{64}$/

/**
 * The offer name gate — the same refusal classes as the Beam 3 manifest law,
 * stated in the share domain: empty, too long, path traversal (both slash
 * directions, dot names, NUL), control characters, bidi/format characters.
 */
export function validateOfferFileName(name) {
  const n = typeof name === 'string' ? name : ''
  if (!n.length) return { ok: false, code: 'name_empty' }
  if (n.length > SHARE_OFFER_MAX_NAME_LENGTH) return { ok: false, code: 'name_too_long' }
  if (n.includes('/') || n.includes('\\') || n === '.' || n === '..' || n.includes('\0')) {
    return { ok: false, code: 'name_path' }
  }
  for (const ch of n) {
    const c = ch.codePointAt(0)
    if (c < 0x20 || c === 0x7f) return { ok: false, code: 'name_control' }
    if ((c >= 0x200b && c <= 0x200f) || c === 0x202e || (c >= 0x2066 && c <= 0x2069)) {
      return { ok: false, code: 'name_bidi' }
    }
  }
  return { ok: true, code: 'name_ok' }
}

/**
 * THE SENDER'S OFFER (the consent-first sequence, step 1). Files are
 * { name, size, digest } descriptors — the digest is the file's sha256 hex,
 * computed BEFORE the offer exists (L4's reassembly checks against it).
 * The envelope structurally carries NO bytes: any byte-bearing field the
 * caller passes is dropped here. Every refusal is typed and fires BEFORE the
 * offer exists (0.13); the size boundary is the battery-pinned one (limit-1
 * accepted, the limit refused).
 */
export async function createShareOffer({ files, note = '', label = '', window: windowKey = SHARE_OFFER_DEFAULT_WINDOW, now = Date.now() } = {}) {
  try {
    if (!Array.isArray(files) || !files.length) return { ok: false, code: 'empty' }
    if (files.length > SHARE_OFFER_MAX_FILES) {
      return { ok: false, code: 'too_many', have: files.length, max: SHARE_OFFER_MAX_FILES }
    }
    const ttl = SHARE_OFFER_EXPIRY_WINDOWS[windowKey]
    if (!Number.isFinite(ttl)) return { ok: false, code: 'bad_window' }
    const clean = []
    let total = 0
    for (const f of files) {
      const nc = validateOfferFileName(f && f.name)
      if (!nc.ok) return { ok: false, code: nc.code, name: String((f && f.name) || '').slice(0, 40) }
      // THE TYPEOF LAW (the R130-F1 class): '100' the string, 1.5 the float,
      // -1 and NaN are refused — a size is a non-negative safe integer NUMBER.
      if (typeof (f && f.size) !== 'number' || !Number.isInteger(f.size) || f.size < 0 || !Number.isSafeInteger(f.size)) {
        return { ok: false, code: 'bad_size', name: String((f && f.name) || '').slice(0, 40) }
      }
      if (!SHARE_OFFER_DIGEST_RE.test(String((f && f.digest) || ''))) {
        return { ok: false, code: 'bad_digest', name: String((f && f.name) || '').slice(0, 40) }
      }
      total += f.size
      if (total >= SHARE_OFFER_MAX_BYTES) {
        // the truthful limit refusal — fires AT the limit, names the number
        return { ok: false, code: 'offer_too_big', total, limit: SHARE_OFFER_MAX_BYTES }
      }
      clean.push({ name: f.name, size: f.size, digest: String(f.digest) })
    }
    const createdAt = Number(now) || Date.now()
    const offer = {
      kind: 'share-offer',
      v: SHARE_OFFER_VERSION,
      oid: await randomHex(16),
      files: clean,
      count: clean.length,
      totalBytes: total,
      createdAt,
      expiresAt: createdAt + ttl,
      window: windowKey,
    }
    // The note/label stay opt-in cosmetic fields (D6 discipline): capped, and
    // dropped when they are not strings — they never touch the consent facts.
    const n = typeof note === 'string' ? note.slice(0, SHARE_NOTE_CAP) : ''
    if (n) offer.note = n
    const l = typeof label === 'string' ? label.slice(0, SHARE_LABEL_CAP) : ''
    if (l) offer.label = l
    return { ok: true, offer, card: createOfferCard({ offer, role: 'sender', now: createdAt }) }
  } catch {
    return { ok: false, code: 'invalid' }
  }
}

/** The card: the persistent state object both ends hold. No timers ride it. */
export function createOfferCard({ offer, role = 'receiver', now = Date.now() } = {}) {
  if (!offer || typeof offer !== 'object') throw shareOfferError('BAD_OFFER', 'a card needs an offer')
  return {
    kind: 'share-offer-card',
    role: role === 'sender' ? 'sender' : 'receiver',
    oid: String(offer.oid || ''),
    offer,
    state: SHARE_OFFER_STATES.OFFERED,
    createdAt: Number(offer.createdAt) || Date.now(),
    expiresAt: Number(offer.expiresAt) || 0,
    openedAt: Number(now) || Date.now(),
  }
}

/** The pure edge. Throws the typed SHARE_OFFER_STATE_ILLEGAL on anything the
 * table does not name — an illegal edge is never silently absorbed. */
export function shareOfferStep(state, event) {
  const next = SHARE_OFFER_TRANSITIONS[`${state}|${event}`]
  if (!next) throw shareOfferError('STATE_ILLEGAL', `${event} in ${state}`)
  return next
}

export function isShareOfferTerminal(state) {
  return Object.values(SHARE_OFFER_TERMINALS).includes(state)
}

/** The pure expiry judgment (L2/L7): an INJECTED now against the window —
 * nothing schedules it, nothing fires it. The caller asks; the module types. */
export function offerExpiredAt(cardOrOffer, now = Date.now()) {
  const o = cardOrOffer && cardOrOffer.offer ? cardOrOffer.offer : cardOrOffer
  const exp = Number(o && o.expiresAt)
  if (!Number.isFinite(exp) || exp <= 0) return false
  return (Number(now) || Date.now()) >= exp
}

/**
 * The typed event driver — never throws, never silence. An Accept (or a
 * revoke) attempted on an expired open card is coerced to EXPIRE so the
 * truthful terminal lands. The CHUNKS_DONE edge carries the verification
 * receipt: without a digest the card's own offer lists, the completion is
 * refused — the machine cannot reach COMPLETE on unverified bytes (L4).
 */
export function fireOfferEvent(card, event, { now = Date.now(), verifiedDigest = '' } = {}) {
  if (!card || typeof card !== 'object' || !card.state) return { ok: false, code: 'bad_card' }
  let ev = event
  if (card.state === SHARE_OFFER_STATES.OFFERED && offerExpiredAt(card, now) &&
      (ev === SHARE_OFFER_EVENTS.ACCEPT || ev === SHARE_OFFER_EVENTS.REVOKE)) {
    ev = SHARE_OFFER_EVENTS.EXPIRE // the truthful terminal, not a late accept
  }
  if (ev === SHARE_OFFER_EVENTS.CHUNKS_DONE) {
    const verified = typeof verifiedDigest === 'string' && SHARE_OFFER_DIGEST_RE.test(verifiedDigest) &&
      card.offer && Array.isArray(card.offer.files) && card.offer.files.some((f) => f.digest === verifiedDigest)
    if (!verified) {
      return { ok: false, code: 'unverified_completion', from: card.state, event: ev }
    }
  }
  let next
  try {
    next = shareOfferStep(card.state, ev)
  } catch (e) {
    return { ok: false, code: e.code || 'SHARE_OFFER_STATE_ILLEGAL', from: card.state, event: ev }
  }
  card.state = next
  card.lastEvent = ev
  card.lastAt = Number(now) || Date.now()
  const out = { ok: true, state: next, event: ev, card }
  if (isShareOfferTerminal(next)) {
    out.terminal = next
    out.next = SHARE_TERMINAL_NEXT[next] || ''
  }
  return out
}

/** The lazy typed expiry (L7): the UI calls this when it renders or when the
 * user acts — an open card past its window lands EXPIRED; a card inside its
 * window (or past the open state) is returned unchanged. Nothing auto-runs. */
export function advanceShareOffer(card, { now = Date.now() } = {}) {
  if (!card || typeof card !== 'object' || !card.state) return { ok: false, code: 'bad_card' }
  if (card.state === SHARE_OFFER_STATES.OFFERED && offerExpiredAt(card, now)) {
    return fireOfferEvent(card, SHARE_OFFER_EVENTS.EXPIRE, { now })
  }
  return { ok: true, state: card.state, card }
}

// ── L1: the receive grant — the consent gate no caller can forge ────────────

/** Module-private: the assembler refuses any plan not sealed with THIS symbol. */
const RECEIVE_GRANT = Symbol('ucrypt:share:receive-grant')

/**
 * THE EXPLICIT ACCEPT (the consent-first sequence, step 2) — the ONLY door to
 * the receive grant. From OFFERED and inside the window: ACCEPTED, plus the
 * grant the assemblers require. Past the window: the typed EXPIRED terminal.
 * From any other state: the typed refusal (never silence, never auto-accept).
 */
export function acceptShareOffer(card, { now = Date.now() } = {}) {
  if (!card || typeof card !== 'object') return { ok: false, code: 'bad_card' }
  if (card.state !== SHARE_OFFER_STATES.OFFERED) {
    const t = isShareOfferTerminal(card.state) ? card.state : null
    return {
      ok: false,
      code: t === SHARE_OFFER_STATES.EXPIRED ? 'expired' : 'not_open',
      state: card.state,
      ...(t ? { terminal: t, next: SHARE_TERMINAL_NEXT[t] || '' } : {}),
    }
  }
  if (offerExpiredAt(card, now)) {
    // the truthful landing: the Accept did NOT happen, the card typed EXPIRED
    const out = fireOfferEvent(card, SHARE_OFFER_EVENTS.EXPIRE, { now })
    return {
      ok: false, code: 'expired', terminal: out.ok ? out.terminal : SHARE_OFFER_TERMINALS.EXPIRED,
      next: SHARE_TERMINAL_NEXT.EXPIRED, card,
    }
  }
  const at = Number(now) || Date.now()
  const out = fireOfferEvent(card, SHARE_OFFER_EVENTS.ACCEPT, { now: at })
  if (!out.ok) return out
  const grant = { grantToken: RECEIVE_GRANT, oid: card.oid, acceptedAt: at, offer: card.offer }
  return {
    ...out,
    grant,
    acceptSignal: { kind: 'share-offer-accept', v: SHARE_OFFER_VERSION, oid: card.oid, acceptedAt: at },
  }
}

/**
 * The receiver's Decline — a LOCAL typed terminal (the D7 law is carried to
 * the offer layer: NO decline signal exists in this module, the sender's only
 * honest knowledge is the expiry). From OFFERED only; elsewhere typed.
 */
export function declineShareOffer(card, { now = Date.now() } = {}) {
  if (!card || typeof card !== 'object') return { ok: false, code: 'bad_card' }
  if (card.state !== SHARE_OFFER_STATES.OFFERED) {
    return { ok: false, code: 'not_open', state: card.state }
  }
  return fireOfferEvent(card, SHARE_OFFER_EVENTS.DECLINE, { now })
}

/**
 * THE SENDER'S REVOKE (L3) — before acceptance. Produces the revoke signal
 * the UI carries to the peer; the peer's applyOfferSignal lands it typed.
 * Past the window the truthful EXPIRED terminal lands instead (the offer was
 * already dead — the revoke did not fire before the expiry).
 */
export function revokeShareOffer(card, { now = Date.now() } = {}) {
  if (!card || typeof card !== 'object') return { ok: false, code: 'bad_card' }
  if (card.role !== 'sender') return { ok: false, code: 'not_sender' }
  if (card.state !== SHARE_OFFER_STATES.OFFERED) {
    const t = isShareOfferTerminal(card.state) ? card.state : null
    return { ok: false, code: 'not_open', state: card.state, ...(t ? { terminal: t, next: SHARE_TERMINAL_NEXT[t] || '' } : {}) }
  }
  const at = Number(now) || Date.now()
  const out = fireOfferEvent(card, SHARE_OFFER_EVENTS.REVOKE, { now: at })
  // the signal rides ONLY when the revoke itself landed (a revoke past the
  // window was coerced to the truthful EXPIRED terminal — nothing to signal)
  if (out.ok && out.event === SHARE_OFFER_EVENTS.REVOKE) {
    out.revokeSignal = { kind: 'share-offer-revoke', v: SHARE_OFFER_VERSION, oid: card.oid, revokedAt: at }
  }
  return out
}

/** Shape-gate a peer signal (accept / revoke). Garbage degrades typed. */
function normalizeOfferSignal(signal) {
  let s = signal
  if (typeof s === 'string') {
    try { s = JSON.parse(s) } catch { return { ok: false, code: 'invalid_json' } }
  }
  if (!s || typeof s !== 'object' || Array.isArray(s)) return { ok: false, code: 'invalid_shape' }
  if (typeof s.kind !== 'string') return { ok: false, code: 'invalid_kind' }
  if (s.kind !== 'share-offer-accept' && s.kind !== 'share-offer-revoke') return { ok: false, code: 'unknown_kind' }
  if (s.v !== SHARE_OFFER_VERSION) return { ok: false, code: 'invalid_version' }
  if (typeof s.oid !== 'string' || !SHARE_OFFER_OID_RE.test(s.oid)) return { ok: false, code: 'invalid_oid' }
  return { ok: true, kind: s.kind === 'share-offer-accept' ? 'accept' : 'revoke', oid: s.oid }
}

/**
 * Apply a peer signal to a card — typed at every path, never silence:
 *   accept-signal → the sender's card OFFERED → ACCEPTED;
 *   revoke-signal → the receiver's OFFERED card → REVOKED; an already
 *   accepted/receiving card → INTERRUPTED (typed, never silence); a signal
 *   for another offer is foreign; garbage is invalid. Never throws.
 */
export function applyOfferSignal(signal, card, { now = Date.now() } = {}) {
  const sig = normalizeOfferSignal(signal)
  if (!sig.ok) return { ok: false, code: sig.code, terminal: SHARE_OFFER_TERMINALS.INVALID_REFUSED, next: SHARE_TERMINAL_NEXT.INVALID_REFUSED }
  if (!card || typeof card !== 'object' || !card.state) return { ok: false, code: 'bad_card' }
  if (String(card.oid) !== sig.oid) return { ok: false, code: 'foreign', state: card.state }
  if (sig.kind === 'accept') {
    if (card.role !== 'sender') return { ok: false, code: 'not_sender_card', state: card.state }
    return fireOfferEvent(card, SHARE_OFFER_EVENTS.ACCEPT, { now })
  }
  return fireOfferEvent(card, SHARE_OFFER_EVENTS.REVOKE, { now })
}

// ── L5: the receiver's offer gate (the hostile-signal front door) ───────────

function offerInvalidRefusal(code, extra = {}) {
  return {
    ok: false,
    code,
    terminal: SHARE_OFFER_TERMINALS.INVALID_REFUSED,
    next: SHARE_TERMINAL_NEXT.INVALID_REFUSED,
    ...extra,
  }
}

/**
 * THE RECEIVER'S GATE (the consent-first sequence, step 2's front door).
 * Accepts the offer envelope as an object or a pasted JSON string — pasted
 * garbage degrades TYPED (never throws, never crashes, never silence).
 * Order of truth: shape → expiry → size → bound → duplicate → the persistent
 * card. The bound counts only OPEN (OFFERED) cards — declined/expired cards
 * free their slot. The card it returns never auto-closes (L7).
 */
export function openIncomingOffer(signal, { now = Date.now(), openOffers = [], bound = SHARE_OFFER_INBOUND_BOUND } = {}) {
  try {
    let o = signal
    if (typeof o === 'string') {
      try { o = JSON.parse(o) } catch { return offerInvalidRefusal('invalid_json') }
    }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return offerInvalidRefusal('invalid_shape')
    if (o.kind !== 'share-offer') return offerInvalidRefusal('invalid_kind')
    if (o.v !== SHARE_OFFER_VERSION) return offerInvalidRefusal('invalid_version')
    if (typeof o.oid !== 'string' || !SHARE_OFFER_OID_RE.test(o.oid)) return offerInvalidRefusal('invalid_oid')
    if (!Array.isArray(o.files) || !o.files.length) return offerInvalidRefusal('invalid_files')
    if (o.files.length > SHARE_OFFER_MAX_FILES) return offerInvalidRefusal('too_many')
    if (typeof o.createdAt !== 'number' || !Number.isFinite(o.createdAt)) return offerInvalidRefusal('invalid_created')
    if (typeof o.expiresAt !== 'number' || !Number.isFinite(o.expiresAt) || o.expiresAt <= o.createdAt) return offerInvalidRefusal('invalid_expiry')
    if (SHARE_OFFER_EXPIRY_WINDOWS[o.window] === undefined) return offerInvalidRefusal('invalid_window')
    const at = Number(now) || Date.now()
    if (o.createdAt > at + 60 * 1000) return offerInvalidRefusal('clock_nonsense')
    let total = 0
    for (const f of o.files) {
      const nc = validateOfferFileName(f && f.name)
      if (!nc.ok) return offerInvalidRefusal(nc.code)
      // THE TYPEOF LAW at the hostile door: '100' the string never becomes a size.
      if (typeof (f && f.size) !== 'number' || !Number.isInteger(f.size) || f.size < 0 || !Number.isSafeInteger(f.size)) {
        return offerInvalidRefusal('invalid_size')
      }
      if (!SHARE_OFFER_DIGEST_RE.test(String((f && f.digest) || ''))) return offerInvalidRefusal('invalid_digest')
      total += f.size
    }
    if (typeof o.totalBytes !== 'number' || o.totalBytes !== total) return offerInvalidRefusal('invalid_total')
    if (o.count !== o.files.length) return offerInvalidRefusal('invalid_count')
    if (at >= o.expiresAt) {
      return { ok: false, code: 'expired', terminal: SHARE_OFFER_TERMINALS.EXPIRED, next: SHARE_TERMINAL_NEXT.EXPIRED }
    }
    if (total >= SHARE_OFFER_MAX_BYTES) {
      return {
        ok: false, code: 'offer_too_big', total, limit: SHARE_OFFER_MAX_BYTES,
        terminal: SHARE_OFFER_TERMINALS.OVERSIZED_REFUSED, next: SHARE_TERMINAL_NEXT.OVERSIZED_REFUSED,
      }
    }
    const open = Array.isArray(openOffers)
      ? openOffers.filter((c) => c && c.state === SHARE_OFFER_STATES.OFFERED)
      : []
    if (open.length >= (Number(bound) > 0 ? Number(bound) : SHARE_OFFER_INBOUND_BOUND)) {
      return {
        ok: false, code: 'busy', bound: Number(bound) > 0 ? Number(bound) : SHARE_OFFER_INBOUND_BOUND,
        terminal: SHARE_OFFER_TERMINALS.BUSY_REFUSED, next: SHARE_TERMINAL_NEXT.BUSY_REFUSED,
      }
    }
    const dup = open.find((c) => c && c.oid === o.oid)
    if (dup) return { ok: false, code: 'duplicate', existing: dup, next: 'This offer is already open — Accept or Decline it instead.' }
    const card = createOfferCard({ offer: o, role: 'receiver', now: at })
    return { ok: true, card, offer: o, state: SHARE_OFFER_STATES.OFFERED, retainCopy: SHARE_RETAIN_COPY, persistenceCopy: SHARE_CARD_PERSISTENCE_COPY }
  } catch {
    // the last-resort typed landing — the gate can never crash the surface
    return offerInvalidRefusal('invalid')
  }
}

// ── L4: the chunk framing (sender) + the verified reassembly (receiver) ─────

/**
 * Frame ONE file into sha256-stamped chunks (the Beam 3 framing, reused
 * internally and kept invisible). The file's whole sha256 rides back for the
 * offer descriptor — the reassembly later verifies against it.
 */
export async function offerFrameFile(bytes, { chunkSize = SHARE_OFFER_CHUNK_SIZE } = {}) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) return { ok: false, code: 'empty_file' }
  const total = beam3ChunkCount(bytes.length, chunkSize)
  const frames = []
  for (let i = 0; i < total; i++) frames.push(await beam3FrameChunk(bytes, i, total, chunkSize))
  return { ok: true, total, size: bytes.length, digest: await sha256Hex(bytes), frames }
}

/** The streaming path: frame one slice (the UI can loop this for big files). */
export async function offerFrameSlice(bytes, index, total, { chunkSize = SHARE_OFFER_CHUNK_SIZE } = {}) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) return { ok: false, code: 'empty_file' }
  const t = Number(total)
  if (!Number.isInteger(t) || t < 1) return { ok: false, code: 'bad_total' }
  try {
    return { ok: true, frame: await beam3FrameChunk(bytes, Number(index), t, chunkSize) }
  } catch {
    return { ok: false, code: 'bad_slice' }
  }
}

/** The offer's chunk count for a size (0 B → 0; 1 B → 1; exact → 1). */
export function offerChunkCount(size, chunkSize = SHARE_OFFER_CHUNK_SIZE) {
  return beam3ChunkCount(size, chunkSize)
}

/**
 * THE VERIFIED REASSEMBLER (L4). Constructible ONLY with the grant
 * acceptShareOffer minted (the module-private Symbol — unforgeable outside
 * this module: no Accept, no assembler, no bytes). The plan must name a file
 * EXACTLY as the accepted offer listed it — the consent covers exactly the
 * listed files, nothing can be smuggled past it. Every refusal is typed and
 * carries the integrity terminal; a Beam 3-domain error is translated here
 * so no Beam 3 code ever reaches a share surface (the invisibility law).
 */
export class ShareOfferAssembler {
  constructor(grant, fileRef) {
    if (!grant || grant.grantToken !== RECEIVE_GRANT || !grant.offer) {
      throw shareOfferError('CONSENT_REQUIRED', 'nothing is received without the explicit Accept grant')
    }
    const ref = fileRef && typeof fileRef === 'object' ? fileRef : {}
    const match = grant.offer.files.find((f) => f.name === ref.name && f.size === ref.size && f.digest === ref.digest)
    if (!match) throw shareOfferError('NOT_IN_OFFER', 'the file is not part of the accepted offer')
    this.grant = grant
    this.file = match
    this.integrityFailed = false
    this._asm = new Beam3ChunkAssembler({ totalChunks: beam3ChunkCount(match.size, SHARE_OFFER_CHUNK_SIZE), totalBytes: match.size })
  }

  /**
   * Accept one frame — the sha256 stamp is verified BEFORE the byte is kept.
   * Typed results only: { ok:true, ... } | { ok:false, terminal: INTEGRITY_FAILED, ... }.
   * Never throws.
   */
  async acceptFrame(frame) {
    const failed = () => ({ ok: false, code: 'integrity_failed', terminal: SHARE_OFFER_TERMINALS.INTEGRITY_FAILED, next: SHARE_TERMINAL_NEXT.INTEGRITY_FAILED })
    if (this.integrityFailed) return failed()
    let verified
    try {
      verified = await beam3VerifyFrame(frame, SHARE_OFFER_CHUNK_SIZE)
    } catch {
      this.integrityFailed = true
      const out = failed()
      out.reason = 'chunk_digest_or_shape'
      out.chunk = frame && Number.isFinite(Number(frame.i)) ? Number(frame.i) : null
      return out
    }
    const fresh = !this._asm.parts.has(verified.i)
    if (fresh && this._asm.receivedBytes + verified.data.length > this.file.size) {
      // the consented size is a ceiling — the sender cannot overrun it
      this.integrityFailed = true
      const out = failed()
      out.code = 'over_run'
      out.reason = 'the sender exceeded the consented size'
      return out
    }
    try {
      this._asm.accept(verified.i, verified.data)
    } catch {
      this.integrityFailed = true
      const out = failed()
      out.reason = 'chunk_refused'
      return out
    }
    return { ok: true, index: verified.i, receivedBytes: this._asm.receivedBytes, complete: this._asm.complete }
  }

  /**
   * THE REASSEMBLY HASH GATE — runs only when every chunk is present; the
   * assembled bytes are sha256-verified against the OFFER's digest BEFORE the
   * completion card may render. A mismatch is the typed integrity terminal.
   */
  async complete() {
    const failed = () => ({ ok: false, code: 'integrity_failed', terminal: SHARE_OFFER_TERMINALS.INTEGRITY_FAILED, next: SHARE_TERMINAL_NEXT.INTEGRITY_FAILED })
    if (this.integrityFailed) return failed()
    if (!this._asm.complete) {
      return { ok: false, code: 'incomplete', have: this._asm.parts.size, need: this._asm.totalChunks }
    }
    const bytes = this._asm.assemble()
    const digest = await sha256Hex(bytes)
    if (digest !== this.file.digest) {
      const out = failed()
      out.reason = 'assembly_digest_mismatch'
      return out
    }
    return { ok: true, name: this.file.name, size: this.file.size, bytes, digest, verified: true }
  }
}

/**
 * Drive one inbound chunk through the machine + assembler together: ACCEPTED
 * promotes to RECEIVING on the first chunk; an integrity refusal lands the
 * INTEGRITY_FAIL event so the typed terminal is reached. CHUNKS_DONE is NOT
 * fired here — the machine reaches COMPLETE only through finishOfferFile's
 * verified receipt (L4).
 */
export async function receiveOfferChunk(card, assembler, frame, { now = Date.now() } = {}) {
  if (!card || !assembler) return { ok: false, code: 'bad_args' }
  if (card.state === SHARE_OFFER_STATES.ACCEPTED) {
    const b = fireOfferEvent(card, SHARE_OFFER_EVENTS.BEGIN, { now })
    if (!b.ok) return b
  }
  if (card.state !== SHARE_OFFER_STATES.RECEIVING) {
    // typed, with the card's terminal when it stands on one — never silence
    const t = isShareOfferTerminal(card.state) ? card.state : null
    return { ok: false, code: 'not_receiving', state: card.state, ...(t ? { terminal: t, next: SHARE_TERMINAL_NEXT[t] || '' } : {}) }
  }
  const out = await assembler.acceptFrame(frame)
  if (!out.ok && out.terminal === SHARE_OFFER_TERMINALS.INTEGRITY_FAILED) {
    const f = fireOfferEvent(card, SHARE_OFFER_EVENTS.INTEGRITY_FAIL, { now })
    if (f.ok) out.state = card.state
  }
  return out
}

/**
 * Finish one file: the verified reassembly FIRST, the machine's CHUNKS_DONE
 * (carrying the verification receipt) only on ok — the completion card is
 * unreachable on unverified bytes. The completion copy promises exactly the
 * truth: reveal is the user's act, UCrypt never opens the file.
 */
export async function finishOfferFile(card, assembler, { now = Date.now() } = {}) {
  if (!card || !assembler) return { ok: false, code: 'bad_args' }
  if (card.state !== SHARE_OFFER_STATES.RECEIVING) {
    // typed, with the card's terminal when it stands on one — never silence
    const t = isShareOfferTerminal(card.state) ? card.state : null
    return { ok: false, code: 'not_receiving', state: card.state, ...(t ? { terminal: t, next: SHARE_TERMINAL_NEXT[t] || '' } : {}) }
  }
  const done = await assembler.complete()
  if (!done.ok) {
    if (done.terminal === SHARE_OFFER_TERMINALS.INTEGRITY_FAILED) {
      fireOfferEvent(card, SHARE_OFFER_EVENTS.INTEGRITY_FAIL, { now })
    }
    return done
  }
  const out = fireOfferEvent(card, SHARE_OFFER_EVENTS.CHUNKS_DONE, { now, verifiedDigest: done.digest })
  if (!out.ok) return out
  return {
    ok: true,
    state: card.state,
    name: done.name,
    size: done.size,
    digest: done.digest,
    verified: true,
    completionCopy: SHARE_COMPLETION_COPY,
  }
}
