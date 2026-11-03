/**
 * UCrypt — R76 Part E "Secure Direct Device Transfer" — TRANSFER SESSION
 * (state-machine constants, filename hygiene, chunk protocol). New in v2.42.14.
 *
 * First-release limits are HARD product rules from the owner order:
 *   - default transfer limit 20 MB; hard cap 100 MB
 *   - 16 KiB AES-GCM chunks with transfer/chunk-bound AAD
 *   - the receiver ALWAYS explicitly accepts; never auto-open, never
 *     auto-execute, never auto-resume after restart
 * The worker (lib/transfer/worker.js) owns the key material; these helpers are
 * pure or trivially parameterized so they stay honest and testable.
 */

import { sha256, bytesToBase64, base64ToBytes } from '../crypto.js'
import { buildChunkAad, chunkNonce, TRANSFER_FRAME_VERSION } from './core.js'

/** Chunk size for the transfer data channel (owner order: 16 KiB). */
export const CHUNK_SIZE = 16384
/** Default per-transfer limit (owner order: 20 MB). */
export const DEFAULT_TRANSFER_LIMIT = 20 * 1024 * 1024
/** Absolute hard cap (owner order: 100 MB) — larger files are refused. */
export const HARD_TRANSFER_CAP = 100 * 1024 * 1024

/** Typed error without importing mailbox.js (which imports this module). */
function terr(code, message) {
  const e = new Error(message)
  e.code = code
  e.transferCode = code
  return e
}

/** Number of 16 KiB chunks a file of `size` bytes occupies (≥1 for size>0). */
export function chunkCountFor(size) {
  const s = Number(size) || 0
  return s <= 0 ? 0 : Math.ceil(s / CHUNK_SIZE)
}

/**
 * Assemble the canonical chunk-frame metadata from a transfer session's
 * NON-SECRET facts. This is the SINGLE assembly point shared by the sender
 * (sealChunk) and the receiver (openChunk) — the exact fields, and therefore
 * the exact AAD bytes, are identical on both sides by construction (R79
 * F-R78-1: one versioned frame schema, one shared builder in core.js).
 *
 * @param {{transferId:string, senderDeviceId:string, receiverDeviceId:string,
 *          chunkIndex:number, totalChunks:number, totalBytes:number,
 *          metadataHash:string, noncePrefix:Uint8Array}} parts
 */
export function buildFrameMeta(parts) {
  const meta = {
    transferId: String((parts && parts.transferId) || ''),
    senderDeviceId: String((parts && parts.senderDeviceId) || ''),
    receiverDeviceId: String((parts && parts.receiverDeviceId) || ''),
    // Integer coercion is EXPLICIT: a fractional or absent index is a typed
    // refusal here, not a surprise deeper inside the nonce construction.
    chunkIndex: Number.isInteger(Number(parts && parts.chunkIndex)) ? Number(parts.chunkIndex) : NaN,
    totalChunks: Number((parts && parts.totalChunks) || 0),
    totalBytes: Number((parts && parts.totalBytes) || 0),
    metadataHash: String((parts && parts.metadataHash) || ''),
    noncePrefix: parts && parts.noncePrefix,
  }
  if (!meta.transferId || !meta.senderDeviceId || !meta.receiverDeviceId) {
    throw terr('bad_record', 'Frame metadata is missing a binding field (transfer/device ids)')
  }
  if (!Number.isInteger(meta.chunkIndex) || meta.chunkIndex < 0) {
    throw terr('bad_record', 'Frame metadata chunk index must be a non-negative integer')
  }
  // The metadata hash is the offer's file digest — always a 64-hex sha256.
  // Binding an empty/short hash would weaken the "same transfer id, different
  // metadata → reject" gate, so it is refused at the builder.
  if (!/^[0-9a-f]{64}$/.test(meta.metadataHash)) {
    throw terr('bad_record', 'Frame metadata is missing the 64-hex file digest')
  }
  if (!meta.noncePrefix || meta.noncePrefix.length !== 4) {
    throw terr('bad_record', 'Frame metadata is missing the per-transfer nonce prefix')
  }
  if (meta.totalChunks <= 0 || meta.totalBytes <= 0 || meta.chunkIndex >= meta.totalChunks) {
    throw terr('bad_record', 'Frame metadata chunk index/count/size is out of range')
  }
  return meta
}

// --- Filename hygiene ---------------------------------------------------------

const EXECUTABLE_ARCHIVE_EXTS = new Set([
  'exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'sh', 'js', 'mjs', 'jar',
  'vbs', 'htm', 'html', 'apk', 'dmg', 'deb', 'rpm', 'appimage', 'zip', '7z',
  'rar', 'gz', 'tgz', 'tar', 'iso', 'dll',
])

/**
 * Strip everything dangerous out of a peer-supplied file name: path components
 * (forward/back slashes AND Windows drive letters), control characters,
 * leading dots, collapsed whitespace; cap at 120 chars; fall back to
 * 'received-file' when nothing sane remains. The sanitized name is what the
 * receiver dialog shows and what the a[download] uses — never the raw string.
 */
export function sanitizeFilename(name) {
  let n = String(name || '')
  n = n.replace(/^([a-zA-Z]):/, '')        // drive letters ("C:")
  n = n.split(/[\\/]+/).pop() || ''        // path components
  n = n.replace(/[\u0000-\u001f\u007f]+/g, '') // control chars
  n = n.replace(/^\.+/, '')                // leading dots (dotfiles / "..")
  n = n.replace(/\s+/g, ' ').trim()        // collapse whitespace
  if (n.length > 120) n = n.slice(0, 120).trim()
  return n || 'received-file'
}

/**
 * True when the (sanitized) name has an executable-or-archive extension —
 * the receiver UI MUST show a prominent warning banner when this is true.
 * Case-insensitive; the list is the owner-ordered set.
 */
export function executableOrArchiveWarning(name) {
  const n = String(name || '').toLowerCase()
  const dot = n.lastIndexOf('.')
  if (dot < 0 || dot === n.length - 1) return false
  return EXECUTABLE_ARCHIVE_EXTS.has(n.slice(dot + 1))
}

/**
 * Build the file offer metadata. The MIME type is ALWAYS
 * 'application/octet-stream' — a claimed MIME from a peer is never trusted;
 * the receiver decides by name+warning, not by type sniffing.
 * R79 (F-R78-1): the offer also carries totalChunks — the CHUNK COUNT both
 * sides bind into every frame's AAD. It is derived from size here so the
 * sender's offer and the receiver's re-build agree without any extra wire
 * field beyond what was already authenticated.
 */
export function buildFileOffer(fileMeta) {
  const size = Number(fileMeta && fileMeta.size) || 0
  return {
    name: sanitizeFilename(fileMeta && fileMeta.name),
    size,
    sha256hex: String(fileMeta && fileMeta.sha256hex || ''),
    mime: 'application/octet-stream',
    kind: 'file',
    totalChunks: chunkCountFor(size),
  }
}

// --- Pure helpers ---------------------------------------------------------------

/**
 * Validate a transfer request against the per-device limit and the absolute
 * hard cap. Returns {ok:true} or {ok:false, reason:'hard_cap'|'over_limit'}.
 * Pure — used by the worker AND directly testable.
 */
export function validateTransferRequest({ size, limit, hardCap } = {}) {
  const s = Number(size) || 0
  const cap = Number(hardCap) || HARD_TRANSFER_CAP
  const lim = Number(limit) || DEFAULT_TRANSFER_LIMIT
  if (s <= 0) return { ok: false, reason: 'empty' }
  if (s > cap) return { ok: false, reason: 'hard_cap' }
  if (s > lim) return { ok: false, reason: 'over_limit' }
  return { ok: true }
}

/** Next sequence number (per-transfer monotonic int, starting at 0). */
export function nextSeq(current) {
  return (Number(current) || 0) + 1
}

/**
 * Replay-cache pruning — bounded array of {m: messageId, t: seenAt}, max 400
 * entries (drop oldest first) and drop entries older than an hour. Pure.
 */
export function pruneReplay(list, now = Date.now()) {
  const HOUR = 60 * 60 * 1000
  const seen = new Set()
  const out = []
  for (const e of Array.isArray(list) ? list : []) {
    if (!e || typeof e.m !== 'string' || seen.has(e.m)) continue
    if (typeof e.t !== 'number' || now - e.t > HOUR) continue
    seen.add(e.m)
    out.push(e)
  }
  while (out.length > 400) out.shift()
  return out
}

// --- Chunk sealing / opening (worker-side; worker supplies the session key) ----

/**
 * Seal one 16 KiB chunk under the transfer session key (R79 frame schema v1):
 *   nonce = deterministic per-transfer prefix(32b) || uint64be(chunkIndex)
 *   AAD   = buildChunkAad({transferId, senderDeviceId, receiverDeviceId,
 *                          chunkIndex, totalChunks, totalBytes, metadataHash})
 * Returns the wire frame {v, seq, iv(b64), ct(b64)} — frames travel over the
 * RTCPeerConnection data channel 'ucrypt-xfer' as JSON strings.
 *
 * @param {CryptoKey} transferKey K_transfer (worker-owned, non-extractable)
 * @param {object} meta canonical frame metadata (buildFrameMeta)
 * @param {Uint8Array} bytes the 16 KiB (or final partial) plaintext chunk
 */
export async function sealChunk(transferKey, meta, bytes) {
  const m = buildFrameMeta(meta)
  const iv = chunkNonce(m.noncePrefix, m.chunkIndex)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: buildChunkAad(m) },
    transferKey,
    bytes
  )
  return { v: TRANSFER_FRAME_VERSION, seq: m.chunkIndex, iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) }
}

/** Byte-equality for the deterministic nonce gate (no early-exit timing a
 * sniffer could exploit — the channel is already encrypted, this is hygiene). */
function nonceEquals(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * Open a sealed chunk with STRICT binding (R79 frame schema v1):
 *   1. schema version — only TRANSFER_FRAME_VERSION is accepted;
 *   2. seq match — the frame's seq must equal the expected index in meta;
 *   3. deterministic nonce — the frame's iv MUST equal the nonce constructed
 *      from the per-transfer prefix and its index (a mutated, replayed or
 *      transplanted frame fails here before any decryption work);
 *   4. AAD + GCM tag — any binding-field mismatch (transfer, devices, index,
 *      counts, size, metadata) fails the tag and the frame is refused.
 * There is NO fallback path: a mismatch is a rejection, never a re-try with
 * different semantics (owner order R79 §1.1).
 */
export async function openChunk(transferKey, meta, frame) {
  const m = buildFrameMeta(meta)
  if (!frame || typeof frame !== 'object') throw terr('bad_record', 'Frame is not an object')
  if (frame.v !== TRANSFER_FRAME_VERSION) {
    throw terr('bad_record', `Frame schema version mismatch (got ${String(frame.v)})`)
  }
  if (Number(frame.seq) !== m.chunkIndex) {
    throw terr('bad_record', `Frame seq ${String(frame.seq)} does not match the expected index ${m.chunkIndex}`)
  }
  const iv = base64ToBytes(String(frame.iv || ''))
  const expected = chunkNonce(m.noncePrefix, m.chunkIndex)
  if (!nonceEquals(iv, expected)) {
    throw terr('nonce_mismatch', 'Frame nonce does not match the deterministic per-transfer construction')
  }
  const ct = base64ToBytes(String(frame.ct || ''))
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: expected, additionalData: buildChunkAad(m) },
    transferKey,
    ct
  )
  return new Uint8Array(plain)
}

// --- Final integrity gate ---------------------------------------------------------

/**
 * Pure integrity verification of a fully received transfer. `chunks` is the
 * ordered array of decrypted chunk byte-arrays the receiver accumulated
 * (expectedSeq discipline enforced upstream: gap ⇒ fail, duplicate ⇒ fail).
 * The transfer is accepted ONLY when the accumulated length equals offer.size
 * AND sha256(chunks) equals offer.sha256hex — otherwise {ok:false} and the
 * buffer is NEVER saved.
 *
 * @param {Uint8Array[]} chunks ordered decrypted chunks
 * @param {{size:number, sha256hex:string}} offer
 * @returns {Promise<{ok:boolean, reason?:string, size?:number, sha256hex?:string}>}
 */
export async function finalizeInbox(chunks, offer) {
  const list = Array.isArray(chunks) ? chunks : []
  let total = 0
  for (const c of list) total += (c && c.length) || 0
  if (total !== Number(offer.size)) {
    return { ok: false, reason: 'size_mismatch', size: total }
  }
  const merged = new Uint8Array(total)
  let off = 0
  for (const c of list) {
    if (!c || !c.length) continue
    merged.set(c, off)
    off += c.length
  }
  const digestHex = Array.from(await sha256(merged)).map(b => b.toString(16).padStart(2, '0')).join('')
  if (digestHex !== String(offer.sha256hex || '').toLowerCase()) {
    return { ok: false, reason: 'sha_mismatch', size: total, sha256hex: digestHex }
  }
  return { ok: true, size: total, sha256hex: digestHex }
}
