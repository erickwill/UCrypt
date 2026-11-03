/**
 * UCrypt — R136 §5.2 — THE BEAM 3 CHUNK FRAMING ("256 KiB, individually
 * sha256-stamped, end-to-end sealed so the cloud only ever stores
 * ciphertext; deleted by tombstone after both sides acknowledge").
 *
 * The frame shape (the wire unit on every plane):
 *   { i, total, sha256, data } — data is base64 of the ciphertext chunk.
 *
 * The receiver verifies the per-chunk digest BEFORE accepting the frame,
 * enforces order-or-drop semantics (out-of-order frames are buffered only
 * within the ack window), and re-checks the manifest budget on every frame
 * (chunkFitsBudget — a sender cannot overrun the consented size).
 *
 * PURE — bytes in, bytes out; the battery drives real WebCrypto digests.
 */

import { BEAM3_CHUNK_SIZE } from './planes.js'
import { sha256Hex } from './manifest.js'
import { sessionPrefix } from './relay.js'

/** The typed chunk error. */
export function chunkError(code, detail) {
  const e = new Error(`BEAM3_CHUNK_${code}: ${detail}`)
  e.code = `BEAM3_CHUNK_${code}`
  return e
}

/** Chunk count for a size (0 B → 0; 1 B → 1; 256 KiB exact → 1). */
export function chunkCountFor(size, chunkSize = BEAM3_CHUNK_SIZE) {
  const n = Number(size)
  if (!Number.isInteger(n) || n < 0) return 0
  if (n === 0) return 0
  return Math.ceil(n / chunkSize)
}

function bytesToB64(u8) {
  let s = ''
  const CH = 0x8000
  for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH))
  return btoa(s)
}

function b64ToBytes(b64) {
  const s = atob(String(b64 || ''))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i += 1) out[i] = s.charCodeAt(i)
  return out
}

/**
 * Frame one chunk: slice the source bytes, stamp the digest.
 * @param {Uint8Array} sourceBytes — the (already sealed) payload slice source
 * @param {number} index
 * @param {number} total
 */
export async function frameChunk(sourceBytes, index, total, chunkSize = BEAM3_CHUNK_SIZE) {
  if (!sourceBytes || !(sourceBytes instanceof Uint8Array)) throw chunkError('SOURCE', 'source bytes missing')
  const i = Number(index)
  const t = Number(total)
  if (!Number.isInteger(i) || i < 0 || i >= t) throw chunkError('INDEX', `index ${i} outside 0..${t - 1}`)
  const off = i * chunkSize
  const slice = sourceBytes.subarray(off, Math.min(off + chunkSize, sourceBytes.length))
  if (i < t - 1 && slice.length !== chunkSize) throw chunkError('SHORT', 'non-final chunk shorter than the frame size')
  return { i, total: t, sha256: await sha256Hex(slice), data: bytesToB64(slice) }
}

/**
 * Verify an inbound frame's digest and shape. Throws chunkError on any
 * violation — the receiver NEVER accepts an unstamped frame.
 */
export async function verifyFrame(frame, chunkSize = BEAM3_CHUNK_SIZE) {
  if (!frame || typeof frame !== 'object') throw chunkError('SCHEMA', 'frame missing')
  const i = Number(frame.i)
  const t = Number(frame.total)
  if (!Number.isInteger(i) || i < 0) throw chunkError('INDEX', 'frame index invalid')
  if (!Number.isInteger(t) || t <= 0 || i >= t) throw chunkError('TOTAL', 'frame total invalid')
  const data = b64ToBytes(frame.data)
  if (i < t - 1 && data.length !== chunkSize) throw chunkError('SHORT', 'non-final chunk shorter than the frame size')
  if (i === t - 1 && (data.length === 0 || data.length > chunkSize)) throw chunkError('FINAL', 'final chunk size invalid')
  const digest = await sha256Hex(data)
  if (String(frame.sha256).toLowerCase() !== digest) throw chunkError('DIGEST', `chunk ${i} digest mismatch — the frame is corrupted or tampered`)
  return { i, data }
}

/**
 * THE REASSEMBLER — bounded-memory, order-aware collection with the
 * manifest budget re-check on every frame. Frames may arrive out of order
 * within the ack window; the assembled output is exact.
 */
export class ChunkAssembler {
  constructor({ totalChunks, totalBytes, onProgress } = {}) {
    if (!Number.isInteger(totalChunks) || totalChunks < 0) throw chunkError('PLAN', 'totalChunks invalid')
    this.totalChunks = totalChunks
    this.totalBytes = Number(totalBytes) || 0
    this.onProgress = typeof onProgress === 'function' ? onProgress : null
    /** @type {Map<number, Uint8Array>} */
    this.parts = new Map()
    this.receivedBytes = 0
    this.highestContiguous = -1
  }

  /** Accept one VERIFIED frame (pass through verifyFrame first). */
  accept(index, data) {
    const i = Number(index)
    if (this.parts.has(i)) return { duplicate: true }
    this.parts.set(i, data)
    this.receivedBytes += data.length
    if (this.receivedBytes > this.totalBytes) {
      // the consent overrun — refuse and roll the bookkeeping back
      this.parts.delete(i)
      this.receivedBytes -= data.length
      throw chunkError('OVER_RUN', 'the sender exceeded the consented size — chunk refused')
    }
    while (this.parts.has(this.highestContiguous + 1)) this.highestContiguous += 1
    if (this.onProgress) this.onProgress(this.receivedBytes, this.totalBytes)
    return { duplicate: false, highestContiguous: this.highestContiguous }
  }

  /** All chunks present? */
  get complete() {
    return this.totalChunks === 0 || (this.parts.size === this.totalChunks && this.highestContiguous === this.totalChunks - 1)
  }

  /** Assemble the final bytes (exact length; wipes the parts map after). */
  assemble() {
    if (!this.complete) throw chunkError('INCOMPLETE', `assembly with ${this.parts.size}/${this.totalChunks} chunks`)
    const out = new Uint8Array(this.totalBytes)
    let off = 0
    for (let i = 0; i < this.totalChunks; i += 1) {
      const p = this.parts.get(i)
      out.set(p, off)
      off += p.length
    }
    this.parts.clear() // wipe the intermediate buffers after assembly
    return out
  }
}

/**
 * Tombstone plan for a completed relay session (Plane B): both sides
 * acknowledged the completed manifest → every chunk object of the session
 * is deletable (zero orphan ciphertext ever — the Beam 2 compaction law,
 * carried to the cloud).
 */
export function tombstonePlan(sessionId, totalChunks) {
  // the namespace gate (sessionPrefix throws on a hostile sessionId — the
  // tombstone names must land inside the session's own folder)
  const prefix = sessionPrefix(sessionId)
  const names = []
  for (let i = 0; i < Number(totalChunks) || 0; i += 1) names.push(`${prefix}chunk-${String(i).padStart(6, '0')}.bin`)
  return { sessionId, chunkNames: names, recordNames: [`${prefix}offer.json`, `${prefix}complete.json`] }
}
