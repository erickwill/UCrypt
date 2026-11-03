/**
 * UCrypt — R142 §5.2-b3 — THE BRIDGE CHANNEL (the data plane's pure core).
 *
 * Reliable ordered DataChannel semantics with:
 *   - 16 KiB chunks (the wire unit; the receiver reassembles and verifies);
 *   - bufferedamountlow backpressure (the math lives here, the socket in the
 *     page module);
 *   - PROGRESSIVE SHA-256 computed while streaming (the receiver never
 *     re-reads the file to verify — the hash arrives with the last chunk);
 *   - the receiver writes <name>.ucrypt-part then renames ATOMICALLY (the
 *     naming law lives in the page/worker; the state for it lives here).
 *
 * The v1 sealed envelope header (the chain group seal) is applied by the page
 * module with the chain's own crypto — this module carries the framing and
 * the verification math. PURE — battery-pinned (G95).
 */

import { sha256Hex } from '../beam3/manifest.js'

export const BRIDGE_CHUNK_BYTES = 16 * 1024

export function channelError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_CHANNEL_${code}`
  return e
}

/* ── The progressive SHA-256 (incremental, pure, the streaming fingerprint) ── */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

export class ProgressiveSha256 {
  constructor() {
    this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
    this.buf = new Uint8Array(64)
    this.bufLen = 0
    this.bytes = 0
  }
  update(data) {
    const d = data instanceof Uint8Array ? data : new Uint8Array(data)
    this.bytes += d.length
    let off = 0
    if (this.bufLen) {
      const need = 64 - this.bufLen
      const take = Math.min(need, d.length)
      this.buf.set(d.subarray(0, take), this.bufLen)
      this.bufLen += take
      off = take
      if (this.bufLen === 64) { this._block(this.buf, 0); this.bufLen = 0 }
    }
    for (; off + 64 <= d.length; off += 64) this._block(d, off)
    if (off < d.length) {
      this.buf.set(d.subarray(off), 0)
      this.bufLen = d.length - off
    }
    return this
  }
  _block(p, off) {
    const w = new Uint32Array(64)
    for (let i = 0; i < 16; i++) w[i] = (p[off + i * 4] << 24) | (p[off + i * 4 + 1] << 16) | (p[off + i * 4 + 2] << 8) | p[off + i * 4 + 3]
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3)
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    const h = this.h
    let [a, b, c, d, e, f, g, hh] = h
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
      const ch = (e & f) ^ (~e & g)
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) >>> 0
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0
  }
  /** The final digest as lowercase hex (the auto-checked fingerprint). */
  hex() {
    const bitLenHi = Math.floor(this.bytes / 0x20000000)
    const bitLenLo = (this.bytes << 3) >>> 0
    const pad = new Uint8Array(((this.bufLen < 56 ? 56 : 120) - this.bufLen) + 8)
    pad[0] = 0x80
    const dv = pad.length - 8
    pad[dv] = (bitLenHi >>> 24) & 255; pad[dv + 1] = (bitLenHi >>> 16) & 255; pad[dv + 2] = (bitLenHi >>> 8) & 255; pad[dv + 3] = bitLenHi & 255
    pad[dv + 4] = (bitLenLo >>> 24) & 255; pad[dv + 5] = (bitLenLo >>> 16) & 255; pad[dv + 6] = (bitLenLo >>> 8) & 255; pad[dv + 7] = bitLenLo & 255
    const save = this.bytes
    this.update(pad)
    this.bytes = save
    return Array.from(this.h).map((x) => x.toString(16).padStart(8, '0')).join('')
  }
}

/** True when the incremental hash agrees with the one-shot WebCrypto hash. */
export async function verifyProgressiveSha256(bytes, expectedHex) {
  const p = new ProgressiveSha256()
  p.update(bytes)
  const got = p.hex()
  return got === String(expectedHex || '').toLowerCase() ? true : got
}

/* ── The framing ── */

/** The sender's header frame (plaintext metadata; the seal wraps the whole). */
export function buildHeaderFrame({ sessionId, fileName, size, sha256Hex: sha, chunkBytes = BRIDGE_CHUNK_BYTES }) {
  if (!sessionId) throw channelError('SHAPE', 'the header needs a sessionId')
  if (!(Number.isFinite(size) && size >= 0)) throw channelError('SHAPE', 'the header needs the file size')
  if (!/^[0-9a-fA-F]{64}$/.test(String(sha || ''))) throw channelError('SHAPE', 'the header needs the file sha256')
  const chunkTotal = size === 0 ? 0 : Math.ceil(size / chunkBytes)
  return { v: 1, kind: 'bridge-file', sessionId, fileName: String(fileName || ''), size, sha256: String(sha).toLowerCase(), chunkBytes, chunkTotal }
}

/** Split the payload into wire chunks (Uint8Array views copied — safe to send). */
export function chunkBytes(bytes, { chunkBytes = BRIDGE_CHUNK_BYTES } = {}) {
  const d = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  const total = Math.ceil(d.length / chunkBytes) || 0
  const frames = []
  for (let i = 0; i < total; i++) frames.push(d.slice(i * chunkBytes, (i + 1) * chunkBytes))
  return frames
}

/**
 * The receiver's assembler: feed the chunks IN ORDER, get honest progress,
 * and seal with the progressive hash. The part-file rename decision (the
 * atomic <name>.ucrypt-part → <name>) belongs to the writer — this module
 * only asserts the math: the count, the size, the hash.
 */
export class BridgeAssembler {
  constructor({ size, sha256Hex: sha, chunkBytes = BRIDGE_CHUNK_BYTES } = {}) {
    if (!(Number.isFinite(size) && size >= 0)) throw channelError('SHAPE', 'the assembler needs the file size')
    if (!/^[0-9a-fA-F]{64}$/.test(String(sha || ''))) throw channelError('SHAPE', 'the assembler needs the file sha256')
    this.size = size
    this.sha = String(sha).toLowerCase()
    this.chunkBytes = chunkBytes
    this.progressive = new ProgressiveSha256()
    this.received = 0
    this.parts = []
  }
  /** Feed one chunk; throws on overflow, tracks the running hash. */
  push(chunk) {
    const c = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
    if (this.received + c.length > this.size) throw channelError('OVERFLOW', 'the chunks exceed the declared size — the pipe is lying')
    this.progressive.update(c)
    this.received += c.length
    this.parts.push(c)
    return this.progressLine()
  }
  progressLine() {
    const done = this.size === 0 || this.received >= this.size
    return { received: this.received, size: this.size, done, ratio: this.size ? this.received / this.size : 1 }
  }
  /** Seal: the size checked, the progressive hash checked against the header. */
  seal() {
    if (this.received !== this.size) throw channelError('SIZE', `received ${this.received} of ${this.size} bytes — the transfer is incomplete`)
    const got = this.progressive.hex()
    if (got !== this.sha) throw channelError('DIGEST', 'the file does not match its fingerprint — refusing the rename')
    return { ok: true, sha256: got, bytes: this.received }
  }
}

/* ── The backpressure math (§5.2-b3: bufferedamountlow) ── */

export const CHANNEL_BACKPRESSURE = Object.freeze({
  /** Stop feeding above this many bytes buffered. */
  highWaterBytes: 1 * 1024 * 1024,
  /** Resume when the socket drains to this. */
  lowWaterBytes: 256 * 1024,
})

/** May we feed another chunk? (the pure law the socket loop asks) */
export function mayFeed(bufferedAmount, { high = CHANNEL_BACKPRESSURE.highWaterBytes } = {}) {
  return Number(bufferedAmount) < high
}

/** The honest speed line: bytes over elapsed ms → a human line + ETA. */
export function speedLine(bytesDone, elapsedMs, sizeTotal) {
  if (!(elapsedMs > 0)) return { bps: 0, line: '', etaLine: '' }
  const bps = bytesDone / (elapsedMs / 1000)
  const eta = bps > 0 && sizeTotal > bytesDone ? Math.ceil((sizeTotal - bytesDone) / bps) : 0
  const fmt = (n) => (n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB/s` : n > 1024 ? `${(n / 1024).toFixed(0)} KB/s` : `${n} B/s`)
  const etaLine = eta > 0 ? (eta > 90 ? `${Math.ceil(eta / 60)} min left` : `${eta} s left`) : ''
  return { bps, line: fmt(bps), etaLine }
}

/* ── The one-shot file digest helper (the sender computes it once up front) ── */
export async function fileSha256Hex(bytes) {
  return sha256Hex(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
}
