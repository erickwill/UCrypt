/**
 * UCrypt — R136 §5.1/§7 — THE BEAM 3 OFFER MANIFEST (the LocalSend
 * borrowing: metadata-first offer; the receiver consents on named files
 * with sizes BEFORE a single byte moves).
 *
 * The manifest is the offer's payload contract:
 *   { v:3, files:[{name,size,type}], totalBytes, count, sha256 }
 * where sha256 is the digest over the canonical manifest bytes — the
 * transcript binds it (transcript.js), so an offer cannot be substituted
 * after pairing.
 *
 * HOSTILE INPUTS ARE TYPED REFUSALS (the R136 fuzz additions): path
 * traversal, absolute paths, control/bidi/format characters, oversized
 * names, non-integer or negative or over-cap sizes, count bombs.
 *
 * PURE — battery-pinned (TRF-MANIFEST-*, G71).
 */

import { canonicalJsonBytes } from '../beam2/identity.js'
import { BEAM3_MAX_FILE_BYTES, validateBeam3FileEdge } from './planes.js'

/** The manifest schema version. */
export const MANIFEST_VERSION = 3

/** Defensive caps (the R129/R130 batch-cap lineage, raised for Beam 3). */
export const MAX_FILES_PER_OFFER = 16
export const MAX_NAME_LENGTH = 240

/** The typed manifest error. */
export function manifestError(code, detail) {
  const e = new Error(`BEAM3_MANIFEST_${code}: ${detail}`)
  e.code = `BEAM3_MANIFEST_${code}`
  return e
}

/** Hex digest helper (async — WebCrypto). */
export async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Name sanitizer gate: the exact refusal classes (R136 fuzz targets).
 * Returns {ok, code} — a refused name NEVER reaches a manifest.
 */
export function validateFileName(name) {
  const n = String(name ?? '')
  if (!n.length) return { ok: false, code: 'ERR_NAME_EMPTY' }
  if (n.length > MAX_NAME_LENGTH) return { ok: false, code: 'ERR_NAME_TOO_LONG' }
  if (n.includes('/') || n.includes('\\')) return { ok: false, code: 'ERR_NAME_PATH' }
  if (n === '.' || n === '..') return { ok: false, code: 'ERR_NAME_PATH' }
  if (n.includes('\0')) return { ok: false, code: 'ERR_NAME_CONTROL' }
  // control + bidi/format characters (the R130-F5 class at the new door)
  for (const ch of n) {
    const c = ch.codePointAt(0)
    if (c < 0x20 || c === 0x7f) return { ok: false, code: 'ERR_NAME_CONTROL' }
    if ((c >= 0x200b && c <= 0x200f) || c === 0x202e || (c >= 0x2066 && c <= 0x2069)) {
      return { ok: false, code: 'ERR_NAME_BIDI' }
    }
  }
  return { ok: true, code: 'NAME_OK' }
}

/**
 * Build a manifest from file descriptors [{name, size, type}] — validates
 * every field, computes the canonical digest. Throws manifestError on the
 * first violation.
 */
export async function buildManifest(files) {
  const list = Array.isArray(files) ? files : []
  if (!list.length) throw manifestError('EMPTY', 'an offer carries at least one file')
  if (list.length > MAX_FILES_PER_OFFER) throw manifestError('COUNT', `an offer carries at most ${MAX_FILES_PER_OFFER} files (got ${list.length})`)
  const clean = []
  let total = 0
  for (const f of list) {
    const nameCheck = validateFileName(f && f.name)
    if (!nameCheck.ok) throw manifestError(nameCheck.code, `file name refused: ${JSON.stringify(String(f && f.name).slice(0, 40))}`)
    const edge = validateBeam3FileEdge(f && f.size)
    if (!edge.ok) throw manifestError(edge.code, `file size refused: ${String(f && f.size)}`)
    const size = Number(f.size)
    total += size
    if (total > BEAM3_MAX_FILE_BYTES) throw manifestError('TOTAL_OVER_CAP', `offer total ${total} exceeds the cap`)
    clean.push({ name: String(f.name), size, type: String(f.type || 'application/octet-stream').slice(0, 120) })
  }
  const manifest = { v: MANIFEST_VERSION, files: clean, totalBytes: total, count: clean.length }
  const sha256 = await sha256Hex(canonicalJsonBytes(manifest))
  return { ...manifest, sha256 }
}

/**
 * Validate an INBOUND manifest (the receive modal's contract): the same
 * refusals, plus the digest check — a manifest whose bytes do not match
 * its own sha256 is refused (tamper-evident before consent).
 */
export async function validateManifest(m) {
  if (!m || typeof m !== 'object') throw manifestError('SCHEMA', 'manifest missing')
  if (m.v !== MANIFEST_VERSION) throw manifestError('VERSION', `expected v:${MANIFEST_VERSION}`)
  if (!Array.isArray(m.files) || !m.files.length) throw manifestError('EMPTY', 'manifest carries no files')
  if (m.files.length > MAX_FILES_PER_OFFER) throw manifestError('COUNT', 'too many files')
  if (!Number.isInteger(m.totalBytes) || m.totalBytes < 0) throw manifestError('TOTAL', 'totalBytes invalid')
  if (m.totalBytes > BEAM3_MAX_FILE_BYTES) throw manifestError('TOTAL_OVER_CAP', 'offer total exceeds the cap')
  let total = 0
  for (const f of m.files) {
    const nameCheck = validateFileName(f && f.name)
    if (!nameCheck.ok) throw manifestError(nameCheck.code, 'hostile file name refused')
    const edge = validateBeam3FileEdge(f && f.size)
    if (!edge.ok) throw manifestError(edge.code, 'hostile file size refused')
    total += Number(f.size)
  }
  if (total !== m.totalBytes) throw manifestError('TOTAL_MISMATCH', 'file sizes do not sum to totalBytes')
  const { sha256, ...rest } = m
  const digest = await sha256Hex(canonicalJsonBytes(rest))
  if (String(sha256).toLowerCase() !== digest) throw manifestError('DIGEST', 'manifest digest mismatch — the offer was altered')
  return { ...m, sha256: digest }
}

/**
 * The size-only re-check on EVERY inbound chunk frame (the receiver's
 * running guard — the manifest totalBytes is the ceiling).
 */
export function chunkFitsBudget(receivedBytes, totalBytes) {
  const got = Number(receivedBytes) || 0
  const cap = Number(totalBytes) || 0
  if (got > cap) throw manifestError('OVER_RUN', `received ${got} > manifest ${cap} — the sender exceeded the consented size`)
  return true
}
