/**
 * UCrypt — R124 §2 "The Async Pickup" (D13 — the last deferred feature).
 *
 * THE PRODUCT (law 0.38): when a Direct Share receiver hasn't replied and the
 * invitation is about to expire, the sender can — OPT-IN, ONE CLICK, PER-SHARE,
 * DEFAULT OFF — hold the file(s) on THEIR OWN cloud so the friend can pick it
 * up later, offline, through any messenger.
 *
 * THE CRYPTOGRAPHY:
 *   pickup key  = HKDF-SHA-256(ikm = utf8(8-word code), salt 'ucrypt:pickup:v1',
 *                              info 'ucrypt:pickup:v1:key') → AES-256-GCM,
 *                 non-extractable — domain-separated from EVERY other key in
 *                 the product (the share session key, the chain keys, the
 *                 credential keys). A fresh 8-word code (~88 bits) from the
 *                 SAME pinned wordlist; distinct from the live session's
 *                 ephemeral keys.
 *   the blob    = ONE opaque binary file uploaded to the sender's own cloud:
 *                 { v:1, iv:b64, ct:b64 } — inside: the descriptor AND the
 *                 file bytes, sealed together. THE CLOUD SEES ONLY
 *                 CIPHERTEXT; the uploaded file's NAME is a fixed neutral
 *                 string (ucrypt-pickup.bin) so the cloud never learns the
 *                 real filename or its size in a readable label.
 *   the notice  = 'UCRYPT-PICKUP1:' + shared-link + '#' + code — ONE
 *                 pasteable string. THE MESSENGER SEES ONLY THE LINK AND THE
 *                 CODE: the filename, the size, and the content ride INSIDE
 *                 the ciphertext (the descriptor decrypts only after the key).
 *   the link    = the transport's native shared-link mechanism (Drive
 *                 anyone-with-link, Dropbox shared link, a secret Gist's raw
 *                 URL) — it grants ONLY that file's ciphertext; NO credential
 *                 rides the code, the receiver needs NO account.
 *
 * THE SEPARATION LAW (0.27 — absolute): the pickup creates NO chain
 * relationship and carries NO vault access — this module imports NOTHING
 * from vault.js or sync.js, touches NO vault/sync/chain storage key, and the
 * receiver's UCrypt holds only the decrypted file. The code DIES ON
 * COMPLETION (the receiver marks the notice consumed — one-time, capped).
 *
 * THE TTL: bounded (1h / 24h / 7d — 0.15-attributed options, default 24 h),
 * visible on BOTH ends (the sender at hold time; the receiver on the
 * descriptor door and in the sealed expiresAt), enforced INSIDE the seal
 * (the expired blob answers its typed terminal before any file surfaces).
 *
 * THE HONEST ABSENCE: transports without a shared-link mechanism (WebDAV /
 * Custom URL, the Drive bridge rung) are honestly labeled "pickup not
 * supported" — the LIVE share still works when both are online (lib/
 * transports/pickup-links.js owns that table; this module stays transport-
 * blind by parameter injection).
 *
 * THE RING (0.28): the caller records flow 'pickup' rows (stage names only,
 * sanitized, capped, local-only) — this module exposes the stage-name
 * constants so the ring names the rung the same way everywhere.
 */

import { sha256, bytesToBase64, base64ToBytes } from './crypto.js'
import { sanitizeFilename, executableOrArchiveWarning, CHUNK_SIZE } from './transfer/session.js'

// ── Pinned constants (0.15-class — measured, never changed unilaterally) ──
export const PICKUP_PREFIX = 'UCRYPT-PICKUP1:'
/** HKDF salt + info — the pickup's own domain (0.38: domain-separated). */
export const PICKUP_SALT = 'ucrypt:pickup:v1'
export const PICKUP_INFO_KEY = 'ucrypt:pickup:v1:key'
/** The pickup code: 8 × 11 bits = 88 bits (the same strength class as the share code). */
export const PICKUP_CODE_WORDS = 8
/** The TTL choices (bounded, 0.15-attributed): 1 h / 24 h / 7 d — default 24 h. */
export const PICKUP_TTL_DEFAULT_MS = 24 * 60 * 60 * 1000
export const PICKUP_TTL_CHOICES_MS = [
  1 * 60 * 60 * 1000,
  24 * 60 * 60 * 1000,
  7 * 24 * 60 * 60 * 1000,
]
/** The neutral cloud filename — the real filename NEVER rides the cloud (0.38). */
export const PICKUP_CLOUD_NAME = 'ucrypt-pickup.bin'
/** The same file/session caps the live share carries (0.15-aligned, D9/D12). */
export const PICKUP_FILE_CAP = 20 * 1024 * 1024
export const PICKUP_SESSION_CAP = 50 * 1024 * 1024
/** The note cap rides the live share's rule (one line). */
export const PICKUP_NOTE_CAP = 200
/** The receiver's one-time consumption memory (the code dies on completion). */
export const PICKUP_CONSUMED_CAP = 50
const PICKUP_CONSUMED_KEY = 'ucrypt:pickup:consumed'
/** The blob format version. */
export const PICKUP_BLOB_VERSION = 1

// The ring stage names (0.28 — the ring names the rung; here the stage).
export const PICKUP_STAGES = Object.freeze({
  HOLD_OFFER: 'hold-offer',
  HOLD_CREATE: 'hold-create',
  HOLD_UPLOAD: 'hold-upload', // the transport's own upload leg (the bridge records it)
  HOLD_UPLOADED: 'hold-uploaded',
  NOTICE_ISSUED: 'notice-issued',
  NOTICE_PASTED: 'notice-pasted',
  DOWNLOAD: 'download',
  DECRYPT: 'decrypt',
  CONSENT: 'consent',
  SAVE: 'save',
  CANCEL: 'cancel',
  EXPIRED_TERMINAL: 'expired-terminal',
})

// ── Small helpers (the share module's own discipline, mirrored) ─────────────

const enc = (s) => new TextEncoder().encode(s)
const dec = (b) => new TextDecoder().decode(b)

function b64(bytes) {
  return bytesToBase64(bytes)
}

function unb64(s) {
  return base64ToBytes(String(s || ''))
}

async function randomBytes(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

function bip39Words() {
  const w = globalThis.CRYPTKEY_BIP39
  if (!Array.isArray(w) || w.length !== 2048) throw new Error('Pickup: the wordlist is missing')
  return w
}

// R130 (FINDING R130-F1 — the fuzz's first product find, law 0.44): the
// pickup parser is a receiver-side trust boundary (pasted text) — its entry
// coercion must hold for ANY input. A hostile-coercion object degrades to
// '' (the typed-refusal path) instead of throwing.
function safeText(v) {
  if (typeof v === 'string') return v
  if (v === null || v === undefined || typeof v !== 'object') return String(v ?? '')
  try { return String(v) } catch { return '' }
}

function bitsFromBytes(bytes) {
  const bits = []
  for (const byte of bytes) for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1)
  return bits
}

/** 8 pickup words — uniform, rejection-sampled 11-bit picks (the share code's own discipline). */
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

function isWordlistWord(w) {
  return bip39Words().includes(String(w || '').toLowerCase())
}

/** Parse "word-word-…-word" against the pinned list; null when anything drifts. */
export function parsePickupWords(s, count = PICKUP_CODE_WORDS) {
  const parts = safeText(s).trim().toLowerCase().split(/[-\s]+/).filter(Boolean)
  if (parts.length !== count) return null
  for (const p of parts) if (!isWordlistWord(p)) return null
  return parts
}

// ── The pickup key (law 0.38's derivation, verbatim) ────────────────────────

/**
 * THE PICKUP KEY: HKDF-SHA-256(ikm = utf8(code), salt 'ucrypt:pickup:v1',
 * info 'ucrypt:pickup:v1:key') → AES-256-GCM, non-extractable. A different
 * code derives a different key; a different purpose derives nothing (the
 * salt/info are pinned here and battery-asserted against cross-derivation).
 */
export async function derivePickupKey(codeWords) {
  const code = Array.isArray(codeWords) ? codeWords.join('-') : String(codeWords || '')
  if (!parsePickupWords(code)) throw new Error('Pickup: the code is not 8 valid words')
  const ikm = enc(code)
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc(PICKUP_SALT), info: enc(PICKUP_INFO_KEY) },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable — the key material never leaves the engine
    ['encrypt', 'decrypt'],
  )
}

// ── The blob (the cloud sees ONLY this — ciphertext under a neutral name) ───

/**
 * Seal ONE pickup blob. files: [{ name, bytes }] (≤5 files, ≤20 MB each,
 * ≤50 MB total — the live share's own bounds). The descriptor (names, sizes,
 * digests, the note, the TTL) rides INSIDE the seal — the cloud and the
 * messenger never see it. Returns { blob, code, words, codeText, expiresAt,
 * descriptor } — the caller uploads `blob` under PICKUP_CLOUD_NAME and then
 * builds the notice with buildPickupNotice({ link, code: codeText }).
 */
export async function sealPickup({ files, note = '', ttlMs = PICKUP_TTL_DEFAULT_MS, now = Date.now() } = {}) {
  const list = Array.isArray(files) ? files : []
  if (!list.length) throw new Error('Pickup: no files staged')
  if (list.length > 5) throw new Error('Pickup: at most 5 files')
  let total = 0
  const sealedFiles = []
  for (const f of list) {
    const name = sanitizeFilename(String((f && f.name) || '')).slice(0, 200)
    const bytes = f && f.bytes instanceof Uint8Array ? f.bytes : null
    if (!name || !bytes) throw new Error('Pickup: a staged file lost its shape')
    if (bytes.length > PICKUP_FILE_CAP) throw new Error('Pickup: a file exceeds the 20 MB cap')
    total += bytes.length
    if (total > PICKUP_SESSION_CAP) throw new Error('Pickup: the batch exceeds the 50 MB cap')
    sealedFiles.push({ name, bytes })
  }
  const ttl = Number(ttlMs)
  if (!PICKUP_TTL_CHOICES_MS.includes(ttl)) throw new Error('Pickup: the TTL is not one of the bounded choices')
  const expiresAt = now + ttl
  const codeBits = bitsFromBytes(await randomBytes(Math.ceil((PICKUP_CODE_WORDS * 11) / 8)))
  const words = wordsFromBits(codeBits, PICKUP_CODE_WORDS)
  const codeText = words.join('-')
  const digestOf = async (bytes) => {
    const h = await crypto.subtle.digest('SHA-256', bytes)
    return Array.from(new Uint8Array(h)).map((x) => x.toString(16).padStart(2, '0')).join('')
  }
  const descriptor = {
    v: PICKUP_BLOB_VERSION,
    createdAt: now,
    expiresAt,
    count: sealedFiles.length,
    files: [],
  }
  const n = String(note || '').slice(0, PICKUP_NOTE_CAP)
  if (n) descriptor.note = n
  const payloads = []
  for (const f of sealedFiles) {
    const digest = await digestOf(f.bytes)
    descriptor.files.push({
      name: f.name,
      size: f.bytes.length,
      digest,
      highRisk: executableOrArchiveWarning(f.name),
    })
    payloads.push(b64(f.bytes))
  }
  const plain = enc(JSON.stringify({ desc: descriptor, files: payloads }))
  const key = await derivePickupKey(words)
  const iv = await randomBytes(12)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain))
  const envelope = { v: PICKUP_BLOB_VERSION, iv: b64(iv), ct: b64(ct) }
  return {
    blob: enc(JSON.stringify(envelope)),
    code: codeText,
    words,
    expiresAt,
    descriptor,
  }
}

/**
 * Open ONE pickup blob with the pasted code. THE TTL IS ENFORCED HERE — an
 * expired blob answers { ok:false, code:'expired' } before anything surfaces
 * (the typed terminal the receiver renders: "This pickup expired — ask them
 * to share again"). A wrong/altered code answers 'tampered' (AES-GCM's own
 * refusal — the ciphertext never lies twice).
 */
export async function openPickup(blobBytes, codeText, { now = Date.now() } = {}) {
  let envelope = null
  try {
    envelope = JSON.parse(dec(blobBytes instanceof Uint8Array ? blobBytes : new Uint8Array(blobBytes)))
  } catch {
    return { ok: false, code: 'malformed' }
  }
  if (!envelope || envelope.v !== PICKUP_BLOB_VERSION || typeof envelope.iv !== 'string' || typeof envelope.ct !== 'string') {
    return { ok: false, code: 'malformed' }
  }
  const words = parsePickupWords(codeText)
  if (!words) return { ok: false, code: 'bad_code' }
  let key
  try {
    key = await derivePickupKey(words)
  } catch {
    return { ok: false, code: 'bad_code' }
  }
  let plain
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv) }, key, unb64(envelope.ct))
  } catch {
    return { ok: false, code: 'tampered' }
  }
  let body
  try {
    body = JSON.parse(dec(new Uint8Array(plain)))
  } catch {
    return { ok: false, code: 'tampered' }
  }
  const desc = body && body.desc
  const files = Array.isArray(body && body.files) ? body.files : null
  if (!desc || !files || desc.count !== files.length) return { ok: false, code: 'tampered' }
  // THE TTL INSIDE THE SEAL — the cloud's own expiry and this one agree by
  // construction (the sender sealed the same expiresAt it rendered).
  if (Number(desc.expiresAt) && now > Number(desc.expiresAt)) {
    return { ok: false, code: 'expired', expiresAt: Number(desc.expiresAt) }
  }
  return {
    ok: true,
    desc,
    expiresAt: Number(desc.expiresAt) || 0,
    files: files.map((f, i) => ({
      name: sanitizeFilename(String((desc.files[i] && desc.files[i].name) || '')).slice(0, 200),
      size: Number(desc.files[i] && desc.files[i].size) || 0,
      digest: String((desc.files[i] && desc.files[i].digest) || ''),
      highRisk: !!(desc.files[i] && desc.files[i].highRisk),
      bytes: unb64(f),
    })),
  }
}

// ── The notice (ONE pasteable string; the messenger sees link + code only) ──

/**
 * Build the notice: 'UCRYPT-PICKUP1:' + link + '#' + code. The link must be
 * https and whitespace-free; the code is the 8-word string. Nothing else
 * rides — no filename, no size, no grant, no secret (battery-pinned).
 */
export function buildPickupNotice({ link, code }) {
  const l = String(link || '').trim()
  const c = String(code || '').trim()
  if (!/^https:\/\//i.test(l) || /\s/.test(l)) throw new Error('Pickup: the shared link is not a clean https URL')
  if (!parsePickupWords(c)) throw new Error('Pickup: the code is not 8 valid words')
  return PICKUP_PREFIX + l + '#' + c
}

/**
 * Parse the pasted notice. The split is at the LAST '#' — a shared link that
 * itself contains '#' (a fragment) still parses (the code is always the last
 * segment, and only an 8-word code validates). The receiver's input handler
 * consults this BEFORE the share-invitation parser (the prefix owns itself).
 */
export function parsePickupNotice(text) {
  const raw = safeText(text).trim()
  if (!raw.startsWith(PICKUP_PREFIX)) return { ok: false, code: 'not_pickup' }
  const rest = raw.slice(PICKUP_PREFIX.length)
  const hash = rest.lastIndexOf('#')
  if (hash < 0) return { ok: false, code: 'malformed' }
  const link = rest.slice(0, hash).trim()
  const code = rest.slice(hash + 1).trim()
  if (!/^https:\/\//i.test(link) || /\s/.test(link)) return { ok: false, code: 'malformed' }
  if (!parsePickupWords(code)) return { ok: false, code: 'bad_code' }
  return { ok: true, link, code }
}

// ── The TTL machine (bounded, visible on both ends) ─────────────────────────

/** 'active' | 'expired' — the ONE verdict both ends derive from the same sealed expiresAt. */
export function pickupTtlState(expiresAt, now = Date.now()) {
  return now > Number(expiresAt) ? 'expired' : 'active'
}

/** The remaining ms (≥0), for the sender's and receiver's visible lines. */
export function pickupTtlRemaining(expiresAt, now = Date.now()) {
  return Math.max(0, Number(expiresAt) - now)
}

/** Validate a caller-chosen TTL against the bounded choices (the surface layer already offers exactly these). */
export function isValidPickupTtl(ms) {
  return PICKUP_TTL_CHOICES_MS.includes(Number(ms))
}

// ── The receiver's one-time consumption (the code dies on completion) ───────

/**
 * The consumed memory — the pickup's OWN storage key (never the vault, never
 * the chain, never any export; the 0.14 exclusion class). SHA-256 of the
 * whole notice, capped at 50 (the share guard's own cap discipline).
 */
export async function noticeFingerprint(noticeText) {
  const h = await crypto.subtle.digest('SHA-256', enc(String(noticeText || '').trim()))
  return Array.from(new Uint8Array(h)).map((x) => x.toString(16).padStart(2, '0')).join('')
}

export async function readPickupConsumed() {
  try {
    const g = (await chrome.storage.local.get(PICKUP_CONSUMED_KEY))[PICKUP_CONSUMED_KEY]
    return Array.isArray(g) ? g.slice(0, PICKUP_CONSUMED_CAP) : []
  } catch {
    return []
  }
}

// R130 (FINDING R130-F3 — the concurrency pass, law 0.44): the consumed
// memory's read-modify-write is ONE serialized unit — a parallel rush of
// marks merges into the chain instead of interleaving the reads (the same
// discipline the share guard's R130-F3 fix carries; the R114 class, closed
// at both consumed memories).
let _consumedChain = Promise.resolve()

export function markPickupConsumed(noticeText) {
  const run = _consumedChain.then(async () => {
    const fp = await noticeFingerprint(noticeText)
    const list = await readPickupConsumed()
    const next = [fp, ...list.filter((x) => x !== fp)].slice(0, PICKUP_CONSUMED_CAP)
    await chrome.storage.local.set({ [PICKUP_CONSUMED_KEY]: next })
    return fp
  })
  _consumedChain = run.catch(() => {})
  return run
}

export async function isPickupConsumed(noticeText) {
  const fp = await noticeFingerprint(noticeText)
  return (await readPickupConsumed()).includes(fp)
}

// ── The download (the receiver needs NO account, NO credential) ─────────────

/**
 * Fetch the held ciphertext through the shared link. The receiver supplies
 * nothing but the link — no token, no account, no header (the no-credentials
 * law, battery-pinned: the fetch is issued bare). A 404/410 answers the
 * 'gone' type (the sender cancelled or the TTL sweep reached it); an HTML
 * body answers 'cloud_page' (an interstitial — never silently parsed).
 */
export async function downloadPickup(link, { timeoutMs = 60000 } = {}) {
  const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null
  const to = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null
  try {
    const res = await fetch(String(link || ''), ctl ? { signal: ctl.signal, credentials: 'omit', redirect: 'follow' } : { credentials: 'omit', redirect: 'follow' })
    if (res.status === 404 || res.status === 410) return { ok: false, code: 'gone', status: res.status }
    if (!res.ok) return { ok: false, code: 'cloud_error', status: res.status }
    const ct = String(res.headers && res.headers.get ? res.headers.get('content-type') || '' : '').toLowerCase()
    if (ct.includes('text/html')) return { ok: false, code: 'cloud_page', status: res.status }
    const bytes = new Uint8Array(await res.arrayBuffer())
    return { ok: true, bytes, status: res.status }
  } catch (e) {
    return { ok: false, code: 'network', error: String((e && e.message) || e).slice(0, 120) }
  } finally {
    if (to) clearTimeout(to)
  }
}

// ── The separation invariants, machine-checked here for the battery ─────────

/** The keys the pickup may EVER touch: its own consumption memory only. */
export const PICKUP_STORAGE_KEYS = Object.freeze([PICKUP_CONSUMED_KEY])
