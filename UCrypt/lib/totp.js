/**
 * UCrypt — TOTP authenticator core (v2.4.0).
 *
 * Pure, dependency-free RFC 6238 (TOTP) / RFC 4226 (HOTP) implementation on
 * Web Crypto HMAC. No chrome.* usage — testable in Node and reusable from the
 * popup, options page, and background worker alike.
 *
 * Token secrets are stored INSIDE the encrypted vault (AES-256-GCM) as
 * entries of type 'totp', so they inherit lock/idle-timeout/sync semantics
 * for free. The codes themselves are computed on demand and never persisted.
 *
 * Exports:
 *   normalizeSecret(s)                    -> uppercase base32 without spaces/dashes/padding
 *   isValidBase32Secret(s, {minBytes})    -> bool
 *   base32Decode(str)                     -> Uint8Array | null   (RFC 4648, case-insensitive)
 *   base32Encode(bytes)                   -> string             (RFC 4648, unpadded, uppercase)
 *   hotp(secretBytes, counter, opts)      -> Promise<string>    (RFC 4226, dynamic truncation)
 *   totp(secret, opts)                    -> Promise<{code, remainingSec, period, counter}>
 *   parseOtpauthUri(uri)                  -> {label, issuer, secret, digits, period, algorithm} | null
 *   buildOtpauthUri(params)               -> string
 *   generateTotpSecret(byteLen)           -> string (CSPRNG base32)
 *   SUPPORTED_ALGORITHMS / DEFAULT_TOTP_OPTS / MIN_SECRET_BYTES
 *
 * Verified against the RFC 4226 Appendix-D and RFC 6238 Appendix-B vectors
 * (SHA-1/SHA-256/SHA-512) in tests/round12-test.mjs.
 */

export const SUPPORTED_ALGORITHMS = ['SHA-1', 'SHA-256', 'SHA-512']

export const DEFAULT_TOTP_OPTS = Object.freeze({
  digits: 6,
  period: 30,
  algorithm: 'SHA-1',
})

/** Secrets below this many decoded bytes are rejected (80 bits — Google's floor). */
export const MIN_SECRET_BYTES = 8

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// --- base32 (RFC 4648) ------------------------------------------------------

/** Uppercase, strip padding, spaces, dashes and other separators. */
export function normalizeSecret(s) {
  if (typeof s !== 'string') return ''
  return s.toUpperCase().replace(/[=\s\-_.]/g, '')
}

export function base32Decode(str) {
  const clean = normalizeSecret(str)
  if (!clean) return null
  let bits = 0
  let value = 0
  const out = []
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch)
    if (idx === -1) return null // invalid character
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  // RFC 4648: leftover bits (< 5) must be zero — tolerate but ignore them.
  return new Uint8Array(out)
}

export function base32Encode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return ''
  let bits = 0
  let value = 0
  let out = ''
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export function isValidBase32Secret(s, { minBytes = MIN_SECRET_BYTES } = {}) {
  const bytes = base32Decode(s)
  if (!bytes) return false
  return bytes.length >= minBytes
}

// --- HOTP / TOTP ------------------------------------------------------------

function counterToBytes(counter) {
  // 64-bit big-endian (RFC 4226 §5.3 — the HTOP value is an 8-byte counter).
  const bytes = new Uint8Array(8)
  let lo = counter % 0x100000000
  let hi = Math.floor(counter / 0x100000000)
  for (let i = 7; i >= 4; i--) { bytes[i] = lo % 256; lo = Math.floor(lo / 256) }
  for (let i = 3; i >= 0; i--) { bytes[i] = hi % 256; hi = Math.floor(hi / 256) }
  return bytes
}

function clampDigits(d) {
  const n = Math.round(Number(d))
  if (!Number.isFinite(n)) return DEFAULT_TOTP_OPTS.digits
  return Math.min(10, Math.max(6, n))
}

function clampPeriod(p) {
  const n = Math.round(Number(p))
  if (!Number.isFinite(n)) return DEFAULT_TOTP_OPTS.period
  return Math.min(120, Math.max(15, n))
}

function normalizeAlgorithm(a) {
  const up = String(a || '').toUpperCase().replace(/[^A-Z0-9-]/g, '')
  if (SUPPORTED_ALGORITHMS.includes(up)) return up
  // Tolerate the common "SHA1"/"SHA256" spellings.
  if (up === 'SHA1') return 'SHA-1'
  if (up === 'SHA256') return 'SHA-256'
  if (up === 'SHA512') return 'SHA-512'
  return DEFAULT_TOTP_OPTS.algorithm
}

/**
 * RFC 4226 HOTP. Returns the decimal code zero-padded to `digits`.
 * digits 6..10, algorithm one of SUPPORTED_ALGORITHMS.
 */
export async function hotp(secretBytes, counter, { digits = 6, algorithm = 'SHA-1' } = {}) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length === 0) {
    throw new Error('HOTP: empty secret')
  }
  counter = Math.floor(Number(counter))
  if (!Number.isFinite(counter) || counter < 0) throw new Error('HOTP: invalid counter')

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: normalizeAlgorithm(algorithm) },
    false,
    ['sign'],
  )
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterToBytes(counter)))

  // Dynamic truncation (RFC 4226 §5.4)
  const offset = mac[mac.length - 1] & 0x0f
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] & 0xff) << 16 |
    (mac[offset + 2] & 0xff) << 8 |
    (mac[offset + 3] & 0xff)

  const digitsN = clampDigits(digits)
  return String(bin % 10 ** digitsN).padStart(digitsN, '0')
}

/**
 * RFC 6238 TOTP. `secret` is a base32 string (as pasted/stored).
 * Returns { code, remainingSec, period, counter } — remainingSec counts down
 * to the NEXT code window, computed against `timeSec` (defaults to now).
 */
export async function totp(secret, { timeSec = Date.now() / 1000, period = 30, digits = 6, algorithm = 'SHA-1' } = {}) {
  const bytes = base32Decode(secret)
  if (!bytes || bytes.length < MIN_SECRET_BYTES) {
    throw new Error('Invalid TOTP secret (need ≥ 8 decoded base32 bytes)')
  }
  const periodN = clampPeriod(period)
  const t = Number(timeSec)
  if (!Number.isFinite(t) || t < 0) throw new Error('Invalid time')
  const counter = Math.floor(t / periodN)
  const code = await hotp(bytes, counter, { digits, algorithm })
  return {
    code,
    remainingSec: periodN - Math.floor(t % periodN),
    period: periodN,
    counter,
  }
}

// --- otpauth:// URIs (the format QR codes carry) -----------------------------

/**
 * Tolerant otpauth://totp/ parser. Returns null on anything that is not a
 * usable TOTP URI (missing/invalid secret, hotp type, malformed label).
 * Query params win over label-prefix issuer, per the de-facto Google spec.
 */
export function parseOtpauthUri(uri) {
  if (typeof uri !== 'string') return null
  const trimmed = uri.trim()
  if (!trimmed.toLowerCase().startsWith('otpauth://totp/')) return null

  let parsed
  try {
    parsed = new URL(trimmed)
  } catch {
    return null
  }
  if (parsed.protocol !== 'otpauth:') return null

  const type = (parsed.host || '').toLowerCase()
  if (type !== 'totp') return null

  const params = parsed.searchParams
  const secret = normalizeSecret(params.get('secret') || '')
  const bytes = base32Decode(secret)
  if (!bytes || bytes.length < MIN_SECRET_BYTES) return null

  // Label: everything after "otpauth://totp/", possibly "Issuer:account".
  let label = ''
  try {
    label = decodeURIComponent(parsed.pathname.replace(/^\/+/, ''))
  } catch {
    label = parsed.pathname.replace(/^\/+/, '')
  }
  if (!label && !params.get('issuer')) return null

  let issuer = (params.get('issuer') || '').trim()
  if (!issuer && label.includes(':')) {
    const pre = label.slice(0, label.indexOf(':')).trim()
    if (pre) issuer = pre
  }
  label = label.trim()
  if (!label) issuer = issuer || ''

  return {
    label,
    issuer,
    secret,
    digits: clampDigits(params.get('digits') ?? DEFAULT_TOTP_OPTS.digits),
    period: clampPeriod(params.get('period') ?? DEFAULT_TOTP_OPTS.period),
    algorithm: normalizeAlgorithm(params.get('algorithm') ?? DEFAULT_TOTP_OPTS.algorithm),
  }
}

/** Inverse of parseOtpauthUri — only emits non-default params to stay compact. */
export function buildOtpauthUri({ label, issuer = '', secret, digits = 6, period = 30, algorithm = 'SHA-1' }) {
  const clean = normalizeSecret(secret)
  const bytes = base32Decode(clean)
  if (!bytes || bytes.length < MIN_SECRET_BYTES) throw new Error('buildOtpauthUri: invalid secret')
  const l = String(label || '').trim()
  if (!l) throw new Error('buildOtpauthUri: label required')
  const iss = String(issuer || '').trim()
  const path = iss ? `${iss}:${l}` : l
  const params = new URLSearchParams()
  params.set('secret', clean)
  if (iss) params.set('issuer', iss)
  const digitsN = clampDigits(digits)
  if (digitsN !== DEFAULT_TOTP_OPTS.digits) params.set('digits', String(digitsN))
  const periodN = clampPeriod(period)
  if (periodN !== DEFAULT_TOTP_OPTS.period) params.set('period', String(periodN))
  const alg = normalizeAlgorithm(algorithm)
  if (alg !== DEFAULT_TOTP_OPTS.algorithm) params.set('algorithm', alg)
  return `otpauth://totp/${encodeURIComponent(path)}?${params.toString()}`
}

/** CSPRNG secret, base32. 20 bytes = 160 bits = the Google-Authenticator norm. */
export function generateTotpSecret(byteLen = 20) {
  const n = Math.min(64, Math.max(10, Math.round(Number(byteLen) || 20)))
  const bytes = new Uint8Array(n)
  crypto.getRandomValues(bytes)
  return base32Encode(bytes)
}
