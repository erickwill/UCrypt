/**
 * UCrypt — R142 §5.2-b4 — THE SAFETY CODE (THE SYNC CODE the owner demands).
 *
 * A fresh 6-digit code PER SESSION, derived from the chain group seal + BOTH
 * session nonces. Both devices display it; the human compares; a mismatch
 * aborts BEFORE ANY PAYLOAD BYTE (G93 R11). The file hash remains an
 * auto-checked fingerprint, never user-compared (row 44 stands).
 *
 * This is the short-authentication-string discipline defending against a
 * compromised relay: the code never crosses the wire — both sides derive it
 * from material they already share (the chain seal) plus the nonces that
 * rode the signed handshake.
 *
 * PURE (the hash is injectable for the battery; the default is WebCrypto).
 */

export const SAFETY_CODE_DIGITS = 6

export function safetyCodeError(code, message) {
  const e = new Error(message)
  e.code = `BRIDGE_CODE_${code}`
  return e
}

/** The canonical material: order-independent, so both roles derive one code. */
function codeMaterial({ chainSealHex, nonceA, nonceB }) {
  const a = String(nonceA || '')
  const b = String(nonceB || '')
  const [lo, hi] = a <= b ? [a, b] : [b, a]
  return `${String(chainSealHex || '')}|${lo}|${hi}`
}

/** Default HMAC-SHA256 via WebCrypto (available in pages and workers). */
async function defaultHmac(keyHex, message) {
  const enc = new TextEncoder()
  const keyBytes = new Uint8Array(keyHex.match(/.{2}/g).map((h) => parseInt(h, 16)))
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message))
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Derive the session's 6-digit code. `hmac` is injectable: (keyHex, message) → hex.
 * Nonces must be non-empty strings; the seal hex must be hex-ish and non-empty.
 */
export async function deriveSafetyCode({ chainSealHex, nonceA, nonceB, digits = SAFETY_CODE_DIGITS, hmac = defaultHmac } = {}) {
  const seal = String(chainSealHex || '')
  if (!/^[0-9a-fA-F]{16,}$/.test(seal)) throw safetyCodeError('SEAL', 'the safety code derives from the chain group seal (hex)')
  if (!nonceA || !nonceB || typeof nonceA !== 'string' || typeof nonceB !== 'string') {
    throw safetyCodeError('NONCE', 'both session nonces are required (fresh per session)')
  }
  const mac = await hmac(seal.toLowerCase(), codeMaterial({ chainSealHex: seal, nonceA, nonceB }))
  if (!/^[0-9a-fA-F]{16,}$/.test(mac)) throw safetyCodeError('HMAC', 'the injected hmac returned a malformed hex')
  let acc = 0n
  for (let i = 0; i < mac.length; i += 8) acc = (acc * 256n + BigInt(parseInt(mac.slice(i, i + 8), 16))) % 1000000n
  return String(acc).padStart(digits, '0')
}

/** The comparison is a string compare — typed, and the ONLY door to OPEN. */
export function compareSafetyCodes(shown, typed) {
  return typeof shown === 'string' && typeof typed === 'string' && shown.length === SAFETY_CODE_DIGITS && shown === typed
}

/** Display shaping: "481 902" — the human reads it in halves. */
export function formatSafetyCode(code) {
  if (typeof code !== 'string' || code.length !== SAFETY_CODE_DIGITS) throw safetyCodeError('SHAPE', 'formatSafetyCode needs the 6-digit code')
  return `${code.slice(0, 3)} ${code.slice(3)}`
}
