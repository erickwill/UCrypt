/**
 * UCrypt — R134 §2.A — LAW 0.54: SIGNED CHAIN TRUST ("Beam Two — The AirDrop
 * Standard: One Touch, Any Device, Zero Ceremony").
 *
 * THE LAW: at join time, every device generates a WebCrypto ECDSA P-256
 * DEVICE keypair (universally supported in Chromium; Ed25519 exposure is NOT
 * depended on). The PUBLIC key rides the chain envelope through the
 * replication lane; the PRIVATE key never leaves the device (structural
 * secret refusal — the chain-replicate engine already throws on secrets;
 * this module's refusal set is the Beam 2 half of that law).
 *
 * Every Beam 2 control message and file manifest is signed by the sender's
 * device key and verified by the receiver against the CHAIN-KNOWN public
 * key. Result: a MITM is impossible WITHIN the chain by construction — trust
 * no longer depends on a human comparing codes. The 4×4 fingerprint (already
 * derived from the offer sha in the legacy path) remains as defense-in-depth
 * and is displayed on both screens simultaneously — zero copying, visual
 * comparison only.
 *
 * PURE MODULE — no DOM, no chrome.*: the storage adapter is injected so the
 * battery (bun) runs the real WebCrypto paths end to end. In production the
 * adapter is chrome.storage.local; in the battery it is an in-memory map.
 */

import { utf8Bytes, bytesToHex } from '../transfer/core.js'

/** The device keypair storage key (chrome.storage.local in production). */
export const BEAM2_IDENTITY_KEY = 'ucrypt:beam2:deviceKey'

/** The chain roster key that carries PUBLISHED device public keys (JWK). */
export const BEAM2_CHAIN_KEYS_KEY = 'ucrypt:beam2:chainKeys'

/** The one algorithm, named by the law. */
export const DEVICE_KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' }
export const DEVICE_KEY_SIGN_ALG = { name: 'ECDSA', hash: { name: 'SHA-256' } }

/**
 * The Beam 2 half of the structural secret refusal (the REPLIC-8
 * discipline, extended): a Beam 2 envelope that carries any of these key
 * shapes is refused BEFORE it is ever sealed or published — the engine
 * throws, it does not warn.
 */
export const SECRET_REFUSAL_KEY_RE =
  /(priv(ate)?)|(secret)|(token)|(mnemonic)|(seed)|(passphrase)|(password)|(recoveryWords)|(agrPriv)|(signPriv)/i

/** Typed refusal error — caught nowhere by design (the engine must throw). */
export function beam2SecretError(detail) {
  const e = new Error(`BEAM2_SECRET_REFUSAL: ${detail}`)
  e.code = 'BEAM2_SECRET_REFUSAL'
  return e
}

/**
 * Deep-scan an object for forbidden key shapes (the refusal set). Throws
 * beam2SecretError on the first hit. Arrays are walked; nested objects too.
 * @param {*} obj any envelope fragment about to ride the wire
 * @param {string} where a label naming the caller (for the typed message)
 */
export function assertNoSecretsRide(obj, where = 'envelope') {
  const walk = (node, path) => {
    if (node === null || node === undefined) return
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) walk(node[i], `${path}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const k of Object.keys(node)) {
        if (SECRET_REFUSAL_KEY_RE.test(k)) {
          throw beam2SecretError(`${where}: forbidden key "${k}" at ${path}.${k} — device private material never rides an envelope (law 0.54)`)
        }
        walk(node[k], `${path}.${k}`)
      }
      return
    }
  }
  walk(obj, '$')
}

/**
 * Generate the Beam 2 device keypair (ECDSA P-256, extractable — the public
 * half must serialize into the chain envelope; the private half is stored
 * ONLY in this device's local storage and never serialized outward by any
 * caller in this codebase; the refusal set above gates the wire).
 * @returns {Promise<{publicKey:CryptoKey, privateKey:CryptoKey}>}
 */
export async function generateDeviceKeyPair() {
  return crypto.subtle.generateKey(DEVICE_KEY_ALG, true, ['sign', 'verify'])
}

/** Export the PUBLIC half as JWK (the only half that ever leaves the device). */
export async function exportPublicKeyJwk(publicKey) {
  return crypto.subtle.exportKey('jwk', publicKey)
}

/**
 * Stable device identity hash for Beam 2: SHA-256 over the public JWK's
 * canonical coordinates → 32 hex chars (16 bytes). Deterministic for a
 * given key — the receiver can derive the sender's id from its published
 * public key and match the chain roster.
 */
export async function deviceKeyThumbprint(publicKeyJwk) {
  const material = `${publicKeyJwk.crv}|${publicKeyJwk.x}|${publicKeyJwk.y}`
  const digest = await crypto.subtle.digest('SHA-256', utf8Bytes(material))
  return bytesToHex(new Uint8Array(digest)).slice(0, 32)
}

/** Canonical JSON bytes: sorted keys, no whitespace — the signing input. */
export function canonicalJsonBytes(value) {
  const canon = (v) => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v)
    if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
    const keys = Object.keys(v).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`
  }
  return utf8Bytes(canon(value))
}

/** Sign canonical bytes with the device private key → base64 signature. */
export async function signWithDeviceKey(privateKey, bytes) {
  const sig = await crypto.subtle.sign(DEVICE_KEY_SIGN_ALG, privateKey, bytes)
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
}

/** Verify a base64 signature over canonical bytes against a public JWK. */
export async function verifyWithDeviceKey(publicKeyJwk, sigB64, bytes) {
  let key
  try {
    key = await crypto.subtle.importKey('jwk', publicKeyJwk, DEVICE_KEY_ALG, true, ['verify'])
  } catch {
    return false
  }
  let raw
  try {
    const bin = atob(String(sigB64 || ''))
    raw = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i)
  } catch {
    return false
  }
  try {
    return await crypto.subtle.verify(DEVICE_KEY_SIGN_ALG, key, raw, bytes)
  } catch {
    return false
  }
}

/**
 * Sign a Beam 2 control message's PAYLOAD (the inner object, before the
 * outer record envelope seals it). The signature covers the canonical
 * payload JSON — the receiver recomputes the same canonical bytes.
 * Law 0.54 gate: the refusal set runs FIRST — a payload carrying private
 * material is refused before any key touches it.
 */
export async function signPayloadWithDeviceKey(privateKey, payloadObj) {
  assertNoSecretsRide(payloadObj, 'signPayload')
  return signWithDeviceKey(privateKey, canonicalJsonBytes(payloadObj))
}

/**
 * Verify a Beam 2 control message's payload signature against the
 * chain-known public JWK of the claimed sender. Returns a typed verdict —
 * the caller MUST refuse to render the receive modal on `ok:false`
 * (law 0.54: signatures verified BEFORE the modal renders).
 */
export async function verifyPayloadAgainstChainKey(senderPubJwk, sigB64, payloadObj) {
  if (!senderPubJwk || typeof senderPubJwk !== 'object') {
    return { ok: false, reason: 'no-chain-key' }
  }
  if (!sigB64) return { ok: false, reason: 'no-signature' }
  try {
    const ok = await verifyWithDeviceKey(senderPubJwk, sigB64, canonicalJsonBytes(payloadObj))
    return { ok, reason: ok ? null : 'signature-mismatch' }
  } catch {
    return { ok: false, reason: 'verify-error' }
  }
}

/**
 * Get-or-create this device's Beam 2 keypair via the injected storage
 * adapter. Called at join time AND at every Beam 2 session start (idempotent
 * — the same key for the device's lifetime unless the user resets).
 * @param {() => Promise<any>} loadFn
 * @param {(v: any) => Promise<void>} saveFn
 */
export async function getOrCreateBeam2Identity(loadFn, saveFn) {
  const existing = await loadFn()
  if (existing && existing.pubJwk && existing.pkcs8) return existing
  const pair = await generateDeviceKeyPair()
  const pubJwk = await exportPublicKeyJwk(pair.publicKey)
  const pkcs8 = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))))
  const thumb = await deviceKeyThumbprint(pubJwk)
  const record = { pubJwk, pkcs8, thumb, createdAt: Date.now(), law: '0.54' }
  await saveFn(record)
  return record
}

/**
 * Rehydrate the signing CryptoKey from the stored record.
 * @returns {Promise<{privateKey:CryptoKey}|null>}
 */
export async function loadBeam2SigningKey(record) {
  if (!record || !record.pkcs8) return null
  try {
    const bin = atob(record.pkcs8)
    const raw = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i)
    const privateKey = await crypto.subtle.importKey('pkcs8', raw, DEVICE_KEY_ALG, true, ['sign'])
    return { privateKey }
  } catch {
    return null
  }
}

/**
 * Publish MY public key into the chain roster (the replication lane's
 * destination). The roster is a plain map deviceId → { pubJwk, at } — it
 * rides the chain envelope as config metadata (the class whitelist's
 * non-secret class) — a public key is not a secret.
 * @param {(key: string) => Promise<any>} loadFn
 * @param {(key: string, v: any) => Promise<void>} saveFn
 */
export async function publishToChainRoster(loadFn, saveFn, deviceId, pubJwk) {
  const roster = (await loadFn(BEAM2_CHAIN_KEYS_KEY)) || {}
  roster[deviceId] = { pubJwk, at: Date.now() }
  await saveFn(BEAM2_CHAIN_KEYS_KEY, roster)
  return roster
}

/** Look up a peer's chain-known public key (null when unknown → refuse). */
export async function chainKeyFor(loadFn, deviceId) {
  const roster = (await loadFn(BEAM2_CHAIN_KEYS_KEY)) || {}
  const entry = roster[deviceId]
  return entry && entry.pubJwk ? entry.pubJwk : null
}
