/**
 * UCrypt — R141 §7.4 — THE MAILBOX SEAL (the E2E layer, re-typed clean).
 *
 * Envelopes are sealed to the CHAIN (the established keys every member
 * already derives from the sync words) and SIGNED by the sender's device
 * identity — the ciphertext-only-at-the-backend law stands: the backend
 * stores opaque sealed bytes. The receiving device opens with its own
 * chain keys and verifies the sender's signature; a tampered or foreign
 * envelope is a typed refusal, never a fallback.
 *
 * The primitives are the SAME crypto lineage the vault sync uses
 * (lib/crypto.js AES-256-GCM string seals; ECDSA P-256 device keys) —
 * re-typed here with INJECTED subtle so the battery proves them without
 * the worker. No import from the retired transport.
 *
 * PURE (crypto injected) — battery-pinned (G91).
 */

import { mailboxError } from './protocol.js'

const te = new TextEncoder()
const td = new TextDecoder()

/** The group seal: AES-256-GCM under the chain's rendezvous-group plane key
 * (the same HKDF label the chain already derives — the established keys). */
export async function groupSeal(subtle, groupKey, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const pt = te.encode(JSON.stringify(obj))
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, groupKey, pt))
  const out = new Uint8Array(iv.length + ct.length)
  out.set(iv, 0); out.set(ct, iv.length)
  return bytesToB64(out)
}

export async function groupOpen(subtle, groupKey, b64) {
  let raw
  try { raw = b64ToBytes(String(b64 || '')) } catch { throw mailboxError('SEAL_SHAPE', 'the sealed envelope is not base64') }
  if (raw.length <= 12) throw mailboxError('SEAL_SHAPE', 'the sealed envelope is too short')
  const iv = raw.slice(0, 12)
  const ct = raw.slice(12)
  let pt
  try {
    pt = await subtle.decrypt({ name: 'AES-GCM', iv }, groupKey, ct)
  } catch {
    throw mailboxError('SEAL_FOREIGN', 'the sealed envelope did not open with this chain\u2019s keys')
  }
  try { return JSON.parse(td.decode(pt)) } catch { throw mailboxError('SEAL_SHAPE', 'the opened envelope is not valid JSON') }
}

/** The device signature over the canonical envelope bytes (ECDSA P-256). */
export async function signEnvelope(subtle, signPrivateKey, obj) {
  const data = te.encode(JSON.stringify(obj))
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signPrivateKey, data)
  return bytesToB64(new Uint8Array(sig))
}

export async function verifyEnvelopeSignature(subtle, signPublicKeyJwk, obj, sigB64) {
  let key
  try {
    key = await subtle.importKey('jwk', signPublicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  } catch {
    throw mailboxError('SIGNER_KEY', 'the sender\u2019s signing key is malformed')
  }
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64ToBytes(String(sigB64 || '')), te.encode(JSON.stringify(obj)))
  if (!ok) throw mailboxError('SIGNATURE', 'the envelope\u2019s signature does not verify')
  return true
}

/** The sender's address: HMAC-SHA-256 over the member id under the chain's
 * locator plane key — a member's inbox path is unguessable off-chain. */
export async function memberAddress(locatorKeyBits, memberId) {
  const key = await crypto.subtle.importKey('raw', locatorKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(memberId))))
  return [...mac].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32)
}

export function bytesToB64(bytes) {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s)
}

export function b64ToBytes(b64) {
  const s = atob(String(b64 || ''))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}
