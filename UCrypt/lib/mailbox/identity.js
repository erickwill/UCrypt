/**
 * UCrypt — R141 §7.2 — THE MAILBOX IDENTITY (matrix row 43: stable for life).
 *
 * Each device has ONE persisted mailbox identity — created ONCE at bonding,
 * never regenerated across reloads, restarts, or extension updates. Names
 * come from the roster; the default at creation is "<Browser> on <OS>";
 * the nameless placeholder class is banned everywhere (the R141 copy lint). Mailbox addresses derive from this
 * identity (the member id IS the transfer-plane device id — the chain's
 * roster already carries it).
 *
 * Re-typed clean: the persistence is INJECTED (a get/set pair), the crypto
 * is the platform subtle, the seal key is the chain's device-registry plane
 * key — the same discipline the chain already uses. Nothing imports the
 * retired transport. PURE-able — the battery drives an injected storage.
 *
 * PURE (storage/crypto injected) — battery-pinned (G91 identity-stability
 * rows, the simulated-restart proof).
 */

const te = new TextEncoder()
const td = new TextDecoder()

export const MAILBOX_IDENTITY_VERSION = 1

function hex(bytes) { return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('') }

/** The default name law (R140 §6.1 carried forward): "<Browser> on <OS>". */
export function defaultDeviceName(userAgent = '') {
  const ua = String(userAgent || '')
  let browser = 'Browser'
  if (/Edg\//.test(ua)) browser = 'Edge'
  else if (/OPR\//.test(ua)) browser = 'Opera'
  else if (/Brave/.test(ua)) browser = 'Brave'
  else if (/Chrome\//.test(ua)) browser = 'Chrome'
  else if (/Firefox\//.test(ua)) browser = 'Firefox'
  let os = 'an unknown system'
  if (/Windows/.test(ua)) os = 'Windows'
  else if (/Android/.test(ua)) os = 'Android'
  else if (/Linux/.test(ua)) os = 'Linux'
  else if (/Mac OS X/.test(ua)) os = 'macOS'
  else if (/CrOS/.test(ua)) os = 'ChromeOS'
  return `${browser} on ${os}`
}

/** Load-or-create. The identity is a plain JSON record sealed under the
 * device-registry key: {deviceId, label, signPubJwk, agrPubJwk, signPrivJwk,
 * agrPrivJwk, createdAt}. A restart reloads the SAME record (the battery
 * proves identity across a simulated restart with a fresh storage handle). */
export async function getOrCreateMailboxIdentity({ storage, registryKey, subtle = crypto.subtle, userAgent = '', rosterName = null, sealFn = null, openFn = null } = {}) {
  if (!storage || typeof storage.get !== 'function' || typeof storage.set !== 'function') {
    throw new Error('MAILBOX_IDENTITY_STORAGE: the identity needs an injected storage')
  }
  const KEY = 'ucrypt:mailbox:identity'
  const { [KEY]: sealed } = await storage.get(KEY)
  if (sealed) {
    try {
      const json = openFn
        ? await openFn(sealed, registryKey)
        : td.decode(await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64ToBytes(sealed).slice(0, 12)) }, registryKey, b64ToBytes(sealed).slice(12)))
      const rec = JSON.parse(json)
      if (rec && rec.v === MAILBOX_IDENTITY_VERSION && rec.deviceId && rec.signPrivJwk && rec.agrPrivJwk) {
        return { ...rec, label: typeof rec.label === 'string' && rec.label.trim() ? rec.label : defaultDeviceName(userAgent) }
      }
    } catch { /* a seal that no longer opens recreates — the same law as the chain identity */ }
  }
  const deviceId = hex(crypto.getRandomValues(new Uint8Array(16)))
  const signKeys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const agrKeys = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  const signPubJwk = await subtle.exportKey('jwk', signKeys.publicKey)
  const agrPubJwk = await subtle.exportKey('jwk', agrKeys.publicKey)
  const signPrivJwk = await subtle.exportKey('jwk', signKeys.privateKey)
  const agrPrivJwk = await subtle.exportKey('jwk', agrKeys.privateKey)
  const { d: _dropSign, ...signPubClean } = signPubJwk
  const { d: _dropAgr, ...agrPubClean } = agrPubJwk
  const label = (typeof rosterName === 'string' && rosterName.trim() && !/unnamed device/i.test(rosterName))
    ? rosterName.trim().slice(0, 60)
    : defaultDeviceName(userAgent)
  const rec = {
    v: MAILBOX_IDENTITY_VERSION, deviceId, label,
    signPubJwk: signPubClean, agrPubJwk: agrPubClean,
    signPrivJwk, agrPrivJwk, createdAt: Date.now(),
  }
  const json = JSON.stringify(rec)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, registryKey, te.encode(json)))
  const sealedOut = b64(new Uint8Array([...iv, ...ct]))
  await storage.set(KEY, sealedOut)
  return rec
}

function b64(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}
function b64ToBytes(b64s) {
  const s = atob(String(b64s || ''))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}
