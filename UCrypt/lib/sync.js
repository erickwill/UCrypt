/**
 * UCrypt Sync — sync-code cryptography (v2.3.0).
 *
 * The sync code is a 24-word BIP-39 mnemonic (~256-bit entropy + 8-bit
 * checksum). It is the ONLY credential: PBKDF2-derived into an AES-GCM key
 * that encrypts the vault before it touches any transport. Servers see
 * ciphertext only.
 *
 * v2.2.0: removed the "public relay" (kvdb.io) transport claimed in v2.1.0 —
 * it used the wrong HTTP verb (POST instead of PUT for kv writes), depended
 * on a third-party service with no SLA, and was never reachable from the UI
 * anyway (audit finding #8). Transport selection lives in lib/transports/.
 *
 * v2.3.0: VERSIONED sync KDF. The sync key was still derived at 210k
 * iterations while the master passphrase moved to 600k (OWASP 2023). New
 * setups derive at 600k (version 2); records from v2.2.0 and earlier are
 * transparently derived at 210k (version 1) so nothing breaks, and the
 * options UI offers an explicit one-click upgrade that re-derives and
 * re-pushes the encrypted blob.
 */

import { deriveKey, encryptString, decryptString, secureRandomBytes, sha256 } from './crypto.js'
// R119 v1.5 — the /k/ segment's mode flag validates against the ladder's
// signin-mode allowlist (the SAME words the ladder records on the transport
// config). ladder.js is engine-only (no DOM, no chrome.i18n, no imports) —
// a leaf dependency by construction, no cycle.
import { isSigninMode } from './ladder.js'

// Deterministic salt: the sync code is already high-entropy, so the salt does
// not need per-device randomness — it must be identical on every device.
const SYNC_SALT = new Uint8Array([67, 114, 121, 112, 116, 75, 101, 121, 83, 121, 110, 99, 83, 97, 108, 116])

// --- Versioned sync KDF (v2.3.0) -------------------------------------------

/** Version used for all NEW sync-code setups. */
export const SYNC_KDF_VERSION = 2

/** PBKDF2 iteration counts per version. v1 = v2.2.0 and earlier. */
export const SYNC_KDF_ITERATIONS = { 1: 210000, 2: 600000 }

/**
 * Derive the AES-GCM sync key from a mnemonic at an explicit KDF version.
 * Every device holding the same sync code must use the SAME version — that
 * is why the version is persisted alongside the stored sync code instead of
 * silently floating with the app version.
 */
export async function deriveSyncKey(mnemonic, version = SYNC_KDF_VERSION) {
  const iterations = SYNC_KDF_ITERATIONS[version]
  if (!iterations) throw new Error(`Unknown sync KDF version: ${version}`)
  return deriveKey(mnemonic.replace(/[\s\-]+/g, ' ').trim(), SYNC_SALT, iterations)
}

// --- BIP-39 sync code generation -------------------------------------------

function getWordlist() {
  if (typeof globalThis !== 'undefined' && globalThis.CRYPTKEY_BIP39) return globalThis.CRYPTKEY_BIP39
  throw new Error('BIP-39 wordlist not loaded. Ensure wordlists.js is loaded before sync.js.')
}

export async function generateSyncCode() {
  const wl = getWordlist()
  if (wl.length < 2048) throw new Error('BIP-39 wordlist too small (need 2048 words)')

  const entropy = secureRandomBytes(32) // 256 bits → 24 words
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy))
  let bits = ''
  for (const b of entropy) bits += b.toString(2).padStart(8, '0')
  bits += hash[0].toString(2).padStart(8, '0').slice(0, 8) // 8-bit checksum

  const words = []
  for (let i = 0; i < bits.length; i += 11) words.push(wl[parseInt(bits.slice(i, i + 11), 2)])

  return {
    words,
    mnemonic: words.join(' '),
    qrUri: 'ucrypt-sync://' + words.join('-'),
  }
}

export async function validateSyncCode(mnemonic) {
  const wl = getWordlist()
  const words = mnemonic.trim().toLowerCase().split(/[\s\-]+/).filter(Boolean)
  if (words.length !== 24) return { valid: false, reason: `Expected 24 words, got ${words.length}` }

  const ws = new Set(wl)
  for (const w of words) if (!ws.has(w)) return { valid: false, reason: `Unknown word: "${w}"` }

  let bits = ''
  for (const w of words) bits += wl.indexOf(w).toString(2).padStart(11, '0')
  const entropyStr = bits.slice(0, 256), checksumStr = bits.slice(256)
  const entBytes = []
  for (let i = 0; i < entropyStr.length; i += 8) entBytes.push(parseInt(entropyStr.slice(i, i + 8), 2))
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(entBytes)))
  const expected = hash[0].toString(2).padStart(8, '0').slice(0, 8)
  if (checksumStr !== expected) return { valid: false, reason: 'Checksum mismatch — a word may be wrong' }
  return { valid: true, words }
}

export async function deriveSyncKeyLegacy(mnemonic) {
  return deriveSyncKey(mnemonic, 1)
}

// --- R95 F-95-03 — the FULL PAIRING PAYLOAD (the CEO's "Brave-Sync-style"
// complete solution) ---------------------------------------------------------
//
// The canonical words-only carrier stays byte-identical to the shipped seal
// format ('ucrypt-sync://w1-w2-…-w24' — lib/sync.js + lib/vault.js:2030 are
// the two canonical builders; nothing changes for the default flow). The
// OPTIONAL full form rides the cloud LOCATION next to the words so the
// joining device does not have to guess the provider or retype the address:
//
//   ucrypt-pairing-v1://w/<w1-…-w24>/p/<provider>[/u/<address>][/c/<creds>]
//
// SECRET LAW (0.14) — what may ride, machine-enforced by safeCloudForPairing:
//   RIDES:    the provider id and, ONLY for user-typed-URL providers, the
//             address with ANY embedded userinfo (user:pass@) stripped.
//   NEVER:    tokens, passwords, headers, cookies, the vault, the master
//             passphrase — the joiner still signs in once (law 0.13's
//             "+1 sign-in where OAuth applies" is exactly this boundary).
//
// R102 PAYLOAD LAW v1.1 (the Join Symphony, J1) — the OPTIONAL COMPLETE
// pairing: under a SECOND, separately-labeled opt-in ("Complete pairing",
// default OFF, never persisted), the user-typed-URL provider's OWN sign-in
// (WebDAV username + password) may ride a versioned, size-capped, allowlisted
// /c/ segment so the joining device can connect automatically — Brave's
// code-arrives-everything experience, still zero-infrastructure:
//
//   /c/<base64url(JSON { v:1, u:<user>, p:<pass> })>
//
//   RIDES (complete only):  webdav config.user + config.pass — the exact
//             pair the origin itself authenticates with, carried ONCE.
//   NEVER:     headers, cookies, the vault, the master passphrase.
//
// R110 PAYLOAD LAW v1.4 ("The Whole Credential" — the CEO's direct order,
// amending 0.14): the pairing code carries the COMPLETE cloud configuration.
// The client secret (when present on the origin) and the user's OWN OAuth
// grant now ride — under the "Include sign-in credentials" toggle, which
// DEFAULTS ON (CEO-pinned, law 0.15). The secret and the grant are sealed
// for TRANSIT under a key derived from the 24 words (HKDF-SHA-256 — the
// mnemonic is 256-bit entropy, so a fast KDF is sound) and ride the /k/
// segment as OPAQUE base64url blobs: no log, no diagnostic, no scan surface
// can ever render the values — the booleans (secret-carried / grant-carried)
// are all any observer gets. The joiner re-seals them under ITS OWN vault
// key on arrival. OAuth tokens other than the user's own grant never ride.
// The QR degrades truthfully when capacity forces it — the drop order is
// PINNED (0.14): address → grant → secret → client ID → words-only; the
// copied code always carries everything.
//
//   /k/<base64url(JSON { v:3, cid, b, s, g })>
//     s = the client secret, transit-sealed (≤256 b64url chars)
//     g = the OAuth grant, transit-sealed   (≤1024 b64url chars)
//   v2 (cid/b only) and v1 remain parseable — additions-only, never a break.
//   PARSER IS THE TRUST BOUNDARY (unchanged, extended): the joiner-side
//   parser re-validates EVERYTHING — base64url decode, JSON, the {v,u,p}
//   allowlist (unknown fields rejected BY CONSTRUCTION), version pin (v=1),
//   per-field length caps — and the /u/ userinfo strip stays UNCONDITIONAL
//   even when a complete /c/ segment rides next to it.
//   Both ends print the same one-sentence truth: "Anyone with this code can
//   read your cloud backup — like Brave's sync code. Keep it only where you
//   keep passwords."
//
// R119 PAYLOAD LAW v1.5 ("The Sign-In Ladder", order §3.6 — ADDITIONS-ONLY):
// the /k/ segment gains the ladder's MODE FLAG m ∈ {'fast','guided','manual'}
// — carried when the origin's cloud.conn.m is present AND isSigninMode(m)
// (the ladder records signinMode on the transport config when a connection
// is made; the allowlist here is the SAME table). Pinned cap: 12 chars —
// junk degrades THAT FIELD ONLY (fail-closed per field, fail-open on words
// — the established parser law). All v1.4 caps stand UNCHANGED.
//
//   /k/<base64url(JSON { v:4, cid, b, s?, g?, m })>
//
//   THE SECRET/GRAIN DISCIPLINE (the core of v1.5): when the origin's mode
//   is 'fast', the sealed s/g segments MUST NOT ride — dropped even when the
//   caller passed them. The fast connection is DEVICE-LOCAL (the browser's
//   own account — nothing to carry); the joiner's own fast rung lights from
//   the shared client ID (law 0.23: the client ID always rides — cid
//   behavior unchanged). 'guided'/'manual' keep the v1.4 behavior EXACTLY:
//   the transit-sealed opaque blobs ride when the caller passed them (zero
//   regression, law 0.14 untouched — s/g stay the worker-sealed blobs).
//   VERSIONS: v4 when m rides; v3 when s/g ride without m; v2 when only
//   cid/b — the parser accepts v2/v3/v4 (additions-only, never a break).
//   The transparency names moved with the law: pairingSegmentNames(conn)
//   below is the pure carried-segments list — a fast origin's list NEVER
//   names the sign-in credentials.

const PAIRING_PROVIDER_URL_FIELDS = {
  webdav: 'url',
  custom: 'url',
}

// R102 payload law v1.1 — the credential field allowlist per provider.
// ONLY webdav carries distinct stored credentials (user + pass); custom
// stores its auth inside the URL itself (already covered by the location
// opt-in, userinfo always stripped), and the OAuth transports' grants are
// categorically NEVER giftable. The list IS the law: a provider not named
// here can never emit a /c/ segment.
// R106 payload law v1.2 — the NON-SECRET connection-parameter allowlist per
// provider (the owner's S1: the cloud service data rides the code so the
// joiner's setup is one click). cid = the PUBLIC OAuth client id; b = the
// bridge /exec URL (an address, not a credential). Secrets are categorically
// excluded — 0.14 stands unchanged; the list IS the law.
const PAIRING_CONN_FIELDS = {
  // R108 §2.3 — the keys are the TRANSPORT RECORD's REAL config keys (what
  // the wizard's Save writes), not the card labels: gdrive stores its client
  // ID under "clientId" (the wizard's idField) — v1.2 read "oauthClientId"
  // here, a key the gdrive record NEVER carries (the live forensic caught
  // it: even an opted-in code emitted no client ID). github's card key IS
  // "oauthClientId"; dropbox's is "appKey". The joiner-side landing map
  // (PAIRING_CONN_FIELD_TARGETS) mirrors these.
  // R119 v1.5 — m: the origin's ladder rung (config.signinMode — the SAME
  // allowlist lib/ladder.js validates) rides the projection so the /k/
  // builder can carry it; the builder re-validates with isSigninMode before
  // anything ships (junk never rides). Additive: a record without
  // signinMode projects exactly as v1.4 did.
  gdrive: { cid: 'clientId', b: 'url', m: 'signinMode' },
  github: { cid: 'oauthClientId', m: 'signinMode' },
  // R108 §2.3 — dropbox's client ID is its APP KEY on the card (the wizard's
  // idField is "appKey"); v1.2 read "oauthClientId" here, a config key the
  // dropbox transport never stores — the same bug class the CEO caught on
  // gdrive. The allowlist now reads the REAL field.
  dropbox: { cid: 'appKey', m: 'signinMode' },
}
const PAIRING_CRED_FIELDS = {
  webdav: { user: 'user', pass: 'pass' },
}

/** R108 §2.3 — the joiner-side twin of PAIRING_CONN_FIELDS: where each
 * provider's carried client ID lands in the transport wizard (the REAL card
 * field keys — the forensic's second root cause: v1.2 wrote github's key
 * onto every card, so gdrive's "clientId" and dropbox's "appKey" stayed
 * empty). Exported so the battery pins the pairing; options.js consumes it. */
export const PAIRING_CONN_FIELD_TARGETS = {
  gdrive: 'clientId',
  github: 'oauthClientId',
  dropbox: 'appKey',
}
/** The bridge /exec URL's landing keys, in preference order (gdrive's bridge
 * card uses "scriptUrl"; a generic url field stays the fallback). */
export const PAIRING_CONN_BRIDGE_TARGETS = ['scriptUrl', 'url']

/** Field length caps for the /c/ segment (defence in depth — a hostile or
 * bloated code must be refused before any consumer renders it). */
export const PAIRING_CREDS_CAPS = { b64: 512, field: 256 }

/** R110 payload law v1.4 — the lawful cap growth for the sealed-credential
 * era: the transit-sealed secret (≤256 b64url) and grant (≤1024 b64url) ride
 * the /k/ segment, whose whole cap grows to 2048 b64url chars. The PLAINTEXT
 * admission bounds are DERIVED from the post-seal caps (the gauntlet's
 * finding: an admission bound larger than what the post-seal cap can hold
 * would make the builder drop lawful values — the bounds below keep EVERY
 * admitted value sealable by construction):
 *   secret:  256 b64url = 192 bytes − 28 B overhead (IV+tag) → 164 → 160 chars
 *   grant:  1024 b64url = 768 bytes − 28 B overhead → 740 → 700 chars
 * These numbers ARE the law: the builder refuses larger values, the parser
 * drops them, the battery pins them. (A Google GOCSPX secret is ~35 chars —
 * both bounds carry generous headroom over the real shapes.) */
export const PAIRING_V14_CAPS = {
  secretPlain: 160, grantPlain: 700,
  secretB64: 256, grantB64: 1024,
  kSegB64: 2048,
}

/** R119 payload law v1.5 — the mode flag's ONLY new cap: a signin mode is
 * one of the three pinned words (isSigninMode — lib/ladder.js), capped at
 * 12 chars as defence in depth. Every v1.4 cap stands UNCHANGED above —
 * this constant adds, it never widens. */
export const PAIRING_V15_CAPS = { modeChars: 12 }

/** R110 v1.4 — the sealed-credential field allowlist per provider (the law
 * in one table): ONLY these config fields may ever be projected for transit
 * sealing, ONLY for the named provider. webdav keeps its /c/ v1 sign-in
 * (unchanged since v1.1); custom's URL auth stays covered by the unconditional
 * /u/ userinfo strip (0.14 unchanged there); github/dropbox grants are not
 * named — a provider absent from this table can never emit s/g. */
export const PAIRING_SECRET_FIELDS = {
  gdrive: { secret: 'clientSecret', grant: 'refreshToken' },
}

/** R110 v1.4 — the PINNED QR drop order (0.14): when the QR band cannot hold
 * the whole carrier, segments drop in exactly this sequence, every rung named
 * on the surface. Exported so the battery pins the ladder and the renderer
 * derives its rung lines from the same law. */
export const PAIRING_QR_DROP_ORDER = ['address', 'grant', 'secret', 'cid']

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlDecode(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

// --- R110 v1.4 — THE TRANSIT SEAL --------------------------------------------
//
// The client secret and the OAuth grant ride the pairing code SEALED under a
// key derived from the 24 words. The mnemonic is 256 bits of entropy with an
// 8-bit checksum, so HKDF-SHA-256 (a fast, salted, domain-separated extract-
// and-expand over the normalized words) is the sound KDF — no password-grade
// stretching is needed, and the derivation stays fast enough to run inside
// the sheet's render. The blobs are AES-GCM (encryptString: random 96-bit IV
// + auth tag) rendered base64url — OPAQUE to every parser, log, diagnostic
// and scan surface; only the words open them. Domain separation keeps the
// transit key independent from the vault's sync key (a compromised transit
// blob never helps an attacker against the vault envelope).

const TRANSIT_SALT = 'ucrypt:pairing-transit-salt:v1'
const TRANSIT_INFO = 'ucrypt:pairing-transit-key:v1'

/** Normalize the 24 words EXACTLY like deriveSyncKey does (whitespace/
 * hyphen collapse, trim, lowercase) so origin and joiner derive the same
 * transit key from the same code. */
function transitMnemonicInput(words) {
  const list = (Array.isArray(words) ? words : String(words || '').split(/[\s-]+/))
    .map((w) => String(w).trim().toLowerCase()).filter(Boolean)
  if (list.length !== 24) throw new Error('The transit seal needs exactly 24 words')
  return list.join(' ')
}

/** Derive the pairing-code transit key (AES-GCM, 256-bit) from the words. */
export async function derivePairingTransitKey(words) {
  const norm = transitMnemonicInput(words)
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(TRANSIT_SALT), info: new TextEncoder().encode(TRANSIT_INFO) },
    base, 256,
  )
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

// F-R110-CAPS-1 (found by the R110 gauntlet): encryptString already emits
// standard base64 — encoding THAT again inflated every blob ×1.34 and pushed
// lawful values over the post-seal caps. The transit blob is therefore the
// sealed envelope's base64 rendered base64URL-SAFE directly (same length).
const b64ToB64url = (s) => String(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const b64urlToB64 = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/')
  return t + '='.repeat((4 - (t.length % 4)) % 4)
}

/** Seal ONE credential value for transit → an opaque base64url blob.
 * Throws on any failure — the caller (the worker) degrades by OMITTING the
 * segment, never by shipping a weaker form. */
export async function sealCredentialForTransit(value, words) {
  const key = await derivePairingTransitKey(words)
  const packed = await encryptString(String(value), key)
  return b64ToB64url(packed)
}

/** Open ONE transit-sealed credential blob with the words → the plaintext.
 * Fail-closed: any size, shape, base64 or AEAD failure throws — the joiner
 * then reports the typed truth ("the sign-in did not arrive intact") and
 * falls back to the one-click sign-in card. */
export async function openCredentialFromTransit(blob, words) {
  const s = String(blob || '')
  if (!s || s.length > PAIRING_V14_CAPS.grantB64 || !/^[A-Za-z0-9_-]+$/.test(s)) {
    throw new Error('The sealed credential segment failed the shape check')
  }
  const key = await derivePairingTransitKey(words)
  return decryptString(b64urlToB64(s), key)
}

/** Strip userinfo from a URL string; null when the URL is unusable. */
function stripUrlUserinfo(raw) {
  try {
    const u = new URL(String(raw))
    u.username = ''
    u.password = ''
    const out = u.toString()
    return out || null
  } catch { return null }
}

/**
 * The secret-law allowlist: from a FULL transport record (which may hold
 * secrets) extract ONLY the non-secret fields the pairing payload may carry.
 * Everything else (tokens, passwords, headers) is ignored BY CONSTRUCTION —
 * a caller may pass the whole record; this function decides what survives.
 */
/**
 * The secret-law allowlist: from a FULL transport record (which may hold
 * secrets) extract ONLY the non-secret fields the pairing payload may carry.
 * Everything else (tokens, passwords, headers) is ignored BY CONSTRUCTION —
 * a caller may pass the whole record; this function decides what survives.
 *
 * R102 v1.1: opts.complete opts IN the provider's own stored sign-in — but
 * ONLY for providers named in PAIRING_CRED_FIELDS, ONLY when BOTH fields are
 * non-empty, and ONLY as the versioned /c/ payload. Every other provider
 * (OAuth transports especially) can never emit credentials, with or without
 * the opt-in.
 */
export function safeCloudForPairing(transport, opts = {}) {
  const t = transport && typeof transport === 'object' ? transport : null
  const id = String((t && t.id) || '').trim()
  if (!id) return null
  const config = (t && t.config && typeof t.config === 'object') ? t.config : {}
  const urlField = PAIRING_PROVIDER_URL_FIELDS[id]
  let url = null
  if (urlField) {
    const rawUrl = String(config[urlField] || '').trim()
    if (rawUrl) url = stripUrlUserinfo(rawUrl)
  }
  let creds = null
  const credFields = PAIRING_CRED_FIELDS[id]
  if (opts.complete && credFields) {
    const u = String(config[credFields.user] || '')
    const p = String(config[credFields.pass] || '')
    if (u && p && u.length <= PAIRING_CREDS_CAPS.field && p.length <= PAIRING_CREDS_CAPS.field) {
      creds = { u, p }
    }
  }
  // v1.2: the non-secret connection parameters ride when present (allowlist + caps)
  let conn = null
  const connFields = PAIRING_CONN_FIELDS[id]
  if (connFields && config) {
    conn = {}
    for (const [k, f] of Object.entries(connFields)) {
      const v = String(config[f] || '').trim()
      if (v && v.length <= PAIRING_CREDS_CAPS.field) conn[k] = v
    }
    if (!Object.keys(conn).length) conn = null
  }
  // R110 v1.4 — under the toggle (complete), the WHOLE credential projects:
  // the gdrive client secret and the user's own OAuth grant ride as RAW
  // values HERE — the WORKER is this function's only complete-mode caller
  // (vault.js completeCloudForPairing) and it transit-seals them into opaque
  // blobs BEFORE the projection reaches any page. A raw secret/grant must
  // never survive past the worker boundary — the sealing step in vault.js is
  // the enforcement, and the no-secrets diagnostics gate re-proves it each
  // round. Plaintext admission caps are lawful (see PAIRING_V14_CAPS).
  let secret = null
  let grant = null
  const secretFields = PAIRING_SECRET_FIELDS[id]
  if (opts.complete && secretFields && config) {
    const s = String(config[secretFields.secret] || '')
    const g = String(config[secretFields.grant] || '')
    if (s && s.length <= PAIRING_V14_CAPS.secretPlain) secret = s
    if (g && g.length <= PAIRING_V14_CAPS.grantPlain) grant = g
  }
  return {
    provider: id,
    ...(url ? { url } : {}),
    ...(creds ? { creds } : {}),
    ...(conn ? { conn } : {}),
    ...(secret ? { secret } : {}),
    ...(grant ? { grant } : {}),
  }
}

/**
 * Build the pairing carrier. words-only (no cloud argument) is byte-identical
 * to the seal format. With cloud, the full pairing URI is emitted.
 */
export function buildPairingUri(words, cloud = null) {
  const list = Array.isArray(words) ? words.map((w) => String(w).trim()).filter(Boolean) : []
  if (!cloud || !cloud.provider) return 'ucrypt-sync://' + list.join('-')
  let uri = 'ucrypt-pairing-v1://w/' + list.join('-') + '/p/' + encodeURIComponent(String(cloud.provider))
  if (cloud.url) uri += '/u/' + encodeURIComponent(String(cloud.url))
  // R102 v1.1 — the complete-pairing /c/ segment: versioned JSON, base64url,
  // allowlisted fields only (the allowlist ran in safeCloudForPairing; this
  // builder refuses anything else by construction).
  if (cloud.creds && typeof cloud.creds === 'object' && cloud.creds.u && cloud.creds.p) {
    const payload = { v: 1, u: String(cloud.creds.u), p: String(cloud.creds.p) }
    const b64 = b64urlEncode(JSON.stringify(payload))
    if (b64.length <= PAIRING_CREDS_CAPS.b64) uri += '/c/' + b64
  }
  // v1.2 → R110 v1.4 → R119 v1.5 — the /k/ segment: the non-secret connection
  // parameters PLUS the transit-sealed credential blobs (s = the client
  // secret, g = the OAuth grant — OPAQUE base64url strings handed over by the
  // worker's sealing step; this builder never sees plaintext credentials).
  // R119 v1.5 — the ladder's MODE FLAG: m rides when present AND lawful
  // (isSigninMode — junk degrades to absent, the builder never ships a junk
  // m), and the SECRET/GRAIN DISCIPLINE holds: a FAST origin's s/g MUST NOT
  // ride — dropped even when the caller passed them (the fast connection is
  // device-local; the joiner's own fast rung lights from the shared client
  // ID). guided/manual keep the v1.4 behavior EXACTLY (zero regression).
  // Version decision: v4 when m rides; v3 when s/g ride without m; v2 when
  // only cid/b — the parser accepts v2/v3/v4 (additions-only, never a break).
  if (cloud.conn && typeof cloud.conn === 'object') {
    const c = {}
    if (cloud.conn.cid) c.cid = String(cloud.conn.cid).slice(0, PAIRING_CREDS_CAPS.field)
    if (cloud.conn.b) c.b = String(cloud.conn.b).slice(0, PAIRING_CREDS_CAPS.field)
    const m = isSigninMode(cloud.conn.m) ? cloud.conn.m : null
    const fast = m === 'fast'
    if (!fast && cloud.conn.s && typeof cloud.conn.s === 'string'
      && cloud.conn.s.length <= PAIRING_V14_CAPS.secretB64
      && /^[A-Za-z0-9_-]+$/.test(cloud.conn.s)) c.s = cloud.conn.s
    if (!fast && cloud.conn.g && typeof cloud.conn.g === 'string'
      && cloud.conn.g.length <= PAIRING_V14_CAPS.grantB64
      && /^[A-Za-z0-9_-]+$/.test(cloud.conn.g)) c.g = cloud.conn.g
    if (m) c.m = m
    if (c.cid || c.b || c.s || c.g || c.m) {
      const kb64 = b64urlEncode(JSON.stringify({ v: c.m ? 4 : ((c.s || c.g) ? 3 : 2), ...c }))
      if (kb64.length <= PAIRING_V14_CAPS.kSegB64) uri += '/k/' + kb64
    }
  }
  return uri
}

/**
 * Parse EITHER carrier. Returns:
 *   { words: [24 strings], provider?: string, url?: string, creds?: {u,p} }
 * or null when the input carries no 24-word payload (never throws — the join
 * wizard's own validation reports the typed error).
 */
// R130 (FINDING R130-F1 — the fuzz's first product find, law 0.44): the
// parser is the trust boundary, so its entry coercion must hold for ANY
// input — String({ toString: null }) THROWS ("Cannot convert object to
// primitive value"), and a throwing entry is a crash the hostile zoo can
// reach without ever touching the regex. The coercion degrades a hostile
// object to '' (the typed-refusal path) instead of throwing. Lawful inputs
// are untouched: strings ride, null/undefined coerce to '', numbers and
// booleans stringify as before.
function safeText(v) {
  if (typeof v === 'string') return v
  if (v === null || v === undefined || typeof v !== 'object') return String(v ?? '')
  try { return String(v) } catch { return '' }
}

export function parsePairingUri(raw) {
  const s = safeText(raw).trim()
  if (!s) return null
  const full = s.match(/^ucrypt-pairing-v1:\/\/w\/([^/\s]+)\/p\/([^/\s]+)(?:\/u\/([^/\s]+))?(?:\/c\/([A-Za-z0-9_-]+))?(?:\/k\/([A-Za-z0-9_-]+))?\/?$/i)
  if (full) {
    const words = full[1].split(/[\s-]+/).filter(Boolean)
    if (words.length !== 24) return null
    let provider = null
    try { provider = decodeURIComponent(full[2]) } catch { provider = full[2] }
    let url = null
    if (full[3]) {
      try { url = decodeURIComponent(full[3]) } catch { url = full[3] }
      // R95 (live-proof defect): the PARSER is the trust boundary for
      // INCOMING payloads — a hand-built or hostile URI may carry embedded
      // userinfo (user:pass@). The sender's allowlist strips it at build
      // time; the joiner strips it HERE too, so no consumer of the parsed
      // payload can ever render or prefill a credential-bearing address.
      // R102 v1.1: UNCONDITIONAL — even a complete code with a /c/ segment
      // never carries userinfo in /u/; credentials ride /c/ alone.
      url = stripUrlUserinfo(url)
      if (!url) url = null
    }
    // R102 v1.1 — the /c/ complete-pairing segment. Fail-closed on creds,
    // fail-open on words: ANY violation (size, base64, JSON, the {v,u,p}
    // allowlist, the version pin, field caps) drops the credentials and the
    // code degrades to the location-only form. Unknown fields are rejected
    // BY CONSTRUCTION — the parsed object can only ever carry u and p.
    let creds = null
    if (full[4]) {
      try {
        if (full[4].length <= PAIRING_CREDS_CAPS.b64) {
          const obj = JSON.parse(b64urlDecode(full[4]))
          if (obj && typeof obj === 'object' && obj.v === 1
            && typeof obj.u === 'string' && typeof obj.p === 'string'
            && obj.u.length > 0 && obj.p.length > 0
            && obj.u.length <= PAIRING_CREDS_CAPS.field
            && obj.p.length <= PAIRING_CREDS_CAPS.field
            && Object.keys(obj).every((k) => k === 'v' || k === 'u' || k === 'p')) {
            creds = { u: obj.u, p: obj.p }
          }
        }
      } catch { creds = null }
    }
    // v1.2 → R110 v1.4 → R119 v1.5 — the /k/ segment: typed parse, allowlisted
    // fields only (v, cid, b, s, g, m), junk degrades to null (never throws —
    // the joiner's own flow reports). The sealed blobs (s/g) pass through as
    // OPAQUE strings: the parser is the trust boundary but never the crypto
    // boundary — only the 24 words open them (openCredentialFromTransit).
    // Any cap violation or shape violation drops THAT field (fail-closed
    // per field, fail-open on words) — an oversize blob degrades to the
    // remaining fields, never to a refusal of the code.
    // R119 v1.5 — the version pin widens additively to v4 and the allowlist
    // gains 'm': the mode flag parses ONLY on v4 (the version law's parse
    // side — m never rides v2/v3) and only when isSigninMode passes within
    // the pinned 12-char cap; junk, oversize or a non-string m drops THAT
    // FIELD ONLY. The sealed blobs keep their exact v1.4 shape law and now
    // ride v3 (no m) or v4 (a guided/manual m beside them) — a v4 m:'fast'
    // never strips them here: the parser validates per field, it does not
    // second-guess the origin (the fast discipline lives on the BUILDER).
    let conn = null
    if (full[5]) {
      try {
        if (full[5].length <= PAIRING_V14_CAPS.kSegB64) {
          const obj = JSON.parse(b64urlDecode(full[5]))
          if (obj && typeof obj === 'object' && (obj.v === 2 || obj.v === 3 || obj.v === 4)
            && Object.keys(obj).every((k) => k === 'v' || k === 'cid' || k === 'b' || k === 's' || k === 'g' || k === 'm')) {
            conn = {}
            if (typeof obj.cid === 'string' && obj.cid && obj.cid.length <= PAIRING_CREDS_CAPS.field) conn.cid = obj.cid
            if (typeof obj.b === 'string' && obj.b && obj.b.length <= PAIRING_CREDS_CAPS.field) conn.b = obj.b
            // R119 v1.5 — the mode flag (v4 only): lawful signin mode within
            // the pinned cap; anything else degrades THAT FIELD ONLY.
            if (obj.v === 4 && typeof obj.m === 'string' && obj.m
              && obj.m.length <= PAIRING_V15_CAPS.modeChars && isSigninMode(obj.m)) conn.m = obj.m
            if ((obj.v === 3 || obj.v === 4) && typeof obj.s === 'string' && obj.s && obj.s.length <= PAIRING_V14_CAPS.secretB64
              && /^[A-Za-z0-9_-]+$/.test(obj.s)) conn.s = obj.s
            if ((obj.v === 3 || obj.v === 4) && typeof obj.g === 'string' && obj.g && obj.g.length <= PAIRING_V14_CAPS.grantB64
              && /^[A-Za-z0-9_-]+$/.test(obj.g)) conn.g = obj.g
            if (!Object.keys(conn).length) conn = null
          }
        }
      } catch { conn = null }
    }
    return { words, provider, ...(url ? { url } : {}), ...(creds ? { creds } : {}), ...(conn ? { conn } : {}) }
  }
  // words-only: the seal scheme is optional (manual word entry never had it)
  const bare = s.replace(/^ucrypt-sync:\/\//i, '')
  const words = bare.split(/[\s-]+/).filter(Boolean)
  if (words.length === 24) return { words }
  return null
}

// ── R119 v1.5 — the carried-segments transparency names ─────────────────────
//
// The pairing surface's "This code carries: …" line must never lie about a
// v1.5 code. The localized SENTENCE belongs to the page (options.js owns its
// region — adoption happens there later); the SEGMENT NAMES are the payload's
// own truth, so they are computed HERE — the same module that builds and
// parses the /k/ segment, pure and testable. The names are localized-key-
// NEUTRAL stable tokens (the page maps each to its locale string later):
//   'words'                  the 24 recovery words — always ride
//   'provider'               the cloud type — rides with any connection
//   'client-id'              the PUBLIC OAuth client id (law 0.23 — when
//                            present; cid behavior unchanged)
//   'address'                the bridge /exec URL (conn.b)
//   'sign-in-mode:<mode>'    the ladder rung the origin connected with —
//                            the SHARED-CLIENT fact named aloud
//   'sign-in-credentials'    the sealed s/g pair — NEVER on a fast origin's
//                            list (the discipline mirrored: the builder
//                            drops them, so the line must not name them)
// Junk/oversize mode values degrade to absent (isSigninMode is the same
// allowlist the builder and parser run) — the list never names a mode the
// URI cannot carry.
export function pairingSegmentNames(conn) {
  const names = ['words']
  const c = conn && typeof conn === 'object' ? conn : null
  if (!c) return names
  names.push('provider')
  if (c.cid) names.push('client-id')
  if (c.b) names.push('address')
  if (isSigninMode(c.m)) names.push('sign-in-mode:' + c.m)
  if (c.m !== 'fast' && (c.s || c.g)) names.push('sign-in-credentials')
  return names
}

// --- Sync SNAPSHOT serialization (v2.42.5 — R69, F-R69-LOC-1) ---------------
//
// The sync wire carries a REDUCED snapshot built from a syncable-field
// whitelist — never the raw vault object. `lastUsedAt` (device-local usage
// telemetry written by touchEntry() after every real fill) and any other
// local-only state must NEVER leave the device: the fill history of a user
// is behavioural data, not vault content, and letting it ride the envelope
// transferred it to the cloud and to every paired device (F-R69-LOC-1).
//
// The whitelist mirrors the canonical merge field set exactly (vault.js
// canonicalVaultJson) so the snapshot can never create merge churn: the
// canonical comparison ignores lastUsedAt, and the wire no longer carries it.
//
// BACKWARD COMPATIBILITY: envelopes written by ≤ v2.42.4 builds DO contain
// lastUsedAt. fromSyncSnapshot() accepts them (old peers keep working) and
// strips every non-whitelisted field on adoption, so the first re-push from
// this device omits the telemetry. Local values are never erased: the pull
// path re-attaches THIS device's own lastUsedAt after an LWW merge.

/**
 * R100 (S8.9 completion — the chain-roster→transfer-map seeding, the R99
 * candidate): the CHAIN ROSTER rides the snapshot's top level. Each device
 * contributes its own PUBLIC identity (deviceId + the two public JWKs —
 * non-secret by construction); every pull learns the whole chain into the
 * transfer peer map, which is the living beam's fan-out target list. The
 * TOFU law is enforced by the transfer plane's learnPeer (a key change is
 * an incident, never an update). Pure — the vault snapshot fields are
 * untouched; the roster is a separate top-level carrier.
 */
const CHAIN_DEVICES_MAX = 10 // the peer-map cap (mailbox.js) — one law

function cleanDevice(d) {
  if (!d || typeof d !== 'object') return null
  const deviceId = typeof d.deviceId === 'string' ? d.deviceId.slice(0, 128) : ''
  const label = typeof d.label === 'string' ? d.label.slice(0, 80) : ''
  // R108 §3.2 — the label's write time rides the roster (a public number):
  // the per-entry last-writer law needs it to merge renames from any device.
  const labelSetAt = Number.isFinite(Number(d.labelSetAt)) ? Math.max(0, Math.min(Number(d.labelSetAt), 8640000000000000)) : 0
  // R111 §3.1 — the LIVING-SYNC telemetry (self-declared, public numbers):
  // each device stamps its OWN row with its last push (when + which lane)
  // and the entry count it holds, so every roster row can say "direct ·
  // just now" / "cloud · 2 min ago · 12 logins". A missing or malformed
  // stamp degrades to the old row (the surface shows the last-seen only).
  const syncAt = Number.isFinite(Number(d.syncAt)) ? Math.max(0, Math.min(Number(d.syncAt), 8640000000000000)) : 0
  const syncLane = d.syncLane === 'direct' ? 'direct' : (d.syncLane === 'cloud' ? 'cloud' : '')
  const entryCount = Number.isFinite(Number(d.entryCount)) ? Math.max(0, Math.min(Math.floor(Number(d.entryCount)), 1000000)) : -1
  // R127 §2 (law 0.41 — THE CHAIN-VISIBILITY LAW; the forensic's F-carrier
  // fix): the SELF-DECLARED device type + its write time ride the wire
  // roster. cleanDevice used to DROP both fields — the R113 type law's
  // carrier lost the type on every stamp, so a chain member's type never
  // crossed the envelope (the live wire-capture proof: type:null on the
  // pushed row). Sanitized exactly like learnPeer's merge: a bounded
  // string + a public write-time number.
  const deviceType = sanitizeDeviceTypeName(d.deviceType)
  const typeSetAt = Number.isFinite(Number(d.typeSetAt)) ? Math.max(0, Math.min(Number(d.typeSetAt), 8640000000000000)) : 0
  const jwkOk = (j) => !!(j && typeof j === 'object' && typeof j.kty === 'string' && j.kty.length <= 16)
  if (!deviceId || !jwkOk(d.signPubJwk) || !jwkOk(d.agrPubJwk)) return null
  const out = { deviceId, signPubJwk: d.signPubJwk, agrPubJwk: d.agrPubJwk, label, labelSetAt }
  if (syncAt) { out.syncAt = syncAt; out.syncLane = syncLane; out.entryCount = entryCount }
  if (deviceType) { out.deviceType = deviceType; out.typeSetAt = typeSetAt }
  return out
}

/** The bounded device-type allowlist shared by the roster carrier (pure;
 *  the transfer plane's sanitizeDeviceType is the enforcing twin — this
 *  copy lives in sync.js because the carrier is pure and leaf-imported). */
function sanitizeDeviceTypeName(t) {
  const s = typeof t === 'string' ? t.toLowerCase().trim() : ''
  return (s === 'phone' || s === 'tablet' || s === 'computer') ? s : ''
}

/** Stamp THIS device's public identity onto a snapshot (push side). */
export function withChainDevices(snapshot, device) {
  const self = cleanDevice(device)
  if (!self) return snapshot
  const prior = chainDevicesFrom(snapshot).filter((d) => d.deviceId !== self.deviceId)
  const devices = [self, ...prior].slice(0, CHAIN_DEVICES_MAX)
  return { ...snapshot, chainDevices: devices }
}

/** Extract + validate the roster from a RAW parsed envelope (pull side).
 * Bad records are DROPPED (never trusted, never fatal); the vault fields of
 * the envelope are ignored here — this reads the top-level carrier only. */
export function chainDevicesFrom(snapshot) {
  const v = snapshot && typeof snapshot === 'object' ? snapshot : {}
  const arr = Array.isArray(v.chainDevices) ? v.chainDevices : []
  const out = []
  for (const d of arr) {
    const c = cleanDevice(d)
    if (c) out.push(c)
    if (out.length >= CHAIN_DEVICES_MAX) break
  }
  return out
}

/** Fields of a vault entry that may cross the sync wire. */
const SYNCABLE_ENTRY_FIELDS = [
  'domain', 'username', 'password', 'type', 'totp', 'note', 'card',
  'address', 'fields', 'meta', 'uris', 'history', 'createdAt', 'updatedAt',
  // v2.42.7 — R70 (F-R70-MODEL-1): token→login association metadata
  // (nonsecret by construction) so the pairing survives every journey.
  'linkedLoginKey',
]

// --- S9 (R111) — CHAIN-SHARED STATE -----------------------------------------
//
// "Any UCrypt instance attached to the chain may share among themselves ALL
// DATA … google drive (or another service) configurations" — the CEO's law,
// this round's headline. The cloud configuration belongs to the CHAIN: a
// change on any device propagates to every device, and every device sees the
// SAME connection — current, never frozen at join time.
//
// THE RECORD (S9.2): one sealed top-level carrier on the sync envelope —
// the SAME plane the chain roster rides (chainDevices), NEVER inside the
// vault payload entries, NEVER the words:
//   { v, provider, endpoint, clientId, mode, secret?, grant?, rev, setBy, setAt }
//   - provider   the transport id ('gdrive' | 'github' | 'dropbox' | 'webdav'
//                | 'custom' | 'gist') — the connection the chain shares.
//   - endpoint   the STRIPPED address (userinfo never rides — 0.14 law).
//   - clientId   the PUBLIC OAuth client id / app key.
//   - mode       'oauth' | 'bridge' | 'signin' | 'url' — the connection shape.
//   - secret/grant  the TRANSIT-SEALED client secret + OAuth grant — present
//                ONLY under the chain-credentials opt-in (default ON, matching
//                payload law v1.4's toggle), sealed EXACTLY as v1.4 seals them
//                (sealCredentialForTransit — the HKDF key from the words). The
//                envelope itself is already AES-GCM sealed with the sync key;
//                the inner transit seal is the same belt-and-braces the join
//                carrier uses, and lets the adopter re-seal under its own
//                credential key without the page ever seeing a value.
//   - rev        the MONOTONIC change counter (S9.3): bumped on every local
//                config change, never decremented; last-writer-wins by rev.
//   - setBy/setAt  who wrote it (deviceId) and when (epoch ms) — diagnostics
//                and the conflict card name both.
//
// THE MERGE (S9.3/S9.4): higher rev wins; equal rev with a DIFFERENT author
// is the offline double-write → the typed conflict (both options, one click
// each); equal rev same author is an idempotent re-delivery.
//
// SECURITY (S9.5): the record holds NO plaintext credentials — the secret/
// grant values exist on the wire ONLY as transit-sealed opaque blobs, and a
// device adopts them by re-sealing under its OWN credential key (the same
// lifecycle as every credential: lock-drop, disconnect-clear, export-
// exclusion, diagnostics booleans only). The labeled trade lives on the
// surface: one revocation at Google kills it for every device.

export const CHAIN_STATE_VERSION = 1

/** Wire bounds (defence in depth — a hostile record is refused, never
 * rendered). The secret/grant caps are the POST-seal b64url shapes (v1.4's
 * transit blobs are base64url; the /k/ caps bound the same construction). */
export const CHAIN_STATE_CAPS = {
  provider: 24, endpoint: 512, clientId: 256, mode: 16,
  secretB64: 1024, grantB64: 2048,
  revMax: 2 ** 53 - 1,
}

const CHAIN_STATE_PROVIDERS = new Set(['gdrive', 'github', 'dropbox', 'webdav', 'custom', 'gist'])
const CHAIN_STATE_MODES = new Set(['oauth', 'bridge', 'signin', 'url'])

const boundedStr = (v, cap) => (typeof v === 'string' ? v.slice(0, cap) : '')
const boundedB64url = (v, cap) => (typeof v === 'string' && v.length <= cap && /^[A-Za-z0-9_-]*$/.test(v) ? v : undefined)

/** Validate + bound a raw chain-state record (pull side). A record that fails
 * validation returns null — it is DROPPED, never trusted, never fatal (the
 * roster's law). The words NEVER appear here or anywhere in the record. */
export function cleanChainState(raw) {
  if (!raw || typeof raw !== 'object') return null
  if (raw.v !== CHAIN_STATE_VERSION) return null
  const provider = boundedStr(raw.provider, CHAIN_STATE_CAPS.provider)
  if (!CHAIN_STATE_PROVIDERS.has(provider)) return null
  const rev = Number.isFinite(Number(raw.rev)) ? Math.max(0, Math.min(Math.floor(Number(raw.rev)), CHAIN_STATE_CAPS.revMax)) : null
  if (rev === null) return null
  const out = {
    v: CHAIN_STATE_VERSION,
    provider,
    endpoint: boundedStr(raw.endpoint, CHAIN_STATE_CAPS.endpoint),
    clientId: boundedStr(raw.clientId, CHAIN_STATE_CAPS.clientId),
    mode: CHAIN_STATE_MODES.has(raw.mode) ? raw.mode : 'url',
    rev,
    setBy: boundedStr(raw.setBy, 128),
    setAt: Number.isFinite(Number(raw.setAt)) ? Math.max(0, Math.min(Number(raw.setAt), 8640000000000000)) : 0,
  }
  // The sealed credentials ride ONLY when present AND well-formed (b64url,
  // within cap). A malformed blob is DROPPED — the record lands without it
  // (the adopter's surface names what arrived, truthfully).
  const secret = boundedB64url(raw.secret, CHAIN_STATE_CAPS.secretB64)
  const grant = boundedB64url(raw.grant, CHAIN_STATE_CAPS.grantB64)
  if (secret) out.secret = secret
  if (grant) out.grant = grant
  return out
}

/** Stamp the chain's shared connection record onto a snapshot (push side).
 * A null state stamps nothing — the envelope stays roster-only (a device
 * with no transport configured shares nothing). */
export function withChainState(snapshot, state) {
  const clean = cleanChainState(state)
  if (!clean) return snapshot
  return { ...snapshot, chainState: clean }
}

/** Extract + validate the shared record from a RAW parsed envelope (pull
 * side — call BEFORE fromSyncSnapshot strips unknown top-level fields). */
export function chainStateFrom(snapshot) {
  const v = snapshot && typeof snapshot === 'object' ? snapshot : {}
  return cleanChainState(v.chainState)
}

/**
 * S9.3/S9.4 — THE MERGE LAW. `seen` is the device's last-observed record
 * identity { rev, setBy } (the local mirror's head); `incoming` is the raw
 * record off the wire. Outcomes:
 *   'none'     nothing to merge (missing/invalid incoming).
 *   'same'     idempotent re-delivery (same rev, same author, or older).
 *   'adopt'    the chain's record is NEWER → apply it (the typed notice).
 *   'conflict' equal rev, DIFFERENT author — both devices wrote offline at
 *              the same counter position → the typed conflict card, both
 *              options one click each.
 * Pure — never touches storage, never throws on hostile input.
 */
export function mergeChainState(seen, incoming) {
  const rec = cleanChainState(incoming)
  if (!rec) return { outcome: 'none', record: null }
  const s = seen && typeof seen === 'object' ? seen : null
  if (!s || !Number.isFinite(Number(s.rev))) return { outcome: 'adopt', record: rec }
  const seenRev = Number(s.rev) || 0
  if (rec.rev > seenRev) return { outcome: 'adopt', record: rec }
  if (rec.rev < seenRev) return { outcome: 'same', record: rec }
  // Equal rev: the same author re-delivering itself is idempotent; a
  // DIFFERENT author at the same counter position is the offline double-write.
  if (rec.setBy && s.setBy && rec.setBy === s.setBy) return { outcome: 'same', record: rec }
  return { outcome: 'conflict', record: rec }
}

/**
 * Build the syncable snapshot of a vault: whitelisted entry fields only,
 * tombstones reduced to their three wire fields, lastModified preserved.
 * Pure — the local vault object is never mutated.
 */
export function toSyncSnapshot(vaultData) {
  const v = vaultData && typeof vaultData === 'object' ? vaultData : {}
  const strip = (e) => {
    const out = {}
    for (const k of SYNCABLE_ENTRY_FIELDS) {
      if (e[k] !== undefined) out[k] = e[k]
    }
    return out
  }
  return {
    entries: (Array.isArray(v.entries) ? v.entries : []).map(strip),
    tombstones: (Array.isArray(v.tombstones) ? v.tombstones : []).map(t => ({
      domain: t?.domain, username: t?.username, deletedAt: t?.deletedAt || 0,
    })),
    lastModified: v.lastModified || 0,
  }
}

/**
 * Adopt a DECRYPTED remote envelope: unknown/legacy fields (lastUsedAt from
 * an old peer, or anything a future peer adds) are stripped HERE so they can
 * never reach the local vault, the merge, or the next push. Old envelopes
 * stay readable; their telemetry simply never lands.
 */
export function fromSyncSnapshot(snapshot) {
  return toSyncSnapshot(snapshot)
}

// --- Vault blob crypto for sync ---------------------------------------------

export async function encryptForSync(vaultData, syncKey) {
  // v2.42.5 — R69: the encrypted envelope is built from the syncable
  // snapshot, never from the raw vault object (telemetry never encrypts).
  const json = JSON.stringify(toSyncSnapshot(vaultData))
  return encryptString(json, syncKey)
}

export async function decryptFromSync(blob, syncKey) {
  const json = await decryptString(blob, syncKey)
  // v2.42.5 — R69: legacy envelopes are sanitized on read (backward compat).
  return fromSyncSnapshot(JSON.parse(json))
}

// --- Fingerprint (shown in UI so users can verify both devices match) -------

export async function syncFingerprint(mnemonic) {
  // Normalized like validateSyncCode: case-insensitive, whitespace collapsed.
  const norm = mnemonic.replace(/[\s\-]+/g, ' ').trim().toLowerCase()
  const hash = await sha256(new TextEncoder().encode(norm))
  const hex = Array.from(hash.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
  return hex.replace(/(..)(..)(..)(..)/, '$1-$2-$3-$4').toUpperCase()
}
