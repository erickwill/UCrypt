/**
 * UCrypt — Diagnostics export (R105 §2.2 — THE OWNER'S VERDICT).
 *
 * Help area > "Export diagnostics": ONE JSON object copied to the clipboard
 * that makes any residual acceptance finding self-triageable. It reads ONLY
 * the typed ledgers and status messages the UI already renders — never
 * secrets:
 *
 *   - build sha (BUILD.json's payloadSha256) + manifest version
 *   - browser UA + locale
 *   - vault state (locked/unlocked, the LOGIN entry COUNT — never contents)
 *   - chain state (joined, the direct-plane device COUNT — never the words,
 *     never the device tokens)
 *   - cloud transport (type id, configured, the typed last test/push/pull
 *     LEDGER LINES — never credentials; the sealed grant fields of the
 *     transport envelope are never read, per the 0.14 export-exclusion
 *     discipline this module joins)
 *   - the last N typed errors from the EXISTING rings (the transport
 *     ledgers, the sync hop, the QR decode outcome) — each a typed line the
 *     surfaces already showed the user
 *   - R115 (law 0.28) — THE EVIDENCE RINGS: the last 10 typed ring rows
 *     (flow, transport, stage, outcome, HTTP kind, status, elapsed ms,
 *     retry tier, the typed error and its own sanitized words). Every
 *     network-facing flow — connect, sync, share, transfer — records here;
 *     when an intermittent failure strikes, the owner's ONE paste names the
 *     stage and the cause. The rings are sanitized by construction (the
 *     egrings module redacts credential-bearing query values and never
 *     stores headers/bodies) — the no-secrets gate machine-checks it.
 *   - the QR decode-ladder's last landing rung (rung NUMBERS only — never
 *     the decoded text)
 *   - storage quota usage
 *
 * 0.14 LAW (the module joins the export-exclusion set): no sealed-record
 * pattern, no credential field, no word of the sync code may appear in the
 * output — enforced structurally (the module has NO code path to those
 * sources) and machine-checked twice per round: the static no-secrets scan
 * (tests/r105-diagnostics.test.mjs) and the runtime battery that plants
 * sealed-record patterns in a mock store and asserts the export string
 * carries none of them.
 *
 * Pure-ish module: every chrome.* access goes through small indirections the
 * battery mocks. Failures degrade to typed nulls — the export never throws
 * away the whole summary because one ring was unreadable.
 */

const DIAG_SCHEMA = 'ucrypt.diagnostics/1'
const QR_RING_KEY = 'ucrypt:qr:lastDecode'
const LAST_TEST_KEY = 'ucrypt:lastTest'
// R115 (law 0.28) — the evidence rings ride the export through the egrings
// module's own renderer (sanitized, capped, local-only by construction).
import { diagnosticsRings, RING_DIAG_LIMIT } from './egrings.js'
// R108 §2.5 — the pairing code's carried-segments ring (written by the join
// flow at parse time and by the origin's sheet at render time). Metadata
// ONLY: the provider id and PRESENCE FLAGS — never the words, never the
// connection values, never a credential (the 0.14 export-exclusion set
// applies; the static scan and the planted-secrets battery check it).
const PAIRING_RING_KEY = 'ucrypt:pairing:lastSegments'
const RECENT_ERRORS_CAP = 12

async function bgSend(type, data = {}) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type, ...data }, (r) => {
        void chrome.runtime.lastError // typed degradation below
        resolve(r || null)
      })
    } catch {
      resolve(null)
    }
  })
}

async function localGet(key) {
  try {
    const r = await chrome.storage.local.get(key)
    return r && r[key] !== undefined ? r[key] : null
  } catch {
    return null
  }
}

async function sessionGet(key) {
  try {
    if (!chrome.storage.session) return null
    const r = await chrome.storage.session.get(key)
    return r && r[key] !== undefined ? r[key] : null
  } catch {
    return null
  }
}

/** BUILD.json rides the payload; read it for the build sha. Typed fallback. */
async function readBuild() {
  try {
    const url = chrome.runtime.getURL('BUILD.json')
    const res = await fetch(url)
    if (!res.ok) throw new Error(String(res.status))
    const j = await res.json()
    return {
      manifestVersion: String(j.version || chrome.runtime.getManifest().version || ''),
      payloadSha256: String(j.payloadSha256 || ''),
      builtAt: String(j.builtAt || ''),
      round: String(j.round || ''),
    }
  } catch {
    let v = ''
    try { v = String(chrome.runtime.getManifest().version || '') } catch { /* typed null */ }
    return { manifestVersion: v, payloadSha256: '', builtAt: '', round: '' }
  }
}

/**
 * ONE typed error row per existing-ring entry. Only FAILURES (and the QR
 * no-qr outcome) belong here — the rings' successes are visible on their own
 * surfaces; the diagnostics export is for triage.
 */
function ringRows({ lastTest, lastPush, lastPull, syncHop, qr }) {
  const rows = []
  const push = (at, surface, message) => {
    if (!at || !message) return
    rows.push({ at: new Date(at).toISOString(), surface, message: String(message).slice(0, 140) })
  }
  if (lastTest && lastTest.ok === false) push(lastTest.at, 'cloud.test', lastTest.message || lastTest.error)
  if (lastPush && lastPush.ok === false) push(lastPush.at, 'cloud.push', lastPush.error || lastPush.message)
  if (lastPull && lastPull.ok === false) push(lastPull.at, 'cloud.pull', lastPull.error || lastPull.message)
  if (syncHop && syncHop.ok === false) push(syncHop.at, 'cloud.syncHop', syncHop.error)
  if (qr && qr.outcome && qr.outcome !== 'ok') push(qr.at, 'qr.decode', `outcome=${qr.outcome} rung=${qr.attempt}/${qr.attempts}`)
  rows.sort((a, b) => (a.at < b.at ? 1 : -1))
  return rows.slice(0, RECENT_ERRORS_CAP)
}

/**
 * Build the diagnostics object. Every field is honest by construction: an
 * unreadable ring degrades to null with the row OMITTED — never invented.
 */
export async function collectDiagnostics({ now = Date.now() } = {}) {
  const [build, state, kdf, transferStatus, savedTransport, lastTest, qrLast, syncStatus, pairingLast] = await Promise.all([
    readBuild(),
    bgSend('GET_STATE'),
    bgSend('SYNC_KDF_INFO'),
    bgSend('TRANSFER_STATUS'),
    localGet('ucrypt:transport'),
    localGet(LAST_TEST_KEY),
    sessionGet(QR_RING_KEY),
    bgSend('SYNC_STATUS'),
    sessionGet(PAIRING_RING_KEY),
  ])

  const vault = {
    locked: !(state && state.ok && state.state && state.state.isUnlocked),
    hasMaster: !!(state && state.ok && state.state && state.state.hasMaster),
    // the LOGIN entry COUNT only — the module has no path to entry contents
    entries: state && state.ok && state.state && typeof state.state.entryCount === 'number'
      ? state.state.entryCount
      : null,
  }
  const chain = {
    joined: !!(kdf && kdf.ok && kdf.info && kdf.info.hasSyncCode),
    // the direct-plane roster COUNT only — never device ids/tokens
    devices: transferStatus && transferStatus.ok && Array.isArray(transferStatus.peers)
      ? transferStatus.peers.length
      : 0,
  }
  const sync = (syncStatus && syncStatus.ok && syncStatus.status) || {}
  const cloud = {
    // the transport TYPE ID + configured truth only — never the config
    // object (the sealed grant envelope is never opened here)
    type: savedTransport && typeof savedTransport.id === 'string' ? savedTransport.id : '',
    configured: !!(savedTransport && savedTransport.id),
    lastTest: lastTest && typeof lastTest === 'object'
      ? { ok: !!lastTest.ok, at: lastTest.at ? new Date(lastTest.at).toISOString() : null, message: String(lastTest.message || '').slice(0, 140) }
      : null,
    lastPush: sync.lastPush
      ? { ok: !!sync.lastPush.ok, at: sync.lastPush.at ? new Date(sync.lastPush.at).toISOString() : null, error: String(sync.lastPush.error || '').slice(0, 140) }
      : null,
    lastPull: sync.lastPull
      ? { ok: !!sync.lastPull.ok, at: sync.lastPull.at ? new Date(sync.lastPull.at).toISOString() : null, error: String(sync.lastPull.error || '').slice(0, 140) }
      : null,
  }
  const qr = { lastDecode: qrLast && typeof qrLast === 'object' ? { ...qrLast } : null }
  // R111 §2 (S9.5) — the chain-shared state, BOOLEANS ONLY: the share
  // opt-in, the per-device override, whether a shared record is known (and
  // its monotonic counter). The mirror's public address/client-ID strings
  // stay OUT of the export by default (the pairing-segments law: the flags
  // answer the only question a finding needs).
  // R108 §2.5 — the carried-segments line (presence flags only; the client
  // ID itself is public yet stays out of the export by default — the flags
  // answer the only question a finding needs: did the settings ride?).
  const pairing = {
    lastSegments: pairingLast && typeof pairingLast === 'object'
      ? {
        at: pairingLast.at ? new Date(pairingLast.at).toISOString() : null,
        provider: String(pairingLast.provider || ''),
        carriedConn: !!pairingLast.carriedConn,
        carriedCreds: !!pairingLast.carriedCreds,
        carrier: String(pairingLast.carrier || ''),
      }
      : null,
  }

  let chainState = null
  try {
    const cs = await bgSend('CHAIN_STATE_STATUS')
    if (cs && cs.ok) {
      chainState = {
        shareCredentials: !!cs.shareCredentials,
        override: !!cs.override,
        hasSharedRecord: !!(cs.mirror && cs.mirror.rev),
        rev: cs.mirror && Number.isFinite(Number(cs.mirror.rev)) ? cs.mirror.rev : 0,
        provider: cs.mirror && cs.mirror.provider ? cs.mirror.provider : '',
        pendingConflict: !!cs.conflict,
      }
    }
  } catch { /* typed null — the diagnostics never throw into the export */ }

  // R112 §2 (D6/D9) — THE SHARE BOOLEANS: Direct Share appears in the
  // diagnostics as booleans and counts ONLY — never the invitation string,
  // never the share words, never a file name, never the note (the note's
  // own law: it never enters logs or diagnostics). The guard keys carry no
  // secrets by construction (timestamps + ephemeral-key hashes + sids).
  let share = null
  try {
    const g = await localGet('ucrypt:share:guard')
    share = {
      consumedCount: Array.isArray(g && g.consumed) ? g.consumed.length : 0,
      acceptedLastHour: Array.isArray(g && g.accepted)
        ? g.accepted.filter((t) => Number(t) > Date.now() - 60 * 60 * 1000).length
        : 0,
    }
    // R124 §2 (D13) — THE PICKUP BOOLEANS (presence flags only): has a hold
    // ever been created on this device; has a pickup ever completed here.
    // The pickup's OWN keys only — the share ledger is NEVER read here (the
    // LG-5 export-exclusion law stands untouched). The holds record carries
    // public refs and timestamps; the consumed list carries only notice
    // fingerprints — the export stays no-secrets by construction.
    try {
      const holds = await localGet('ucrypt:pickup:holds')
      const holdRows = Array.isArray(holds && holds['ucrypt:pickup:holds']) ? holds['ucrypt:pickup:holds'] : []
      const consumed = await localGet('ucrypt:pickup:consumed')
      share.pickupHeld = holdRows.length > 0
      share.pickupPickedUp =
        (Array.isArray(consumed && consumed['ucrypt:pickup:consumed']) && consumed['ucrypt:pickup:consumed'].length > 0)
    } catch { /* the pickup flags degrade to false — the export never throws */ }
  } catch { /* typed null */ }

  let storageInfo = { localBytesInUse: null, usage: null, quota: null }
  try {
    storageInfo.localBytesInUse = await chrome.storage.local.getBytesInUse(null)
  } catch { /* typed null */ }
  try {
    if (navigator.storage && navigator.storage.estimate) {
      const est = await navigator.storage.estimate()
      storageInfo.usage = typeof est.usage === 'number' ? est.usage : null
      storageInfo.quota = typeof est.quota === 'number' ? est.quota : null
    }
  } catch { /* typed null */ }

  // R115 (law 0.28) — the evidence rings: the last 10 typed rows. Each row
  // is already sanitized by the egrings module (no secrets, no
  // credential-bearing URLs, no headers/bodies); a read failure degrades to
  // an empty list — the export never throws.
  let evidenceRings = []
  try {
    evidenceRings = (await diagnosticsRings()).map((r) => ({
      at: r.at ? new Date(r.at).toISOString() : null,
      flow: r.flow,
      transport: r.transport,
      stage: r.stage,
      outcome: r.outcome,
      httpKind: r.httpKind || null,
      status: r.status != null ? r.status : null,
      elapsedMs: r.elapsedMs != null ? r.elapsedMs : null,
      retryTier: r.retryTier != null ? r.retryTier : null,
      error: r.error || null,
      message: r.message || null,
    }))
  } catch { /* typed empty — the diagnostics never throw into the export */ }

  return {
    schema: DIAG_SCHEMA,
    generatedAt: new Date(now).toISOString(),
    build,
    browser: {
      userAgent: typeof navigator !== 'undefined' ? String(navigator.userAgent || '') : '',
      languages: typeof navigator !== 'undefined' && Array.isArray(navigator.languages) ? navigator.languages.length : null,
    },
    locale: (() => {
      try { return chrome.i18n && chrome.i18n.getUILanguage ? chrome.i18n.getUILanguage() : '' } catch { return '' }
    })(),
    vault,
    chain,
    cloud,
    chainState,
    share,
    qr,
    pairing,
    evidenceRings,
    storage: storageInfo,
    recentErrors: ringRows({ lastTest, lastPush: sync.lastPush, lastPull: sync.lastPull, syncHop: sync.syncHop, qr: qrLast }),
  }
}

/** Stable JSON text (2-space, key order as built). */
export function diagnosticsJson(d) {
  return JSON.stringify(d, null, 2)
}

/** Test-visible constants (additions-only). */
export const DIAGNOSTICS_CONSTANTS = { DIAG_SCHEMA, QR_RING_KEY, LAST_TEST_KEY, PAIRING_RING_KEY, RECENT_ERRORS_CAP, RING_DIAG_LIMIT }
