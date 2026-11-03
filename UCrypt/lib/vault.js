/**
 * UCrypt — Encrypted password storage with multi-transport sync (v2.3.0).
 *
 * Crypto model:
 *   Master passphrase → PBKDF2 (600k, SHA-256) → AES-GCM-256 key → vault blob
 *   Sync code (24-word BIP-39) → PBKDF2 (600k v2.3.0+ / 210k legacy) → AES-GCM-256 key → sync blob
 *
 * v2.2.0 hardening (audit findings #4/#5/#6/#14/#15):
 *   - MV3 service workers die after ~30s idle. The unlocked state (derived
 *     CryptoKeys + decrypted vault) now persists in chrome.storage.session —
 *     memory-only storage that survives service-worker restarts but is wiped
 *     when the browser closes. Auto-lock still applies on idle.
 *   - chrome.storage.sync has an 8,192-byte PER-ITEM quota; a real vault
 *     exceeds it quickly. The sync blob is now stored in chunks of ≤6,000
 *     chars under indexed keys.
 *   - lockVault() now clears decrypted data from memory AND session storage.
 *   - wipeVault() also clears transport configs and session storage.
 *   - After saving locally, the vault auto-pushes to the configured cloud
 *     transport (if any) instead of the old raw-WebDAV-only path.
 *
 * v2.3.0 hardening:
 *   - The sync KDF version is persisted next to the stored sync code, so
 *     legacy (210k, v1) records keep working while new setups derive at 600k
 *     (v2) — with an explicit upgradeSyncKdf() path.
 *   - Downloaded sync blobs pass a cheap structural pre-check (base64 shape,
 *     sane length) BEFORE any PBKDF2 + AES-GCM work is spent on them.
 *   - Sync downloads/pushes surface classified errors (SyncError kinds)
 *     instead of opaque fetch strings.
 *
 * v2.4.0:
 *   - TOTP authenticator tokens live in the vault as entries of type 'totp'
 *     (domain __totp__, username = label, secret in a structured .totp block).
 *     They inherit encryption, idle-lock and sync for free.
 * v2.42.7 — R70 (F-R70-MODEL-1, "One Authenticator"): the standalone
 *   type:'totp' entry is the ONLY canonical persisted TOTP representation.
 *   The secret exists in exactly one entry — never duplicated onto its login.
 *   Association is metadata on the token: `linkedLoginKey` = the login's
 *   nonsecret deterministic key (`entryKey(domain, username)`). Legacy
 *   attached `login.totp` envelopes remain READ-compatible and are converted
 *   to exactly one canonical token at the first eligible local write
 *   (migrateLegacyAttachedTotp, idempotent, failure-safe — no silent drop).
 *   - ENTRY-LEVEL MERGE WITH TOMBSTONES. Until now pullFromSync() adopted
 *     whole-vault LWW snapshots, so a deletion made on device A silently
 *     resurrected if device B (still holding the entry) had a newer
 *     lastModified. deleteEntry() now records a tombstone; pullFromSync()
 *     merges by (domain, username): per-entry LWW on updatedAt, deletions
 *     win over entries they are newer than, re-saves clear the tombstone.
 *     Tombstones are pruned after 30 days (TOMBSTONE_TTL_MS).
 *
 * v2.8.0 — CLOUD LIFECYCLE HARDENING (import → cloud → restore):
 *   - RESTORE-SAFE setSyncCode(). The old code pushed the local vault
 *     whenever `vaultData?.entries` was truthy — an EMPTY array IS truthy, so
 *     restoring a sync code on a fresh device FIRST CLOBBERED the cloud copy
 *     (chrome.storage.sync chunks + the configured transport) with an empty
 *     vault, then "pulled" the just-destroyed blob back. Restoring now
 *     PULLS AND MERGES FIRST; a push only happens when the local vault
 *     actually holds content the remote may not have.
 *   - PUSH OUTCOME LEDGER. Every transport push records {ok, at, error,
 *     transportId, lastModified} under 'ucrypt:lastPush' so the UI can tell
 *     the truth about cloud state, and so a push that died with the MV3
 *     worker is retried by the periodic sync tick.
 *   - saveEntriesBatch(entries, { awaitPush }) — the import path can await
 *     the transport push and report its real outcome instead of guessing.
 *   - TYPE-AWARE deleteEntry(domain, username, type) — deleting an imported
 *     bookmark/note/card can no longer take same-key siblings (a login with
 *     the same domain+username, or two bookmarks sharing a title) with it.
 *   - getSyncStatus() counts LOGINS only (consistent with getVaultState)
 *     and surfaces the last-push outcome.
 */

import { deriveKey, deriveCredentialKey, encryptString, decryptString, secureRandomBytes, bytesToBase64, base64ToBytes, sealSecret, openSecret, isSealedEnvelope, CRED_ENV_SCHEMA, sha256 } from './crypto.js'
import { looksLikeVaultEnvelope } from './transports/http.js'
// R171 — THE HONEST ERROR LAW: the ONE materializer every ledger writer and
// renderer rides (a Promise/object can never reach user copy — the E-24 cure).
// R174 — the string-poison heal rides the same leaf (the A3 cure: the only
// poison class that survives storage is a STRING; the heal rewrites it).
import { materializeUserText, healPoisonedUserText } from './honest-error.js'
// R89 (F-R89-GHOST-DELETE + F-R89-DYN-IMPORT): the old deleteCloudCopy called
// `await import('./transports/index.js')` and destructured a `syncDeleteVault`
// export THAT NEVER EXISTED in any module — the typed cloud-copy delete has
// thrown "syncDeleteVault is not a function" since it shipped. The REAL API is
// getTransport(id).deleteVault(config). Static import per the v2.12.0 ruling
// (dynamic import() throws on ServiceWorkerGlobalScope; no cycle: transports/
// index.js → transports only, never imports vault.js).
import { getTransport, transports } from './transports/index.js'
import { siteKeyOf } from './sites.js'
// v2.12.0 — REAL-CHROMIUM E2E FINDING: dynamic import() is disallowed on
// ServiceWorkerGlobalScope (classic AND module workers). This module is the
// worker's core, so every lazy import() here threw in a real browser — TOTP
// saves, sync-code set/restore, KDF upgrade, transport push/pull all broke.
// All of them are STATIC imports now (no cycles: sync.js → crypto.js only,
// totp.js is standalone, transports/index.js → transports only).
import { normalizeSecret, isValidBase32Secret } from './totp.js'
// v2.42.5 — R69 (F-R69-LOC-1): the canonical sync-snapshot serializer lives in
// sync.js (which imports crypto.js only — no cycle; the MV3 worker forbids
// dynamic import, so this is a static import like every other dependency).
import { toSyncSnapshot, fromSyncSnapshot, withChainDevices, chainDevicesFrom, withChainState, chainStateFrom, mergeChainState, cleanChainState, CHAIN_STATE_VERSION, SYNC_KDF_VERSION, SYNC_KDF_ITERATIONS, deriveSyncKey, validateSyncCode, safeCloudForPairing, sealCredentialForTransit, openCredentialFromTransit, PAIRING_V14_CAPS, PAIRING_CREDS_CAPS, PAIRING_SECRET_FIELDS } from './sync.js'

// R100 (S8.9 completion): the CHAIN ROSTER BRIDGE — the worker injects the
// transfer-plane identity provider (push side) and the learn sink (pull
// side). vault.js never imports the transfer plane (the standing no-cycle
// law); the bridge is configured once at worker init and is optional — an
// unconfigured bridge stamps nothing and learns nothing (old behavior).
let _chainIdentityProvider = null
let _chainDevicesSink = null
// R108 §3.2 — the optional roster augmenter: the worker's chance to merge
// the sealed peer map's labels (per-entry last-writer) into the push roster,
// so a rename made on ANY device rides the next sync envelope. Optional and
// unconfigured → identical behavior (the old stamp).
let _chainRosterAugmenter = null
// S9 (R111) — the chain-shared state bridge: the provider builds the record
// from THIS device's transport (push side); the sink applies an incoming
// record (pull side). Optional and unconfigured → the envelope carries no
// chain state and none is adopted (the old behavior).
let _chainStateProvider = null
let _chainStateSink = null
export function configureSyncChainBridge({ identityProvider, chainDevicesSink, rosterAugmenter, chainStateProvider, chainStateSink } = {}) {
  _chainIdentityProvider = typeof identityProvider === 'function' ? identityProvider : null
  _chainDevicesSink = typeof chainDevicesSink === 'function' ? chainDevicesSink : null
  _chainRosterAugmenter = typeof rosterAugmenter === 'function' ? rosterAugmenter : null
  _chainStateProvider = typeof chainStateProvider === 'function' ? chainStateProvider : null
  _chainStateSink = typeof chainStateSink === 'function' ? chainStateSink : null
}

/** The wire snapshot: the syncable snapshot + the device's public identity
 * (the roster carrier). A provider failure stamps nothing — the push is
 * never blocked by the transfer plane. The augmenter (R108) runs AFTER the
 * self stamp and may add the map's other devices / refresh their labels;
 * an augmenter failure keeps the un-augmented roster (the push stands).
 * S9 (R111): the chain-shared connection record rides the SAME top-level
 * plane from its own provider — a provider failure or a locked vault stamps
 * no record (the push stands, the record simply waits for the next one). */
async function snapshotForWire(vaultData, opts = {}) {
  const snap = toSyncSnapshot(vaultData)
  let stamped = snap
  if (_chainIdentityProvider) {
    try {
      const device = await _chainIdentityProvider()
      stamped = withChainDevices(snap, device)
      if (_chainRosterAugmenter && Array.isArray(stamped.chainDevices)) {
        try { stamped.chainDevices = await _chainRosterAugmenter(stamped.chainDevices) } catch { /* the push stands */ }
      }
    } catch { /* the roster stamp stands down — the push carries the bare snapshot */ }
  }
  if (_chainStateProvider) {
    try {
      const cs = await _chainStateProvider(opts)
      if (cs) stamped = withChainState(stamped, cs)
    } catch { /* the push stands — the record rides the next envelope */ }
  }
  return stamped
}

/** Deliver a pulled envelope's roster to the transfer plane. The sink never
 * breaks the pull: one refused device is a typed warning, not a failure. */
async function deliverChainDevices(rawParsed) {
  if (!_chainDevicesSink) return
  try {
    const devices = chainDevicesFrom(rawParsed)
    if (devices.length) await _chainDevicesSink(devices)
  } catch (e) {
    console.warn('[UCrypt] chain roster learn refused:', e && e.message ? String(e.message).slice(0, 100) : e)
  }
}

/** S9 (R111) — deliver a pulled envelope's chain-shared connection record to
 * the worker's sink. The sink NEVER breaks the pull: a refused record is a
 * typed warning, and the vault merge stands regardless. */
async function deliverChainState(rawParsed) {
  if (!_chainStateSink) return
  try {
    const rec = chainStateFrom(rawParsed)
    if (rec) await _chainStateSink(rec)
  } catch (e) {
    console.warn('[UCrypt] chain state adoption refused:', e && e.message ? String(e.message).slice(0, 100) : e)
  }
}
import { syncUpload, syncDownload, syncDownloadWithEvidence } from './transports/index.js'
// S8.9 (R99) — THE LIVING BEAM: the continuous direct-sync trigger + the
// cloud-leg ledger recorder. vault.js never imports the transfer worker; the
// engine is a leaf module configured by the worker (no import cycle).
import { noteVaultMutation, recordCloudLeg } from './beamsync.js'
// R177 — R-177.4 THE THENABLE BIRTH-RECORDER: the push catch testifies into
// the evidence ring when a thenable arrives (the static hunt is clean; the
// runtime names its own birth frame chain — the next field arrival is
// self-identifying).
import { recordRing } from './egrings.js'
// R178 — R-178.2 THE RENEWAL WRITE-BACK HOOK (the leaf seam — gdrive mints,
// the vault writes the record; no import cycle): every successful silent
// mint/refresh notifies this hook and the vault's ONE writer seat re-seals
// the record's webToken (token+exp+via) — ONE custody truth, ONE clock.
import { registerCustodyWriteBack } from './cloud/custody-writeback.js'

const LOCAL_KEY = 'ucrypt:vault'        // Encrypted blob (local primary copy)
const SYNC_META_KEY = 'ucrypt:vaultSyncMeta' // { chunks: n } for chunked sync blob
const SYNC_CHUNK_PREFIX = 'ucrypt:vaultSync:' // Indexed chunk keys (legacy single key kept for migration)
const SALT_KEY = 'ucrypt:vaultSalt'    // PBKDF2 salt for the master passphrase
const SETTINGS_KEY = 'ucrypt:settings' // Generator settings, preferences
const SYNC_CODE_KEY = 'ucrypt:syncCode' // Sync code, encrypted with master key
const SYNC_KDF_VER_KEY = 'ucrypt:syncKdfVersion' // v2.3.0 — PBKDF2 iteration bucket for the sync key
const TRANSPORT_KEY = 'ucrypt:transport' // { id, config } — cloud transport setup
const LAST_PUSH_KEY = 'ucrypt:lastPush' // v2.8.0 — push outcome ledger for UI + retry
const LAST_PULL_KEY = 'ucrypt:lastPull' // R61-A §1.1 — pull outcome ledger: did the newest cloud READ positively observe the remote?
// R140 §7 — THE CHAIN WAKE CYCLE cache: per service-worker lifetime, the
// cold-start cure's clock (firstProbeCompletedAt / attempts / lastProbe).
// The verdict is DERIVED from this + the pull ledger — a persisted verdict
// is a cache, never a writer (the stale-latch class is unrepresentable).
export const CHAIN_WAKE_KEY = 'ucrypt:chainState:wake'
// R112 §3.1 — the background's SYNC_ATTN_DIAGNOSE reads the ledger through
// this exported alias (one source of truth for the key name; 0.11).
export const LAST_PULL_KEY_PUBLIC = LAST_PULL_KEY
// R178 — R-178.4: the worker's test seat composes the BOTH-LANE verdict from
// the last-push ledger through this exported alias (one source of truth for
// the key name — 0.11, the same law the pull key rides).
export const LAST_PUSH_KEY_PUBLIC = LAST_PUSH_KEY
const LAST_HOP_KEY = 'ucrypt:lastSyncHop' // v2.15.0 — R24-F1: chrome.storage.sync first-hop outcome ledger
// R127 (law 0.41 — the live walk's F-renamed finding): chain-STATE changes
// (a device rename, a peer removal) live in the sealed peer map — OUTSIDE
// the vault's entries. The push gate compares vault content only, so a
// rename never re-rode the envelope ("Already in sync" skipped it). The
// roster-dirty marker: every outbound roster mutation stamps it; the next
// sync consumes it and pushes the envelope even when the entries did not
// change — the roster rides with the very next cycle, exactly like the
// law-0.41 roster itself.
const ROSTER_DIRTY_KEY = 'ucrypt:rosterDirty'
export async function markRosterDirty() {
  try { await chrome.storage.local.set({ [ROSTER_DIRTY_KEY]: { at: Date.now() } }) } catch { /* the marker must never break the caller */ }
}
async function consumeRosterDirty() {
  try {
    const { [ROSTER_DIRTY_KEY]: v } = await chrome.storage.local.get(ROSTER_DIRTY_KEY)
    if (v) await chrome.storage.local.remove(ROSTER_DIRTY_KEY)
    return !!v
  } catch { return false }
}
// v2.16.0 — Brave/Chrome parity: the auto-lock interval is USER-CONFIGURABLE
// (Security tab → Auto-lock; stored in ucrypt:settings.autolockMinutes,
// 0 = never). The default stays 10 minutes.
const DEFAULT_LOCK_TIMEOUT = 10 * 60 * 1000
// v2.16.0 — password history (beyond-Brave rotation safety net): every real
// password change keeps the previous password (capped) so it can be restored.
const PASSWORD_HISTORY_CAP = 5
const SYNC_CHUNK_SIZE = 6000           // chars per chunk (< 8192-byte item quota)
const TOTP_DOMAIN = '__totp__'         // pseudo-domain for authenticator token entries
const TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // tombstones older than 30d are pruned

/**
 * R45-A (v2.36.0) — SESSION PERSISTENCE REMOVED BY SECURITY ORDER.
 *
 * History: v2.2.0–v2.35 persisted the unlocked state (CryptoKey objects AND
 * the fully decrypted vault) into chrome.storage.session so the MV3 service
 * worker could restore an unlocked session across worker recycles. The
 * Round-45 security order classifies that as a HIGH release blocker:
 * decrypting key material must exist ONLY in worker memory, and a worker
 * recycle may restore only behavior that does not re-serialize key or vault
 * data into any storage area.
 *
 * THE COMPLIANT MODEL (documented behavior, pinned by tests):
 *   - The unlocked vault lives ONLY in this module's worker memory.
 *   - An MV3 worker recycle re-locks the vault (honest lock boundary — no
 *     silent key serialization). The boot code below still re-derives the
 *     truthful LOCKED state (hasMaster from the persisted salt) on every
 *     wake, so the UI never falls back to the setup wizard (the v2.20 bug).
 *   - A 30-second keep-alive alarm runs while the vault is unlocked so an
 *     active session is not interrupted by routine recycles; clearing the
 *     alarm at lock lets the worker idle out normally.
 *   - Browser restart, explicit lock, and worker recycle all converge to the
 *     same state: LOCKED, with zero key material anywhere on disk or in
 *     storage.session (the legacy 'ucrypt:session' record older versions
 *     left behind is scrubbed on boot, lock, and wipe).
 */
const LEGACY_SESSION_KEY = 'ucrypt:session' // pre-v2.36 record — scrubbed, never read
const KEEPALIVE_ALARM = 'ucrypt:keepalive'

// In-memory unlocked state — the ONLY place key material and decrypted data exist
let masterKey = null
let credentialKey = null // R45-A: domain-separated key for transport-secret envelopes
let syncKey = null
let vaultData = null
let lastActivity = Date.now()
let isUnlocked = false
let hasMaster = false
let lockTimeoutMs = DEFAULT_LOCK_TIMEOUT // v2.16.0 — loaded from ucrypt:settings
// R45-A: a lock landing DURING an in-flight unlock/setMaster must win — the
// unlock's later steps otherwise resurrect isUnlocked=true on top of the
// lock, leaving the module "unlocked" with NO keys (caught live: the round-45
// journey hit isUnlocked:true + masterKey:null + syncKey:set). Every lock
// bumps the epoch; an unlock aborts unless its epoch is still current.
let lockEpoch = 0

/**
 * v2.16.0 — read the user-configured auto-lock interval from ucrypt:settings
 * before any idle-timeout decision is made (initVault calls this first so a
 * worker restart applies the configured interval immediately).
 * Stored as minutes; 0 = never lock. Clamped to 1..1440 when set.
 */
async function loadAutoLockSetting() {
  try {
    const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY)
    const min = Number(s?.autolockMinutes)
    lockTimeoutMs = Number.isFinite(min)
      ? (min <= 0 ? 0 : Math.min(1440, Math.max(1, Math.round(min))) * 60 * 1000)
      : DEFAULT_LOCK_TIMEOUT
  } catch { lockTimeoutMs = DEFAULT_LOCK_TIMEOUT }
}

// ---------------------------------------------------------------------------
// SESSION SCRUB (R45-A) + KEEP-ALIVE
// ---------------------------------------------------------------------------

/**
 * Remove any legacy persisted-session record left by v2.2.0–v2.35 builds.
 * Called on boot, lock, and wipe so an upgrade converges to the clean model
 * at the earliest possible moment. Never reads the record.
 */
const ACTIVE_SESSION_KEY = 'ucrypt:activeSession'

async function clearLegacySession() {
  try { await chrome.storage.session.remove(LEGACY_SESSION_KEY) } catch { /* the legacy-key cleanup is best-effort — the session store may be gone (named-swallow law, R169 C1) */ }
}

async function clearActiveSession() {
  try { await chrome.storage.session.remove(ACTIVE_SESSION_KEY) } catch { /* best-effort */ }
}

async function saveActiveSession(passphrase) {
  try {
    if (chrome.storage?.session?.set && typeof passphrase === 'string' && passphrase.length >= 8) {
      await chrome.storage.session.set({
        [ACTIVE_SESSION_KEY]: {
          passphrase,
          lastActivity: Date.now(),
          unlockedAt: Date.now(),
        },
      })
    }
  } catch { /* session storage unavailable in test harness */ }
}

async function touchActiveSession() {
  try {
    if (chrome.storage?.session?.get && chrome.storage?.session?.set) {
      const got = await chrome.storage.session.get(ACTIVE_SESSION_KEY)
      const sess = got && got[ACTIVE_SESSION_KEY]
      if (sess && typeof sess === 'object' && sess.passphrase) {
        await chrome.storage.session.set({
          [ACTIVE_SESSION_KEY]: { ...sess, lastActivity: Date.now() },
        })
      }
    }
  } catch { /* best-effort */ }
}

/**
 * Keep the MV3 worker alive while the vault is UNLOCKED so an active session
 * is not silently re-locked by a routine 30s recycle (the honest documented
 * recycle behavior remains: recycle ⇒ locked; the alarm simply prevents the
 * recycle while the user is mid-session). Cleared at lock so an idle locked
 * extension costs nothing. Guarded — the test harness has no chrome.alarms.
 */
async function ensureKeepAlive() {
  try {
    if (chrome.alarms?.create) {
      await chrome.alarms.clear(KEEPALIVE_ALARM)
      chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5, delayInMinutes: 0.5 })
    }
  } catch { /* alarms unavailable — recycle locks the vault, which is safe */ }
}

async function clearKeepAlive() {
  try { if (chrome.alarms?.clear) await chrome.alarms.clear(KEEPALIVE_ALARM) } catch { /* the alarm cleanup is best-effort — a gone alarm needs no clear (named-swallow law, R169 C1) */ }
}

// ---------------------------------------------------------------------------
// INITIALIZATION
// ---------------------------------------------------------------------------

export async function initVault() {
  // v2.16.0 — load the configured auto-lock interval first.
  await loadAutoLockSetting()
  await clearLegacySession()
  // R171 — THE LEDGER SELF-HEAL at every worker init (the E-24 cure's
  // storage half): poisoned historical ledger rows materialize in place.
  try { await healLedgerRowsAtInit() } catch { /* best-effort — the render guard still holds */ }
  const { [SALT_KEY]: saltB64 } = await chrome.storage.local.get(SALT_KEY)
  hasMaster = !!saltB64
  if (!hasMaster) {
    vaultData = { entries: [], lastModified: 0 }
    await clearActiveSession()
    return { hasMaster: false, isUnlocked: false }
  }
  // UCRYPT-22: Restore active unlocked session from RAM-only chrome.storage.session
  // across window close/reopen or MV3 worker recycle when within lockTimeoutMs.
  try {
    if (chrome.storage?.session?.get) {
      const got = await chrome.storage.session.get(ACTIVE_SESSION_KEY)
      const sess = got && got[ACTIVE_SESSION_KEY]
      if (sess && typeof sess === 'object' && typeof sess.passphrase === 'string' && sess.passphrase.length >= 8) {
        const lastAct = Number(sess.lastActivity) || 0
        const withinTimeout = lockTimeoutMs === 0 || (lastAct > 0 && (Date.now() - lastAct) < lockTimeoutMs)
        if (withinTimeout) {
          await unlockVault(sess.passphrase)
          return { hasMaster: true, isUnlocked: true }
        } else {
          await clearActiveSession()
        }
      }
    }
  } catch {
    await clearActiveSession()
  }
  return { hasMaster: true, isUnlocked: false }
}

/**
 * v2.13.0 — R22-F5: refresh the worker's in-memory vault after a file import
 * overwrote chrome.storage.local. The imported file carries its own salt, so
 * every derived key in memory (and any session restore) is invalid — the
 * vault returns to LOCKED state and must be unlocked again. This replaces
 * the old chrome.runtime.reload() trick, which restarted the WHOLE
 * extension, killed every open popup/options page and — observed clinically
 * on Chromium 153 — can leave the replacement worker unbooted.
 */
export async function reloadFromStorage() {
  await clearLegacySession()
  await clearActiveSession()
  masterKey = null
  credentialKey = null
  syncKey = null
  vaultData = { entries: [], lastModified: 0 }
  isUnlocked = false
  hasMaster = false
  await clearKeepAlive()
  return initVault()
}

// ---------------------------------------------------------------------------
// MASTER PASSPHRASE (vault encryption)
// ---------------------------------------------------------------------------

export async function setMasterPassphrase(passphrase) {
  if (passphrase.length < 8) throw new Error('Master passphrase must be at least 8 characters')
  const myEpoch = lockEpoch
  const salt = secureRandomBytes(16)
  // R85 (F-R84-VAULT-1): captured BEFORE any state change — the guard's
  // allowEmptyOverwrite decision needs to know whether a vault already exists.
  const { [SALT_KEY]: existingSalt } = await chrome.storage.local.get(SALT_KEY)
  const hasMasterBeforeSetup = !!existingSalt
  // R85 (F-R84-VAULT-1) — ALL-OR-NOTHING SETUP GUARD: a setup run while the
  // vault is LOCKED and a local blob already exists is EXACTLY the R84
  // empty-reset vector (the old bytes silently persisted {entries:[]} over
  // it). The refusal happens HERE — before any key or state assignment — so a
  // refused setup can never leave a phantom-unlocked module whose new keys
  // disagree with the persisted blob. The legitimate re-key flow runs while
  // UNLOCKED (the current content rides along and is preserved); a fresh
  // start after a wipe has no salt and no blob and passes untouched.
  if (hasMasterBeforeSetup && !isUnlocked) {
    const { [LOCAL_KEY]: existingBlob } = await chrome.storage.local.get(LOCAL_KEY)
    if (existingBlob) {
      await auditVaultMutation({
        op: 'guard-block',
        before: null,
        after: 0,
        blobSize: String(existingBlob).length,
        note: 'locked setup over an existing vault refused (R84 empty-reset vector; pre-state not decryptable while locked)',
      })
      const err = new Error('A vault already exists on this device. Unlock it first — changing the passphrase keeps every entry; a fresh setup requires an explicit wipe.')
      err.code = 'empty_vault_guard'
      throw err
    }
  }
  // R45-A: vault key + credential-envelope key derived together at unlock;
  // both stay in worker memory only.
  const keys = await Promise.all([
    deriveKey(passphrase, salt),
    deriveCredentialKey(passphrase, salt),
  ])
  if (lockEpoch !== myEpoch) throw new Error('Vault locked during setup — try again')
  ;[masterKey, credentialKey] = keys
  isUnlocked = true
  lastActivity = Date.now()
  hasMaster = true

  if (!vaultData?.entries) vaultData = { entries: [], lastModified: Date.now() }
  // R85 (F-R84-VAULT-1): setMasterPassphrase was the ONE unguarded
  // empty-reset vector — an existing non-empty local blob plus a fresh
  // passphrase used to reset the content to {entries:[]} silently. The
  // cold-boot write guard inside saveVault now refuses that path (typed
  // empty_vault_guard), and the legitimate first-run case (no blob yet)
  // passes with an audit record.
  await saveVault({ skipTransport: true, allowEmptyOverwrite: !hasMasterBeforeSetup, auditOp: 'set-master', auditNote: hasMasterBeforeSetup ? 'passphrase set over an existing vault' : 'first-run vault creation' })
  await chrome.storage.local.set({ [SALT_KEY]: bytesToBase64(salt) })
  await saveActiveSession(passphrase)
  await ensureKeepAlive()
  // If a sync code exists from a previous setup, re-derive its key
  await loadSyncKey()
  return true
}

export async function unlockVault(passphrase) {
  const { [SALT_KEY]: saltB64 } = await chrome.storage.local.get(SALT_KEY)
  if (!saltB64) throw new Error('No master passphrase set')

  const salt = base64ToBytes(saltB64)
  const myEpoch = lockEpoch
  // R45-A: vault key + credential-envelope key derived together at unlock.
  const keys = await Promise.all([
    deriveKey(passphrase, salt),
    deriveCredentialKey(passphrase, salt),
  ])

  // Try local copy first, then legacy + chunked chrome.storage.sync copies
  let blob = (await chrome.storage.local.get(LOCAL_KEY))[LOCAL_KEY]
  if (!blob) {
    const synced = await readChunkedSync()
    if (synced) {
      blob = synced
      await chrome.storage.local.set({ [LOCAL_KEY]: blob }) // Cache locally
    }
  }

  // R45 race fix (round-45 journey evidence): the derived keys land in the
  // module state ONLY after the decrypt proves the passphrase — the old
  // assign-then-null-on-failure pattern let a CONCURRENT wrong-passphrase
  // unlock null the globals under a just-completed correct unlock
  // (isUnlocked:true + keys:null = a phantom-unlocked vault).
  let json = null
  if (blob) {
    try {
      json = await decryptString(blob, keys[0])
    } catch {
      throw new Error('Wrong master passphrase')
    }
  }

  if (lockEpoch !== myEpoch) {
    // A lock landed while the PBKDF2/decrypt awaits were in flight — the
    // lock MUST win. Nothing was assigned to module state; the user re-unlocks.
    throw new Error('Vault locked during unlock — try again')
  }
  ;[masterKey, credentialKey] = keys
  vaultData = json ? JSON.parse(json) : { entries: [], lastModified: Date.now() }
  isUnlocked = true
  lastActivity = Date.now()
  // R85 (F-R84-VAULT-1): the audit ring's "before" anchor after a cold boot
  // comes from the freshly decrypted state.
  _lastKnownCount = vaultEntryCount()

  await loadSyncKey()
  // R45-A §2.3 migration: any transport secret saved in plaintext by an
  // older build is sealed into its envelope at the first unlock. The
  // migration window is therefore exactly one locked→unlock cycle.
  await migrateTransportEnvelopes()
  // v2.42.7 — R70 §2.4 (F-R70-MODEL-1): the first eligible local write after
  // unlock converts any legacy attached login.totp copies into exactly one
  // canonical standalone token each. Failure-safe: the persist below keeps
  // the legacy blob intact until the canonical form is written; a failed
  // persist simply re-runs this migration on the next unlock.
  const mig = migrateLegacyAttachedTotp()
  if (mig.scanned > 0) {
    console.log(`[UCrypt] TOTP canonical migration: ${mig.secretsRemoved} attached copy/copies converted (${mig.tokensAdded} token(s) created, ${mig.linksMade} link(s), ${mig.retained} retained-unreadable)`)
    await saveVault()
  }
  await saveActiveSession(passphrase)
  await ensureKeepAlive()
  return true
}

/**
 * R109 §3.1 (law 0.24) — the PURE passphrase re-verification for the
 * credential popup layers. Derives both keys from the typed passphrase and
 * proves them against the stored vault blob's AES-GCM authentication — the
 * EXACT production math unlockVault uses — with ZERO state mutation: no key
 * assignment, no unlock broadcast, no sync trigger, no audit write. A wrong
 * passphrase throws the same typed error the unlock path reports.
 * Unlocked-only in spirit: the popups use it as a deliberate re-auth, so the
 * caller checks isUnlocked first (the worker case refuses while locked —
 * a locked vault's confirm IS the unlock, a different surface).
 */
export async function verifyPassphrase(passphrase) {
  const { [SALT_KEY]: saltB64 } = await chrome.storage.local.get(SALT_KEY)
  if (!saltB64) throw new Error('No master passphrase set')
  const salt = base64ToBytes(saltB64)
  const keys = await Promise.all([
    deriveKey(passphrase, salt),
    deriveCredentialKey(passphrase, salt),
  ])
  const blob = (await chrome.storage.local.get(LOCAL_KEY))[LOCAL_KEY]
  if (!blob) throw new Error('No vault blob to verify against')
  try {
    await decryptString(blob, keys[0])
  } catch {
    throw new Error('Wrong master passphrase')
  }
  return true
}

/**
 * R109 §3.2 (the CEO's S2) — the ONE reveal path for a stored transport
 * secret's plaintext, used ONLY by the credential popup after its passphrase
 * re-auth: opens the transport record transiently (the same openTransportConfig
 * every sync consumer uses) and returns the ONE requested field. Secrets are
 * never logged, never cached, never returned in bulk; the caller renders the
 * value inside the popup only.
 */
export async function revealTransportSecret(fieldKey) {
  const record = await getTransportRecord()
  if (!record) throw new Error('No transport is configured')
  const allowed = transportSecretFieldMap()[record.id] || []
  if (!allowed.includes(String(fieldKey))) throw new Error('That field is not a sealable secret')
  const v = (record.config || {})[String(fieldKey)]
  if (typeof v !== 'string' || !v) throw new Error('Nothing is stored in that field yet')
  return v
}

export async function lockVault() {
  // R45-A: drop EVERY decrypting key + decrypted data from worker memory and
  // scrub the legacy session record. Nothing decrypting survives the lock.
  lockEpoch++
  masterKey = null
  credentialKey = null
  syncKey = null
  vaultData = null
  isUnlocked = false
  await clearLegacySession()
  await clearActiveSession()
  await clearKeepAlive()
}

export function touchVault() {
  lastActivity = Date.now()
  touchActiveSession()
}

/**
 * v2.7.0 — the vault stores logins (no type), TOTP tokens (type 'totp') and
 * imported "other data" (type 'note'|'card'|'address'|'bookmark'|'history'|
 * 'form', introduced by the Import Center). Every "entries" count and login
 * list must use this predicate so other-data never pollutes passwords, health
 * or autofill.
 */
export const OTHER_ENTRY_TYPES = ['note', 'card', 'address', 'bookmark', 'history', 'form']

export function isLoginEntry(e) {
  return !!e && (e.type === undefined || e.type === null || e.type === 'login')
}

export function isOtherEntry(e) {
  return !!e && OTHER_ENTRY_TYPES.includes(e.type)
}

function loginEntryCount() {
  return (vaultData?.entries || []).filter(isLoginEntry).length
}

export function getVaultState() {
  if (isUnlocked && lockTimeoutMs > 0 && Date.now() - lastActivity > lockTimeoutMs) {
    // Fire-and-forget lock (async cleanup)
    lockVault()
    return { isUnlocked: false, hasMaster, entryCount: 0 }
  }
  return {
    isUnlocked,
    hasMaster,
    entryCount: loginEntryCount(), // logins only; 2FA tokens shown separately
    lastActivity,
    lockTimeoutMs, // v2.16.0 — ms (0 = never); the UI reflects the real value
  }
}

// ---------------------------------------------------------------------------
// VAULT CRUD
// ---------------------------------------------------------------------------

async function saveVault(opts = {}) {
  if (!masterKey) throw new Error('Vault is locked')
  vaultData.lastModified = Date.now()
  const json = JSON.stringify(vaultData)
  const encrypted = await encryptString(json, masterKey)

  // R85 (F-R84-VAULT-1) — COLD-BOOT WRITE GUARD: no code path may persist an
  // EMPTY vault state (no entries, no tombstones) over a NON-EMPTY one unless
  // the caller carries an explicit user action (opts.allowEmptyOverwrite).
  // This is the hardening the R84 P0-candidate incident demanded REGARDLESS
  // of attribution: a save-with-cleared-state race (worker kill mid-write,
  // autolock racing unlock) can no longer produce a silent 0-entry blob.
  // Every guard decision is audit-logged; the refusal is typed.
  const afterCount = vaultEntryCount()
  const beforeAnchor = _lastKnownCount
  if (!hasVaultContent() && !opts.allowEmptyOverwrite) {
    const { [LOCAL_KEY]: existingBlob } = await chrome.storage.local.get(LOCAL_KEY)
    if (existingBlob) {
      let priorCount = -1 // undecryptable counts as non-empty (safe direction)
      try {
        const prev = JSON.parse(await decryptString(existingBlob, masterKey))
        priorCount = vaultEntryCount(prev) + vaultTombstoneCount(prev)
      } catch { /* keep -1 */ }
      if (priorCount !== 0) {
        await auditVaultMutation({
          op: 'guard-block',
          before: priorCount === -1 ? null : priorCount,
          after: afterCount,
          blobSize: String(existingBlob).length,
          note: opts.guardNote || 'empty-overwrite refused by the cold-boot write guard',
        })
        const err = new Error('Refusing to overwrite a non-empty vault with an empty state — if this is intentional, wipe or reset the vault explicitly')
        err.code = 'empty_vault_guard'
        throw err
      }
    }
  }

  // 1. Local primary
  // R95-F2 (the quota law): a REFUSED persist must never leave the in-memory
  // state ahead of the disk — after a failed chrome.storage.local.set the
  // in-memory vault would carry entries the durable copy does not, and any
  // later lock/unload would silently lose them. On failure the last good
  // blob is read back, decrypted, and the in-memory vault restored to it
  // BEFORE the typed rethrow: memory and disk can never disagree.
  try {
    await chrome.storage.local.set({ [LOCAL_KEY]: encrypted })
  } catch (err) {
    let restored = null
    try {
      const { [LOCAL_KEY]: lastGood } = await chrome.storage.local.get(LOCAL_KEY)
      if (lastGood) restored = JSON.parse(await decryptString(lastGood, masterKey))
    } catch { /* rollback source unreadable — surface the original error */ }
    if (restored) {
      vaultData = restored
      _lastKnownCount = vaultEntryCount(restored) + vaultTombstoneCount(restored)
      try {
        await auditVaultMutation({
          op: 'persist-rollback',
          before: afterCount,
          after: _lastKnownCount,
          blobSize: 0,
          note: 'R95-F2: refused persist — the in-memory state was restored from the last good blob on disk',
        })
      } catch { /* audit must never mask the original failure */ }
    }
    throw err
  }
  // R85 (F-R84-VAULT-1): audit EVERY successful vault persist.
  await auditVaultMutation({
    op: opts.auditOp || 'save',
    before: beforeAnchor,
    after: afterCount,
    blobSize: encrypted.length,
    note: opts.auditNote || '',
  })
  _lastKnownCount = afterCount

  // 2. chrome.storage.sync (chunked — per-item quota is 8,192 bytes)
  //    R24-F1 (v2.15.0): the outcome is RECORDED either way. The old code
  //    swallowed quota/sign-in failures with only a console.warn, so the
  //    built-in zero-config first hop was silent when working AND silent
  //    when failing — users on de-Googled Chromium builds (Helium class)
  //    never learned that this hop was inert and that they need a cloud
  //    transport. The ledger makes the hop truthful in the UI.
  //    v2.16.0 — skipSync (touchEntry usage stats) skips this layer too.
  if (syncKey && !opts.skipSync) {
    // v2.42.5 — R69 (F-R69-LOC-1): the first-hop (chrome.storage.sync) legs
    // carry the SYNCABLE SNAPSHOT, not the raw local vault — lastUsedAt and
    // any other device-local state never reach shared storage. The local
    // primary copy above intentionally keeps the full device-local state.
    const syncEncrypted = await encryptString(JSON.stringify(await snapshotForWire(vaultData, { lane: 'cloud' })), syncKey)
    try {
      const chunks = await writeChunkedSync(syncEncrypted)
      await recordHopOutcome({ ok: true, at: Date.now(), chunks, bytes: syncEncrypted.length })
    } catch (err) {
      console.warn('[UCrypt] chrome.storage.sync write failed:', err)
      await recordHopOutcome({ ok: false, at: Date.now(), error: String(err?.message || err) })
    }
  }

  // 3. Auto-push to the configured cloud transport (fire-and-forget unless
  //    asked). v2.16.0 — the push goes through the single-flight sync lock so
  //    concurrent saves/alarms/unlock-pulls can never interleave uploads.
  //    opts.skipSync (touchEntry) skips BOTH cloud layers: a usage-stat
  //    update must not rewrite the sync chunks, push to the transport or
  //    rewrite the hop ledger — it only persists the local copy.
  if (!opts.skipSync && !opts.skipTransport) {
    const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
    if (t?.id && syncKey) {
      // LAW 0.49 (R133) — the mutation lane rides the 30 s debounce: bursts
      // coalesce into ONE auto-sync cycle whose final state always lands
      // (the durable alarm backs the debounce when the worker dies mid-wait;
      // the cloud-leg record and the confirm-retry ride inside the closure).
      scheduleCloudAutoSync(opts.op)
    }
  }
  // S8.9 (R99) — THE LIVING BEAM: the SAME mutation event fires the direct
  // fan-out beside the cloud push (the fast lane vs the record of truth;
  // both legs always run, both legs are recorded per-ledger). Fire-and-forget:
  // the engine is single-flight, coalesces bursts, and can never block or
  // fail the mutation that triggered it.
  if (!opts.skipSync) {
    try { noteVaultMutation(String((opts && opts.op) || 'save')) } catch { /* the cloud push is unaffected */ }
  }
}

/** True when the vault holds anything a peer could need (entries or tombstones). */
function hasVaultContent() {
  return !!((vaultData?.entries && vaultData.entries.length) ||
            (vaultData?.tombstones && vaultData.tombstones.length))
}

// --- R85 (F-R84-VAULT-1): append-only local audit ring + cold-boot write guard -------

/** Local-only, NEVER-synced audit ring (chrome.storage.local — the chunked
 * sync writer only ever touches ucrypt:vaultSync:* keys, so this ring never
 * leaves the device). Capped at 200 entries. Every vault mutation and every
 * guard decision lands here with {op, ts, before/after counts, blob size} —
 * the forensic instrument the R84 incident lacked. */
const VAULT_AUDIT_KEY = 'ucrypt:vaultAudit'
const VAULT_AUDIT_MAX = 200
let _lastKnownCount = null // in-memory "before" anchor (null on cold boot)

async function auditVaultMutation({ op, before, after, blobSize = 0, note = '' }) {
  try {
    const { [VAULT_AUDIT_KEY]: ring } = await chrome.storage.local.get(VAULT_AUDIT_KEY)
    const list = Array.isArray(ring) ? ring : []
    list.push({ op: String(op || 'unknown'), ts: Date.now(), before: before === null ? null : Number(before), after: Number(after) || 0, blobSize: Number(blobSize) || 0, note: String(note || '').slice(0, 120) })
    while (list.length > VAULT_AUDIT_MAX) list.shift()
    await chrome.storage.local.set({ [VAULT_AUDIT_KEY]: list })
  } catch { /* audit is best-effort — never blocks a vault write */ }
}

/** R111 §3.1 — exported for the roster bridge: the identity provider stamps
 * the device's own entry count onto its roster row (a public number). */
export function vaultEntryCountPublic() {
  return (vaultData?.entries || []).length
}

function vaultEntryCount(vault = vaultData) {
  return (vault?.entries || []).length
}

/** Tombstone count for the guard's "non-empty" arithmetic (entries or
 * tombstones both mean the vault has content a peer could need). */
function vaultTombstoneCount(vault = vaultData) {
  return (vault?.tombstones && typeof vault.tombstones === 'object')
    ? Object.keys(vault.tombstones).length
    : (Array.isArray(vault?.tombstones) ? vault.tombstones.length : 0)
}

/**
 * v2.8.0 — push outcome ledger. Written on EVERY transport push attempt so
 * (a) the Sync tab / import report can show the real cloud state, and
 * (b) the periodic sync tick can detect a push that never landed (MV3 worker
 * killed mid-upload) and retry it.
 */
// R174 — THE SELF-IDENTIFYING ROW LAW (R-174.6): every ledger/sync row
// stamps the build version — a field exhibit identifies its own floor, no
// more asking which build the owner ran. Read defensively (the battery's
// stubs ride; a missing manifest rides an empty stamp — the row stays
// honest either way).
let _buildStampCache = null
export function ledgerBuildStamp() {
  if (_buildStampCache !== null) return _buildStampCache
  let v = ''
  try { v = String((typeof chrome !== 'undefined' && chrome && chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '') } catch { v = '' }
  _buildStampCache = v ? `v${v}` : ''
  return _buildStampCache
}

async function recordPushOutcome(outcome) {
  try {
    // R171 — THE HONEST-ERROR LAW at the write seam: every user-facing text
    // field is MATERIALIZED before storage — a Promise/object can never
    // again enter a ledger row (the E-24 "[object Promise]" class dies at
    // the source; the render-side materializer + the init self-heal catch
    // the historical rows).
    const o = { ...outcome }
    if (o.error !== undefined) o.error = materializeUserText(o.error, { cap: 300 })
    if (o.reason !== undefined) o.reason = materializeUserText(o.reason, { cap: 300 })
    if (o.confirmError !== undefined && o.confirmError !== null) o.confirmError = materializeUserText(o.confirmError, { cap: 200 })
    await chrome.storage.local.set({
      // R174 — the build stamp rides EVERY row (R-174.6).
      [LAST_PUSH_KEY]: { ...o, build: ledgerBuildStamp(), lastModified: vaultData?.lastModified || 0 },
    })
  } catch { /* ledger is best-effort */ }
}

// ── R178 — R-178.3 THE ENVELOPE LIFECYCLE (ONE state machine, every seat) ──
//
// "vault not created yet" / "vault envelope present" used to be WORDS each
// seat guessed from its own local view (the test verdict's list answer, the
// panel's era, the cycle rows) — the field's E-46 repeat and the D5
// false-negative grew from that. The lifecycle is now ONE PERSISTED state
// machine under ONE key, and every seat speaks FROM it:
//
//   never-created → created(id, at) → read(at) → written(at)
//
//   remote-absent  — a positively-observed ABSENT remote (the honest
//                    backward step — the ground truth, never a guess)
//   remote-read    — the transport leg's blob decoded with THIS sync key
//                    (a file observed + read: created facts ride the
//                    evidence when the transport offers them)
//   remote-written — the upload leg RESOLVED (the R-177.4 landed truth —
//                    the copy LANDED; the read-back confirm is a separate
//                    verdict and never demotes the write)
//
// Storage-shape: plain JSON only; the fields are metadata (file id, byte
// counts, instants) — never a secret, never credential material.
export const ENVELOPE_LIFECYCLE_KEY = 'ucrypt:envelopeLifecycle'

export async function getEnvelopeLifecycle() {
  try {
    const { [ENVELOPE_LIFECYCLE_KEY]: lc } = await chrome.storage.local.get(ENVELOPE_LIFECYCLE_KEY)
    return (lc && typeof lc === 'object' && typeof lc.state === 'string')
      ? lc
      : { state: 'never-created', at: 0 }
  } catch { return { state: 'never-created', at: 0 } }
}

async function noteEnvelopeLifecycle(event, evidence = null) {
  try {
    const cur = await getEnvelopeLifecycle()
    const now = Date.now()
    const next = { ...cur, at: now }
    const takeEvidence = () => {
      if (evidence && typeof evidence === 'object') {
        if (evidence.fileId) next.fileId = String(evidence.fileId).slice(0, 64)
        if (Number.isFinite(Number(evidence.bytes))) next.bytes = Number(evidence.bytes)
        if (evidence.modifiedTime) next.modifiedTime = String(evidence.modifiedTime).slice(0, 40)
      }
    }
    if (event === 'remote-absent') {
      next.state = 'never-created'
      next.fileId = null
      next.bytes = null
    } else if (event === 'remote-read') {
      takeEvidence()
      if (cur.state === 'never-created') next.createdAt = now
      if (cur.state === 'never-created' || cur.state === 'created') next.state = 'read'
      next.readAt = now
    } else if (event === 'remote-written') {
      if (evidence && Number.isFinite(Number(evidence.bytes))) next.writtenBytes = Number(evidence.bytes)
      next.state = 'written'
      next.writtenAt = now
    }
    await chrome.storage.local.set({ [ENVELOPE_LIFECYCLE_KEY]: next })
  } catch { /* the lifecycle never blocks sync */ }
}

/** The lifecycle's OWNER-FACING words (the one composer — every seat renders
 * FROM this, never its own guess; i18n keys ride the surfaces). */
export function envelopeLifecycleWords(lc, hh) {
  const l = lc && typeof lc === 'object' ? lc : { state: 'never-created' }
  switch (l.state) {
    case 'written': return `vault envelope present (written ${hh || ''})`.replace(' )', ')')
    case 'read': return `vault envelope present (read ${hh || ''})`.replace(' )', ')')
    case 'created': return `vault envelope present (created ${hh || ''})`.replace(' )', ')')
    default: return 'vault not created yet (the first sync will create it)'
  }
}

/**
 * v2.15.0 — R24-F1: first-hop outcome ledger, the chrome.storage.sync twin of
 * recordPushOutcome(). Written on EVERY chunked-sync write attempt so the
 * popup Sync tab can show whether the built-in browser hop actually works on
 * this profile (it silently does not on de-Googled Chromium builds).
 */
async function recordHopOutcome(outcome) {
  try {
    // R174 — the build stamp rides the hop row too (R-174.6).
    await chrome.storage.local.set({ [LAST_HOP_KEY]: { ...outcome, build: ledgerBuildStamp() } })
  } catch { /* ledger is best-effort */ }
}

// --- Chunked chrome.storage.sync blob storage ------------------------------

async function writeChunkedSync(blob) {
  const chunks = []
  for (let i = 0; i < blob.length; i += SYNC_CHUNK_SIZE) chunks.push(blob.slice(i, i + SYNC_CHUNK_SIZE))

  // Clean up any legacy/old chunks beyond the current count
  const { [SYNC_META_KEY]: meta } = await chrome.storage.sync.get(SYNC_META_KEY)
  const oldCount = meta?.chunks || 0
  if (oldCount > chunks.length) {
    const stale = []
    for (let i = chunks.length; i < oldCount; i++) stale.push(SYNC_CHUNK_PREFIX + i)
    await chrome.storage.sync.remove(stale).catch(() => {})
  }

  const payload = {}
  payload[SYNC_META_KEY] = { chunks: chunks.length, updatedAt: Date.now() }
  chunks.forEach((c, i) => { payload[SYNC_CHUNK_PREFIX + i] = c })
  await chrome.storage.sync.set(payload)
  return chunks.length
}

async function readChunkedSync() {
  // Legacy single-key blob (v2.1.0)
  const legacy = (await chrome.storage.sync.get('ucrypt:vaultSync'))['ucrypt:vaultSync']
  if (legacy) return legacy
  const { [SYNC_META_KEY]: meta } = await chrome.storage.sync.get(SYNC_META_KEY)
  if (!meta?.chunks) return null
  const keys = []
  for (let i = 0; i < meta.chunks; i++) keys.push(SYNC_CHUNK_PREFIX + i)
  const stored = await chrome.storage.sync.get(keys)
  let blob = ''
  for (const k of keys) {
    if (!stored[k]) return null
    blob += stored[k]
  }
  return blob
}

// ---------------------------------------------------------------------------
// ENTRY ACCESS
// ---------------------------------------------------------------------------

/**
 * v2.11.0 — SERVING FIX (clinical audit round 20, findings F1/F2/F3).
 *
 * The old implementation was `entries.filter(e => e.domain === domain)`:
 *   F1 — it served NON-LOGIN entries. Imported bookmarks (Netscape HTML)
 *        carry REAL hostnames (`domain: csvDomain(url)`), so after importing
 *        bookmarks the autofill overlay offered them as "saved logins" and
 *        Fill wrote an EMPTY password over whatever the user had typed.
 *        Only login entries are servable — 2FA seeds, notes, cards,
 *        bookmarks, history and forms are never autofill material.
 *   F2 — it matched the hostname EXACTLY. A login saved on
 *        `accounts.example.com` was never offered on `example.com` or
 *        `login.accounts.example.com` — Brave/Chrome serve per SITE
 *        (eTLD+1). Exact-domain matches rank first; same-site matches
 *        follow (same trust boundary the Chrome/Brave use).
 *   F3 — the order was insertion order, so "Fill now" always filled the
 *        FIRST-SAVED login. Matches now rank by (exact > same-site), then
 *        most-recently-UPDATED first — the entry the user probably means.
 *
 * An empty/invalid page domain serves nothing.
 *
 * v2.16.0 — Brave parity gap closed: alias domains (entry.uris) match at
 * rank 0 like the primary domain (exact hostname), and take part in the
 * same-site (eTLD+1) ranking at rank 1. A login saved for
 * accounts.example.com with the alias example.org now serves on both.
 */
export function getEntriesForDomain(domain) {
  if (!isUnlocked || !vaultData?.entries) return []
  const page = String(domain || '').trim().toLowerCase()
  if (!page) return []
  let siteKey = ''
  try {
    // sites.js is side-effect-free and tiny; vault.js imports it statically
    // (see the import block at the top of this file).
    siteKey = siteKeyOf(page)
  } catch { siteKey = '' }
  const scored = []
  for (const e of vaultData.entries) {
    if (!isLoginEntry(e)) continue
    const uris = Array.isArray(e.uris) ? e.uris : []
    let rank = null
    if (e.domain === page || uris.includes(page)) rank = 0
    else if (siteKey) {
      const hosts = [e.domain, ...uris]
      for (const h of hosts) {
        let eKey = ''
        try { eKey = siteKeyOf(h) } catch { eKey = '' }
        if (eKey && eKey === siteKey) { rank = 1; break }
      }
    }
    if (rank === null) continue
    scored.push({ e, rank, at: Number(e.updatedAt) || Number(e.createdAt) || 0 })
  }
  scored.sort((a, b) => a.rank - b.rank || b.at - a.at)
  return scored.map(s => s.e)
}

/**
 * v2.16.0 — last-used tracking (device-local). Called by the background
 * worker every time a fill REALLY happens on a page. Sets lastUsedAt without
 * touching updatedAt (that is "last changed" and drives LWW merge), then
 * persists the local copy ONLY — skipSync keeps usage statistics out of the
 * sync chunks, the transport and the hop ledger entirely.
 */
export async function touchEntry(domain, username) {
  if (!isUnlocked || !vaultData?.entries) return
  const e = vaultData.entries.find(x => x.domain === domain && x.username === username && isLoginEntry(x))
  if (!e) return
  e.lastUsedAt = Date.now()
  await saveVault({ skipTransport: true, skipSync: true })
}

export function getAllEntries() {
  if (!isUnlocked || !vaultData?.entries) return []
  return [...vaultData.entries]
}

/** All login entries (TOTP tokens + imported other-data excluded). */
export function getLoginEntries() {
  if (!isUnlocked || !vaultData?.entries) return []
  return vaultData.entries.filter(isLoginEntry)
}

/** Imported "other data" (notes, cards, identities, bookmarks, history, forms). */
export function getOtherEntries() {
  if (!isUnlocked || !vaultData?.entries) return []
  return vaultData.entries.filter(isOtherEntry)
}

// ---------------------------------------------------------------------------
// TOTP TOKEN ENTRIES (v2.4.0) — stored inside the encrypted vault
// ---------------------------------------------------------------------------

function clamp(n, min, max, fallback) {
  const x = Math.round(Number(n))
  if (!Number.isFinite(x)) return fallback
  return Math.min(max, Math.max(min, x))
}

export function getTotpTokens() {
  if (!isUnlocked || !vaultData?.entries) return []
  return vaultData.entries.filter(e => e.type === 'totp')
}

/**
 * Upsert an authenticator token, keyed by label. Validates the base32 secret
 * through lib/totp.js BEFORE anything is written — a bad secret must never
 * reach the encrypted store.
 */
export async function saveTotpToken(token = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const label = String(token.label || '').trim().slice(0, 64)
  if (!label) throw new Error('Label is required')

  const clean = normalizeSecret(token.secret)
  if (!isValidBase32Secret(clean)) {
    throw new Error('Invalid TOTP secret — expect base32 (A-Z, 2-7), ≥ 8 decoded bytes')
  }

  const now = Date.now()
  const idx = vaultData.entries.findIndex(e => e.type === 'totp' && e.username === label)
  const prev = idx >= 0 ? vaultData.entries[idx] : null
  const totpBlock = prev?.totp && prev.totp.secret === clean
    ? { ...prev.totp } // unchanged secret — preserve stored params
    : {
        secret: clean,
        issuer: String(token.issuer || '').trim().slice(0, 64),
        digits: clamp(token.digits, 6, 10, 6),
        period: clamp(token.period, 15, 120, 30),
        algorithm: ['SHA-1', 'SHA-256', 'SHA-512'].includes(String(token.algorithm || '').toUpperCase())
          ? String(token.algorithm).toUpperCase()
          : 'SHA-1',
      }

  const entry = {
    domain: TOTP_DOMAIN,
    username: label,
    password: '',
    type: 'totp',
    totp: totpBlock,
    createdAt: prev ? prev.createdAt : now,
    updatedAt: now,
  }
  // v2.42.7 — R70 (F-R70-MODEL-1): association metadata — the login this
  // token belongs to, as its nonsecret deterministic key. Nonsecret by
  // construction (domain + username). An explicit '' clears the link (the
  // user removed the association); undefined preserves the existing link.
  const linkIn = token.linkedLoginKey
  if (linkIn !== undefined) {
    const link = String(linkIn).slice(0, 400)
    if (link) entry.linkedLoginKey = link
  } else if (prev?.linkedLoginKey) {
    entry.linkedLoginKey = prev.linkedLoginKey
  }
  if (idx >= 0) vaultData.entries[idx] = entry
  else vaultData.entries.push(entry)

  // A re-add of the same label is a resurrection — clear any tombstone.
  clearTombstone(TOTP_DOMAIN, label)
  await saveVault()
  return entry
}

export async function deleteTotpToken(label) {
  // v2.8.0 — explicit type: the default deleteEntry match is login-only now.
  return deleteEntry(TOTP_DOMAIN, label, 'totp')
}

/**
 * v2.42.7 — R70 §2.4 (F-R70-MODEL-1): legacy attached `login.totp` migration.
 *
 * Old envelopes (≤ the R69 bridge model) may carry a SECOND persisted copy of
 * a TOTP secret attached to its login entry. This migration converts every
 * such login to the ONE canonical representation: a standalone `type:'totp'`
 * entry (secret-match linking first, so an already-stored token is linked,
 * never duplicated) plus the `linkedLoginKey` association, and removes the
 * login's attached copy only after the canonical token exists in the passed
 * in-memory vault. The caller persists through the normal saveVault() path;
 * if that persist fails, storage still holds the legacy blob untouched and
 * the migration simply re-runs at the next unlock — IDEMPOTENT by
 * construction (a migrated vault has no attached copies left to scan).
 *
 * Unreadable seeds are RETAINED, never dropped (order §2.4): the login keeps
 * its legacy block and is counted in `retained` for the report.
 *
 * @param {{entries?:Array}} v the in-memory vault object (mutated in place)
 * @returns {{scanned:number, tokensAdded:number, linksMade:number, secretsRemoved:number, retained:number}}
 */
export function migrateLegacyAttachedTotp(v = vaultData) {
  const report = { scanned: 0, tokensAdded: 0, linksMade: 0, secretsRemoved: 0, retained: 0 }
  if (!v || !Array.isArray(v.entries)) return report
  const now = Date.now()
  for (const e of v.entries) {
    if (!e || !isLoginEntry(e) || !e.totp?.secret) continue
    report.scanned++
    const clean = normalizeSecret(e.totp.secret)
    if (!isValidBase32Secret(clean)) {
      report.retained++ // failure-safe: keep the legacy block, report it
      continue
    }
    // One secret = one token. Identity by secret first (an identical token
    // may already exist under any label) — never create a second copy.
    let token = v.entries.find(t => t?.type === 'totp' && t.totp?.secret === clean)
    if (!token) {
      let label = String(e.totp.issuer || e.username || '').trim().slice(0, 64) || 'Authenticator'
      if (v.entries.some(t => t?.type === 'totp' && t.username === label)) {
        let n = 2
        while (v.entries.some(t => t?.type === 'totp' && t.username === `${label} (${n})`)) n++
        label = `${label} (${n})`
      }
      token = {
        domain: TOTP_DOMAIN, username: label, password: '', type: 'totp',
        totp: {
          secret: clean,
          issuer: String(e.totp.issuer ?? '').trim().slice(0, 64),
          digits: clamp(e.totp.digits, 6, 10, 6),
          period: clamp(e.totp.period, 15, 120, 30),
          algorithm: ['SHA-1', 'SHA-256', 'SHA-512'].includes(String(e.totp.algorithm || '').toUpperCase())
            ? String(e.totp.algorithm).toUpperCase() : 'SHA-1',
        },
        createdAt: now, updatedAt: now,
      }
      v.entries.push(token)
      report.tokensAdded++
    }
    const key = entryKey(e.domain, e.username)
    if (token.linkedLoginKey !== key) {
      token.linkedLoginKey = key
      token.updatedAt = now
      report.linksMade++
    }
    // Canonical token is in place — only now is the duplicate copy removed.
    delete e.totp
    e.updatedAt = now
    report.secretsRemoved++
  }
  return report
}

/**
 * v2.42.7 — R70: read-only view of the current tombstones (device-local
 * deletion markers). Exported so sync tooling and verification suites can
 * prove deletion semantics (a stale peer must not resurrect a deleted
 * entry) without reaching into worker memory.
 */
export function getTombstones() {
  if (!isUnlocked || !vaultData) return []
  return Array.isArray(vaultData.tombstones) ? vaultData.tombstones.map(t => ({ ...t })) : []
}

/** True when a vault object still carries any legacy attached TOTP copy. */
export function hasLegacyAttachedTotp(v = vaultData) {
  return !!v && Array.isArray(v.entries) &&
    v.entries.some(e => e && isLoginEntry(e) && e.totp?.secret)
}

// ---------------------------------------------------------------------------
// TOMBSTONES + ENTRY-LEVEL MERGE (v2.4.0)
// ---------------------------------------------------------------------------

function entryKey(domain, username) {
  return `${domain}\u0000${username}`
}

function recordTombstone(domain, username) {
  if (!Array.isArray(vaultData.tombstones)) vaultData.tombstones = []
  const key = entryKey(domain, username)
  const existing = vaultData.tombstones.find(t => t && t.domain === domain && t.username === username)
  const now = Date.now()
  if (existing) existing.deletedAt = now
  else vaultData.tombstones.push({ domain, username, deletedAt: now })
}

function clearTombstone(domain, username) {
  if (!Array.isArray(vaultData?.tombstones)) return
  vaultData.tombstones = vaultData.tombstones.filter(
    t => !(t && t.domain === domain && t.username === username)
  )
}

function pruneTombstones() {
  if (!Array.isArray(vaultData?.tombstones)) return
  const cutoff = Date.now() - TOMBSTONE_TTL_MS
  vaultData.tombstones = vaultData.tombstones.filter(t => t && (t.deletedAt || 0) >= cutoff)
}

/**
 * UCRYPT-17 — Type-aware merge key so non-login entry types (bookmark, note,
 * card, identity, form, totp) never collide with login entries sharing the
 * same (domain, username) tuple during mergeVaults or canonicalVaultJson.
 * Login entries keep the exact legacy key `${domain}\u0000${username}` for
 * 100% backward compatibility.
 */
export function mergeEntryKey(e) {
  if (!e) return ''
  const base = entryKey(e.domain, e.username)
  const t = typeof e.type === 'string' && e.type && e.type !== 'login' ? e.type : ''
  return t ? `${base}\u0000type:${t}` : base
}

function mergeTombstoneKey(t) {
  if (!t) return ''
  const base = entryKey(t.domain, t.username)
  const type = typeof t.type === 'string' && t.type && t.type !== 'login' ? t.type : ''
  return type ? `${base}\u0000type:${type}` : base
}

/**
 * Merge two vault snapshots (local + remote) into a third. Pure — no chrome,
 * no IO — so the tests can hammer it directly.
 *
 * Rules:
 *   - entries unify on mergeEntryKey(e) (domain, username, and non-login type); per-entry LWW on updatedAt
 *   - UCRYPT-16: when two login entries share the same key with DIFFERENT non-empty passwords,
 *     the losing side's password is preserved in `winner.history` with `source: 'sync-conflict-copy'`
 *     so a silent LWW merge never destroys a password modified on another device
 *   - a tombstone removes an entry whose updatedAt is NOT newer than it
 *   - tombstone sets union, keeping the latest deletedAt per key
 *   - tombstones older than TOMBSTONE_TTL_MS are dropped (peers converged by then)
 *   - lastModified carries over as the max of both sides
 */
export function mergeVaults(local, remote) {
  const tmap = new Map() // key -> deletedAt (max of both sides)
  for (const side of [local, remote]) {
    for (const t of (Array.isArray(side?.tombstones) ? side.tombstones : [])) {
      if (!t || t.domain == null || t.username == null) continue
      const k = mergeTombstoneKey(t)
      tmap.set(k, Math.max(tmap.get(k) || 0, t.deletedAt || 0))
    }
  }

  const emap = new Map() // key -> entry (newest wins, preserving conflict-copy password history)
  for (const side of [local, remote]) {
    for (const e of (Array.isArray(side?.entries) ? side.entries : [])) {
      if (!e || e.domain == null || e.username == null) continue
      const k = mergeEntryKey(e)
      const prev = emap.get(k)
      if (!prev) {
        emap.set(k, e)
        continue
      }
      const eWins = (e.updatedAt || 0) > (prev.updatedAt || 0)
      const winner = eWins ? e : prev
      const loser = eWins ? prev : e
      const isLogin = (!winner.type || winner.type === 'login') && (!loser.type || loser.type === 'login')
      const winPw = String(winner.password ?? '')
      const losePw = String(loser.password ?? '')
      if (isLogin && winPw && losePw && winPw !== losePw) {
        const winHist = Array.isArray(winner.history) ? winner.history : []
        const loseHist = Array.isArray(loser.history) ? loser.history : []
        const combinedHist = [...winHist]
        if (!combinedHist.some(h => h && h.password === losePw)) {
          combinedHist.unshift({
            password: losePw,
            changedAt: loser.updatedAt || loser.createdAt || Date.now(),
            source: 'sync-conflict-copy',
          })
        }
        for (const h of loseHist) {
          if (h && h.password && h.password !== winPw && !combinedHist.some(x => x && x.password === h.password)) {
            combinedHist.push(h)
          }
        }
        emap.set(k, {
          ...winner,
          history: combinedHist.slice(0, PASSWORD_HISTORY_CAP),
        })
      } else {
        emap.set(k, winner)
      }
    }
  }

  const entries = []
  for (const [k, e] of emap) {
    const baseKey = entryKey(e.domain, e.username)
    const deletedAt = tmap.get(k) ?? ((!e.type || e.type === 'login') ? tmap.get(baseKey) : undefined)
    if (deletedAt != null && deletedAt >= (e.updatedAt || 0)) continue // deletion wins
    entries.push(e)
  }

  const cutoff = Date.now() - TOMBSTONE_TTL_MS
  const tombstones = []
  for (const [k, deletedAt] of tmap) {
    if (deletedAt < cutoff) continue
    const parts = k.split('\u0000')
    const domain = parts[0] || ''
    const username = parts[1] || ''
    const typePart = parts[2] && parts[2].startsWith('type:') ? parts[2].slice(5) : undefined
    tombstones.push({
      domain,
      username,
      ...(typePart ? { type: typePart } : {}),
      deletedAt,
    })
  }

  return {
    entries,
    tombstones,
    lastModified: Math.max(local?.lastModified || 0, remote?.lastModified || 0),
  }
}

/**
 * v2.16.0 — normalize an alias-URI list from user input. Accepts full URLs or
 * bare hostnames; extracts the hostname, lowercases, de-dupes, caps at 10.
 * Returns undefined for an effectively-empty list so the canonical JSON
 * omits the field entirely (old entries stay byte-identical).
 */
function normalizeUris(uris) {
  if (!Array.isArray(uris)) return undefined
  const out = []
  for (const raw of uris) {
    let s = String(raw || '').trim().toLowerCase()
    if (!s) continue
    try {
      const u = new URL(s.includes('://') ? s : 'https://' + s)
      s = u.hostname
    } catch {
      s = s.replace(/^https?:\/\//, '').split('/')[0].trim()
    }
    // v2.19.0 — R28-F9 (audit): a trailing-dot FQDN ("example.com.") is the
    // same host for every serving purpose — strip it so it de-dupes against
    // the bare hostname instead of riding along as a phantom alias.
    s = s.replace(/\.+$/, '')
    if (!s || !s.includes('.') || /\s/.test(s) || s.length > 253) continue
    if (!out.includes(s)) out.push(s)
    if (out.length >= 10) break
  }
  return out.length ? out : undefined
}

/**
 * v2.16.0 — password history helper: the previous password of an entry
 * becomes a history record (capped at PASSWORD_HISTORY_CAP). Empty previous
 * passwords are never recorded. Returns undefined when there is nothing to
 * keep so old entries stay byte-identical in the canonical JSON.
 */
function pushPasswordHistory(prev) {
  if (!prev) return undefined
  const prevPw = String(prev.password ?? '')
  const rest = Array.isArray(prev.history) ? prev.history : []
  if (!prevPw) return rest.length ? rest.slice(0, PASSWORD_HISTORY_CAP) : undefined
  return [
    { password: prevPw, changedAt: prev.updatedAt || prev.createdAt || Date.now() },
    ...rest,
  ].slice(0, PASSWORD_HISTORY_CAP)
}

/** Canonical, order-independent JSON of entries+tombstones (for change detection & SHA-256 hashing). */
export function canonicalVaultJson(v) {
  const entries = (Array.isArray(v?.entries) ? v.entries : [])
    .map(e => ({ e, k: mergeEntryKey(e) }))
    .sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : 0))
    .map(({ e }) => ({
      domain: e.domain, username: e.username, password: e.password,
      type: e.type || undefined, totp: e.totp || undefined,
      // v2.42.7 — R70 (F-R70-MODEL-1): token→login association metadata
      // (nonsecret) travels so the pairing survives sync/merge/restore.
      linkedLoginKey: e.linkedLoginKey || undefined,
      // v2.7.0 — Import Center payload fields. All optional: old entries
      // serialize byte-identically (undefined keys are omitted by JSON).
      note: e.note || undefined,
      card: e.card || undefined,
      address: e.address || undefined,
      fields: e.fields || undefined,
      meta: e.meta || undefined,
      // v2.16.0 — Brave parity gap: alias domains (multi-URI per login) and
      // the capped password history travel WITH the entry across devices.
      // lastUsedAt is deliberately NOT canonical: it is device-local usage
      // telemetry and must never create merge churn.
      uris: Array.isArray(e.uris) && e.uris.length ? e.uris : undefined,
      history: Array.isArray(e.history) && e.history.length ? e.history : undefined,
      createdAt: e.createdAt, updatedAt: e.updatedAt,
    }))
  const tombstones = (Array.isArray(v?.tombstones) ? v.tombstones : [])
    .map(t => ({ t, k: mergeTombstoneKey(t) }))
    .sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : 0))
    .map(({ t }) => ({
      domain: t.domain,
      username: t.username,
      ...(t.type && t.type !== 'login' ? { type: t.type } : {}),
      deletedAt: t.deletedAt,
    }))
  return JSON.stringify({ entries, tombstones })
}

/** Canonical payload JSON of a single entry (excluding timestamps/history for content-equality checks). */
export function canonicalEntryPayloadJson(e) {
  if (!e) return ''
  return JSON.stringify({
    domain: e.domain,
    username: e.username,
    password: e.password,
    type: e.type || undefined,
    totp: e.totp || undefined,
    linkedLoginKey: e.linkedLoginKey || undefined,
    note: e.note || undefined,
    card: e.card || undefined,
    address: e.address || undefined,
    fields: e.fields || undefined,
    meta: e.meta || undefined,
    uris: Array.isArray(e.uris) && e.uris.length ? e.uris : undefined,
  })
}

/**
 * UCRYPT-16 — Compute deterministic SHA-256 hex digest of a vault snapshot's
 * canonical JSON (or a pre-computed canonical JSON string).
 */
export async function computeVaultHash(v) {
  const canonical = typeof v === 'string' ? v : canonicalVaultJson(v || { entries: [], tombstones: [] })
  const bytes = new TextEncoder().encode(canonical)
  const digest = await sha256(bytes)
  return Array.from(digest).map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * UCRYPT-16 — Compare local and remote vault snapshots during merge, compute
 * their canonical SHA-256 digests, and produce a structured hash-mismatch &
 * per-entry conflict report for the Sync Settings 'Conflict Resolver' UI.
 * Never includes plaintext passwords or secret values in `diffEntries`.
 */
export async function detectVaultHashConflict(localVault, remoteVault) {
  const safeLocal = localVault && typeof localVault === 'object' ? localVault : { entries: [], tombstones: [], lastModified: 0 }
  const safeRemote = remoteVault && typeof remoteVault === 'object' ? remoteVault : { entries: [], tombstones: [], lastModified: 0 }

  const localCanonical = canonicalVaultJson(safeLocal)
  const remoteCanonical = canonicalVaultJson(safeRemote)
  const mergedVault = mergeVaults(safeLocal, safeRemote)
  const mergedCanonical = canonicalVaultJson(mergedVault)

  const [localHash, remoteHash, mergedHash] = await Promise.all([
    computeVaultHash(localCanonical),
    computeVaultHash(remoteCanonical),
    computeVaultHash(mergedCanonical),
  ])

  const localMap = new Map()
  for (const e of (Array.isArray(safeLocal.entries) ? safeLocal.entries : [])) {
    if (e && e.domain != null && e.username != null) localMap.set(mergeEntryKey(e), e)
  }
  const remoteMap = new Map()
  for (const e of (Array.isArray(safeRemote.entries) ? safeRemote.entries : [])) {
    if (e && e.domain != null && e.username != null) remoteMap.set(mergeEntryKey(e), e)
  }

  const localTombMap = new Map()
  for (const t of (Array.isArray(safeLocal.tombstones) ? safeLocal.tombstones : [])) {
    if (t && t.domain != null && t.username != null) localTombMap.set(mergeTombstoneKey(t), t.deletedAt || 0)
  }
  const remoteTombMap = new Map()
  for (const t of (Array.isArray(safeRemote.tombstones) ? safeRemote.tombstones : [])) {
    if (t && t.domain != null && t.username != null) remoteTombMap.set(mergeTombstoneKey(t), t.deletedAt || 0)
  }

  const allKeys = new Set([...localMap.keys(), ...remoteMap.keys()])
  const diffEntries = []
  let conflictCount = 0
  let localOnlyCount = 0
  let cloudOnlyCount = 0

  for (const k of [...allKeys].sort()) {
    const l = localMap.get(k)
    const r = remoteMap.get(k)
    if (l && r) {
      const lPayload = canonicalEntryPayloadJson(l)
      const rPayload = canonicalEntryPayloadJson(r)
      if (lPayload !== rPayload) {
        conflictCount += 1
        const lUpd = l.updatedAt || l.createdAt || 0
        const rUpd = r.updatedAt || r.createdAt || 0
        const pwChanged = String(l.password ?? '') !== String(r.password ?? '')
        const ntChanged = String(l.note ?? '') !== String(r.note ?? '')
        diffEntries.push({
          key: k,
          domain: String(l.domain || ''),
          username: String(l.username || ''),
          type: String(l.type || r.type || 'login'),
          kind: 'content-mismatch',
          conflictKind: 'content-mismatch',
          localUpdatedAt: lUpd,
          remoteUpdatedAt: rUpd,
          winner: rUpd > lUpd ? 'cloud' : 'local',
          passwordDiffers: pwChanged,
          passwordChanged: pwChanged,
          noteDiffers: ntChanged,
          noteChanged: ntChanged,
        })
      }
    } else if (l && !r) {
      const rDeletedAt = remoteTombMap.get(k) ?? ((!l.type || l.type === 'login') ? remoteTombMap.get(entryKey(l.domain, l.username)) : undefined)
      const lUpd = l.updatedAt || l.createdAt || 0
      if (rDeletedAt != null) {
        conflictCount += 1
        diffEntries.push({
          key: k,
          domain: String(l.domain || ''),
          username: String(l.username || ''),
          type: String(l.type || 'login'),
          kind: 'delete-vs-edit',
          conflictKind: 'delete-vs-edit',
          localUpdatedAt: lUpd,
          remoteUpdatedAt: rDeletedAt,
          winner: rDeletedAt >= lUpd ? 'cloud' : 'local',
          passwordDiffers: false,
          passwordChanged: false,
          noteDiffers: false,
          noteChanged: false,
        })
      } else {
        localOnlyCount += 1
        diffEntries.push({
          key: k,
          domain: String(l.domain || ''),
          username: String(l.username || ''),
          type: String(l.type || 'login'),
          kind: 'local-only',
          conflictKind: 'local-only',
          localUpdatedAt: lUpd,
          remoteUpdatedAt: 0,
          winner: 'local',
          passwordDiffers: false,
          passwordChanged: false,
          noteDiffers: false,
          noteChanged: false,
        })
      }
    } else if (!l && r) {
      const lDeletedAt = localTombMap.get(k) ?? ((!r.type || r.type === 'login') ? localTombMap.get(entryKey(r.domain, r.username)) : undefined)
      const rUpd = r.updatedAt || r.createdAt || 0
      if (lDeletedAt != null) {
        conflictCount += 1
        diffEntries.push({
          key: k,
          domain: String(r.domain || ''),
          username: String(r.username || ''),
          type: String(r.type || 'login'),
          kind: 'delete-vs-edit',
          conflictKind: 'delete-vs-edit',
          localUpdatedAt: lDeletedAt,
          remoteUpdatedAt: rUpd,
          winner: lDeletedAt >= rUpd ? 'local' : 'cloud',
          passwordDiffers: false,
          passwordChanged: false,
          noteDiffers: false,
          noteChanged: false,
        })
      } else {
        cloudOnlyCount += 1
        diffEntries.push({
          key: k,
          domain: String(r.domain || ''),
          username: String(r.username || ''),
          type: String(r.type || 'login'),
          kind: 'cloud-only',
          conflictKind: 'cloud-only',
          localUpdatedAt: 0,
          remoteUpdatedAt: rUpd,
          winner: 'cloud',
          passwordDiffers: false,
          passwordChanged: false,
          noteDiffers: false,
          noteChanged: false,
        })
      }
    }
  }

  const hasHashMismatch = localHash !== remoteHash
  const hasDirectCollision = conflictCount > 0
  const bothSidesDiverged = hasHashMismatch && mergedHash !== localHash && mergedHash !== remoteHash
  const cappedDiffs = diffEntries.slice(0, 50)
  const directConflicts = cappedDiffs.filter(
    d => d.conflictKind === 'content-mismatch' || d.conflictKind === 'delete-vs-edit'
  )

  return {
    hashMismatch: hasHashMismatch,
    hasHashMismatch,
    hasConflict: hasDirectCollision,
    hasDirectCollision,
    bothSidesDiverged,
    requiresManualResolution: hasHashMismatch && (hasDirectCollision || bothSidesDiverged),
    localHash,
    remoteHash,
    mergedHash,
    localBytes: localCanonical.length,
    remoteBytes: remoteCanonical.length,
    mergedBytes: mergedCanonical.length,
    localEntryCount: Array.isArray(safeLocal.entries) ? safeLocal.entries.length : 0,
    remoteEntryCount: Array.isArray(safeRemote.entries) ? safeRemote.entries.length : 0,
    mergedEntryCount: Array.isArray(mergedVault.entries) ? mergedVault.entries.length : 0,
    localTombstoneCount: Array.isArray(safeLocal.tombstones) ? safeLocal.tombstones.length : 0,
    remoteTombstoneCount: Array.isArray(safeRemote.tombstones) ? safeRemote.tombstones.length : 0,
    localLastModified: Number(safeLocal.lastModified) || 0,
    remoteLastModified: Number(safeRemote.lastModified) || 0,
    conflictCount,
    localOnlyCount,
    cloudOnlyCount,
    conflicts: directConflicts,
    diffs: cappedDiffs,
    diffEntries: cappedDiffs,
    mergedVault,
  }
}

export async function saveEntry(domain, username, password, note, uris) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const idx = vaultData.entries.findIndex(e => e.domain === domain && e.username === username)
  // v2.9.0 — DATA-LOSS FIX: updating a login that carries imported extras
  // (note / card / address / fields / meta) used to rebuild the entry with
  // only the core fields and silently WIPE the extras. Preserve them.
  const prev = idx >= 0 ? vaultData.entries[idx] : null
  const entry = {
    domain, username, password,
    ...(prev ? {
      type: prev.type, card: prev.card,
      address: prev.address, fields: prev.fields, meta: prev.meta,
      // v2.42.5 — R69 (F-R69-IMP-1 class): the attached authenticator seed
      // and the password history are vault content exactly like card/fields
      // — an edit through this path must never silently drop them.
      totp: prev.totp, history: prev.history,
    } : {}),
    createdAt: prev ? prev.createdAt : Date.now(),
    updatedAt: Date.now(),
  }
  // v2.9.0 — optional per-login note: explicit argument wins, otherwise an
  // existing note is preserved.
  if (note !== undefined) entry.note = String(note)
  else if (prev && prev.note !== undefined) entry.note = prev.note
  // v2.16.0 — alias domains (multi-URI): explicit argument wins, otherwise
  // an existing list is preserved.
  if (uris !== undefined) {
    const clean = normalizeUris(uris)
    if (clean) entry.uris = clean
  } else if (prev && prev.uris !== undefined) {
    entry.uris = prev.uris
  }
  // v2.16.0 — password history: a rotation through ANY save path (save
  // prompt, popup, import dedupe path) keeps the previous password.
  if (prev && prev.password !== password) {
    const hist = pushPasswordHistory(prev)
    if (hist) entry.history = hist
  }
  if (idx >= 0) vaultData.entries[idx] = entry
  else vaultData.entries.push(entry)
  // Re-saving a previously deleted login is a resurrection — drop the
  // tombstone so a peer's older tombstone cannot delete it again (v2.4.0).
  clearTombstone(domain, username)
  await saveVault()
  return entry
}

/**
 * v2.9.0 — ATOMIC entry update (rename / password change / note edit).
 *
 * The old options-dialog flow issued DELETE_ENTRY then SAVE_ENTRY: two
 * persists, two pushes, and a failure window where the old key was already
 * gone but the new one was not yet saved. updateEntry does everything in ONE
 * mutation + ONE persist + ONE push:
 *   - rename (domain/username changed) → tombstone the old key so peers drop
 *     it, clear any tombstone on the new key (resurrection semantics),
 *   - reject when the target key already exists (never silently merge),
 *   - patch fields: password, note, uris (any extra key provided is preserved
 *     on the entry; unknown keys are rejected to keep vault shapes canonical).
 *
 * @returns the updated entry
 */
export async function updateEntry(origDomain, origUsername, patch = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(origDomain ?? '')
  const ou = String(origUsername ?? '')
  const idx = vaultData.entries.findIndex(e => e.domain === od && e.username === ou)
  if (idx < 0) throw new Error('Original entry not found — it may have been deleted')

  const allowed = ['domain', 'username', 'password', 'note']
  const nextDomain = patch.domain !== undefined ? String(patch.domain) : od
  const nextUsername = patch.username !== undefined ? String(patch.username) : ou
  if (!nextDomain || !nextDomain.includes('.') || /\s/.test(nextDomain)) {
    throw new Error('A valid domain is required')
  }
  if (patch.password !== undefined && !String(patch.password)) {
    throw new Error('Password cannot be empty')
  }

  const renamed = nextDomain !== od || nextUsername !== ou
  if (renamed) {
    const clash = vaultData.entries.findIndex(
      e => e !== vaultData.entries[idx] && e.domain === nextDomain && e.username === nextUsername)
    if (clash >= 0) {
      throw new Error(`An entry for ${nextUsername || '(no username)'} @ ${nextDomain} already exists`)
    }
  }

  const prev = vaultData.entries[idx]
  const nextPassword = patch.password !== undefined ? String(patch.password) : prev.password
  const entry = {
    ...prev,
    domain: nextDomain,
    username: nextUsername,
    password: nextPassword,
    note: patch.note !== undefined ? String(patch.note) : prev.note,
    updatedAt: Date.now(),
  }
  // v2.42.7 — R70 §2.3 (F-R70-MODEL-1): a rename must not orphan an
  // authenticator. Tokens linked to the OLD key are re-pointed to the NEW
  // key in the same in-memory batch — one saveVault() persist, atomic, and
  // the rename report stays truthful.
  let relinked = 0
  if (renamed) {
    const oldKey = entryKey(od, ou)
    const newKey = entryKey(nextDomain, nextUsername)
    for (const t of vaultData.entries) {
      if (t.type === 'totp' && t.linkedLoginKey === oldKey) {
        t.linkedLoginKey = newKey
        t.updatedAt = entry.updatedAt
        relinked++
      }
    }
  }
  // v2.16.0 — password history: a real password change through the editor
  // (or a history RESTORE — which is just another update) archives the
  // previous password so the rotation is reversible.
  if (patch.password !== undefined && nextPassword !== prev.password) {
    const hist = pushPasswordHistory(prev)
    if (hist) entry.history = hist
    else delete entry.history
  }
  // v2.16.0 — alias domains (multi-URI per login). Explicit patch wins;
  // an empty/invalid list clears the field. Handled explicitly (NOT through
  // the generic whitelist below) so the value is always normalized.
  if (patch.uris !== undefined) {
    const clean = normalizeUris(patch.uris)
    if (clean) entry.uris = clean
    else delete entry.uris
  }
  // Only whitelisted patch keys can introduce NEW fields (e.g. a first note
  // on an entry that never had one); everything else stays as it was.
  for (const k of allowed) {
    if (prev[k] === undefined && patch[k] !== undefined) entry[k] = patch[k]
  }

  vaultData.entries[idx] = entry
  if (renamed) {
    // Peers must drop the old key: tombstone it. (LWW merge removes entries
    // whose updatedAt is not newer than the tombstone — the old entry is
    // older by construction.) The new key may inherit a stale tombstone.
    recordTombstone(od, ou)
    clearTombstone(nextDomain, nextUsername)
  }
  await saveVault()
  // v2.42.7 — R70 §2.3: the rename report names the relinked authenticators.
  return { ...entry, _relinkedAuthenticators: renamed ? relinked : 0 }
}

/**
 * R160 ARC B′ — T8'S CONFLICTS-AS-COPIES (the import door). The browser
 * export carried a DIFFERENT password for a login the vault already holds:
 * the vault copy stays authoritative (the deepest layer's NEVER-OVERWRITE
 * stands), and the incoming copy is PRESERVED — appended to the entry's
 * password history with the typed provenance ('import-conflict-copy') so
 * the user resolves it later instead of finding the browser's data silently
 * dropped. Capped by PASSWORD_HISTORY_CAP like any history row.
 * @returns {Promise<number>} the previous history length (the undo handle)
 */
export async function appendImportCopy(domain, username, password, { source = 'import-conflict-copy', at = Date.now() } = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(domain ?? '')
  const ou = String(username ?? '')
  const pw = String(password ?? '')
  if (!pw) throw new Error('Import copy without a password is nothing to preserve')
  const idx = vaultData.entries.findIndex(e => e.domain === od && e.username === ou && (e.type === undefined || e.type === 'login'))
  if (idx < 0) throw new Error('Original entry not found — it may have been deleted')
  const prev = vaultData.entries[idx]
  const prevLen = Array.isArray(prev.history) ? prev.history.length : 0
  const row = { password: pw, changedAt: Number(at) || Date.now(), source: String(source || 'import-conflict-copy') }
  prev.history = [row, ...(Array.isArray(prev.history) ? prev.history : [])].slice(0, PASSWORD_HISTORY_CAP)
  prev.updatedAt = prev.updatedAt || Date.now()
  await saveVault()
  return prevLen
}

/**
 * R160 ARC B′ — THE IMPORT COPY'S UNDO DOOR (the transactional rollback's
 * reverse step). Restores the entry's history array to exactly `prevLen`
 * rows (the state before the copy landed). Never used on the happy path.
 */
export async function truncateImportCopy(domain, username, prevLen) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(domain ?? '')
  const ou = String(username ?? '')
  const idx = vaultData.entries.findIndex(e => e.domain === od && e.username === ou && (e.type === undefined || e.type === 'login'))
  if (idx < 0) return false
  const prev = vaultData.entries[idx]
  const n = Number(prevLen)
  if (!Number.isFinite(n) || n < 0) return false
  if (Array.isArray(prev.history) && prev.history.length > n) {
    const rest = prev.history.slice(n)
    if (rest.length) prev.history = rest
    else delete prev.history
    await saveVault()
    return true
  }
  return false
}

/**
 * R160 ARC B′ — T8'S NEWEST-WINS-ON-EMPTY (the import fill door). The vault
 * login exists but its password field is EMPTY: the browser export's value
 * fills the empty slot (the newest data the user has for that login). The
 * door REFUSES when the vault copy already holds a password — a conflict
 * belongs to the COPY class (appendImportCopy), never to a fill.
 * @returns {Promise<boolean>} whether the fill happened
 */
export async function fillEmptyPassword(domain, username, password) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(domain ?? '')
  const ou = String(username ?? '')
  const pw = String(password ?? '')
  if (!pw) throw new Error('An empty import value fills nothing')
  const idx = vaultData.entries.findIndex(e => e.domain === od && e.username === ou && (e.type === undefined || e.type === 'login'))
  if (idx < 0) throw new Error('Original entry not found — it may have been deleted')
  const prev = vaultData.entries[idx]
  if (String(prev.password ?? '')) return false // the slot is not empty — never a silent overwrite
  prev.password = pw
  prev.updatedAt = Date.now()
  await saveVault()
  return true
}

/**
 * R160 ARC B′ — THE IMPORT FILL'S UNDO DOOR (the transactional rollback's
 * reverse step). Restores the EXACT previous password value (including the
 * empty string the fill replaced) WITHOUT archiving it into the password
 * history — a rollback must leave the vault byte-true, not leave a residue
 * row. Never used on the happy path.
 */
export async function restorePasswordValue(domain, username, previousPassword) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(domain ?? '')
  const ou = String(username ?? '')
  const idx = vaultData.entries.findIndex(e => e.domain === od && e.username === ou && (e.type === undefined || e.type === 'login'))
  if (idx < 0) return false
  const prev = vaultData.entries[idx]
  const was = String(prev.password ?? '')
  const next = String(previousPassword ?? '')
  if (was === next) return false
  prev.password = next
  await saveVault()
  return true
}

/**
 * v2.10.0 — ATOMIC edit for imported "other data" (notes, cards,
 * identities, bookmarks, history, forms). The Import Center pane could only
 * DELETE these items; a mistyped title or a moved bookmark meant deleting
 * and re-importing. Like updateEntry, this is ONE mutation + ONE persist +
 * ONE push.
 *
 * Key model: other entries live under pseudo-domains ('__note__',
 * '__bookmark__', …) so they can never collide with a real login. The match
 * is exact on (domain, username, TYPE) — deleting/editing a note can never
 * touch a login, bookmark or any other sibling that shares the title.
 *
 * Patchable fields (everything else is rejected):
 *   username — the human title (all types)
 *   note     — free text (note / card / address)
 *   url      — bookmark target, validated as http(s) (bookmark only)
 *   folder   — bookmark folder label (bookmark only)
 *
 * Renames tombstone the old (domain, username) key — same semantics as
 * updateEntry; peers drop the stale copy and adopt the new one.
 *
 * @returns the updated entry
 */
export async function updateOtherEntry(origDomain, origUsername, type, patch = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const od = String(origDomain ?? '')
  const ou = String(origUsername ?? '')
  const t = String(type ?? '')
  if (!OTHER_ENTRY_TYPES.includes(t)) {
    throw new Error(`Unknown entry type: ${t || '(none)'}`)
  }
  const idx = vaultData.entries.findIndex(
    e => e.domain === od && e.username === ou && e.type === t)
  if (idx < 0) throw new Error('Original entry not found — it may have been deleted')

  const nextUsername = patch.username !== undefined ? String(patch.username) : ou
  if (!nextUsername.trim()) {
    throw new Error('A title is required')
  }
  if (nextUsername.length > 320) {
    throw new Error('Title is too long (max 320 characters)')
  }

  const prev = vaultData.entries[idx]
  const entry = { ...prev, username: nextUsername, updatedAt: Date.now() }

  if (patch.note !== undefined && ['note', 'card', 'address'].includes(t)) {
    const note = String(patch.note)
    if (note.length > 10000) throw new Error('Note is too long (max 10000 characters)')
    if (note) entry.note = note
    else delete entry.note
  }

  if (t === 'bookmark' && (patch.url !== undefined || patch.folder !== undefined)) {
    const meta = { ...(prev.meta || {}) }
    if (patch.url !== undefined) {
      const url = String(patch.url).trim()
      if (url) {
        let parsed = null
        try { parsed = new URL(url) } catch { /* not absolute — validate below */ }
        const ok = parsed
          ? (parsed.protocol === 'http:' || parsed.protocol === 'https:')
          : /^(https?:\/\/)?[^\s]+\.[^\s]+/i.test(url) // tolerate pasted bare domains
        if (!ok) throw new Error('Bookmark URL must be a valid http(s) address')
        meta.url = url
      } else {
        delete meta.url
      }
    }
    if (patch.folder !== undefined) {
      const folder = String(patch.folder).trim()
      if (folder) meta.folder = folder.slice(0, 253)
      else delete meta.folder
    }
    if (Object.keys(meta).length) entry.meta = meta
    else delete entry.meta
  }

  // v2.18.0 — R27: history/form entries gained a URL field in the edit
  // dialog (same validation as bookmarks; the rest of meta — visit counts,
  // timestamps — is preserved through the {...prev} spread).
  if ((t === 'history' || t === 'form') && patch.url !== undefined) {
    const meta = { ...(prev.meta || {}) }
    const url = String(patch.url).trim()
    if (url) {
      let parsed = null
      try { parsed = new URL(url) } catch { /* not absolute — validate below */ }
      const ok = parsed
        ? (parsed.protocol === 'http:' || parsed.protocol === 'https:')
        : /^(https?:\/\/)?[^\s]+\.[^\s]+/i.test(url)
      if (!ok) throw new Error('URL must be a valid http(s) address')
      meta.url = url.slice(0, 2048)
    } else {
      delete meta.url
    }
    if (Object.keys(meta).length) entry.meta = meta
    else delete entry.meta
  }

  // v2.18.0 — R27: structured CARD editing. Number is required (the vault
  // key uses its last four digits); spaces/dashes are stripped like the
  // importer does; the cardholder ALWAYS mirrors entry.username, exactly
  // like itemToVaultEntry creates cards. Unchanged payloads never bump the
  // entry (JSON compare before assign).
  if (t === 'card' && patch.card !== undefined) {
    const c = patch.card && typeof patch.card === 'object' ? patch.card : {}
    const prevCard = prev.card || {}
    const number = String(c.number !== undefined ? c.number : prevCard.number || '').replace(/[\s-]+/g, '')
    if (!number) throw new Error('Card number is required')
    if (number.length > 32) throw new Error('Card number is too long (max 32 digits)')
    const cleanCard = {
      holder: String(nextUsername || '').slice(0, 200),
      brand: String(c.brand !== undefined ? c.brand : prevCard.brand || '').trim().slice(0, 60),
      number,
      expMonth: String(c.expMonth !== undefined ? c.expMonth : prevCard.expMonth || '').trim().slice(0, 4),
      expYear: String(c.expYear !== undefined ? c.expYear : prevCard.expYear || '').trim().slice(0, 8),
      code: String(c.code !== undefined ? c.code : prevCard.code || '').trim().slice(0, 8),
    }
    if (JSON.stringify(cleanCard) !== JSON.stringify(prev.card || {})) entry.card = cleanCard
  }

  // v2.18.0 — R27: structured IDENTITY editing. Whitelisted keys, values
  // capped at 200 chars, empty values dropped (the import shape); the name
  // ALWAYS mirrors entry.username. Existing unknown keys on prev.address
  // survive unless overwritten (import never creates them, but never
  // destroy what a peer device may have written).
  if (t === 'address' && patch.address !== undefined) {
    const a = patch.address && typeof patch.address === 'object' ? patch.address : {}
    const prevAddress = prev.address || {}
    const cleanAddress = { ...prevAddress }
    const ADDRESS_KEYS = ['email', 'phone', 'org', 'street', 'city', 'state', 'zip', 'country', 'ssn']
    for (const k of ADDRESS_KEYS) {
      if (a[k] === undefined) continue
      const v = String(a[k]).trim().slice(0, 200)
      if (v) cleanAddress[k] = v
      else delete cleanAddress[k]
    }
    // v2.42.8 — R71-P: a patch may NAME the identity explicitly (the profile
    // capture review stores the captured person name even when the profile
    // label/title differs, e.g. title "Home" for "Ada Lovelace"). Legacy
    // mirror semantics stay intact when the patch leaves `name` unnamed —
    // the manager editor and every R27 flow keep their exact behavior.
    if (a.name === undefined || !String(a.name).trim()) {
      cleanAddress.name = String(nextUsername || '').slice(0, 200)
    } else {
      cleanAddress.name = String(a.name).trim().slice(0, 200)
    }
    const keys = Object.keys(cleanAddress)
    if (keys.length > 20) throw new Error('Too many identity fields (max 20)')
    if (JSON.stringify(cleanAddress) !== JSON.stringify(prev.address || {})) entry.address = cleanAddress
    if (!keys.length) delete entry.address
  }

  // v2.18.0 — R27: custom fields[] editing for note/card/address/form
  // (mirrors saveEntriesBatch's validation; empty list removes the key).
  if (patch.fields !== undefined && ['note', 'card', 'address', 'form'].includes(t)) {
    if (!Array.isArray(patch.fields)) throw new Error('Custom fields must be a list')
    if (patch.fields.length > 50) throw new Error('Too many custom fields (max 50)')
    const cleanFields = patch.fields
      .map(f => ({ name: String(f?.name ?? '').trim().slice(0, 100), value: String(f?.value ?? '').slice(0, 1000) }))
      .filter(f => f.name)
    if (cleanFields.length) entry.fields = cleanFields
    else delete entry.fields
  }

  // v2.18.0 — R27: a rename must keep the denormalized holder/name in sync
  // even when the structured payload itself did not change.
  // v2.42.8 — R71-P: when THIS patch named the identity explicitly, the
  // captured person name wins over the title mirror (see the address branch
  // above); every other path keeps the R27 mirror unchanged.
  if (t === 'card' && entry.card && entry.card.holder !== nextUsername) {
    entry.card = { ...entry.card, holder: String(nextUsername || '').slice(0, 200) }
  }
  const patchNamedIdentity = t === 'address' && patch.address !== undefined &&
    patch.address && typeof patch.address === 'object' &&
    String(patch.address.name ?? '').trim() !== ''
  if (t === 'address' && entry.address && !patchNamedIdentity && entry.address.name !== nextUsername) {
    entry.address = { ...entry.address, name: String(nextUsername || '').slice(0, 200) }
  }

  const renamed = nextUsername !== ou
  if (renamed) {
    const clash = vaultData.entries.findIndex(
      e => e !== vaultData.entries[idx] && e.domain === od &&
           e.username === nextUsername && e.type === t)
    if (clash >= 0) {
      throw new Error(`Another ${t} titled "${nextUsername}" already exists`)
    }
  }

  vaultData.entries[idx] = entry
  if (renamed) {
    // Same tombstone semantics as updateEntry: peers drop the old key.
    // The pseudo-domain keeps this isolated from any real login.
    recordTombstone(od, ou)
    clearTombstone(od, nextUsername)
  }
  await saveVault()
  return entry
}

/**
 * v2.7.0 — bulk import path (Import Center). Saves MANY entries with ONE
 * persist + ONE transport push. The v2.6.0 per-row saveEntry loop would have
 * re-encrypted and re-pushed the whole vault once per row — quadratic cost
 * for a 500-row migration.
 *
 * Entry shapes:
 *   logins    {domain, username, password}
 *   tokens    {type:'totp', username:label, totp:{secret,issuer,…}}
 *   other     {type:'note'|'card'|'address'|'bookmark'|'history'|'form', …}
 *
 * NEVER-OVERWRITE at the deepest layer (defense-in-depth): identical content
 * → duplicate, skipped; existing entry with different content → conflict,
 * skipped. The Import Center's plan already filters these, so on the happy
 * path nothing is skipped — but even a buggy caller cannot destroy vault
 * data through this API. Per-item failures (bad TOTP secret, oversized
 * field, …) skip that item and are reported — one bad row never fails the
 * batch.
 *
 * v2.8.0 — opts.awaitPush: when true, the transport push is AWAITED and its
 * real outcome (see pushToTransport) is returned as `.push`, so the import
 * report can state whether the data actually reached the cloud instead of
 * assuming the fire-and-forget push succeeded.
 */
export async function saveEntriesBatch(entries = [], opts = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const list = Array.isArray(entries) ? entries : []
  if (list.length > 10000) throw new Error('Refusing to import more than 10000 entries at once')

  const now = Date.now()
  let added = 0
  let duplicates = 0
  let conflicts = 0
  const skipped = []
  const batchAddedSeeds = new Set() // v2.42.7 — R70: one-secret-one-token inside the batch too

  // TOTP secret validation comes from the static lib/totp.js import.
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') continue
    try {
      if (raw.type === 'totp') {
        const label = String(raw.username || '').trim().slice(0, 64)
        if (!label) { skipped.push({ reason: 'TOTP token without a label' }); continue }
        const clean = normalizeSecret(raw.totp?.secret || raw.secret || '')
        if (!isValidBase32Secret(clean)) {
          skipped.push({ reason: `invalid TOTP secret for "${label}"` })
          continue
        }
        const idx = vaultData.entries.findIndex(e => e.type === 'totp' && e.username === label)
        if (idx >= 0) {
          const prev = vaultData.entries[idx]
          if (prev.totp?.secret === clean) { duplicates++; continue }
          conflicts++
          skipped.push({ reason: `token "${label}" already exists with a different secret — kept the vault copy` })
          continue
        }
        // v2.42.7 — R70 (F-R70-MODEL-1): ONE SECRET, ONE TOKEN — a second
        // token row carrying a seed the vault (or this batch) already holds
        // is a duplicate/no-op regardless of its label.
        const seedOwner = vaultData.entries.find(e => e.type === 'totp' && e.totp?.secret === clean)
        if (seedOwner) {
          duplicates++
          skipped.push({
            reason: batchAddedSeeds.has(clean)
              ? 'identical authenticator seed appears earlier in this batch — first occurrence kept'
              : `identical authenticator seed is already in the vault (token "${seedOwner.username}") — nothing changed`,
          })
          continue
        }
        const entry = {
          domain: TOTP_DOMAIN, username: label, password: '', type: 'totp',
          totp: {
            secret: clean,
            issuer: String(raw.totp?.issuer ?? '').trim().slice(0, 64),
            digits: clamp(raw.totp?.digits, 6, 10, 6),
            period: clamp(raw.totp?.period, 15, 120, 30),
            algorithm: ['SHA-1', 'SHA-256', 'SHA-512'].includes(String(raw.totp?.algorithm || '').toUpperCase())
              ? String(raw.totp.algorithm).toUpperCase() : 'SHA-1',
          },
          createdAt: now, updatedAt: now,
        }
        // v2.42.7 — R70 (F-R70-MODEL-1): the import plan's association
        // metadata rides the item (nonsecret login key) — never the secret
        // itself (a login entry never carries a persisted totp copy).
        const link = String(raw.linkedLoginKey ?? '').slice(0, 400)
        if (link) entry.linkedLoginKey = link
        vaultData.entries.push(entry)
        batchAddedSeeds.add(clean)
        clearTombstone(TOTP_DOMAIN, label)
        added++
        continue
      }

      const domain = String(raw.domain || '').trim().slice(0, 253)
      const username = String(raw.username ?? '').slice(0, 320)
      const password = String(raw.password ?? '').slice(0, 2048)
      if (!domain) { skipped.push({ reason: 'entry without a domain' }); continue }
      if (!isLoginEntry({ type: raw.type })) {
        // other-data entry — light structural validation per type
        const type = String(raw.type)
        const entry = {
          domain, username: username || type, password: '',
          type,
          note: raw.note ? String(raw.note).slice(0, 10000) : undefined,
          card: raw.type === 'card' && raw.card && typeof raw.card === 'object'
            ? {
                holder: String(raw.card.holder || '').slice(0, 200),
                brand: String(raw.card.brand || '').slice(0, 60),
                number: String(raw.card.number || '').replace(/[\s-]/g, '').slice(0, 32),
                expMonth: String(raw.card.expMonth || '').slice(0, 4),
                expYear: String(raw.card.expYear || '').slice(0, 8),
                code: String(raw.card.code || '').slice(0, 8),
              }
            : undefined,
          address: raw.type === 'address' && raw.address && typeof raw.address === 'object'
            ? Object.fromEntries(Object.entries(raw.address).slice(0, 20).map(([k, v]) => [String(k).slice(0, 30), String(v ?? '').slice(0, 200)]))
            : undefined,
          fields: Array.isArray(raw.fields) && raw.fields.length
            ? raw.fields.slice(0, 50).map(f => ({ name: String(f?.name || '').slice(0, 100), value: String(f?.value ?? '').slice(0, 1000) })).filter(f => f.name)
            : undefined,
          meta: raw.meta && typeof raw.meta === 'object'
            ? {
                url: String(raw.meta.url || '').slice(0, 2048),
                folder: String(raw.meta.folder || '').slice(0, 200),
                visitedAt: Number(raw.meta.visitedAt) || 0,
                visitCount: Number(raw.meta.visitCount) || 0,
              }
            : undefined,
          createdAt: now, updatedAt: now,
        }
        if (entry.type === 'card' && !entry.card?.number) { skipped.push({ reason: 'card without a number' }); continue }
        if (entry.type === 'bookmark' && !entry.meta?.url) { skipped.push({ reason: 'bookmark without a URL' }); continue }
        if (entry.type === 'history' && !entry.meta?.url) { skipped.push({ reason: 'history record without a URL' }); continue }
        const payload = JSON.stringify([entry.note, entry.card, entry.address, entry.fields, entry.meta])
        const idx = vaultData.entries.findIndex(e => e.domain === domain && e.username === entry.username && e.type === type)
        if (idx >= 0) {
          const prev = vaultData.entries[idx]
          const prevPayload = JSON.stringify([prev.note, prev.card, prev.address, prev.fields, prev.meta])
          if (prevPayload === payload) { duplicates++; continue }
          conflicts++
          skipped.push({ reason: `"${entry.username}" (${type}) already exists with different content — kept the vault copy` })
          continue
        }
        vaultData.entries.push(entry)
        clearTombstone(domain, entry.username)
        added++
        continue
      }

      // plain login — never overwrite an existing (domain, username)
      if (!password && !raw.allowEmptyPassword) { skipped.push({ reason: `login "${username || domain}" without a password` }); continue }
      const idx = vaultData.entries.findIndex(e => e.domain === domain && e.username === username && (e.type === undefined || e.type === 'login'))
      if (idx >= 0) {
        const prev = vaultData.entries[idx]
        if (prev.password === password) { duplicates++; continue }
        conflicts++
        skipped.push({ reason: `login "${username || domain}" already exists with a different password — kept the vault copy` })
        continue
      }
      // v2.9.0 — DATA-LOSS FIX: the login branch used to save ONLY the core
      // fields, discarding the note/fields/folder that Bitwarden/LastPass/
      // 1Password logins carry (itemToVaultEntry now forwards them).
      // v2.17.0 — R26-B1: multi-URI imports land as alias domains —
      // normalizeUris strips to bare hostnames, de-dupes, caps at 10; the
      // primary domain itself is not repeated as an alias.
      // v2.19.0 — R28-F9 (audit): the primary-drop comparison is case-safe
      // now, and an all-invalid uris list stores `undefined` instead of an
      // empty array (smaller wire blob; cleaner merge semantics).
      const aliases = Array.isArray(raw.uris) && raw.uris.length
        ? (normalizeUris(raw.uris) || []).filter(h => h && h.toLowerCase() !== domain.toLowerCase()).slice(0, 10)
        : []
      // v2.42.5 — R69 (F-R69-IMP-1): the attached authenticator seed travels
      // WITH the login. The seed is validated and clamped exactly like a
      // standalone token save — an unvalidated secret string is never
      // stored. An INVALID seed skips the SEED with a reported reason; the
      // login itself is still imported.
      let totp
      if (raw.totp && typeof raw.totp === 'object') {
        const seed = normalizeSecret(String(raw.totp.secret || ''))
        if (isValidBase32Secret(seed)) {
          // v2.42.5 — R69: algorithm DIALECT normalization (SHA256 → SHA-256;
          // the undashed Google/Bitwarden form used to silently fall back to
          // SHA-1 at this whitelist — wrong codes, silently).
          const algRaw = String(raw.totp.algorithm || '').toUpperCase().replace(/^SHA(\d)/, 'SHA-$1')
          totp = {
            secret: seed,
            issuer: String(raw.totp.issuer ?? '').slice(0, 64),
            digits: clamp(raw.totp.digits, 6, 10, 6),
            period: clamp(raw.totp.period, 15, 120, 30),
            algorithm: ['SHA-1', 'SHA-256', 'SHA-512'].includes(algRaw) ? algRaw : 'SHA-1',
          }
        } else {
          skipped.push({ reason: `TOTP seed for "${username || domain}" was present but invalid (not base32/otpauth) — the login was imported WITHOUT it and the raw string was not stored` })
        }
      }
      // v2.42.5 — R69 (no-silent-drop class): password history passed by a
      // caller is sanitized and forwarded (capped like saveEntry) instead of
      // being silently discarded.
      const hist = Array.isArray(raw.history)
        ? raw.history
          .filter(h => h && typeof h === 'object' && String(h.password ?? '').length > 0)
          .slice(0, 5)
          .map(h => ({ password: String(h.password).slice(0, 2048), changedAt: Number(h.changedAt) || now }))
        : undefined
      vaultData.entries.push({
        domain, username, password,
        ...(hist && hist.length ? { history: hist } : {}),
        uris: aliases.length ? aliases : undefined,
        note: raw.note ? String(raw.note).slice(0, 10000) : undefined,
        fields: Array.isArray(raw.fields) && raw.fields.length
          ? raw.fields.slice(0, 50).map(f => ({ name: String(f?.name || '').slice(0, 100), value: String(f?.value ?? '').slice(0, 1000) })).filter(f => f.name)
          : undefined,
        meta: raw.meta && typeof raw.meta === 'object'
          ? {
              url: String(raw.meta.url || '').slice(0, 2048),
              folder: String(raw.meta.folder || '').slice(0, 200),
              visitedAt: Number(raw.meta.visitedAt) || 0,
              visitCount: Number(raw.meta.visitCount) || 0,
            }
          : undefined,
        createdAt: now, updatedAt: now,
      })
      clearTombstone(domain, username)
      added++
      // v2.42.7 — R70 (F-R70-MODEL-1, "One Authenticator"): a seed arriving
      // ON a login row is CONVERTED here into exactly one canonical
      // standalone token (linked to this login) in the SAME atomic batch —
      // the login itself NEVER persists a totp copy. An invalid seed is
      // reported with its reason and the raw string is never stored; the
      // login still imports. An identical seed already in the vault (or
      // earlier in this batch) is a duplicate/no-op on the TOKEN axis only.
      if (totp) {
        const tokenLabel = String(totp.issuer || username || domain || 'Authenticator').trim().slice(0, 64) || 'Authenticator'
        // The batch writes straight into vaultData, so one lookup serves both
        // "already in the vault" and "earlier in this batch" — distinguished
        // by the seeds this same run created.
        const seedOwner = vaultData.entries.find(e => e.type === 'totp' && e.totp?.secret === totp.secret)
        if (seedOwner) {
          // identical seed — never a second token carrying the same secret
          const key = entryKey(domain, username)
          if (batchAddedSeeds.has(totp.secret)) {
            skipped.push({ reason: 'identical authenticator seed appears earlier in this batch — first occurrence kept' })
          } else {
            if (!seedOwner.linkedLoginKey) {
              seedOwner.linkedLoginKey = key
              seedOwner.updatedAt = now
            }
            skipped.push({ reason: `identical authenticator seed is already in the vault (token "${seedOwner.username}") — the login was linked to it` })
          }
          duplicates++
        } else {
          let label = tokenLabel
          if (vaultData.entries.some(e => e.type === 'totp' && e.username === label)) {
            let n = 2
            while (vaultData.entries.some(e => e.type === 'totp' && e.username === `${label} (${n})`)) n++
            label = `${label} (${n})`
          }
          vaultData.entries.push({
            domain: TOTP_DOMAIN, username: label, password: '', type: 'totp',
            totp: { ...totp },
            linkedLoginKey: entryKey(domain, username),
            createdAt: now, updatedAt: now,
          })
          batchAddedSeeds.add(totp.secret)
          clearTombstone(TOTP_DOMAIN, label)
          added++ // the canonical authenticator is a real, reported addition
        }
      }
    } catch (e) {
      skipped.push({ reason: e?.message || 'unknown per-item error' })
    }
  }

  if (added > 0) {
    if (opts.awaitPush) {
      // v2.8.0 — import path: ONE persist, then an AWAITED push so callers
      // learn whether the data actually reached the cloud.
      // v2.16.0 — through the single-flight lock (raw core was unserialized).
      await saveVault({ skipTransport: true })
      const push = await pushVaultToTransport()
      recordCloudLeg({ ok: !!(push && push.ok), transport: '', reason: String((push && push.reason) || '').slice(0, 60) })
      return { added, duplicates, conflicts, skipped, push }
    }
    await saveVault() // ONE persist + ONE fire-and-forget transport push
  }
  return { added, duplicates, conflicts, skipped }
}

/**
 * Remove an entry and tombstone the deletion so a peer cannot resurrect it.
 *
 * v2.8.0 — TYPE-AWARE: the optional `type` restricts the match to entries of
 * exactly that type ('note', 'card', 'bookmark', …). Without it only LOGINS
 * (entries without a type, or type 'login') match — so deleting an imported
 * bookmark can no longer take a same-key login with it, and vice versa. The
 * tombstone key stays (domain, username): merge treats same-key entries of
 * different types as the same identity, which matches how importers key them.
 *
 * Delete an entry.
 *
 * v2.42.7 — R70 §2.3 (F-R70-MODEL-1): deleting a LOGIN never silently
 * destroys its standalone authenticator. Linked tokens (linkedLoginKey ===
 * the login's key) are kept and UNLINKED by default — the UI warns and the
 * token stays visible in the 2FA tab. Only an explicit
 * `opts.alsoLinkedTotp === true` (the user chose "Delete linked
 * authenticator too") tombstones + removes them, so peers converge.
 * Deleting a token removes only the token (its link dies with it).
 *
 * Returns a truthful summary: { removed, unlinkedAuthenticators, deletedAuthenticators }.
 */
export async function deleteEntry(domain, username, type, opts = {}) {
  if (!isUnlocked) throw new Error('Vault is locked')
  const targetKey = entryKey(domain, username)
  let removed = 0
  if (type != null) {
    const before = vaultData.entries.length
    vaultData.entries = vaultData.entries.filter(e =>
      !(e.domain === domain && e.username === username && e.type === type))
    removed = before - vaultData.entries.length
  } else {
    const before = vaultData.entries.length
    vaultData.entries = vaultData.entries.filter(e =>
      !(e.domain === domain && e.username === username && isLoginEntry(e)))
    removed = before - vaultData.entries.length
  }
  // v2.42.7 — R70 §2.3: standalone authenticators linked to the deleted
  // entry. Default: keep + unlink (mark unlinked). Explicit choice: delete.
  let unlinkedAuthenticators = 0
  let deletedAuthenticators = 0
  if (type == null || type !== 'totp') {
    const linked = vaultData.entries.filter(e => e.type === 'totp' && e.linkedLoginKey === targetKey)
    if (linked.length) {
      if (opts.alsoLinkedTotp === true) {
        const keep = new Set(linked)
        vaultData.entries = vaultData.entries.filter(e => !keep.has(e))
        for (const t of linked) recordTombstone(t.domain, t.username)
        deletedAuthenticators = linked.length
      } else {
        for (const t of linked) {
          delete t.linkedLoginKey // marked unlinked — stays in the 2FA tab
          t.updatedAt = Date.now()
        }
        unlinkedAuthenticators = linked.length
      }
    }
  }
  // v2.4.0 — tombstone the deletion so a peer still holding an older copy
  // cannot resurrect the entry on the next merge.
  if (removed > 0) recordTombstone(domain, username)
  pruneTombstones()
  await saveVault()
  return { removed, unlinkedAuthenticators, deletedAuthenticators }
}

/** R85 (§5): LEAVE this device — clears the transport record and the sync
 * chain secrets here; the local vault stays untouched and the cloud copy is
 * NOT deleted. The in-memory sync key dies with the current epoch. */
export async function leaveDevice() {
  const hadSync = !!syncKey
  await chrome.storage.local.remove([SYNC_CODE_KEY, TRANSPORT_KEY, 'ucrypt:webdavUrl', 'ucrypt:gistId', 'ucrypt:webdav:etag', LAST_PUSH_KEY, LAST_HOP_KEY])
  // S9.5 (R111) — the disconnect clears the chain-shared state beside the
  // transport: the mirror, the notice, the conflict (the 0.14 lifecycle).
  await clearChainStateData().catch(() => {})
  await chrome.storage.sync.remove([SYNC_META_KEY, 'ucrypt:vaultSync']).catch(() => {})
  syncKey = null
  await auditVaultMutation({ op: 'leave-device', before: null, after: vaultEntryCount(), blobSize: 0, note: hadSync ? 'chain + transport secrets cleared; local vault kept; cloud untouched' : 'no chain was set' })
  return { ok: true }
}

/** R85 (§5): DELETE the cloud copy through the real transport. Requires the
 * caller to have confirmed (the options page collects the typed DELETE). */
export async function deleteCloudCopy() {
  if (!isUnlocked) throw new Error('Vault is locked')
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t?.id) throw new Error('No cloud transport is configured')
  const { config } = await getTransportRecord() || {}
  if (!config) throw new Error('No transport secrets stored')
  // R89 (F-R89-GHOST-DELETE): the REAL transport delete API (the ghost
  // syncDeleteVault never existed — see the top-of-file note). Transports
  // without a deleteVault implementation report an honest failed delete.
  const timpl = getTransport(t.id)
  const outcome = timpl && typeof timpl.deleteVault === 'function' ? await timpl.deleteVault(config) : false
  await auditVaultMutation({ op: 'delete-cloud', before: null, after: vaultEntryCount(), blobSize: 0, note: `transport ${t.id}: ${outcome ? 'envelope deleted' : 'delete failed'}` })
  try {
    await chrome.storage.local.remove([LAST_PUSH_KEY])
  } catch { /* ledger refresh is cosmetic */ }
  return { ok: !!outcome, deleted: !!outcome }
}

export async function wipeVault() {
  // R85 (F-R84-VAULT-1): the one EXPLICIT full-delete action — audit-logged
  // with the pre-wipe counts so the ring always explains a 0-entry state.
  await auditVaultMutation({ op: 'wipe', before: vaultEntryCount(), after: 0, blobSize: 0, note: 'explicit user wipe' })
  _lastKnownCount = null
  vaultData = { entries: [], lastModified: Date.now() }
  // Read the chunk metadata BEFORE removing it (v2.2.0 fix — the old order
  // removed the metadata first, leaving stale chunks in chrome.storage.sync).
  const { [SYNC_META_KEY]: meta } = await chrome.storage.sync.get(SYNC_META_KEY)
  const staleKeys = meta?.chunks
    ? Array.from({ length: meta.chunks }, (_, i) => SYNC_CHUNK_PREFIX + i)
    : []
  await chrome.storage.local.remove(
    [LOCAL_KEY, SALT_KEY, SYNC_CODE_KEY, SYNC_KDF_VER_KEY, TRANSPORT_KEY, 'ucrypt:webdavUrl', 'ucrypt:gistId',
     'ucrypt:chainState', 'ucrypt:chainStateNotice', 'ucrypt:chainStateConflict', 'ucrypt:syncLedger',
      // v2.19.0 — R28-F2 (audit 28a-2): the WebDAV If-Match ETag is
      // transport-DERIVED state — surviving a wipe, the next device's first
      // push could 412 against a version that no longer exists.
      'ucrypt:webdav:etag',
      LAST_PUSH_KEY, LAST_HOP_KEY,
      // R45-A: the encrypted verified-backup proof — a wiped device must not
      // show a backup truth about a vault that no longer exists locally.
      'ucrypt:backupProof',
      // R45-E: a wiped device is a FRESH START — the first-run choice and the
      // checklist skips are asked again.
      'ucrypt:firstRunChoice', 'ucrypt:checklistSkips']
  )
  await chrome.storage.sync.remove([SYNC_META_KEY, 'ucrypt:vaultSync', ...staleKeys]).catch(() => {})
  masterKey = null; credentialKey = null; syncKey = null; isUnlocked = false; hasMaster = false
  await clearLegacySession()
  await clearKeepAlive()
}

// ---------------------------------------------------------------------------
// SYNC CODE (24-word BIP-39 mnemonic — the universal credential)
// ---------------------------------------------------------------------------

/**
 * Store the sync code and derive/persist its key.
 *
 * v2.8.0 — RESTORE-SAFE ORDERING. The pre-2.8.0 code pushed the local vault
 * whenever `vaultData?.entries` was truthy — but an EMPTY array IS truthy, so
 * the "I already have a sync code" path on a fresh device overwrote the cloud
 * copy (chrome.storage.sync chunks AND the configured transport) with an empty
 * vault BEFORE any pull could run, destroying the very data being restored.
 *
 * Correct order:
 *   1. persist the code + derived key
 *   2. if the local vault is EMPTY → PULL + MERGE first (adopt the cloud copy)
 *   3. only push when the local vault actually holds content (entries or
 *      tombstones) that the remote may not have — never an empty vault
 *
 * Returns a summary the UI can relay: { pulled, pullReason, entryCount }.
 */
export async function setSyncCode(mnemonic, syncKeyDerived, kdfVersion = 2, opts = {}) {
  // v2.16.0 — defensive: every UI caller derives the key first and passes it
  // in, but a bare setSyncCode(mnemonic) used to assign syncKey = undefined
  // and crash the first encrypt with an opaque SubtleCrypto TypeError.
  syncKey = syncKeyDerived || (await deriveSyncKey(mnemonic))

  // LAW 0.48 (R133) — the join/restore-by-code moment arms the member
  // lifecycle: a key set over an EMPTY vault is a device that RECEIVES first
  // (awaiting-first-pull). The pull below lands the content and the adoption
  // path flips the state to 'synced' — pairing → pull is self-completing.
  try { await armAwaitingFirstPull(opts && opts.source === 'adopt' ? 'joined-chain' : 'sync-code-set') } catch { /* lifecycle is best-effort */ }

  // Persist which KDF bucket this record was derived at (v2.3.0) — plain
  // metadata, not secret. Absent key + legacy record ⇒ treated as v1 (210k).
  await chrome.storage.local.set({ [SYNC_KDF_VER_KEY]: kdfVersion })

  // Store the mnemonic encrypted with the master key (protected at rest)
  if (masterKey) {
    const encrypted = await encryptString(mnemonic, masterKey)
    await chrome.storage.local.set({ [SYNC_CODE_KEY]: encrypted })
  }
  // The master key can be absent in edge cases (record written before the
  // passphrase exists is impossible in our flows, but stay defensive).

  // RESTORE PATH: an empty local vault must ADOPT the cloud copy, never
  // replace it. pullFromSync() reads the chunked chrome.storage.sync copy and
  // the configured transport, merges (empty local ⇒ adopts as-is) and caches
  // locally without an echo push.
  // v2.19.0 — R28-F3 (audit 27a-4): an EXISTING vault used to push with zero
  // remote observation — re-entering the sync code while the transport was
  // down re-uploaded the local snapshot over a cloud copy that was never
  // read. Every setSyncCode now pulls first; the transport push below is
  // deferred when the pull reports the transport UNREACHABLE (remoteObserved
  // false WITH a transportError). A pull that READ the remote but could not
  // decrypt it (skipped-garbage — the KDF-upgrade signature, or a corrupt
  // record) still pushes: the user explicitly re-keyed this vault.
  let pull
  pull = await pullFromSync().catch(e => ({ synced: false, reason: materializeUserText(e && e.message !== undefined ? e.message : e, { cap: 300, generic: '' }) || undefined, remoteObserved: false, transportError: materializeUserText(e && e.message !== undefined ? e.message : e, { cap: 300, generic: '' }) || undefined }))

  // R132 (law 0.46 — the JOIN-PROPAGATION fix; the CEO's S1, second half):
  // an ADOPTED code means THIS device just joined the chain — its device
  // entry must ride the VERY NEXT envelope. The restore path above pulls
  // and (with an empty vault) never pushes, and the merge gate would call
  // the result "Already in sync" — the joiner's stamp never reached the
  // origin (the live finding: the origin's roster stayed blind to the new
  // member). The roster-dirty marker forces the next sync cycle (the
  // auto-cycle, the unlock pull, Sync now, or Refresh devices) to push the
  // envelope carrying THIS device's stamp; the origin's pull-side learn
  // (chainDevicesSink) merges it. Both directions battery-pinned.
  if (opts && opts.source === 'adopt') {
    await markRosterDirty()
  }

  // FIRST-DEVICE / EXISTING-VAULT PATH: push only when there is real content.
  // An empty vault must never overwrite a cloud copy we may simply have failed
  // to read (transient transport outage).
  if (hasVaultContent()) {
    // v2.42.5 — R69 (F-R69-LOC-1): snapshot serialization — device-local
    // usage telemetry never rides the first-hop chunk write.
    const syncEncrypted = await encryptString(JSON.stringify(await snapshotForWire(vaultData, { lane: 'cloud' })), syncKey)
    // R24-F1 (v2.15.0): this path bypassed saveVault, so its chunk writes
    // never reached the first-hop ledger — the popup row said "not attempted"
    // while storage.sync actually held chunks (caught by the round-24
    // real-browser journey). Record the outcome here too.
    try {
      const chunks = await writeChunkedSync(syncEncrypted)
      await recordHopOutcome({ ok: true, at: Date.now(), chunks, bytes: syncEncrypted.length })
    } catch (err) {
      console.warn('[UCrypt] sync write failed:', err)
      await recordHopOutcome({ ok: false, at: Date.now(), error: String(err?.message || err) })
    }
    // v2.16.0 — through the single-flight lock (raw core was unserialized).
    // v2.19.0 — R28-F3: the transport push waits for an OBSERVED remote. The
    // first hop (chunks) still writes — chrome.storage.sync was read by the
    // pull this round, so that medium IS observed.
    const transportUnreachable = !!(pull && pull.remoteObserved === false && pull.transportError)
    if (transportUnreachable) {
      console.warn('[UCrypt] setSyncCode: transport unreachable — the transport push is deferred to the next gated sync')
      recordCloudLeg({ ok: false, transport: '', reason: 'transport_unreachable' })
    } else {
      const r = await pushVaultToTransport().catch(() => null)
      recordCloudLeg({ ok: !!(r && r.ok), transport: '', reason: String((r && r.reason) || '').slice(0, 60) })
    }
  }
  return {
    pulled: !!(pull && pull.synced),
    pullReason: pull ? (pull.reason || null) : null,
    entryCount: (vaultData?.entries || []).length,
  }
}

/**
 * Load (derive) the sync key from the stored, master-encrypted mnemonic.
 * v2.3.0: honours the persisted KDF version — records saved by v2.2.0 and
 * earlier have no version key and derive at 210k (v1) exactly as before.
 */
async function loadSyncKey() {
  if (!masterKey) return
  const { [SYNC_CODE_KEY]: encryptedCode, [SYNC_KDF_VER_KEY]: kdfVersion } = await chrome.storage.local.get([SYNC_CODE_KEY, SYNC_KDF_VER_KEY])
  if (!encryptedCode) return
  try {
    const mnemonic = await decryptString(encryptedCode, masterKey)
    const version = Number.isInteger(kdfVersion) ? kdfVersion : 1 // legacy default
    syncKey = await deriveSyncKey(mnemonic, version)
  } catch (e) {
    console.warn('[UCrypt] Failed to load sync key:', e)
  }
}

/**
 * v2.42.14 — R76 Part E (Secure Direct Device Transfer) — ADDITIVE READ-ONLY
 * export. The transfer worker must derive its device-trust-plane keys from the
 * SAME post-unlock derivation path the sync plane uses: the stored,
 * master-encrypted mnemonic (SYNC_CODE_KEY), decrypted with the in-memory
 * master key exactly as loadSyncKey() above does. This export exposes the
 * mnemonic to the worker ONLY while the vault is UNLOCKED (the master key
 * exists in worker memory only between unlock and lock/timeout — lockVault()
 * clears it, and a locked call returns null, never a decrypted value).
 * Nothing here writes, caches or logs the words: the caller derives its keys
 * and drops the plaintext. The sync plane's semantics are untouched — this is
 * a read-only window over existing state, not a behavior change.
 */
export async function getUnlockedSyncMnemonic() {
  if (!masterKey) return null
  const { [SYNC_CODE_KEY]: encryptedCode } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!encryptedCode) return null
  try {
    return await decryptString(encryptedCode, masterKey)
  } catch (e) {
    console.warn('[UCrypt] Transfer plane: failed to read the master-encrypted sync code:', e)
    return null
  }
}

/**
 * v2.3.0 — re-derive the sync key at the CURRENT KDF version (600k) and
 * re-push the encrypted vault so every peer sees the upgraded envelope.
 * Explicit user action from the options UI — never automatic, because a
 * device still running an old version could not read the new blob.
 */
export async function upgradeSyncKdf() {
  if (!isUnlocked || !masterKey) throw new Error('Vault is locked')
  const { [SYNC_CODE_KEY]: encryptedCode } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!encryptedCode) throw new Error('No sync code set up')
  const { [SYNC_KDF_VER_KEY]: kdfVersion } = await chrome.storage.local.get(SYNC_KDF_VER_KEY)
  const currentVersion = Number.isInteger(kdfVersion) ? kdfVersion : 1
  if (currentVersion >= SYNC_KDF_VERSION) {
    return { upgraded: false, reason: `Sync key already at the current KDF version (v${currentVersion})` }
  }
  const mnemonic = await decryptString(encryptedCode, masterKey)
  const check = await validateSyncCode(mnemonic)
  if (!check.valid) throw new Error('Stored sync code failed validation — refusing to re-key')
  const newKey = await deriveSyncKey(mnemonic, SYNC_KDF_VERSION)
  await setSyncCode(mnemonic, newKey, SYNC_KDF_VERSION)
  return { upgraded: true, from: currentVersion, to: SYNC_KDF_VERSION }
}

/** Sync-key KDF info for the UI. */
export async function getSyncKdfInfo() {
  const { [SYNC_CODE_KEY]: code } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!code) return { hasSyncCode: false }
  const { [SYNC_KDF_VER_KEY]: kdfVersion } = await chrome.storage.local.get(SYNC_KDF_VER_KEY)
  const version = Number.isInteger(kdfVersion) ? kdfVersion : 1
  return {
    hasSyncCode: true,
    version,
    iterations: SYNC_KDF_ITERATIONS[version] || 210000,
    isCurrent: version >= SYNC_KDF_VERSION,
    currentVersion: SYNC_KDF_VERSION,
  }
}

export async function isSyncEnabled() {
  const { [SYNC_CODE_KEY]: code } = await chrome.storage.local.get(SYNC_CODE_KEY)
  return !!code
}

/**
 * R56-SYNC-DEVICES — re-authenticated sync-code reveal (Add device).
 *
 * Verifies the master passphrase WITHOUT touching unlock state: the key is
 * derived, used to decrypt the stored master-encrypted sync code, validated,
 * and then discarded — nothing is assigned to module state, nothing is
 * persisted, nothing is logged. A wrong passphrase is reported exactly like
 * the unlock surface does ("Wrong master passphrase"). Returns null when no
 * sync code is set up. The pairing QR reuses the SAME words-only payload
 * builder as the create flow (lib/sync.js) — one canonical format.
 */
export async function revealSyncCode(passphrase) {
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('Master passphrase required')
  const { [SALT_KEY]: saltB64 } = await chrome.storage.local.get(SALT_KEY)
  if (!saltB64) throw new Error('No master passphrase set')
  const salt = base64ToBytes(saltB64)
  const myEpoch = lockEpoch
  // Re-auth cost is deliberate: one PBKDF2-600k derivation, same as unlock.
  const key = await deriveKey(passphrase, salt)
  const { [SYNC_CODE_KEY]: encryptedCode } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!encryptedCode) return null
  let mnemonic
  try {
    mnemonic = await decryptString(encryptedCode, key)
  } catch {
    throw new Error('Wrong master passphrase')
  }
  if (lockEpoch !== myEpoch) {
    // A lock landed while PBKDF2/decrypt were in flight — refuse loudly
    // rather than reveal after a lock.
    throw new Error('Vault locked during reveal — try again')
  }
  const check = await validateSyncCode(mnemonic)
  if (!check.valid) throw new Error('Stored sync code failed validation')
  const words = mnemonic.split(/\s+/)
  return { words, qrUri: 'ucrypt-sync://' + words.join('-') }
}

/**
 * R110 §3 (law 0.15) — the WINDOW-AWARE reveal: within the CEO's 60-second
 * passphrase confirmation window the sheet's reveal does not re-derive the
 * master key (the human was already proven — the worker enforces the window,
 * the page can never fake it). The vault's OWN lock law still stands: a
 * locked vault refuses, a lock landing mid-reveal refuses via the epoch
 * check on the next read. Same output shape as revealSyncCode.
 */
export async function revealSyncCodeWithinWindow() {
  if (!isUnlocked || !masterKey) throw new Error('Unlock the vault first — the confirmation window never replaces the vault lock')
  const mnemonic = await getUnlockedSyncMnemonic()
  if (!mnemonic) return null
  const check = await validateSyncCode(mnemonic)
  if (!check.valid) throw new Error('Stored sync code failed validation')
  const words = mnemonic.split(/\s+/)
  return { words, qrUri: 'ucrypt-sync://' + words.join('-') }
}

/**
 * R91 §3.5c (CEO S-E) — the backup-verification check. The page sends words
 * typed from the user's OFFLINE copy at chosen positions; this compares them
 * against the SEALED sync code and returns per-position booleans. The stored
 * words are NEVER returned, never logged; the vault must be unlocked (the
 * sealed code decrypts with the in-memory master key only then).
 */
export async function verifyBackupWords(positionedWords) {
  if (!masterKey || !isUnlocked) throw new Error('Unlock the vault first, then verify the backup')
  const { [SYNC_CODE_KEY]: encryptedCode } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!encryptedCode) throw new Error('No sync code is set up yet')
  const myEpoch = lockEpoch
  const mnemonic = await decryptString(encryptedCode, masterKey)
  if (lockEpoch !== myEpoch) throw new Error('Vault locked during verification — try again')
  const words = mnemonic.split(/\s+/)
  const checks = {}
  let asked = 0
  let matched = 0
  for (const [pos, word] of Object.entries(positionedWords || {})) {
    const idx = parseInt(pos, 10)
    if (!Number.isInteger(idx) || idx < 1 || idx > words.length) continue
    asked++
    const ok = String(word || '').trim().toLowerCase() === String(words[idx - 1] || '').toLowerCase()
    checks[idx] = ok
    if (ok) matched++
  }
  return { verified: asked > 0 && matched === asked, checks, matched, asked }
}

/**
 * R91 §3.5c — the sheet-confirmation guard. Called by SYNC_CODE_BACKUP_CONFIRM
 * after the user has seen the re-authenticated reveal: this only asserts that
 * a sync code exists and the vault is unlocked (the reveal itself already did
 * the passphrase work). No flag logic here — the worker owns the flag.
 */
export async function confirmBackupSheet() {
  if (!masterKey || !isUnlocked) throw new Error('Unlock the vault first, then confirm the backup')
  const { [SYNC_CODE_KEY]: encryptedCode } = await chrome.storage.local.get(SYNC_CODE_KEY)
  if (!encryptedCode) throw new Error('No sync code is set up yet')
}

// ---------------------------------------------------------------------------
// CREDENTIAL ENVELOPE (R45-A §2.3) — transport secrets at rest
// ---------------------------------------------------------------------------

/**
 * Per-transport SECRET fields (R45-A). These config values are credentials
 * (tokens, passwords, bridge secrets, capability URLs) and are NEVER stored
 * in the clear: TRANSPORT_SAVE seals each one into a versioned AES-GCM
 * envelope (fresh IV, AAD = schema|transportId) and every push/pull/test
 * opens them transiently in worker memory. Non-secret fields (labels, URLs
 * that carry no embedded credentials, API-base overrides) stay readable so
 * the locked UI can still show truthful non-secret status.
 */
const TRANSPORT_SECRET_FIELDS = {
  // R92 (F-R92-GRANTSEAL, class-a P1 found in the §1.2 build): the OAUTH
  // GRANTS (gdrive/dropbox refreshToken, github oauthAccessToken) were NOT
  // in this map — the fields' own labels said "stored sealed, device-only"
  // while the values sat as PLAINTEXT strings inside the ucrypt:transport
  // config object. Every credential is now sealed: the OAuth grants, the
  // R92 own-secret fields (clientSecret/oauthClientSecret/appSecret), the
  // bridge secret, the pasted tokens, the WebDAV password, the custom URL.
  // Legacy plaintext values are sealed by migrateTransportEnvelopes() at the
  // next unlock.
  gdrive: ['secret', 'clientSecret', 'refreshToken'],
  dropbox: ['token', 'refreshToken', 'appSecret'],
  github: ['token', 'oauthAccessToken', 'oauthClientSecret'],
  webdav: ['pass'],     // WebDAV password (url/user are non-secret labels)
  custom: ['url'],      // the URL ITSELF carries auth tokens (path/query)
}

function secretFieldsFor(transportId) {
  return TRANSPORT_SECRET_FIELDS[transportId] || []
}

/** R93 §5 — read-only view of the secret-field map for the setup self-check
 * (the 0.14 audit). Additions-only export; the map itself stays const. */
export function transportSecretFieldMap() {
  return { ...TRANSPORT_SECRET_FIELDS }
}

/**
 * Seal every secret field of a transport config into its envelope. Called by
 * TRANSPORT_SAVE while the vault is UNLOCKED (the credential key exists only
 * then). A field that is already an envelope of the current schema passes
 * through untouched (idempotent re-saves).
 */
export async function sealTransportConfig(transportId, config) {
  if (!credentialKey) throw new Error('Vault is locked')
  const fields = secretFieldsFor(transportId)
  const out = { ...config }
  for (const f of fields) {
    const v = out[f]
    if (v === undefined || v === null || v === '') continue
    if (isSealedEnvelope(v)) continue
    out[f] = await sealSecret(v, credentialKey, transportId)
  }
  return out
}

/**
 * R171 — THE CUSTODY-DEATH CLEAR (the invalid_grant contract, custody half).
 * The stored grant is DEAD (Google's refresh endpoint refused it with
 * invalid_grant): the sealed envelope is re-written WITHOUT the grant
 * fields (refreshToken + webToken for gdrive; each transport's own grant
 * fields otherwise) — every other field rides untouched (the client ID,
 * the mode, the settings). The dead grant never lingers; the next Connect
 * re-mints fresh. Requires the vault UNLOCKED (the envelope opens under the
 * credential key); while locked the throw is the honest answer (the caller
 * already carries the typed evidence).
 * @returns {{ ok: boolean, cleared: string[] }}
 *
 * R176 — R-176.1c THE LIVING BANK AT THE CLEAR SEAT: a dead REFRESH grant
 * no longer executes a LIVE access token. The clear spares a banked
 * webToken whose exp is still in the future (beyond the 30 s service
 * margin the lanes use) — the access custody is independent property; the
 * lanes keep USING it (R-176.1c) until it truly dies, and only then does
 * the one-click road home (R-176.6) knock. The map's Adjudication 1.4
 * named this seat: the over-broad clear could empty a live bank and the
 * next seat would misname the empty bank "expired".
 */
export async function clearTransportGrants() {
  if (!credentialKey) throw new Error('Vault is locked')
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t || !t.id) return { ok: true, cleared: [] }
  const grantFields = ['refreshToken', 'webToken', 'oauthAccessToken', 'accessToken']
  const opened = await openTransportConfig(t.id, t.config)
  // R-176.1c — the alive-webToken spare: an access token whose exp is in
  // the future is USED by every lane before ANY mint is attempted — the
  // clear must never empty a living bank.
  const wt = opened.webToken && typeof opened.webToken === 'object' ? opened.webToken : null
  const webTokenAlive = !!(wt && typeof wt.token === 'string' && wt.token.length > 0 &&
    Number.isFinite(Number(wt.exp)) && Number(wt.exp) > Date.now() + 30000)
  const effective = webTokenAlive ? grantFields.filter((f) => f !== 'webToken') : grantFields
  const cleared = effective.filter((f) => opened[f] !== undefined && opened[f] !== null && opened[f] !== '')
  if (!cleared.length) return { ok: true, cleared: [] }
  for (const f of cleared) delete opened[f]
  const sealed = await sealTransportConfig(t.id, opened)
  await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: t.id, config: sealed, setAt: Date.now() } })
  return { ok: true, cleared }
}

// R178 — R-178.2 THE RENEWAL WRITE-BACK (the ONE writer seat for the
// renewal): every successful silent mint/refresh re-seals the record's
// webToken — token + exp + at + via — WHOLE-OBJECT, id-preserving, granted
// ONLY to the record that owns the mint (the grant's identity is proven
// BEFORE the write; a mismatched notification is dropped, never written).
// The refreshed custody is the ONE custody truth: the modal's clocks, the
// era seats, and the custody chip all read THIS webToken — the twin-clock
// class (E-42) dies at the root. Nothing renders, logs, exports, or syncs:
// the token is sealed into the envelope (the R85 law) before the storage
// write. Fail-closed: any doubt (locked, id mismatch, grant mismatch)
// drops the write — a stale clock is honest, a wrong-record write is not.
registerCustodyWriteBack(async (ev) => {
  try {
    if (!ev || typeof ev !== 'object') return
    const transportId = String(ev.transportId || (ev.webToken ? 'gdrive' : '') || '')
    if (transportId !== 'gdrive') return
    const evWt = ev.webToken && typeof ev.webToken === 'object' ? ev.webToken : null
    const tok = String(ev.token || (evWt && evWt.token) || '').trim()
    const exp = Number(ev.exp || (evWt && evWt.exp) || (Date.now() + 3600 * 1000))
    const via = String(ev.via || (evWt && evWt.via) || 'offline-refresh')
    if (!tok || !Number.isFinite(exp)) return

    const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
    if (!t || t.id !== 'gdrive' || !t.config) return

    const newWebToken = {
      token: tok,
      exp,
      at: Date.now(),
      via,
      persistentSession: true,
      autoRenew: true,
    }

    if (credentialKey) {
      const opened = await openTransportConfig(t.id, t.config)
      if (String(ev.refreshToken || '') && String(opened.refreshToken || '') && String(opened.refreshToken || '') !== String(ev.refreshToken)) return
      opened.webToken = newWebToken
      opened.persistentSession = true
      opened.autoRenew = true
      const sealed = await sealTransportConfig(t.id, opened)
      await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: t.id, config: sealed, setAt: Date.now() } })
    } else {
      // UCRYPT-22: Secret fields in t.config are already sealed envelopes;
      // webToken is a non-sealed fast-custody object, so silent renewals can
      // safely update t.config.webToken even while the vault is locked.
      const updatedCfg = {
        ...t.config,
        webToken: newWebToken,
        persistentSession: true,
        autoRenew: true,
      }
      await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: t.id, config: updatedCfg, setAt: Date.now() } })
    }
  } catch { /* the write-back never breaks the mint; the old era stays honest */ }
})

/**
 * R171 — THE LEDGER SELF-HEAL (the E-24 cure's storage half): the poisoned
 * historical ledger rows (a pre-R171 build wrote a Promise into a ledger
 * row's error/message — the owner's card printed "[object Promise]") are
 * MATERIALIZED once per worker init and re-written when changed. The owner's
 * existing poisoned row heals itself on the next worker wake — no manual
 * step, no reinstall.
 * R174 — THE STRING-POISON HEAL (R-174.4, the A3 adjudication): a live
 * Promise cannot survive storage — the ONLY poison class that persists is
 * the STRING "[object Promise]" baked by a pre-R171 writer's String(thenable).
 * The heal now rides healPoisonedUserText: a poisoned STRING row rewrites to
 * the typed generic, healthy strings stay byte-true — the owner's 10:41 row
 * heals at the next wake (the R171 heal's blind spot is dead).
 * @returns {{ healed: number }}
 */
export async function healLedgerRowsAtInit() {
  let healed = 0
  // R174 — the hop key rides its REAL name (the legacy 'ucrypt:lastHop'
  // literal rode a key no writer has used since v2.15.0's rename — a heal
  // blind spot the R174 walk caught; both names ride, the legacy stays for
  // truly ancient rows).
  const keys = [LAST_PULL_KEY, LAST_PUSH_KEY, 'ucrypt:lastTest', LAST_HOP_KEY, 'ucrypt:lastHop']
  try {
    const got = await chrome.storage.local.get(keys)
    for (const k of keys) {
      const row = got && got[k]
      if (!row || typeof row !== 'object') continue
      const next = { ...row }
      let changed = false
      for (const f of ['error', 'message', 'reason', 'confirmError']) {
        const v = next[f]
        if (v === undefined || v === null) continue
        const healedWords = healPoisonedUserText(v, { cap: 300, generic: k === 'ucrypt:lastTest' ? 'The last test could not be read — press Test connection for the live verdict.' : 'The recorded outcome could not be read — the next sync writes a fresh row.' })
        if (healedWords !== v) { next[f] = healedWords; changed = true }
      }
      if (changed) {
        await chrome.storage.local.set({ [k]: next })
        healed += 1
      }
    }
  } catch { /* the self-heal is best-effort — the render-side materializer still guards the eye */ }
  return { healed }
}

/**
 * Open a stored transport config into a TRANSIENT decrypted copy for one
 * push/pull/test call. The plaintext config exists only inside this call
 * frame — it is never written back, never logged, never cached.
 */
async function openTransportConfig(transportId, storedConfig) {
  if (!credentialKey) throw new Error('Vault is locked')
  const fields = secretFieldsFor(transportId)
  const out = { ...(storedConfig || {}) }
  for (const f of fields) {
    const v = out[f]
    if (typeof v !== 'string' || v === '') continue
    if (isSealedEnvelope(v)) out[f] = await openSecret(v, credentialKey, transportId)
    // A plaintext value (pre-migration legacy record) passes through as-is —
    // migration seals it at the next unlock, and pushes keep working.
  }
  return out
}

/**
 * The ONE read path every sync consumer must use: returns the transport
 * record with its secrets OPENED for immediate in-memory use, or null.
 * While the vault is LOCKED the credential key does not exist and this
 * throws — callers turn that into the truthful 'Vault is locked' outcome
 * (order §2.5: locked sync must report locked and skip, never decrypt a
 * persisted key merely to reach the cloud).
 * R150 CURE 1(a): the stored id resolves through the LEGACY-ALIAS READER —
 * a null/aliased/unknown id migrates to the shape's true transport (re-saved
 * + logged) before anything opens; an id that still cannot resolve returns
 * null (the surfaces render the typed BRIDGE_SETUP state — never
 * "Unknown transport: <raw>").
 */
// ── R150 D-2 (LAW #42 — THE REGISTRY LAW, ported verbatim from the oracle) ──
// PURE — the shape resolution is exportable and battery-pinned
// (tests/r150-cloud.test.mjs — the legacy rows + the v3.5.0 upgrade row).

/** The registry's known ids (read from the ONE registry — never duplicated). */
const TRANSPORT_KNOWN_IDS = transports.map((t) => String(t.id))

/** True when the id names a transport in THIS build's registry. */
export function isKnownTransportId(id) {
  return typeof id === 'string' && TRANSPORT_KNOWN_IDS.includes(id.trim())
}

/**
 * Legacy/foreign id aliases → the registry id. The v3.5.0-era registry used
 * EXACTLY these five ids (verified against the archive seal), so every alias
 * here is defensive (an older/foreign writer's naming), never a rename.
 */
export const TRANSPORT_ID_ALIASES = Object.freeze({
  drive: 'gdrive',
  googledrive: 'gdrive',
  google: 'gdrive',
  'gdrive-bridge': 'gdrive',
  'gdrive-oauth': 'gdrive',
  'gdrive-manual': 'gdrive',
  gist: 'github',
  github_gist: 'github',
  web_dav: 'webdav',
  dav: 'webdav',
  'custom-url': 'custom',
})

/**
 * Infer the transport kind from the stored config's SHAPE (key NAMES — the
 * values may be sealed envelopes and are never read here). Returns null when
 * the shape names nothing (the honest BRIDGE_SETUP heal).
 */
export function inferTransportIdFromConfig(config) {
  const c = (config && typeof config === 'object') ? config : {}
  const present = (k) => { const v = c[k]; return v != null && String(v) !== '' }
  if (present('scriptUrl')) return 'gdrive'
  if (present('oauthClientId') || present('oauthAccessToken') || present('oauthClientSecret')) return 'github'
  if (present('appKey') || present('appSecret')) return 'dropbox'
  if (present('clientId') && (present('clientSecret') || present('refreshToken'))) return 'gdrive'
  const tok = typeof c.token === 'string' ? c.token.trim() : ''
  if (tok) {
    if (/^sl\./.test(tok)) return 'dropbox'
    if (/^ghp_|^github_pat_/.test(tok)) return 'github'
    return null // a token whose provider cannot be named — never guessed
  }
  if (present('url')) return (present('user') || present('pass')) ? 'webdav' : 'custom'
  return null
}

/**
 * THE SHAPE RESOLUTION (pure; the battery pins it). Given the raw stored
 * record, return ONE of:
 *   { ok:true, id }                      — the id already names a transport;
 *   { ok:true, id, migrated:true, why }  — alias/shape resolution (migrate);
 *   { ok:false, reason }                 — unresolvable (the BRIDGE_SETUP heal).
 * NOTE: a KNOWN id never carries `migrated` — the known path is a no-op by
 * construction (the migration is never re-run over a healthy record).
 */
export function resolveTransportRecordShape(t) {
  const rawId = (t && typeof t === 'object') ? t.id : undefined
  const cfg = (t && typeof t === 'object' && t.config && typeof t.config === 'object') ? t.config : {}
  const trimmed = typeof rawId === 'string' ? rawId.trim() : ''
  if (isKnownTransportId(trimmed)) return { ok: true, id: trimmed }
  if (trimmed && TRANSPORT_ID_ALIASES[trimmed.toLowerCase()]) {
    return { ok: true, id: TRANSPORT_ID_ALIASES[trimmed.toLowerCase()], migrated: true, why: `alias:${trimmed.toLowerCase().slice(0, 40)}` }
  }
  const inferred = inferTransportIdFromConfig(cfg)
  if (inferred && isKnownTransportId(inferred)) {
    return { ok: true, id: inferred, migrated: true, why: trimmed ? `shape:unknown-id:${trimmed.slice(0, 24)}` : 'shape:null-id' }
  }
  return { ok: false, reason: trimmed ? 'unknown-id' : 'null-id' }
}

/** R150 CURE 1(a) — the migration log (diagnostics-only; entries carry NO
 * values, only the id transition and the reason). Ring-capped. */
export const TRANSPORT_MIGRATION_LOG_KEY = 'ucrypt:migration:log'
const TRANSPORT_MIGRATION_LOG_CAP = 20
export async function logTransportMigration(entry) {
  try {
    const got = await chrome.storage.local.get(TRANSPORT_MIGRATION_LOG_KEY)
    const arr = Array.isArray(got[TRANSPORT_MIGRATION_LOG_KEY]) ? got[TRANSPORT_MIGRATION_LOG_KEY] : []
    arr.push({
      at: Date.now(),
      from: (entry && entry.from != null) ? String(entry.from).slice(0, 64) : null,
      to: (entry && entry.to != null) ? String(entry.to).slice(0, 64) : null,
      why: String((entry && entry.why) || '').slice(0, 80),
    })
    await chrome.storage.local.set({ [TRANSPORT_MIGRATION_LOG_KEY]: arr.slice(-TRANSPORT_MIGRATION_LOG_CAP) })
  } catch { /* the log never blocks the migration */ }
}

/** R150 CURE 1(b) — the typed health record (the BRIDGE_SETUP state's
 * persisted face; diagnostics + the init gate's evidence). */
export const TRANSPORT_HEALTH_KEY = 'ucrypt:transport-health'

/** The typed BRIDGE_SETUP sentence (the ONE next step the surfaces render;
 * the ONE-TRUTH card machine in lib/cloud/cred.js carries the same words). */
export const TRANSPORT_BRIDGE_SETUP_WORDS = 'Your saved cloud setup names a storage this build cannot resolve — choose a transport and press Connect.'

/**
 * THE INIT INTEGRITY CHECK (Cure 1b): at every worker wake the stored
 * record is resolved ONCE. A migrated record re-saves under the correct id
 * (the sealed envelopes' AAD matches — the shape names the transport the
 * config was created for) and logs; an unresolvable record writes the typed
 * BRIDGE_SETUP health row and logs. Never throws; never destroys.
 */
export async function healTransportRecordAtInit() {
  try {
    const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
    if (!t || typeof t !== 'object') return { ok: true, state: 'none' }
    const res = resolveTransportRecordShape(t)
    if (res.ok) {
      if (res.migrated) {
        await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: res.id, config: t.config || {}, setAt: Date.now() } })
        await logTransportMigration({ from: t.id ?? null, to: res.id, why: res.why })
      }
      return { ok: true, state: 'resolved', id: res.id, migrated: !!res.migrated }
    }
    await chrome.storage.local.set({ [TRANSPORT_HEALTH_KEY]: { state: 'bridge-setup', at: Date.now(), from: t.id ?? null } })
    await logTransportMigration({ from: t.id ?? null, to: null, why: `unresolvable-at-init:${res.reason}` })
    return { ok: true, state: 'bridge-setup', from: t.id ?? null }
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 120) }
  }
}

/**
 * THE PUBLIC RESOLVER (read-only): which transport id does the stored record
 * name, and does it resolve against THIS build's registry? The surfaces and
 * the chain verdict read THIS (never the raw id) — a null/unknown id claims
 * connected nowhere. Does not open secrets, does not write.
 */
export async function resolveTransportRecord() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t || typeof t !== 'object') return { usableId: null, hasConfig: false, health: null }
  const res = resolveTransportRecordShape(t)
  if (!res.ok) return { usableId: null, hasConfig: true, health: 'bridge-setup' }
  return { usableId: res.id, hasConfig: true, health: null }
}

export async function getTransportRecord() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t || typeof t !== 'object') return null
  const res = resolveTransportRecordShape(t)
  if (!res.ok) return null
  if (res.migrated) {
    // R150 CURE 1(a) — the migration IS the read: re-save under the resolved
    // id (same sealed envelopes — the shape named the transport they were
    // created for) and log the transition. Best-effort: the in-frame
    // resolution stands even if the write fails.
    try {
      await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: res.id, config: t.config || {}, setAt: Date.now() } })
      await logTransportMigration({ from: t.id ?? null, to: res.id, why: res.why })
    } catch { /* the resolution stands; the next init re-tries the write */ }
  }
  return { id: res.id, config: await openTransportConfig(res.id, t.config), ...(res.migrated ? { migrated: { from: t.id ?? null, to: res.id, why: res.why } } : {}) }
}

// ═════════ S9 (R111) — CHAIN-SHARED STATE ═════════
//
// "The chain must visibly live — the cloud configuration as chain-shared
// state" (the CEO's directive). The law (order §2):
//   S9.2  The shared record rides the sync envelope's top-level metadata
//         (never inside the vault payload, never the words): provider id,
//         endpoint address, client ID, connection mode — plus, ONLY under
//         the chain-credentials opt-in (default ON, matching payload law
//         v1.4's toggle), the TRANSIT-SEALED client secret and grant, sealed
//         exactly as v1.4 seals them.
//   S9.3  A config change on any device propagates with the next sync — the
//         direct lane first when a peer is present, the cloud the record of
//         truth otherwise; a MONOTONIC change counter, last-writer-wins,
//         typed conflict handling.
//   S9.4  Adoption renders one typed notice and applies; an offline change
//         meets the typed conflict — both options, one click each.
//   S9.5  Sealed per-device at rest (the adopted credentials re-seal under
//         THIS device's credential key); the standing credential lifecycle
//         (lock-drop, disconnect-clear, export-exclusion); diagnostics show
//         BOOLEANS only; the shared-grant trade is labeled on the surface;
//         every device may run its own sign-in (per-device override).
//   S9.6  v1.4 remains the join carrier; S9 keeps the configuration current
//         thereafter.
//
// THE LOCAL MIRROR (`ucrypt:chainState`) holds BOOLEANS and public fields
// ONLY — never a credential value, never a sealed blob: it feeds the surface
// and the diagnostics. The credentials live ONLY inside the sealed transport
// record (TRANSPORT_KEY), re-sealed on adoption like any TRANSPORT_SAVE.

const CHAIN_STATE_KEY = 'ucrypt:chainState'
const CHAIN_STATE_NOTICE_KEY = 'ucrypt:chainStateNotice'
const CHAIN_STATE_CONFLICT_KEY = 'ucrypt:chainStateConflict'
const CHAIN_STATE_PENDING_KEY = 'ucrypt:chainStatePending' // S9.5 — the override's stored incoming record (one-click rejoin)
const CHAIN_STATE_LEDGER_KEY = 'ucrypt:syncLedger' // §3.2 — the visible moments (persist)
const CHAIN_STATE_LEDGER_CAP = 30

/** S9.2 — the projection map: an OPENED transport config → the record's
 * public fields + the credential fields eligible for transit sealing. The
 * keys are the REAL config keys (the R108 lesson). `endpoint` rides only
 * when the transport has an address; `mode` names the connection shape. */
function chainStateProjection(transportId) {
  switch (transportId) {
    case 'gdrive':
      return {
        endpoint: 'scriptUrl',
        clientId: 'clientId',
        mode: (c) => ((c.scriptUrl || c.url || c.authMode === 'bridge') ? 'bridge' : (c.authMode === 'fast' ? 'fast' : 'oauth')),
        secret: 'clientSecret',
        grant: 'refreshToken',
      }
    case 'github':
      return { endpoint: null, clientId: 'oauthClientId', mode: () => 'oauth', secret: 'oauthClientSecret', grant: 'oauthAccessToken' }
    case 'dropbox':
      return { endpoint: null, clientId: 'appKey', mode: () => 'oauth', secret: 'appSecret', grant: 'refreshToken' }
    case 'webdav':
      // The WebDAV sign-in rides as ONE sealed JSON blob ({ user, pass }) —
      // the same shapes the /c/ pairing segment carries (payload law v1.1).
      return { endpoint: 'url', clientId: null, mode: () => 'signin', secret: '__signin__', grant: null }
    case 'custom':
      // The URL itself carries its auth (userinfo stripped by the pairing
      // law); nothing sealed rides for custom.
      return { endpoint: 'url', clientId: null, mode: () => 'url', secret: null, grant: null }
    default:
      return null
  }
}

const stripUserinfo = (url) => {
  try {
    const u = new URL(String(url))
    if (u.username || u.password) {
      u.username = ''
      u.password = ''
    }
    return u.toString()
  } catch { return String(url || '') }
}

/** The chain-credentials opt-in (S9.5/S9.2): default ON — matching payload
 * law v1.4's toggle default (the CEO's order). Persisted in the settings. */
async function chainShareCredentialsEnabled() {
  try {
    const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY)
    return !s || s.chainShareCredentials !== false
  } catch { return true }
}

/** The device's own public mirror of the chain-shared state — BOOLEANS and
 * public fields only (the diagnostics law). */
async function readChainStateMirror() {
  const { [CHAIN_STATE_KEY]: m } = await chrome.storage.local.get(CHAIN_STATE_KEY)
  return (m && typeof m === 'object') ? m : null
}

async function writeChainStateMirror(mirror) {
  await chrome.storage.local.set({ [CHAIN_STATE_KEY]: mirror })
}

/** The device's own public identity for setBy — injected by the worker (the
 * same identity the roster carries). Never a secret. */
let _chainStateSelfId = null
export function setChainStateSelfId(deviceId) {
  _chainStateSelfId = typeof deviceId === 'string' ? deviceId.slice(0, 128) : null
}

/**
 * S9.2 (push side) — build THIS device's chain-shared record from the
 * current transport. Returns null when nothing is configured (nothing to
 * share) or the vault is locked (the secrets cannot be projected — the
 * record rides the next push; never a weaker-than-labeled form).
 * The credential values exist ONLY inside this frame: they are transit-
 * sealed under the words and replaced by opaque blobs before returning.
 */
export async function buildChainStateRecord() {
  const record = await getTransportRecord()
  if (!record) return null
  const proj = chainStateProjection(record.id)
  if (!proj) return null
  const cfg = record.config || {}
  const share = await chainShareCredentialsEnabled()
  const rawEndpoint = proj.endpoint ? (cfg[proj.endpoint] || (record.id === 'gdrive' ? cfg.url : '') || '') : ''
  const rec = {
    v: CHAIN_STATE_VERSION,
    provider: record.id,
    endpoint: proj.endpoint ? stripUserinfo(rawEndpoint) : '',
    clientId: proj.clientId ? String(cfg[proj.clientId] || '').slice(0, 256) : '',
    mode: proj.mode(cfg),
    rev: 0, setBy: _chainStateSelfId || '', setAt: Date.now(),
  }
  const mirror = await readChainStateMirror()
  if (mirror && Number.isFinite(Number(mirror.rev))) rec.rev = Math.max(0, Math.floor(Number(mirror.rev)))
  // F-R111-CONF-1 (the live matrix caught it): the record's IDENTITY
  // (rev/setBy/setAt) is the ADOPTED state's identity — a device re-emitting
  // what it ADOPTED must never re-author it (the join-time phantom conflict:
  // the joiner's auto-push re-emitted the origin's record under the JOINER'S
  // name, and the origin read a same-rev different-author "conflict" from its
  // own joiner). Only a REAL local change (noteChainStateLocalChange) or the
  // "keep mine" resolution re-authors the record.
  rec.setBy = (mirror && mirror.setBy) || _chainStateSelfId || ''
  rec.setAt = (mirror && mirror.setAt) || Date.now()
  if (share) {
    const mnemonic = await getUnlockedSyncMnemonic()
    if (mnemonic) {
      try {
        if (proj.secret === '__signin__') {
          if (cfg.user || cfg.pass) {
            rec.secret = await sealCredentialForTransit(JSON.stringify({ user: String(cfg.user || ''), pass: String(cfg.pass || '') }), mnemonic)
          }
        } else if (proj.secret && cfg[proj.secret]) {
          rec.secret = await sealCredentialForTransit(String(cfg[proj.secret]), mnemonic)
        }
        if (proj.grant && cfg[proj.grant]) {
          rec.grant = await sealCredentialForTransit(String(cfg[proj.grant]), mnemonic)
        }
      } catch { /* the seal stands down — the record lands without the named piece (the surface names the truth) */ }
    }
  }
  return cleanChainState(rec)
}

/**
 * S9.5 (adoption) — apply an incoming chain-shared record as THIS device's
 * transport: open the transit blobs with OUR OWN words, land the config
 * through the SAME sealTransportConfig path any manual save uses (the
 * credentials re-seal under this device's credential key — sealed at rest,
 * lock-dropped keys, export-excluded), then refresh the local mirror and
 * write the typed adoption notice. The raw values exist only inside this
 * frame; nothing is logged; the page sees booleans only.
 */
export async function applyChainStateRecord(record) {
  const rec = cleanChainState(record)
  if (!rec) return { ok: false, reason: 'The shared connection record is malformed — nothing was applied' }
  if (!isUnlocked || !credentialKey) return { ok: false, locked: true, reason: 'Vault is locked — unlock to adopt the chain connection' }
  const mnemonic = await getUnlockedSyncMnemonic()
  if (!mnemonic) return { ok: false, locked: true, reason: 'The sync words are not available — the sealed credentials cannot be opened' }
  const cfg = {}
  const proj = chainStateProjection(rec.provider)
  if (!proj) return { ok: false, reason: `The shared record names an unknown transport (${rec.provider}) — nothing was applied` }
  if (proj.endpoint && rec.endpoint) {
    cfg[proj.endpoint] = rec.endpoint
    if (rec.provider === 'gdrive') cfg.url = rec.endpoint
  }
  if (proj.clientId && rec.clientId) cfg[proj.clientId] = rec.clientId
  if (rec.provider === 'gdrive') {
    if (rec.mode === 'bridge' || rec.endpoint) {
      cfg.authMode = 'bridge'
      cfg.signinMode = 'advanced'
    } else if (rec.mode === 'fast') {
      cfg.authMode = 'fast'
      cfg.signinMode = 'fast'
    } else {
      cfg.authMode = 'oauth'
      cfg.signinMode = 'guided'
    }
  }
  try {
    if (proj.secret && rec.secret) {
      const opened = await openCredentialFromTransit(rec.secret, mnemonic)
      if (proj.secret === '__signin__') {
        let signin = null
        try { signin = JSON.parse(opened) } catch { signin = null }
        if (!signin || typeof signin !== 'object') return { ok: false, reason: 'The shared sign-in blob did not open — nothing was applied' }
        if (signin.user) cfg.user = String(signin.user).slice(0, 256)
        if (signin.pass) cfg.pass = String(signin.pass).slice(0, 256)
      } else {
        cfg[proj.secret] = String(opened)
      }
    }
    if (proj.grant && rec.grant) {
      cfg[proj.grant] = String(await openCredentialFromTransit(rec.grant, mnemonic))
    }
  } catch {
    return { ok: false, reason: 'The sealed credentials did not open with this chain’s words — nothing was applied' }
  }
  const sealed = await sealTransportConfig(rec.provider, cfg)
  // R123 §2.2 (the CEO's S2) — the record carries its OWN setAt: the
  // attention state's staleness check compares the pull ledger's failed row
  // against THIS timestamp — a reconnect that postdates the failure means
  // the stale row no longer speaks for the current connection.
  await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: rec.provider, config: sealed, setAt: Date.now() } })
  // The mirror refreshes to the ADOPTED state; the per-device override flag
  // is device-local state and survives the adoption untouched.
  const prev = await readChainStateMirror()
  const mirror = {
    v: CHAIN_STATE_VERSION,
    provider: rec.provider,
    endpoint: rec.endpoint,
    clientId: rec.clientId,
    mode: rec.mode,
    rev: rec.rev,
    setBy: rec.setBy,
    setAt: rec.setAt,
    hasSecret: !!rec.secret,
    hasGrant: !!rec.grant,
  }
  if (prev && prev.override) mirror.override = true
  await writeChainStateMirror(mirror)
  await writeChainStateNotice({ at: Date.now(), provider: rec.provider, by: rec.setBy, rev: rec.rev, kind: 'adopted' })
  return { ok: true, applied: { provider: rec.provider, rev: rec.rev, hasSecret: !!rec.secret, hasGrant: !!rec.grant } }
}

async function writeChainStateNotice(notice) {
  try { await chrome.storage.local.set({ [CHAIN_STATE_NOTICE_KEY]: notice }) } catch { /* notice failures never break adoption */ }
}

/**
 * S9.3/S9.4 (pull side) — the worker's sink: merge an incoming record under
 * the merge law and act. Never throws; every outcome is typed for the
 * surface and the diagnostics.
 */
export async function handleIncomingChainState(incoming) {
  const mirror = await readChainStateMirror()
  const { outcome, record: rec } = mergeChainState(mirror, incoming)
  if (outcome === 'none') return { applied: false, reason: 'none' }
  if (outcome === 'same') return { applied: false, reason: 'current' }
  if (outcome === 'conflict') {
    // S9.4 — the offline double-write: store BOTH options, one click each.
    const conflict = {
      at: Date.now(),
      mine: mirror ? { provider: mirror.provider, endpoint: mirror.endpoint, clientId: mirror.clientId, mode: mirror.mode, rev: mirror.rev, setBy: mirror.setBy, setAt: mirror.setAt } : null,
      theirs: rec,
    }
    try { await chrome.storage.local.set({ [CHAIN_STATE_CONFLICT_KEY]: conflict }) } catch { /* typed below */ }
    await writeChainStateNotice({ at: Date.now(), provider: rec.provider, by: rec.setBy, rev: rec.rev, kind: 'conflict' })
    return { applied: false, conflict: true, reason: 'conflict' }
  }
  // outcome === 'adopt'
  if (mirror && mirror.override) {
    // S9.5 — the per-device override: the record is STORED (pending, one
    // click to rejoin) but this device keeps its own sign-in. The surface
    // names the pending state.
    try { await chrome.storage.local.set({ [CHAIN_STATE_PENDING_KEY]: rec }) } catch { /* typed below */ }
    await writeChainStateNotice({ at: Date.now(), provider: rec.provider, by: rec.setBy, rev: rec.rev, kind: 'pending-override' })
    return { applied: false, pending: true, reason: 'override' }
  }
  const applied = await applyChainStateRecord(rec)
  if (applied && applied.ok) return { applied: true, reason: 'adopted', ...applied }
  return { applied: false, reason: (applied && applied.reason) || 'apply-failed', locked: !!(applied && applied.locked) }
}

/** The status the surface and the diagnostics read — BOOLEANS and public
 * fields only (0.14: no secret value, no sealed blob, no words ever). */
export async function chainStateStatus() {
  const mirror = await readChainStateMirror()
  const { [CHAIN_STATE_NOTICE_KEY]: notice } = await chrome.storage.local.get(CHAIN_STATE_NOTICE_KEY)
  const { [CHAIN_STATE_CONFLICT_KEY]: conflict } = await chrome.storage.local.get(CHAIN_STATE_CONFLICT_KEY)
  const { [CHAIN_STATE_PENDING_KEY]: pending } = await chrome.storage.local.get(CHAIN_STATE_PENDING_KEY)
  const t = await getTransportRecord().catch(() => null)
  const proj = t ? chainStateProjection(t.id) : null
  const cfg = (t && t.config) || {}
  const share = await chainShareCredentialsEnabled()
  return {
    ok: true,
    shareCredentials: share,
    override: !!(mirror && mirror.override),
    hasTransport: !!t,
    transportId: t ? t.id : null,
    mirror: mirror ? {
      provider: mirror.provider, endpoint: mirror.endpoint, clientId: mirror.clientId,
      mode: mirror.mode, rev: mirror.rev || 0, setBy: mirror.setBy || '', setAt: mirror.setAt || 0,
      hasSecret: !!mirror.hasSecret, hasGrant: !!mirror.hasGrant,
    } : null,
    notice: (notice && typeof notice === 'object') ? { at: notice.at, provider: notice.provider, by: notice.by, rev: notice.rev, kind: notice.kind } : null,
    pendingOverride: !!(pending && typeof pending === 'object'),
    conflict: (conflict && typeof conflict === 'object') ? {
      at: conflict.at,
      mine: conflict.mine || null,
      theirs: conflict.theirs ? { provider: conflict.theirs.provider, endpoint: conflict.theirs.endpoint, clientId: conflict.theirs.clientId, mode: conflict.theirs.mode, rev: conflict.theirs.rev, setBy: conflict.theirs.setBy, setAt: conflict.theirs.setAt } : null,
    } : null,
    local: t && proj ? {
      provider: t.id,
      endpoint: proj.endpoint ? stripUserinfo(cfg[proj.endpoint] || '') : '',
      clientId: proj.clientId ? String(cfg[proj.clientId] || '') : '',
      mode: proj.mode(cfg),
      hasSecret: !!(proj.secret && cfg[proj.secret]),
      hasGrant: !!(proj.grant && cfg[proj.grant]),
    } : null,
  }
}

/** S9.4 — resolve the typed conflict, one click: 'chain' applies the stored
 * incoming record; 'mine' keeps this device's connection and bumps the
 * monotonic counter past the incoming rev so THIS state wins the next
 * propagation (the honest last-writer resolution). */
export async function resolveChainStateConflict(choice) {
  const { [CHAIN_STATE_CONFLICT_KEY]: conflict } = await chrome.storage.local.get(CHAIN_STATE_CONFLICT_KEY)
  if (!conflict || typeof conflict !== 'object') return { ok: false, reason: 'No conflict is pending' }
  if (choice === 'chain') {
    if (!conflict.theirs) return { ok: false, reason: 'The stored chain record is gone — re-sync to receive it again' }
    const applied = await applyChainStateRecord(conflict.theirs)
    if (applied && applied.ok) {
      await chrome.storage.local.remove(CHAIN_STATE_CONFLICT_KEY)
      return { ok: true, resolved: 'chain', applied: applied.applied }
    }
    return applied
  }
  if (choice === 'mine') {
    const mirror = await readChainStateMirror()
    const prevMirror = mirror || {}
    const bump = {
      ...prevMirror,
      rev: Math.max(Number(prevMirror.rev) || 0, (conflict.theirs && conflict.theirs.rev) || 0) + 1,
      setBy: _chainStateSelfId || prevMirror.setBy || '',
      setAt: Date.now(),
    }
    await writeChainStateMirror(bump)
    await chrome.storage.local.remove(CHAIN_STATE_CONFLICT_KEY)
    await writeChainStateNotice({ at: Date.now(), provider: bump.provider || '', by: bump.setBy, rev: bump.rev, kind: 'resolved-mine' })
    return { ok: true, resolved: 'mine', rev: bump.rev }
  }
  return { ok: false, reason: 'Unknown resolution — use "chain" or "mine"' }
}

/** S9.5 — the per-device override toggle: ON = this device keeps its own
 * sign-in (incoming chain records land as PENDING, one click to rejoin);
 * OFF = re-adopt the chain's newest record on the next pull (or immediately
 * when one is already stored as the notice's pending rev). */
export async function setChainStateOverride(on) {
  const mirror = await readChainStateMirror() || {}
  mirror.override = !!on
  await writeChainStateMirror(mirror)
  if (!on) {
    // Re-adopt immediately: the PENDING record (the override's stored
    // incoming) is preferred; the conflict's theirs is the fallback.
    const { [CHAIN_STATE_PENDING_KEY]: pending } = await chrome.storage.local.get(CHAIN_STATE_PENDING_KEY)
    if (pending) {
      const applied = await applyChainStateRecord(pending)
      if (applied && applied.ok) {
        await chrome.storage.local.remove(CHAIN_STATE_PENDING_KEY)
        return { ok: true, override: false, adopted: true }
      }
      return { ok: true, override: false, adopted: false, reason: (applied && applied.reason) || 'apply-failed' }
    }
    const { [CHAIN_STATE_CONFLICT_KEY]: conflict } = await chrome.storage.local.get(CHAIN_STATE_CONFLICT_KEY)
    if (conflict && conflict.theirs) {
      const applied = await applyChainStateRecord(conflict.theirs)
      if (applied && applied.ok) {
        await chrome.storage.local.remove(CHAIN_STATE_CONFLICT_KEY)
        return { ok: true, override: false, adopted: true }
      }
      return { ok: true, override: false, adopted: false, reason: (applied && applied.reason) || 'apply-failed' }
    }
  }
  return { ok: true, override: !!on }
}

/** S9.5 — the opt-in toggle (the surface's labeled switch): whether the
 * SEALED credentials ride the chain-shared record. The public fields
 * (provider/endpoint/client ID/mode) always share — that is S9's law; the
 * toggle gates the credentials, and the surface's trade line says so. */
export async function setChainShareCredentials(on) {
  const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY)
  const settings = (s && typeof s === 'object') ? s : {}
  settings.chainShareCredentials = !!on
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings })
  return { ok: true, shareCredentials: !!on }
}

/** S9.3 — TRANSPORT_SAVE calls this after every successful local save: the
 * monotonic counter BUMPS (never decrements) and the mirror refreshes from
 * the just-saved record. Public fields only — the sealed record is read for
 * PRESENCE booleans, never opened here. */
export async function noteChainStateLocalChange() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t?.id) return { ok: false, reason: 'no-transport' }
  const proj = chainStateProjection(t.id)
  if (!proj) return { ok: false, reason: 'unknown-transport' }
  const cfg = t.config || {}
  const mirror = await readChainStateMirror() || {}
  const next = {
    v: CHAIN_STATE_VERSION,
    provider: t.id,
    endpoint: proj.endpoint ? stripUserinfo(cfg[proj.endpoint] || '') : '',
    clientId: proj.clientId ? String(cfg[proj.clientId] || '').slice(0, 256) : '',
    mode: proj.mode(cfg),
    rev: (Number(mirror.rev) || 0) + 1,
    setBy: _chainStateSelfId || mirror.setBy || '',
    setAt: Date.now(),
    hasSecret: !!(proj.secret && cfg[proj.secret]),
    hasGrant: !!(proj.grant && cfg[proj.grant]),
  }
  if (mirror && mirror.override) next.override = true
  await writeChainStateMirror(next)
  return { ok: true, rev: next.rev }
}

/** S9.5 — the disconnect/leave/wipe clear: the mirror, the notice, the
 * conflict. The transport record itself is cleared by the callers (the
 * standing TRANSPORT_KEY removal) — this clears the S9 state beside it. */
export async function clearChainStateData() {
  await chrome.storage.local.remove([CHAIN_STATE_KEY, CHAIN_STATE_NOTICE_KEY, CHAIN_STATE_CONFLICT_KEY, CHAIN_STATE_PENDING_KEY])
  return { ok: true }
}

// ═══ §3.2 (R111) — THE VISIBLE MOMENT: the sync-activity ledger ═══════
//
// When a change crosses a lane and lands here, the receiving device shows
// an unobtrusive informational line ("Vault updated — 1 new login from
// XEON") — the toast may expire (0.8), the LEDGER LINE PERSISTS. Every
// adopter records one typed line; open pages are notified so a visible
// surface renders the moment live. No secret, no value — counts and labels
// only, machine-gated by the no-secrets diagnostics gate.

export function recordSyncMoment(moment) {
  // Fire-and-forget from the adopt paths; never throws, never blocks sync.
  ;(async () => {
    try {
      const { [CHAIN_STATE_LEDGER_KEY]: ledger } = await chrome.storage.local.get(CHAIN_STATE_LEDGER_KEY)
      const arr = Array.isArray(ledger) ? ledger : []
      const entry = {
        at: Date.now(),
        lane: moment && moment.lane === 'direct' ? 'direct' : 'cloud',
        added: Number.isFinite(Number(moment && moment.added)) ? Math.max(0, Math.floor(Number(moment.added))) : 0,
        updated: Number.isFinite(Number(moment && moment.updated)) ? Math.max(0, Math.floor(Number(moment.updated))) : 0,
        by: typeof (moment && moment.by) === 'string' ? moment.by.slice(0, 80) : '',
      }
      // One line only when something actually arrived — silence is the
      // honest "nothing changed".
      if (!entry.added && !entry.updated) return
      arr.unshift(entry)
      await chrome.storage.local.set({ [CHAIN_STATE_LEDGER_KEY]: arr.slice(0, CHAIN_STATE_LEDGER_CAP) })
      try {
        chrome.runtime.sendMessage({ type: 'UCRYPT_SYNC_MOMENT', ...entry }).catch?.(() => {})
      } catch { /* no receiver open — the ledger line persists for the next open */ }
    } catch { /* ledger failures never block sync */ }
  })()
}

export async function syncMomentLedger() {
  const { [CHAIN_STATE_LEDGER_KEY]: ledger } = await chrome.storage.local.get(CHAIN_STATE_LEDGER_KEY)
  return { ok: true, ledger: Array.isArray(ledger) ? ledger.slice(0, CHAIN_STATE_LEDGER_CAP) : [] }
}

/**
 * R102 (J1) — the COMPLETE-pairing projection: the transport record with its
 * secrets OPENED, projected through the secret-law allowlist under the
 * complete opt-in — provider + stripped URL + (webdav only, both fields
 * present) the exact stored sign-in. Built HERE in the worker: the sealed
 * envelope never leaves the background context, the page never touches a
 * credential envelope, and the projection is handed to the pairing renderer
 * exactly once per render. While LOCKED this throws — the sheet's renderer
 * turns that into the words-only carrier (the strict default stands).
 *
 * R110 PAYLOAD LAW v1.4 (the CEO's "the whole credential"): the projection
 * now covers EVERY credential present on the origin — the webdav sign-in
 * (the /c/ segment, unchanged), the gdrive CLIENT SECRET and the user's OWN
 * OAUTH GRANT (the /k/ segment's s/g blobs). The raw secret/grant values
 * exist ONLY inside this function's frame: they are transit-sealed under the
 * key derived from the device's own stored 24 words and REPLACED by the
 * opaque blobs before the projection returns — the page (and everything
 * downstream of it) can only ever see `conn.s` / `conn.g` as opaque strings
 * and presence booleans. The sealing degrades honestly: a missing mnemonic
 * or a seal failure OMITS that segment (the code stays complete minus the
 * named piece), never ships a weaker-than-labeled form.
 */
export async function completeCloudForPairing() {
  const record = await getTransportRecord()
  if (!record) return null
  const cloud = safeCloudForPairing(record, { complete: true })
  if (!cloud) return null
  if (cloud.secret || cloud.grant) {
    const mnemonic = await getUnlockedSyncMnemonic()
    if (!mnemonic) {
      // Locked or unset words: the transit key cannot exist — omit the
      // segments (the strict default stands; the renderer labels the truth).
      delete cloud.secret
      delete cloud.grant
    } else {
      const words = mnemonic.trim().split(/\s+/)
      const conn = { ...(cloud.conn || {}) }
      if (cloud.secret) {
        try {
          const blob = await sealCredentialForTransit(cloud.secret, words)
          if (blob.length <= PAIRING_V14_CAPS.secretB64) conn.s = blob
        } catch { /* omit — never a weaker-than-labeled segment */ }
        delete cloud.secret
      }
      if (cloud.grant) {
        try {
          const blob = await sealCredentialForTransit(cloud.grant, words)
          if (blob.length <= PAIRING_V14_CAPS.grantB64) conn.g = blob
        } catch { /* omit — never a weaker-than-labeled segment */ }
        delete cloud.grant
      }
      if (conn.s || conn.g) cloud.conn = conn
      else if (cloud.conn && !Object.keys(conn).length) delete cloud.conn
    }
  }
  return cloud
}

/**
 * R110 v1.4 — the JOINER'S ARRIVAL PATH: store the credentials that rode the
 * pairing code, sealed under THIS device's own vault key — the identical
 * lifecycle to the origin's (lock-drop, disconnect-clear, export-exclusion).
 * The worker opened the transit blobs (background.js) and passes the opened
 * fields here; this function only ever writes SEALED envelopes. Merge rules:
 * the same provider only (a different configured transport is a typed
 * refusal — the user decides first), existing non-empty values are never
 * silently overwritten by empty arrivals.
 */
export async function storeArrivedCredentials(provider, fields) {
  const id = String(provider || '').trim()
  if (!id) return { ok: false, error: 'No provider named for the arrived credentials' }
  if (!isUnlocked) return { ok: false, locked: true, error: 'Unlock the vault first — arrived credentials seal under this vault\'s key' }
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (t && t.id && t.id !== id) {
    return { ok: false, error: `A different cloud transport (${t.id}) is configured — disconnect it first, then paste the code again` }
  }
  const incoming = fields && typeof fields === 'object' ? fields : {}
  const config = { ...((t && t.config) || {}) }
  const allowed = PAIRING_SECRET_FIELDS[id] || {}
  const stored = []
  if (incoming.clientId) { config.clientId = String(incoming.clientId).slice(0, PAIRING_CREDS_CAPS.field); stored.push('clientId') }
  if (allowed.secret && incoming[allowed.secret]) {
    config[allowed.secret] = String(incoming[allowed.secret]).slice(0, PAIRING_V14_CAPS.secretPlain)
    stored.push(allowed.secret)
  }
  if (allowed.grant && incoming[allowed.grant]) {
    config[allowed.grant] = String(incoming[allowed.grant]).slice(0, PAIRING_V14_CAPS.grantPlain)
    stored.push(allowed.grant)
  }
  if (!stored.length) return { ok: false, error: 'No credential fields arrived — nothing to store' }
  if (id === 'gdrive' && !config.authMode) {
    config.authMode = 'oauth'
    if (!config.signinMode) config.signinMode = 'guided'
  }
  const sealed = await sealTransportConfig(id, config)
  await chrome.storage.local.set({ [TRANSPORT_KEY]: { id, config: sealed, setAt: Date.now() } })
  // Booleans only cross this boundary — never the values (0.14).
  return { ok: true, stored }
}

/** Non-secret transport status for the locked UI (order §2.5). */
export async function getTransportStatus() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t?.id) return null
  const stored = t.config || {}
  const secrets = secretFieldsFor(t.id)
  return {
    id: t.id,
    // Secret fields: only the fact that a value is stored — never the value.
    hasSecrets: secrets.map(f => ({ field: f, stored: typeof stored[f] === 'string' && stored[f].length > 0 })),
    anySecretSealed: secrets.some(f => isSealedEnvelope(stored[f])),
  }
}

// --- R45-E: LAST VERIFIED BACKUP PROOF --------------------------------------

const BACKUP_PROOF_KEY = 'ucrypt:backupProof'
const BACKUP_PROOF_AAD = 'backup-proof'

/**
 * R45-E: after a transport push CONFIRMED by the remote (upload resolved ok),
 * record a local, ENCRYPTED proof: { rev, digest, transportId, at } — sealed
 * with the credential key, so the proof is opaque while locked and the wipe
 * dialog can show the truth only where it may be shown. The digest is of the
 * CIPHERTEXT blob (no plaintext material).
 */
async function recordBackupProof(blob, transportId) {
  if (!credentialKey) return
  try {
    const rev = vaultData?.lastModified || 0
    const digest = bytesToBase64(await sha256(new TextEncoder().encode(blob)))
    const proof = { rev, digest, transportId, at: Date.now() }
    await chrome.storage.local.set({
      [BACKUP_PROOF_KEY]: await sealSecret(JSON.stringify(proof), credentialKey, BACKUP_PROOF_AAD),
    })
  } catch { /* best-effort — the ledger remains the primary truth */ }
}

/**
 * The last verified backup record, or null. Null while LOCKED (the proof is
 * sealed) — the wipe dialog requires unlock anyway, so the truth is always
 * available exactly where it is shown.
 */
export async function getBackupProof() {
  if (!credentialKey) return null
  const { [BACKUP_PROOF_KEY]: sealed } = await chrome.storage.local.get(BACKUP_PROOF_KEY)
  if (!sealed) return null
  try {
    return JSON.parse(await openSecret(sealed, credentialKey, BACKUP_PROOF_AAD))
  } catch { return null }
}

/**
 * R45-A migration: seal plaintext secrets written by builds before the
 * credential envelope existed. Runs right after a successful unlock (the
 * credential key is the ONLY thing that can produce the envelopes). Any
 * value that already is an envelope is left untouched; missing values are
 * left to the user to fill in.
 */
export async function migrateTransportEnvelopes() {
  if (!credentialKey) return false
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (!t?.id || !t.config) return false
  const fields = secretFieldsFor(t.id)
  let changed = false
  const out = { ...t.config }
  for (const f of fields) {
    const v = out[f]
    if (typeof v !== 'string' || v === '' || isSealedEnvelope(v)) continue
    out[f] = await sealSecret(v, credentialKey, t.id)
    changed = true
  }
  if (changed) {
    // R123 §2.2 — setAt rides every transport write (the staleness law).
    await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: t.id, config: out, setAt: Date.now() } })
  }
  return changed
}

// ---------------------------------------------------------------------------
// SYNC ENGINE (chrome.storage.sync + cloud transport)
// ---------------------------------------------------------------------------

/**
 * v2.16.0 — SINGLE-FLIGHT sync serialization (clinical audit finding F3).
 * The popup's Sync-now, the options Push/Pull buttons, the 15-minute tick,
 * the onChanged debounce and the post-unlock pull can all overlap; each one
 * reads-modifies-writes the vault and pushes. A promise-chain mutex now
 * serializes every pull/push so two uploads of the same blob can never race
 * and ledger writes can never interleave.
 *
 * Deadlock-safe by construction: the RAW cores (_pullCore/_pushCore) never
 * take the lock themselves — only the exported wrappers (and syncNow, which
 * calls the cores directly INSIDE one acquired lock) do.
 */
// ---------------------------------------------------------------------------
// LAW 0.48 — THE MEMBER LIFECYCLE (R133, the CEO's F1 made law:
// DIRECTION-OF-TRUTH). A brand-new chain member holds an EMPTY vault BY
// DESIGN — it receives data first and pushes after. The old engine's only
// empty-vault answer was a push refusal recorded as a FAILURE ("Last push
// failed — Local vault is empty"), which lied about the direction of truth:
// the CEO's exact words — "an unlogic error since if the instance is brand
// new added to the chain, it supposedly should have a empty vault, that
// would receive data from the other orginal instance". The lifecycle is
// typed, persisted, and machine-gated:
//   'unjoined'            — no sync key yet (setup still in progress)
//   'awaiting-first-pull' — key set, local vault empty, no landed pull yet:
//                           push is DISABLED (a typed SKIP row, never a red
//                           failure); the primary action is Pull now
//   'synced'              — content exists locally (or a pull positively
//                           completed) — two-way sync is armed and the
//                           empty-vault loss guard holds here
// The state derives from the strongest truth available (content present ⇒
// synced, regardless of any stale marker) and is battery-pinned (EMPTYJOIN).
// ---------------------------------------------------------------------------
const LIFECYCLE_KEY = 'ucrypt:memberLifecycle'
let _lifecycleCache = null

async function readLifecycleRecord() {
  if (_lifecycleCache) return _lifecycleCache
  try {
    const { [LIFECYCLE_KEY]: rec } = await chrome.storage.local.get(LIFECYCLE_KEY)
    _lifecycleCache = (rec && typeof rec === 'object' && rec.state) ? rec : null
  } catch { _lifecycleCache = null }
  return _lifecycleCache
}

async function writeLifecycleRecord(rec) {
  _lifecycleCache = rec
  try { await chrome.storage.local.set({ [LIFECYCLE_KEY]: rec }) } catch { /* best-effort */ }
}

/** Arm the awaiting-first-pull state: called when a sync key is set/restored
 * (the join / restore-by-code moment) while the local vault holds no content.
 * Never demotes a device that already synced. */
export async function armAwaitingFirstPull(reason) {
  if (hasVaultContent()) return getMemberLifecycle()
  const rec = await readLifecycleRecord()
  if (rec && rec.state === 'synced') return { state: 'synced', since: rec.since }
  const next = { state: 'awaiting-first-pull', since: Date.now(), reason: String(reason || '').slice(0, 80) }
  await writeLifecycleRecord(next)
  return next
}

/** Flip to 'synced' — the first pull landed content, or the member created
 * its first local content. Idempotent (in-memory cache makes the hot path a
 * no-op after the first flip). */
export async function markMemberSynced(note) {
  const rec = await readLifecycleRecord()
  if (rec && rec.state === 'synced') return { state: 'synced', since: rec.since }
  const next = {
    state: 'synced',
    since: Date.now(),
    ...(rec && rec.state === 'awaiting-first-pull' && rec.since ? { armedAt: rec.since } : {}),
    note: String(note || '').slice(0, 80),
  }
  await writeLifecycleRecord(next)
  return next
}

/** The typed lifecycle — the engine's direction-of-truth answer (0.48). */
export async function getMemberLifecycle() {
  if (!syncKey) {
    return { state: 'unjoined', since: null }
  }
  if (hasVaultContent()) {
    // Content is the strongest truth — a device that holds data is synced
    // even if the marker was lost (a storage wipe must never re-arm a skip
    // on a device that carries entries).
    const rec = await readLifecycleRecord()
    if (!rec || rec.state !== 'synced') await markMemberSynced('content-present')
    return { state: 'synced', since: (rec && rec.since) || null }
  }
  const rec = await readLifecycleRecord()
  if (rec && rec.state === 'awaiting-first-pull') {
    return { state: 'awaiting-first-pull', since: rec.since }
  }
  // Key set + empty vault + no marker: a fresh join/restore arms itself now
  // (self-derived — a brand-new member never needs a manual flag).
  const next = await armAwaitingFirstPull('derived-empty-key-set')
  return { state: next.state === 'synced' ? 'synced' : next.state, since: next.since || null }
}

// ---------------------------------------------------------------------------
// LAW 0.49 — AUTO-SYNC (R133, the CEO's F2 made law: "make the sync process
// automatically among online instances"). The mutation-triggered cloud sync
// fires after a 30 s debounce (bursts coalesce into ONE cycle; the final
// state always lands), with a durable one-shot alarm as the backup when the
// MV3 worker dies mid-debounce. "Sync now" and the pull's convergence push
// stay immediate — the debounce is only the mutation lane.
// ---------------------------------------------------------------------------
const AUTO_SYNC_DEBOUNCE_MS = 30000
const AUTO_SYNC_ALARM = 'ucrypt:sync-mutation'
export const AUTO_SYNC_STATE_KEY = 'ucrypt:autoSyncState'
export const AUTO_SYNC_RETRY_ALARM = 'ucrypt:auto-sync-retry'
export const MAX_AUTO_SYNC_RETRIES = 6
export const BASE_AUTO_SYNC_RETRY_MS = 15000
export const MAX_AUTO_SYNC_RETRY_MS = 900000
export const AUTO_SYNC_BACKOFF_SCHEDULE_SECONDS = [15, 30, 60, 120, 240, 480]

let _autoSyncTimer = null
let _autoSyncRetryTimer = null

/**
 * UCRYPT-19 — Classify whether a sync outcome (pull, push, or combined cycle)
 * failed due to a temporary network / connectivity / upstream server issue
 * eligible for automatic exponential backoff retry.
 */
export function classifyTransientNetworkSyncFailure(outcome) {
  if (!outcome || typeof outcome !== 'object') {
    return { transient: false, kind: null, status: null, reason: '', stage: 'sync' }
  }
  if (outcome.locked || outcome.skippedLocked || outcome.syncSkipped || outcome.conflictDetected) {
    return { transient: false, kind: null, status: null, reason: String(outcome.reason || ''), stage: 'sync' }
  }
  const pullLeg = outcome.pull && typeof outcome.pull === 'object' ? outcome.pull : null
  const pushLeg = outcome.push && typeof outcome.push === 'object' ? outcome.push : null
  if (pullLeg && pullLeg.remoteObserved === false && !pullLeg.locked && !pullLeg.syncSkipped) {
    const sub = classifyTransientNetworkSyncFailure(pullLeg)
    if (sub.transient) return { ...sub, stage: 'pull' }
  }
  if (pushLeg && pushLeg.ok === false && !pushLeg.locked && !pushLeg.skipped) {
    const sub = classifyTransientNetworkSyncFailure(pushLeg)
    if (sub.transient) return { ...sub, stage: 'push' }
  }

  const kind = typeof outcome.kind === 'string' ? outcome.kind.toLowerCase().trim() : ''
  const status = Number.isFinite(Number(outcome.status)) ? Number(outcome.status) : null
  const rawReason = String(
    outcome.transportError ||
    outcome.error ||
    outcome.userMessage ||
    outcome.message ||
    outcome.reason ||
    outcome.confirmError ||
    ''
  ).trim()

  const stage = outcome.pushed !== undefined && outcome.remoteObserved === undefined
    ? 'push'
    : (outcome.remoteObserved !== undefined ? 'pull' : 'sync')

  // Never retry auth, permission, decryption, or corrupted vault errors automatically
  if (
    kind === 'auth' ||
    kind === 'permission' ||
    kind === 'decrypt' ||
    kind === 'corrupt' ||
    kind === 'config' ||
    status === 401 ||
    status === 403 ||
    outcome.custodyDead === true ||
    /invalid_grant|revoked|access_denied|redirect_uri_mismatch|admin_policy|wrong.*passphrase|cannot be read with this chain|aes-gcm|tag mismatch/i.test(rawReason)
  ) {
    return { transient: false, kind: kind || 'auth', status, reason: rawReason, stage }
  }

  const transientKinds = new Set(['network', 'timeout', 'server', 'rate_limit', 'offline', 'unreachable'])
  const transientStatuses = new Set([0, 408, 425, 429, 500, 502, 503, 504])
  const transientPattern = /network|offline|timed?\s*out|timeout|failed to fetch|net::|econnreset|enotfound|eai_again|socket hang up|unreachable|could not be reached|temporarily unavailable|service unavailable|bad gateway|gateway timeout|too many requests|rate.?limit|connection.*reset|dns|http\s*(408|429|500|502|503|504)|status\s*(408|429|500|502|503|504)/i

  const isSuccess =
    (outcome.ok === true && outcome.confirmed !== false) ||
    (outcome.synced === true && (!pushLeg || pushLeg.ok !== false)) ||
    (outcome.remoteObserved === true && outcome.ok !== false && (!pushLeg || pushLeg.ok !== false))

  if (isSuccess) {
    return { transient: false, kind: null, status, reason: rawReason, stage }
  }

  if (transientKinds.has(kind)) {
    return {
      transient: true,
      kind,
      status,
      reason: rawReason || `Temporary ${kind} error while contacting cloud storage`,
      stage,
    }
  }
  if (status !== null && transientStatuses.has(status)) {
    const derivedKind = status === 429 ? 'rate_limit' : (status === 408 || status === 504 ? 'timeout' : (status >= 500 ? 'server' : 'network'))
    return {
      transient: true,
      kind: derivedKind,
      status,
      reason: rawReason || `Temporary cloud error (HTTP ${status})`,
      stage,
    }
  }
  if (rawReason && transientPattern.test(rawReason)) {
    const derivedKind = /timed?\s*out|timeout|408|504/i.test(rawReason)
      ? 'timeout'
      : (/rate.?limit|too many requests|429/i.test(rawReason)
          ? 'rate_limit'
          : (/500|502|503|bad gateway|service unavailable/i.test(rawReason) ? 'server' : 'network'))
    return {
      transient: true,
      kind: derivedKind,
      status,
      reason: rawReason,
      stage,
    }
  }

  return { transient: false, kind: kind || null, status, reason: rawReason, stage }
}

/**
 * UCRYPT-19 — Boolean predicate returning true when `outcome` represents a
 * temporary network / connectivity / upstream server issue eligible for
 * automatic exponential backoff retry.
 */
export function isTransientNetworkSyncFailure(outcome) {
  return classifyTransientNetworkSyncFailure(outcome).transient
}

/**
 * UCRYPT-19 — Pure exponential backoff calculator for automatic sync retries.
 * Default schedule: 15s -> 30s -> 60s -> 120s -> 240s -> 480s (capped at 900s / 6 attempts).
 */
export function computeAutoSyncBackoff({
  attempt = 1,
  baseMs = BASE_AUTO_SYNC_RETRY_MS,
  maxMs = MAX_AUTO_SYNC_RETRY_MS,
  maxAttempts = MAX_AUTO_SYNC_RETRIES,
  jitterRatio = 0,
  randomFn = Math.random,
  now = Date.now(),
} = {}) {
  const safeAttempt = Math.max(1, Math.floor(Number(attempt) || 1))
  const safeMaxAttempts = Math.max(1, Math.floor(Number(maxAttempts) || MAX_AUTO_SYNC_RETRIES))
  const safeBaseMs = Math.max(1000, Number(baseMs) || BASE_AUTO_SYNC_RETRY_MS)
  const safeMaxMs = Math.max(safeBaseMs, Number(maxMs) || MAX_AUTO_SYNC_RETRY_MS)

  const scheduleSeconds = []
  for (let i = 1; i <= safeMaxAttempts; i++) {
    scheduleSeconds.push(Math.round(Math.min(safeMaxMs, safeBaseMs * Math.pow(2, i - 1)) / 1000))
  }

  if (safeAttempt > safeMaxAttempts) {
    return {
      exhausted: true,
      attempt: safeAttempt,
      retryCount: safeAttempt,
      maxAttempts: safeMaxAttempts,
      delayMs: 0,
      delaySeconds: 0,
      backoffMs: 0,
      backoffSeconds: 0,
      nextRetryAt: 0,
      scheduleSeconds,
    }
  }

  const expMs = Math.min(safeMaxMs, safeBaseMs * Math.pow(2, safeAttempt - 1))
  let delayMs = expMs
  const jr = Number(jitterRatio) || 0
  if (jr > 0 && typeof randomFn === 'function') {
    const factor = 1 + ((Number(randomFn()) || 0.5) * 2 - 1) * Math.min(0.5, jr)
    delayMs = Math.min(safeMaxMs, Math.max(safeBaseMs, Math.round(expMs * factor)))
  }
  const delaySeconds = Math.max(1, Math.round(delayMs / 1000))
  return {
    exhausted: false,
    attempt: safeAttempt,
    retryCount: safeAttempt,
    maxAttempts: safeMaxAttempts,
    delayMs,
    delaySeconds,
    backoffMs: delayMs,
    backoffSeconds: delaySeconds,
    nextRetryAt: now + delayMs,
    scheduleSeconds,
  }
}

function normalizeAutoSyncRetryState(raw = null) {
  const s = raw && typeof raw === 'object' ? raw : {}
  const attempt = Math.max(0, Math.floor(Number(s.attempt ?? s.retryCount) || 0))
  const maxAttempts = Math.max(1, Math.floor(Number(s.maxAttempts) || MAX_AUTO_SYNC_RETRIES))
  const failures = Math.max(0, Math.floor(Number(s.failures) || 0))
  const backoffMs = Math.max(0, Math.floor(Number(s.backoffMs ?? s.delayMs) || 0))
  const backoffSeconds = Math.max(0, Math.floor(Number(s.backoffSeconds ?? s.delaySeconds) || Math.round(backoffMs / 1000)))
  const nextRetryAt = typeof s.nextRetryAt === 'number' && s.nextRetryAt > 0 ? s.nextRetryAt : null
  const retrying = !!(s.retrying && (s.inFlight || (nextRetryAt && nextRetryAt > 0)))
  return {
    lastAutoAt: typeof s.lastAutoAt === 'number' && s.lastAutoAt > 0 ? s.lastAutoAt : null,
    nextAt: typeof s.nextAt === 'number' && s.nextAt > 0 ? s.nextAt : nextRetryAt,
    failures,
    retrying,
    inFlight: !!s.inFlight,
    exhausted: !!s.exhausted,
    attempt,
    retryCount: attempt,
    maxAttempts,
    backoffMs,
    backoffSeconds,
    delayMs: backoffMs,
    delaySeconds: backoffSeconds,
    nextRetryAt,
    lastError: typeof s.lastError === 'string' && s.lastError ? s.lastError : null,
    lastErrorKind: typeof s.lastErrorKind === 'string' && s.lastErrorKind ? s.lastErrorKind : null,
    lastErrorStatus: Number.isFinite(Number(s.lastErrorStatus)) ? Number(s.lastErrorStatus) : null,
    lastFailedAt: typeof s.lastFailedAt === 'number' && s.lastFailedAt > 0 ? s.lastFailedAt : null,
    lastSuccessAt: typeof s.lastSuccessAt === 'number' && s.lastSuccessAt > 0 ? s.lastSuccessAt : null,
    source: typeof s.source === 'string' && s.source ? s.source : null,
    stage: typeof s.stage === 'string' && s.stage ? s.stage : null,
    scheduleSeconds: Array.isArray(s.scheduleSeconds) && s.scheduleSeconds.length
      ? s.scheduleSeconds
      : AUTO_SYNC_BACKOFF_SCHEDULE_SECONDS,
  }
}

export async function getAutoSyncRetryState() {
  try {
    const { [AUTO_SYNC_STATE_KEY]: raw } = await chrome.storage.local.get(AUTO_SYNC_STATE_KEY)
    return normalizeAutoSyncRetryState(raw)
  } catch {
    return normalizeAutoSyncRetryState(null)
  }
}

export async function recordAutoSyncRetryState(patch = {}) {
  try {
    const prev = await getAutoSyncRetryState()
    const merged = normalizeAutoSyncRetryState({ ...prev, ...(patch || {}) })
    await chrome.storage.local.set({ [AUTO_SYNC_STATE_KEY]: merged })
    try {
      if (chrome && chrome.runtime && typeof chrome.runtime.sendMessage === 'function') {
        const p = chrome.runtime.sendMessage({ type: 'UCRYPT_AUTO_SYNC_RETRY_STATE', retryState: merged })
        if (p && typeof p.catch === 'function') p.catch(() => {})
      }
    } catch { /* no open extension pages listening */ }
    return merged
  } catch {
    return normalizeAutoSyncRetryState(patch)
  }
}

export async function clearAutoSyncRetryState(note = 'sync-ok') {
  if (_autoSyncRetryTimer) {
    clearTimeout(_autoSyncRetryTimer)
    _autoSyncRetryTimer = null
  }
  try {
    if (chrome && chrome.alarms && typeof chrome.alarms.clear === 'function') {
      await chrome.alarms.clear(AUTO_SYNC_RETRY_ALARM)
    }
  } catch { /* best-effort */ }
  const mins = await getAutoSyncMinutes().catch(() => 15)
  const now = Date.now()
  return recordAutoSyncRetryState({
    lastAutoAt: now,
    lastSuccessAt: now,
    nextAt: now + mins * 60 * 1000,
    failures: 0,
    retrying: false,
    inFlight: false,
    exhausted: false,
    attempt: 0,
    retryCount: 0,
    backoffMs: 0,
    backoffSeconds: 0,
    nextRetryAt: null,
    lastError: null,
    lastErrorKind: null,
    lastErrorStatus: null,
    source: String(note || 'sync-ok'),
  })
}

/**
 * UCRYPT-19 — Arm an exponential backoff retry when an automatic sync fails
 * due to a temporary network issue. Persists retry state in `ucrypt:autoSyncState`
 * so the 'Cloud sync' status section can display live visual feedback & countdown.
 */
export async function scheduleAutoSyncBackoffRetry(outcome, opts = {}) {
  const check = classifyTransientNetworkSyncFailure(outcome)
  if (!check.transient) {
    return { scheduled: false, transient: false, reason: check.reason, kind: check.kind }
  }
  const prev = await getAutoSyncRetryState()
  const nextAttempt = (opts && Number.isFinite(Number(opts.attempt)) && Number(opts.attempt) >= 1)
    ? Math.floor(Number(opts.attempt))
    : ((prev.retrying || prev.inFlight || prev.failures > 0) ? (Math.max(prev.attempt, prev.failures) + 1) : 1)

  const backoff = computeAutoSyncBackoff({
    attempt: nextAttempt,
    baseMs: opts && opts.baseMs ? opts.baseMs : BASE_AUTO_SYNC_RETRY_MS,
    maxMs: opts && opts.maxMs ? opts.maxMs : MAX_AUTO_SYNC_RETRY_MS,
    maxAttempts: opts && opts.maxAttempts ? opts.maxAttempts : MAX_AUTO_SYNC_RETRIES,
    jitterRatio: opts && opts.jitterRatio ? opts.jitterRatio : 0,
  })

  if (_autoSyncRetryTimer) {
    clearTimeout(_autoSyncRetryTimer)
    _autoSyncRetryTimer = null
  }

  const now = Date.now()
  if (backoff.exhausted) {
    try {
      if (chrome && chrome.alarms && typeof chrome.alarms.clear === 'function') {
        await chrome.alarms.clear(AUTO_SYNC_RETRY_ALARM)
      }
    } catch { /* best-effort */ }
    const mins = await getAutoSyncMinutes().catch(() => 15)
    const state = await recordAutoSyncRetryState({
      lastAutoAt: now,
      lastFailedAt: now,
      nextAt: now + mins * 60 * 1000,
      failures: nextAttempt,
      retrying: false,
      inFlight: false,
      exhausted: true,
      attempt: backoff.maxAttempts,
      retryCount: backoff.maxAttempts,
      maxAttempts: backoff.maxAttempts,
      backoffMs: 0,
      backoffSeconds: 0,
      nextRetryAt: null,
      lastError: check.reason || 'Temporary network issue persisted across all automatic retry attempts',
      lastErrorKind: check.kind || 'network',
      lastErrorStatus: check.status,
      source: String((opts && opts.source) || 'auto-sync'),
      stage: check.stage || 'sync',
      scheduleSeconds: backoff.scheduleSeconds,
    })
    return {
      scheduled: false,
      transient: true,
      exhausted: true,
      attempt: backoff.maxAttempts,
      retryCount: backoff.maxAttempts,
      backoffMs: 0,
      backoffSeconds: 0,
      state,
      retryState: state,
    }
  }

  const nextRetryAt = now + backoff.delayMs
  const state = await recordAutoSyncRetryState({
    lastAutoAt: now,
    lastFailedAt: now,
    nextAt: nextRetryAt,
    failures: nextAttempt,
    retrying: true,
    inFlight: false,
    exhausted: false,
    attempt: nextAttempt,
    retryCount: nextAttempt,
    maxAttempts: backoff.maxAttempts,
    backoffMs: backoff.delayMs,
    backoffSeconds: backoff.delaySeconds,
    nextRetryAt,
    lastError: check.reason || 'Temporary network issue while syncing with cloud storage',
    lastErrorKind: check.kind || 'network',
    lastErrorStatus: check.status,
    source: String((opts && opts.source) || 'auto-sync'),
    stage: check.stage || 'sync',
    scheduleSeconds: backoff.scheduleSeconds,
  })

  if (!(opts && opts.skipTimer)) {
    _autoSyncRetryTimer = setTimeout(() => {
      _autoSyncRetryTimer = null
      runAutoSyncBackoffRetryNow({ source: 'auto-backoff-timer' }).catch(() => {})
    }, backoff.delayMs)
    try {
      if (chrome && chrome.alarms && typeof chrome.alarms.create === 'function') {
        chrome.alarms.create(AUTO_SYNC_RETRY_ALARM, { when: nextRetryAt })
      }
    } catch { /* best-effort */ }
  }

  return {
    scheduled: true,
    transient: true,
    exhausted: false,
    attempt: nextAttempt,
    retryCount: nextAttempt,
    maxAttempts: backoff.maxAttempts,
    delayMs: backoff.delayMs,
    delaySeconds: backoff.delaySeconds,
    backoffMs: backoff.delayMs,
    backoffSeconds: backoff.delaySeconds,
    nextRetryAt,
    state,
    retryState: state,
  }
}

/**
 * UCRYPT-19 — Execute an automatic sync retry attempt right now, updating
 * `ucrypt:autoSyncState` with `inFlight: true` while running so the 'Cloud sync'
 * UI shows real-time retry-in-progress feedback, and either clearing backoff on
 * success or advancing to the next exponential backoff step on continued network failure.
 */
export async function runAutoSyncBackoffRetryNow(opts = {}) {
  if (_autoSyncRetryTimer) {
    clearTimeout(_autoSyncRetryTimer)
    _autoSyncRetryTimer = null
  }
  const prev = await getAutoSyncRetryState()
  const activeAttempt = Math.max(1, prev.attempt || 1)
  await recordAutoSyncRetryState({
    retrying: true,
    inFlight: true,
    exhausted: false,
    attempt: activeAttempt,
    retryCount: activeAttempt,
    maxAttempts: prev.maxAttempts || MAX_AUTO_SYNC_RETRIES,
    source: String((opts && opts.source) || 'auto-retry'),
  })

  if (!isUnlocked) {
    const pausedState = await recordAutoSyncRetryState({
      retrying: false,
      inFlight: false,
      lastError: 'Vault is locked — automatic sync retry will resume once unlocked',
      source: 'locked-skip',
    })
    return { ok: false, skippedLocked: true, retryState: pausedState }
  }

  const res = await syncNow({ source: String((opts && opts.source) || 'auto-retry') })
  const check = classifyTransientNetworkSyncFailure(res)
  const pullFailed = !!(res && res.remoteObserved === false)
  const pushFailed = !!(res && res.push && res.push.ok === false)

  if (!pullFailed && !pushFailed && !check.transient) {
    const cleared = await clearAutoSyncRetryState('auto-retry-ok')
    return { ok: true, recovered: true, result: res, retryState: cleared }
  }

  if (check.transient) {
    const next = await scheduleAutoSyncBackoffRetry(res, {
      source: String((opts && opts.source) || 'auto-retry'),
      attempt: activeAttempt + 1,
      skipTimer: !!(opts && opts.skipTimer),
    })
    return {
      ok: false,
      recovered: false,
      transient: true,
      result: res,
      retryScheduled: next.scheduled,
      retryState: next.state,
    }
  }

  const halted = await recordAutoSyncRetryState({
    retrying: false,
    inFlight: false,
    nextRetryAt: null,
    backoffMs: 0,
    backoffSeconds: 0,
    lastError: check.reason || (res && (res.transportError || res.reason)) || null,
    lastErrorKind: check.kind || 'non-transient',
    lastFailedAt: Date.now(),
  })
  return { ok: false, recovered: false, transient: false, result: res, retryState: halted }
}

function scheduleCloudAutoSync(op) {
  // In-memory debounce (the worker-lived lane)…
  if (_autoSyncTimer) clearTimeout(_autoSyncTimer)
  _autoSyncTimer = setTimeout(() => {
    _autoSyncTimer = null
    pushVaultToTransport()
      .then(async (r) => {
        try {
          const tId = String((r && r.transportId) || '')
          recordCloudLeg({ ok: !!(r && r.ok), transport: tId, reason: String((r && r.reason) || (r && r.confirmError) || '').slice(0, 60) })
        } catch { /* the leg record never blocks the push */ }
        // LAW 0.49 — a push whose READ-BACK did not confirm schedules the
        // typed retry; a push that failed due to a temporary network issue
        // arms the exponential backoff retry engine (UCRYPT-19).
        if (r && r.ok) {
          if (r.confirmed === false) {
            try { chrome.alarms.create('ucrypt:sync-confirm-retry', { delayInMinutes: 2 }) } catch { /* best-effort */ }
          } else {
            await clearAutoSyncRetryState('mutation-push-ok').catch(() => {})
          }
        } else if (r && !r.ok) {
          await scheduleAutoSyncBackoffRetry(r, { source: 'mutation-auto-sync' }).catch(() => {})
        }
      })
      .catch(async (err) => {
        try { recordCloudLeg({ ok: false, transport: '', reason: String((err && err.message) || err).slice(0, 60) }) } catch { /* best-effort */ }
        await scheduleAutoSyncBackoffRetry(err, { source: 'mutation-auto-sync' }).catch(() => {})
      })
  }, AUTO_SYNC_DEBOUNCE_MS)
  // …plus the durable one-shot alarm (the worker-died lane). Same name ⇒
  // Chrome replaces it — bursts always land exactly one follow-up cycle.
  try { chrome.alarms.create(AUTO_SYNC_ALARM, { delayInMinutes: 0.5 }) } catch { /* best-effort */ }
  void op
}

let syncLock = Promise.resolve()
function withSyncLock(fn) {
  const next = syncLock.then(fn, fn)
  syncLock = next.then(() => {}, () => {})
  return next
}

/**
 * Encrypt the in-memory vault with the sync key and push it through the
 * configured cloud transport. NEVER THROWS — the outcome (success or the
 * classified SyncError) is recorded in the 'ucrypt:lastPush' ledger and
 * returned, so callers can await a truthful answer and the UI can display it.
 *
 * v2.16.0 hardening (audit findings F4/F8 + proposal D):
 *   - EMPTY-PUSH GUARD: a fresh device whose pull failed transiently must
 *     never clobber the cloud copy with an empty vault. The guard that v2.8.0
 *     applied to setSyncCode now protects every transport push too — a vault
 *     with neither entries nor tombstones is refused (deleting the LAST entry
 *     still pushes, because the tombstone is real content).
 *   - TELEMETRY: the ledger records the blob size and the push duration so
 *     the UI can show how big the upload was and how long it took.
 */
async function pushToTransport() {
  // R45-A §2.5: a locked vault NEVER reaches the cloud — there is no
  // credential key to open the transport secrets, and no session-persisted
  // key may be silently decrypted to refresh anything. The ledger records
  // the truthful locked outcome.
  if (!isUnlocked || !credentialKey) {
    const outcome = { ok: false, pushed: false, reason: 'Vault is locked — unlock to sync', locked: true }
    await recordPushOutcome(outcome)
    return outcome
  }
  if (!syncKey) {
    const outcome = { ok: false, pushed: false, reason: 'No sync code set up' }
    await recordPushOutcome(outcome)
    return outcome
  }
  const t = await getTransportRecord()
  if (!t) {
    const outcome = { ok: false, pushed: false, reason: 'No transport configured' }
    await recordPushOutcome(outcome)
    return outcome
  }
  if (!hasVaultContent()) {
    // LAW 0.48 — DIRECTION-OF-TRUTH: the empty vault is TYPED by the member
    // lifecycle. A fresh joiner's push is DISABLED — a typed SKIP row, never
    // a red failure (the CEO's F1: "Last push failed — Local vault is empty"
    // on a brand-new member was the lie; receiving comes first). The genuine
    // data-loss guard arms ONLY in 'synced', where empty-local + non-empty-
    // remote is a real loss signal, and its row carries the typed recovery
    // question instead of a dead end.
    const lc = await getMemberLifecycle()
    if (lc.state === 'awaiting-first-pull') {
      const outcome = {
        ok: false,
        pushed: false,
        skipped: true,
        skipClass: 'awaiting-first-pull',
        lifecycle: 'awaiting-first-pull',
        transportId: t.id,
        at: Date.now(),
        reason: 'Push waits — this device receives your chain\u2019s data first (Pull now); an empty vault never overwrites the cloud copy',
        nextAction: 'pull',
      }
      await recordPushOutcome(outcome)
      return outcome
    }
    // R172 — THE VIRGIN-REMOTE LAW (R-172.3): when the newest pull
    // POSITIVELY observed the remote empty (the typed EMPTY_REMOTE — the
    // transport leg answered and ruled the copy out), a fresh cloud copy
    // proceeds directly: a virgin remote can never block the first push.
    // The loss guard arms only where there is something to lose. The fact
    // reads the pull ledger's own typed fields (transportState 'absent' +
    // remoteObserved true) — never a guess.
    let remotePositivelyEmpty = false
    try {
      const { [LAST_PULL_KEY]: led } = await chrome.storage.local.get(LAST_PULL_KEY)
      remotePositivelyEmpty = !!(
        led &&
        led.ok === true &&
        led.remoteObserved === true &&
        (led.transportState === 'absent' || (led.transportState === 'readable' && Number(led.remoteEntryCount) === 0))
      )
    } catch { /* the ledger read never blocks the guard */ }
    if (!remotePositivelyEmpty) {
      const outcome = {
        ok: false,
        pushed: false,
        transportId: t.id,
        at: Date.now(),
        guardClass: 'empty-vault-synced',
        guardQuestion: 'Your local vault is empty — the cloud copy may hold your data. Pull now to restore it here, or confirm this device should start fresh.',
        reason: 'Local vault is empty — the remote copy was left untouched',
        nextAction: 'pull-or-confirm',
      }
      await recordPushOutcome(outcome)
      return outcome
    }
    try {
      recordCloudLeg({ ok: true, transport: String(t.id || ''), reason: 'the empty-local guard stood down — the remote is positively EMPTY (EMPTY_REMOTE); the first push proceeds' })
    } catch { /* the leg ledger never blocks the push */ }
  }
  const started = Date.now()
  // R177 — R-177.4 THE UPLOAD'S TRUTH: the flag flips the instant the
  // transport's upload leg RESOLVES — from that moment the copy has LANDED,
  // and no later rejection (the proof record, the read-back confirm, the
  // verdict assembly) may be reported as "push failed". The field's own rows
  // proved the false-negative class: cycles reading "✓ merge: Already in
  // sync (merge found no changes)" against a cloud the same row called
  // unpushed — a merge can only find no changes when the remote copy already
  // MATCHES, which is only possible when earlier pushes' uploads LANDED
  // while their verdict rows said failed (E-39's pattern, 23:59:17).
  let uploadLanded = false
  try {
    // v2.42.5 — R69 (F-R69-LOC-1): the cloud envelope is the SYNCABLE
    // SNAPSHOT. lastUsedAt (device-local fill telemetry) and any
    // non-whitelisted state never reach the transport or a peer device.
    const blob = await encryptString(JSON.stringify(await snapshotForWire(vaultData, { lane: 'cloud' })), syncKey)
    await syncUpload(blob, t.id, t.config)
    uploadLanded = true // the upload leg resolved — the copy LANDED (R-177.4)
    // R178 — R-178.3 THE LIFECYCLE WRITE: the upload landing is the state
    // machine's 'written' event (the bytes ride; the read-back confirm is a
    // separate verdict and never demotes the landed truth).
    try { await noteEnvelopeLifecycle('remote-written', { bytes: blob.length }) } catch { /* the lifecycle never blocks the push */ }
    await recordBackupProof(blob, t.id) // R45-E: encrypted verified-backup proof
    // LAW 0.49 — READ-BACK CONFIRMATION (R133, the CEO's F2 made law): the
    // push is "confirmed" only when a fresh GET returns the bytes we pushed
    // (sha256 match). The "Cloud copy confirmed ✓ <time>" truth flips ONLY on
    // a matching read-back — never on the upload's 2xx alone. A mismatch is
    // a typed warning with an automatic retry (the alarm rides in the
    // outcome's confirmError; background schedules the backoff).
    let confirmed = false
    let confirmError = null
    try {
      const back = await syncDownload(t.id, t.config)
      if (back && back === blob) {
        confirmed = true
      } else if (back) {
        const a = Array.from(new Uint8Array(await sha256(new TextEncoder().encode(back)))).map(b => b.toString(16).padStart(2, '0')).join('')
        const b = Array.from(new Uint8Array(await sha256(new TextEncoder().encode(blob)))).map(x => x.toString(16).padStart(2, '0')).join('')
        confirmed = a === b
        if (!confirmed) confirmError = 'read-back mismatch — the cloud copy does not match what we pushed; retrying automatically'
      } else {
        confirmError = 'read-back saw no copy yet — retrying automatically'
      }
    } catch (e) {
      // R177 — R-177.4 THE BELT AT THE LAST CONFIRM SEAT: this catch was the
      // ONE verdict-zone seat still baking String(e) — a thenable rejection
      // here rode the row as the poison string "[object Promise]"
      // ("pushed — read-back failed — [object Promise] — retrying
      // automatically", the epic's live catch). The materializer rides:
      // a typed error donates its words, a thenable arrives fingerprinted —
      // the R174 poison class is dead at its last writer seat.
      confirmError = 'read-back failed — ' + materializeUserText(e, { cap: 110 }) + ' — retrying automatically'
    }
    const outcome = {
      ok: true,
      pushed: true,
      confirmed,
      confirmedAt: confirmed ? Date.now() : null,
      confirmError: confirmed ? null : confirmError,
      transportId: t.id,
      at: Date.now(),
      bytes: blob.length,
      durationMs: Date.now() - started,
    }
    await recordPushOutcome(outcome)
    return outcome
  } catch (e) {
    // R171 — THE CUSTODY-DEATH CLEAR: the refresh endpoint answered
    // invalid_grant (the typed flag the transport throws) — the stored
    // grant is DEAD and is cleared HERE (the dead grant never lingers;
    // the typed reconnect card still rides to the surface). Best-effort:
    // the clear never masks the original error.
    if (e && e.custodyDead) {
      try { await clearTransportGrants() } catch { /* the ledger keeps the typed evidence */ }
    }
    // R177 — R-177.4 THE THENABLE BIRTH-RECORDER: the belt fingerprints the
    // arrival honestly (R-176.4, field-proven at 23:59:17); when the arrival
    // is a thenable, the catching frame also records its OWN stack into the
    // evidence ring — the next field arrival NAMES its birth frame chain
    // (the static hunt of v3.36.0 is clean; only the runtime can name the
    // dynamic birth — so the runtime is made to testify).
    if (e && typeof e.then === 'function') {
      try {
        await recordRing({
          flow: 'sync', transport: String(t.id || ''), stage: 'push-thenable-birth',
          outcome: 'fail', httpKind: 'catch', error: 'thenable-at-push-catch',
          message: 'a thenable arrived where words belong — the catch-site frame chain: ' +
            String(new Error().stack || '').split('\n').slice(2, 8).join(' <- ').replace(/\s+/g, ' ').slice(0, 280),
        })
      } catch { /* the recorder never masks the original error */ }
    }
    // R177 — R-177.4 THE UPLOAD-TRUTH VERDICT: "push failed" may only mean
    // the copy did not land. A post-upload rejection speaks the LANDED truth
    // (the proof step / verdict step failed — the typed words ride) — the
    // false-negative class is dead at the writer. The machine-readable fact
    // rides beside the words (landed: true) so every reader names the era.
    const materialized = materializeUserText(e, { cap: 300 })
    const errorWords = uploadLanded
      ? 'the copy landed; the verdict step failed — ' + materialized
      : materialized
    const outcome = {
      ok: false,
      pushed: false,
      landed: uploadLanded,
      transportId: t.id,
      at: Date.now(),
      kind: (e && typeof e.kind === 'string' && e.kind) || null,
      status: (e && Number.isFinite(Number(e.status))) ? Number(e.status) : null,
      custodyDead: !!(e && e.custodyDead),
      error: errorWords,
    }
    await recordPushOutcome(outcome)
    return outcome
  }
}

/** Awaitable, single-flight transport push for callers that must report the real outcome.
 * R175 — the push-only cycle lands its ONE row too (the mutation debounce's
 * own truth; the coalescing writer keeps the bursts quiet — R-175.7).
 * R176 — R-176.6 THE ONE-CLICK ROAD HOME: the retry that rides a fresh
 * VERIFIED mint is TYPED — the cycle row's source names it ('retry') so the
 * owner reads "this push was the mint's own retry", bounded (once per
 * save — the save fires exactly one), never a silent loop. */
export function pushVaultToTransport(opts = null) {
  const retryOf = !!(opts && opts.retryOf)
  return withSyncLock(async () => {
    const push = await pushToTransport()
    try {
      await recordCycleOutcome(buildCycleRow({ push, source: retryOf ? 'retry' : 'push' }))
    } catch { /* the cycle ledger never blocks the push */ }
    return push
  })
}

/**
 * Pull from all sources (chrome.storage.sync chunks + configured transport),
 * decrypt with the sync key, and adopt the newest copy.
 *
 * v2.16.0 — the merge-push is now ONE awaited push inside the pull (the old
 * code fired saveVault's fire-and-forget push AND syncNow pushed again —
 * two concurrent uploads of the same blob, audit finding F2). The pull
 * reports `pushed` so syncNow never duplicates it.
 */
async function _pullCore(opts = {}) {
  // R45-A §2.5: a locked vault never consults the cloud — scheduled ticks,
  // unlock-pull debounces and every other caller get the truthful locked
  // answer, and the pull is skipped entirely.
  if (!isUnlocked) return { synced: false, reason: 'Vault is locked — unlock to sync', remoteObserved: false, locked: true }
  if (!syncKey) return { synced: false, reason: 'Sync code not set up' }

  const candidates = []

  const chunked = await readChunkedSync().catch(() => null)
  if (chunked) candidates.push(chunked)

  // v2.17.0 — R26-F1: the transport leg is THREE-STATE. A download that
  // THROWS used to be swallowed (a bare console.warn), the pull then answered
  // the same "No readable remote vault" as a positively empty remote — and
  // syncNow pushed the LOCAL snapshot over a cloud copy that was never read.
  // A transient outage (or an expired Dropbox token) could thereby regress
  // the remote. The push is now gated on a POSITIVELY observed remote.
  // v2.20.0 — R29-F3 (audit 27a-3 — the fix the R27 record claimed but the
  // source never carried): a fifth state, 'unreadable'. 'readable' used to be
  // claimed on ANY non-null download BEFORE the envelope/decrypt checks — a
  // transport blob this key cannot read (foreign vault on the same URL,
  // corrupt/partial write, different KDF envelope) plus a readable chunked
  // candidate still reported remoteObserved:true and the merge path PUSHED
  // over a remote it had never semantically read. The transport leg's blob is
  // now tracked per-candidate; if it fails the envelope pre-check or the GCM
  // decrypt, the leg downgrades to 'unreadable' — NOT observed for push
  // purposes, with its own truthful reason.
  let transportState = 'unconfigured' // 'absent' | 'readable' | 'unreadable' | 'error'
  // v2.19.0 — R28-F4 (audit 27a-5): 'unconfigured' (a skipTransport pull — the
  // onChanged chunk-merge debounce) never consulted the transport, so for
  // every remote-observation purpose it is NOT observed — exactly like
  // 'error'. The convergence push below requires a POSITIVELY observed
  // transport leg ('readable' or 'absent'); 'unreadable' and 'error' never push.
  const transportObserved = () => transportState === 'readable' || transportState === 'absent'
  let transportError = null
  // R112 §3.1 (law 0.26 — the resolution-path law): the typed cause data.
  // The ledger used to flatten the transport error to a user-message STRING,
  // which destroyed the SyncError kind — the attention state could say
  // "something failed" but never NAME the cause. The kind and status now
  // ride every error exit so the classifier (classifyAttentionCause) can
  // name the fix: auth → re-sign, network → test, protocol/config → edit
  // setup, 'unreadable' → the safe reseed. Payload additions-only.
  let transportErrorKind = null
  let transportErrorStatus = null
  // R116 §2.1 (the refresh-path completion): the recovery card's KIND rides
  // the ledger too — 'client_disabled' / 'invalid_grant' / … — so the
  // attention classifier can name the DISABLED client as its own cause and
  // never render it as "expired login" (the CEO's S2 cause-class law).
  let transportErrorRecoveryKind = null
  // R172 — THE ACTIVE-METHOD STAMP (R-172.1/R-172.7): the ledger carries the
  // transport's ACTIVE method ('fast' | 'guided' | 'bridge' | 'manual' | ''),
  // derived from the record's own material — the classifier consults it
  // BEFORE any class fires, and the surfaces speak the active method's words.
  let transportLegMode = ''
  let transportBlobIndex = -1 // index of the transport leg's blob inside candidates
  // R178 — R-178.3 THE REMOTE EVIDENCE: the transport leg's own read facts
  // (fileId/bytes/modifiedTime/at) when the transport offered them — null
  // when the leg answered without evidence (the honest absence).
  let transportEvidence = null
  // R92 §2.5 — the R91 class-b nit (lastPull.transportId ledger): _pullCore
  // never carried the consulted transport's ID, so the pull-outcome ledger
  // always recorded transportId:null. The ID now rides EVERY exit shape
  // once the transport is configured — the ledger can truthfully say WHICH
  // transport the newest cloud read consulted.
  let transportLegId = null
  // v2.20.0 — R29-F4 (journey 29 catch): the observation-bearing exits used to
  // build the UI's transportError with `(transportError && …) || String(transportError) || fallback`
  // — and String(null) is the TRUTHY string 'null', which short-circuited the
  // fallback and rendered "✗ … — null" in the Sync row. The helper also gives
  // the 'unreadable' leg its own truthful note instead of the generic text.
  const transportNote = () => (transportError && (transportError.userMessage || transportError.message))
    || (transportError ? String(transportError) : '')
    || (transportState === 'unreadable'
      ? 'the cloud copy could not be read with this sync code'
      : 'the transport was not consulted this round')
  if (!opts.skipTransport) {
    // R45-A §2.3: the transport record is opened through the credential
    // envelope path — secrets exist transiently in worker memory only.
    // While locked this throws; the leg reports 'error' with the truthful
    // locked note and the push stays unobserved (never fired).
    let t = null
    try {
      t = await getTransportRecord()
      // R172 — the active method derives from the record's OWN material
      // (the field names only; never a value — law 0.14):
      //   authMode 'fast' | a webToken/refreshToken custody → 'fast'
      //   authMode 'bridge' | a scriptUrl → 'bridge'
      //   otherwise an OAuth-shaped client id or the recorded signinMode
      //   names guided/manual honestly.
      const c = (t && t.config) || null
      const sig = String((c && c.signinMode) || '')
      const am = String((c && c.authMode) || '')
      if (am === 'fast' || sig === 'fast' || String((c && c.webToken && c.webToken.token) || '').trim() || String((c && c.refreshToken) || '').trim()) transportLegMode = 'fast'
      else if (am === 'bridge' || sig === 'manual' || String((c && c.scriptUrl) || '').trim()) transportLegMode = 'bridge'
      else if (sig === 'guided' || String((c && c.clientId) || '').trim()) transportLegMode = 'guided'
      else transportLegMode = sig || am || ''
    } catch (e) {
      transportState = 'error'
      transportError = e
      transportErrorKind = (e && e.kind) || null
      transportErrorStatus = (e && e.status) || null
      transportErrorRecoveryKind = (e && e.recovery && e.recovery.kind) || null
    }
    if (t?.id) {
      transportLegId = t.id
      try {
        // R178 — R-178.3 THE EVIDENCE SEAM: the pull reads WITH the remote's
        // own evidence (file id + byte count + modified time) when the
        // transport offers it — the pull row then carries WHAT was read, and
        // "the cloud copy was read" can never again mean "only the first
        // hop answered" (the map's Adjudication 5). The plain download
        // contract stays byte-true for every other caller.
        const dl = await syncDownloadWithEvidence(t.id, t.config)
        const blob = dl && dl.blob
        if (dl && dl.evidence) transportEvidence = dl.evidence
        if (blob) {
          transportBlobIndex = candidates.length
          candidates.push(blob)
          transportState = 'readable'
        } else {
          transportState = 'absent' // 404/409/init-marker — confirmed absence
        }
      } catch (e) {
        transportState = 'error'
        transportError = e
        transportErrorKind = (e && e.kind) || null
        transportErrorStatus = (e && e.status) || null
        transportErrorRecoveryKind = (e && e.recovery && e.recovery.kind) || null
        // R171 — the pull path rides the custody-death clear too (the
        // refresh grant died mid-read — the stored grant never lingers).
        if (e && e.custodyDead) {
          try { await clearTransportGrants() } catch { /* the ledger keeps the typed evidence */ }
        }
        console.warn('[UCrypt] transport download failed:', e)
      }
    }
  }

  let newest = null
  let skippedGarbage = 0
  for (let ci = 0; ci < candidates.length; ci++) {
    const blob = candidates[ci]
    // v2.3.0: structural pre-check — don't spend PBKDF2 + GCM on HTML error
    // pages, JSON error bodies, or empty files. (Authenticity itself is
    // still enforced by the GCM tag during decryption.)
    if (!looksLikeVaultEnvelope(blob)) {
      skippedGarbage++
      // R29-F3: the TRANSPORT leg's own blob is structurally foreign —
      // the leg never delivered readable data this round.
      if (ci === transportBlobIndex) transportState = 'unreadable'
      continue
    }
    try {
      const json = await decryptString(blob, syncKey)
      // v2.42.5 — R69 (F-R69-LOC-1): the remote envelope is sanitized the
      // moment it is decrypted — legacy lastUsedAt telemetry (envelopes from
      // ≤ v2.42.4 peers) and ANY non-whitelisted field are stripped BEFORE
      // adoption, the merge, or the canonical comparison. Old envelopes stay
      // readable; their telemetry never lands on this device and never
      // re-rides the next push.
      const __raw = JSON.parse(json)
      await deliverChainDevices(__raw)
      await deliverChainState(__raw)
      // R178 — R-178.3 THE LIFECYCLE READ: the transport leg's blob decoded
      // with THIS sync key — the envelope was READ (the state machine's
      // 'read' event; the created facts ride the evidence when offered).
      if (ci === transportBlobIndex) {
        try { await noteEnvelopeLifecycle('remote-read', transportEvidence) } catch { /* the lifecycle never blocks the pull */ }
      }
      const remote = fromSyncSnapshot(__raw)
      if (!newest || (remote.lastModified || 0) > (newest.lastModified || 0)) newest = remote
    } catch {
      // wrong key or corrupt blob — skip
      skippedGarbage++
      // R29-F3: the transport leg's blob passed the envelope shape but its
      // GCM tag (or its JSON) failed with OUR key — an unverifiable remote.
      if (ci === transportBlobIndex) transportState = 'unreadable'
    }
  }

  if (!newest) {
    // LAW 0.48 — a pull that positively completed with NO remote copy is the
    // first-device truth: the member is 'synced' (nothing to receive). A
    // landed pull with content flips via the adoption/merge paths below.
    if (!skippedGarbage && transportState !== 'error') {
      try { await markMemberSynced('pull-completed-empty-remote') } catch { /* lifecycle is best-effort */ }
    }
    // R178 — R-178.3 THE ENVELOPE LIFECYCLE: a positively-observed ABSENT
    // remote is the state machine's ground truth — 'never-created' (the copy
    // the panel and the test verdict speak is the SAME state every seat).
    if (transportState === 'absent') {
      try { await noteEnvelopeLifecycle('remote-absent', null) } catch { /* the lifecycle never blocks the pull */ }
    }
    if (skippedGarbage > 0) {
      // v2.21.0 — R30-a (lens-reversal, CORRECTED): this exit deliberately
      // does NOT carry a transportError note — the shape is LOAD-BEARING.
      // setSyncCode (R28-F3) classifies a failed pull by
      //   remoteObserved:false + transportError  → "transport unreachable"  → defer the push
      //   remoteObserved:false + NO transportError → "remote present but
      //   undecryptable" (the KDF-upgrade signature, or a corrupt record)
      //   → PUSH, because the user explicitly re-keyed this vault.
      // The skipped-garbage exit IS the second case: data was downloaded and
      // positively failed the envelope/decrypt checks — the transport leg
      // answered. Attaching a transportError here (as an R30 audit finding
      // briefly did) silently flipped every setSyncCode push into defer mode
      // — caught by the round-25 harness and proven by this comment. The
      // "unusable data" reason string itself is the Sync row's explanation.
      return { synced: false, reason: `Remote storage returned unusable data (${skippedGarbage} candidate${skippedGarbage === 1 ? '' : 's'} skipped)`, remoteObserved: false, transportState, garbage: skippedGarbage, transportId: transportLegId }
    }
    if (transportState === 'error') {
      // R26-F1: the remote's state is UNKNOWN — refuse to declare it empty.
      // Callers (syncNow) must NOT push over an unobserved remote.
      return {
        synced: false,
        reason: 'Transport unreachable — the pull was skipped, so nothing was pushed over an unreadable remote',
        remoteObserved: false,
        // R172 — THE HONEST SYNC RESULT (R-172.2): a SKIPPED sync is typed —
        // the named reason (the ledger row), what was skipped (the push leg),
        // the protection rule that caused the skip, and the cure. "Nothing
        // to change" is reserved for a sync that RAN and found zero deltas.
        syncSkipped: true,
        skippedLegs: ['push'],
        protection: 'never-push-over-unreadable-remote',
        transportError: transportNote(),
        transportErrorKind, // R112 §3.1 — the typed cause rides the ledger
        transportErrorStatus,
        transportErrorRecoveryKind, // R116 §2.1 — the card kind (client_disabled / invalid_grant / …)
        transportMode: transportLegMode, // R172 — the ACTIVE-method stamp (the classifier consults it first)
        transportState,
        transportId: transportLegId,
      }
    }
    // R172 — THE TYPED EMPTY_REMOTE (R-172.3): a pull that positively
    // completed with NO remote copy is a NAMED class, never an unnamed
    // shape — a virgin remote can never block a fresh cloud copy, and the
    // road-home fork reads THIS flag.
    // R178 — R-178.3 THE NAMED EMPTY: the words ARE the Named Unknown the
    // command mandates — "cloud empty — nothing to pull" (the old shape
    // 'No readable remote vault' could read as a failure; the empty cloud is
    // a READ SUCCESS whose content is nothing).
    return {
      synced: false,
      reason: 'cloud empty — nothing to pull (the remote was positively read as absent)',
      emptyRemote: true,
      remoteObserved: true,
      transportState,
      remoteEntryCount: 0,
      connectionSyncKind: 'initial-upload',
      transportMode: transportLegMode,
      transportId: transportLegId,
      ...(transportEvidence ? { transportEvidence } : {}),
    }
  }

  const remoteEntryCount = ((newest && Array.isArray(newest.entries)) ? newest.entries.length : 0) +
    ((newest && Array.isArray(newest.tombstones)) ? newest.tombstones.length : 0)

  // v2.4.0 — ENTRY-LEVEL MERGE. The old code blindly adopted the newest
  // snapshot, which resurrected deletions made on other devices. Now the
  // remote snapshot is merged with the local one (per-entry LWW + tombstones).
  const hadLocalVault = !!(vaultData?.entries && vaultData.entries.length) ||
                        !!(vaultData?.tombstones && vaultData.tombstones.length)
  if (!hadLocalVault) {
    // First device / empty vault — adopt as-is (nothing to merge against).
    // v2.42.7 — R70 §2.4: a legacy peer envelope may carry attached
    // login.totp copies — convert to the canonical model before adopting.
    const migAdopt = migrateLegacyAttachedTotp(newest)
    if (migAdopt.scanned > 0) {
      console.log(`[UCrypt] TOTP canonical migration (adopted envelope): ${migAdopt.secretsRemoved} converted`)
    }
    vaultData = newest
    await saveVault({ skipTransport: true }) // cache locally; no echo push
    // LAW 0.48 — THE FIRST PULL LANDED: the joiner's lifecycle flips to
    // 'synced' (two-way sync begins) and — LAW 0.49 — one debounced auto-sync
    // cycle pushes the freshly adopted vault back so the loop's push leg is
    // CONFIRMED by read-back without a human step (the stale "Last push
    // failed" row the CEO captured can never survive the first pull).
    if (hasVaultContent() || transportObserved()) {
      try { await markMemberSynced('first-pull-adopted') } catch { /* lifecycle is best-effort */ }
      if (hasVaultContent()) scheduleCloudAutoSync('first-pull-adopted')
    }
    // R111 §3.2 — the as-is adoption's visible moment (the cloud lane).
    recordSyncMoment({ lane: 'cloud', added: (newest.entries || []).length, updated: 0, by: '' })
    return {
      synced: true,
      reason: 'Updated from sync',
      entryCount: newest.entries?.length || 0,
      remoteEntryCount,
      transportState,
      transportMode: transportLegMode,
      connectionSyncKind: remoteEntryCount > 0 ? 'initial-download-adopted' : 'recurrent-in-sync',
      remoteObserved: transportObserved(), // R26-F1 + R28-F4
      ...(transportEvidence ? { transportEvidence } : {}),
      ...(transportObserved() ? { transportId: transportLegId } : { transportError: transportNote(), transportId: transportLegId }),
    }
  }

  // UCRYPT-16 — Run SHA-256 canonical hash comparison & per-entry diff
  // between the pre-merge local vault and the remote cloud vault snapshot.
  const localSnapshotBeforeMerge = JSON.parse(JSON.stringify(vaultData || { entries: [], tombstones: [], lastModified: 0 }))
  const remoteSnapshotBeforeMerge = JSON.parse(JSON.stringify(newest || { entries: [], tombstones: [], lastModified: 0 }))
  const hashConflictReport = await detectVaultHashConflict(localSnapshotBeforeMerge, remoteSnapshotBeforeMerge)

  const merged = mergeVaults(vaultData, newest)
  // R111 §3.2 — capture the pre-merge entries for the visible moment's diff.
  const beforeEntriesForDiff = vaultData.entries
  // v2.42.5 — R69 (F-R69-LOC-1): usage telemetry is device-local. When the
  // merge adopts a REMOTE copy of an entry (newer updatedAt), that copy has
  // no lastUsedAt (snapshots never carry it), so THIS device's own value is
  // re-attached — local usage history survives adoption, and no foreign
  // telemetry can appear because remote snapshots were stripped at the
  // decrypt chokepoint above. canonicalVaultJson ignores lastUsedAt, so this
  // can never create merge churn or a sync ping-pong.
  {
    const ownUsed = new Map()
    for (const e of vaultData.entries) {
      if (e.lastUsedAt) ownUsed.set(mergeEntryKey(e), e.lastUsedAt)
    }
    for (const e of merged.entries) {
      if (!e.lastUsedAt) {
        const lu = ownUsed.get(mergeEntryKey(e))
        if (lu) e.lastUsedAt = lu
      }
    }
  }
  // v2.42.7 — R70 §2.4 (F-R70-MODEL-1): a legacy peer snapshot can merge
  // attached login.totp copies back in — convert to the canonical model
  // before the change comparison so the canonical form is what persists.
  migrateLegacyAttachedTotp(merged)
  const localCanonical = canonicalVaultJson(vaultData)
  const mergedCanonical = canonicalVaultJson(merged)
  // R178 — R-178.3: the REMOTE fingerprint's canonical form is computed
  // HERE (once, before the already-in-sync exit that names it — the exit
  // cannot reference a declaration that lived below it).
  const remoteCanonical = canonicalVaultJson(newest)

  // UCRYPT-16 — Record the SHA-256 hash comparison & conflict state for the
  // Sync Settings 'Conflict Resolver' UI whenever a hash mismatch is observed
  // (or refresh the clean matched state when hashes match).
  const conflictPolicy = await getVaultConflictPolicy()
  const shouldPauseForManualResolution = !!(
    hashConflictReport.hasHashMismatch &&
    !opts.forceAutoMerge &&
    (opts.pauseOnHashMismatch === true ||
      (conflictPolicy === 'manual' && (hashConflictReport.requiresManualResolution || hashConflictReport.hasHashMismatch)))
  )
  await recordVaultConflictFromMerge({
    localVault: localSnapshotBeforeMerge,
    remoteVault: remoteSnapshotBeforeMerge,
    mergedVault: merged,
    report: hashConflictReport,
    paused: shouldPauseForManualResolution,
    transportId: transportLegId,
  })
  if (shouldPauseForManualResolution) {
    return {
      synced: false,
      conflictDetected: true,
      conflictPending: true,
      localHash: hashConflictReport.localHash,
      remoteHash: hashConflictReport.remoteHash,
      mergedHash: hashConflictReport.mergedHash,
      conflictCount: hashConflictReport.conflictCount,
      reason: `Hash mismatch detected during merge (local ${hashConflictReport.localHash.slice(0, 8)}… vs cloud ${hashConflictReport.remoteHash.slice(0, 8)}…) — open Conflict Resolver in Sync Settings to choose Local, Cloud, or Smart Merge`,
      remoteEntryCount,
      transportState,
      transportMode: transportLegMode,
      connectionSyncKind: 'hash-mismatch-conflict',
      remoteObserved: transportObserved(),
      ...(transportEvidence ? { transportEvidence } : {}),
      transportId: transportLegId,
    }
  }

  // R127 (law 0.41): a pending roster change (a rename / a removal — chain
  // state outside the vault) consumes the marker and FORCES the envelope:
  // the "Already in sync" exit must never swallow a roster change.
  const rosterDirty = await consumeRosterDirty()
  if (mergedCanonical === localCanonical && !rosterDirty) {
    // Merge produced nothing new locally — still refresh lastModified/session.
    // v2.17.0 — R26-F1: even this "no changes" exit reports observation
    // truthfully — with the transport unreachable, the merge ran against the
    // chunked copy only, and syncNow must not push over the unseen remote.
    vaultData.lastModified = Math.max(vaultData.lastModified || 0, newest.lastModified || 0)
    // R178 — R-178.3 THE MERGE NAMES ITS FINGERPRINTS (the map's Adjudication
    // 5): "Already in sync" must name WHAT was compared — local X vs remote Y
    // (entry counts + the snapshot revisions + the canonical byte lengths).
    // The bare "Already in sync (merge found no changes)" over a remote the
    // same frame called unpushed was the field's D5 false-negative face.
    const fpLocal = `${(vaultData.entries || []).length} entries · rev ${vaultData.lastModified || 0} · ${localCanonical.length} B`
    const fpRemote = `${(newest.entries || []).length} entries · rev ${newest.lastModified || 0} · ${remoteCanonical.length} B`
    return {
      synced: false,
      reason: `Already in sync (merge found no changes — local ${fpLocal} vs remote ${fpRemote})`,
      localHash: hashConflictReport.localHash,
      remoteHash: hashConflictReport.remoteHash,
      mergedHash: hashConflictReport.mergedHash,
      hasHashMismatch: hashConflictReport.hasHashMismatch,
      remoteEntryCount,
      transportState,
      transportMode: transportLegMode,
      connectionSyncKind: 'recurrent-in-sync',
      remoteObserved: transportObserved(), // R26-F1 + R28-F4
      ...(transportEvidence ? { transportEvidence } : {}),
      ...(transportObserved() ? { transportId: transportLegId } : { transportError: transportNote(), transportId: transportLegId }),
    }
  }

  vaultData = merged
  pruneTombstones()
  // LAW 0.48 — a merge that landed content completes the join too (a joiner
  // whose vault already held tombstones takes the merge path).
  if (hasVaultContent()) {
    try { await markMemberSynced('pull-merged') } catch { /* lifecycle is best-effort */ }
  }
  // R111 §3.2 — the CLOUD lane's visible moment: the merge landed changes,
  // so the receiving device records one persisted ledger line (counts only —
  // the cloud copy is anonymous, so no device name can honestly ride it).
  {
    const __diff = diffVaultEntries(beforeEntriesForDiff, merged.entries)
    recordSyncMoment({ lane: 'cloud', added: __diff.added, updated: __diff.updated, by: '' })
  }
  // Push back when the merge result differs from what the remote had, so the
  // peer converges (it lacks our entries/tombstones). Otherwise pull silently.
  // v2.16.0 — that convergence push is EXACTLY ONE awaited upload (the empty
  // guard inside pushToTransport also applies: a merge can only produce real
  // content or tombstones here, so the guard cannot block a legitimate push).
  // (R178 — remoteCanonical is computed once above, before the
  // already-in-sync exit that names its fingerprint.)
  // R127 (law 0.41): the roster-dirty fall-through forces the push even when
  // the entries match — the envelope carries the roster, and the roster changed.
  const needsPush = mergedCanonical !== remoteCanonical || rosterDirty
  await saveVault({ skipTransport: true })
  if (!needsPush) {
    return {
      synced: true,
      reason: 'Merged changes from sync',
      localHash: hashConflictReport.localHash,
      remoteHash: hashConflictReport.remoteHash,
      mergedHash: hashConflictReport.mergedHash,
      hasHashMismatch: hashConflictReport.hasHashMismatch,
      entryCount: merged.entries.filter(e => e.type !== 'totp').length,
      remoteEntryCount,
      transportState,
      transportMode: transportLegMode,
      connectionSyncKind: 'recurrent-merged',
      remoteObserved: transportObserved(), // R26-F1 + R28-F4
      ...(transportEvidence ? { transportEvidence } : {}),
      transportId: transportLegId,
      ...(transportObserved() ? {} : { transportError: transportNote() }),
    }
  }
  // v2.17.0 — R26-F1: the transport remote was NOT readable this round, so
  // the merge ran against the chunked copy only — pushing the result could
  // clobber a NEWER cloud snapshot we never saw. The merged data is safe
  // locally; the next successful pull/push converges.
  // v2.19.0 — R28-F4 (audit 27a-5): the skipTransport path ('unconfigured')
  // used to fall THROUGH and push the merged result over a transport that
  // was never consulted — the onChanged chunk-merge debounce could regress
  // a peer whose transport push had succeeded where its chunk write failed.
  if (!transportObserved()) {
    return {
      synced: true,
      // R29-F3: three truthful skip reasons — unreachable, undecryptable,
      // never-consulted. 'unreadable' no longer masquerades as 'readable'.
      reason: transportState === 'error'
        ? 'Merged changes from sync — push skipped (the transport is unreachable; nothing is pushed over an unreadable remote)'
        : transportState === 'unreadable'
          ? 'Merged changes from sync — push skipped (the cloud copy could not be read with this sync code; nothing is pushed over a remote this key cannot verify)'
          : 'Merged changes from sync — push skipped (the transport was not consulted this round)',
      localHash: hashConflictReport.localHash,
      remoteHash: hashConflictReport.remoteHash,
      mergedHash: hashConflictReport.mergedHash,
      hasHashMismatch: hashConflictReport.hasHashMismatch,
      entryCount: merged.entries.filter(e => e.type !== 'totp').length,
      remoteEntryCount,
      transportState,
      transportMode: transportLegMode,
      remoteObserved: false,
      transportError: transportNote(),
      transportId: transportLegId,
    }
  }
  const push = await pushToTransport()
  return {
    synced: true,
    reason: 'Merged changes from sync — pushed result',
    localHash: hashConflictReport.localHash,
    remoteHash: hashConflictReport.remoteHash,
    mergedHash: hashConflictReport.mergedHash,
    hasHashMismatch: hashConflictReport.hasHashMismatch,
    entryCount: merged.entries.filter(e => e.type !== 'totp').length,
    remoteEntryCount,
    transportState,
    transportMode: transportLegMode,
    connectionSyncKind: 'recurrent-merged-updated',
    remoteObserved: true,
    ...(transportEvidence ? { transportEvidence } : {}),
    pushed: true,
    transportId: transportLegId,
    push,
  }
}

export function pullFromSync(opts = {}) {
  // R175 — the pull-only cycle obeys the one-truth law too (R-175.1): the
  // unlock pull and the 15-min tick land their ONE row (the coalescing
  // writer keeps the repetition quiet — R-175.7). The merge-convergence
  // push (pull.pushed) rides the same row — never a sibling verdict.
  return withSyncLock(() => _pullCore(opts).then(async (pull) => {
    const recorded = await recordPullLedger(pull)
    try {
      await recordCycleOutcome(buildCycleRow({ pull: recorded, push: (recorded && recorded.pushed) ? (recorded.push || null) : null, source: 'pull' }))
    } catch { /* the cycle ledger never blocks the pull */ }
    return recorded
  }))
}

/**
 * R61-A §1.1 — the pull-outcome ledger. Every completed pull records whether
 * the device positively observed the remote (read a copy or positively ruled
 * it out). `attempted && !ok` is the "Chain needs attention — upload blocked
 * until cloud copy can be read" evidence; a pull that never ran (no sync
 * code) leaves the ledger untouched so the no-chain state stays truthful.
 * The ledger NEVER throws — recording must not break sync.
 * R95 §1.1: exported so the battery can pin the not-consulted-pull-never-writes
 * law (the R94-F1 proof was live-only; the battery row is the standing pin).
 */
export async function recordPullLedger(pull) {
  try {
    // "Not consulted" pulls (vault locked, no transport configured, leg
    // skipped) are NOT failed reads — they carry no evidence about the remote
    // and must never drive the attention state. A real transport read counts
    // as observed ONLY when the pull positively saw the remote
    // (remoteObserved === true: a copy was read OR its absence was confirmed).
    // R95-D2 (robustness): transportError may arrive as an Error-shaped
    // object; String(obj) is "[object Object]", which silently defeated the
    // not-consulted regex. Read the human message off the object first.
    const terr = pull && pull.transportError
    const terrStr = typeof terr === 'string'
      ? terr
      : (terr && (terr.userMessage || terr.message)) || ''
    const notConsulted = !!(pull && (pull.locked === true ||
      /not consulted/i.test(String(terrStr || pull.reason || ''))))
    // R95-D1 (§1.1 closeout): the never-ran shapes carry NO evidence about
    // the remote either — a null pull (no call) and the no-sync-code pull
    // ('Sync code not set up') must leave the ledger untouched, exactly like
    // the not-consulted pulls R94-F1 already returns untouched. The ledger's
    // own docstring has promised the no-sync-code case since R61-A ("a pull
    // that never ran leaves the ledger untouched so the no-chain state stays
    // truthful"), but the shape fell through the guard: on a no-chain device
    // with a transport configured, the 15-min tick wrote attempted:true/ok:
    // false and the transfer settings' Last pull row rendered "✗ … — Sync
    // code not set up" — a pull that never happened, on a chain that does
    // not exist. Battery row: tests/r95-ground.test.mjs G1.
    const neverRan = !pull || pull.reason === 'Sync code not set up'
    if (neverRan || notConsulted) return pull
    const attempted = !!pull && typeof pull === 'object' && !notConsulted
    const ok = attempted && pull.remoteObserved === true
    // R112 §3.1 (law 0.26) — the typed cause fields ride the ledger: kind
    // (SyncError kind), status (HTTP status), state ('error'/'unreadable'/
    // 'absent'/'readable') and garbage (the skipped-candidate count). The
    // attention classifier reads THESE — never a string regex on the
    // message — so the cause named to the user is the cause the transport
    // typed. Plain-object serialization only (chrome.storage-safe).
    const kind = attempted ? (typeof pull.transportErrorKind === 'string' ? pull.transportErrorKind : null) : null
    const status = attempted && Number.isFinite(Number(pull.transportErrorStatus)) ? Number(pull.transportErrorStatus) : null
    // R116 §2.1 — the recovery card's kind + the raw engine line ride the
    // ledger (the cause-class precision: the classifier names the DISABLED
    // client as its own cause; the Show-more detail carries the exact words,
    // which never contain a secret — a SyncError message is a typed line).
    const recoveryKind = attempted ? (typeof pull.transportErrorRecoveryKind === 'string' ? pull.transportErrorRecoveryKind : null) : null
    const tstate = attempted && typeof pull.transportState === 'string' ? pull.transportState : null
    const garbage = attempted && Number.isFinite(Number(pull.garbage)) ? Number(pull.garbage) : null
    const remoteEntryCount = attempted && Number.isFinite(Number(pull.remoteEntryCount)) ? Number(pull.remoteEntryCount) : null
    const connectionSyncKind = attempted && typeof pull.connectionSyncKind === 'string' ? pull.connectionSyncKind : null
    // R172 — the ACTIVE-method stamp rides the ledger (the classifier and
    // the surfaces consult it BEFORE any class fires — R-172.1/R-172.7).
    const transportMode = attempted && typeof pull.transportMode === 'string' ? pull.transportMode : null
    await chrome.storage.local.set({
      [LAST_PULL_KEY]: {
        attempted,
        ok,
        at: Date.now(),
        remoteObserved: attempted ? pull.remoteObserved === true : false,
        // R171 — the honest-error materializer rides the pull ledger too:
        // the error/reason fields are strings before they ever touch storage.
        // (A null error stays null — the materializer only answers when the
        // value exists; the no-evidence rows keep their byte-true shape.)
        error: attempted ? ((pull && (pull.transportError || pull.reason)) != null ? materializeUserText((pull && (pull.transportError || pull.reason)) || null, { cap: 300, generic: '' }) || null : null) : null,
        kind,
        status,
        recoveryKind,
        transportMode,
        transportState: tstate,
        remoteEntryCount,
        connectionSyncKind,
        garbage,
        transportId: (pull && pull.transportId) || null,
        // R174 — the build stamp rides the pull row too (R-174.6): the
        // field exhibit identifies its own floor.
        build: ledgerBuildStamp(),
      },
    })
    // ── R140 §7 — THE WAKE-CACHE STAMP: every pull attempt IS a probe of the
    // wake cycle. The first attempt of a cycle completes the probe window; a
    // failure climbs the ladder (the derivation stays PENDING until the
    // ladder exhausts); ANY success auto-clears the verdict. The stale-latch
    // class — a transient cold-start failure outliving its own cause — is
    // unrepresentable from this stamp on. ──
    try {
      const { [CHAIN_WAKE_KEY]: wake } = await chrome.storage.local.get(CHAIN_WAKE_KEY)
      if (wake && wake.wakeId) {
        const now = Date.now()
        const next = { ...wake, firstProbeCompletedAt: wake.firstProbeCompletedAt || now }
        if (ok) {
          next.lastProbe = { ok: true, at: now, probeName: 'pull-probe' }
          next.attempts = 0
        } else {
          next.attempts = Math.min(99, (Number(next.attempts) || 0) + 1)
          next.lastProbe = { ok: false, at: now, probeName: 'pull-probe', kind: kind || '', status, transportState: tstate, garbage: garbage || 0 }
        }
        await chrome.storage.local.set({ [CHAIN_WAKE_KEY]: next })
      }
    } catch { /* the wake cache is best-effort — the ledger remains the truth */ }
  } catch { /* ledger failures never block sync */ }
  return pull
}

// ---------------------------------------------------------------------------
// R112 §3.1 — THE RESOLUTION PATH (law 0.26: cause → one-click action →
// deeper diagnostic). "Chain needs attention — upload blocked until the cloud
// copy can be read" is no longer a wall: the pull ledger now carries the
// typed cause (kind/status/transportState/garbage — see recordPullLedger)
// and classifyAttentionCause names THE cause with THE one-click fix.
// ---------------------------------------------------------------------------

/** The five typed causes the attention state decomposes into (§3.1). Each
 * cause: { id, i18n key family suffix, actionable } — the surface renders
 * the sentence, the primary one-click button, and the deeper diagnostic. */
export const ATTENTION_CAUSES = {
  AUTH: 'auth',           // the sign-in expired / the grant was refused
  AUTH_DISABLED: 'auth_disabled', // R116 §2.1 — the OAuth client is DISABLED / testing-mode (never "expired login")
  AUTH_REVOKED: 'auth_revoked',   // R116 §2.1 — the grant was revoked at the provider
  // R153 §5 (C-2) — THE OAUTH PRODUCTION LAW: the named provider errors are
  // their OWN causes, each with its named cure — never a generic "connection
  // problem".
  AUTH_CONSENT: 'auth_consent',   // access_denied — the consent was refused (Testing mode: the account is not a test user)
  AUTH_CONFIG: 'auth_config',     // redirect_uri_mismatch — the client's redirect/type config does not match
  AUTH_ADMIN: 'auth_admin',       // admin_policy_enforced — the workspace admin blocks this app
  // R172 — THE OAUTH RE-AUTH CAUSE (R-172.1/R-172.7): a config-class failure
  // on a record whose ACTIVE method is OAuth is a RE-AUTH, never "the setup
  // answered unexpectedly" — the cause names the one-click sign-in cure in
  // the active method's words. The BRIDGE cause stays for bridge evidence.
  OAUTH_REAUTH: 'oauth_reauth',
  UNREACHABLE: 'unreachable', // the network / the server did not answer
  BRIDGE: 'bridge',       // the setup answered wrong (protocol/config)
  UNREADABLE: 'unreadable',   // the copy was fetched but cannot be read with this sync code
  NOCOPY: 'nocopy',       // connected, but no cloud copy exists yet
  UNKNOWN: 'unknown',     // no typed evidence — the honest fallback
}

/**
 * Name the cause of the attention state from the pull ledger's typed fields.
 * Order is evidence-first: a fetched-but-unreadable copy beats a transport
 * error note (the leg answered, the DATA is the problem); a typed SyncError
 * kind beats everything else; the absence of typed evidence on an old ledger
 * row falls back to 'unknown' (the generic resolution path still applies).
 * R116 §2.1 (the refresh-path completion): the AUTH class splits by the
 * recovery card's kind — 'client_disabled' → AUTH_DISABLED (its own card
 * with the Cloud Console deep link, NEVER the re-sign-in card),
 * revoked-grant wording → AUTH_REVOKED (the reconnect card), everything
 * else auth → AUTH (the re-sign-in card). A disabled client must never
 * render as "expired login".
 * @param {{kind?:string,status?:number,recoveryKind?:string,transportMode?:string,transportState?:string,garbage?:number,error?:string}|null} lastPull
 */
export function classifyAttentionCause(lastPull) {
  if (!lastPull || !lastPull.attempted || lastPull.ok) return null
  const state = typeof lastPull.transportState === 'string' ? lastPull.transportState : null
  const kind = typeof lastPull.kind === 'string' ? lastPull.kind : null
  const status = (lastPull.status === null || lastPull.status === undefined) ? null : (Number.isFinite(Number(lastPull.status)) ? Number(lastPull.status) : null) // R173 — null is null, never 0 (the coercion trap that wore the UNREACHABLE wall on an observed empty remote)
  const garbage = Number.isFinite(Number(lastPull.garbage)) ? Number(lastPull.garbage) : 0
  const recoveryKind = typeof lastPull.recoveryKind === 'string' ? lastPull.recoveryKind : ''
  const errWords = typeof lastPull.error === 'string' ? lastPull.error : ''
  // R172 — THE ACTIVE-METHOD CONSULT (R-172.1, order (a)→(b)→(c)): the
  // ledger's transportMode names the record's ACTIVE method from its OWN
  // material. A config-class failure on an OAuth-active record is a
  // RE-AUTH (the one-click sign-in cure) — the guided/bridge words are
  // structurally unreachable for it. A raw-shape pattern is NEVER the sole
  // classifier input anymore.
  const mode = typeof lastPull.transportMode === 'string' ? lastPull.transportMode : ''
  const oauthActive = mode === 'fast' || mode === 'guided'
  // R173 — the Number(null) coercion trap dies here: a status-less row is
  // not a network row (status null stays null — the honest fallback, never
  // the UNREACHABLE wall). The confirmed-absent pull needs no branch here:
  // the engine already marks it ok:true (a positively-observed remote —
  // readable OR empty — is a successful read; the fork answers it).
  // 1. The copy was FETCHED but cannot be read with this sync code
  //    (envelope pre-check failed, or GCM refused it) → the safe reseed.
  if (state === 'unreadable' || (!state && garbage > 0)) return ATTENTION_CAUSES.UNREADABLE
  // 2. Typed auth failure (401/403 or the OAuth refresh refused) — the
  //    cause-precision split (R116 §2.1): the disabled client is its OWN
  //    cause (the console checklist), the revoked grant is its OWN cause
  //    (the reconnect card); the plain expired grant stays the re-sign card.
  if (kind === 'auth' || status === 401 || status === 403) {
    if (recoveryKind === 'client_disabled' || /client_disabled|client was disabled|disabled or in testing/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_DISABLED
    }
    // R153 §5 (C-2) — the NAMED provider errors type FIRST (they are more
    // specific than the generic expired-grant class), each with its own cure.
    if (recoveryKind === 'redirect_uri_mismatch' || /redirect_uri_mismatch/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_CONFIG
    }
    if (recoveryKind === 'admin_policy_enforced' || /admin_policy_enforced/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_ADMIN
    }
    if (recoveryKind === 'access_denied' || /access_denied/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_CONSENT
    }
    // "Unverified app" is the testing-mode family — the publish-to-production
    // checklist (auth_disabled's card) is the named cure.
    if (recoveryKind === 'unverified_app' || /unverified/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_DISABLED
    }
    if (recoveryKind === 'invalid_grant' && /revok/i.test(errWords)) {
      return ATTENTION_CAUSES.AUTH_REVOKED
    }
    return ATTENTION_CAUSES.AUTH
  }
  // 3. The setup answered wrong (the bridge said something unplausible, the
  //    config is malformed) → the classifier card + Edit setup.
  //    R172 — the one-truth split: an OAuth-active record's config failure
  //    is the OAUTH_REAUTH cause (the active method's cure) — the bridge
  //    card renders for bridge evidence only (R-172.7: "answered
  //    unexpectedly" never reaches an OAuth surface again).
  if (kind === 'protocol' || kind === 'config') {
    if (oauthActive) return ATTENTION_CAUSES.OAUTH_REAUTH
    return ATTENTION_CAUSES.BRIDGE
  }
  // 4. Could not reach the storage at all (network/timeout/server/429) →
  //    Test connection.
  if (kind === 'network' || kind === 'timeout' || kind === 'server' || kind === 'rate_limit' || status === 0) {
    return ATTENTION_CAUSES.UNREACHABLE
  }
  // 5. No typed evidence (a legacy ledger row, or an unclassified throw) —
  //    the honest fallback with the generic one-click path.
  return ATTENTION_CAUSES.UNKNOWN
}

/**
 * The recovery state's fourth cause (§3.1 "no copy yet"): connected +
 * verified backup + never pushed = the cloud copy simply does not exist yet.
 * The state's own one-click is Sync now.
 * @param {{lastPush?:{ok?:boolean}|null, transport?:{hasConfig?:boolean}|null}|null} syncStatus getSyncStatus() shape
 */
export function classifyNoCopyYet(syncStatus) {
  const pushed = !!(syncStatus && syncStatus.lastPush && syncStatus.lastPush.ok)
  const connected = !!(syncStatus && syncStatus.transport && syncStatus.transport.hasConfig)
  return connected && !pushed
}

/** The reseed's archive name: filesystem/API-safe, sortable, self-describing. */
export function reseedArchiveName(at = Date.now()) {
  return 'archived-' + new Date(at).toISOString().replace(/[:.]/g, '-')
}

/**
 * THE SAFE RESEED (§3.1, the 'unreadable' cause's fix). The cloud copy is
 * unreadable with this sync code — the local vault is NEVER at risk, and the
 * old copy is never deleted:
 *   1. fetch the raw bytes (if the copy cannot even be fetched, refuse —
 *      typed; nothing was touched);
 *   2. archive them under a sibling name (<vault>.<archived-…>) — "rename,
 *      never delete" (transports that cannot archive refuse typed, with the
 *      one-click Edit-setup path — the bridge);
 *   3. upload the FRESH envelope of THIS vault (the same snapshot-for-wire
 *      shape every push uses);
 *   4. run a real pull — one readable read unblocks the chain automatically
 *      (the standing law), and the moment lands in the visible ledger.
 * The DOUBLE CONFIRM lives in the surface (two explicit confirms); this
 * function is the worker-side executor and refuses while locked. Single
 * flight: runs inside the sync lock.
 * @returns {{ok:true, archived:string|null, pushed:boolean, read:object} |
 *           {ok:false, stage:'locked'|'no-transport'|'fetch'|'archive'|'push', error:string, cause?:string}}
 */
export async function reseedCloudCopy() {
  return withSyncLock(async () => {
    if (!isUnlocked) return { ok: false, stage: 'locked', error: 'Unlock the vault first — the reseed reads the local vault' }
    const t = await getTransportRecord().catch(() => null)
    if (!t || !t.id) return { ok: false, stage: 'no-transport', error: 'No cloud storage is connected — Connect cloud first' }
    const transport = getTransport(t.id)
    if (!transport) return { ok: false, stage: 'no-transport', error: `Unknown transport: ${t.id}` }
    // 1. FETCH the old bytes (never deletes; a confirmed absence skips the
    // archive leg — there is nothing to preserve).
    let raw = null
    try {
      raw = await syncDownload(t.id, t.config)
    } catch (e) {
      // R174 — the writer-depth materializer (the poison cannot be born; the
      // typed SyncError userMessage keeps its byte-true priority)
      return { ok: false, stage: 'fetch', error: materializeUserText(e, { cap: 300 }) }
    }
    // 2. ARCHIVE (rename — never delete).
    let archived = null
    if (raw != null) {
      if (typeof transport.canArchive !== 'function' || !transport.canArchive(t.config)) {
        return { ok: false, stage: 'archive', error: 'This connection type cannot archive the old copy — Edit setup to reconnect (the bridge cannot preserve it)', cause: 'bridge-cannot-archive' }
      }
      const archiveName = reseedArchiveName()
      try {
        archived = await transport.archiveUpload(raw, t.config, archiveName)
      } catch (e) {
        // R174 — the writer-depth materializer (the same law)
        return { ok: false, stage: 'archive', error: materializeUserText(e, { cap: 300 }) }
      }
    }
    // 3. PUSH the fresh envelope. A stale WebDAV ETag would 412 the fresh
    // write against the file the archive leg never touched — drop it first
    // (the next read re-learns the primary's current ETag).
    if (t.id === 'webdav') {
      try { await chrome.storage.local.remove('ucrypt:webdav:etag') } catch { /* best effort */ }
    }
    const push = await pushToTransport()
    if (!push || !push.pushed) {
      return { ok: false, stage: 'push', error: (push && (push.error || push.reason)) || 'The fresh upload did not confirm', archivedName: archived }
    }
    // 4. READ-BACK — one readable read unblocks the chain (the standing law:
    // the attention state clears the moment a read succeeds).
    const read = await _pullCore({})
    // The visible moment (the persisted ledger) — the reseed is a sync event.
    recordSyncMoment({ lane: 'cloud', added: 0, updated: 0, by: '', reseed: true })
    return { ok: true, archivedName: archived, push, read: { ok: !!read.remoteObserved, reason: read.reason || null } }
  })
}

/**
 * R98 (S8.6) — THE BEAM ENVELOPE. The sealed vault envelope is "the exact
 * bytes the cloud would carry, unchanged" — built by the SAME encryptForSync
 * path the transport push uses (the syncable snapshot, fresh IV, the sync
 * key). The descriptor is non-secret (name/size/digest); the BYTES go to the
 * beam transfer plane only on demand (16 KiB slices — the worker keeps the
 * envelope in memory for the lifetime of one beam transfer, wiped on
 * terminal/lock like every other plane state).
 *
 * Credentials never ride the beam — the envelope carries no transport
 * secrets, and the beam's cloud hint is provider + URL only (payload law).
 */
export async function beamEnvelope() {
  if (!isUnlocked || !credentialKey) {
    return { ok: false, locked: true, reason: 'Vault is locked — unlock to arm the beam' }
  }
  if (!syncKey) return { ok: false, reason: 'No sync code set up' }
  if (!hasVaultContent()) return { ok: false, empty: true, reason: 'The vault is empty — a fresh chain needs nothing transferred' }
  // The EXACT cloud bytes: the same construction lib/sync.js encryptForSync
  // performs (the syncable snapshot, one AES-GCM seal under the sync key).
  // R111 §3.1: the DIRECT lane is named on the wire — the self roster row's
  // "last sync" line says which lane carried this envelope (direct here).
  const blob = await encryptString(JSON.stringify(await snapshotForWire(vaultData, { lane: 'direct' })), syncKey)
  const envelopeBytes = base64ToBytes(blob)
  const digestBytes = new Uint8Array(await sha256(envelopeBytes))
  const sha256hex = Array.from(digestBytes).map(b => b.toString(16).padStart(2, '0')).join('')
  // R100 FIX (the live matrix caught it — the F-R98-BEAM bug class again):
  // `size` is the DECODED BYTE count (the chunk pump slices bytes), never
  // the base64 STRING length — a size/bytes disagreement refuses every
  // chunk at the sender's own seal gate (size_mismatch) and the direct leg
  // dies before its first frame.
  return { ok: true, name: 'ucrypt-vault.enc', bytesB64: blob, size: envelopeBytes.length, sha256hex }
}

/**
 * R111 §3.2 — the entry-level diff for the visible moment: how many entries
 * the adoption ADDED (new domain+username keys) and how many it UPDATED
 * (existing keys whose canonical form changed). Counts only — never values
 * (the ledger line carries numbers and a label, nothing else).
 */
function diffVaultEntries(beforeEntries, afterEntries) {
  const keyOf = (e) => `${e?.domain || ''}\u0000${e?.username || ''}`
  const before = new Map()
  for (const e of (beforeEntries || [])) before.set(keyOf(e), canonicalVaultJson(e))
  let added = 0
  let updated = 0
  for (const e of (afterEntries || [])) {
    const k = keyOf(e)
    if (!before.has(k)) added++
    else if (before.get(k) !== canonicalVaultJson(e)) updated++
  }
  return { added, updated }
}

/**
 * R98 (S8.6) — THE BEAM ADOPT (joiner side). The envelope arrived over the
 * direct channel with its SHA-256 verified by the transfer plane (and
 * re-verified here against the offer's digest before anything is decrypted).
 * Adoption is the RESTORE-SAFE pull-first path: first-run is the empty-vault
 * case (adopt as-is); otherwise the entry-level merge (per-entry LWW +
 * tombstones) — the same semantics as the cloud pull, so a beam and a cloud
 * pull can never disagree.
 */
export async function adoptBeamEnvelope(blobB64, expectedSha256hex) {
  if (!isUnlocked) return { ok: false, locked: true, reason: 'Vault is locked — unlock to receive the beam' }
  if (!syncKey) return { ok: false, reason: 'Sync code not set up — the words must be set first' }
  const raw = base64ToBytes(String(blobB64 || ''))
  if (expectedSha256hex) {
    const digestBytes = new Uint8Array(await sha256(raw))
    const got = Array.from(digestBytes).map(b => b.toString(16).padStart(2, '0')).join('')
    if (got !== String(expectedSha256hex).toLowerCase()) {
      return { ok: false, reason: 'SHA-256 mismatch — the beam did not land intact; nothing was adopted' }
    }
  }
  // looksLikeVaultEnvelope takes the BASE64 STRING (the same shape every
  // transport download returns) — the envelope pre-check is structural only.
  if (!looksLikeVaultEnvelope(String(blobB64 || ''))) {
    return { ok: false, reason: 'The received beam payload is not a vault envelope — nothing was adopted' }
  }
  let remote = null
  try {
    remote = fromSyncSnapshot(await (async () => { const __raw = JSON.parse(await decryptString(String(blobB64 || ''), syncKey)); await deliverChainDevices(__raw); await deliverChainState(__raw); return __raw })())
  } catch {
    return { ok: false, reason: 'The beam payload failed to decrypt with this sync code — nothing was adopted' }
  }
  if (!remote || typeof remote !== 'object') {
    return { ok: false, reason: 'The beam payload is not a readable vault — nothing was adopted' }
  }
  const hadLocalVault = !!(vaultData?.entries && vaultData.entries.length) ||
                        !!(vaultData?.tombstones && vaultData.tombstones.length)
  if (!hadLocalVault) {
    // First device / empty vault — adopt as-is (the restore-safe first run).
    const migAdopt = migrateLegacyAttachedTotp(remote)
    if (migAdopt.scanned > 0) {
      console.log(`[UCrypt] TOTP canonical migration (beam adopt): ${migAdopt.secretsRemoved} converted`)
    }
    vaultData = remote
    await saveVault({ skipTransport: true })
    // R132 (law 0.46 — the join propagation): the beam landing is a JOIN —
    // this device's entry rides the very next envelope (the origin's pull
    // learns it; the "Already in sync" gate must never swallow the stamp).
    await markRosterDirty()
    return { ok: true, adopted: 'as-is', entryCount: (remote.entries || []).length, added: (remote.entries || []).length, updated: 0 }
  }
  const beforeEntries = vaultData.entries
  const merged = mergeVaults(vaultData, remote)
  const migMerged = migrateLegacyAttachedTotp(merged)
  if (migMerged.scanned > 0) {
    console.log(`[UCrypt] TOTP canonical migration (beam merge): ${migMerged.secretsRemoved} converted`)
  }
  const localCanonical = canonicalVaultJson(vaultData)
  const mergedCanonical = canonicalVaultJson(merged)
  if (mergedCanonical === localCanonical) {
    return { ok: true, adopted: 'current', entryCount: (vaultData.entries || []).length, added: 0, updated: 0 }
  }
  const beforeCount = (vaultData.entries || []).length
  const __diff = diffVaultEntries(beforeEntries, merged.entries)
  vaultData = merged
  vaultData.lastModified = Date.now()
  await saveVault({ skipTransport: true })
  // R132 (law 0.46 — the join propagation): the beam landing is a JOIN —
  // this device's entry rides the very next envelope (both adopt terminals).
  await markRosterDirty()
  return { ok: true, adopted: 'merged', entryCount: (vaultData.entries || []).length, beforeCount, added: __diff.added, updated: __diff.updated }
}

// ---------------------------------------------------------------------------
// R175 — THE ONE CYCLE, ONE TRUTH (R-175.1) + THE QUIET LEDGER (R-175.7).
// The field (E-31/E-32/E-34) proved one sync cycle emitting "✓ Already in
// sync" AND, one second later, "✗ The error message could not be read" —
// two rows, two verdicts, one cycle. The law: a sync cycle emits EXACTLY ONE
// result row, and that row names EVERY lane's verdict (pull: ok / typed-fail;
// merge: ok + words; push: ok / typed-fail / skipped-with-reason). The
// ✓-then-✗ pair within one cycle is BANNED as a shape. The row lives in
// ucrypt:lastCycle; the banner, the Cloud backup card, and the checklist all
// read THE SAME row (the map's one-truth wiring diagram).
//
// THE QUIET LEDGER (R-175.7): identical consecutive cycles — same verdict,
// same lane words, same build, same source — COALESCE into one row with a
// ×N counter and the latest timestamp, so an owner pressing Sync now a huge
// number of times reads one truth, not noise. The auto-sync tick (every 15
// min, and at every unlock) obeys the same law: no silent failures, no
// duplicate walls.
// ---------------------------------------------------------------------------

const LAST_CYCLE_KEY = 'ucrypt:lastCycle'

/** Materialize one lane's words through the honest materializer (the row is
 * self-sufficient — surfaces never re-materialize). */
function _cycleWords(v) {
  return materializeUserText(v, { cap: 240 }) || ''
}

/** Build the typed cycle row from the pull and push outcomes (PURE — plain
 * storage-safe shapes only). Lanes absent from the cycle are omitted (never
 * a silent lane, never a lying lane). */
export function buildCycleRow({ pull = null, push = null, source = 'cycle' } = {}) {
  const at = Date.now()
  const lanes = []
  // The PULL lane: ok when the remote was positively observed (a copy read OR
  // its absence confirmed — the R-174.2 virgin truth); null when the pull did
  // not run (locked / no sync code / not consulted — a waiting lane, never a
  // failure); false when a real consult failed (the typed words ride).
  if (pull) {
    const locked = pull.locked === true
    const notConsulted = pull.syncSkipped === true || pull.remoteObserved === false || locked
    const virginRead = pull.emptyRemote === true && pull.remoteObserved === true
    const pullOk = locked ? null : (pull.remoteObserved === true ? true : (pull.remoteObserved === false ? false : null))
    // R178 — R-178.3 THE PULL ROW CARRIES THE REMOTE EVIDENCE: when the
    // transport leg offered its read facts, the words NAME WHAT was read
    // (file id + byte count + modified time — metadata only, never a
    // secret). Without evidence the words honestly name the era (never a
    // bare claim the transport leg cannot back — the D5 false-negative
    // class dies at the words' own writer).
    const ev = pull && pull.transportEvidence && typeof pull.transportEvidence === 'object' ? pull.transportEvidence : null
    const evWords = (ev && ev.fileId)
      ? ` (file ${String(ev.fileId).slice(0, 12)} · ${Number(ev.bytes) || 0} B${ev.modifiedTime ? ' · modified ' + String(ev.modifiedTime).slice(0, 24) : ''})`
      : ''
    const pullWords = pullOk === false
      ? (pull.transportError || pull.reason || '')
      : virginRead
        ? 'cloud empty — nothing to pull (the remote was positively read as absent)'
        : pullOk === true
          ? (evWords ? 'the cloud copy was read' + evWords : 'a copy was read (the transport leg gave no read evidence)')
          : (locked ? 'the vault is locked — the pull waits for the unlock' : '')
    lanes.push({ lane: 'pull', ok: pullOk, words: _cycleWords(pullWords) })
    // The MERGE lane: its verdict IS the pull's own reason when the read
    // landed (merge ran against the remote's copy); omitted when no read ran.
    if (!notConsulted) {
      lanes.push({ lane: 'merge', ok: true, words: _cycleWords(pull.reason || 'merge complete') })
    }
    void notConsulted
  }
  // The PUSH lane: ok (pushed, + the confirmation words), skipped-with-reason
  // (ok:null — the joiner's waiting row, never a red failure), or typed-fail.
  if (push) {
    if (push.skipped) lanes.push({ lane: 'push', ok: null, skipped: true, skipClass: String(push.skipClass || ''), words: _cycleWords(push.reason || push.error || 'the push waits') })
    else if (push.ok === false) lanes.push({ lane: 'push', ok: false, words: _cycleWords(push.error || push.reason || '') })
    else lanes.push({
      lane: 'push',
      ok: true,
      words: _cycleWords(push.confirmed === false && push.confirmError ? `pushed — ${push.confirmError}` : (push.reason || 'pushed')),
    })
  }
  const anyFail = lanes.some((l) => l.ok === false)
  const allIdle = lanes.length > 0 && lanes.every((l) => l.ok === null)
  const verdict = anyFail ? 'failed' : (allIdle ? 'idle' : 'ok')
  return { at, build: ledgerBuildStamp(), source: String(source || 'cycle'), verdict, lanes }
}

/** The coalescing writer (R-175.7) — NEVER THROWS. Identical consecutive
 * cycles (verdict + lane ok/words byte-equal + build + source) become ONE
 * row with a ×N counter and the latest timestamp. */
export async function recordCycleOutcome(row) {
  try {
    if (!row || !Array.isArray(row.lanes)) return
    const { [LAST_CYCLE_KEY]: prev } = await chrome.storage.local.get(LAST_CYCLE_KEY)
    const sig = (r) => JSON.stringify([r.source, r.verdict, r.build, (r.lanes || []).map((l) => [l.lane, l.ok, l.words, !!l.skipped])])
    let times = 1
    let firstAt = row.at
    if (prev && prev.firstAt && sig(prev) === sig(row)) {
      times = Math.min(9999, (Number(prev.times) || 1) + 1)
      firstAt = Number(prev.firstAt) || prev.at
    }
    await chrome.storage.local.set({ [LAST_CYCLE_KEY]: { ...row, times, firstAt } })
  } catch { /* the cycle ledger is best-effort — sync never blocks on it */ }
}

/** Read the newest cycle row (the surfaces' one projection). */
export async function getLastCycle() {
  try {
    const { [LAST_CYCLE_KEY]: c } = await chrome.storage.local.get(LAST_CYCLE_KEY)
    return c || null
  } catch { return null }
}

/**
 * v2.16.0 — single-flight Sync-now: ONE lock holds the whole pull+push cycle.
 * If the pull already pushed (merge convergence), the push is NOT repeated
 * (audit finding F2). Otherwise the user's explicit expectation stands —
 * Sync-now pushes the current vault — as long as there is REAL content to
 * push (the empty-vault guard; audit finding F4).
 * R175 — the cycle lands as ONE row (R-175.1): the pull's verdict, the
 * merge's verdict, and the push's verdict all ride `ucrypt:lastCycle` — the
 * ✓-then-✗ pair within one cycle is unrepresentable from this writer on.
 */
export async function syncNow(opts = {}) {
  return withSyncLock(async () => {
    const pull = await recordPullLedger(await _pullCore(opts))
    if (pull && pull.conflictDetected) {
      const cycleSource = (opts && typeof opts.source === 'string' && opts.source) ? opts.source : 'sync-now'
      await recordCycleOutcome(buildCycleRow({ pull, push: null, source: cycleSource }))
      return { ...pull, connectionSyncKind: 'hash-mismatch-conflict' }
    }
    let push = null
    const canPushEmptyVirginOrZero = !!(
      pull &&
      pull.remoteObserved === true &&
      (pull.emptyRemote === true || pull.transportState === 'absent' || (pull.transportState === 'readable' && Number(pull.remoteEntryCount) === 0))
    )
    if (pull && pull.pushed) {
      push = pull.push || { ok: true, pushed: true, reason: 'Merged changes from sync — pushed result' }
    } else if (pull && pull.remoteObserved !== false && vaultData && syncKey && (hasVaultContent() || canPushEmptyVirginOrZero)) {
      if (canPushEmptyVirginOrZero) {
        try { await markMemberSynced('virgin-remote-seed') } catch { /* best-effort */ }
      }
      push = await pushToTransport()
    }
    const cycleSource = (opts && typeof opts.source === 'string' && opts.source) ? opts.source : 'sync-now'
    await recordCycleOutcome(buildCycleRow({ pull, push: push || null, source: cycleSource }))
    const syncKind = (pull && pull.connectionSyncKind)
      ? pull.connectionSyncKind
      : (pull && pull.emptyRemote && push && push.ok)
        ? 'initial-upload'
        : 'recurrent-in-sync'
    // UCRYPT-19 — When a full sync cycle succeeds cleanly (remote observed and
    // any push succeeded), automatically clear any pending exponential backoff retry!
    if (pull && pull.remoteObserved === true && (!push || push.ok !== false)) {
      await clearAutoSyncRetryState(cycleSource).catch(() => {})
    }
    if (pull && pull.pushed) return { ...pull, connectionSyncKind: syncKind }
    // v2.17.0 — R26-F1: NEVER push over an unobserved remote. If the pull
    // could not positively read (or positively rule out) the cloud copy, the
    // local snapshot stays local until the transport answers again.
    if (pull && pull.remoteObserved === false) return pull
    if (push) return { ...pull, push, pushed: !!push.ok, connectionSyncKind: syncKind }
    return { ...pull, connectionSyncKind: syncKind }
  })
}

/** Sync status for UI. v2.8.0: logins-only count + last cloud-push outcome. */
export async function getSyncStatus() {
  const { [TRANSPORT_KEY]: t } = await chrome.storage.local.get(TRANSPORT_KEY)
  const { [LAST_PUSH_KEY]: lastPush } = await chrome.storage.local.get(LAST_PUSH_KEY)
  const { [LAST_HOP_KEY]: hop } = await chrome.storage.local.get(LAST_HOP_KEY)
  const { [LAST_PULL_KEY]: lastPull } = await chrome.storage.local.get(LAST_PULL_KEY)
  const { [VAULT_CONFLICT_KEY]: conflictRec } = await chrome.storage.local.get(VAULT_CONFLICT_KEY)
  const loginCount = (vaultData?.entries || []).filter(isLoginEntry).length
  // LAW 0.48 (R133) — the typed member lifecycle rides the sync status (the
  // UI's direction-of-truth: the joiner's primary action is Pull now), and
  // LAW 0.49's auto-sync cadence + next-cycle bookkeeping ride beside it.
  const lifecycle = await getMemberLifecycle()
  const autoMinutes = await getAutoSyncMinutes()
  const retryState = await getAutoSyncRetryState()
  return {
    syncEnabled: !!syncKey,
    lifecycle,
    autoSync: {
      minutes: autoMinutes,
      lastAutoAt: retryState.lastAutoAt,
      nextAt: retryState.nextAt,
      failures: retryState.failures,
      retrying: retryState.retrying,
      inFlight: retryState.inFlight,
      exhausted: retryState.exhausted,
      attempt: retryState.attempt,
      maxAttempts: retryState.maxAttempts,
      backoffMs: retryState.backoffMs,
      backoffSeconds: retryState.backoffSeconds,
      nextRetryAt: retryState.nextRetryAt,
      lastError: retryState.lastError,
      lastErrorKind: retryState.lastErrorKind,
      lastErrorStatus: retryState.lastErrorStatus,
      lastFailedAt: retryState.lastFailedAt,
      lastSuccessAt: retryState.lastSuccessAt,
      source: retryState.source,
      stage: retryState.stage,
      scheduleSeconds: retryState.scheduleSeconds,
    },
    transport: t ? { id: t.id, hasConfig: !!t.config } : null,
    lastModified: vaultData?.lastModified || 0,
    entryCount: loginCount,
    totalCount: (vaultData?.entries || []).length,
    vaultConflict: conflictRec
      ? {
          status: conflictRec.status || 'clean',
          active: !!(conflictRec.hasHashMismatch && (conflictRec.paused || conflictRec.requiresManualResolution || conflictRec.status === 'pending' || conflictRec.status === 'pending-review')),
          hasHashMismatch: !!conflictRec.hasHashMismatch,
          requiresManualResolution: !!conflictRec.requiresManualResolution,
          detectedAt: conflictRec.detectedAt || 0,
          localHash: conflictRec.localHash || '',
          remoteHash: conflictRec.remoteHash || '',
          mergedHash: conflictRec.mergedHash || '',
          conflictCount: Number(conflictRec.conflictCount) || 0,
          localOnlyCount: Number(conflictRec.localOnlyCount) || 0,
          cloudOnlyCount: Number(conflictRec.cloudOnlyCount) || 0,
          resolvedAt: conflictRec.resolvedAt || null,
          resolvedChoice: conflictRec.resolvedChoice || null,
        }
      : null,
    lastPush: lastPush
      ? {
          ok: !!lastPush.ok,
          at: lastPush.at || 0,
          transportId: lastPush.transportId || null,
          error: lastPush.error || lastPush.reason || null,
          kind: (typeof lastPush.kind === 'string' && lastPush.kind) || null,
          status: Number.isFinite(Number(lastPush.status)) ? Number(lastPush.status) : null,
          lastModified: lastPush.lastModified || 0,
          build: (typeof lastPush.build === 'string' && lastPush.build) || null,
          bytes: typeof lastPush.bytes === 'number' ? lastPush.bytes : null,
          durationMs: typeof lastPush.durationMs === 'number' ? lastPush.durationMs : null,
          skipped: !!lastPush.skipped,
          skipClass: (typeof lastPush.skipClass === 'string' && lastPush.skipClass) || null,
          guardClass: (typeof lastPush.guardClass === 'string' && lastPush.guardClass) || null,
          guardQuestion: (typeof lastPush.guardQuestion === 'string' && lastPush.guardQuestion) || null,
          confirmed: typeof lastPush.confirmed === 'boolean' ? lastPush.confirmed : null,
          confirmedAt: typeof lastPush.confirmedAt === 'number' ? lastPush.confirmedAt : null,
          confirmError: (typeof lastPush.confirmError === 'string' && lastPush.confirmError) || null,
        }
      : null,
    backupProof: await getBackupProof(),
    syncHop: hop
      ? {
          ok: !!hop.ok,
          at: hop.at || 0,
          chunks: typeof hop.chunks === 'number' ? hop.chunks : null,
          bytes: typeof hop.bytes === 'number' ? hop.bytes : null,
          error: hop.error || null,
        }
      : null,
    lastPull: lastPull
      ? {
          attempted: !!lastPull.attempted,
          ok: !!lastPull.ok,
          at: lastPull.at || 0,
          remoteObserved: !!lastPull.remoteObserved,
          error: lastPull.error || null,
          kind: (typeof lastPull.kind === 'string' && lastPull.kind) || null,
          status: Number.isFinite(Number(lastPull.status)) ? Number(lastPull.status) : null,
          recoveryKind: (typeof lastPull.recoveryKind === 'string' && lastPull.recoveryKind) || null,
          build: (typeof lastPull.build === 'string' && lastPull.build) || null,
          transportMode: (typeof lastPull.transportMode === 'string' && lastPull.transportMode) || null,
          transportState: (typeof lastPull.transportState === 'string' && lastPull.transportState) || null,
          garbage: Number.isFinite(Number(lastPull.garbage)) ? Number(lastPull.garbage) : null,
          transportId: lastPull.transportId || null,
        }
      : null,
  }
}

/** LAW 0.49 (R133) — the auto-sync cadence is USER-CONFIGURABLE (default 15
 * minutes, clamped 1–120). Persisted in ucrypt:settings.autoSyncMinutes; the
 * background's interval alarm re-derives from here on every boot/tick. */
export async function getAutoSyncMinutes() {
  const s = await getSettings()
  const m = Number(s && s.autoSyncMinutes)
  return Number.isFinite(m) && m >= 1 ? Math.min(120, Math.round(m)) : 15
}

export async function setAutoSyncMinutes(minutes) {
  const m = Number(minutes)
  if (!Number.isFinite(m) || m < 1) throw new Error('Invalid auto-sync interval')
  const clamped = Math.min(120, Math.round(m))
  const s = await getSettings()
  await saveSettings({ ...s, autoSyncMinutes: clamped })
  try { await chrome.alarms.create('ucrypt:sync-pull', { periodInMinutes: clamped }) } catch { /* the tick re-derives */ }
  return clamped
}

// ---------------------------------------------------------------------------
// SETTINGS
// ---------------------------------------------------------------------------

export async function getSettings() {
  const { [SETTINGS_KEY]: s } = await chrome.storage.local.get(SETTINGS_KEY)
  return s || {}
}

export async function saveSettings(settings) {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings })
}

export async function setAutoLockMinutes(minutes) {
  const min = Number(minutes)
  if (!Number.isFinite(min)) throw new Error('Invalid auto-lock interval')
  const clamped = min <= 0 ? 0 : Math.min(1440, Math.max(1, Math.round(min)))
  lockTimeoutMs = clamped * 60 * 1000
  const s = await getSettings()
  await saveSettings({ ...s, autolockMinutes: clamped })
  return clamped
}

// Backwards-compat shim: the old WebDAV URL option is superseded by transports
export async function setWebDAVUrl(url) {
  // R123 §2.2 — setAt rides every transport write (the staleness law).
  if (url) await chrome.storage.local.set({ [TRANSPORT_KEY]: { id: 'webdav', config: { url }, setAt: Date.now() } })
  else await chrome.storage.local.remove(TRANSPORT_KEY)
}

// ---------------------------------------------------------------------------
// UCRYPT-16 / UCRYPT-21 — VAULT HASH-MISMATCH & MERGE CONFLICT RESOLVER
// ---------------------------------------------------------------------------

export const VAULT_CONFLICT_KEY = 'ucrypt:vaultConflict'

// In-memory snapshot cache while the service worker is unlocked so the user
// can manually choose Local, Cloud, or Smart Merge in Sync Settings.
let _pendingConflictSnapshots = null

export function _setPendingConflictSnapshotsForTest(snapshots) {
  _pendingConflictSnapshots = snapshots
}

export async function getVaultConflictPolicy() {
  try {
    const s = await getSettings()
    return s && s.vaultConflictPolicy === 'manual' ? 'manual' : 'auto-with-review'
  } catch {
    return 'auto-with-review'
  }
}

export async function setVaultConflictPolicy(policy) {
  const normalized = policy === 'manual' ? 'manual' : 'auto-with-review'
  const s = await getSettings()
  await saveSettings({ ...s, vaultConflictPolicy: normalized })
  return normalized
}

async function sealConflictSnapshot(snapshotObj) {
  if (!masterKey || !snapshotObj) return null
  try {
    const pt = new TextEncoder().encode(JSON.stringify(snapshotObj))
    const { ciphertext, iv } = await encrypt(masterKey, pt)
    return { ct: toBase64(ciphertext), iv: toBase64(iv) }
  } catch {
    return null
  }
}

async function unsealConflictSnapshot(sealed) {
  if (!masterKey || !sealed || typeof sealed.ct !== 'string' || typeof sealed.iv !== 'string') return null
  try {
    const pt = await decrypt(masterKey, fromBase64(sealed.ct), fromBase64(sealed.iv))
    return JSON.parse(new TextDecoder().decode(pt))
  } catch {
    return null
  }
}

/**
 * Record the SHA-256 hash comparison and conflict metadata observed during
 * `_pullCore` so the Sync Settings 'Conflict Resolver' UI can display both
 * versions and let the user manually choose Local, Cloud, or Smart Merge.
 */
export async function recordVaultConflictFromMerge({
  localVault,
  remoteVault,
  mergedVault,
  report,
  paused = false,
  transportId = null,
}) {
  try {
    if (!report) return null
    const now = Date.now()
    if (report.hasHashMismatch) {
      _pendingConflictSnapshots = {
        localVault: JSON.parse(JSON.stringify(localVault || { entries: [], tombstones: [], lastModified: 0 })),
        remoteVault: JSON.parse(JSON.stringify(remoteVault || { entries: [], tombstones: [], lastModified: 0 })),
        mergedVault: JSON.parse(JSON.stringify(mergedVault || report.mergedVault || { entries: [], tombstones: [], lastModified: 0 })),
        report,
        at: now,
      }
      const [sealedLocal, sealedRemote, sealedMerged] = await Promise.all([
        sealConflictSnapshot(_pendingConflictSnapshots.localVault),
        sealConflictSnapshot(_pendingConflictSnapshots.remoteVault),
        sealConflictSnapshot(_pendingConflictSnapshots.mergedVault),
      ])
      const diffEntries = Array.isArray(report.diffEntries) ? report.diffEntries : []
      const conflicts = diffEntries.filter(d => d.kind === 'content-mismatch' || d.kind === 'delete-vs-edit')
      const status = paused
        ? 'pending'
        : (report.requiresManualResolution ? 'pending-review' : 'mismatch-merged')
      const active = !!(paused || report.requiresManualResolution || status === 'pending' || status === 'pending-review')
      const record = {
        status,
        active,
        canResolve: true,
        paused: !!paused,
        hasHashMismatch: true,
        hashMismatch: true,
        hasConflict: !!(report.hasDirectCollision || conflicts.length > 0),
        hasDirectCollision: !!report.hasDirectCollision,
        bothSidesDiverged: !!report.bothSidesDiverged,
        requiresManualResolution: !!report.requiresManualResolution,
        autoMerged: status === 'mismatch-merged',
        detectedAt: now,
        transportId: transportId || null,
        localHash: report.localHash,
        remoteHash: report.remoteHash,
        mergedHash: report.mergedHash,
        localBytes: report.localBytes,
        remoteBytes: report.remoteBytes,
        mergedBytes: report.mergedBytes,
        localEntryCount: report.localEntryCount,
        remoteEntryCount: report.remoteEntryCount,
        mergedEntryCount: report.mergedEntryCount,
        localTombstoneCount: report.localTombstoneCount,
        remoteTombstoneCount: report.remoteTombstoneCount,
        localLastModified: report.localLastModified,
        remoteLastModified: report.remoteLastModified,
        localUpdatedAt: report.localLastModified,
        remoteUpdatedAt: report.remoteLastModified,
        conflictCount: report.conflictCount,
        diffCount: diffEntries.length,
        localOnlyCount: report.localOnlyCount,
        cloudOnlyCount: report.cloudOnlyCount,
        diffEntries,
        diffs: diffEntries,
        conflicts,
        ...(sealedLocal ? { sealedLocal } : {}),
        ...(sealedRemote ? { sealedRemote } : {}),
        ...(sealedMerged ? { sealedMerged } : {}),
      }
      await chrome.storage.local.set({ [VAULT_CONFLICT_KEY]: record })
      return record
    }

    const { [VAULT_CONFLICT_KEY]: prev } = await chrome.storage.local.get(VAULT_CONFLICT_KEY)
    const cleanRecord = {
      status: 'clean',
      active: false,
      canResolve: false,
      paused: false,
      hasHashMismatch: false,
      hashMismatch: false,
      hasConflict: false,
      hasDirectCollision: false,
      bothSidesDiverged: false,
      requiresManualResolution: false,
      autoMerged: false,
      detectedAt: now,
      transportId: transportId || null,
      localHash: report.localHash,
      remoteHash: report.remoteHash,
      mergedHash: report.mergedHash,
      localBytes: report.localBytes,
      remoteBytes: report.remoteBytes,
      mergedBytes: report.mergedBytes,
      localEntryCount: report.localEntryCount,
      remoteEntryCount: report.remoteEntryCount,
      mergedEntryCount: report.mergedEntryCount,
      localTombstoneCount: report.localTombstoneCount,
      remoteTombstoneCount: report.remoteTombstoneCount,
      localLastModified: report.localLastModified,
      remoteLastModified: report.remoteLastModified,
      localUpdatedAt: report.localLastModified,
      remoteUpdatedAt: report.remoteLastModified,
      conflictCount: 0,
      diffCount: 0,
      localOnlyCount: 0,
      cloudOnlyCount: 0,
      diffEntries: [],
      diffs: [],
      conflicts: [],
      ...(prev && prev.resolvedAt ? {
        resolvedAt: prev.resolvedAt,
        resolvedChoice: prev.resolvedChoice,
        winningHash: prev.winningHash,
      } : {}),
    }
    await chrome.storage.local.set({ [VAULT_CONFLICT_KEY]: cleanRecord })
    return cleanRecord
  } catch {
    return null
  }
}

/**
 * Return the current Conflict Resolver status for Sync Settings (`options.js`).
 */
export async function getVaultConflictStatus() {
  const rawPolicy = await getVaultConflictPolicy()
  const policy = rawPolicy === 'manual' ? 'manual' : 'auto'
  const { [VAULT_CONFLICT_KEY]: stored } = await chrome.storage.local.get(VAULT_CONFLICT_KEY)
  const currentLocalHash = isUnlocked && vaultData ? await computeVaultHash(vaultData) : null
  const currentLocalCount = isUnlocked && vaultData && Array.isArray(vaultData.entries) ? vaultData.entries.length : 0
  const canResolveSnapshot = !!(
    _pendingConflictSnapshots ||
    (stored && (stored.sealedLocal || stored.sealedRemote))
  )
  const diffEntries = stored && Array.isArray(stored.diffEntries) ? stored.diffEntries : []
  const conflicts = stored && Array.isArray(stored.conflicts)
    ? stored.conflicts
    : diffEntries.filter(d => d.kind === 'content-mismatch' || d.kind === 'delete-vs-edit')
  const isActive = !!(
    stored &&
    stored.hasHashMismatch &&
    (stored.paused || stored.requiresManualResolution || stored.status === 'pending' || stored.status === 'pending-review')
  )
  return {
    ok: true,
    isUnlocked: !!isUnlocked,
    policy,
    rawPolicy,
    currentLocalHash,
    currentLocalCount,
    canResolveSnapshot,
    conflict: stored
      ? {
          status: stored.status || 'clean',
          active: isActive,
          canResolve: !!(canResolveSnapshot || isActive || stored.hasHashMismatch),
          paused: !!stored.paused,
          hasHashMismatch: !!stored.hasHashMismatch,
          hashMismatch: !!stored.hasHashMismatch,
          hasConflict: !!(stored.hasDirectCollision || Number(stored.conflictCount) > 0 || conflicts.length > 0),
          hasDirectCollision: !!stored.hasDirectCollision,
          bothSidesDiverged: !!stored.bothSidesDiverged,
          requiresManualResolution: !!stored.requiresManualResolution,
          autoMerged: stored.status === 'mismatch-merged',
          detectedAt: stored.detectedAt || 0,
          transportId: stored.transportId || null,
          localHash: stored.localHash || currentLocalHash || '',
          remoteHash: stored.remoteHash || '',
          mergedHash: stored.mergedHash || '',
          localBytes: Number(stored.localBytes) || 0,
          remoteBytes: Number(stored.remoteBytes) || 0,
          mergedBytes: Number(stored.mergedBytes) || 0,
          localEntryCount: Number(stored.localEntryCount) || 0,
          remoteEntryCount: Number(stored.remoteEntryCount) || 0,
          mergedEntryCount: Number(stored.mergedEntryCount) || 0,
          localTombstoneCount: Number(stored.localTombstoneCount) || 0,
          remoteTombstoneCount: Number(stored.remoteTombstoneCount) || 0,
          localLastModified: Number(stored.localLastModified) || 0,
          remoteLastModified: Number(stored.remoteLastModified) || 0,
          localUpdatedAt: Number(stored.localUpdatedAt || stored.localLastModified) || 0,
          remoteUpdatedAt: Number(stored.remoteUpdatedAt || stored.remoteLastModified) || 0,
          conflictCount: Number(stored.conflictCount) || 0,
          diffCount: diffEntries.length,
          localOnlyCount: Number(stored.localOnlyCount) || 0,
          cloudOnlyCount: Number(stored.cloudOnlyCount) || 0,
          diffEntries,
          diffs: diffEntries,
          conflicts,
          resolvedAt: stored.resolvedAt || null,
          resolvedChoice: stored.resolvedChoice || null,
          winningHash: stored.winningHash || null,
        }
      : null,
  }
}

/**
 * Live-check local vs. cloud vault hashes right now from the Conflict Resolver
 * UI. If a hash mismatch is found, pauses before overwriting so the user can
 * inspect the side-by-side comparison and manually choose Local, Cloud, or Merge.
 */
export async function checkVaultConflictNow() {
  if (!isUnlocked) {
    return { ok: false, locked: true, error: 'Unlock the vault first to compare local and cloud vault hashes' }
  }
  const pull = await withSyncLock(() => _pullCore({ pauseOnHashMismatch: true }))
  const status = await getVaultConflictStatus()
  const hasMismatch = !!(status.conflict && status.conflict.hasHashMismatch)
  return {
    ok: true,
    inSync: !hasMismatch,
    localHash: (status.conflict && status.conflict.localHash) || status.currentLocalHash || '',
    entryCount: status.currentLocalCount || 0,
    pull,
    ...status,
  }
}

/**
 * Manually resolve a detected vault hash mismatch by choosing:
 *   - `'local'` — Keep Local Vault Version and push it to Cloud
 *   - `'cloud'` — Adopt Cloud Vault Version and replace Local
 *   - `'merge'` — Smart Merge both versions (preserving conflict-copy passwords in entry history) and push
 */
export async function resolveVaultConflict(choice, opts = {}) {
  const normalizedChoice = choice === 'local' ? 'local' : (choice === 'cloud' ? 'cloud' : 'merge')
  if (!isUnlocked && !opts.allowLockedTest) {
    return { ok: false, locked: true, error: 'Unlock the vault first to resolve a vault conflict' }
  }
  return withSyncLock(async () => {
    const { [VAULT_CONFLICT_KEY]: stored } = await chrome.storage.local.get(VAULT_CONFLICT_KEY)
    let localSnap = _pendingConflictSnapshots && _pendingConflictSnapshots.localVault
    let remoteSnap = _pendingConflictSnapshots && _pendingConflictSnapshots.remoteVault
    let mergedSnap = _pendingConflictSnapshots && _pendingConflictSnapshots.mergedVault

    if (!localSnap && stored && stored.sealedLocal) {
      localSnap = await unsealConflictSnapshot(stored.sealedLocal)
    }
    if (!remoteSnap && stored && stored.sealedRemote) {
      remoteSnap = await unsealConflictSnapshot(stored.sealedRemote)
    }
    if (!mergedSnap && stored && stored.sealedMerged) {
      mergedSnap = await unsealConflictSnapshot(stored.sealedMerged)
    }

    if (!localSnap && vaultData) {
      localSnap = JSON.parse(JSON.stringify(vaultData))
    }
    if (!mergedSnap && localSnap && remoteSnap) {
      mergedSnap = mergeVaults(localSnap, remoteSnap)
    }

    let chosenVault = null
    if (normalizedChoice === 'local') {
      if (!localSnap) return { ok: false, error: 'No local vault snapshot available to restore' }
      chosenVault = JSON.parse(JSON.stringify(localSnap))
    } else if (normalizedChoice === 'cloud') {
      if (!remoteSnap) return { ok: false, error: 'No cloud vault snapshot available to adopt — run Check Hashes or Sync Now first' }
      chosenVault = JSON.parse(JSON.stringify(remoteSnap))
    } else {
      if (!mergedSnap && localSnap) mergedSnap = JSON.parse(JSON.stringify(localSnap))
      if (!mergedSnap) return { ok: false, error: 'No merged vault snapshot available' }
      chosenVault = JSON.parse(JSON.stringify(mergedSnap))
    }

    migrateLegacyAttachedTotp(chosenVault)
    chosenVault.lastModified = Math.max(Date.now(), Number(chosenVault.lastModified) || 0)
    vaultData = chosenVault
    pruneTombstones()

    const winningHash = await computeVaultHash(vaultData)
    if (isUnlocked && masterKey && !opts.skipPersist) {
      await saveVault({ skipTransport: true })
    }

    let push = null
    if (!opts.skipPush && syncKey) {
      try {
        push = await pushToTransport()
      } catch (e) {
        push = { ok: false, error: (e && e.message) || String(e) }
      }
    }

    const now = Date.now()
    const entryCount = Array.isArray(vaultData.entries) ? vaultData.entries.length : 0
    const resolvedRecord = {
      ...(stored && typeof stored === 'object' ? stored : {}),
      status: 'resolved',
      active: false,
      canResolve: false,
      paused: false,
      hasHashMismatch: false,
      hashMismatch: false,
      hasConflict: false,
      requiresManualResolution: false,
      autoMerged: false,
      localHash: winningHash,
      remoteHash: (push && push.ok) ? winningHash : ((stored && stored.remoteHash) || winningHash),
      mergedHash: winningHash,
      localEntryCount: entryCount,
      remoteEntryCount: (push && push.ok)
        ? entryCount
        : ((stored && Number(stored.remoteEntryCount)) || entryCount),
      mergedEntryCount: entryCount,
      conflictCount: 0,
      diffCount: 0,
      localOnlyCount: 0,
      cloudOnlyCount: 0,
      diffEntries: [],
      diffs: [],
      conflicts: [],
      resolvedAt: now,
      resolvedChoice: normalizedChoice,
      winningHash,
    }
    delete resolvedRecord.sealedLocal
    delete resolvedRecord.sealedRemote
    delete resolvedRecord.sealedMerged
    _pendingConflictSnapshots = null

    await chrome.storage.local.set({ [VAULT_CONFLICT_KEY]: resolvedRecord })
    return {
      ok: true,
      choice: normalizedChoice,
      hash: winningHash,
      winningHash,
      entryCount,
      pushed: !!(push && push.ok),
      push,
      conflict: resolvedRecord,
    }
  })
}


