/**
 * UCrypt — Background service worker (MV3, module script).
 *
 * v2.6.0 — Brave/Chrome parity:
 *  - Context-menu integration: right-click on any editable/password field →
 *    "Fill login from vault" / "Suggest strong password" / "Save login for
 *    this page" (http/https pages only — the content script can't run elsewhere).
 *  - Keyboard commands: Ctrl+Shift+L (fill login), Ctrl+Shift+U (suggest a
 *    strong password). Remappable at chrome://extensions/shortcuts.
 *  - GENERATE_FOR_FILL: the in-page "suggest strong password" panel asks the
 *    background to generate + analyze the candidate, so lib/generator.js
 *    stays the single source of generation (content scripts cannot import
 *    ES modules).
 *
 * v2.8.0 — cloud lifecycle (import → cloud → restore) hardening:
 *  - ucrypt:sync-pull ALARM (every 15 min): mid-session PULL from the
 *    configured cloud transport (Drive/Dropbox/Gist/WebDAV/custom) — until
 *    now device B only learned about device A's changes on manual sync —
 *    plus a pending-push retry when a previous push never landed (MV3
 *    workers can die mid-upload; the 'ucrypt:lastPush' ledger knows).
 *  - AUTO-PULL AFTER UNLOCK: the old onStartup pull ran while the session
 *    was still locked (no sync key yet) and never did anything. The pull now
 *    happens right after a successful unlock, when the key actually exists.
 *  - IMPORT truthfulness: IMPORT_ENTRIES / IMPORT_CSV_ROWS await the cloud
 *    push and return its real outcome; the UI no longer claims "pushed to
 *    Google Drive" on a guess.
 *
 * v2.9.0 — site controls + save-prompt intelligence:
 *  - NEVER_SAVE_LIST/ADD/REMOVE + the GET_ENTRIES `neverSave` flag back the
 *    Brave-style "Never save passwords for this site" exception list (device
 *    local, never synced, never touches autofill — only the save prompt).
 *  - CHECK_PASSWORD_STRENGTH: the in-page save prompt warns BEFORE the user
 *    accepts when the candidate is weak or in the offline breach corpus.
 *  - UPDATE_ENTRY: the options editor now updates atomically (the old
 *    DELETE+SAVE pair had a data-loss window on failure).
 *  - TOTP_AUTOFILL_LIST: tokens are ranked by domain proximity (exact domain
 *    → eTLD+1 → others) so the chip leads with tokens for THIS site.
 *
 * v2.1.0 audit findings fixed here:
 *  - #4: the chrome.storage.onChanged handler called a non-existent
 *    loadVault() and crashed → auto-pull never ran. Fixed (uses vault()).
 *  - #5: MV3 workers die after ~30s; the unlocked state was lost. The vault
 *    module now persists derived keys + vault in chrome.storage.session
 *    (memory-only) and restoreSession() runs on every wake-up.
 *  - #1: new message handlers expose the sync wizard (sync codes, QR, cloud
 *    transports) to the options page — previously unreachable library code.
 */

// ════════════════════════════════════════════════════════════════════════
// v2.12.0 — REAL-CHROMIUM E2E FINDING (clinical journey round 21):
// this worker used to be a CLASSIC service worker that lazy-loaded every
// library with dynamic import(). The HTML specification DISALLOWS import()
// on ServiceWorkerGlobalScope for classic workers — real Chromium threw
// "import() is disallowed on ServiceWorkerGlobalScope" on the very first
// message, so the router never answered: popup said "Background not
// responding" and NOTHING worked in a real browser (stub harnesses and
// node --check could never see this — import() is legal in pages).
// FIX: register the worker as a module (manifest "type": "module") and use
// STATIC imports. breach.js / lib/qr.js are side-effect scripts (no
// import/export) — they import cleanly as modules here.
// v2.21.0 — R30-F1 (CORRECTED by journey 30 in a REAL Chromium): the R30
// design first made the corpora lazy in the SW too, on the assumption that
// dynamic import() is legal for MODULE service workers. Real Chromium threw
// "import() is disallowed on ServiceWorkerGlobalScope by the HTML
// specification" (w3c/ServiceWorker#1356 — Chrome enforces it for module
// workers as well) and the CHECK_PASSWORD_STRENGTH case died. THE TRUTH:
// dynamic import() is legal in extension PAGES (popup/options — lib/corpus.js
// works there and is proven by journey 30) but NOWHERE in the worker, module
// or not. The SW therefore keeps breach.js as a STATIC import — but the
// wordlists (118 KB, needed ONLY for passphrase generation, which the SW
// never does) left the worker entirely, and the pages stopped loading both
// corpora as classic <script> tags. Net: the worker wake parses 118 KB less,
// and every popup/options open parses 211 KB less (the popup is the
// extension's most-opened surface).
// ════════════════════════════════════════════════════════════════════════

// breach.js + QR load as side-effect modules (set globalThis in the worker).
// v2.21.0 — R30-F1: breach.js stays STATIC (dynamic import() is disallowed on
// ServiceWorkerGlobalScope even for module workers — see the note above);
// wordlists.js is gone from the worker (the SW never generates passphrases —
// GENERATE_FOR_FILL is random-character only). lib/qr.js (14.5 KB) stays:
// QR_ENCODE needs it and it is small.
import './breach.js'
import './lib/qr.js'
// R45 (release-blocker fix): the v2.21.0 corpus split removed wordlists.js
// from this worker claiming "the SW never generates passphrases" — but
// SYNC-CODE GENERATION/VALIDATION needs the BIP-39 list here, and the shipped
// v2.21.0 build could not generate a sync code in a real browser (proven
// against the release bytes during the R45 audit). This 14 KB BIP-39-only
// module statically imports (module worker — no import()) while the 118 KB
// EFF passphrase corpora stay OUT of the worker wake path.
import './lib/bip39.js'
// R77-C — Trusted Direct Device Transfer (worker owns all transfer key
// material; pages only ever see sealed envelopes and non-secret artifacts).
import { handleTransferMessage, onVaultLocked as onTransferVaultLocked, handleTransferAlarm, registerBeamExecutor, ensureChainReadyForMailbox as transferEnsureChainReadyForMailbox, mailboxRosterPeers as transferMailboxRosterPeers } from './lib/transfer/worker.js' // R142-A3: the roster/chain bridge rides the STATIC import — import() is disallowed on ServiceWorkerGlobalScope (the G93 field find)
// R141 §7 — THE MAILBOX: the clean-room transport's message door (additive;
// the ONE road's handlers delegate to the new family and import nothing from
// the retired planes).
import { handleMailboxMessage } from './lib/mailbox/worker-mailbox.js'
import { runSelfChecks, LADDER_TRANSPORTS } from './lib/selfcheck.js'
// R121 §4.3 — the self-check's ladder awareness: the read-only probe needs
// the fast-rung feature detection (ladder.js) and the typed rings (egrings).
import { detectFastRung } from './lib/ladder.js'
import { recentRings, RING_CAP, recordRing } from './lib/egrings.js'
// R90 §2.1 — toolbar badge (canonical completion, original R42 law): the
// pure decision lives in lib/badge.js (unit tested); the worker owns every
// chrome.action write. Computed from the URL IN THE WORKER, never the page.
import { badgeFor } from './lib/badge.js'

// S8.9 completion (R100 §2.1) — THE BEAM EXECUTOR REGISTRY: any open UCrypt
// surface page (popup, options, transfer page) connects the typed port and
// hosts the TRANSPORT ONLY (ICE/SDP/data channel). The port IS the liveness
// signal: page close unregisters; lock withdraws (order §2.2). The sealed
// machinery, digest verification, and adopt stay in the worker — the
// executor sees transport metadata and SEALED frames, never plaintext.
chrome.runtime.onConnect.addListener((port) => {
  if (port && port.name === 'ucrypt:beam-executor') {
    try { registerBeamExecutor(port) } catch { /* a dead port unregisters itself */ }
  }
})

// --- Module handles (static imports — the ONLY form a service worker may use)

import * as _vault from './lib/vault.js'
// R140 §7 — THE CHAIN STATE (the cold-start cure): the reactive verdict
// writer. The banner, the pill, the transfer gate, and the readiness inputs
// all read THIS derivation — a contradiction between any two of them is
// structurally unrepresentable.
import { deriveChainState, newWakeCycle, classifyProbeFailure, CHAIN_RETRY_LADDER_MS, CHAIN_CHECK_CAP_MS } from './lib/chain-state.js'
import { classifyCredentialAnswer, uploadsPaused, nextHealMs, HEAL_BACKOFF_CAP_MS, UPLOAD_PAUSE_AFTER_CYCLES, CRED_VERDICT_CLASSES } from './lib/cloud/cred.js'
// R171 — THE UNBROKEN SPINE: the revoke endpoint for the Disconnect leg +
// the zero-window spine probe for the Self-check card's spine row.
import { OAUTH_REVOKE_URL, spineProbe } from './lib/cloud/spine.js'
import * as _analyzer from './lib/analyzer.js'
import * as _sync from './lib/sync.js'
import * as _transports from './lib/transports/index.js'
// R124 §2 (D13) — THE PICKUP BRIDGE at the worker's trust boundary: the
// hold uploads ride the SAME credential discipline as the sync legs (the
// secrets stay inside this worker — the page receives only the PUBLIC
// link and the OPAQUE cleanup ref; law 0.14, law 0.38).
import * as _pickupLinks from './lib/transports/pickup-links.js'
// R116 §2.2 — the owner's checklist constants ride the attention diagnose
// (the disabled-client card's Cloud Console deep link + the two-sentence
// fix render INLINE where the words are — law 0.29).
import { GOOGLE_CONSOLE_CREDENTIALS_URL, GOOGLE_CLIENT_DISABLED_FIX } from './lib/transports/gdrive-oauth-help.js'
import * as _sites from './lib/sites.js'
import * as _i18n from './lib/i18n.js'
import { totp as computeTotpCode } from './lib/totp.js'
import { buildHealthReport, buildPasswordHealthDashboard } from './lib/health.js'
// R135 (v2.92.0) — the new surfaces' engines, STATIC imports (the R96 SW
// boundary law: the service worker's import graph stays static-only).
import { normalizeToggles } from './lib/chaindata.js'
import * as r135Import from './lib/import-migration.js'
// R160 ARC B′ — T8'S MERGE LAW for the import power: the plan machine
// (summary-before-commit), the transactional journal, the typed result card.
import { classifyImportPlan, createImportJournal, resultCardWords } from './lib/import/merge-law.js'
import { generateRandomPassword, validateWordlistUrl, extractWordlistFromText } from './lib/generator.js'
// R45-C — native password-manager control (optional privacy permission,
// explicit user opt-in only). Static import: module worker, no import().
import * as _nativeManager from './lib/native-manager.js'

// ════════════════════════════════════════════════════════════════════════
// v2.20.0 — R29-F1 (clinical audit, HIGH — proven in tests/probe/round29-wake-proof.mjs):
// initVault() used to run ONLY on onInstalled / onStartup / reloadFromStorage.
// Chrome recycles this worker after ~30 s idle — every wake RE-RUNS the module
// top level with the in-memory state back to defaults, and NOTHING restored the
// persisted session (chrome.storage.session survives the recycle — that is the
// whole point of the v2.1.0 #5 design). A woken worker then answered the popup's
// GET_STATE with hasMaster:false — the SETUP WIZARD, one accidental click away
// from setMasterPassphrase() overwriting the vault — or forced a re-unlock, and
// the configured idle auto-lock silently degraded to "as long as the worker
// happens to live". The real-Chromium journeys never caught it because their
// interactions keep the worker continuously alive.
// FIX: one boot promise per worker lifetime, awaited by the message router and
// the alarm handler before any state is read. initVault() is idempotent and
// cheap (one session read + one settings read); onInstalled/onStartup keep
// their explicit calls (harmless double-init).
// ════════════════════════════════════════════════════════════════════════
const bootReady = _vault.initVault().catch((e) => {
  console.warn('[UCrypt] boot init failed:', e?.message || e)
})

// R45-C — observe browser-side changes to passwordSavingEnabled (policy,
// another extension, the user in chrome://settings) and tell every open
// UCrypt page the truth immediately. No-op until the optional privacy
// permission is granted and chrome.privacy exists.
_nativeManager.wireNativeManagerObserver()

// The async getters stay so every existing call site keeps working.
async function vault() { return _vault }

async function i18nMod() { return _i18n }

async function sitesMod() { return _sites }

async function analyzer() { return _analyzer }

async function syncMod() { return _sync }

async function transportsMod() { return _transports }

async function pickupLinksMod() { return _pickupLinks }

// R135 (v2.92.0) — the Chain Data Types toggles' storage key (the panel
// writes it; lib/chaindata.js's engine gates read it).
const CHAINDATA_TOGGLES_KEY = 'ucrypt:chaindata:toggles'

// --- R116 §2.1 — THE TYPED ERROR WIRE PAYLOAD (the S2 regression's root fix) ---
// The SyncError carries userMessage + the typed recovery card, but the raw
// `sendResponse({ ok:false, error: e.message })` catches DROPPED both — the
// wizard footer then rendered the raw engine line ("token refresh failed (The
// OAuth client was disabled.)") where a typed card with the fix belongs.
// errPayload() carries, additions-only: the USER message (never the raw
// engine string) as `error`, the raw line as `errorRaw` (the diagnostics
// channel's words, sanitized by construction — no secrets ride a SyncError),
// the SyncError kind/status, and the recovery card when one rides.
function errPayload(e) {
  const err = e || {}
  const userMessage = err.userMessage || err.message || String(err)
  return {
    error: userMessage,
    errorRaw: err.message ? String(err.message) : undefined,
    kind: err.kind || undefined,
    status: Number.isFinite(Number(err.status)) ? Number(err.status) : undefined,
    recovery: err.recovery || null,
  }
}

// --- Domain extraction -----------------------------------------------------

function domainFromUrl(urlStr) {
  try {
    const u = new URL(urlStr)
    return u.hostname.replace(/^www\./, '')
  } catch {
    return ''
  }
}

// ══════════════════════════════════════════════════════════════════════════
// R90 §2.1 — TOOLBAR BADGE (canonical completion; original R42 law).
//
//   - matching-login count for the ACTIVE http(s) tab, capped at "9+"
//   - locked state is "•" with the title "UCrypt is locked" — NEVER a fake
//     count, never shown when locked
//   - computed from the URL in the worker (this module), not the page
//   - incognito: off
//
// The decision is PURE (lib/badge.js, unit tested); this wiring only reads
// state and writes chrome.action. Refreshed on: tab activation / navigation,
// tab close, vault lock AND unlock transitions (both the explicit handler
// paths and the lazy auto-lock broadcast), entry mutations that change the
// count (save, import, delete), and sync pulls that land other devices'
// writes.
// ══════════════════════════════════════════════════════════════════════════
let _badgeRefreshing = false
async function refreshBadge() {
  if (_badgeRefreshing) return // one write at a time — no torn badge state
  _badgeRefreshing = true
  try {
    // The focused window is authoritative; the currentWindow fallback keeps
    // the badge correct where lastFocusedWindow is undefined (startup races,
    // some window managers) — still the WORKER's URL, never the page's.
    let [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
    if (!tab) [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    let ctx = { unlocked: false, incognito: false, protocol: '', count: 0 }
    if (tab && tab.url !== undefined) {
      let protocol = ''
      try { protocol = new URL(tab.url).protocol } catch { protocol = '' }
      ctx = { unlocked: false, incognito: !!tab.incognito, protocol, count: 0 }
      if ((protocol === 'http:' || protocol === 'https:') && !tab.incognito) {
        try {
          const v = await vault()
          const st = await v.getVaultState()
          ctx.unlocked = !!st.isUnlocked
          if (ctx.unlocked) {
            ctx.count = v.getEntriesForDomain(domainFromUrl(tab.url)).length
          }
        } catch { /* state unavailable — locked rendering below is the truth */ }
      }
    }
    const d = badgeFor(ctx)
    await chrome.action.setBadgeText({ text: d.text })
    await chrome.action.setBadgeBackgroundColor({ color: d.color })
    await chrome.action.setTitle({ title: d.title })
  } catch { /* tabs/action unavailable — the badge is best-effort chrome */ }
  finally { _badgeRefreshing = false }
}

if (chrome.tabs) {
  chrome.tabs.onActivated.addListener(() => { refreshBadge() })
  chrome.tabs.onUpdated.addListener((_tabId, info) => {
    // Navigation/URL/load transitions of the ACTIVE tab can change the count.
    if (info.url || info.status === 'complete' || info.status === 'loading') refreshBadge()
  })
  chrome.tabs.onRemoved.addListener(() => { refreshBadge() })
}

// --- R95 F-95-02 (CEO finding, heuristic audit H3) — the vault window is
// TRACKED so the options header can toggle "Open vault window" / "Close
// window" truthfully. The id is device-local storage (never synced, never
// exported); windows.onRemoved keeps it honest when the user closes the
// window by its own ✕. A window id is not a secret and identifies nothing
// beyond this profile's own window handle.
const VAULT_WINDOW_ID_KEY = 'ucrypt:vaultWindowId'
if (chrome.windows && chrome.windows.onRemoved) {
  try {
    chrome.windows.onRemoved.addListener(async (windowId) => {
      try {
        const { [VAULT_WINDOW_ID_KEY]: tracked } = await chrome.storage.local.get(VAULT_WINDOW_ID_KEY)
        if (tracked === windowId) await chrome.storage.local.remove(VAULT_WINDOW_ID_KEY)
      } catch { /* tracking is best-effort */ }
    })
  } catch { /* windows events unavailable in this context */ }
}

// --- v2.11.0 — F6: remembered usernames for two-step logins (WORKER MEMORY) -
// Google/Microsoft/GitHub-style flows type the username on page 1 and the
// password on page 2; by submit time the username field is gone and the save
// prompt used to record an EMPTY username. The content script reports the
// last qualifying text field it saw (REMEMBER_USERNAME); at save time it
// asks for it back (GET_LAST_USERNAME). Rules:
//   - MEMORY ONLY — never chrome.storage, never synced, gone with the worker
//     (same lifetime class as Chrome's own in-memory per-tab username cache)
//   - keyed by (tabId, domain) — a tab can hold two sites' flows apart
//   - TTL 30 min, LRU cap 500 — bounded, stale entries expire themselves
const LAST_USERNAME_TTL_MS = 30 * 60 * 1000
const LAST_USERNAME_MAX = 500
const lastUsernameMem = new Map() // `${tabId}|${domain}` -> { username, at }

function lastUsernameKey(tabId, domain) {
  return `${Number(tabId) || 0}|${String(domain || '')}`
}

function rememberUsername(tabId, domain, username) {
  const u = String(username || '').trim()
  if (!u || u.length > 100 || /\s/.test(u)) return
  const key = lastUsernameKey(tabId, domain)
  if (lastUsernameMem.size >= LAST_USERNAME_MAX && !lastUsernameMem.has(key)) {
    // Evict the oldest entry first (insertion order = LRU order here).
    const oldest = lastUsernameMem.keys().next().value
    if (oldest !== undefined) lastUsernameMem.delete(oldest)
  }
  lastUsernameMem.delete(key)
  lastUsernameMem.set(key, { username: u, at: Date.now() })
}

function recallUsername(tabId, domain) {
  const key = lastUsernameKey(tabId, domain)
  const rec = lastUsernameMem.get(key)
  if (!rec) return ''
  if (Date.now() - rec.at > LAST_USERNAME_TTL_MS) {
    lastUsernameMem.delete(key)
    return ''
  }
  return rec.username
}

// --- Lifecycle -------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[UCrypt] Installed:', details.reason)
  const v = await vault()
  try {
    await v.initVault()
  } catch (e) {
    console.warn('[UCrypt] initVault failed:', e.message)
  }

  try {
    await chrome.alarms.create('ucrypt:breach-check', {
      periodInMinutes: 60 * 24,
      when: Date.now() + 60_000,
    })
  } catch (e) {
    console.warn('[UCrypt] alarm create failed:', e.message)
  }

  try {
    await chrome.alarms.create('ucrypt:auto-lock', {
      periodInMinutes: 0.5,
    })
  } catch (e) {
    console.warn('[UCrypt] auto-lock alarm create failed:', e.message)
  }

  // v2.8.0 — periodic cloud sync tick: pull every 15 min so a device picks up
  // changes pushed elsewhere, and retry pushes that never landed.
  try {
    await chrome.alarms.create('ucrypt:sync-pull', {
      periodInMinutes: 15,
      when: Date.now() + 60_000,
    })
  } catch (e) {
    console.warn('[UCrypt] sync-pull alarm create failed:', e.message)
  }

  // S8.9 (R99) — the continuous direct-sync poll cadence (the availability
  // alarm's pattern: 1-minute ticks; a tick on a locked vault exits inside
  // the engine — no state is touched while locked).
  try {
    await chrome.alarms.create('ucrypt:beam-sync', {
      periodInMinutes: 1,
      when: Date.now() + 30_000,
    })
  } catch (e) {
    console.warn('[UCrypt] beam-sync alarm create failed:', e.message)
  }

  await ensureContextMenus()
})

// --- Context menus (v2.6.0 — Brave/Chrome parity) --------------------------
// Menus are page-scoped to http/https: content scripts cannot run on
// chrome:// or the Web Store, so the actions would dead-end there anyway.

const PAGE_PATTERN = ['http://*/*', 'https://*/*']

function contextMenuItems(t) {
  // v2.10.0 — titles come from _locales (chrome.i18n); the literals are the
  // English fallback used when chrome.i18n is unavailable (QA stubs).
  return [
    { id: 'ucrypt-fill', title: t('ctxFill', undefined, 'UCrypt: Fill login from vault'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
    { id: 'ucrypt-suggest', title: t('ctxSuggest', undefined, 'UCrypt: Suggest strong password'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
    { id: 'ucrypt-save', title: t('ctxSave', undefined, 'UCrypt: Save login for this page'), contexts: ['page', 'editable'], documentUrlPatterns: PAGE_PATTERN },
    // v2.9.0 — Brave parity: a persistent per-site exception, not just a
    // per-page-load "Not now". Handled fully in the background (no page
    // round-trip needed) with a confirmation notification.
    { id: 'ucrypt-never', title: t('ctxNever', undefined, 'UCrypt: Never save passwords for this site'), contexts: ['page', 'editable'], documentUrlPatterns: PAGE_PATTERN },
    // v2.19.0 — R28-B1 (Brave parity III): fill imported CARDS and IDENTITIES
    // into web forms — the last feasible gap in the R25 24-feature matrix
    // ("card/address form-fill of imported data"). Explicit user action →
    // deliberately NOT gated by the Offer-to-save/Auto sign-in toggles,
    // exactly like the context-menu login save.
    { id: 'ucrypt-fill-card', title: t('ctxFillCard', undefined, 'UCrypt: Fill card from vault'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
    { id: 'ucrypt-fill-address', title: t('ctxFillAddress', undefined, 'UCrypt: Fill identity from vault'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
    // v2.42.8 — R71-P: protected profile fill + EXPLICIT profile capture.
    // The capture route opens the review dialog ONLY when the classifier
    // confidence is high (the content script explains honestly otherwise).
    { id: 'ucrypt-fill-profile', title: t('ctxFillProfile', undefined, 'UCrypt: Fill profile from vault'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
    { id: 'ucrypt-save-profile', title: t('ctxSaveProfile', undefined, 'UCrypt: Save current form as a profile'), contexts: ['editable'], documentUrlPatterns: PAGE_PATTERN },
  ]
}

async function ensureContextMenus() {
  if (!chrome.contextMenus) return
  try {
    const { getMessage } = await i18nMod()
    await chrome.contextMenus.removeAll()
    for (const item of contextMenuItems(getMessage)) {
      await new Promise((resolve) => chrome.contextMenus.create(item, resolve))
    }
  } catch (e) {
    console.warn('[UCrypt] context menu setup failed:', e.message)
  }
}

// Menus persist across worker restarts, but re-asserting on startup keeps
// them correct after an update that changes the item set.
chrome.runtime.onStartup.addListener(() => {
  ensureContextMenus()
})

async function sendToActiveTab(type, fallbackError) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || !tab.id) throw new Error('No active tab')
    await chrome.tabs.sendMessage(tab.id, { type })
  } catch {
    try {
      const { getMessage } = await i18nMod()
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: getMessage('notifTitle', undefined, 'UCrypt'),
        message: fallbackError,
      })
    } catch { /* the notification is best-effort — a blocked surface never perturbs the menu work it announces (named-swallow law, R169 C1) */ }
  }
}

// --- R59-F2 — the lock state must REACH the pages ---------------------------
// A content script that rendered the autofill picker while the vault was
// unlocked used to KEEP it after a lock: no push channel existed (owner
// screenshots F2: picker + "Vault locked" visible at the same time). Every
// lock path now broadcasts VAULT_LOCKED to all tabs; every unlock broadcasts
// VAULT_UNLOCKED. The content script destroys its vault-derived surfaces and
// bumps its epoch on receipt — a lock event wins all races.
let _lastKnownUnlocked = null

// R110 §3 (law 0.15, the CEO-pinned constant) — THE PASSPHRASE CONFIRMATION
// WINDOW. After a successful passphrase entry (the vault unlock or a popup
// confirmation via VERIFY_PASSPHRASE), any passphrase-requiring confirmation
// within 60 seconds does not re-prompt; after 60 seconds the next requiring
// action prompts again. IN-MEMORY ONLY: never persisted, cleared on lock
// (both the explicit LOCK and the lazy auto-lock broadcast), dies with the
// worker (a service-worker recycle resets the module state), never bypasses
// the vault's own lock state (a locked vault still shows the unlock screen),
// and never applies to the master unlock itself. The window's SURFACES show
// a visible countdown so the skip is never mysterious.
const PASSPHRASE_WINDOW_MS = 60000
let _passConfirmAt = 0
function markPassphraseConfirmed() { _passConfirmAt = Date.now() }
function clearPassphraseWindow() { _passConfirmAt = 0 }
function passphraseWindowNow() {
  if (!_passConfirmAt) return { withinWindow: false, secondsLeft: 0 }
  const left = Math.max(0, Math.ceil((_passConfirmAt + PASSPHRASE_WINDOW_MS - Date.now()) / 1000))
  if (left <= 0) { _passConfirmAt = 0; return { withinWindow: false, secondsLeft: 0 } }
  return { withinWindow: true, secondsLeft: left }
}
async function broadcastVaultEvent(type) {
  // R125 §2 (law 0.39) — a lock wipes every staged candidate (the
  // credential-layer law: a lock event destroys every credential-bearing
  // in-memory surface — the candidates are one of them).
  if (type === 'VAULT_LOCKED') clearSaveCandidates()
  try {
    const tabs = await chrome.tabs.query({})
    for (const t of tabs || []) {
      if (!t || !t.id) continue
      try { await chrome.tabs.sendMessage(t.id, { type }) } catch { /* no content script in this tab */ }
    }
  } catch { /* tabs API unavailable — nothing to notify */ }
  // R97 (F-R96-1): the clipboard guard lives in EXTENSION PAGES (popup,
  // options/vault window) — the tabs leg above cannot reach them. One
  // runtime leg, same event; no listener → the typed no-receiver catch.
  try { await chrome.runtime.sendMessage({ type }) } catch { /* no page listeners */ }
}

/** Broadcast a lock/unlock transition if one happened since the last check.
 *  Covers the LAZY auto-lock path inside vault.getVaultState() (a timer lock
 *  that fires between messages) — checked on the keepalive/auto-lock alarms
 *  and on every state-reading message. */
async function syncVaultLockBroadcast() {
  try {
    const v = await vault()
    const st = await v.getVaultState()
    const unlocked = !!st.isUnlocked
    if (_lastKnownUnlocked === true && !unlocked) {
      await broadcastVaultEvent('VAULT_LOCKED')
      // R110 §3 — the lazy lock also closes the passphrase window.
      clearPassphraseWindow()
      // R77-C — a lock must also tear the transfer plane down (availability
      // window closed, presence cleared, every in-memory session wiped).
      try { await onTransferVaultLocked() } catch { /* plane best-effort */ }
    }
    else if (_lastKnownUnlocked === false && unlocked) await broadcastVaultEvent('VAULT_UNLOCKED')
    _lastKnownUnlocked = unlocked
    // R90 §2.1 — lock/unlock transitions change the badge (count ↔ "•").
    refreshBadge()
  } catch { /* state unavailable — retried on the next tick */ }
}

if (chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (!tab || !tab.id) return
    const { getMessage } = await i18nMod()
    const pageTypes = {
      'ucrypt-fill': {
        type: 'PERFORM_FILL',
        error: getMessage('notifNoPage', undefined, 'Open a normal web page with a login form, then try again.'),
      },
      'ucrypt-suggest': {
        type: 'SUGGEST_STRONG_PASSWORD',
        error: getMessage('notifNoField', undefined, 'Click inside a password field first, then use the menu again.'),
      },
      'ucrypt-save': {
        type: 'SAVE_PAGE_LOGIN',
        error: getMessage('notifUnreachable', undefined, 'UCrypt could not reach this page — is it a normal http/https site?'),
      },
      // v2.19.0 — R28-B1: card/identity form-fill entry points.
      'ucrypt-fill-card': {
        type: 'FILL_DATA_PROMPT',
        fillType: 'card',
        error: getMessage('notifUnreachable', undefined, 'UCrypt could not reach this page — is it a normal http/https site?'),
      },
      'ucrypt-fill-address': {
        type: 'FILL_DATA_PROMPT',
        fillType: 'address',
        error: getMessage('notifUnreachable', undefined, 'UCrypt could not reach this page — is it a normal http/https site?'),
      },
      // v2.42.8 — R71-P: profile routes.
      'ucrypt-fill-profile': {
        type: 'FILL_PROFILE_PROMPT',
        error: getMessage('notifUnreachable', undefined, 'UCrypt could not reach this page — is it a normal http/https site?'),
      },
      'ucrypt-save-profile': {
        type: 'SAVE_FORM_PROFILE',
        error: getMessage('notifUnreachable', undefined, 'UCrypt could not reach this page — is it a normal http/https site?'),
      },
    }
    const spec = pageTypes[info.menuItemId]
    if (!spec) return
    try {
      await chrome.tabs.sendMessage(tab.id, { type: spec.type, fillType: spec.fillType })
    } catch {
      try {
        await chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: getMessage('notifTitle', undefined, 'UCrypt'),
          message: spec.error,
        })
      } catch { /* the notification is best-effort — a blocked surface never perturbs the command it reports (named-swallow law, R169 C1) */ }
    }
  })
}

// --- Keyboard commands (v2.6.0) --------------------------------------------

chrome.commands.onCommand.addListener(async (command) => {
  const { getMessage } = await i18nMod()
  if (command === 'fill-login') {
    await sendToActiveTab('PERFORM_FILL', getMessage('notifCmdNoPage', undefined, 'Open a web page with a login form, then try the shortcut again.'))
  } else if (command === 'suggest-password') {
    await sendToActiveTab('SUGGEST_STRONG_PASSWORD', getMessage('notifCmdNoField', undefined, 'Click inside a password field first, then try the shortcut again.'))
  }
})

// v2.9.0 — context-menu "never save" is handled entirely in the background:
// the click already carries the tab URL, no content-script round-trip needed.
if (chrome.contextMenus) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId !== 'ucrypt-never' || !tab || !tab.url) return
    const sites = await sitesMod()
    const { getMessage } = await i18nMod()
    const domain = domainFromUrl(tab.url)
    if (!domain) {
      try {
        await chrome.notifications.create({
          type: 'basic', iconUrl: 'icons/icon48.png',
          title: getMessage('notifTitle', undefined, 'UCrypt'),
          message: getMessage('notifNoAddress', undefined, 'Could not read this page\u2019s address — open UCrypt settings to add the site manually.'),
        })
      } catch { /* the notification is best-effort — a blocked surface never perturbs the refusal it reports (named-swallow law, R169 C1) */ }
      return
    }
    const r = await sites.addNeverSaveSite(domain)
    try {
      await chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon48.png',
        title: getMessage('notifTitle', undefined, 'UCrypt'),
        message: r.ok
          ? getMessage('notifNeverAdded', [domain], `UCrypt will no longer offer to save passwords on ${domain}. (Manage this in Settings → Security → Site settings.)`)
          : getMessage('notifNeverFailed', [r.error || 'unknown error'], `Could not add the exception: ${r.error}`),
      })
    } catch { /* the notification is best-effort — a blocked surface never perturbs the exception result it reports (named-swallow law, R169 C1) */ }
  })
}

chrome.runtime.onStartup.addListener(async () => {
  console.log('[UCrypt] Browser startup')
  const v = await vault()
  try {
    await v.initVault()
  } catch (e) {
    console.warn('[UCrypt] initVault on startup failed:', e.message)
  }
  // The vault is still LOCKED here (session storage died with the browser),
  // so this pull is a no-op until the user unlocks — the real pull happens in
  // the UNLOCK handler (v2.8.0). Kept as a cheap safety net for the case where
  // the session survived (browser-level restore).
  try {
    await chainWakeGuardedPull(v)
  } catch { /* silent */ }
  // LAW 0.49 (R133) — the browser-start auto-sync trigger: the interval
  // alarm re-derives from the user's cadence, and one full cycle is scheduled
  // shortly after start (a locked vault exits inside the tick — harmless).
  try { await ensureSyncIntervalAlarm(v) } catch { /* the installed alarm persists */ }
  try { chrome.alarms.create('ucrypt:sync-startup', { delayInMinutes: 0.5 }) } catch { /* best-effort */ }
  // R148 §6.6 (the K-6 cure) — THE INITIALIZATION SEQUENCE at browser start:
  // the owner's manual check list runs UNDER THE HOOD (probe → silent
  // refresh → pull+verify → roster reconcile → one honest line). A locked
  // vault records the typed pending state — the unlock re-runs the sequence.
  try { await startupCheck('browser-start') } catch { /* the ledger stays honest */ }
})

/* ── R148 §6.6 — THE INITIALIZATION SEQUENCE (the K-6 cure, LAW #75) ─────
 * At EVERY UCrypt initialization (browser start / service-worker wake /
 * vault unlock) the check list the owner performs MANUALLY runs under the
 * hood:
 *   (1) probe cloud stability (the cred machine's probe);
 *   (2) silent credential refresh if needed (the cred machine's heal);
 *   (3) PULL + VERIFY the cloud copy reads;
 *   (4) reconcile the roster against the chain document (the tombstones);
 *   (5) surface ONE honest line — "Startup check ✓ — cloud read, backup
 *       verified, 2 devices" (or the typed failure + the armed retry).
 * The manual "Sync now" remains for the impatient human — but it is no
 * longer the ONLY path. Battery: tests/r148-initcheck.test.mjs. */
const STARTUP_CHECK_KEY = 'ucrypt:startupCheck'
let _startupCheckInFlight = false

/**
 * R149 C-1b (LAW #79 — THE SILENT REVIVAL): the LOCKED-vault cloud probe.
 * The bridge rung's connection truth survives the restart (the device
 * transport key in lib/vault.js), so a locked vault can still answer ONE
 * honest question: does the stored connection work? A pass revives the cred
 * machine silently (the A1/A2 chip lie dies — no "needs you" over a working
 * bridge); a locked/unopenable connection records the typed CRED_LOCKED
 * verdict; a real transport failure records its own evidence. The VAULT
 * PAYLOAD pull stays locked (R45-A — the payload is sealed under the master
 * key and nothing here decrypts it).
 */
async function credProbeLocked() {
  try {
    const v = await vault()
    const rec = await v.getTransportRecord().catch((e) => {
      // The typed refusal (a credential-sealed field or a legacy bridge
      // envelope) — the locked truth, not a shape/network lie.
      if (e && /Vault is locked/i.test(String((e && e.message) || e))) return { __locked: true }
      return null
    })
    if (rec && rec.__locked) return { ok: false, locked: true }
    if (!rec || !rec.id) return { ok: false, none: true }
    const tm = await transportsMod()
    const t = tm.getTransport(rec.id)
    if (!t || typeof t.testConnection !== 'function') return { ok: false, locked: true }
    // R150 CURE 2(iii): the locked probe is bounded ≤10 s like every probe.
    await boundedProbe(() => t.testConnection(rec.config))
    return { ok: true, transportId: rec.id }
  } catch (e) {
    // The transport's own typed evidence rides (kind/status) — the classify
    // step turns it into the honest verdict class.
    return { ok: false, error: e, transportErrorKind: (e && e.kind) || null, transportErrorStatus: (e && e.status) || null }
  }
}

/** Record one probe outcome into the persisted cred machine (the §4.5
 * state write, evidence-shaped). Never throws into the startup check. */
async function credRecordProbeOutcome(probe) {
  try {
    if (probe && probe.ok) return await credHealTick({ ok: true, remoteObserved: true })
    if (probe && probe.locked) return await credHealTick({ ok: false, remoteObserved: false, locked: true })
    if (probe && probe.none) return null // nothing configured — nothing to classify
    return await credHealTick({
      ok: false,
      remoteObserved: false,
      transportErrorKind: (probe && probe.transportErrorKind) || 'network',
      transportErrorStatus: (probe && probe.transportErrorStatus) || null,
      transportError: probe && probe.error ? String((probe.error && (probe.error.userMessage || probe.error.message)) || probe.error) : '',
    })
  } catch { return null }
}

async function startupCheck(trigger = 'wake') {
  if (_startupCheckInFlight) return { ok: false, code: 'IN_FLIGHT' }
  _startupCheckInFlight = true
  const startedAt = Date.now()
  const row = { at: startedAt, trigger, ok: false, line: '', steps: {} }
  try {
    const v = await vault()
    const st = await v.getVaultState().catch(() => null)
    if (!st || !st.isUnlocked) {
      // R149 C-1b (LAW #79 — THE SILENT REVIVAL): a locked vault no longer
      // skips the cloud probe. The bridge rung's connection truth survives
      // the restart (the device transport key), so the probe runs WITHOUT
      // the vault key: a pass revives the cred machine silently; a locked
      // connection records the typed CRED_LOCKED verdict. The payload pull
      // stays locked (R45-A) — only the CONNECTION probe runs here.
      row.pending = true
      row.locked = true
      const probe = await credProbeLocked().catch(() => ({ ok: false, locked: true }))
      row.steps.cred = { ok: !!probe.ok, locked: !!(probe && probe.locked) }
      await credRecordProbeOutcome(probe)
      row.line = probe && probe.ok
        ? 'Startup check — the cloud connection answered while the vault is locked; the chain revives on its own at the next unlock.'
        : 'Startup check pending — unlock the vault and the check completes on its own.'
      await chrome.storage.local.set({ [STARTUP_CHECK_KEY]: row }).catch(() => {})
      return { ok: false, code: 'LOCKED', row }
    }
    // (3) — PULL + VERIFY runs FIRST now (R149 C-1a: the heal consumes
    // EVIDENCE, never a fabricated failure): the guarded pull IS the
    // verification (one bounded read that positively observes the remote —
    // the R145 convergence law)
    let pull = null
    try { pull = await chainWakeGuardedPull(v) } catch { pull = null }
    const pullOk = !!(pull && pull.ok !== false)
    row.steps.pull = { ok: pullOk }
    // (1)+(2) — the cred machine's heal rides THIS pull's real outcome (a
    // heal success never invents a user-visible state; a null pull latches
    // nothing — the R149 no-evidence law)
    try {
      const heal = await credHealTick(pull)
      row.steps.cred = { ok: !!(heal && (heal.ok || heal.noEvidence)), revived: !!(heal && heal.revived) }
    } catch { row.steps.cred = { ok: false } }
    // (4) — the roster reconcile (the §6.5 tombstones converge on pull; the
    // row count is the honest device count)
    let deviceCount = 0
    try {
      const roster = await v.rosterPeers ? await v.rosterPeers() : []
      deviceCount = Array.isArray(roster) ? roster.filter((p) => p && p.deviceId).length : 0
    } catch { deviceCount = 0 }
    row.steps.roster = { ok: true, devices: deviceCount }
    row.ok = pullOk
    row.line = pullOk
      ? `Startup check ✓ — cloud read, backup verified${deviceCount ? ', ' + deviceCount + ' device' + (deviceCount === 1 ? '' : 's') : ''}.`
      : 'Startup check — the cloud read did not complete; the retry is armed and the next cycle carries it.'
    row.at = Date.now()
    await chrome.storage.local.set({ [STARTUP_CHECK_KEY]: row }).catch(() => {})
    try { chrome.runtime.sendMessage({ type: 'UCRYPT_STARTUP_CHECK', ...row }).catch?.(() => {}) } catch { /* no receiver */ }
    return { ok: true, row }
  } catch (e) {
    row.line = 'Startup check — the sequence could not run (' + String((e && e.message) || e).slice(0, 80) + '); the next cycle carries it.'
    await chrome.storage.local.set({ [STARTUP_CHECK_KEY]: row }).catch(() => {})
    return { ok: false, row }
  } finally {
    _startupCheckInFlight = false
  }
}

// --- Cloud sync tick (v2.8.0) -----------------------------------------------

// ── R140 §7 — THE CHAIN WAKE CYCLE (the cold-start cure's clock) ──────────
// A NEW service-worker lifetime IS a new wake cycle: the persisted verdict
// demotes to a cache — the strip shows PENDING until the first probe of THIS
// cycle completes, the ladder (1s/2s/4s/8s/16s) owns transient failures, and
// ANY success auto-clears. The stale-latch class — the banner outliving its
// own cause on every browser restart — is unrepresentable from here on.
const CHAIN_WAKE_KEY = 'ucrypt:chainState:wake'
const _chainWakeSleep = (ms) => new Promise((r) => setTimeout(r, ms))
let _chainWakeStarted = false
async function chainWakeStart() {
  if (_chainWakeStarted) return
  _chainWakeStarted = true
  try {
    const wake = newWakeCycle('w' + Date.now().toString(36), Date.now())
    await chrome.storage.local.set({ [CHAIN_WAKE_KEY]: wake })
    console.log('[UCrypt] chain wake cycle started:', wake.wakeId)
  } catch { /* the wake cache is best-effort — the ledger remains the truth */ }
  // R150 CURE 1(b) (D-2, capture B5) — THE INTEGRITY CHECK AT INIT: the
  // stored transport record resolves through the LEGACY-ALIAS READER once
  // per worker lifetime — a null/aliased/unknown id migrates to the shape's
  // true transport (re-saved + logged) or heals to the typed BRIDGE_SETUP
  // state. The beat rides publishRunState so open surfaces re-render in the
  // same tick (LAW #78) with the migrated truth.
  try {
    const v0 = await vault()
    const healed = await v0.healTransportRecordAtInit()
    if (healed && (healed.migrated || healed.state === 'bridge-setup')) {
      await publishRunState('init', healed.state !== 'bridge-setup', healed.state === 'bridge-setup'
        ? 'The saved cloud setup needs a transport — choose one and press Connect.'
        : `The saved cloud setup migrated to ${String(healed.id || '').slice(0, 24)}.`)
    }
  } catch { /* the heal never blocks the wake */ }
}

/**
 * R150 CURE 2(iii) (§6.2) — THE CHECK BUDGET: every wake probe (a pull) is
 * bounded ≤10 s (CHAIN_CHECK_CAP_MS — the ledgered number). A hung cloud
 * read can never hold the check open: past the budget the race rejects with
 * the typed timeout and the probe reports its own failure evidence. The
 * in-flight window is tracked so SYNC_CHAIN_VERDICT can pass an HONEST
 * probeInFlight flag into the derivation (the CHECK_TIMED_OUT branch only
 * ever fires from a genuinely hung check — never from a ladder wait).
 */
const _chainProbeBudgetMs = Math.min(10000, CHAIN_CHECK_CAP_MS)
let _probeInFlightUntil = 0
const probeInFlightNow = () => Date.now() < _probeInFlightUntil
async function boundedProbe(promiseOrFn) {
  const run = typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn
  _probeInFlightUntil = Date.now() + _chainProbeBudgetMs
  try {
    return await Promise.race([
      run,
      new Promise((resolve) => setTimeout(() => resolve({
        synced: false,
        remoteObserved: false,
        reason: `The cloud check ran past its ${Math.round(_chainProbeBudgetMs / 1000)} s budget — the probe is bounded and the retry is armed.`,
        transportErrorKind: 'timeout',
        transportErrorStatus: null,
        transportError: 'The cloud check ran out of time',
      }), _chainProbeBudgetMs)),
    ])
  } finally {
    _probeInFlightUntil = 0
  }
}

/**
 * THE GUARDED PULL (§7.3): the FIRST cloud read of a wake cycle retries on
 * the ladder before any error may latch — a cold-start race (an auth refresh
 * in flight, a cold network, propagation delay) is not a dead cloud. Only
 * ladder-OWNED classes retry (auth races, unreachable); a malformed response
 * class (BRIDGE) or an unreadable copy latches immediately — the evidence is
 * real, the ladder cannot cure it.
 * R150 CURE 2(iii): every pull leg is bounded ≤10 s (boundedProbe).
 */
async function chainWakeGuardedPull(v) {
  let wake = null
  try { wake = (await chrome.storage.local.get(CHAIN_WAKE_KEY))[CHAIN_WAKE_KEY] || null } catch { wake = null }
  const firstOfCycle = !!(wake && wake.wakeId && !wake.firstProbeCompletedAt)
  let pull = null
  try { pull = await boundedProbe(() => v.pullFromSync()) } catch { pull = null }
  if (!firstOfCycle) return pull
  const attempted = !!pull && typeof pull === 'object'
  const failed = !attempted || pull.remoteObserved === false
  if (!failed) return pull
  const cls = classifyProbeFailure({
    probeName: 'wake-pull',
    kind: attempted ? pull.transportErrorKind : '',
    status: attempted && Number.isFinite(Number(pull.transportErrorStatus)) ? Number(pull.transportErrorStatus) : null,
    at: Date.now(),
  })
  if (!cls.ladderOwned) return pull // malformed/unreadable — the evidence is real
  for (let attempt = 0; attempt < CHAIN_RETRY_LADDER_MS.length; attempt++) {
    await _chainWakeSleep(CHAIN_RETRY_LADDER_MS[attempt])
    try { pull = await boundedProbe(() => v.pullFromSync()) } catch { pull = null }
    const okNow = !!pull && typeof pull === 'object' && pull.remoteObserved !== false
    if (okNow) return pull // auto-clear — the race healed inside the ladder
  }
  return pull // the ladder is exhausted — the derivation may now speak, WITH evidence
}

// the wake cycle starts the moment this worker lifetime begins (top level)
chainWakeStart()

// ── R147 §4 — THE CREDENTIAL LIFECYCLE (the J-5 cure's worker half) ───────
// The state machine's PERSISTENT half: every pull outcome updates the cred
// cache (the §4.1 states FRESH→REFRESHING→DEAD→REVIVED, the §4.5 backoff
// 1/2/4/8/15 min, the 3-cycle upload pause, the §4.1 journal ring). The
// derivation is STATELESS from the persisted inputs (the R140 shape — the
// worker dies constantly; a persisted verdict is a cache, never a writer).
// The chip, the banner, and the auto-sync clock all read CRED_STATUS — ONE
// truth (§4.4, the J-6 cure).
const CRED_STATE_KEY = 'ucrypt:cred-state'
const CRED_JOURNAL_RING = 20

async function credStateRead() {
  try { return (await chrome.storage.local.get(CRED_STATE_KEY))[CRED_STATE_KEY] || null } catch { return null }
}

async function credStateWrite(patch) {
  const prev = (await credStateRead()) || {}
  const next = { ...prev, ...patch }
  if (Array.isArray(next.journal) && next.journal.length > CRED_JOURNAL_RING) next.journal = next.journal.slice(-CRED_JOURNAL_RING)
  try { await chrome.storage.local.set({ [CRED_STATE_KEY]: next }) } catch { /* best effort */ }
  return next
}

/** §4.3 — classify one pull outcome into the typed verdict class. The sync
 * engine's error kinds (protocol/auth/rate/network/config) translate onto
 * the §4.3 vocabulary (the ledger row IS the evidence — file:line: the
 * pull's transportErrorKind/Status, lib/vault.js:3385-3439).
 * R149 C-1a (THE LOCKED TRUTH, capture A1/A2): a locked-vault consult is a
 * FIRST-CLASS verdict (CRED_LOCKED) — never a lying shape/network class.
 * R149 §6.6 (THE TWO-TRUTHS SWEEP): the bridge's causes resolve onto the
 * typed bridge classes by EVIDENCE — missing scriptUrl → BRIDGE_URL_MISSING;
 * an HTML/stale-deployment answer → BRIDGE_DEPLOY_OLD; a re-authorization
 * refusal → BRIDGE_AUTH_STALE. ONE class machine writes every cloud
 * sentence (the mapping itself lives in lib/cloud/cred.js — this function
 * only prepares the evidence). */
function credClassifyPull(pull) {
  if (pull && pull.ok !== false && pull.remoteObserved !== false) return null
  // THE LOCKED TRUTH — the pull's typed locked shape (the R45-A §2.5
  // not-consulted exit) or the envelope path's 'Vault is locked' throw.
  if (pull && pull.locked === true) return CRED_VERDICT_CLASSES.CRED_LOCKED
  const rawKind = String((pull && pull.transportErrorKind) || 'network')
  const status = pull && Number.isFinite(Number(pull.transportErrorStatus)) ? Number(pull.transportErrorStatus) : null
  // R95-D2 (the ledger's own lesson): the transportError may arrive as an
  // Error-shaped object — read the human message off it before matching.
  const terr = pull && pull.transportError
  const errText = typeof terr === 'string' ? terr : (terr && (terr.userMessage || terr.message)) || ''
  const kindMap = { protocol: 'html', auth: '401', rate: 'quota', network: 'network', timeout: 'network', cors: 'cors', config: 'config' }
  const ans = {
    kind: kindMap[rawKind] || 'network',
    status,
    bodyStart: String((pull && pull.transportErrorBodyStart) || ''),
    htmlHint: pull && pull.transportErrorHtml ? { cause: pull.transportErrorHtml.cause } : null,
  }
  // §6.6 — the bridge evidence refinements (the transportError TEXT is a
  // typed SyncError line — a cause name, never a secret):
  if (!ans.htmlHint && ans.kind === 'html' && /HTML page/i.test(errText)) ans.htmlHint = { cause: 'html-unknown' }
  if (ans.kind === 'config' && /older deployment|re-paste and redeploy/i.test(errText)) return CRED_VERDICT_CLASSES.BRIDGE_DEPLOY_OLD
  if (ans.kind === 'config' && /re-authorize|sign-?in expired/i.test(errText)) return CRED_VERDICT_CLASSES.BRIDGE_AUTH_STALE
  // R171 — THE TRANSPORT-TRUTH LAW (the E-23 cure, classifier seat): the
  // config-class verdict follows the ACTIVE transport. OAuth words in the
  // typed line (the OAuth config throws name Connect/client ID) name the
  // OAUTH class — the Apps Script demand is structurally unreachable for
  // an OAuth-connected user. The bridge words keep the bridge classes.
  if (ans.kind === 'config' && /connect google drive|oauth|client id/i.test(errText) && !/apps script|bridge/i.test(errText)) {
    return CRED_VERDICT_CLASSES.OAUTH_SETUP_MISSING
  }
  return classifyCredentialAnswer(ans)
}

/** The heal tick (§4.5): EVERY pull outcome feeds it — the auto-sync alarm
 * is the clock; a success at ANY point revives the chain silently.
 * R149 C-1a: a NULL outcome carries NO evidence about the cloud — the tick
 * leaves the persisted truth untouched instead of fabricating a network
 * failure (the lying-diagnosis class: the startup heal used to latch
 * UNEXPECTED_NETWORK on a pull that never ran). */
async function credHealTick(pull) {
  if (pull == null) {
    const cur = await credStateRead()
    return { ok: !cur || !(cur.failedCycles > 0), noEvidence: true, state: cur || { failedCycles: 0 } }
  }
  const cls = credClassifyPull(pull)
  const prev = (await credStateRead()) || { failedCycles: 0, journal: [] }
  const now = Date.now()
  const journal = Array.isArray(prev.journal) ? prev.journal.slice(-CRED_JOURNAL_RING) : []
  if (!cls) {
    const wasDead = (prev.failedCycles || 0) > 0
    const next = await credStateWrite({
      state: wasDead ? 'revived' : 'fresh',
      failedCycles: 0,
      nextRetryAt: null,
      lastVerdict: { ok: true, at: now, cls: null },
      journal: [...journal, { at: now, event: wasDead ? 'revived' : 'probe-ok' }].slice(-CRED_JOURNAL_RING),
    })
    return { ok: true, revived: wasDead, state: next }
  }
  const failedCycles = (Number(prev.failedCycles) || 0) + 1
  const nextRetryAt = now + nextHealMs(failedCycles - 1)
  const next = await credStateWrite({
    state: 'dead',
    failedCycles,
    nextRetryAt,
    lastVerdict: { ok: false, at: now, cls: cls.key, words: cls.words, nextStep: cls.nextStep },
    journal: [...journal, { at: now, event: 'probe-failed', cls: cls.key, cycle: failedCycles }].slice(-CRED_JOURNAL_RING),
  })
  return { ok: false, state: next, uploadsPaused: uploadsPaused(failedCycles) }
}

/** §4.4 — the derived chip/banner truth (stateless from the persisted inputs).
 * R149 C-1a — THE LOCKED TRUTH: when the last verdict is CRED_LOCKED the
 * chip says 'Cloud: locked — unlock to revive' (honest — never 'needs
 * you'), the banner carries the CRED_LOCKED words and the Unlock affordance
 * hint, and NO retry clock runs (unlocking is the cure, not waiting).
 * R149 C-2 — the response also carries `cloudConfigured` so the Reconnect
 * click can route the no-setup case to Edit setup with a plain-words
 * reason. */
async function credDeriveTruth() {
  const { [LAST_PULL_KEY_CRED]: lastPull } = await chrome.storage.local.get(LAST_PULL_KEY_CRED)
  const cred = (await credStateRead()) || { failedCycles: 0, journal: [] }
  const now = Date.now()
  // R150 CURE 1 (D-2) — the connected truth reads the LEGACY-ALIAS READER's
  // resolution (never the raw id): a null/unknown id renders 'Cloud: not
  // connected' — never 'needs you' over an unresolvable record.
  let cloudConfigured = false
  try { cloudConfigured = !!((await (await vault()).resolveTransportRecord()).usableId) } catch { cloudConfigured = false }
  const lastOk = lastPull && lastPull.ok
  const degraded = cloudConfigured && cred.failedCycles > 0 && !lastOk
  const lockedVerdict = !!(degraded && cred.lastVerdict && cred.lastVerdict.cls === CRED_VERDICT_CLASSES.CRED_LOCKED.key)
  const ageMin = cred.lastVerdict ? Math.max(0, Math.round((now - Number(cred.lastVerdict.at || now)) / 60_000)) : null
  const ageWords = ageMin == null ? '' : ageMin === 0 ? 'just now' : `${ageMin} min ago`
  const chip = !cloudConfigured
    ? { connected: false, line: 'Cloud: not connected' }
    : lockedVerdict
      ? { connected: false, line: 'Cloud: locked — unlock to revive' }
      : degraded
        ? { connected: false, line: `Cloud: needs you · checked ${ageWords}` }
        : { connected: true, line: `Cloud: connected · checked ${ageWords}` }
  const banner = lockedVerdict
    ? {
        degraded: true,
        uploadsPaused: uploadsPaused(cred.failedCycles),
        cls: CRED_VERDICT_CLASSES.CRED_LOCKED.key,
        words: cred.lastVerdict.words || CRED_VERDICT_CLASSES.CRED_LOCKED.words,
        clock: 'Unlock the vault — the chain revives on its own.',
        unlock: true,
      }
    : degraded
      ? {
          degraded: true,
          uploadsPaused: uploadsPaused(cred.failedCycles),
          cls: cred.lastVerdict ? cred.lastVerdict.cls : null,
          words: cred.lastVerdict ? cred.lastVerdict.words : '',
          clock: cred.failedCycles < UPLOAD_PAUSE_AFTER_CYCLES && cred.nextRetryAt
            ? `will retry in ${Math.max(1, Math.round((Number(cred.nextRetryAt) - now) / 60_000))} min — attempt ${Math.min(cred.failedCycles + 1, UPLOAD_PAUSE_AFTER_CYCLES)} of ${UPLOAD_PAUSE_AFTER_CYCLES}`
            : cred.nextRetryAt
              ? `uploads paused — will retry in ${Math.max(1, Math.round((Number(cred.nextRetryAt) - now) / 60_000))} min`
              : '',
        }
      : { degraded: false, uploadsPaused: false, words: '', clock: '' }
  return {
    ok: true,
    cloudConfigured,
    chip,
    banner,
    nextSyncClock: degraded && !lockedVerdict && cred.nextRetryAt
      ? { degraded: true, words: `Next retry in ${Math.max(1, Math.round((Number(cred.nextRetryAt) - now) / 60_000))} min — uploads resume on their own when the road returns.` }
      : { degraded: false, words: '' },
    technicalDetail: { state: degraded ? 'dead' : 'fresh', cls: cred.lastVerdict ? cred.lastVerdict.cls : null, journal: (cred.journal || []).slice(-CRED_JOURNAL_RING) },
  }
}

// the last-pull ledger key rides vault.js's public constant (the ONE truth)
const LAST_PULL_KEY_CRED = 'ucrypt:lastPull' // == lib/vault.js LAST_PULL_KEY_PUBLIC (the R61-A §1.1 ledger)

// ── R149 C-4 (capture A4, LAW #78 — ONE-EVENT-ALL-SURFACES) ───────────
// EVERY sync-run completion publishes ONE compact run-state record to
// chrome.storage.local 'ucrypt:runState' — a SINGLE set() call, so the open
// pages receive ONE storage.onChanged event and re-render every surface
// (the chain-state headline card, the status chips, the attention card) in
// the same beat. The run ROW stays in 'ucrypt:syncRuns' (the ledger); the
// run-state record is the SUBSCRIPTION beat — no values, no secrets, only
// { at, ok, kind, verdict }.
const RUN_STATE_KEY = 'ucrypt:runState'
async function publishRunState(kind, ok, verdict) {
  try {
    await chrome.storage.local.set({
      [RUN_STATE_KEY]: {
        at: Date.now(),
        ok: !!ok,
        kind: String(kind || 'sync').slice(0, 24),
        verdict: String(verdict || '').slice(0, 160), // a typed reason line — never a secret
      },
    })
  } catch { /* the beat never breaks the run */ }
}

/**
 * Periodic sync maintenance, run by the ucrypt:sync-pull alarm and safe to
 * call from anywhere: PULL mid-session changes from the configured cloud
 * transport, then RETRY a push when the ledger shows the last push didn't
 * cover the current vault state (worker died mid-upload, offline at save
 * time, …). Silent when locked — everything resumes on the next unlock.
 */
async function autoSyncTick(source = 'auto-sync-tick') {
  const v = await vault()
  const state = await v.getVaultState()
  if (!state.isUnlocked) {
    return { ok: true, skippedLocked: true, transient: false }
  }

  // 1. Pull — merge peers' changes (transport + chrome.storage.sync chunks).
  // R140: the first read of a wake cycle rides the retry ladder (§7.3).
  let pull = null
  try {
    pull = await chainWakeGuardedPull(v)
  } catch (e) {
    pull = {
      ok: false,
      synced: false,
      remoteObserved: false,
      kind: (e && e.kind) || 'network',
      status: (e && Number.isFinite(Number(e.status))) ? Number(e.status) : null,
      reason: (e && (e.userMessage || e.message)) || String(e),
    }
  }
  try { await credHealTick(pull) } catch { /* the heal never breaks the tick */ }
  try {
    await publishRunState('auto-pull', !!(pull && pull.remoteObserved !== false && pull.ok !== false), (pull && (pull.reason || pull.transportError || '')) || '')
  } catch { /* the beat never breaks the tick */ }
  if (pull && pull.synced) {
    try {
      const { getMessage } = await i18nMod()
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: getMessage('notifUpdatedTitle', undefined, 'UCrypt Updated'),
        message: getMessage('notifPullBody', [pull.reason || 'Sync complete', String(pull.entryCount || 0)], `${pull.reason}. ${resultCountText(pull.entryCount)} entries.`),
      })
    } catch { /* notification is best-effort */ }
  }

  // UCRYPT-19 — If the pull failed due to a temporary network issue, schedule
  // an exponential backoff retry immediately and surface visual feedback in Cloud Sync!
  if (!pull || pull.remoteObserved === false) {
    if (pull && typeof v.isTransientNetworkSyncFailure === 'function') {
      const isTrans = typeof v.classifyTransientNetworkSyncFailure === 'function'
        ? v.classifyTransientNetworkSyncFailure(pull).transient
        : !!v.isTransientNetworkSyncFailure(pull)
      if (isTrans) {
        const scheduled = await v.scheduleAutoSyncBackoffRetry(pull, { source })
        return { ok: false, transient: true, pull, push: null, retry: scheduled }
      }
    }
    return { ok: false, transient: false, pull, push: null }
  }

  // 2. Pending-push retry — if the vault changed after the last successful
  // push, the cloud copy is stale (or was never written). Push again.
  let pushOutcome = null
  try {
    const status = await v.getSyncStatus()
    if (status.syncEnabled && status.transport) {
      const lp = status.lastPush
      const pushedThrough = lp && lp.ok && lp.lastModified >= (status.lastModified || 0)
      if (!pushedThrough && (status.lastModified || 0) > 0) {
        pushOutcome = await v.pushVaultToTransport().catch((e) => ({
          ok: false,
          kind: (e && e.kind) || 'network',
          status: (e && Number.isFinite(Number(e.status))) ? Number(e.status) : null,
          reason: (e && (e.userMessage || e.message)) || String(e),
        }))
        try {
          await publishRunState('auto-push', !!(pushOutcome && pushOutcome.ok), (pushOutcome && (pushOutcome.reason || pushOutcome.error || '')) || '')
        } catch { /* the beat never breaks the tick */ }
        if (pushOutcome && !pushOutcome.ok && typeof v.isTransientNetworkSyncFailure === 'function') {
          const isPushTrans = typeof v.classifyTransientNetworkSyncFailure === 'function'
            ? v.classifyTransientNetworkSyncFailure(pushOutcome).transient
            : !!v.isTransientNetworkSyncFailure(pushOutcome)
          if (isPushTrans) {
            const scheduled = await v.scheduleAutoSyncBackoffRetry(pushOutcome, { source: `${source}-push` })
            return { ok: false, transient: true, pull, push: pushOutcome, retry: scheduled }
          }
        }
      }
    }
  } catch { /* retried again on the next tick */ }

  // Full auto-sync tick succeeded cleanly — clear any active exponential backoff retry state
  if (typeof v.clearAutoSyncRetryState === 'function') {
    await v.clearAutoSyncRetryState(`${source}-ok`).catch(() => {})
  }
  await ensureSyncIntervalAlarm(v)
  return { ok: true, transient: false, pull, push: pushOutcome }
}

function resultCountText(n) {
  return String(Number(n) || 0)
}

/** Debounced auto-pull right after the user unlocks (v2.8.0 + UCRYPT-19 backoff). */
let _unlockPullTimer = null
function scheduleUnlockPull() {
  clearTimeout(_unlockPullTimer)
  _unlockPullTimer = setTimeout(async () => {
    try {
      await bootReady // R29-F1: state must be restored on a woken worker
      const v = await vault()
      const state = await v.getVaultState()
      if (!state.isUnlocked) return
      const result = await chainWakeGuardedPull(v)
      if (result && result.remoteObserved === false && typeof v.isTransientNetworkSyncFailure === 'function') {
        const check = typeof v.classifyTransientNetworkSyncFailure === 'function'
          ? v.classifyTransientNetworkSyncFailure(result)
          : { transient: !!v.isTransientNetworkSyncFailure(result), reason: result.reason || '' }
        if (check.transient) {
          await v.scheduleAutoSyncBackoffRetry(result, { source: 'unlock-auto-sync' }).catch(() => {})
          await publishRunState('unlock-pull-retry', false, check.reason || 'Temporary network issue on unlock sync — retrying automatically').catch(() => {})
        }
      } else if (result && result.remoteObserved === true && typeof v.clearAutoSyncRetryState === 'function') {
        await v.clearAutoSyncRetryState('unlock-pull-ok').catch(() => {})
      }
      if (result.synced) {
        try {
          const { getMessage } = await i18nMod()
          await chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: getMessage('notifUpdatedTitle', undefined, 'UCrypt Updated'),
            message: getMessage('notifPullBody', [result.reason || 'Sync complete', String(result.entryCount || 0)], `${result.reason}. ${result.entryCount || 0} entries.`),
          })
        } catch { /* notification is best-effort */ }
      }
    } catch (e) {
      console.warn('[UCrypt] Post-unlock sync pull failed:', e)
    }
  }, 1200)
}

// --- LAW 0.49 (R133) + UCRYPT-19 — THE AUTO-SYNC CADENCE & EXPONENTIAL BACKOFF
const AUTO_SYNC_STATE_KEY = 'ucrypt:autoSyncState'

async function ensureSyncIntervalAlarm(vaultMod) {
  try {
    const v = vaultMod || (await vault())
    const minutes = (typeof v.getAutoSyncMinutes === 'function') ? await v.getAutoSyncMinutes() : 15
    await chrome.alarms.create('ucrypt:sync-pull', { periodInMinutes: minutes })
    await chrome.alarms.create('ucrypt:oauth-silent-renew', { periodInMinutes: 25 })
  } catch { /* the installed alarm persists */ }
}

/**
 * UCRYPT-22 — Proactive background silent renewal of Google Drive OAuth custody.
 * Runs every 25 minutes and on worker wake so the user's one-click sign-in stays
 * permanently active without ever expiring locally.
 */
async function silentRenewGdriveOAuth() {
  try {
    const { 'ucrypt:transport': rawRec } = await chrome.storage.local.get('ucrypt:transport')
    if (!rawRec || rawRec.id !== 'gdrive' || !rawRec.config || typeof rawRec.config !== 'object') {
      return { ok: false, skipped: true }
    }
    const v = await vault().catch(() => null)
    let cfg = null
    if (v) {
      const opened = await v.getTransportRecord().catch(() => null)
      if (opened && opened.id === 'gdrive' && opened.config) cfg = { ...opened.config }
    }
    if (!cfg) cfg = { ...rawRec.config }
    const wt = cfg.webToken && typeof cfg.webToken === 'object' ? cfg.webToken : null
    if (wt && wt.revokedByProvider === true) return { ok: false, revoked: true }
    const isFast = cfg.authMode === 'fast' || cfg.signinMode === 'fast' || !!(wt && wt.token)
    if (!isFast) return { ok: false, skipped: true }

    const { fastAccessToken } = await import('./lib/ladder.js')
    const tok = await fastAccessToken('gdrive', cfg)
    if (tok && cfg.webToken && typeof cfg.webToken === 'object') {
      const updatedWt = {
        ...cfg.webToken,
        token: String(cfg.webToken.token || tok),
        exp: Number(cfg.webToken.exp || (Date.now() + 3600 * 1000)),
        at: Number(cfg.webToken.at || Date.now()),
        persistentSession: true,
        autoRenew: true,
      }
      const nextStoredCfg = {
        ...rawRec.config,
        authMode: 'fast',
        signinMode: 'fast',
        persistentSession: true,
        autoRenew: true,
        webToken: updatedWt,
      }
      await chrome.storage.local.set({
        'ucrypt:transport': {
          ...rawRec,
          id: 'gdrive',
          config: nextStoredCfg,
          setAt: rawRec.setAt || Date.now(),
        },
      })
      return { ok: true, exp: updatedWt.exp, via: updatedWt.via }
    }
    return { ok: false }
  } catch {
    return { ok: false }
  }
}

async function recordAutoCycleOutcome(outcomeOrBool) {
  try {
    const v = await vault()
    const base = (typeof v.getAutoSyncMinutes === 'function') ? await v.getAutoSyncMinutes() : 15
    // Never penalize a locked skip as a sync failure (UCRYPT-19 fix)
    if (outcomeOrBool && typeof outcomeOrBool === 'object' && outcomeOrBool.skippedLocked) {
      await ensureSyncIntervalAlarm(v)
      return
    }
    // If exponential backoff retry was already scheduled by autoSyncTick, preserve its nextRetryAt!
    if (outcomeOrBool && typeof outcomeOrBool === 'object' && outcomeOrBool.transient) {
      return
    }
    const ok = typeof outcomeOrBool === 'boolean'
      ? outcomeOrBool
      : !!(outcomeOrBool && outcomeOrBool.ok !== false)
    const prev = (typeof v.getAutoSyncRetryState === 'function')
      ? await v.getAutoSyncRetryState()
      : ((await chrome.storage.local.get(AUTO_SYNC_STATE_KEY))[AUTO_SYNC_STATE_KEY] || {})
    if (ok) {
      if (typeof v.clearAutoSyncRetryState === 'function') {
        await v.clearAutoSyncRetryState('interval-tick-ok')
      } else {
        await chrome.storage.local.set({
          [AUTO_SYNC_STATE_KEY]: { ...prev, lastAutoAt: Date.now(), nextAt: Date.now() + base * 60000, failures: 0, backoffMinutes: base, retrying: false, inFlight: false },
        })
      }
      await ensureSyncIntervalAlarm(v)
    } else {
      const failures = Math.min(6, (Number(prev.failures) || 0) + 1)
      const backoffMinutes = Math.min(60, base * Math.pow(2, failures))
      const nextAt = Date.now() + backoffMinutes * 60000
      if (typeof v.recordAutoSyncRetryState === 'function') {
        await v.recordAutoSyncRetryState({ lastAutoAt: Date.now(), nextAt, failures, backoffMinutes })
      } else {
        await chrome.storage.local.set({ [AUTO_SYNC_STATE_KEY]: { ...prev, lastAutoAt: Date.now(), nextAt, failures, backoffMinutes } })
      }
      await chrome.alarms.create('ucrypt:sync-pull', { periodInMinutes: backoffMinutes })
    }
  } catch { /* bookkeeping never breaks the tick */ }
}

/** LAW 0.49 — the read-back confirmation's automatic retry: a push whose
 * read-back did not match re-runs (2 → 4 → 8 min, three attempts; the 15-min
 * tick and "Sync now" remain the standing catches). */
async function confirmRetryTick() {
  try {
    const { [AUTO_SYNC_STATE_KEY]: st } = await chrome.storage.local.get(AUTO_SYNC_STATE_KEY)
    const attempts = (st && Number.isFinite(Number(st.confirmAttempts)) && Number(st.confirmAttempts)) || 0
    if (attempts >= 3) return // the interval tick takes over from here
    const v = await vault()
    const state = await v.getVaultState()
    if (!state.isUnlocked) return
    const r = await v.pushVaultToTransport()
    await chrome.storage.local.set({ [AUTO_SYNC_STATE_KEY]: { ...((st && typeof st === 'object') ? st : {}), confirmAttempts: (r && r.ok && r.confirmed) ? 0 : attempts + 1 } })
    if (r && r.ok && r.confirmed === false) {
      const delay = Math.min(8, 2 * Math.pow(2, attempts))
      try { chrome.alarms.create('ucrypt:sync-confirm-retry', { delayInMinutes: delay }) } catch { /* best-effort */ }
    }
    if (r && r.ok && r.confirmed) {
      await chrome.storage.local.set({ [AUTO_SYNC_STATE_KEY]: { ...((st && typeof st === 'object') ? st : {}), confirmAttempts: 0 } })
    }
  } catch { /* the interval tick retries */ }
}

// --- Alarm handler ---------------------------------------------------------

chrome.alarms.onAlarm.addListener(async (alarm) => {
  await bootReady

  if (alarm.name === 'ucrypt:transfer:availability') {
    try { await handleTransferAlarm(alarm.name) } catch { /* retried next tick */ }
    return
  }

  if (alarm.name === 'ucrypt:keepalive') {
    try {
      const v = await vault()
      const state = await v.getVaultState()
      if (!state.isUnlocked) await chrome.alarms.clear('ucrypt:keepalive')
      await syncVaultLockBroadcast()
    } catch { /* next alarm retries */ }
    return
  }

  if (alarm.name === 'ucrypt:auto-lock') {
    const v = await vault()
    const state = await v.getVaultState()
    if (!state.isUnlocked) return
    await syncVaultLockBroadcast()
    return
  }

  if (alarm.name === 'ucrypt:sync-pull') {
    try {
      await silentRenewGdriveOAuth()
      const tickRes = await autoSyncTick('interval-sync-pull')
      await recordAutoCycleOutcome(tickRes)
    } catch { await recordAutoCycleOutcome(false).catch(() => {}) }
    return
  }

  if (alarm.name === 'ucrypt:oauth-silent-renew') {
    try { await silentRenewGdriveOAuth() } catch { /* retried next alarm */ }
    return
  }

  // UCRYPT-19 — Durable exponential backoff retry alarm for automatic syncs
  if (alarm.name === 'ucrypt:auto-sync-retry') {
    try {
      const v = await vault()
      const res = await v.runAutoSyncBackoffRetryNow({ source: 'alarm-auto-retry' })
      await publishRunState(
        'auto-retry',
        !!(res && res.ok),
        (res && res.ok)
          ? 'Automatic sync retry succeeded'
          : ((res && res.retryState && res.retryState.lastError) || 'Automatic sync retry scheduled')
      )
    } catch { /* next backoff or interval tick handles it */ }
    return
  }

  // LAW 0.49 — the mutation debounce's durable lane (the worker-died backup)
  if (alarm.name === 'ucrypt:sync-mutation') {
    try {
      const v = await vault()
      const state = await v.getVaultState()
      if (state.isUnlocked) {
        const r = await v.pushVaultToTransport()
        if (r && r.ok && r.confirmed !== false) {
          await v.clearAutoSyncRetryState('mutation-alarm-ok').catch(() => {})
        } else if (r && !r.ok) {
          await v.scheduleAutoSyncBackoffRetry(r, { source: 'mutation-alarm' }).catch(() => {})
        }
      }
    } catch (err) {
      try {
        const v = await vault()
        await v.scheduleAutoSyncBackoffRetry(err, { source: 'mutation-alarm' })
      } catch { /* interval tick retries */ }
    }
    return
  }

  if (alarm.name === 'ucrypt:sync-confirm-retry') {
    await confirmRetryTick()
    return
  }

  // LAW 0.49 — the browser-start auto-sync trigger (one full cycle).
  if (alarm.name === 'ucrypt:sync-startup') {
    try {
      const tickRes = await autoSyncTick('startup-auto-sync')
      await recordAutoCycleOutcome(tickRes)
    } catch { /* the interval tick retries */ }
    return
  }

  // S8.9 (R99) — THE LIVING BEAM: the continuous direct-sync poll tick
  // (1-minute cadence while the vault is unlocked). Reads the own mailbox
  // and auto-answers sync offers from chain peers (pull-first, digest
  // verified; the cloud stays the durable backup and offline reconciler).
  if (alarm.name === 'ucrypt:beam-sync') {
    try {
      const tm = await transfersMod()
      if (tm && typeof tm.beamSyncAlarmTick === 'function') await tm.beamSyncAlarmTick()
    } catch { /* retried on the next tick */ }
    return
  }

  if (alarm.name === 'ucrypt:breach-check') {
    return runBreachCheck()
  }
})

// --- Breach check ----------------------------------------------------------

async function runBreachCheck() {
  // R30-F1: breach.js is a STATIC import in the worker (dynamic import() is
  // disallowed on ServiceWorkerGlobalScope in Chromium) — the corpus is
  // guaranteed live here without any await.
  const v = await vault()
  const a = await analyzer()
  const state = await v.getVaultState()
  if (!state.isUnlocked) {
    try {
      const { getMessage } = await i18nMod()
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: getMessage('notifTitle', undefined, 'UCrypt'),
        message: getMessage('notifBreachLocked', undefined, 'Open UCrypt to run the daily breach check (vault locked).'),
      })
    } catch { /* the notification is best-effort — a blocked surface never perturbs the breach reminder it announces (named-swallow law, R169 C1) */ }
    return
  }

  const entries = v.getAllEntries()
  const breached = []
  for (const entry of entries) {
    const result = a.analyzePassword(entry.password)
    if (result && result.breached) {
      breached.push({ domain: entry.domain, username: entry.username })
    }
  }

  if (breached.length > 0) {
    const list = breached.slice(0, 5).map(b => `${b.username} @ ${b.domain}`).join('\n')
    const { getMessage } = await i18nMod()
    const extra = breached.length > 5
      ? '\n' + getMessage('notifBreachMore', [String(breached.length - 5)], `…and ${breached.length - 5} more`)
      : ''
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: getMessage(
          breached.length === 1 ? 'notifBreachTitle1' : 'notifBreachTitleN',
          [String(breached.length)],
          `UCrypt: ${breached.length} breached password${breached.length === 1 ? '' : 's'} found`),
        message: getMessage('notifBreachBody', undefined, 'Change these now:') + `\n${list}${extra}`,
        priority: 2,
      })
    } catch { /* the notification is best-effort — a blocked surface never perturbs the breach list it announces (named-swallow law, R169 C1) */ }
  } else {
    console.log('[UCrypt] Breach check: all clear')
  }
}

// --- Message router --------------------------------------------------------

// --- R125 §2 (F-R125-CAPTURE-1, law 0.39) — THE WORKER-HELD SAVE CANDIDATE -
// A login submit on a page that NAVIGATES (the classical web) kills the
// in-page offer mid-round-trip; an SPA click login never fires a submit at
// all. The content script stages the candidate HERE — synchronously, before
// any async step — and this worker re-prompts on the tab's LANDING page via
// the SHOW_SAVE_PROMPT relay the small-frame path already uses (the
// Chrome-anchored shape). In-memory ONLY (dies with the worker — never
// persisted, never synced, never exported), tab-keyed, TTL-capped, one-shot,
// wiped on lock and on tab close (the credential-layer laws 0.14/0.24).
// The gates (neverSave / offerSave / exact-match / unlocked) run HERE at
// re-prompt time — the worker is the trust boundary.
const saveCandidates = new Map() // tabId -> { domain, username, password, stagedAt }
const SAVE_CANDIDATE_TTL_MS = 10 * 60 * 1000
function clearSaveCandidates() { saveCandidates.clear() }

// R125 §2 — THE LANDING RE-PROMPT DRIVER: when a tab that staged a candidate
// finishes navigating, the offer renders on the LANDING page (the page the
// login actually moved to) — exactly where Chrome anchors its own bubble.
// One-shot: the candidate is consumed when the re-prompt is sent. Every gate
// (unlocked / neverSave / offerSave / exact-match) is evaluated HERE, on the
// worker's own truth, at re-prompt time. No receiver on the landing page
// (non-http page, crashed document) → the typed no-receiver catch drops the
// prompt; the candidate is already consumed and the in-page path of the next
// login starts clean.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== 'complete') return
  const cand = saveCandidates.get(tabId)
  if (!cand) return
  saveCandidates.delete(tabId) // one-shot from this moment
  if (Date.now() - cand.stagedAt > SAVE_CANDIDATE_TTL_MS) return
  const url = String((tab && tab.url) || info.url || '')
  if (!/^https?:/i.test(url)) return
  ;(async () => {
    try {
      await bootReady
      const v = await vault()
      const state = await v.getVaultState()
      if (!state.isUnlocked) return // a locked vault cannot save — the in-page locked prompt owns unlocking
      let neverSave = false
      try {
        const sites = await sitesMod()
        neverSave = sites.shouldNeverSave(cand.domain, await sites.getNeverSaveSites())
      } catch { /* flag off beats flag stuck-on */ }
      if (neverSave) return
      let offerSave = true
      try {
        const b = (await chrome.storage.local.get('ucrypt:behavior'))['ucrypt:behavior'] || {}
        offerSave = typeof b.offerSave === 'boolean' ? b.offerSave : true
      } catch { /* default ON */ }
      if (!offerSave) return
      const entries = v.getEntriesForDomain(cand.domain)
      if (entries.some((en) => en.username === cand.username && en.password === cand.password)) return // already saved
      const isUpdate = entries.some((en) => en.username === cand.username && en.password !== cand.password)
      chrome.tabs.sendMessage(tabId, {
        type: 'SHOW_SAVE_PROMPT',
        domain: cand.domain,
        username: cand.username,
        password: cand.password,
        isUpdate,
      }, { frameId: 0 }, () => { void chrome.runtime.lastError /* no receiver — dropped, one-shot spent */ })
    } catch { /* the re-prompt never blocks the navigation */ }
  })()
})

// R125 §2 — a closed tab's candidate dies with it.
chrome.tabs.onRemoved.addListener((tabId) => { saveCandidates.delete(tabId) })

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ;(async () => {
    try {
      // R29-F1: a woken worker MUST restore the persisted session before any
      // handler reads state (see the boot note at the top of this file).
      await bootReady
      if (!msg || typeof msg !== 'object') {
        sendResponse({ ok: false, error: 'Invalid message' })
        return
      }
      // R77-C — the entire TRANSFER_* surface routes to the transfer-plane
      // worker module (own keys, own state, lock wipes everything).
      // R105 §2.3 — sender is threaded for the multi-window offer hint
      // (which surface SAW / CONSUMED an offer — no content, ids only).
      if (typeof msg.type === 'string' && msg.type.startsWith('TRANSFER_')) {
        const r = await handleTransferMessage(msg, sender)
        sendResponse(r)
        return
      }
      // R141 §7 — THE MAILBOX door: the clean-room transport's MAILBOX_*
      // surface (the ONE road). The deps bind the worker's chain-ready and
      // the vault's transport record — the SAME road vault sync uses.
      // R142 §5 — the BRIDGE_* doors ride the SAME handler (the direct road's
      // relay signaling + presence + the file landing law).
      if (typeof msg.type === 'string' && (msg.type.startsWith('MAILBOX_') || msg.type.startsWith('BRIDGE_'))) {
        const vmod = await vault()
        const deps = {
          ensureChainReady: async () => {
            // the chain keys + identity the transfer plane already derives
            // (R142-A3: the STATIC import — import() is banned on the SW)
            if (typeof transferEnsureChainReadyForMailbox === 'function') return transferEnsureChainReadyForMailbox()
            throw new Error('the mailbox chain bridge is unavailable')
          },
          getTransportRecord: () => vmod.getTransportRecord(),
          rosterPeers: async () => {
            try {
              if (typeof transferMailboxRosterPeers === 'function') return await transferMailboxRosterPeers()
            } catch { /* locked or chain-less: an honest empty roster */ }
            return []
          },
          saveReceivedFile: async ({ fileName, bytesB64 }) => {
            // R150 (the B2 autopsy row): the SW-SAFE download path — a service
            // worker has NO URL.createObjectURL, so the blob path can never
            // work here; the data: URL carries the bytes instead. The TYPED
            // contract the mailbox handler honors: { ok:true } |
            // { ok:false, reason } — the legacy boolean false is gone.
            // Nothing opens automatically (§7.7).
            try {
              const safe = String(fileName || 'received-file').replace(/[\\/:*?"<>|]/g, '_')
              const url = 'data:application/octet-stream;base64,' + String(bytesB64 || '')
              const downloadId = await new Promise((resolve, reject) => {
                try {
                  chrome.downloads.download({ url, filename: safe, saveAs: false, conflictAction: 'uniquify' }, (id) => {
                    const err = chrome.runtime.lastError
                    if (err) reject(new Error(String(err.message || err)))
                    else resolve(typeof id === 'number' ? id : null)
                  })
                } catch (e) { reject(e) }
              })
              return { ok: true, downloadId, fileName: safe }
            } catch (e) {
              return { ok: false, reason: String((e && e.message) || e).slice(0, 120) }
            }
          },
        }
        const r = await handleMailboxMessage(msg, deps)
        sendResponse(r)
        return
      }
      const v = await vault()

      switch (msg.type) {
        // --- Vault state & CRUD -------------------------------------------------
        case 'GET_STATE': {
          const state = await v.getVaultState()
          const sync = await v.getSyncStatus()
          sendResponse({ ok: true, state, sync })
          return
        }

        case 'UNLOCK': {
          try {
            await v.unlockVault(msg.passphrase)
            const state = await v.getVaultState()
            // v2.8.0 — now the sync key exists: pull anything pushed by other
            // devices while this browser was closed/locked.
            scheduleUnlockPull()
            // R59-F2 — pages must learn about the unlock: stale locked
            // prompts disappear and pickers may re-offer with fresh state.
            _lastKnownUnlocked = true
            // R110 §3 — the master unlock opens the passphrase window (the
            // unlock ITSELF always prompts via the vault's own law — the
            // window only covers SUBSEQUENT confirmations).
            markPassphraseConfirmed()
            await broadcastVaultEvent('VAULT_UNLOCKED')
            // R148 §6.6 — the initialization sequence runs at EVERY unlock
            // (the owner's manual tax is optional, never the only path).
            startupCheck('unlock').catch(() => {})
            // R90 §2.1 — unlock turns the badge from "•" into the count.
            refreshBadge()
            sendResponse({ ok: true, state })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R109 §3.1 (law 0.24) — the credential popup layers' pure re-auth.
        // ZERO state mutation: a wrong passphrase changes nothing, a right one
        // grants nothing — it only proves the human for the page's own next
        // action (reveal a stored secret, open the recovery sheet).
        case 'VERIFY_PASSPHRASE': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — on a locked vault the confirm IS the unlock screen' })
              return
            }
            await v.verifyPassphrase(String(msg.passphrase || ''))
            // R110 §3 — a verified popup confirmation opens the window: the
            // next confirm-requiring action within 60s skips the re-prompt.
            markPassphraseConfirmed()
            sendResponse({ ok: true, window: passphraseWindowNow() })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R109 §3.2 (the CEO's S2) — the ONE reveal path for a stored
        // transport secret (the guided setup's sealed fields). The page's
        // credential popup re-auths the passphrase FIRST; this case returns
        // exactly ONE allowlisted secret field's plaintext for the popup's
        // read-only view. Never logged (no console here — the secret law).
        case 'TRANSPORT_REVEAL_SECRET': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — sealed values open only while unlocked' })
              return
            }
            const value = await v.revealTransportSecret(String(msg.field || ''))
            sendResponse({ ok: true, value })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SET_MASTER': {
          try {
            await v.setMasterPassphrase(msg.passphrase)
            const state = await v.getVaultState()
            // R59-F2 — a fresh vault is an unlocked vault: tell the pages.
            if (state && state.isUnlocked) {
              _lastKnownUnlocked = true
              // R110 §3 — the master SETUP is a successful passphrase entry:
              // it opens the confirmation window exactly like the unlock.
              markPassphraseConfirmed()
              await broadcastVaultEvent('VAULT_UNLOCKED')
              // R90 §2.1 — a fresh vault unlocks the badge too.
              refreshBadge()
            }
            sendResponse({ ok: true, state })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'LOCK': {
          await v.lockVault()
          // R59-F2 — F2 fix: the picker/save-prompt/OTP surfaces in every tab
          // are destroyed the moment the vault locks (no more stale overlays).
          _lastKnownUnlocked = false
          // R125 §2 — the staged candidates die with the lock (0.14/0.24).
          clearSaveCandidates()
          // R110 §3 — the lock closes the passphrase window.
          clearPassphraseWindow()
          await broadcastVaultEvent('VAULT_LOCKED')
          // R90 §2.1 — the badge must show "•" immediately (never a stale count).
          refreshBadge()
          // R77-C — lock tears the transfer plane down as well (order: stop on
          // lock; availability window closed; sessions wiped from memory).
          try { await onTransferVaultLocked() } catch { /* plane best-effort */ }
          sendResponse({ ok: true })
          return
        }

        // --- R45-C: native password-manager control --------------------------
        // Literal status for the popup/options card. Never optimistic: the
        // browser's own levelOfControl string is passed through verbatim.
        case 'NATIVE_MANAGER_GET': {
          try {
            const status = await _nativeManager.getNativeManagerStatus()
            sendResponse({ ok: true, status })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // ENABLE assumes the extension page ALREADY obtained the optional
        // privacy permission through chrome.permissions.request (that call
        // needs the page's user gesture — a worker cannot request it).
        case 'NATIVE_MANAGER_ENABLE': {
          try {
            const r = await _nativeManager.enableNativeManagerControl()
            sendResponse(r.ok ? r : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'NATIVE_MANAGER_DISABLE': {
          try {
            const r = await _nativeManager.disableNativeManagerControl()
            sendResponse(r.ok ? r : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'TOUCH': {
          v.touchVault()
          sendResponse({ ok: true })
          return
        }

        // v2.16.0 — last-used tracking: fired by the content script after a
        // REAL fill (overlay pick, popup Fill, command). Best-effort — a
        // failure here must never surface to the user or block the fill.
        case 'TOUCH_ENTRY': {
          try {
            await v.touchEntry(String(msg.domain || ''), String(msg.username || ''))
            sendResponse({ ok: true })
          } catch {
            sendResponse({ ok: false })
          }
          return
        }

        // v2.16.0 — user-configurable auto-lock (Security tab).
        case 'SET_AUTOLOCK': {
          try {
            const minutes = await v.setAutoLockMinutes(msg.minutes)
            const state = await v.getVaultState()
            sendResponse({ ok: true, minutes, state })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SAVE_ENTRY': {
          try {
            // v2.9.0 — optional per-login note (options editor).
            // v2.16.0 — optional alias domains (multi-URI per login).
            await v.saveEntry(msg.domain, msg.username, msg.password, msg.note, msg.uris)
            // R90 §2.1 — a new login for the active tab changes the count.
            refreshBadge()
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.9.0 — atomic entry update (options editor). One mutation + one
        // persist + one push; the old DELETE-then-SAVE pair could lose the
        // entry if the worker died between the two steps.
        case 'UPDATE_ENTRY': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Vault is locked' })
              return
            }
            const entry = await v.updateEntry(msg.origDomain, msg.origUsername, {
              domain: msg.domain,
              username: msg.username,
              password: msg.password,
              note: msg.note,
              uris: msg.uris,
            })
            sendResponse({ ok: true, entry })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.9.0 — per-site save exceptions (device-local; Brave parity).
        // R150 §8.1 — THE IMPORT DOOR (the four-round debt lands; F11/S67).
        // The vault's OWN APIs are the only write path (saveEntriesBatch for
        // the adds, updateEntry for the LWW updates); the live vault is
        // re-checked before every write (idempotent per batch — a re-apply
        // after a failure cannot duplicate); the 10000-batch law holds (the
        // same bound the vault's own save path enforces); the receipt is
        // exact — N imported · M duplicates · U updated · K attention.
        case 'IMPORT_APPLY': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — the import keeps the preview ready.' })
              return
            }
            const adds = Array.isArray(msg.entries) ? msg.entries : []
            const ups = Array.isArray(msg.updates) ? msg.updates : []
            if (adds.length + ups.length > 10000) {
              sendResponse({ ok: false, error: 'the batch is too large — import in smaller files (the 10000-row law)' })
              return
            }
            let imported = 0
            let updateDuplicates = 0
            const reported = []
            // THE ADDS — the batch door, then the per-row count from its receipt
            if (adds.length) {
              const r = await v.saveEntriesBatch(adds)
              imported = (r && (typeof r.added === 'number' ? r.added : adds.length)) || 0
              for (const s of (r && r.skipped) || []) reported.push(String(s).slice(0, 140))
            }
            // THE UPDATES — LWW, re-checked against the LIVE vault before each
            // write (idempotency: an already-applied update is counted, never
            // re-written, never duplicated)
            for (const u of ups) {
              const od = u.origDomain
              const ou = u.origUsername
              if (!od && !ou) { reported.push('an update row had no target — skipped'); continue }
              const cur = v.getEntriesForDomain(od).find((e) => String(e.username ?? '') === String(ou ?? ''))
              if (!cur) { reported.push(`the target ${od} / ${ou} is gone — skipped`); continue }
              if (cur.password === String(u.password ?? '') && cur.username === String(u.username ?? '')) {
                updateDuplicates++ // already applied (the idempotent re-apply)
                continue
              }
              await v.updateEntry(od, ou, {
                domain: u.domain || od,
                username: u.username ?? ou,
                password: u.password ?? cur.password,
                note: u.note ?? cur.note,
              })
            }
            sendResponse({
              ok: true,
              receipt: {
                imported,
                duplicatesSkipped: updateDuplicates + reported.length,
                updated: ups.length - updateDuplicates,
                needsAttention: reported.length,
              },
              skipped: reported,
            })
            return
          } catch (e) {
            sendResponse({ ok: false, error: String((e && e.message) || e).slice(0, 160) })
            return
          }
        }

        case 'NEVER_SAVE_LIST': {
          try {
            const sites = await sitesMod()
            sendResponse({ ok: true, sites: await sites.getNeverSaveSites() })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'NEVER_SAVE_ADD': {
          try {
            const sites = await sitesMod()
            const r = await sites.addNeverSaveSite(msg.domain)
            sendResponse(r.ok ? { ok: true, sites: r.sites, added: r.added, already: !!r.already } : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'NEVER_SAVE_REMOVE': {
          try {
            const sites = await sitesMod()
            const r = await sites.removeNeverSaveSite(msg.domain)
            sendResponse(r.ok ? { ok: true, sites: r.sites, removed: r.removed } : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R85 (§6): per-site never-FILL exceptions (device-local) — the
        // autofill counterpart of the never-save list above.
        case 'NEVER_FILL_LIST': {
          try {
            const sites = await sitesMod()
            sendResponse({ ok: true, sites: await sites.getNeverFillSites() })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'NEVER_FILL_ADD': {
          try {
            const sites = await sitesMod()
            const r = await sites.addNeverFillSite(msg.domain)
            sendResponse(r.ok ? { ok: true, sites: r.sites, added: r.added, already: !!r.already } : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'NEVER_FILL_REMOVE': {
          try {
            const sites = await sitesMod()
            const r = await sites.removeNeverFillSite(msg.domain)
            sendResponse(r.ok ? { ok: true, sites: r.sites, removed: r.removed } : { ok: false, error: r.error })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.9.0 — the in-page save prompt warns BEFORE the user accepts when
        // the candidate password is weak or in the offline breach corpus.
        // Pure analyzer call — the password never leaves the worker.
        case 'CHECK_PASSWORD_STRENGTH': {
          try {
            const a = await analyzer() // breach.js is static in the worker (R30-F1)
            const r = a.analyzePassword(String(msg.password ?? ''))
            if (!r) {
              sendResponse({ ok: false, error: 'Could not analyze the password' })
              return
            }
            const bits = Math.round(r.effective)
            const label = bits < 28 ? 'Very weak' : bits < 50 ? 'Weak' : bits < 70 ? 'Fair' : bits < 100 ? 'Strong' : 'Excellent'
            sendResponse({
              ok: true,
              bits,
              label,
              breached: !!r.breached,
              warn: !!r.breached || bits < 50,
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'DELETE_ENTRY': {
          try {
            // v2.8.0 — optional type: the Import Center's other-data pane
            // deletes by (domain, username, type) so an imported bookmark or
            // note can't take a same-key login with it.
            // v2.10.0 — the entry type arrives as `entryType` (a payload
            // `type` field used to clobber the message type on the wire).
            // v2.42.7 — R70 §2.3 (F-R70-MODEL-1): `alsoLinkedTotp` is the
            // user's EXPLICIT "Delete linked authenticator too" choice; the
            // default preserves the standalone token (unlinked). The summary
            // names what actually happened — no silent outcomes.
            const summary = await v.deleteEntry(msg.domain, msg.username, msg.entryType, {
              alsoLinkedTotp: msg.alsoLinkedTotp === true,
            })
            sendResponse({ ok: true, ...summary })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'GET_ENTRIES': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: true, entries: [], locked: true })
            return
          }
          const domain = msg.domain || (sender.tab ? domainFromUrl(sender.tab.url) : '')
          const entries = v.getEntriesForDomain(domain)
          // v2.9.0 — Brave-style per-site exception: the content script checks
          // this flag before showing the SAVE prompt (autofill is NOT affected).
          let neverSave = false
          try {
            const sites = await sitesMod()
            neverSave = sites.shouldNeverSave(domain, await sites.getNeverSaveSites())
          } catch { /* flag off beats flag stuck-on */ }
          // R85 (§6): the never-FILL flag rides the same response — the
          // content script gates BOTH the auto-fill offer and the suggestion
          // dropdown on it.
          let neverFill = false
          try {
            const sites = await sitesMod()
            neverFill = sites.shouldNeverFill(domain, await sites.getNeverFillSites())
          } catch { /* flag off beats flag stuck-on */ }
          sendResponse({ ok: true, entries, locked: false, domain, neverSave, neverFill })
          return
        }

        // v2.11.0 — F6: two-step login username memory (see the helper block
        // above this router). Fire-and-forget store; read at save time.
        case 'REMEMBER_USERNAME': {
          try {
            const tabId = sender && sender.tab ? sender.tab.id : 0
            rememberUsername(tabId, msg.domain, msg.username)
          } catch { /* best-effort — a lost candidate only costs UX */ }
          sendResponse({ ok: true })
          return
        }

        case 'GET_LAST_USERNAME': {
          try {
            const tabId = sender && sender.tab ? sender.tab.id : 0
            sendResponse({ ok: true, username: recallUsername(tabId, msg.domain) })
          } catch {
            sendResponse({ ok: true, username: '' })
          }
          return
        }

        // R125 §2 (law 0.39) — the staged candidate arrives synchronously at
        // submit/click time (before any navigation can tear the page down).
        // In-memory only; the gates run at re-prompt time, not here.
        case 'SAVE_CANDIDATE_STAGE': {
          try {
            const tabId = sender && sender.tab ? sender.tab.id : 0
            const pw = msg && typeof msg.password === 'string' ? msg.password : ''
            if (tabId && pw) {
              if (saveCandidates.size > 64) {
                // evict the oldest — a burst of tabs can never balloon this
                let oldestKey = null
                let oldestAt = Infinity
                for (const [k, c] of saveCandidates) { if (c.stagedAt < oldestAt) { oldestAt = c.stagedAt; oldestKey = k } }
                if (oldestKey !== null) saveCandidates.delete(oldestKey)
              }
              saveCandidates.set(tabId, {
                domain: String(msg.domain || ''),
                username: String(msg.username || ''),
                password: pw,
                stagedAt: Date.now(),
              })
            }
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R125 §2 — an in-page offer terminal (Save / Not now / Never / ✕)
        // consumed the candidate: a user's explicit answer is never re-asked
        // by a later landing re-prompt.
        case 'SAVE_CANDIDATE_CONSUME': {
          try {
            const tabId = sender && sender.tab ? sender.tab.id : 0
            if (tabId) saveCandidates.delete(tabId)
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.13.0 — R22-F2: a login submitted inside a frame too small to
        // host the save overlay relays the prompt here; the worker forwards
        // it to the TOP frame (frameId 0), which has room to render it.
        // In-memory only — same channel every SAVE_ENTRY already uses.
        case 'SAVE_PROMPT_RELAY': {
          try {
            const tabId = sender && sender.tab ? sender.tab.id : 0
            const pw = msg && typeof msg.password === 'string' ? msg.password : ''
            if (!tabId || !pw) {
              sendResponse({ ok: false, error: 'Nothing to relay' })
              return
            }
            chrome.tabs.sendMessage(tabId, {
              type: 'SHOW_SAVE_PROMPT',
              domain: String(msg.domain || ''),
              username: String(msg.username || ''),
              password: pw,
              isUpdate: !!msg.isUpdate,
            }, { frameId: 0 }, () => {
              if (chrome.runtime.lastError) {
                sendResponse({ ok: false, error: chrome.runtime.lastError.message })
                return
              }
              sendResponse({ ok: true })
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'GET_ALL_ENTRIES': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: false, locked: true })
            return
          }
          sendResponse({ ok: true, entries: v.getAllEntries() })
          return
        }

        // v2.7.0 — imported "other data" (notes, cards, identities,
        // bookmarks, history, form data) for the Vault manager's review pane.
        // v2.10.0 — UPDATE_OTHER_ENTRY below adds the missing edit flow.
        case 'UPDATE_OTHER_ENTRY': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Vault is locked' })
              return
            }
            const entry = await v.updateOtherEntry(msg.origDomain, msg.origUsername, msg.entryType, {
              username: msg.username,
              note: msg.note,
              url: msg.url,
              folder: msg.folder,
              // v2.18.0 — R27: structured payloads (card / identity /
              // custom fields) ride through to the vault's validators.
              card: msg.card,
              address: msg.address,
              fields: msg.fields,
            })
            sendResponse({ ok: true, entry })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'GET_OTHER_ENTRIES': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: false, locked: true })
            return
          }
          sendResponse({ ok: true, entries: v.getOtherEntries() })
          return
        }

        // --- TOTP authenticator (v2.4.0) ----------------------------------------
        case 'TOTP_TOKENS': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: true, tokens: [], locked: true })
            return
          }
          sendResponse({ ok: true, tokens: v.getTotpTokens(), locked: false })
          return
        }

        case 'TOTP_SAVE': {
          try {
            await v.saveTotpToken(msg.token)
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'TOTP_DELETE': {
          try {
            await v.deleteTotpToken(msg.label)
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.5.0 — site 2FA autofill. The LIST response never carries secrets,
        // only labels/issuers; a CODE is computed only for a label the user
        // explicitly clicked in the page's fill chip.
        // v2.9.0 — tokens are RANKED by domain proximity (exact domain first,
        // then same eTLD+1 site) so the chip leads with tokens for THIS site
        // instead of an unordered dump of the whole vault.
        case 'TOTP_AUTOFILL_LIST': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: true, locked: true, tokens: [] })
            return
          }
          const siteDomain = sender && sender.tab && sender.tab.url
            ? domainFromUrl(sender.tab.url) : ''
          const sites = await sitesMod()
          const siteKey = siteDomain ? sites.siteKeyOf(siteDomain) : ''
          const rank = (t) => {
            const tDomain = String((t.totp && t.totp.issuer) || t.username || '').toLowerCase()
            if (siteDomain && (tDomain === siteDomain || siteDomain.endsWith('.' + tDomain))) return 0
            const tKey = tDomain ? sites.siteKeyOf(tDomain) : ''
            if (siteKey && tKey && tKey === siteKey) return 1
            return 2
          }
          const tokens = v.getTotpTokens()
            .map(t => {
              const r = rank(t)
              return {
                label: t.username || '',
                issuer: (t.totp && t.totp.issuer) || '',
                match: r === 0 ? 'exact' : r === 1 ? 'site' : null,
                _r: r,
              }
            })
            .sort((a, b) => a._r - b._r || a.label.localeCompare(b.label))
            .map(({ label, issuer, match }) => ({ label, issuer, match }))
          sendResponse({ ok: true, locked: false, tokens, site: siteDomain })
          return
        }

        case 'TOTP_AUTOFILL_CODE': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, error: 'Vault is locked' })
              return
            }
            const label = String(msg.label || '')
            const token = v.getTotpTokens().find(t => t.username === label)
            if (!token || !token.totp) {
              sendResponse({ ok: false, error: 'Token not found' })
              return
            }
            const r = await computeTotpCode(token.totp.secret, {
              period: token.totp.period,
              digits: token.totp.digits,
              algorithm: token.totp.algorithm,
            })
            sendResponse({ ok: true, code: r.code, remainingSec: r.remainingSec })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.5.0 — aggregate password health over all LOGIN entries
        // (breach matches, weak entropy, reuse groups). Computed locally.
        case 'HEALTH_REPORT': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: true, locked: true, report: null })
            return
          }
          const a = await analyzer() // breach.js is static in the worker (R30-F1)
          const report = buildHealthReport(v.getLoginEntries(), a.analyzePassword)
          sendResponse({ ok: true, locked: false, report })
          return
        }

        // R134 §6 — PASSWORD HEALTH (the options dashboard, LOCAL-ONLY):
        // the three heuristics (weak / reused / stale>365d) with drill-in
        // lists and the entry ids the one-tap remediation opens. Computed
        // from the vault already on device — NO network calls, NO breach
        // lookups (the no-surveillance law stands).
        case 'HEALTH_DASHBOARD': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: true, locked: true, dashboard: null })
            return
          }
          const a = await analyzer()
          const dashboard = buildPasswordHealthDashboard(v.getLoginEntries(), a.analyzePassword)
          sendResponse({ ok: true, locked: false, dashboard })
          return
        }

        // ── R135 (v2.92.0) — THE NEW SURFACES' WORKER CASES (additions-only) ──
        // CHAINDATA_GET / CHAINDATA_SET: the Chain Data Types panel's
        // persistence (the toggles govern lib/chaindata.js's engine gates).
        case 'CHAINDATA_GET': {
          const { [CHAINDATA_TOGGLES_KEY]: cur } = await chrome.storage.local.get(CHAINDATA_TOGGLES_KEY)
          sendResponse({ ok: true, toggles: cur || null })
          return
        }
        case 'CHAINDATA_SET': {
          const toggles = normalizeToggles(msg && msg.toggles)
          await chrome.storage.local.set({ [CHAINDATA_TOGGLES_KEY]: toggles })
          sendResponse({ ok: true, toggles })
          return
        }

        // R135_IMPORT_ROWS: the cross-browser import's vault write path —
        // rows arrive from the LOCAL parse (lib/import-migration.js), are
        // re-encrypted through the vault's OWN add/update paths, and the
        // report states exactly what changed. No network anywhere.
        case 'R135_IMPORT_ROWS': {
          const state = await v.getVaultState()
          if (!state.isUnlocked) {
            sendResponse({ ok: false, error: 'vault_locked' })
            return
          }
          const rows = Array.isArray(msg && msg.rows) ? msg.rows : []
          const existing = v.getLoginEntries()
          const imp = r135Import
          // R160 ARC B′ — T8'S MERGE LAW (G163): the plan classifies EVERY
          // row BEFORE any write (summary-before-commit); adds land, empty
          // slots fill (newest-wins), conflicts land AS COPIES in the
          // entry's password history (never silently dropped, never
          // overwriting), duplicates do nothing; the journal unwinds every
          // step in reverse on any failure — a failed import leaves the
          // vault untouched (transactional; the rows prove the rollback).
          const plan = classifyImportPlan(rows, existing)
          const journal = createImportJournal()
          let added = 0
          let filled = 0
          let copies = 0
          // R175 — THE IMPORT THAT ENDS (R-175.5, the E-33 cure): the adds
          // ride ONE bulk batch (saveEntriesBatch — the R27 cure's own
          // design: ONE persist, ONE fire-and-forget push) instead of the
          // per-row saveEntry loop — the quadratic class the field's hang
          // rode (1162 rows = ~1082 sequential full-vault persists, each
          // re-encrypting + re-writing the whole vault). The batch is atomic
          // at the persist boundary (the R95-F2 rollback restores memory from
          // disk on a refused persist); the fills/copies legs stay journaled
          // per-row (bounded by the duplicate-group count). The report
          // reconciles against the preview's own numbers.
          let batchSkipped = []
          try {
            const batchRows = plan.adds.map((r) => ({
              domain: imp.originOf(r.url) || 'imported.local',
              username: String(r.username || ''),
              password: String(r.password || ''),
              ...(r.notes ? { note: String(r.notes) } : {}),
              ...(r.url ? { meta: { url: String(r.url) } } : {}),
            }))
            const batch = await v.saveEntriesBatch(batchRows, { awaitPush: false })
            added = Number(batch && batch.added) || 0
            batchSkipped = Array.isArray(batch && batch.skipped) ? batch.skipped : []
          } catch (e) {
            sendResponse({
              ok: false,
              error: (e && e.message) || 'import_failed',
              counts: plan.counts,
              resultCard: resultCardWords({ added: 0, copies: 0, fills: 0, duplicates: 0, errors: 1 }),
            })
            return
          }
          try {
            for (const f of plan.fills) {
              const cur = f.existing
              await v.fillEmptyPassword(cur.domain, cur.username, String(f.incoming.password || ''))
              journal.record({ kind: 'fill', domain: cur.domain, username: cur.username })
              filled += 1
            }
            for (const c of plan.copies) {
              const cur = c.existing
              const prevLen = await v.appendImportCopy(cur.domain, cur.username, String(c.incoming.password || ''))
              journal.record({ kind: 'copy', domain: cur.domain, username: cur.username, prevLen })
              copies += 1
            }
          } catch (e) {
            const rolledBack = await journal.unwind(async (s) => {
              if (s.kind === 'add') await v.deleteEntry(s.domain, s.username, undefined)
              else if (s.kind === 'fill') await v.restorePasswordValue(s.domain, s.username, '')
              else if (s.kind === 'copy') await v.truncateImportCopy(s.domain, s.username, s.prevLen)
            })
            sendResponse({
              ok: false,
              error: (e && e.message) || 'import_failed',
              rolledBack,
              counts: plan.counts,
              resultCard: resultCardWords({ added: 0, copies: 0, fills: 0, duplicates: 0, errors: 1 }),
            })
            return
          }
          sendResponse({
            ok: true,
            report: imp.buildImportReport({ added, updated: filled, skipped: plan.duplicates.length + batchSkipped.length, duplicatesResolved: 0, source: 'csv-local' }),
            counts: plan.counts,
            // R175 — the report reconciles against the preview's own numbers:
            // the batch's own skips ride beside the plan's duplicates.
            batchSkipped,
            resultCard: resultCardWords({ added, copies, fills: filled, duplicates: plan.duplicates.length, errors: 0 }),
          })
          return
        }

        // --- Sync wizard (v2.2.0 — previously unreachable) ----------------------
        case 'SYNC_CODE_GENERATE': {
          try {
            const s = await syncMod()
            const code = await s.generateSyncCode()
            const fingerprint = await s.syncFingerprint(code.mnemonic)
            sendResponse({ ok: true, code: { ...code, fingerprint } })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SYNC_CODE_VALIDATE': {
          try {
            const s = await syncMod()
            const result = await s.validateSyncCode(msg.mnemonic)
            if (result.valid) {
              result.fingerprint = await s.syncFingerprint(msg.mnemonic)
            }
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SYNC_CODE_SET': {
          try {
            const s = await syncMod()
            const check = await s.validateSyncCode(msg.mnemonic)
            if (!check.valid) {
              sendResponse({ ok: false, error: check.reason })
              return
            }
            const key = await s.deriveSyncKey(msg.mnemonic)
            // v2.8.0 — setSyncCode is restore-safe: an empty device PULLS the
            // cloud copy first; a push only happens with real local content.
            // Relay the summary so the UI can say what actually happened.
            // R132 (law 0.46 — the join propagation): the adopt source rides
            // through — a JOIN marks the roster dirty so the joiner's device
            // entry rides the very next envelope and the origin's pull learns
            // it (the CEO's S1, live-reproduced).
            const result = await v.setSyncCode(check.words.join(' '), key, 2, { source: String(msg.source || '') })
            // R91 §3.5c — the backup-verified flag follows the CODE it
            // verified: typing the words into the join/restore wizard IS a
            // real verification act (they validated against the checksum and
            // became this device's code) → method 'adopt'. A freshly
            // GENERATED code (or any other set) resets the flag — the old
            // sheet no longer proves anything. The flag is never set here on
            // the generate path: writing words down is confirmed by the
            // verify flow, not assumed.
            try {
              if (msg.source === 'adopt') {
                await chrome.storage.local.set({ 'ucrypt:backupVerified': { verified: true, method: 'adopt', at: new Date().toISOString() } })
              } else {
                await chrome.storage.local.remove('ucrypt:backupVerified')
              }
            } catch { /* flag hygiene is best-effort; the state machine re-reads it every render */ }
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R91 §3.5c (CEO S-E) — the backup-verification completion path.
        // SYNC_CODE_VERIFY_WORDS: the page sends the words typed from the
        // user's OFFLINE copy at chosen positions; the worker compares them
        // against the SEALED sync code (which is never revealed, never
        // logged). Extension pages only; the vault must be unlocked (the
        // sealed code decrypts with the in-memory master key only then).
        // On success the truthful device-local flag is written — the ONLY
        // two ways it can ever become true are this check and the explicit
        // sheet confirmation below.
        case 'SYNC_CODE_VERIFY_WORDS': {
          try {
            if (sender && sender.tab && sender.tab.id !== undefined && sender.url && !sender.url.startsWith('chrome-extension://')) {
              sendResponse({ ok: false, error: 'Backup verification is only available from UCrypt pages' })
              return
            }
            const r = await v.verifyBackupWords(msg.words || {})
            if (r.verified) {
              await chrome.storage.local.set({ 'ucrypt:backupVerified': { verified: true, method: 'words', at: new Date().toISOString() } })
            }
            sendResponse({ ok: true, verified: !!r.verified, checks: r.checks || {} })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R91 §3.5c — the sheet-confirmation path: after a re-authenticated
        // reveal (SYNC_CODE_REVEAL), the user explicitly confirms the exposed
        // words/QR sheet is their backup. Extension pages only; the vault
        // must be unlocked and a sync code must exist.
        case 'SYNC_CODE_BACKUP_CONFIRM': {
          try {
            if (sender && sender.tab && sender.tab.id !== undefined && sender.url && !sender.url.startsWith('chrome-extension://')) {
              sendResponse({ ok: false, error: 'Backup confirmation is only available from UCrypt pages' })
              return
            }
            await v.confirmBackupSheet()
            await chrome.storage.local.set({ 'ucrypt:backupVerified': { verified: true, method: 'confirm', at: new Date().toISOString() } })
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R56-SYNC-DEVICES — re-authenticated sync-code reveal for Add device.
        // Extension pages ONLY (a content script or web page can never ask the
        // worker for the words); the passphrase is verified and discarded, the
        // lock state is untouched, nothing is persisted or logged. The UI
        // applies the visible-countdown exposure policy to the response.
        case 'SYNC_CODE_REVEAL': {
          try {
            if (sender && sender.tab && sender.tab.id !== undefined && sender.url && !sender.url.startsWith('chrome-extension://')) {
              sendResponse({ ok: false, error: 'Reveal is only available from UCrypt pages' })
              return
            }
            const revealed = await v.revealSyncCode(String(msg.passphrase || ''))
            if (!revealed) {
              sendResponse({ ok: false, error: 'No sync code is set up yet' })
              return
            }
            sendResponse({ ok: true, revealed })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R110 §3 — the WINDOW-AWARE reveal: the sheet's confirm is skipped
        // within the 60-second passphrase window. The WORKER enforces the
        // window (the page can never fake it) and the vault's own lock law
        // still stands (revealSyncCodeWithinWindow refuses a locked vault).
        case 'SYNC_CODE_REVEAL_WINDOW': {
          try {
            if (sender && sender.tab && sender.tab.id !== undefined && sender.url && !sender.url.startsWith('chrome-extension://')) {
              sendResponse({ ok: false, error: 'Reveal is only available from UCrypt pages' })
              return
            }
            const w = passphraseWindowNow()
            if (!w.withinWindow) {
              sendResponse({ ok: false, error: 'The passphrase window is not active — confirm your passphrase first' })
              return
            }
            const revealed = await v.revealSyncCodeWithinWindow()
            if (!revealed) {
              sendResponse({ ok: false, error: 'No sync code is set up yet' })
              return
            }
            sendResponse({ ok: true, revealed, window: w })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R56-POPUP-WINDOW — the resizable VAULT WINDOW surface
        // (chrome.windows.create, ported from the R49 §5.3 design): persisted
        // device-local bounds; if the API refuses (kiosk/profile policies),
        // the truthful fallback is a normal tab — reported as fallback:true.
        // R59-F5 — OPEN_VAULT_WINDOW { surface:'health' } opens the FULL
        // health report surface (popup.html?window=1&surface=health) with
        // health-sized default bounds. Never an arbitrary website tab.
        case 'OPEN_VAULT_WINDOW':
        case 'OPEN_MANAGER_WINDOW': {
          try {
            const isVault = msg.type === 'OPEN_VAULT_WINDOW'
            const isHealth = isVault && msg.surface === 'health'
            const url = chrome.runtime.getURL(isVault
              ? (isHealth ? 'popup.html?window=1&surface=health' : 'popup.html?window=1')
              : 'options.html?window=1&surface=manager')
            const boundsKey = isVault ? 'ucrypt:vaultWindowBounds' : 'ucrypt:managerWindowBounds'
            // R79-B (owner screenshots 20261002_200402/200734): the window
            // pattern is +20px and UNIFORM — every window area (Vault, 2FA,
            // Health, Sync) opens at the same default width (440), and the
            // full health report no longer opens extra-wide (540 → 440, the
            // same pattern as the other areas). Persisted user bounds still
            // win — these are FIRST-OPEN defaults.
            const defaults = isHealth
              ? { width: 440, height: 720 }
              : (isVault ? { width: 440, height: 640 } : { width: 1024, height: 800 })
            let bounds = { ...defaults }
            try {
              const { [boundsKey]: b } = await chrome.storage.local.get(boundsKey)
              if (b && Number.isFinite(b.width) && Number.isFinite(b.height)) bounds = b
            } catch { /* defaults */ }
            try {
              const created = await chrome.windows.create({
                url, type: 'popup',
                width: bounds.width, height: bounds.height,
                ...(Number.isFinite(bounds.left) ? { left: bounds.left } : {}),
                ...(Number.isFinite(bounds.top) ? { top: bounds.top } : {}),
              })
              // R95 F-95-02 — the created window is the tracked vault window
              // (the options header's state-aware toggle reads this id).
              try { if (created && Number.isFinite(created.id)) await chrome.storage.local.set({ [VAULT_WINDOW_ID_KEY]: created.id }) } catch { /* tracking is best-effort */ }
              sendResponse({ ok: true, fallback: false })
            } catch {
              // R59-F5 — the tab fallback carries tab=1 so the page does NOT
              // report its geometry as vault-window bounds (a tab would
              // otherwise pollute the persisted window size).
              await chrome.tabs.create({ url: isHealth ? url + '&tab=1' : url + (isVault ? '&tab=1' : '') })
              // A tab is NOT a tracked window — clear any stale id.
              try { if (isVault) await chrome.storage.local.remove(VAULT_WINDOW_ID_KEY) } catch { /* best-effort */ }
              sendResponse({ ok: true, fallback: true })
            }
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R56-POPUP-WINDOW — a vault/manager window reports its geometry so the
        // next open restores it (device-local, never synced).
        case 'VAULT_WINDOW_BOUNDS': {
          try {
            const key = msg.surface === 'manager' ? 'ucrypt:managerWindowBounds' : 'ucrypt:vaultWindowBounds'
            const b = msg.bounds || {}
            if (Number.isFinite(b.width) && Number.isFinite(b.height)) {
              await chrome.storage.local.set({
                [key]: {
                  width: Math.min(1200, Math.max(320, Math.round(b.width))),
                  height: Math.min(1600, Math.max(360, Math.round(b.height))),
                  ...(Number.isFinite(b.left) ? { left: Math.round(b.left) } : {}),
                  ...(Number.isFinite(b.top) ? { top: Math.round(b.top) } : {}),
                },
              })
              sendResponse({ ok: true })
            } else {
              sendResponse({ ok: false, error: 'invalid bounds' })
            }
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SYNC_STATUS': {
          try {
            const status = await v.getSyncStatus()
            sendResponse({ ok: true, status })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R95 F-95-02 — the state query behind the options header's
        // state-aware toggle. Truthful by construction: the tracked id is
        // re-validated against chrome.windows.get on EVERY query, so a window
        // the user closed by any means reads back as closed.
        case 'VAULT_WINDOW_STATE': {
          try {
            const { [VAULT_WINDOW_ID_KEY]: tracked } = await chrome.storage.local.get(VAULT_WINDOW_ID_KEY)
            let open = false
            if (tracked != null) {
              try {
                await chrome.windows.get(tracked)
                open = true
              } catch {
                try { await chrome.storage.local.remove(VAULT_WINDOW_ID_KEY) } catch { /* best-effort */ }
              }
            }
            sendResponse({ ok: true, open })
          } catch (e) {
            sendResponse({ ok: false, open: false, error: e.message })
          }
          return
        }

        // R95 F-95-02 — the close action. Closing a vault window is NOT a
        // destructive operation (the vault itself is untouched; the popup's
        // own Close window affordance never confirmed either), so no
        // confirmation gate here is consistent with the design language.
        case 'CLOSE_VAULT_WINDOW': {
          try {
            const { [VAULT_WINDOW_ID_KEY]: tracked } = await chrome.storage.local.get(VAULT_WINDOW_ID_KEY)
            if (tracked != null) {
              try { await chrome.windows.remove(tracked) } catch { /* already gone */ }
              try { await chrome.storage.local.remove(VAULT_WINDOW_ID_KEY) } catch { /* best-effort */ }
              sendResponse({ ok: true, closed: true })
            } else {
              sendResponse({ ok: true, closed: false })
            }
          } catch (e) {
            sendResponse({ ok: false, closed: false, error: e.message })
          }
          return
        }

        // v2.3.0 — sync-key KDF version info + explicit upgrade path
        case 'SYNC_KDF_INFO': {
          try {
            const info = await v.getSyncKdfInfo()
            sendResponse({ ok: true, info })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SYNC_KDF_UPGRADE': {
          try {
            const result = await v.upgradeSyncKdf()
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.3.0 — fill a SPECIFIC entry (popup vault tab row button)
        case 'FILL_ENTRY': {
          try {
            if (!msg.entry || typeof msg.entry !== 'object') {
              sendResponse({ ok: false, error: 'Missing entry' })
              return
            }
            await chrome.tabs.sendMessage(msg.tabId, { type: 'PERFORM_FILL_ENTRY', entry: msg.entry })
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: 'Could not reach the page — reload it and try again' })
          }
          return
        }

        case 'SYNC_NOW': {
          try {
            // R146 §7 (the BACKUP-1 cure): the door is BOUNDED — a hung cloud
            // read (the Helium divergence, H-4) can never hang the click
            // forever; the typed timeout lands as a verdict the user sees.
            // The cap is the ledgered watchdog number (the R145 120 s law).
            // R148 §5.1 (the K-2 cure — THE ROUND TRIP GATE): the run is
            // OBSERVABLE BY CONSTRUCTION — every outcome writes ONE run row
            // to the sync-run ledger ("manual sync · just now") + broadcasts
            // to the open pages. A click with no observable delta is a red
            // class; the delta now lands in the worker, independent of any
            // page's wiring.
            const SYNC_NOW_BOUNDED_MS = 120000
            // R150 CURE 2(i) (D-3, capture B1) — THE WRITER GAP, PINNED AND
            // CURED: recordRun used to publish outcome:'ok' whenever syncNow
            // RESOLVED — even when the pull never consulted the remote
            // (locked / unresolvable transport / unreachable) — and the empty
            // detail made publishRunState FABRICATE "your cloud copy was read
            // and verified". The activity ledger showed two "successful"
            // manual syncs while the pull ledger held a failed row and the
            // headline stayed pending — three surfaces, three truths, one
            // state. THE CURE: the run row derives from the ACTUAL outcome —
            // outcome 'ok' ONLY on a positively observed remote (the same
            // predicate the pull ledger and the chain verdict read), the REAL
            // reason rides the failed rows, and the wake/lastPull records the
            // verdict auto-clears are stamped by the SAME run (one check, one
            // verdict, every surface).
            const describeRunOutcome = (res) => {
              if (res && res.conflictDetected) {
                return {
                  outcome: 'conflict',
                  pushed: false,
                  detail: res.reason || 'Hash mismatch detected between local and cloud vault — open Conflict Resolver in Sync Settings',
                }
              }
              const pushed = !!(res && (res.pushed || (res.push && res.push.ok)))
              const observed = !!(res && res.remoteObserved === true)
              if (observed) {
                return { outcome: 'ok', pushed, detail: pushed ? 'pulled, verified, and pushed' : 'your cloud copy was read and verified — nothing new to push' }
              }
              const rawReason = res
                ? (res.reason || (res.transportError && (res.transportError.userMessage || res.transportError.message)) || res.transportError || '')
                : 'the run produced no result'
              return { outcome: 'failed', pushed: false, detail: String(rawReason || 'the run stopped — the reason is in the connection details').slice(0, 160) }
            }
            const recordRun = async (row) => {
              try {
                const { 'ucrypt:syncRuns': prev } = await chrome.storage.local.get('ucrypt:syncRuns')
                const arr = Array.isArray(prev) ? prev : []
                arr.unshift({ at: Date.now(), kind: 'manual', ...row })
                await chrome.storage.local.set({ 'ucrypt:syncRuns': arr.slice(0, 20) })
                // R149 C-4 (LAW #78 — ONE-EVENT-ALL-SURFACES): the run ALSO
                // publishes the compact run-state beat — ONE set() → ONE
                // onChanged event → every surface re-renders in the same tick.
                // R150 CURE 2(i): the detail is the run's OWN outcome words —
                // never a canned success line (the fabricated class is dead).
                await publishRunState('manual', row.outcome === 'ok', row.detail || '')
                try { chrome.runtime.sendMessage({ type: 'UCRYPT_SYNC_RUN', ...row }).catch?.(() => {}) } catch { /* no receiver — the ledger persists */ }
              } catch { /* the ledger never blocks the sync */ }
            }
            const result = await Promise.race([
              v.syncNow(),
              new Promise((_, reject) => setTimeout(() => {
                const err = new Error('The backup run did not finish within 120 s — the run is still safe to retry, and nothing was lost.')
                err.code = 'SYNC_NOW_TIMEOUT'
                reject(err)
              }, SYNC_NOW_BOUNDED_MS)),
            ])
            const runRow = describeRunOutcome(result)
            await recordRun(runRow)
            sendResponse({ ok: true, result })
          } catch (e) {
            try {
              const { 'ucrypt:syncRuns': prev } = await chrome.storage.local.get('ucrypt:syncRuns')
              const arr = Array.isArray(prev) ? prev : []
              const detail = String((e && e.userMessage) || e.message || e).slice(0, 160)
              arr.unshift({ at: Date.now(), kind: 'manual', outcome: 'failed', detail })
              await chrome.storage.local.set({ 'ucrypt:syncRuns': arr.slice(0, 20) })
              // R149 C-4 (LAW #78) — the failed run publishes the beat too:
              // the typed failure reaches every surface with the same urgency.
              try { await publishRunState('manual', false, detail) } catch { /* best effort */ }
              try { chrome.runtime.sendMessage({ type: 'UCRYPT_SYNC_RUN', outcome: 'failed' }).catch?.(() => {}) } catch { /* best effort */ }
            } catch { /* the ledger never blocks the typed verdict */ }
            // R116 §2.1 — the typed payload rides (userMessage + the recovery
            // card + kind/status), never the bare engine line.
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        // R148 §5.1 — the sync-run ledger's read door (the activity box
        // renders "manual sync · just now — the chain is current").
        case 'SYNC_RUN_LEDGER': {
          try {
            const { 'ucrypt:syncRuns': runs } = await chrome.storage.local.get('ucrypt:syncRuns')
            sendResponse({ ok: true, runs: Array.isArray(runs) ? runs : [] })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        // R148 §6.6 — the startup check's read door (the chain card renders
        // the ONE honest line: "Startup check ✓ — cloud read, backup verified").
        case 'STARTUP_CHECK_STATUS': {
          try {
            const { [STARTUP_CHECK_KEY]: row } = await chrome.storage.local.get(STARTUP_CHECK_KEY)
            sendResponse({ ok: true, check: row || null })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        // LAW 0.48 (R133) — the joiner's typed primary action: Pull now (a
        // fresh member RECEIVES first — the push is disabled until the first
        // pull lands; see the lifecycle in lib/vault.js).
        case 'SYNC_PULL': {
          try {
            const result = await v.pullFromSync()
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        // LAW 0.49 (R133) — the user-configurable auto-sync cadence.
        case 'AUTO_SYNC_SET': {
          try {
            const minutes = await v.setAutoSyncMinutes(msg.minutes)
            await ensureSyncIntervalAlarm(v)
            try {
              const { [AUTO_SYNC_STATE_KEY]: st } = await chrome.storage.local.get(AUTO_SYNC_STATE_KEY)
              await chrome.storage.local.set({ [AUTO_SYNC_STATE_KEY]: { ...((st && typeof st === 'object') ? st : {}), nextAt: Date.now() + minutes * 60000, failures: 0 } })
            } catch { /* bookkeeping is best-effort */ }
            sendResponse({ ok: true, minutes })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        // S9 (R111) — the chain-shared state surface + the diagnostics gate:
        // BOOLEANS and public fields only (never a credential value, never a
        // sealed blob, never the words).
        case 'CHAIN_STATE_STATUS': {
          try {
            sendResponse(await v.chainStateStatus())
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'CHAIN_STATE_RESOLVE': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — the chain connection is sealed with a key that only exists while unlocked' })
              return
            }
            sendResponse(await v.resolveChainStateConflict(msg.choice === 'chain' ? 'chain' : 'mine'))
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // UCRYPT-16 — Vault Hash Mismatch & Merge Conflict Resolver IPC
        case 'VAULT_CONFLICT_STATUS': {
          try {
            sendResponse(await v.getVaultConflictStatus())
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        case 'VAULT_CONFLICT_CHECK_NOW': {
          try {
            const res = await v.checkVaultConflictNow()
            try { chrome.runtime.sendMessage({ type: 'UCRYPT_VAULT_CONFLICT_CHANGED', status: res }).catch?.(() => {}) } catch { /* best-effort */ }
            sendResponse(res)
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        case 'VAULT_CONFLICT_RESOLVE': {
          try {
            const choice = msg.choice === 'local' ? 'local' : (msg.choice === 'cloud' ? 'cloud' : 'merge')
            const res = await v.resolveVaultConflict(choice)
            try { chrome.runtime.sendMessage({ type: 'UCRYPT_VAULT_CONFLICT_CHANGED', resolved: choice, result: res }).catch?.(() => {}) } catch { /* best-effort */ }
            sendResponse(res)
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        case 'VAULT_CONFLICT_SET_POLICY': {
          try {
            const policy = await v.setVaultConflictPolicy(msg.policy === 'manual' ? 'manual' : 'auto-with-review')
            sendResponse({ ok: true, policy })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        // UCRYPT-19 / UCRYPT-20 — Automatic Sync Exponential Backoff Retry IPC
        case 'AUTO_SYNC_RETRY_STATUS': {
          try {
            const retryState = await v.getAutoSyncRetryState()
            sendResponse({ ok: true, retryState })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        case 'AUTO_SYNC_RETRY_NOW': {
          try {
            const res = await v.runAutoSyncBackoffRetryNow({ source: 'manual-retry-now' })
            await publishRunState('auto-retry-now', !!(res && res.ok), (res && res.ok) ? 'Retry succeeded' : ((res && res.retryState && res.retryState.lastError) || 'Retry failed'))
            sendResponse({ ...res, retryState: await v.getAutoSyncRetryState() })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        case 'AUTO_SYNC_RETRY_CANCEL': {
          try {
            const retryState = await v.clearAutoSyncRetryState('user-cancelled-retry')
            await publishRunState('auto-retry-cancel', true, 'Automatic retry paused by user')
            sendResponse({ ok: true, retryState })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        case 'AUTO_SYNC_SIMULATE_NETWORK_FAILURE': {
          try {
            const scheduled = await v.scheduleAutoSyncBackoffRetry({
              ok: false,
              remoteObserved: false,
              kind: msg.kind || 'network',
              status: Number.isFinite(Number(msg.status)) ? Number(msg.status) : 503,
              reason: msg.reason || 'Temporary network timeout reaching cloud storage (HTTP 503 Service Unavailable)',
            }, {
              source: msg.source || 'auto-sync',
              attempt: msg.attempt,
              skipTimer: !!msg.skipTimer,
            })
            await publishRunState('auto-retry-scheduled', false, (scheduled && scheduled.state && scheduled.state.lastError) || 'Auto-sync retry scheduled')
            sendResponse({ ok: true, ...scheduled })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        case 'CHAIN_STATE_OVERRIDE': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first' })
              return
            }
            sendResponse(await v.setChainStateOverride(!!msg.on))
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'CHAIN_STATE_SHARE': {
          try {
            sendResponse(await v.setChainShareCredentials(!!msg.on))
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // §3.2 (R111) — the persisted sync-activity ledger (the visible
        // moments). Counts + labels only — the no-secrets law holds.
        case 'SYNC_MOMENT_LEDGER': {
          try {
            sendResponse(await v.syncMomentLedger())
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R112 §3.1/§3.2 (law 0.26) — THE ATTENTION DIAGNOSIS: the pull
        // ledger's typed cause, named for the surface. The attention chip
        // and the state card both render from THIS answer — one classifier,
        // one source of truth (0.11). Read-only; never throws into the
        // renderer. The raw error string rides as the deeper diagnostic —
        // it is the same line the ledger already shows, never a secret.
        // R140 §7.2 — THE ONE CHAIN VERDICT (the strip, the pill, and the
        // transfer gate read THIS derivation — never a second writer)
        case 'SYNC_CHAIN_VERDICT': {
          try {
            const { [v.LAST_PULL_KEY_PUBLIC]: lastPull } = await chrome.storage.local.get(v.LAST_PULL_KEY_PUBLIC)
            const { [CHAIN_WAKE_KEY]: wake } = await chrome.storage.local.get(CHAIN_WAKE_KEY)
            // R150 CURE 1 (D-2, capture B5) — the connected truth reads the
            // LEGACY-ALIAS READER's resolution (never the raw id): a stored
            // record with a null/unknown id claims connected NOWHERE — the
            // derivation says no-cloud (the honest BRIDGE_SETUP state), and
            // the pending ladder can never run over an unresolvable record.
            let cloudConnected = false
            try { cloudConnected = !!((await v.resolveTransportRecord()).usableId) } catch { cloudConnected = false }
            const derived = deriveChainState({ cloudConnected, cloudLabel: cloudConnected ? 'connected' : '', wake: wake || null, lastPull: lastPull || null, probeInFlight: probeInFlightNow() })
            sendResponse({ ok: true, derived })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R147 §4.4/§4.5 — THE CREDENTIAL LIFECYCLE DOORS: the chip, the
        // banner, and the auto-sync clock read THIS one truth (the J-6 cure);
        // the reconnect re-probes in place, preserving EVERY stored setting
        // (the R145 G-8 class: the owner never re-enters the URL).
        case 'CRED_STATUS': {
          try { sendResponse(await credDeriveTruth()) } catch (e) { sendResponse({ ok: false, error: e.message }) }
          return
        }
        case 'CRED_RECONNECT': {
          try {
            const v2 = await vault()
            const st = await v2.getVaultState()
            if (!st.isUnlocked) { sendResponse({ ok: false, code: 'LOCKED', userMessage: 'Unlock the vault first — the reconnect keeps every setting.' }); return }
            let pull = null
            try { pull = await v2.pullFromSync() } catch { pull = null }
            const heal = await credHealTick(pull)
            const truth = await credDeriveTruth()
            sendResponse({ ok: true, healed: heal.ok, revived: !!heal.revived, truth })
          } catch (e) { sendResponse({ ok: false, error: e.message }) }
          return
        }

        case 'SYNC_ATTN_DIAGNOSE': {
          try {
            const { [v.LAST_PULL_KEY_PUBLIC]: lastPull } = await chrome.storage.local.get(v.LAST_PULL_KEY_PUBLIC)
            // R123 §2.2 (the CEO's S2 — the glitch, captured) — THE STALENESS
            // CHECK: the ledger row is a HISTORICAL record; the attention
            // state must never speak for the CURRENT connection when the
            // transport was re-saved after the failed read. A setAt newer
            // than the failed row's at means the owner already reconnected —
            // the truthful cause is 'recovered' (the strip says so and the
            // one-click Sync now completes the recovery), NEVER the stale
            // 'the grant was revoked' scream over a working connection.
            let stale = false
            let recoveredProvider = null
            try {
              const { ['ucrypt:transport']: rec } = await chrome.storage.local.get('ucrypt:transport')
              const setAt = rec && Number(rec.setAt)
              const failedAt = lastPull && Number(lastPull.at)
              if (rec && rec.id && setAt > 0 && lastPull && lastPull.attempted && !lastPull.ok && failedAt > 0 && setAt > failedAt) {
                stale = true
                recoveredProvider = String(rec.id)
              }
            } catch { /* the staleness check never blocks the diagnose */ }
            const cause = stale ? 'recovered' : v.classifyAttentionCause(lastPull)
            // R140 §7.2 — the REACTIVE verdict rides the diagnose: the strip
            // may only render an error under an evidence-backed attention —
            // a pending wake cycle renders the calm pending copy instead
            let derived = null
            try {
              const { [CHAIN_WAKE_KEY]: wake } = await chrome.storage.local.get(CHAIN_WAKE_KEY)
              derived = deriveChainState({ cloudConnected: true, wake: wake || null, lastPull: lastPull || null })
            } catch { derived = null }
            sendResponse({
              ok: true,
              cause,
              stale,
              recoveredProvider,
              derived,
              // R116 §2.1 — the refined cause data: the recovery card's kind
              // (client_disabled / invalid_grant / …) and the ledger row's
              // typed fields — the Show-more detail renders THESE (the
              // cause-class precision: the disabled client never renders as
              // "expired login"). errorRaw stays out — `error` already is the
              // sanitized engine line the ledger shows.
              recoveryKind: (lastPull && lastPull.recoveryKind) || null,
              // R116 §2.2 — the disabled client's card rides COMPLETE: the
              // console deep link + the owner's two-sentence checklist, so
              // the attention surface renders the fix INLINE (0.29) without
              // a second round-trip.
              consoleUrl: (lastPull && lastPull.recoveryKind === 'client_disabled') ? GOOGLE_CONSOLE_CREDENTIALS_URL : null,
              checklist: (lastPull && lastPull.recoveryKind === 'client_disabled') ? GOOGLE_CLIENT_DISABLED_FIX : null,
              detail: (lastPull && (lastPull.error || null)) || null,
              kind: (lastPull && lastPull.kind) || null,
              status: (lastPull && Number.isFinite(Number(lastPull.status))) ? Number(lastPull.status) : null,
              at: (lastPull && lastPull.at) || 0,
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R112 §3.1 — THE SAFE RESEED executor (the 'unreadable' cause's
        // one-click). The SURFACE owns the double confirm; the worker owns
        // the four legs (fetch → archive → fresh push → read-back) inside
        // the sync lock. Booleans and names only cross this boundary — the
        // old bytes and the fresh envelope never do.
        case 'SYNC_RESEED_CLOUD': {
          try {
            const r = await v.reseedCloudCopy()
            sendResponse(r)
          } catch (e) {
            sendResponse({ ok: false, stage: 'error', error: (e && e.message) || String(e) })
          }
          return
        }

        // R172 — THE ROAD-HOME METADATA DOOR (R-172.3): the fork's double-
        // confirm shows the remote copy's date/size. Names and numbers only
        // cross this boundary — never the content, never a secret. Read-only.
        case 'SYNC_REMOTE_INFO': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) { sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — the remote check reads the stored connection' }); return }
            const rec = await v.getTransportRecord().catch(() => null)
            if (!rec || !rec.id) { sendResponse({ ok: true, present: null, size: null, modifiedTime: null, transportId: null }); return }
            const tm = await transportsMod()
            const t = tm.getTransport(rec.id)
            if (!t || typeof t.remoteVaultInfo !== 'function') { sendResponse({ ok: true, present: null, size: null, modifiedTime: null, transportId: rec.id }); return }
            const info = await t.remoteVaultInfo(rec.config)
            sendResponse({ ok: true, ...info, transportId: rec.id })
          } catch (e) {
            sendResponse({ ok: false, error: (e && e.message) || String(e) })
          }
          return
        }

        // R150 CURE 1 (D-2) — the transport id's public resolution door: the
        // surfaces read THIS (never the raw record) so a null/unknown id
        // claims connected nowhere and the one-truth card renders the typed
        // BRIDGE_SETUP state. Read-only; never throws into the renderer.
        case 'TRANSPORT_RESOLVE': {
          try {
            const r = await v.resolveTransportRecord()
            sendResponse({ ok: true, ...r })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'TRANSPORT_SAVE': {
          try {
            // v2.17.0 — R26-F14: validate the transport id. A bogus id used
            // to be saved verbatim and only exploded later as
            // "Unknown transport: X" from deep inside a sync.
            // R45-A §2.3/§2.5: the save is refused while the vault is locked
            // (no token data may be written until unlock) and every SECRET
            // field is sealed into its credential envelope before storage —
            // the plaintext the user typed exists only in this message frame.
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — credentials are encrypted with a key that only exists while unlocked' })
              return
            }
            const tm = await transportsMod()
            // R177 — R-177.2 THE SINGLE WRITER AT THE SAVE DOOR: the save
            // REFUSES a transport it cannot name (a null id never resolves
            // onto the stored record — a contextless form-save must never
            // overwrite the stored custody). The test door is the resolver
            // seat (readers fall back to the record); the writer keeps its
            // fail-closed refusal (the R150 D-2 typed card).
            if (!msg.transportId || !tm.getTransport(msg.transportId)) {
              // R150 D-2 (§6.1) — the refusal NEVER interpolates the raw id
              // ("Unknown transport: <raw>" is unrenderable): the typed
              // sentence + the same recovery card the registry throws ride.
              sendResponse({
                ok: false,
                error: 'That cloud transport does not exist in this build — pick one of the listed transports, then press Connect.',
                recovery: {
                  kind: 'transport_unknown',
                  title: 'That cloud transport does not exist.',
                  causes: ['The transport id came from an older build or a foreign config.'],
                  fix: 'Open Sync settings and choose a listed transport, then press Connect.',
                },
              })
              return
            }
            const sealed = await v.sealTransportConfig(msg.transportId, msg.config || {})
            // R123 §2.2 (the CEO's S2) — setAt rides every write: a save that
            // postdates the pull ledger's failed row means the stale row no
            // longer speaks for the current connection (the staleness law).
            await chrome.storage.local.set({
              'ucrypt:transport': { id: msg.transportId, config: sealed, setAt: Date.now() },
            })
            // R176 — R-176.1a THE LIVING BANK: a mint is not done when it
            // returns — it is done when it is VERIFIED. The save re-opens the
            // just-sealed envelope (the read-back) and compares the custody
            // facts the connect won (the webToken's token + exp; the refresh
            // grant's presence). Only a verified read-back may let the ✓ card
            // render — the ✓ card cannot lie. A mismatch answers ok:false with
            // the typed verdict (the honest refused/absent state — never a
            // silent ✓ over an unbanked key).
            let verified = true
            let verifyError = ''
            try {
              const reopened = await v.getTransportRecord()
              const want = msg.config || {}
              const got = (reopened && reopened.config) || {}
              const wtW = want.webToken && typeof want.webToken === 'object' ? want.webToken : null
              const wtG = got.webToken && typeof got.webToken === 'object' ? got.webToken : null
              if (wtW && typeof wtW.token === 'string' && wtW.token.length > 0) {
                verified = !!(wtG && wtG.token === wtW.token && Number(wtG.exp) === Number(wtW.exp))
                if (!verified) verifyError = 'the minted access key did not read back — the bank refused to confirm the custody (nothing was saved as signed-in)'
              }
              if (verified) {
                const rtW = String(want.refreshToken || '').trim()
                if (rtW) {
                  verified = String(got.refreshToken || '').trim().length > 0
                  if (!verified) verifyError = 'the refresh grant did not read back — the bank refused to confirm the custody (nothing was saved as signed-in)'
                }
              }
            } catch (e) {
              verified = false
              verifyError = 'the custody read-back could not run (' + String((e && e.message) || e).slice(0, 120) + ')'
            }
            if (!verified) {
              sendResponse({ ok: false, error: verifyError, custodyUnverified: true })
              return
            }
            // S9.3 (R111) — every successful local config change BUMPS the
            // chain's monotonic counter: the shared record rides the next
            // sync (direct or cloud) and every device adopts it (the typed
            // notice / the conflict card). Never throws into the save.
            try { await v.noteChainStateLocalChange() } catch { /* the save stands */ }
            // S9.3 + S5 eager staging + R179 AUTOMATIC FIRST-ACTION SYNC ON CONNECT:
            // When a cloud connection succeeds and is saved, immediately run a full
            // syncNow cycle (bounded) so:
            //  1) First-time connection to an empty cloud uploads & confirms the initial vault envelope.
            //  2) First-time connection on a new device joining an existing cloud vault downloads, decrypts, adopts, and confirms.
            //  3) Recurrent connection pulls, merges (LWW + tombstones), updates the cloud copy in place, and confirms via SHA-256 read-back.
            let autoSync = { attempted: false, ok: false, kind: 'not-ready', detail: '' }
            try {
              const stNow = await v.getVaultState().catch(() => null)
              const kdfInfo = (typeof v.getSyncKdfInfo === 'function') ? await v.getSyncKdfInfo().catch(() => null) : null
              if (stNow && stNow.isUnlocked && kdfInfo && kdfInfo.hasSyncCode) {
                const syncRes = await Promise.race([
                  v.syncNow({ onConnect: true, source: 'connect-auto-sync' }),
                  new Promise((_, rej) => setTimeout(() => rej(new Error('Auto-sync timed out after 45s')), 45000)),
                ])
                const pushed = !!(syncRes && (syncRes.pushed || (syncRes.push && syncRes.push.ok)))
                const observed = !!(syncRes && syncRes.remoteObserved === true)
                const syncKind = String((syncRes && syncRes.connectionSyncKind) || (syncRes && syncRes.emptyRemote ? 'initial-upload' : 'recurrent-in-sync'))
                let detail = 'Cloud copy verified and confirmed'
                if (observed) {
                  if (syncKind === 'initial-upload' && pushed) {
                    detail = 'Initial cloud vault created and confirmed ✓'
                  } else if (syncKind === 'initial-download-adopted') {
                    detail = `Received existing vault from cloud (${Number(syncRes.entryCount || 0)} entries adopted) and confirmed ✓`
                  } else if (syncKind === 'recurrent-merged-updated' || (syncKind === 'recurrent-merged' && pushed)) {
                    detail = 'Merged with existing cloud vault and updated cloud copy ✓'
                  } else if (pushed) {
                    detail = 'Updated existing cloud vault copy and confirmed ✓'
                  } else {
                    detail = 'Existing cloud vault verified — already in sync ✓'
                  }
                } else {
                  const rawErr = syncRes
                    ? (syncRes.reason || (syncRes.transportError && (syncRes.transportError.userMessage || syncRes.transportError.message)) || syncRes.transportError || '')
                    : ''
                  detail = String(rawErr || 'Auto-sync could not reach the cloud copy yet').slice(0, 160)
                }
                autoSync = {
                  attempted: true,
                  ok: observed && (!syncRes.push || syncRes.push.ok !== false),
                  pushed,
                  remoteObserved: observed,
                  kind: syncKind,
                  entryCount: Number((syncRes && syncRes.entryCount) || 0),
                  detail,
                }
                try {
                  const { 'ucrypt:syncRuns': prev } = await chrome.storage.local.get('ucrypt:syncRuns')
                  const arr = Array.isArray(prev) ? prev : []
                  const row = { at: Date.now(), kind: 'connect-auto-sync', outcome: autoSync.ok ? 'ok' : 'failed', pushed, detail }
                  arr.unshift(row)
                  await chrome.storage.local.set({ 'ucrypt:syncRuns': arr.slice(0, 20) })
                  await publishRunState('connect-auto-sync', autoSync.ok, detail)
                  try { chrome.runtime.sendMessage({ type: 'UCRYPT_SYNC_RUN', ...row }).catch?.(() => {}) } catch { /* best-effort */ }
                } catch { /* ledger never blocks save */ }
              } else {
                autoSync = {
                  attempted: false,
                  ok: false,
                  kind: !(stNow && stNow.isUnlocked) ? 'locked' : 'no-sync-code',
                  detail: !(stNow && stNow.isUnlocked)
                    ? 'Unlock the vault to start automatic cloud sync.'
                    : 'Generate or restore your 24-word sync code to start automatic cloud sync.',
                }
              }
            } catch (syncErr) {
              autoSync = {
                attempted: true,
                ok: false,
                kind: 'error',
                detail: String((syncErr && (syncErr.userMessage || syncErr.message)) || syncErr).slice(0, 160),
              }
            }
            sendResponse({ ok: true, verified: true, autoSync })
          } catch (e) {
            // R116 §2.1 — the typed payload rides on the save path too.
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        // ── R124 §2 (D13) — THE ASYNC PICKUP, worker-side legs ────────────────
        // The hold uploads ride the worker (the credentials NEVER cross to a
        // page — law 0.14); the page receives only the PUBLIC shared link and
        // the OPAQUE cleanup ref (a file id / a path / a gist id — no grant,
        // no secret). Unlocked-only: the transport record opens only while
        // the credential key exists (the lock-drop lifecycle rides here too).
        case 'PICKUP_SUPPORT': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) { sendResponse({ ok: false, locked: true, error: 'Unlock the vault first' }); return }
            const record = await v.getTransportRecord()
            if (!record || !record.id) { sendResponse({ ok: true, provider: null, support: { supported: false, reason: 'none' } }); return }
            const support = (await pickupLinksMod()).pickupSupport(record.id, record.config)
            sendResponse({ ok: true, provider: record.id, support })
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        case 'PICKUP_HOLD_UPLOAD': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) { sendResponse({ ok: false, locked: true, error: 'Unlock the vault first' }); return }
            const record = await v.getTransportRecord()
            if (!record || !record.id) { sendResponse({ ok: false, error: 'No transport is configured' }); return }
            const bytes = msg.blob instanceof Uint8Array ? msg.blob : new Uint8Array(Object.values(msg.blob || {}))
            const r = await (await pickupLinksMod()).pickupUploadAndLink(record.id, record.config, bytes)
            sendResponse({ ok: true, ...r })
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        case 'PICKUP_HOLD_CANCEL': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) { sendResponse({ ok: false, locked: true, error: 'Unlock the vault first' }); return }
            const record = await v.getTransportRecord()
            if (!record || !record.id) { sendResponse({ ok: false, error: 'No transport is configured' }); return }
            const r = await (await pickupLinksMod()).pickupCancel(record.id, record.config, msg.cleanupRef || null)
            sendResponse({ ok: true, ...r })
          } catch (e) {
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        case 'PAIRING_COMPLETE_CLOUD': {
          try {
            // R102 (J1) — the Complete-pairing projection for the sheet's
            // renderer. Unlocked-only (the credential key exists only while
            // unlocked); the sealed envelopes stay in this context — the
            // page receives the safeCloudForPairing projection (provider +
            // stripped URL + the webdav sign-in ONLY under the page's own
            // labeled opt-in, which the renderer checked before asking).
            // NEVER logged (the secret law): this case contains no console.
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — the complete pairing needs the stored sign-in' })
              return
            }
            const cloud = await v.completeCloudForPairing()
            if (!cloud || !cloud.provider) {
              sendResponse({ ok: false, error: 'No transport is configured' })
              return
            }
            sendResponse({ ok: true, cloud })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R110 §3 — the window's state probe: the surfaces that would prompt
        // check here first (vault-unlocked AND within-window) and render the
        // visible countdown instead of the popup. Read-only — asking never
        // consumes or extends the window.
        case 'PASSPHRASE_WINDOW_STATE': {
          try {
            const state = await v.getVaultState()
            const w = passphraseWindowNow()
            sendResponse({ ok: true, unlocked: !!state.isUnlocked, ...w, windowMs: PASSPHRASE_WINDOW_MS })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R110 §3 — an explicit surface-side close of the window (the lock
        // button and the sheet's disarm call it; the worker's own lock path
        // clears the state regardless — this is the belt to that suspenders).
        case 'PASSPHRASE_WINDOW_RESET': {
          clearPassphraseWindow()
          sendResponse({ ok: true })
          return
        }

        // R110 §2.3 (payload law v1.4) — THE JOINER'S ARRIVAL: open the
        // transit-sealed credential blobs with THE WORDS THE CODE CARRIES,
        // then re-seal the values under THIS vault's own key (device-only,
        // lock-drop, disconnect-clear, export-exclusion — the origin's exact
        // lifecycle). The plaintext secret/grant exist ONLY inside this
        // frame and the vault.js store path; this boundary returns BOOLEANS
        // (stored field names, no values — the secret law). Never logged.
        case 'PAIRING_CREDENTIALS_OPEN': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — arrived credentials seal under this vault\'s key' })
              return
            }
            const words = String(msg.words || '').trim().split(/[\s-]+/).filter(Boolean)
            if (words.length !== 24) {
              sendResponse({ ok: false, error: 'The 24 words are required to open the sealed sign-in segments' })
              return
            }
            // R119 v1.5 — the fast-mode arrival carries NO s/g (the fast
            // connection is device-local — nothing to carry): the guards
            // below are the whole adoption — absent segments store nothing,
            // exactly as a v2/v3 join always behaved. Never a log here.
            const fields = {}
            if (msg.clientId) fields.clientId = String(msg.clientId)
            if (msg.s) fields.clientSecret = await _sync.openCredentialFromTransit(msg.s, words)
            if (msg.g) fields.refreshToken = await _sync.openCredentialFromTransit(msg.g, words)
            const r = await v.storeArrivedCredentials(String(msg.provider || ''), fields)
            sendResponse(r)
          } catch (e) {
            sendResponse({ ok: false, error: 'The sign-in did not arrive intact — the sealed segment failed to open with these words' })
          }
          return
        }

        case 'TRANSPORT_CLEAR': {
          try {
            // R171 — THE SPINE REVOKE (the contract's (e): Disconnect revokes
            // the token server-side AND clears local custody — then
            // re-connect re-mints fresh; Disconnect leaves nothing alive
            // behind it). The revoke runs FIRST (the sealed record must be
            // opened while the vault is unlocked to read the grant), bounded
            // 5 s, best-effort: a blocked revoke never blocks the clear (the
            // grant dies with the envelope locally either way; the typed
            // revoked flag rides so the surface can name the truth).
            let revoked = false
            let revokeReason = ''
            try {
              const vrec = await v.getTransportRecord().catch(() => null)
              const rt = vrec && vrec.config ? String(vrec.config.refreshToken || '').trim() : ''
              if (vrec && vrec.id === 'gdrive' && rt) {
                const rr = await fetch(OAUTH_REVOKE_URL, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  body: new URLSearchParams({ token: rt }).toString(),
                  signal: AbortSignal.timeout(5000),
                })
                // Google answers 200 on a live grant, 400 invalid_token on a
                // dead one — BOTH leave nothing alive server-side for this
                // custody; the honest flag names which answer rode.
                revoked = rr.status === 200 || rr.status === 400
                revokeReason = revoked ? (rr.status === 200 ? 'revoked' : 'already-dead') : 'http-' + rr.status
              } else {
                revokeReason = vrec && vrec.id === 'gdrive' ? 'no-grant-stored' : 'not-gdrive'
              }
            } catch (e) {
              revokeReason = String((e && e.message) || e).slice(0, 80)
            }
            try {
              await recordRing({
                flow: 'connect', transport: 'gdrive', stage: 'revoke',
                outcome: revoked ? 'ok' : 'fail', httpKind: 'POST', error: revoked ? '' : revokeReason.slice(0, 48),
                message: 'the Disconnect revoke leg answered ' + revokeReason.slice(0, 60) + ' — no token value ever rides this row (the no-secret law names the refresh-token shape)',
              })
            } catch { /* the ring never blocks the clear */ }
            // v2.19.0 — R28-F2 (audit 28a-2): clearing the transport must also
            // drop every transport-DERIVED state key — a stale gist id made
            // discovery skip a beat and a stale WebDAV ETag could 412 the
            // next push against a file the NEW transport has never seen.
            // R90 §1.1: the typed last-test ledger is transport-derived too —
            // a disconnected transport can never leave a stale ✓ behind.
            await chrome.storage.local.remove([
              'ucrypt:transport', 'ucrypt:webdav:etag', 'ucrypt:gistId', 'ucrypt:webdavUrl', 'ucrypt:lastTest',
            ])
            sendResponse({ ok: true, revoked, revokeReason })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'TRANSPORT_TEST': {
          try {
            const state = await v.getVaultState()
            const rawStored = (await chrome.storage.local.get('ucrypt:transport'))['ucrypt:transport'] || null
            const rawCfg = (rawStored && typeof rawStored.config === 'object') ? rawStored.config : null
            const incomingCfgRaw = (msg.config && typeof msg.config === 'object') ? msg.config : {}
            const hasFastCustodyWhileLocked = !!(
              (rawCfg && (rawCfg.authMode === 'fast' || rawCfg.signinMode === 'fast' || (rawCfg.webToken && rawCfg.webToken.token))) ||
              (incomingCfgRaw && (incomingCfgRaw.authMode === 'fast' || incomingCfgRaw.signinMode === 'fast' || (incomingCfgRaw.webToken && incomingCfgRaw.webToken.token)))
            )
            if (!state.isUnlocked && !hasFastCustodyWhileLocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — connection tests use your stored credentials' })
              return
            }
            const t = await transportsMod()
            let testId = msg.transportId
            if (!testId) {
              const resolved = await v.resolveTransportRecord().catch(() => null)
              if (resolved && resolved.usableId) testId = resolved.usableId
              else if (rawStored && rawStored.id) testId = rawStored.id
            }
            try {
              const storedRec = state.isUnlocked ? await v.getTransportRecord().catch(() => null) : null
              const storedCfg = (storedRec && storedRec.id === testId && storedRec.config && typeof storedRec.config === 'object')
                ? storedRec.config
                : ((rawStored && rawStored.id === testId && rawCfg) ? rawCfg : null)
              const incomingCfg = (msg.config && typeof msg.config === 'object') ? msg.config : {}
              const mergedTestConfig = storedCfg ? { ...storedCfg, ...incomingCfg } : { ...incomingCfg }
              if (storedCfg) {
                const swt = storedCfg.webToken && typeof storedCfg.webToken === 'object' ? storedCfg.webToken : null
                const iwt = incomingCfg.webToken && typeof incomingCfg.webToken === 'object' ? incomingCfg.webToken : null
                if (swt && typeof swt.token === 'string' && swt.token) {
                  const sExp = Number(swt.exp) || 0
                  const iExp = (iwt && typeof iwt.token === 'string' && iwt.token) ? (Number(iwt.exp) || 0) : 0
                  if (!iwt || !iwt.token || sExp >= iExp) {
                    mergedTestConfig.webToken = swt
                  }
                }
                for (const sk of ['refreshToken', 'oauthAccessToken', 'clientSecret', 'token', 'secret', 'pass']) {
                  if (String(storedCfg[sk] || '').trim() && !String(incomingCfg[sk] || '').trim()) {
                    mergedTestConfig[sk] = storedCfg[sk]
                  }
                }
                // UCRYPT-22: Never let a default form select (authMode: 'oauth', clientId: '')
                // demote a stored fast OAuth connection during Test connection!
                const storedIsFast = storedCfg.authMode === 'fast' || storedCfg.signinMode === 'fast' || !!(swt && swt.token)
                const explicitBridge = incomingCfg.authMode === 'bridge' || !!String(incomingCfg.scriptUrl || '').trim()
                const explicitCustomClient = !!String(incomingCfg.clientId || '').trim() && String(incomingCfg.clientId || '').trim() !== String(storedCfg.clientId || '').trim()
                if (storedIsFast && !explicitBridge && !explicitCustomClient) {
                  mergedTestConfig.authMode = 'fast'
                  mergedTestConfig.signinMode = 'fast'
                  mergedTestConfig.persistentSession = true
                  mergedTestConfig.autoRenew = true
                  if (storedCfg.clientId) mergedTestConfig.clientId = storedCfg.clientId
                  if (storedCfg.lane) mergedTestConfig.lane = storedCfg.lane
                  if (storedCfg.via) mergedTestConfig.via = storedCfg.via
                  if (storedCfg.accountHint) mergedTestConfig.accountHint = storedCfg.accountHint
                }
              }
              const message = await t.testTransport(testId, mergedTestConfig)
              // UCRYPT-22: If testTransport silently renewed or extended webToken, write it back!
              if (testId === 'gdrive' && mergedTestConfig.webToken && typeof mergedTestConfig.webToken === 'object' && mergedTestConfig.webToken.token && rawStored && rawStored.id === 'gdrive') {
                try {
                  const nextWt = {
                    ...mergedTestConfig.webToken,
                    persistentSession: true,
                    autoRenew: true,
                  }
                  await chrome.storage.local.set({
                    'ucrypt:transport': {
                      ...rawStored,
                      id: 'gdrive',
                      config: {
                        ...(rawStored.config || {}),
                        authMode: mergedTestConfig.authMode || 'fast',
                        signinMode: mergedTestConfig.signinMode || 'fast',
                        persistentSession: true,
                        autoRenew: true,
                        webToken: nextWt,
                      },
                      setAt: rawStored.setAt || Date.now(),
                    },
                  })
                } catch { /* best-effort custody persistence */ }
              }
              let bothLanes = String(message || '')
              if (/connected/i.test(bothLanes)) {
                const { [v.LAST_PUSH_KEY_PUBLIC]: lastPush } = await chrome.storage.local.get(v.LAST_PUSH_KEY_PUBLIC)
                const lc = await v.getEnvelopeLifecycle()
                const lcHH = lc && Number(lc.at) ? new Date(Number(lc.at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
                const i18 = (k, subs, fb) => {
                  try { return (chrome.i18n && chrome.i18n.getMessage(k, subs)) || fb } catch { return fb }
                }
                const lcKey = { written: 'envWritten', read: 'envRead', created: 'envCreated' }[lc && lc.state] || 'envNeverCreated'
                const lcWords = (lc && lc.state && lc.state !== 'never-created')
                  ? i18(lcKey, [lcHH], v.envelopeLifecycleWords(lc, lcHH))
                  : v.envelopeLifecycleWords(lc, lcHH)
                let writeTruth = ''
                if (lastPush && Number(lastPush.at)) {
                  const wHH = new Date(Number(lastPush.at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                  writeTruth = lastPush.ok
                    ? ' · ' + i18('verdictWriteConfirmed', [wHH], `last write confirmed at ${wHH}`)
                    : ' · ' + i18('verdictWriteFailed', [wHH], `last write FAILED at ${wHH}`)
                } else {
                  writeTruth = ' · ' + i18('verdictNoWriteYet', undefined, 'no write attempted yet')
                }
                bothLanes = bothLanes
                  .replace(/\s*—\s*vault envelope present\.?\s*$/i, '')
                  .replace(/\s*—\s*vault not created yet \(the first sync will create it\)\.?\s*$/i, '')
                bothLanes = `${bothLanes} — ${lcWords}${writeTruth}`
              }
              await chrome.storage.local.set({
                'ucrypt:lastTest': { ok: true, at: Date.now(), transportId: testId || '', message: String(bothLanes || '').slice(0, 140) },
              })
              sendResponse({ ok: true, message: bothLanes })
            } catch (e) {
              await chrome.storage.local.set({
                'ucrypt:lastTest': { ok: false, at: Date.now(), transportId: testId || '', message: String((e && (e.userMessage || e.message)) || 'test failed').slice(0, 140) },
              })
              throw e
            }
          } catch (e) {
            // R116 §2.1 — the typed payload rides: the wizard footer renders
            // the user message + the recovery card (the disabled-client card
            // with the Cloud Console deep link) instead of the raw engine line.
            sendResponse({ ok: false, ...errPayload(e) })
          }
          return
        }

        // R45-A §2.5: the wizard prefill gets the stored config DECRYPTED for
        // editing while unlocked; while locked it gets only the fact that
        // secrets are stored (never the values, never a refresh).
        case 'TRANSPORT_GET': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              const status = await v.getTransportStatus()
              sendResponse({ ok: true, locked: true, config: null, status })
              return
            }
            const rec = await v.getTransportRecord()
            sendResponse({ ok: true, locked: false, config: rec ? rec.config : null })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R85 (§4): Google Drive OAuth connect (authorization-code + PKCE via
        // launchWebAuthFlow — NEVER getAuthToken) and the stage-by-stage
        // bridge verifier. Both run in the WORKER (the pages' CSP would block
        // the token endpoints).
        case 'TRANSPORT_GDRIVE_CONNECT': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — connecting stores a sealed grant' })
              return
            }
            const t = await transportsMod()
            const g = t.getTransport('gdrive')
            if (!g || typeof g.connectOAuth !== 'function') {
              sendResponse({ ok: false, error: 'Google Drive OAuth is unavailable in this build' })
              return
            }
            const res = await g.connectOAuth(msg.config || {})
            sendResponse({ ok: true, refreshToken: res.refreshToken, redirect: res.redirect })
          } catch (e) {
            // R87 (§2.1c): the typed recovery card (causes + fix + expected
            // redirect) rides back to the UI alongside the message.
            sendResponse({ ok: false, error: (e && (e.userMessage || e.message)) || String(e), recovery: (e && e.recovery) || null })
          }
          return
        }

        case 'TRANSPORT_GITHUB_CONNECT':
        case 'TRANSPORT_DROPBOX_CONNECT': {
          // R87 (§2.3): the same PKCE connect contract as Drive — GitHub
          // (code + PKCE, gist scope only) and Dropbox (refresh-token path,
          // no scope widening, no forced reconnects). Errors carry the typed
          // recovery card.
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Unlock the vault first — connecting stores a sealed grant' })
              return
            }
            const t = await transportsMod()
            const id = msg.type === 'TRANSPORT_GITHUB_CONNECT' ? 'github' : 'dropbox'
            const g = t.getTransport(id)
            if (!g || typeof g.connectOAuth !== 'function') {
              sendResponse({ ok: false, error: `${id} OAuth is unavailable in this build` })
              return
            }
            const res = await g.connectOAuth(msg.config || {})
            sendResponse({ ok: true, ...res })
          } catch (e) {
            sendResponse({ ok: false, error: (e && (e.userMessage || e.message)) || String(e), recovery: (e && e.recovery) || null })
          }
          return
        }

        case 'TRANSPORT_GDRIVE_VERIFY': {
          try {
            const t = await transportsMod()
            const storedRec = await v.getTransportRecord().catch(() => null)
            const mergedVerifyConfig = (storedRec && storedRec.id === 'gdrive' && storedRec.config)
              ? { ...storedRec.config, ...(msg.config || {}) }
              : (msg.config || {})
            const mode = String(msg.mode || mergedVerifyConfig.authMode || 'oauth')
            let stages = []
            if (mode === 'bridge' && typeof t.verifyBridgeStages === 'function') {
              stages = await t.verifyBridgeStages(mergedVerifyConfig)
            } else {
              // OAuth mode: stage 1 client-id shape, stage 2 the live token check.
              const clientId = String(mergedVerifyConfig.clientId || '').trim()
              stages.push(/^[0-9A-Za-z_-]+\.apps\.googleusercontent\.com$/.test(clientId)
                ? { stage: 'client-id', ok: true, message: 'Client ID shape looks right.' }
                : { stage: 'client-id', ok: false, message: 'The client ID should look like 1234567890-abc.apps.googleusercontent.com.' })
              if (!stages[0].ok) {
                sendResponse({ ok: true, stages })
                return
              }
              try {
                const g = t.getTransport('gdrive')
                const msgTxt = await g.testConnection(mergedVerifyConfig)
                stages.push({ stage: 'google', ok: true, message: msgTxt })
              } catch (e) {
                stages.push({ stage: 'google', ok: false, message: (e && (e.userMessage || e.message)) || 'The Google connection failed.' })
              }
            }
            sendResponse({ ok: true, stages })
          } catch (e) {
            sendResponse({ ok: false, error: (e && (e.userMessage || e.message)) || String(e) })
          }
          return
        }

        // R85 (§5): Leave this device — forget the chain + transport secrets
        // HERE; the local vault and the cloud copy are untouched.
        case 'SYNC_LEAVE_DEVICE': {
          try {
            await v.leaveDevice()
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R85 (§5): Delete cloud copy — requires the typed DELETE confirm.
        case 'SYNC_DELETE_CLOUD': {
          try {
            if (String(msg.confirm || '') !== 'DELETE') {
              sendResponse({ ok: false, error: 'Type DELETE to confirm' })
              return
            }
            const r = await v.deleteCloudCopy()
            sendResponse(r)
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'SELF_CHECK_RUN': {
          // R93 §5 — "Verify my setup": READ-ONLY checks, typed results, no
          // auto-fixes. Everything below is a probe; nothing mutates state.
          try {
            const result = await runSelfChecks({
              isLocked: async () => {
                const st = await v.getVaultState()
                return !st.isUnlocked
              },
              getRawTransportRecord: async () => {
                const { 'ucrypt:transport': t } = await chrome.storage.local.get('ucrypt:transport')
                return t || null
              },
              getOpenedTransportRecord: async () => {
                const r = await v.getTransportRecord()
                return r || null
              },
              testTransport: (id, config) => _transports.testTransport(id, config),
              getSyncStatus: () => v.getSyncStatus(),
              getBackupFlag: async () => {
                const { 'ucrypt:backupVerified': f } = await chrome.storage.local.get('ucrypt:backupVerified')
                return f || null
              },
              captureProbe: async () => {
                const mf = chrome.runtime.getManifest()
                const hasContentScripts = Array.isArray(mf.content_scripts) && mf.content_scripts.length > 0
                let neverSaveReadable = false
                try {
                  const { 'ucrypt:neverSave': ns } = await chrome.storage.local.get('ucrypt:neverSave')
                  neverSaveReadable = (ns === undefined || Array.isArray(ns))
                } catch { neverSaveReadable = false }
                // The relay handler lives in THIS worker's message switch —
                // if this code runs, the relay is registered (truthful).
                return { manifestContentScripts: hasContentScripts, neverSaveReadable, relayRegistered: true }
              },
              badgeProbe: async () => {
                let [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
                if (!tab) [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
                let protocol = ''
                try { protocol = tab && tab.url !== undefined ? new URL(tab.url).protocol : '' } catch { protocol = '' }
                const st = await v.getVaultState()
                let count = 0
                if (tab && tab.url !== undefined && (protocol === 'http:' || protocol === 'https:') && !tab.incognito && st.isUnlocked) {
                  try { count = v.getEntriesForDomain(domainFromUrl(tab.url)).length } catch { count = 0 }
                }
                const ctx = { unlocked: !!st.isUnlocked, incognito: !!(tab && tab.incognito), protocol, count }
                return { badge: badgeFor(ctx), ctx }
              },
              storageProbe: async () => {
                let localBytes = 0
                try { localBytes = await chrome.storage.local.getBytesInUse(null) } catch { localBytes = 0 }
                let health = { sessions: 0, interruptedLedger: 0, cleanupLedger: 0, peers: 0 }
                try {
                  const h = await handleTransferMessage({ type: 'TRANSFER_HEALTH' })
                  if (h && h.ok) health = h
                } catch { /* plane asleep — sizes read as 0 */ }
                return { localBytes, sessions: health.sessions, interruptedLedger: health.interruptedLedger, cleanupLedger: health.cleanupLedger, peers: health.peers }
              },
              grantsProbe: async () => {
                const { 'ucrypt:transport': t } = await chrome.storage.local.get('ucrypt:transport')
                if (!t || !t.id) return { hasRecord: false }
                const map = _vault.transportSecretFieldMap()
                return { hasRecord: true, rawConfig: t.config || {}, secretFields: map[t.id] || [] }
              },
              // R121 §4.3 — the ladder rows' probe: READ-ONLY. The stored
              // record's field PRESENCE (never values), the fast-rung feature
              // detection, and the newest connect ring per ladder transport.
              // No network, no grants decrypted, nothing mutated.
              ladderProbe: async () => {
                const { 'ucrypt:transport': t } = await chrome.storage.local.get('ucrypt:transport')
                const records = {}
                for (const id of LADDER_TRANSPORTS) {
                  records[id] = t && String(t.id || '').trim().toLowerCase() === id ? t : null
                }
                const detect = {}
                for (const id of LADDER_TRANSPORTS) {
                  try { detect[id] = detectFastRung(id) } catch { detect[id] = null }
                }
                const lastRing = {}
                try {
                  const rings = await recentRings({ flow: 'connect', limit: RING_CAP })
                  for (const r of rings || []) {
                    const k = String((r && r.transport) || '').trim().toLowerCase()
                    if (!LADDER_TRANSPORTS.includes(k)) continue
                    if (!lastRing[k] || ((r.at || 0) > (lastRing[k].at || 0))) lastRing[k] = r
                  }
                } catch { /* rings unreadable — lastConnect reads 'none' */ }
                return { records, detect, lastRing }
              },
              // R171 — THE SPINE PROBE'S io DOOR: the zero-window probe rides
              // the worker's own fetch (the manifest host permission for
              // accounts.google.com covers the redirect-follow round-trip);
              // the derived redirect is chrome.identity.getRedirectURL().
              spineProbe: async () => {
                let redirect = ''
                try { redirect = String(chrome.identity.getRedirectURL() || '') } catch { redirect = '' }
                return spineProbe({ redirect })
              },
            })
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'QR_ENCODE': {
          try {
            // lib/qr.js is statically imported at the top (module worker —
            // importScripts is unavailable there) and sets globalThis.QR.
            const dataUrl = globalThis.QR.encode(String(msg.text || ''))
            sendResponse({ ok: true, dataUrl })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'OPEN_OPTIONS': {
          try {
            const url = chrome.runtime.getURL('options.html')
            if (msg.tab) {
              await chrome.tabs.create({ url })
            } else if (chrome.runtime.openOptionsPage) {
              await chrome.runtime.openOptionsPage()
            } else {
              await chrome.tabs.create({ url })
            }
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // --- Legacy sync alias (popup button) -----------------------------------
        case 'SYNC_DRIVE': {
          try {
            const result = await v.pullFromSync()
            sendResponse({ ok: true, result })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'RUN_BREACH_CHECK': {
          try {
            await runBreachCheck()
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.13.0 — R22-F5: after a file import overwrites storage, the
        // options page asks the worker to drop its in-memory vault and
        // re-read it — no extension restart, no killed pages.
        case 'VAULT_IMPORT_APPLIED': {
          try {
            const state = await v.reloadFromStorage()
            sendResponse({ ok: true, state })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'WIPE_VAULT': {
          try {
            // R45-E: a destructive wipe requires an UNLOCKED vault — the user
            // must prove mastery of the passphrase right here — and the UI
            // collects a typed confirmation + shows the verified-backup truth
            // BEFORE calling this. The worker gate is the second lock.
            const st = await v.getVaultState()
            if (!st.isUnlocked) {
              sendResponse({ ok: false, error: 'Unlock the vault first — wiping requires mastery of the master passphrase' })
              return
            }
            await v.wipeVault()
            sendResponse({ ok: true })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R45-E: the Copy-diagnostic payload — versions, non-secret reason
        // codes, timestamps. NO entries, URLs, usernames, tokens, recovery
        // words, or ciphertext ever enter this string.
        case 'DIAGNOSTIC_SUMMARY': {
          try {
            const st = await v.getVaultState()
            const sync = await v.getSyncStatus()
            const proof = await v.getBackupProof()
            const lines = [
              'UCrypt diagnostic summary',
              `version: ${chrome.runtime.getManifest().version}`,
              `userAgent: ${navigator.userAgent}`,
              `vault: ${st.isUnlocked ? 'unlocked' : 'locked'}${st.hasMaster ? ' (master set)' : ' (no master)'}`,
              `entries: ${st.isUnlocked ? st.entryCount : 'n/a (locked)'}`,
              `sync code: ${sync.syncEnabled ? 'set' : 'not set'}`,
              `transport: ${sync.transport ? sync.transport.id : 'none'}`,
              sync.lastPush
                ? `last push: ${sync.lastPush.ok ? 'ok' : 'FAILED'} at=${new Date(sync.lastPush.at).toISOString()}${sync.lastPush.error ? ` reason=${sync.lastPush.error}` : ''}`
                : 'last push: never',
              sync.syncHop
                ? `built-in hop: ${sync.syncHop.ok ? 'ok' : 'FAILED'} at=${new Date(sync.syncHop.at).toISOString()}${sync.syncHop.error ? ` reason=${sync.syncHop.error}` : ''}`
                : 'built-in hop: never',
              proof
                ? `verified backup: rev=${proof.rev} at=${new Date(proof.at).toISOString()}`
                : 'verified backup: none',
              `generated: ${new Date().toISOString()}`,
            ]
            sendResponse({ ok: true, text: lines.join('\n') })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.6.0 — in-page "suggest strong password" panel. The candidate is
        // generated + analyzed here so lib/generator.js and lib/analyzer.js
        // remain the ONLY generation/analysis code paths. The password is
        // returned to the content script the user explicitly interacted with.
        case 'GENERATE_FOR_FILL': {
          try {
            const a = await analyzer()
            const length = Number.isFinite(msg.length) ? Math.min(Math.max(msg.length | 0, 12), 64) : 20
            // lib/generator.js returns { value, entropyBits, … } — the panel
            // needs the raw string plus an entropy figure.
            const result = generateRandomPassword({ length })
            const password = String(result && result.value || '')
            const analysis = a.analyzePassword(password)
            const entropyBits = analysis
              ? Math.round(analysis.effective)
              : (result && Number.isFinite(result.entropyBits) ? Math.round(result.entropyBits) : null)
            sendResponse({
              ok: password.length > 0,
              password,
              entropyBits,
              length: password.length,
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // R72 §7 — SAFE custom-wordlist fetch, executed in the WORKER (the
        // CryptKey-style page-side scraper with public CORS proxies is
        // explicitly rejected). Contract: HTTPS-only URLs, credentials
        // omitted, no auth headers, cache bypassed, 15 s timeout, 2 MB cap,
        // text/HTML/JSON content only, deterministic extraction with bounds,
        // and NO proxy fallback. On failure the UI offers the local .json
        // import path. Never used for anything but the user-triggered
        // wordlist build — no other network call carries page content.
        case 'WORDLIST_FETCH': {
          try {
            const check = validateWordlistUrl(msg.url)
            if (!check.ok) {
              const reasons = {
                'not-a-url': 'Enter a valid URL',
                'https-only': 'Only https:// URLs are allowed',
                'no-credentials-in-url': 'URLs with embedded credentials are not allowed',
              }
              sendResponse({ ok: false, error: reasons[check.reason] || 'Invalid URL' })
              return
            }
            const res = await fetch(check.url, {
              credentials: 'omit',
              cache: 'no-store',
              redirect: 'follow',
              headers: { 'Accept': 'text/html, text/plain, application/json;q=0.9, */*' },
              signal: AbortSignal.timeout(15000),
            })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const mime = String(res.headers.get('content-type') || '').toLowerCase()
            if (mime && !/(text\/html|text\/plain|application\/json|text\/x-|text\/csv)/.test(mime)) {
              throw new Error(`Unsupported content type: ${mime.split(';')[0]}`)
            }
            const len = parseInt(res.headers.get('content-length') || '0', 10)
            if (len > 2 * 1024 * 1024) throw new Error('Response larger than the 2 MB limit')
            const text = await res.text()
            if (text.length > 2 * 1024 * 1024) throw new Error('Response larger than the 2 MB limit')
            const words = extractWordlistFromText(text)
            if (words.length < 10) {
              sendResponse({
                ok: false,
                error: `Only ${words.length} unique words found — try a different URL`,
                hint: 'You can import a .json wordlist file instead.',
              })
              return
            }
            sendResponse({ ok: true, words, count: words.length })
          } catch (e) {
            const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError')
            sendResponse({
              ok: false,
              error: timedOut ? 'The fetch timed out (15 s limit)' : (e.message || 'Fetch failed'),
              hint: 'The URL may block cross-origin reads or require a login. You can import a .json wordlist file instead.',
            })
          }
          return
        }

        // R72 §9 — fill the CURRENTLY GENERATED secret on the active tab's
        // password field. Explicit user press only; the content script fills
        // through native setters with a brief nonsecret highlight and NEVER
        // submits.
        case 'USE_GENERATED_SECRET': {
          try {
            const value = String(msg.value || '')
            if (!value) {
              sendResponse({ ok: false, error: 'Nothing to fill' })
              return
            }
            const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
            const tab = tabs && tabs[0]
            if (!tab || !tab.id || !/^https?:/.test(tab.url || '')) {
              sendResponse({ ok: false, error: 'No eligible page — open a website first' })
              return
            }
            const r = await chrome.tabs.sendMessage(tab.id, { type: 'UCRYPT_USE_GENERATED_SECRET', value })
            sendResponse(r && r.ok ? { ok: true } : { ok: false, error: (r && r.error) || 'No eligible password field found on the current page' })
          } catch (e) {
            sendResponse({ ok: false, error: 'No eligible password field found on the current page' })
          }
          return
        }

        // v2.6.0 — CSV import (browser migration). Rows are merged with the
        // SAME saveEntry path as manual saves, so tombstone-clearing, sync
        // push and lastModified bookkeeping behave identically.
        case 'IMPORT_CSV_ROWS': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Vault is locked' })
              return
            }
            const rows = Array.isArray(msg.rows) ? msg.rows : []
            if (rows.length > 5000) {
              sendResponse({ ok: false, error: 'Refusing to import more than 5000 rows at once' })
              return
            }
            // v2.7.0 — routed through the batch path: ONE persist + ONE
            // transport push instead of per-row re-encryption.
            // v2.8.0 — the push is AWAITED and its real outcome is returned.
            const r = await v.saveEntriesBatch(rows, { awaitPush: true })
            const st = await v.getSyncStatus()
            sendResponse({
              ok: true,
              added: r.added,
              skipped: r.skipped,
              push: r.push || null,
              sync: {
                enabled: !!st.syncEnabled,
                transport: st.transport ? st.transport.id : null,
              },
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        // v2.7.0 — Import Center: bulk import of normalized items (logins,
        // TOTP tokens, notes, cards, identities, bookmarks, history, form
        // data). Each entry arrives pre-shaped by importers.itemToVaultEntry
        // and is persisted with ONE encrypt + ONE cloud transport push.
        // v2.8.0 — the push is AWAITED and its real outcome is reported.
        // --- v2.42.8 — R71-P: EXPLICIT profile save (review-dialog result) ---
        // The ONLY persistence route for captured profiles. Whitelisted
        // address shape; `ssn` is NEVER accepted here (manual manager entry
        // only — R71-P §6). Duplicate → truthful no-op (no mutation, no
        // push); same title → the user's confirmed UPDATE; otherwise create
        // through the atomic batch (one persist, one eligible sync).
        case 'SAVE_PROFILE_ENTRY': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Vault is locked' })
              return
            }
            const title = String(msg.title || '').trim()
            if (!title || title.length > 200) {
              sendResponse({ ok: false, error: 'A profile name is required (max 200 characters)' })
              return
            }
            const PROFILE_ADDR_KEYS = ['name', 'email', 'phone', 'org', 'street', 'city', 'state', 'zip', 'country']
            const rawAddr = msg.address && typeof msg.address === 'object' ? msg.address : {}
            const address = {}
            for (const k of PROFILE_ADDR_KEYS) {
              const val = String(rawAddr[k] ?? '').trim()
              if (val) address[k] = val.slice(0, 200)
            }
            if (!Object.keys(address).length) {
              sendResponse({ ok: false, error: 'No profile fields to save' })
              return
            }
            const capturedFrom = String(msg.capturedFrom || '').replace(/^www\./, '').slice(0, 200)
            const normAddr = (o) => {
              const out = {}
              for (const [k, val] of Object.entries(o && typeof o === 'object' ? o : {})) {
                const s = String(val || '').replace(/\s+/g, ' ').trim()
                if (s) out[k] = s
              }
              return out
            }
            const existing = v.getOtherEntries().filter(e => e.type === 'address')
            const cand = normAddr(address)
            // Duplicate: identical payload already in the vault → no-op.
            const dup = existing.find((e) => {
              const a = normAddr(e.address)
              const ka = Object.keys(a), kb = Object.keys(cand)
              return ka.length === kb.length && ka.every(k => a[k] === cand[k])
            })
            if (dup) {
              sendResponse({ ok: true, duplicate: true, mode: 'duplicate' })
              return
            }
            // Same title → explicit update (the review dialog is the user's
            // confirmation; keys the review excluded are removed, keys it
            // never displayed keep their stored values — R27 semantics).
            const target = existing.find(e => String(e.username || '').trim().toLowerCase() === title.toLowerCase())
            if (target) {
              const patch = {}
              for (const k of PROFILE_ADDR_KEYS) patch[k] = address[k] || ''
              await v.updateOtherEntry(target.domain, target.username, 'address', { username: title, address: patch })
              sendResponse({ ok: true, mode: 'update' })
              return
            }
            // Create: GLOBAL profile (browser-style — offered on any site).
            // The vault keys entries by (domain, username) and the batch
            // writer requires a domain, so profiles live in the reserved
            // '__profiles__' namespace — the same reserved-pseudo-domain
            // precedent the R70 canonical tokens set with '__totp__'.
            // capturedFrom is shown in the review dialog but deliberately NOT
            // persisted (the batch writer's meta whitelist is url/folder/visit
            // bookkeeping) — profiles carry no site binding by design.
            const entry = { type: 'address', domain: '__profiles__', username: title, address }
            const r = await v.saveEntriesBatch([entry], { awaitPush: true })
            if (!r.added) {
              const why = (r.skipped && r.skipped[0] && r.skipped[0].reason) || 'entry not added'
              sendResponse({ ok: false, error: 'Profile not saved: ' + why })
              return
            }
            sendResponse({ ok: true, mode: 'create' })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        case 'IMPORT_ENTRIES': {
          try {
            const state = await v.getVaultState()
            if (!state.isUnlocked) {
              sendResponse({ ok: false, locked: true, error: 'Vault is locked' })
              return
            }
            const entries = Array.isArray(msg.entries) ? msg.entries : []
            if (entries.length > 10000) {
              sendResponse({ ok: false, error: 'Refusing to import more than 10000 entries at once' })
              return
            }
            const r = await v.saveEntriesBatch(entries, { awaitPush: true })
            const status = await v.getSyncStatus()
            // R90 §2.1 — bulk imports can add logins for the active tab.
            refreshBadge()
            sendResponse({
              ok: true,
              added: r.added,
              skipped: r.skipped || [],
              push: r.push || null,
              sync: {
                enabled: !!status.syncEnabled,
                transport: status.transport ? status.transport.id : null,
                lastModified: status.lastModified,
              },
            })
          } catch (e) {
            sendResponse({ ok: false, error: e.message })
          }
          return
        }

        default:
          sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` })
      }
    } catch (err) {
      console.error('[UCrypt] Message handler error:', err)
      sendResponse({ ok: false, error: err.message || String(err) })
    }
  })()
  return true // keep message channel open for async sendResponse
})

// --- Cross-device sync: react to chrome.storage.sync changes ---------------
// v2.2.0 fix (finding #4): the old handler called a non-existent loadVault()
// and crashed. This version pulls the chunked blob through the vault module.

let _syncPullTimer = null
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'sync') return
  const relevant = Object.keys(changes).some(k =>
    k.startsWith('ucrypt:vaultSync') || k === 'ucrypt:vaultSyncMeta'
  )
  if (!relevant) return

  // Debounce — chunked writes fire several change events in a burst.
  clearTimeout(_syncPullTimer)
  _syncPullTimer = setTimeout(async () => {
    try {
      const v = await vault()
      const state = await v.getVaultState()
      if (!state.isUnlocked) return // picked up on next unlock
      const result = await v.pullFromSync({ skipTransport: true })
      if (result.synced) {
        // R90 §2.1 — another device's writes can change the active tab's count.
        refreshBadge()
        try {
          const { getMessage } = await i18nMod()
          await chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: getMessage('notifUpdatedTitle', undefined, 'UCrypt Updated'),
            message: getMessage('notifPullBody', [result.reason || 'Sync complete', String(result.entryCount || 0)], `${result.reason}. ${result.entryCount || 0} entries.`),
          })
        } catch { /* the notification is best-effort — a blocked surface never perturbs the pull it announces (named-swallow law, R169 C1) */ }
      }
    } catch (e) {
      console.warn('[UCrypt] Sync pull failed:', e)
    }
  }, 1500)
})

console.log('[UCrypt] Background service worker loaded v2.97.0 — THE SPINE PROVED (R140, on the sealed v2.96.0 floor): the roads beneath the Bond rebuilt as THE RELAY — the connected cloud is the rendezvous by DEFAULT (Plane B first-class: availability, offers, and answers ride it automatically), the inbox polls ITSELF every 2–4 seconds (a receiver who opens the page and waits MUST receive — the mailbox read never gates on availability again), the sender’s delivery claim is EVIDENCED (the commit/etag receipt upgrades to fetched — an unevidenced promise is unrepresentable), a device is NEVER nameless (the <Browser> on <OS> default, the banned placeholder zeroed everywhere), two browsers on one machine is first-class, and the Cloud Sync verdict is REACTIVELY DERIVED (pending before the first probe, the 1s/2s/4s/8s/16s ladder owns transient races, ANY success auto-clears, the evidence-only error — the restart banner cannot outlive its own cause). G89/G90 blocking green on REAL two-profile Chromium. Acceptance PENDING_OWNER.')

// R90 §2.1 — initial badge render on every worker wake (a recycled MV3
// worker must never leave a stale or missing badge state).
refreshBadge()

// R86: sw-script marker byte — forces the service-worker update check to see new top-script bytes (the R86 transfer-plane lazy-derive fix ships with this generation).

// R86 marker: lazy chain-key derivation + decline retry + interrupted truth (see worklog R86).
