/**
 * UCrypt — Options page logic (ES module).
 *
 * Responsibilities:
 *   - Full vault CRUD (list / search / add / edit / copy / delete entries).
 *   - Master passphrase set / change / remove.
 *   - Drive sync status + manual sync.
 *   - Generator settings persistence (chrome.storage.local).
 *   - URL scraper for custom diceware wordlist (direct fetch — no proxy).
 *   - Encrypted export / import of the vault.
 *   - Theme toggle (dark/light, persisted in chrome.storage.local).
 *   - Emergency wipe.
 */

if (typeof globalThis.chrome === 'undefined' || !globalThis.chrome?.storage?.local) {
  const mem = {}
  const getStore = (k) => {
    try { const raw = globalThis.localStorage?.getItem(k); return raw != null ? JSON.parse(raw) : mem[k] } catch { return mem[k] }
  }
  const setStore = (k, v) => {
    mem[k] = v
    try { globalThis.localStorage?.setItem(k, JSON.stringify(v)) } catch { /* ignore */ }
  }
  const removeStore = (k) => {
    delete mem[k]
    try { globalThis.localStorage?.removeItem(k) } catch { /* ignore */ }
  }
  const localShim = {
    get(keys, cb) {
      const out = {}
      if (typeof keys === 'string') {
        const val = getStore(keys)
        if (val !== undefined) out[keys] = val
      } else if (Array.isArray(keys)) {
        for (const k of keys) { const val = getStore(k); if (val !== undefined) out[k] = val }
      } else if (keys && typeof keys === 'object') {
        for (const [k, def] of Object.entries(keys)) { const val = getStore(k); out[k] = val !== undefined ? val : def }
      }
      if (typeof cb === 'function') cb(out)
      return Promise.resolve(out)
    },
    set(items, cb) {
      if (items && typeof items === 'object') {
        for (const [k, v] of Object.entries(items)) setStore(k, v)
      }
      if (typeof cb === 'function') cb()
      return Promise.resolve()
    },
    remove(keys, cb) {
      const list = Array.isArray(keys) ? keys : [keys]
      for (const k of list) removeStore(k)
      if (typeof cb === 'function') cb()
      return Promise.resolve()
    },
  }
  globalThis.chrome = {
    ...(globalThis.chrome || {}),
    storage: {
      local: localShim,
      session: localShim,
      onChanged: { addListener() {}, removeListener() {} },
    },
    runtime: {
      id: 'ucrypt-standalone-preview',
      lastError: null,
      getManifest: () => ({ version: '3.46.0', name: 'UCrypt' }),
      getURL: (p) => p,
      sendMessage: (_msg, cb) => {
        const res = { ok: true, entries: [], tokens: [], state: { initialized: true, unlocked: true, isUnlocked: true, hasMaster: true, entries: [], lockTimeoutMs: 900000 }, sync: { entryCount: 0, totalCount: 0 } }
        if (typeof cb === 'function') cb(res)
        return Promise.resolve(res)
      },
      onMessage: { addListener() {}, removeListener() {} },
    },
    i18n: { getMessage: () => '' },
    tabs: { create() {}, query: (_q, cb) => { if (cb) cb([]); return Promise.resolve([]) } },
  }
}

import {
  generateRandomPassword,
  generatePassphrase,
  generatePin,
  generatePronounceable,
  generateMnemonic,
  validateMnemonic,
  generateSecret,
  PassphraseFilterError,
  PRESETS,
} from './lib/generator.js'
import { analyzePassword, strengthBucket, strengthBadge, crackTime } from './lib/analyzer.js'
import { ensureBreachCorpus, ensureBip39, ensureWordlists } from './lib/corpus.js'
import {
  generateSyncCode,
  validateSyncCode,
  deriveSyncKey,
  syncFingerprint,
  buildPairingUri,
  parsePairingUri,
  safeCloudForPairing,
  pairingSegmentNames,
  PAIRING_CONN_FIELD_TARGETS,
  PAIRING_CONN_BRIDGE_TARGETS,
} from './lib/sync.js'
// R45: the page imports the BIP-39 list explicitly — lib/sync.js's
// getWordlist() needs it here (the worker gets the same list via its own
// static import; the v2.21.0 build lost the page path too).
import './lib/bip39.js'
import { registerBeamExecutor } from './lib/beam-executor-page.js'
import { applyI18n, getMessage } from './lib/i18n.js'
// R171 — THE HONEST ERROR LAW: the ONE materializer every user-facing
// interpolation seat rides (a Promise/object can never reach the owner's
// eye — the E-24 "[object Promise]" cure, render half).
// R174 — the string-poison heal rides the render half too (the eye's last
// line): a stored STRING carrying the "[object …]" poison (the field's 10:41
// row) renders the typed generic — never the engine shape.
import { materializeUserText, healPoisonedUserText, beltRender, carry } from './lib/honest-error.js'
import { boundedImport, watchdogLandingWords } from './lib/import-watchdog.js'
// R174 — THE ONE-TRUTH FAMILY RESOLVER (R-174.1/R-174.2/R-174.5): the strip,
// the diagnosed line, and the checklist render ONE named class from the pull
// row's OWN typed fields — the read wall is unreachable pre-read, the
// unnamed fallback is extinct, and the checklist reads CONNECTION evidence.
import { resolveAttentionFamily, readMaySpeakWall, checklistConnectionFacts, ATTENTION_FAMILIES } from './lib/attention-family.js'
// R170 — THE SETTLED HOUSE: the ONE shared disclosure pattern (persistence
// per area + the fire exception) for every collapsed surface on this page.
import { SettledHouse } from './lib/settled-house.js'
import { getVaultSort, setVaultSort, vaultSortComparator, getBehaviorPrefs, saveBehaviorPrefs, mergeLabPrefs } from './lib/prefs.js'
import { transports, getTransport } from './lib/transports/index.js'
// R160 ARC A′ — the proactive Testing-expiry card (the Cloud Sync area's
// Layer-1 detector + the dismissal law; lib/cloud/testing-card.js is PURE).
import { deriveTestingCard, TESTING_EVIDENCE_KEY, TESTING_DISMISSAL_KEY } from './lib/cloud/testing-card.js'
// R160 ARC C′ — the dataset-share summary card (the ten classes with live
// counts; lib/transfer/share-summary.js is PURE and masked).
import { buildShareSummary } from './lib/transfer/share-summary.js'
import { buildBookmarkRestorePlan } from './lib/bookmarks-restore.js'
// R112 §2 — Direct Share (D1–D10): the handshake is the product. The page
// hosts the whole session (the MV3 worker cannot: no RTCPeerConnection —
// the R99 measured fact); the module is share-domain-only — it NEVER
// imports vault/sync (the separation law, 0.27).
import * as Share from './lib/share.js'
// R124 §2 (D13) — THE ASYNC PICKUP: the hold engine (vault-free by law 0.38)
// and its transport bridge. The page orchestrates: the engine derives/seals/
// opens, the bridge uploads/links/cancels, and the hold's state rides THIS
// page's own storage key — the pickup never touches the vault's surfaces.
import * as Pickup from './lib/pickup.js'
import { pickupSupport, pickupUploadAndLink, pickupCancel } from './lib/transports/pickup-links.js'
// R132 (law 0.46 — THE PRESENCE-HONESTY LAW; the CEO's S1): the roster's
// annotation derives from the pure law — an online device is NEVER displayed
// as offline; the capability-less transport renders the honest unknown.
import { presenceAnnotation, presenceTone, PRESENCE_STATES } from './lib/presence.js'
// R132 (law 0.47 — THE PASTE-GUIDANCE LAW; the CEO's S2): every pasted share
// signal is classified with its typed identity and next action.
import { classifyPastedSignal, refineForShareBox, PASTE_CLASSES } from './lib/paste-classify.js'
// R105 §2.2 — the diagnostics export (Help area; the 0.14 export-exclusion
// discipline lives in the module — the page only renders what it returns).
import { collectDiagnostics, diagnosticsJson } from './lib/diagnostics.js'
import * as Walk from './lib/walkthrough.js'
import { gdriveBridgeScript } from './lib/transports/gdrive.js'
import { validateClientIdFormat, identityRedirect, launchOAuthFlow } from './lib/transports/gdrive-oauth-help.js'
// R119 §2 (law 0.32, order §3.5) — THE SIGN-IN LADDER UI: the rungs render
// inside the transport wizard (fast → guided → manual); the walkthrough and
// the typed fast-fail cards live in the module (a renderer: chrome APIs ok).
import { renderLadderBlock, renderPreflightCard, renderWalkthrough } from './lib/ladder-ui.js'
// R120 (law 0.33) — the rung lifecycle: the PURE plan + the truthful state
// line ride lib/ladder.js (the engine's home); the executor below runs the
// plan through the seams that already exist (never a new transport path).
import { preflightClientId, isSigninMode, describeRungState, planRungSwitch } from './lib/ladder.js'
// R120 (law 0.33) — the switch is evidence: the SAME recordRing import path
// the ladder UI's rungRingRecord rows use (lib/egrings.js).
import { recordRing } from './lib/egrings.js'
// R119 — isSigninMode comes from lib/ladder.js (the allowlist's home; lib/sync.js
// imports it there too but does not re-export it).
import {
  SOURCES,
  parseImportFile,
  buildFullPlan,
  planSummary,
  itemToVaultEntry,
  historyRangeOrDefault,
  historyItemsToEntries,
  LIMITS,
  historyPreviewSummary,
  HISTORY_LAW,
  MIGRATION_BROWSERS,
  MIGRATION_BROWSER_IDS,
  passwordsExportLink,
  flattenBookmarkTree,
} from './lib/importers.js'

// --- Constants -------------------------------------------------------------

const PREFS_KEY = 'ucrypt:prefs:popup'
const THEME_KEY = 'ucrypt:theme'
const WORDLIST_KEY = 'ucrypt:customWordlist'
// R156 (the whole-area port) — the typed toast lifetimes ride the ancestor's
// law module again: status toasts auto-dismiss at the bounded TOAST_STATUS_MS
// (6 s, ledgered); a consent toast NEVER auto-closes (LAW #15). The R151-era
// rebuild had regressed this surface to a bare 2800 ms timeout — the
// "Pairing code copied" disease class, killed again at the source.
import { toastLifetime, TOAST_STATUS_MS, parsePastedWords, wordCountMessage } from './lib/r145-laws.js'

const DEFAULT_RANDOM = {
  length: 20,
  lowercase: true,
  uppercase: true,
  numbers: true,
  symbols: true,
  excludeAmbiguous: true,
  noDuplicates: false,
  noSequences: false,
  excludeChars: '',
}

// --- Helpers ---------------------------------------------------------------

function $(id) { return document.getElementById(id) }

function toast(msg, kind = 'info') {
  const el = $('toast')
  if (!el) return
  // LAW 0.52 (R133) — the text rides its own span; the ✕ close is always
  // present (an expiring toast still carries the user's own exit).
  const textEl = $('toastText')
  if (textEl) textEl.textContent = msg
  else el.textContent = msg
  el.className = 'toast' + (kind === 'error' ? ' toast-error' : '')
  void el.offsetWidth
  el.classList.remove('hidden')
  // R145 §4.4 (the G-9 cure) — THE TYPED LIFETIMES: a status toast
  // auto-dismisses at the bounded TOAST_STATUS_MS (6 s, ledgered); a
  // consent toast ('consent'/'sticky') NEVER auto-closes — only the user's
  // × ends it. The × always works in both lifetimes. No timer survives a
  // reload (the element boots hidden; nothing re-opens an old toast).
  clearTimeout(toast._t)
  const life = toastLifetime(kind)
  if (life.autoDismissMs != null) {
    toast._t = setTimeout(() => el.classList.add('hidden'), life.autoDismissMs)
  } else {
    toast._t = null // consent: the user owns the close
  }
}

function mask(s) {
  if (!s) return ''
  s = String(s)
  if (s.length <= 2) return s[0] + '•'.repeat(s.length - 1)
  return s[0] + '•'.repeat(s.length - 2) + s[s.length - 1]
}

// v2.16.0 — device-local vault sort mode (shared with the popup via lib/prefs.js)
let vaultSortMode = 'site'

/**
 * v2.16.0 — compact relative time for the "used … ago" suffix
 * (e.g. "just now", "5 min", "3 h", "2 d") — locale-neutral by design.
 */
function relativeTime(ts) {
  const diff = Date.now() - ts
  if (diff < 60 * 1000) return getMessage('timeJustNow', undefined, 'just now')
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return getMessage('timeMinAgo', [String(mins)], `${mins} min`)
  const hours = Math.floor(mins / 60)
  if (hours < 24) return getMessage('timeHoursAgo', [String(hours)], `${hours} h`)
  const days = Math.floor(hours / 24)
  return getMessage('timeDaysAgo', [String(days)], `${days} d`)
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    // R97 (F-R96-1): every vault-secret copy arms the lock-moment clipboard
    // guard (lib/clipguard.js — install() below). Non-secret copies do NOT
    // arm it and call writeText directly (the diagnostic summary, the
    // transfer decision record, the OAuth redirect URI) — measured scope.
    if (globalThis.UCryptClipGuard) globalThis.UCryptClipGuard.arm()
    return true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.cssText = 'position:fixed;left:-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      if (globalThis.UCryptClipGuard) globalThis.UCryptClipGuard.arm()
      return true
    } catch {
      return false
    }
  }
}

// --- Background messaging ---------------------------------------------------

function bgSend(type, data = {}) {
  return new Promise((resolve) => {
    try {
      // v2.10.0 QA FIX — the payload spread BEFORE the message type. The old
      // `{ type, ...data }` let any payload carrying its own `type` field
      // (e.g. the other-data pane's entry type) CLOBBER the message type on
      // the wire, so DELETE_ENTRY/UPDATE_OTHER_ENTRY never reached their
      // background cases. With data first, the message type always wins.
      chrome.runtime.sendMessage({ ...data, type }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message })
          return
        }
        resolve(response || { ok: false, error: 'No response' })
      })
    } catch (e) {
      resolve({ ok: false, error: e.message })
    }
  })
}

// --- Settings persistence --------------------------------------------------

function loadPrefs() {
  return new Promise((resolve) => {
    chrome.storage.local.get(PREFS_KEY, (r) => {
      const saved = r && r[PREFS_KEY]
      resolve({
        ...saved,
        random: { ...DEFAULT_RANDOM, ...((saved && saved.random) || {}) },
      })
    })
  })
}

function savePrefs(prefs) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [PREFS_KEY]: prefs }, () => resolve())
  })
}

function loadTheme() {
  return new Promise((resolve) => {
    chrome.storage.local.get(THEME_KEY, (r) => {
      resolve(r && r[THEME_KEY] || 'dark')
    })
  })
}

function saveTheme(t) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [THEME_KEY]: t }, () => resolve())
  })
}

function loadCustomWordlist() {
  return new Promise((resolve) => {
    chrome.storage.local.get(WORDLIST_KEY, (r) => {
      try {
        const v = r && r[WORDLIST_KEY]
        resolve(v ? (Array.isArray(v) ? v : JSON.parse(v)) : null)
      } catch {
        resolve(null)
      }
    })
  })
}

function saveCustomWordlist(words) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [WORDLIST_KEY]: JSON.stringify(words) }, () => resolve())
  })
}

function removeCustomWordlist() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(WORDLIST_KEY, () => resolve())
  })
}

// --- Tab switching (v2.3.0: hash-routable — options.html#sync etc.) --------

function switchTab(name) {
  document.querySelectorAll('.opts-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name)
    b.setAttribute('aria-selected', String(b.dataset.tab === name)) // R173 §Arc B (B10) — the main bar speaks tablist
  })
  document.querySelectorAll('.opts-panel').forEach(p => {
    p.classList.toggle('active', p.id === 'tab-' + name)
  })
  try { history.replaceState(null, '', '#' + name) } catch { /* ignore */ }
  // R118 §3.1 — THE TAB-SWITCH FOCUS BEHAVIOR: a keyboard user landing on a
  // new tab needs the new tab's CONTEXT, not a silent panel swap. The
  // panel's heading (tabindex="-1") receives focus (preventScroll — the
  // heading sits at the top anyway); mouse users see nothing change.
  try {
    const panel = document.getElementById('tab-' + name)
    const heading = panel && panel.querySelector('.opts-panel-h1')
    if (heading) heading.focus({ preventScroll: true })
    else if (panel) panel.focus({ preventScroll: true }) // R173 §Arc B (B10) — every panel is focusable (tabindex="-1"): the switch always lands with context
  } catch { /* best-effort — the visual switch already happened */ }
  // R108 §4.1 — the File-transfer front door: the embedded experience loads
  // on FIRST activation only (merely opening Settings never arms the beam —
  // the presence opt-in stays the transfer surface's opening).
  if (name === 'transfer') {
    const fr = document.getElementById('fileTransferFrame')
    if (fr && fr.dataset.src && !fr.src) {
      try { fr.src = fr.dataset.src } catch { /* the Open pointer still works */ }
    }
  }
  refreshChecklist()
  if (name === 'vault') refreshVault()
  if (name === 'sync') refreshSync()
  if (name === 'generator') refreshGenerator()
}

/**
 * v2.3.0 — initial tab resolution order:
 *   1. URL hash (options.html#sync — shareable, works from the QR flow)
 *   2. the 'ucrypt:openTab' handoff flag (popup "Set up sync…" button)
 *   3. last tab if valid, else Vault
 */
let _openJoinOnBoot = false
let _openCloudOnBoot = false // R155 §8 (D.4) — options.html#sync-cloud: the Sync tab AND the cloud overlay
async function resolveInitialTab() {
  // R118 §2.1 — the two-tab world: 'share' joins the valid set (the Direct
  // Share tab; the devices experience keeps 'transfer').
  const valid = ['vault', 'security', 'sync', 'transfer', 'share', 'generator', 'wordlists', 'data']
  const hash = (location.hash || '').replace('#', '')
  // R61-A §1.3 — the #join deep link routes to the Sync tab AND opens the
  // guided join wizard. Captured HERE (before switchTab rewrites the hash).
  if (hash === 'join') { _openJoinOnBoot = true; return 'sync' }
  // R155 §8 (D.4, LAW #98) — the #sync-cloud deep link: the cloud setup
  // opens SCROLLED + FOCUSED (the Z-2 contract) — the accelerator's door,
  // reached from the Device Transfer strip in one click.
  if (hash === 'sync-cloud') { _openCloudOnBoot = true; return 'sync' }
  if (valid.includes(hash)) return hash
  try {
    const { 'ucrypt:openTab': flag } = await chrome.storage.local.get('ucrypt:openTab')
    if (flag) {
      await chrome.storage.local.remove('ucrypt:openTab')
      if (valid.includes(flag)) return flag
    }
  } catch { /* ignore */ }
  const active = document.querySelector('.opts-tab.active')
  return (active && valid.includes(active.dataset.tab)) ? active.dataset.tab : 'vault'
}

// --- Getting-started checklist (v2.3.0; R45-E tri-state rework) -------------

const CHECKLIST_KEY = 'ucrypt:checklistDismissed'
const CHECKLIST_SKIP_KEY = 'ucrypt:checklistSkips'
// R85 (§4): the last REAL checklist signal set — the deep links read it.
let lastChecklistState = { hasMaster: false, hasSyncCode: false }

async function refreshChecklist() {
  const card = $('checklistCard')
  if (!card) return
  const state = await bgSend('GET_STATE')
  const sync = (state && state.ok && state.sync) || {}
  const kdf = await bgSend('SYNC_KDF_INFO')
  try {
    // R87 (§2.2): the deep-link truth is computed from the REAL fetched state
    // (the previous assignment referenced the not-yet-declared `state` and
    // silently kept hasMaster=false forever — S6's wrong-routes component).
    lastChecklistState = {
      hasMaster: !!(state && state.ok && state.state && state.state.hasMaster),
      hasSyncCode: !!(kdf && kdf.ok && kdf.info && kdf.info.hasSyncCode),
    }
    const { [CHECKLIST_KEY]: dismissed } = await chrome.storage.local.get(CHECKLIST_KEY)
    if (dismissed) { card.classList.add('hidden'); return }
  } catch { /* storage unavailable — keep visible */ }
  card.classList.remove('hidden')

  const hasSyncCode = !!(kdf && kdf.ok && kdf.info && kdf.info.hasSyncCode)
  lastChecklistState.hasSyncCode = hasSyncCode
  // R174 — THE CONNECTION EVIDENCE LAW (R-174.1, the E-29 cure): the
  // "Connect a cloud drive" step reads the CONNECTION truth — the transport
  // record resolves = the step is DONE. A push ledger row (ok or failed) is
  // the FIRST-SYNC step's story and can never flip the connection step
  // again: an unfinished "Connect a cloud drive" beside a connected cloud
  // (the field's exact incoherence) is unrepresentable from this law on.
  const conn = checklistConnectionFacts(sync)
  const hasTransport = conn.connected
  // R45-E carried, re-homed: a push's own evidence (verified / waiting /
  // failed) is the FIRST-SYNC step's story — a connected-but-never-pushed
  // cloud is the virgin road's open "Run your first sync" step, never a
  // connection failure.
  const pushSkipped = !!(sync.lastPush && sync.lastPush.skipped)
  const pushFailedFresh = !!(sync.lastPush && sync.lastPush.ok === false && !pushSkipped)
  // R174 — the ⚠ blocked class keys on a BROKEN CONNECTION with fresh push
  // failure evidence — never on a failed push beside a connected cloud.
  const transportBlocked = conn.blocked && pushFailedFresh

  const { [CHECKLIST_SKIP_KEY]: skipsRaw } = await chrome.storage.local.get(CHECKLIST_SKIP_KEY)
  const skips = Array.isArray(skipsRaw) ? skipsRaw : []

  // R175 — THE COMPLETING CHECKLIST (R-175.6): "Run first sync" completes on
  // the first fully-successful typed cycle — the SAME projection as R-175.1.
  // No step may stand open beside evidence of its own completion; the legacy
  // content predicate keeps pre-v3.35 settled devices byte-true (additions-
  // only), and the fresh-cloud cycle's own verdict is the new completion
  // evidence. The step re-renders on every cycle event (the onChanged wire
  // below) — a locked-wake render can never freeze an open step beside a
  // landed cycle again.
  let cycleOk = false
  try {
    const c = (await chrome.storage.local.get('ucrypt:lastCycle'))['ucrypt:lastCycle']
    cycleOk = !!(c && c.verdict === 'ok')
  } catch { cycleOk = false }
  const steps = {
    master: !!(state && state.ok && state.state && state.state.hasMaster),
    syncCode: hasSyncCode,
    transport: hasTransport,
    firstSync: cycleOk || (!!sync.lastModified && (sync.entryCount || 0) > 0),
  }
  let done = 0, skipped = 0, blocked = false
  for (const [key, ok] of Object.entries(steps)) {
    const li = document.querySelector(`#checklist li[data-step="${key}"]`)
    if (!li) continue
    const isSkipped = !ok && skips.includes(key)
    li.classList.toggle('done', ok)
    li.classList.toggle('skipped', isSkipped)
    li.classList.toggle('blocked', !ok && !isSkipped && key === 'transport' && transportBlocked)
    if (key === 'transport' && transportBlocked) blocked = true
    const link = li.querySelector('.check-link')
    if (link) {
      // v2.18.0 — R27-i18n: the state render used to clobber the localized
      // "Open" with a hardcoded literal after applyI18n had run.
      link.textContent = ok ? '✓' : isSkipped ? '↷' : (key === 'transport' && transportBlocked) ? '⚠' : getMessage('checkOpen', undefined, 'Open')
      link.classList.toggle('done', ok)
      if (ok || isSkipped) link.removeAttribute('href')
      else link.setAttribute('href', link.dataset.href || '#')
    }
    // R45-E: per-step "skip intentionally" control while the step is open.
    let skipBtn = li.querySelector('.check-skip')
    if (!skipBtn && !ok) {
      skipBtn = document.createElement('button')
      skipBtn.type = 'button'
      skipBtn.className = 'check-skip btn btn-ghost btn-sm'
      skipBtn.textContent = getMessage('checkSkip', undefined, 'Skip')
      skipBtn.addEventListener('click', async () => {
        const { [CHECKLIST_SKIP_KEY]: cur } = await chrome.storage.local.get(CHECKLIST_SKIP_KEY)
        const next = new Set(Array.isArray(cur) ? cur : [])
        next.add(key)
        await chrome.storage.local.set({ [CHECKLIST_SKIP_KEY]: [...next] })
        refreshChecklist()
      })
      li.appendChild(skipBtn)
    }
    if (skipBtn) skipBtn.classList.toggle('hidden', ok || isSkipped)
    if (ok) done++
    else if (isSkipped) skipped++
  }
  $('checklistProgress').textContent = `${done} / 4`
  const settled = done + skipped
  if (settled === 4 && done < 4) {
    // R45-E: honest partial label — skipped intentionally is NOT "All set".
    $('checklistProgress').textContent = getMessage('checkDoneSkipped', undefined, 'Set up (with skipped steps)')
  } else if (done === 4) {
    $('checklistProgress').textContent = getMessage('checkAllSet', undefined, 'All set 🎉')
  } else if (blocked) {
    // R45-E: a failed cloud attempt must never render as settled.
    $('checklistProgress').textContent = getMessage('checkBlocked', undefined, 'Blocked — the last cloud push failed')
  }
}

// --- Theme -----------------------------------------------------------------

async function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme)
  try {
    const f = document.getElementById('fileTransferFrame')
    if (f && f.contentDocument && f.contentDocument.documentElement) {
      f.contentDocument.documentElement.setAttribute('data-theme', theme)
    }
  } catch { /* cross-origin safe */ }
  await saveTheme(theme)
}

async function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark'
  await applyTheme(cur === 'dark' ? 'light' : 'dark')
}

// --- Vault -----------------------------------------------------------------

let vaultState = null

// v2.21.0 — R30-F3: the login list is cached at load time. The search box
// used to re-run the FULL refreshVault() on every keystroke — a background
// round-trip plus a complete re-render and a per-entry analyzePassword for
// every character typed. The cache makes the keystroke path local; it is
// refreshed by every real reload (and after save/delete, which re-fetch).
let vaultLoginCache = []

// v2.21.0 — R30-F3: per-password analysis memo. renderVault used to run
// analyzePassword (entropy + the breach substring scan) for EVERY entry on
// EVERY render — O(vault) CPU per keystroke. Passwords repeat far more
// often than entries change, so a Map keyed by the password turns the
// per-keystroke cost into cache hits. Cleared whenever the vault reloads.
const _analysisMemo = new Map()
function analyzeCached(pw) {
  const key = String(pw ?? '')
  let m = _analysisMemo.get(key)
  if (m === undefined) {
    m = analyzePassword(key)
    _analysisMemo.set(key, m)
  }
  return m
}

async function refreshVault() {
  const r = await bgSend('GET_STATE')
  if (!r || !r.ok) {
    toast(getMessage('statusBgError', undefined, 'Background error'), 'error')
    return
  }
  vaultState = r.state
  if (!vaultState.hasMaster) {
    $('vaultStatusBanner').classList.remove('hidden')
    $('vaultStatusBanner').querySelector('span').textContent =
      getMessage('statusNoMaster', undefined, 'No master passphrase set yet. Visit the Security tab to set one up.')
    $('vaultLocked').classList.add('hidden')
    $('vaultUnlocked').classList.add('hidden')
    if ($('vaultHeroStateText')) $('vaultHeroStateText').textContent = 'No master passphrase set yet — open Security to create your AES-256-GCM vault'
    if ($('vaultChipEncryptionText')) $('vaultChipEncryptionText').textContent = 'Vault uninitialized'
    return
  }
  if (!vaultState.isUnlocked) {
    $('vaultStatusBanner').classList.remove('hidden')
    $('vaultStatusBanner').querySelector('span').textContent =
      getMessage('vaultLockedBanner', undefined, '🔒 Vault is locked. Enter your passphrase to manage entries.')
    $('vaultLocked').classList.remove('hidden')
    $('vaultUnlocked').classList.add('hidden')
    if ($('vaultHeroStateText')) $('vaultHeroStateText').textContent = 'Vault is locked · AES-256-GCM encrypted at rest · Unlock below to manage entries'
    if ($('vaultChipEncryptionText')) $('vaultChipEncryptionText').textContent = 'Locked · AES-256-GCM'
    // R112 §2 (D9) — the lock kills any live Direct Share session (typed
    // interrupted; the ephemeral keys are destroyed by the listener).
    try { window.dispatchEvent(new CustomEvent('ucrypt:vault-locked')) } catch { /* no listeners yet */ }
    return
  }
  $('vaultStatusBanner').classList.add('hidden')
  $('vaultLocked').classList.add('hidden')
  $('vaultUnlocked').classList.remove('hidden')

  // R30-F1: the breach corpus is lazy — the vault manager's per-entry breach
  // badges and the breached-count stat must never run against an empty set.
  await ensureBreachCorpus()
  const r2 = await bgSend('GET_ALL_ENTRIES')
  if (!r2 || !r2.ok || !r2.entries) {
    toast(getMessage('statusLoadFailed', undefined, 'Could not load entries — reopen the popup.'), 'error')
    return
  }
  // v2.4.0 — TOTP tokens live in the vault as type:'totp' entries; they are
  // managed from the popup's 2FA tab, so the login manager hides them.
  // v2.7.0 — imported other-data (notes/cards/identities/bookmarks/history/
  // forms) is also excluded from the login list and shown in its own pane.
  const loginEntries = r2.entries.filter(e => e.type === undefined || e.type === null || e.type === 'login')
  vaultLoginCache = loginEntries
  _analysisMemo.clear() // R30-F3: fresh data — stale analyses must not survive
  renderVault(loginEntries)
  importOtherDataSection(r2.entries.filter(e => ['note', 'card', 'address', 'bookmark', 'history', 'form'].includes(e.type)))
}

function renderVault(entries) {
  const search = ($('vaultSearch').value || '').toLowerCase().trim()
  const filtered = search
    ? entries.filter(e =>
        (e.domain || '').toLowerCase().includes(search) ||
        (e.username || '').toLowerCase().includes(search)
      )
    : entries

  const domains = new Set(entries.map(e => e.domain))
  const breached = entries.filter(e => {
    const r = analyzeCached(e.password)
    return r && r.breached
  })

  $('statEntries').textContent = String(entries.length)
  $('statDomains').textContent = String(domains.size)
  $('statBreached').textContent = String(breached.length)

  if ($('vaultHeroStateText')) {
    $('vaultHeroStateText').textContent = `Unlocked · ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} across ${domains.size} ${domains.size === 1 ? 'site' : 'sites'} · ${breached.length} breached`
  }
  if ($('vaultChipEncryptionText')) {
    $('vaultChipEncryptionText').textContent = `Unlocked · ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`
  }
  if ($('vaultChipHealthText')) {
    $('vaultChipHealthText').textContent = breached.length > 0 ? `${breached.length} breached · review health` : 'Password Health · 0 breached'
  }
  if ($('dataHeroStateText')) {
    $('dataHeroStateText').textContent = `Encrypted .ucrypt backup ready · ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} in vault · 100% local migration`
  }

  const list = $('vaultList')
  list.innerHTML = ''
  if (filtered.length === 0) {
    // R173 §Arc B (B1) — THE EMPTY TRUTH: an empty vault and a search that
    // matches nothing are DIFFERENT absences; each speaks its own words.
    list.innerHTML = entries.length === 0
      ? `<div class="vault-empty">${getMessage('rowEmptyVault', undefined, 'Your vault is empty — add your first entry with “New entry”, or bring passwords in from the Export / Import tab.')}</div>`
      : `<div class="vault-empty">${getMessage('rowEmptySearch', undefined, 'No entries match your search.')}</div>`
    return
  }
  // v2.16.0 — user-selectable sort (Brave-gap): the historical fixed
  // domain→username order is now the 'site' option among four modes.
  const sorted = [...filtered].sort(vaultSortComparator(vaultSortMode))

  // v2.21.0 — R30-F3: chunked rendering for very large vaults. A 3000-entry
  // vault used to build ~18k DOM nodes synchronously on every render (every
  // keystroke, every sort change). Now: the first CHUNK renders immediately
  // (the stats above still cover the WHOLE vault — after the first pass they
  // are cheap Map hits), and further chunks append when the sentinel scrolls
  // near (IntersectionObserver) or when the explicit "Show the remaining N"
  // button is clicked — the observer alone is not an accessible affordance.
  const CHUNK = 120
  let cursor = 0
  let observer = null

  const sentinel = document.createElement('div')
  sentinel.className = 'vault-chunk-sentinel'
  sentinel.setAttribute('aria-hidden', 'true')

  const showMoreBtn = document.createElement('button')
  showMoreBtn.className = 'btn btn-outline btn-sm vault-show-more'
  showMoreBtn.type = 'button'
  showMoreBtn.addEventListener('click', () => {
    // Explicit request: render EVERYTHING that is left.
    if (observer) { observer.disconnect(); observer = null }
    for (; cursor < sorted.length; cursor++) list.appendChild(makeVaultRow(sorted[cursor]))
    sentinel.remove()
    showMoreBtn.remove()
  })

  function appendChunk() {
    const end = Math.min(cursor + CHUNK, sorted.length)
    for (; cursor < end; cursor++) list.appendChild(makeVaultRow(sorted[cursor]))
    if (cursor < sorted.length) {
      showMoreBtn.textContent = getMessage('rowShowMore', [String(sorted.length - cursor)], `Show the remaining ${sorted.length - cursor} entries`)
      list.appendChild(sentinel) // appendChild MOVES it to the end
      list.appendChild(showMoreBtn)
      if (typeof IntersectionObserver === 'function') {
        if (observer) observer.disconnect()
        observer = new IntersectionObserver((es) => {
          if (es.some(e => e.isIntersecting)) {
            observer.disconnect()
            observer = null
            appendChunk()
          }
        }, { rootMargin: '240px' })
        observer.observe(sentinel)
      } else {
        // Engine without the observer: the button alone carries it.
        sentinel.remove()
      }
    } else {
      if (observer) { observer.disconnect(); observer = null }
      sentinel.remove()
      showMoreBtn.remove()
    }
  }

  appendChunk()
}

function makeVaultRow(entry) {
  const row = document.createElement('div')
  row.className = 'vault-entry'

  const meta = document.createElement('div')
  meta.className = 'vault-entry-meta'
  const dom = document.createElement('div')
  dom.className = 'vault-entry-domain'
  dom.textContent = entry.domain
  const user = document.createElement('div')
  user.className = 'vault-entry-user'
  user.textContent = entry.username || getMessage('rowNoUsername', undefined, '(no username)')
  const date = document.createElement('div')
  date.className = 'vault-entry-date'
  // v2.16.0 — show last-USED next to last-changed when this device has
  // filled the entry (device-local telemetry; "never" means never here).
  const changedStr = new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleDateString()
  const usedAt = Number(entry.lastUsedAt) || 0
  date.textContent = usedAt
    ? `${changedStr} · ${getMessage('usedAgo', [relativeTime(usedAt)], `used ${relativeTime(usedAt)} ago`)}`
    : changedStr
  date.title = usedAt
    ? getMessage('rowChangedBoth', [new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleString(), new Date(usedAt).toLocaleString()], `Changed ${new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleString()} · Used ${new Date(usedAt).toLocaleString()}`)
    : getMessage('rowChangedOnly', [new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleString()], `Changed ${new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleString()}`)
  meta.appendChild(dom)
  meta.appendChild(user)
  meta.appendChild(date)

  const analysis = analyzeCached(entry.password)
  // R72 §3.3 (owner screenshot 20261001_135912): the badge shows the FULL
  // strength label — "VERY WEAK", never a "VERY" truncation — with text +
  // color + an accessible name, and BREACHED supersedes the entropy label.
  const badge = strengthBadge(analysis)
  const strengthBadgeEl = document.createElement('span')
  strengthBadgeEl.className = 'vault-strength'
  strengthBadgeEl.style.background = badge.color
  strengthBadgeEl.style.color = '#fff'
  strengthBadgeEl.textContent = badge.label
  strengthBadgeEl.setAttribute('aria-label', getMessage('strengthBadgeAria', [badge.label], badge.aria))
  strengthBadgeEl.title = getMessage('strengthLine', [badge.label, crackTime(analysis.effective)], `${badge.label} · ${crackTime(analysis.effective)} to crack`)

  const actions = document.createElement('div')
  actions.className = 'vault-entry-actions'

  // v2.16.0 — Copy-username (Brave parity; the popup rows always had it,
  // the options rows only offered copy-password).
  const copyUserBtn = document.createElement('button')
  copyUserBtn.className = 'btn btn-outline btn-sm'
  copyUserBtn.textContent = getMessage('rowBtnCopyUser', undefined, 'Copy user')
  copyUserBtn.title = getMessage('rowBtnCopyUserTitle', undefined, 'Copy username')
  copyUserBtn.onclick = async (e) => {
    e.preventDefault()
    const ok = await copy(entry.username || '')
    if (ok) toast(getMessage('toastUserCopied', undefined, 'Username copied'))
    else toast(getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), 'error')
  }

  const copyBtn = document.createElement('button')
  copyBtn.className = 'btn btn-outline btn-sm'
  copyBtn.textContent = getMessage('rowBtnCopy', undefined, 'Copy')
  copyBtn.title = getMessage('rowBtnCopyTitle', undefined, 'Copy password')
  copyBtn.onclick = async (e) => {
    e.preventDefault()
    const ok = await copy(entry.password)
    if (ok) toast(getMessage('toastPwCopied', undefined, 'Copied — auto-clears in 20s'))
    else toast(getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), 'error')
    setTimeout(async () => {
      try {
        const cur = await navigator.clipboard.readText().catch(() => '')
        if (cur === entry.password) await navigator.clipboard.writeText('')
      } catch { /* the clipboard wipe is best-effort — a closed clipboard never perturbs the copy it cleans (named-swallow law, R169 C1) */ }
    }, 20000)
  }

  const editBtn = document.createElement('button')
  editBtn.className = 'btn btn-outline btn-sm'
  editBtn.textContent = getMessage('rowBtnEdit', undefined, 'Edit')
  editBtn.onclick = (e) => {
    e.preventDefault()
    openEntryDialog(entry)
  }

  const delBtn = document.createElement('button')
  delBtn.className = 'btn btn-danger btn-sm'
  delBtn.textContent = getMessage('rowBtnDelete', undefined, 'Delete')
  delBtn.onclick = async (e) => {
    e.preventDefault()
    if (!confirm(getMessage('rowDeleteConfirm', [entry.username, entry.domain], `Delete "${entry.username}" for ${entry.domain}?`))) return
    // v2.42.7 — R70 §2.3 (F-R70-MODEL-1): a login's standalone authenticator
    // is NEVER silently destroyed. If linked token(s) exist, the user makes
    // the EXPLICIT choice; Cancel (the default) keeps them in the 2FA tab,
    // unlinked, and the toast says exactly that.
    let linkedCount = 0
    try {
      const tr = await bgSend('TOTP_TOKENS')
      const loginKey = `${entry.domain}\u0000${entry.username}`
      linkedCount = (tr?.tokens || []).filter(t => t.linkedLoginKey === loginKey).length
    } catch { /* token probe failed — delete proceeds, tokens untouched */ }
    let alsoDelete = false
    if (linkedCount > 0) {
      alsoDelete = confirm(getMessage('rowDeleteLinkedConfirm', [String(linkedCount)],
        `${linkedCount} linked authenticator token${linkedCount === 1 ? '' : 's'} found for this login.\n\nAlso delete ${linkedCount === 1 ? 'it' : 'them'}?\n\nOK — delete the login AND its authenticator(s)\nCancel — keep the authenticator(s) in the 2FA tab (unlinked)`))
    }
    const r = await bgSend('DELETE_ENTRY', {
      domain: entry.domain,
      username: entry.username,
      ...(linkedCount > 0 ? { alsoLinkedTotp: alsoDelete } : {}),
    })
    if (r && r.ok) {
      if (r.deletedAuthenticators > 0) {
        toast(getMessage('toastEntryDeletedWithTotp', [String(r.deletedAuthenticators)], `Entry deleted — ${r.deletedAuthenticators} linked authenticator${r.deletedAuthenticators === 1 ? '' : 's'} removed too`))
      } else if (r.unlinkedAuthenticators > 0) {
        toast(getMessage('toastEntryDeletedTotpKept', [String(r.unlinkedAuthenticators)], `Entry deleted — ${r.unlinkedAuthenticators} authenticator${r.unlinkedAuthenticators === 1 ? '' : 's'} kept in the 2FA tab (unlinked)`))
      } else {
        toast(getMessage('toastEntryDeleted', undefined, 'Entry deleted'))
      }
      refreshVault()
    } else {
      toast((r && r.error) || getMessage('toastDeleteFailed', undefined, 'Delete failed — try again; the entry is still in your vault.'), 'error')
    }
  }

  actions.appendChild(strengthBadgeEl)
  actions.appendChild(copyUserBtn)
  actions.appendChild(copyBtn)
  actions.appendChild(editBtn)
  actions.appendChild(delBtn)

  row.appendChild(meta)
  row.appendChild(actions)
  return row
}

// --- Entry editor dialog ---------------------------------------------------

// R95 §2 U-6/B7 — the dialog focus law: a dialog REMEMBERS the element that
// opened it and restores focus to it on close (keyboard a11y; the opener is
// kept as an ELEMENT reference and only restored while still connected).
let dialogReturnFocus = null

function openEntryDialog(existing) {
  dialogReturnFocus = document.activeElement
  const dlg = $('entryDialog')
  $('entryDialogTitle').textContent = existing
    ? getMessage('dlgEditTitle', undefined, 'Edit entry')
    : getMessage('entryDialogTitleNew', undefined, 'New entry')
  $('entryDomain').value = (existing && existing.domain) || ''
  // v2.16.0 — alias domains (multi-URI per login, Brave parity gap).
  $('entryUris').value = existing && Array.isArray(existing.uris) ? existing.uris.join(', ') : ''
  $('entryUsername').value = (existing && existing.username) || ''
  // v2.9.0 — passwords start HIDDEN (Brave parity); reveal is an explicit,
  // toggleable action, and the per-login note travels with the entry.
  const pw = $('entryPassword')
  pw.type = 'password'
  pw.value = (existing && existing.password) || ''
  const reveal = $('entryRevealBtn')
  // v2.18.0 — R27-i18n: localized Show/Hide on the reveal toggle
  reveal.textContent = getMessage('entryRevealBtn', undefined, 'Show')
  reveal.setAttribute('aria-pressed', 'false')
  $('entryNote').value = (existing && existing.note) || ''
  // v2.16.0 — password history (capped): listed collapsed; every row can be
  // copied or restored. Restore only PREFILLS the password field — the
  // actual rotation happens through the normal Save path (which archives
  // the current password into history again).
  const histBox = $('entryHistoryBox')
  const histList = $('entryHistoryList')
  histList.textContent = ''
  const hist = existing && Array.isArray(existing.history) ? existing.history : []
  histBox.classList.toggle('hidden', hist.length === 0)
  histBox.open = false
  for (const item of hist) {
    const row = document.createElement('div')
    row.className = 'history-row'
    const label = document.createElement('span')
    label.className = 'history-pw'
    label.textContent = mask((item && item.password) || '')
    const when = document.createElement('span')
    when.className = 'history-when'
    const changed = item && item.changedAt ? new Date(item.changedAt).toLocaleDateString() : '—'
    when.textContent = getMessage('historyChangedAt', [changed], `changed ${changed}`)
    when.title = item && item.changedAt ? new Date(item.changedAt).toLocaleString() : ''
    const copyH = document.createElement('button')
    copyH.className = 'btn btn-outline btn-sm'
    copyH.textContent = getMessage('historyCopy', undefined, 'Copy')
    copyH.onclick = async () => {
      const ok = await copy((item && item.password) || '')
      toast(ok ? getMessage('toastHistoryCopied', undefined, 'Previous password copied') : getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), ok ? 'info' : 'error')
    }
    const restoreH = document.createElement('button')
    restoreH.className = 'btn btn-outline btn-sm'
    restoreH.textContent = getMessage('historyRestore', undefined, 'Restore')
    restoreH.title = getMessage('dlgHistoryRestoreTitle', undefined, 'Puts the old password in the field — click Save to apply it')
    restoreH.onclick = () => {
      pw.value = (item && item.password) || ''
      updateEntryStrength()
      toast(getMessage('toastRestoredToField', undefined, 'Restored into the field — click Save to apply'))
    }
    row.appendChild(label)
    row.appendChild(when)
    const btns = document.createElement('span')
    btns.className = 'history-actions'
    btns.appendChild(copyH)
    btns.appendChild(restoreH)
    row.appendChild(btns)
    histList.appendChild(row)
  }
  $('entrySaveBtn').dataset.editing = existing ? '1' : '0'
  $('entrySaveBtn').dataset.origDomain = (existing && existing.domain) || ''
  $('entrySaveBtn').dataset.origUsername = (existing && existing.username) || ''
  updateEntryStrength() // v2.17.0 — R26-B4: reflect the loaded password
  dlg.classList.remove('hidden')
  setTimeout(() => $('entryDomain').focus(), 50)
}

function toggleEntryReveal() {
  const pw = $('entryPassword')
  const reveal = $('entryRevealBtn')
  const showing = pw.type === 'text'
  pw.type = showing ? 'password' : 'text'
  // v2.18.0 — R27-i18n: localized reveal toggle
  reveal.textContent = showing ? getMessage('entryRevealBtn', undefined, 'Show') : getMessage('entryHideBtn', undefined, 'Hide')
  reveal.setAttribute('aria-pressed', String(!showing))
}

// v2.17.0 — R26-B4: live strength feedback in the editor (the generator tab
// had a meter; the editor typed and generated blindly).
// v2.21.0 — R30-F1: async — awaits the lazy breach corpus once, so the
// verdict is always real; a keystroke sequence guard drops stale renders.
let _strengthSeq = 0
async function updateEntryStrength() {
  const seq = ++_strengthSeq
  const pw = $('entryPassword').value
  const el = $('entryStrength')
  if (!el) return
  if (!pw) {
    el.hidden = true
    el.textContent = ''
    return
  }
  try {
    await ensureBreachCorpus()
    if (seq !== _strengthSeq) return // a newer keystroke already took over
    const a = analyzePassword(pw)
    const badge = strengthBadge(a)
    el.hidden = false
    el.innerHTML = `<span class="dot" style="background:${badge.color}"></span> ${getMessage('strengthLine', [badge.label, crackTime(a.effective)], `${badge.label} · ${crackTime(a.effective)} to crack`)}`
  } catch {
    el.hidden = true
  }
}

function closeEntryDialog() {
  $('entryDialog').classList.add('hidden')
  if (dialogReturnFocus && document.contains(dialogReturnFocus)) dialogReturnFocus.focus()
  dialogReturnFocus = null
}

async function saveEntryFromDialog() {
  const domain = $('entryDomain').value.trim()
  const username = $('entryUsername').value.trim()
  const password = $('entryPassword').value
  const note = $('entryNote').value
  // v2.16.0 — alias domains: a comma-separated string becomes a list; the
  // vault layer normalizes (lowercase, hostname extraction, de-dup, cap 10).
  const uris = $('entryUris').value.split(',').map(s => s.trim()).filter(Boolean)
  const btn = $('entrySaveBtn')
  const editing = btn.dataset.editing === '1'
  const origDomain = btn.dataset.origDomain
  const origUsername = btn.dataset.origUsername
  if (!domain || !password) {
    toast(getMessage('dlgValidationRequired', undefined, 'Domain and password are required'), 'error')
    return
  }
  let r
  if (editing) {
    // v2.9.0 — ATOMIC update (one persist + one push). The old
    // DELETE_ENTRY-then-SAVE_ENTRY pair had a data-loss window: if the save
    // failed after the delete, the entry was simply gone. updateEntry also
    // tombstones the old key so cloud peers drop the old login.
    r = await bgSend('UPDATE_ENTRY', {
      origDomain, origUsername, domain, username, password,
      note: note || '',
      uris,
    })
  } else {
    r = await bgSend('SAVE_ENTRY', { domain, username, password, note: note || '', uris })
  }
  if (r && r.ok) {
    toast(editing ? getMessage('toastEntryUpdated', undefined, 'Entry updated') : getMessage('toastEntrySaved', undefined, 'Entry saved'))
    closeEntryDialog()
    refreshVault()
  } else {
    toast((r && r.error) || getMessage('toastSaveFailed', undefined, 'Save failed — try again; if it repeats, unlock the vault once.'), 'error')
  }
}

async function generateForEntry() {
  const prefs = await loadPrefs()
  try {
    await ensureBreachCorpus() // R30-F1: the meter's breach verdict must be real
    const r = generateRandomPassword(prefs.random)
    $('entryPassword').value = r.value
    updateEntryStrength() // v2.17.0 — R26-B4: meter follows the generated value
  } catch (e) {
    toast(e.message, 'error')
  }
}

// --- Master passphrase ----------------------------------------------------

async function saveMaster() {
  const cur = $('curMaster').value
  const pass = $('newMaster').value
  const pass2 = $('newMaster2').value
  if (pass.length < 8) { toast(getMessage('secPwTooShort', undefined, 'New passphrase must be ≥ 8 chars'), 'error'); return }
  if (pass !== pass2) { toast(getMessage('secPwMismatch', undefined, 'Passphrases do not match'), 'error'); return }
  // If vault already set up, verify current passphrase by unlocking first
  if (vaultState && vaultState.hasMaster) {
    if (!cur) { toast(getMessage('secEnterCurrent', undefined, 'Enter your current passphrase'), 'error'); return }
    const r = await bgSend('UNLOCK', { passphrase: cur })
    if (!r || !r.ok) {
      toast((r && r.error) || getMessage('secCurrentWrong', undefined, 'Current passphrase is incorrect'), 'error')
      return
    }
  }
  const r2 = await bgSend('SET_MASTER', { passphrase: pass })
  if (r2 && r2.ok) {
    toast(getMessage('toastMasterSaved', undefined, 'Master passphrase saved'))
    // R170 NC-1 — the change flow's PERSISTENT typed seat (census row C8):
    // what happened, the proof, the next step. The toast stays.
    const mr = $('masterResult')
    if (mr) {
      mr.className = 'sync-test-result ok'
      mr.textContent = getMessage('masterResultOk', undefined, '✓ Master passphrase saved — every entry re-encrypts under the new passphrase. Next: lock the vault once and unlock with the new passphrase to confirm it.')
    }
    $('curMaster').value = ''
    $('newMaster').value = ''
    $('newMaster2').value = ''
    refreshVault()
    // R87 (§2.2): master-passphrase completion signal — checklist step 1
    // flips in place (S6 state-truth law).
    refreshChecklist()
  } else {
    toast((r2 && r2.error) || getMessage('toastSaveFailed', undefined, 'Save failed — try again; if it repeats, unlock the vault once.'), 'error')
    // R170 NC-1 — the failure lands in the same seat (a typed ✗ line).
    const mr = $('masterResult')
    if (mr) {
      mr.className = 'sync-test-result err'
      mr.textContent = '✗ ' + ((r2 && r2.error) || getMessage('toastSaveFailed', undefined, 'Save failed — try again; if it repeats, unlock the vault once.'))
    }
  }
}

async function removeMaster() {
  // R45-E hardening: unlock + typed confirmation + verified-backup truth.
  // A destructive wipe must never be one accidental click, and it must never
  // imply recovery is possible when the most recent cloud attempt failed.
  const st = await bgSend('GET_STATE')
  const unlocked = !!(st && st.ok && st.state && st.state.isUnlocked)
  if (!unlocked) {
    toast(getMessage('wipeLocked', undefined, 'Unlock the vault first — wiping requires mastery of the master passphrase'), 'error')
    return
  }
  const sync = (st && st.sync) || {}
  const proof = sync.backupProof
  const lastPushOk = !!(sync.lastPush && sync.lastPush.ok)
  const backupLine = proof
    ? getMessage('wipeBackupOk', [new Date(proof.at).toLocaleString()], `Last verified cloud backup: ${new Date(proof.at).toLocaleString()}.`)
    : lastPushOk
      ? getMessage('wipeBackupUnknown', undefined, 'No verified backup record — the cloud copy cannot be confirmed.')
      : getMessage('wipeBackupFailed', undefined, 'NO verified cloud backup — the most recent cloud attempt did not succeed. Everything will be gone.')
  if (!confirm(getMessage('confirmRemoveVault', undefined, 'Remove the entire vault and master passphrase? This deletes ALL entries permanently.') + '\n\n' + backupLine)) return
  const typed = prompt(getMessage('wipeTypePrompt', undefined, 'Type DELETE to confirm permanent removal (no way back):'))
  if (typed !== 'DELETE') {
    toast(getMessage('wipeAborted', undefined, 'Wipe aborted — the confirmation word did not match'), 'error')
    return
  }
  const r = await bgSend('WIPE_VAULT')
  if (r && r.ok) {
    toast(getMessage('toastVaultRemoved', undefined, 'Vault removed'))
    refreshVault()
  } else {
    toast((r && r.error) || getMessage('toastRemoveFailed', undefined, 'Remove failed — try again; the token is still in your vault.'), 'error')
  }
}

async function optsUnlock() {
  const pass = $('optsUnlockPass').value
  if (!pass) { toast(getMessage('toastEnterPassphrase', undefined, 'Enter your passphrase'), 'error'); return }
  const r = await bgSend('UNLOCK', { passphrase: pass })
  if (r && r.ok) {
    $('optsUnlockPass').value = ''
    refreshVault()
  } else {
    toast((r && r.error) || getMessage('toastUnlockFailed', undefined, 'Unlock failed — check your master passphrase and try again.'), 'error')
  }
}

async function wipeAll() {
  // R45-E hardening: the emergency wipe also requires unlock + typed confirm.
  const st = await bgSend('GET_STATE')
  const unlocked = !!(st && st.ok && st.state && st.state.isUnlocked)
  if (!unlocked) {
    toast(getMessage('wipeLocked', undefined, 'Unlock the vault first — wiping requires mastery of the master passphrase'), 'error')
    return
  }
  const proof = st && st.sync && st.sync.backupProof
  const backupLine = proof
    ? getMessage('wipeBackupOk', [new Date(proof.at).toLocaleString()], `Last verified cloud backup: ${new Date(proof.at).toLocaleString()}.`)
    : getMessage('wipeBackupFailed', undefined, 'NO verified cloud backup — the most recent cloud attempt did not succeed. Everything will be gone.')
  if (!confirm(getMessage('confirmWipe1', undefined, '🚨 EMERGENCY WIPE — this permanently deletes ALL vault data, the encryption key, and the salt. Continue?') + '\n\n' + backupLine)) return
  if (!confirm(getMessage('confirmWipe2', undefined, 'Are you absolutely sure? This cannot be undone.'))) return
  const typed = prompt(getMessage('wipeTypePrompt', undefined, 'Type DELETE to confirm permanent removal (no way back):'))
  if (typed !== 'DELETE') {
    toast(getMessage('wipeAborted', undefined, 'Wipe aborted — the confirmation word did not match'), 'error')
    return
  }
  await bgSend('WIPE_VAULT')
  // Also clear prefs + custom wordlist
  await new Promise((r) => chrome.storage.local.remove([PREFS_KEY, WORDLIST_KEY, THEME_KEY], r))
  toast(getMessage('toastWiped', undefined, '🚨 All data wiped'))
  refreshVault()
  refreshGenerator()
}

// --- v2.9.0: Site settings (never-save exceptions) ---------------------------

// R45-E: Copy diagnostic summary — versions, non-secret reason codes,
// timestamps. The payload is assembled in the WORKER and contains no entries,
// URLs, usernames, tokens, recovery words, or ciphertext by construction.
async function copyDiagnosticSummary() {
  try {
    const r = await bgSend('DIAGNOSTIC_SUMMARY')
    if (!r || !r.ok || !r.text) {
      toast((r && r.error) || getMessage('diagFailed', undefined, 'Could not build the diagnostic summary — reopen the page and try again.'), 'error')
      return
    }
    await navigator.clipboard.writeText(r.text)
    toast(getMessage('diagCopied', undefined, 'Diagnostic summary copied — it contains no secrets'))
  } catch (e) {
    toast(e.message || getMessage('diagFailed', undefined, 'Could not build the diagnostic summary — reopen the page and try again.'), 'error')
  }
}

// R45-E: the offline recovery sheet — print-only, generated locally.
// Provider TYPE only (never tokens/URLs/words); the words warning tells the
// user where their offline copy lives instead of re-printing secrets.
async function printRecoverySheet() {
  const st = await bgSend('GET_STATE')
  const sync = (st && st.sync) || {}
  const proof = sync.backupProof
  const kdf = await bgSend('SYNC_KDF_INFO')
  const hasCode = !!(kdf && kdf.ok && kdf.info && kdf.info.hasSyncCode)
  const nm = await bgSend('NATIVE_MANAGER_GET')
  const nmOn = !!(nm && nm.ok && nm.status && nm.status.controlling)
  const transportType = sync.transport ? transportName(sync.transport.id, sync.transport.id) : getMessage('rsNoTransport', undefined, 'None — manual export/import only')
  const backup = proof
    ? getMessage('rsBackupOk', [new Date(proof.at).toLocaleString()], `Last verified cloud backup: ${new Date(proof.at).toLocaleString()}`)
    : getMessage('rsBackupNone', undefined, 'No verified cloud backup recorded yet — run a successful sync, then print this sheet again.')
  const sheet = $('recoverySheet')
  sheet.innerHTML = `
    <h1>UCrypt — Offline Recovery Sheet</h1>
    <p class="rs-warning">${getMessage('rsWordsWarning', undefined, 'Your vault is unlocked with 24 recovery words. They were shown ONCE when you generated or restored the sync code — this sheet does not print them. Keep the offline copy you wrote then; without those words the cloud copy cannot be decrypted by anyone, including us.')}</p>
    <table>
      <tr><th>${getMessage('rsProviderLabel', undefined, 'Cloud provider (type only)')}</th><td>${transportType}</td></tr>
      <tr><th>${getMessage('rsBackupLabel', undefined, 'Last verified backup')}</th><td>${backup}</td></tr>
      <tr><th>${getMessage('rsCodeLabel', undefined, 'Sync code status')}</th><td>${hasCode ? getMessage('rsCodeSet', undefined, 'Set (24 words)') : getMessage('rsCodeNone', undefined, 'Not set up')}</td></tr>
      <tr><th>${getMessage('rsNativeLabel', undefined, 'Native-manager mode')}</th><td>${nmOn ? getMessage('rsNativeOn', undefined, 'ON — UCrypt handles new password saves') : getMessage('rsNativeOff', undefined, 'Off')}</td></tr>
      <tr><th>${getMessage('rsDateLabel', undefined, 'Printed')}</th><td>${new Date().toLocaleString()}</td></tr>
    </table>
    <h2>${getMessage('rsStepsTitle', undefined, 'Restore steps (new device)')}</h2>
    <ol>
      <li>${getMessage('rsStep1', undefined, 'Install UCrypt and set ANY master passphrase (it encrypts this device only).')}</li>
      <li>${getMessage('rsStep2', undefined, 'Unlock, open Settings → Sync, choose "I already have one".')}</li>
      <li>${getMessage('rsStep3', undefined, 'Enter your 24 recovery words exactly. The cloud copy decrypts.')}</li>
      <li>${getMessage('rsStep4', undefined, 'Pull from the cloud; verify your entries; done.')}</li>
    </ol>
    <p class="rs-footer">${getMessage('rsFooter', undefined, 'Generated locally by UCrypt. Contains no passwords, tokens, URLs, or recovery words.')}</p>`
  await window.print()
}

// --- v2.9.0: Site settings (never-save exceptions) ---------------------------

async function refreshNeverSave() {
  const box = $('neverSaveList')
  if (!box) return
  const r = await bgSend('NEVER_SAVE_LIST')
  const sites = (r && r.ok && Array.isArray(r.sites)) ? r.sites : []
  box.textContent = ''
  if (sites.length === 0) {
    const empty = document.createElement('div')
    empty.className = 'never-save-empty'
    empty.textContent = getMessage('nsEmpty', undefined, 'No exceptions — UCrypt offers to save on every site.')
    box.appendChild(empty)
    return
  }
  for (const site of sites) {
    const row = document.createElement('div')
    row.className = 'never-save-row'
    const name = document.createElement('span')
    name.className = 'never-save-site'
    name.textContent = site
    const rm = document.createElement('button')
    rm.className = 'btn btn-outline btn-sm'
    rm.textContent = getMessage('nsRemoveBtn', undefined, 'Remove')
    rm.setAttribute('aria-label', getMessage('nsRemoveAria', [site], `Remove ${site} from the never-save list`))
    rm.onclick = async () => {
      const res = await bgSend('NEVER_SAVE_REMOVE', { domain: site })
      if (res && res.ok) {
        toast(getMessage('toastNsRemoved', [site], `Removed ${site} — UCrypt will offer to save again`))
        refreshNeverSave()
      } else {
        toast((res && res.error) || getMessage('toastRemoveFailed', undefined, 'Remove failed — try again; the token is still in your vault.'), 'error')
      }
    }
    row.appendChild(name)
    row.appendChild(rm)
    box.appendChild(row)
  }
}

async function addNeverSaveFromInput() {
  const input = $('neverSaveInput')
  const domain = (input.value || '').trim()
  if (!domain) { toast(getMessage('toastNsEnterSite', undefined, 'Enter a website address'), 'error'); return }
  const r = await bgSend('NEVER_SAVE_ADD', { domain })
  if (r && r.ok) {
    toast(r.already
      ? getMessage('toastNsAlready', [r.added || domain], `${r.added || domain} is already on the list`)
      : getMessage('toastNsAdded', [r.added], `Added ${r.added} — no more save prompts there`))
    input.value = ''
    refreshNeverSave()
  } else {
    toast((r && r.error) || getMessage('toastNsAddFailed', undefined, 'Could not add the site'), 'error')
  }
}

// --- R105 §2.2: Help > Export diagnostics (the bounded UI exception) --------

/**
 * ONE JSON summary to the clipboard for bug reports — the findings template
 * in docs/acceptance references it. Non-secret copy: the clipboard secrecy
 * guard is NOT armed (the R97 measured scope — this text carries counts and
 * typed ledger lines only). Failure degrades to a readable textarea — never
 * a dead end (0.13). The persistent state line never auto-dismisses (0.8);
 * only the informational toast may expire.
 */
async function exportDiagnostics() {
  const stateEl = $('diagState')
  const outEl = $('diagOut')
  const setLine = (t) => { if (stateEl) stateEl.textContent = t }
  let json = ''
  try {
    json = diagnosticsJson(await collectDiagnostics())
  } catch (e) {
    setLine(getMessage('diagJsonFailed', undefined, 'Diagnostics failed — try again; if it repeats, say what you clicked last.'))
    toast(getMessage('diagJsonFailed', undefined, 'Diagnostics failed — try again.'), 'error')
    return
  }
  let copied = false
  try {
    // Direct writeText — NOT the secret-copy path (no clipguard arm; the
    // R97 measured scope: the diagnostic summary carries no secrets).
    await navigator.clipboard.writeText(json)
    copied = true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = json
      ta.style.cssText = 'position:fixed;left:-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      copied = true
    } catch { /* the textarea fallback below is the typed next step */ }
  }
  if (copied) {
    setLine(getMessage('diagJsonCopied', undefined, 'Diagnostics copied — paste it into your bug report (the findings template).'))
    toast(getMessage('diagJsonCopied', undefined, 'Diagnostics copied.'))
  } else if (outEl) {
    // The typed fallback: the text is ON the page, selectable and copyable.
    outEl.value = json
    outEl.classList.remove('hidden')
    setLine(getMessage('diagJsonCopyFailed', undefined, 'Automatic copy failed — select the text below and copy it manually.'))
    toast(getMessage('diagJsonCopyFailed', undefined, 'Automatic copy failed — copy the text manually.'), 'error')
  }
}

// --- v2.9.0: Plaintext CSV export (migration OUT; double-confirmed) ----------

async function exportCsvMigrate() {
  const r = await bgSend('GET_ALL_ENTRIES')
  if (!r || !r.ok || r.locked) {
    toast(getMessage('toastUnlockFirst', undefined, 'Unlock the vault first'), 'error')
    return
  }
  const logins = (r.entries || []).filter(e => e && e.domain && !e.type)
  if (logins.length === 0) {
    toast(getMessage('toastCsvNothing', undefined, 'No saved logins to export'), 'error')
    return
  }
  if (!confirm(getMessage('expCsvConfirm1', [String(logins.length)], `Export ${logins.length} password${logins.length === 1 ? '' : 's'} as PLAINTEXT CSV?\n\nAnyone who can read the file will have every password. Continue?`))) return
  if (!confirm(getMessage('expCsvConfirm2', undefined, 'Final confirmation: the file is NOT encrypted. Delete it immediately after importing it elsewhere.'))) return

  const { buildBrowserCsv } = await import('./lib/export.js')
  const csv = buildBrowserCsv(logins)
  const stamp = new Date().toISOString().slice(0, 10)
  // R165 ARC G — THE EXPORT DOOR: the journal row (additive; the consent
  // count is typed — TWO confirmations were given above).
  try {
    const j = await new Promise((r) => chrome.storage.local.get('ucrypt:door:journal', r))
    const arr = Array.isArray(j['ucrypt:door:journal']) ? j['ucrypt:door:journal'] : []
    arr.push({ kind: 'consented-csv', at: new Date().toISOString(), rows: logins.length, confirmations: 2 })
    await new Promise((r) => chrome.storage.local.set({ 'ucrypt:door:journal': arr.slice(-8) }, r))
  } catch { /* the journal never blocks the export */ }
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `ucrypt-passwords-${stamp}.csv`
  a.click()
  URL.revokeObjectURL(url)
  toast(getMessage('toastCsvExported', [String(logins.length)], `Exported ${logins.length} logins — handle with care`))
}

// --- Sync (v2.2.0 — real sync code + transport wizard) ----------------------

const TRANSPORT_KEY = 'ucrypt:transport'
let currentTransportId = null
// R129 GRAND AUDIT (R129-A1): the real leave-This-device logic is defined
// inside the sync-wiring closure; the device-management card's handler (a
// later wiring pass) reaches it through this module-scoped bridge. The dead
// phantom-element delegate chain (dmLeaveBtn → $('leaveDeviceBtn') → nothing)
// is retired — the button now provably reaches SYNC_LEAVE_DEVICE.
let _leaveThisDevice = null
function __registerLeaveThisDevice(fn) { _leaveThisDevice = fn }

// R108 §2.3 — the provider-aware prefill map lives in lib/sync.js
// (PAIRING_CONN_FIELD_TARGETS / PAIRING_CONN_BRIDGE_TARGETS) — ONE table,
// ONE law, battery-pinned; options.js is only its consumer.

// R110 §3 (law 0.15, the CEO-pinned 60-second window) — the SURFACE side.
// A passphrase-requiring confirmation first asks the worker; within the
// window it proceeds WITHOUT the popup and renders the visible countdown
// where the prompt would have been — the skip is never mysterious. The
// window never applies to the master unlock and dies with the worker.
async function passphraseWindowActive() {
  try {
    const r = await bgSend('PASSPHRASE_WINDOW_STATE')
    return r && r.ok ? r : { withinWindow: false, secondsLeft: 0 }
  } catch { return { withinWindow: false, secondsLeft: 0 } }
}

let _passWindowChipTimer = null
/** The visible, unobtrusive indicator: a small chip counting down live and
 * removing itself at expiry. Appends INTO the given container — pass a
 * container that stays visible for the window's life (never a button, never
 * a row that hides when its flow completes). */
function showPassWindowChip(secondsLeft, containerEl) {
  try {
    const host = containerEl || document.body
    let chip = host.querySelector('.ucrypt-window-chip')
    if (!chip) {
      chip = document.createElement('span')
      chip.className = 'ucrypt-window-chip'
      chip.setAttribute('role', 'status')
      chip.style.cssText = 'display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--ok,#1e8e3e);margin-left:6px;user-select:none'
      host.appendChild(chip)
    }
    const render = (s) => {
      chip.textContent = getMessage('passWindowActive', [String(s)], `Passphrase confirmed — valid for ${s}s`)
      if (s <= 0) {
        try { chip.remove() } catch { /* the chip removal is best-effort — a re-rendered surface owns the truth (named-swallow law, R169 C1) */ }
        if (_passWindowChipTimer) { clearInterval(_passWindowChipTimer); _passWindowChipTimer = null }
      }
    }
    render(secondsLeft)
    if (_passWindowChipTimer) clearInterval(_passWindowChipTimer)
    _passWindowChipTimer = setInterval(async () => {
      const w = await passphraseWindowActive()
      if (!w.withinWindow) render(0)
      else render(w.secondsLeft)
    }, 1000)
  } catch { /* the chip is best-effort — the skip itself is the behavior */ }
}

/** R110 §3 — the ONE confirm gate: returns true when the human is already
 * proven (window active) and the action has run; false when the caller must
 * open the popup as before. */
async function confirmWithinWindow(hostEl, action) {
  const w = await passphraseWindowActive()
  if (w.withinWindow) {
    // The chip hosts beside the action (the action's row container).
    showPassWindowChip(w.secondsLeft, (hostEl && hostEl.parentElement) || document.body)
    await action()
    return true
  }
  return false
}

// v2.18.0 — R28-i18n (wave 2): every transport display string resolves through
// the catalogs with the registry literals as hard fallbacks (the i18n.js
// convention). lib/transports stays chrome-free — THIS renderer derives the
// keys from the stable transport/field/step ids, exactly like icSrc<Id>*.
const capId = (id) => id[0].toUpperCase() + id.slice(1)
const twNameKey = (id) => `twName${capId(id)}`
const twDescKey = (id) => `twDesc${capId(id)}`
const twStepKeys = (id, step) => [`tw${capId(id)}Step${step}Title`, `tw${capId(id)}Step${step}Text`]
const twFieldKeys = (id, fieldKey) => [`twField${capId(id)}${capId(fieldKey)}`, `twField${capId(id)}${capId(fieldKey)}Help`]
function transportName(id, fallback) {
  return id ? getMessage(twNameKey(id), undefined, fallback || '') : (fallback || '')
}

// R87 (§2.3 / S8): the transport grid carries each card's TRUE state —
// not configured / configured / last push result — typed, from the live
// sync ledger. No card may look dead-ended or falsely ready.
async function transportStateInfo() {
  try {
    const st = await bgSend('GET_STATE')
    const sync = (st && st.ok && st.sync) || {}
    // R119 (law 0.32) — THE RUNG RECORD rides the state line: signinMode
    // ('fast'|'guided'|'manual') is a NON-secret field, so it reads straight
    // from the stored transport record while sealed — no unlock needed.
    let signinMode = ''
    try {
      const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
      // R120 (law 0.33) — the state line reads describeRungState: the ONE
      // truth about which rung is live. A record that already carries a
      // lawful signinMode resolves to exactly that value (the old lines stay
      // byte-identical); a legacy record now speaks its true rung (inferred
      // from the material it holds); 'none'/'no material' renders the old
      // line (isSigninMode passes only on a real rung).
      signinMode = rec ? describeRungState(rec) : ''
    } catch { /* the mode is additive — its absence renders the old line */ }
    // R176 — the bank's custody facts (the mint era + the burn clock), read
    // from the stored record's PLAINTEXT custody shape (the webToken is not
    // a sealed field — the map's Adjudication 1.2) — booleans and instants
    // only, never a token value (law 0.14).
    let _custody = null
    try {
      const rec2 = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
      const cfg2 = rec2 && typeof rec2.config === 'object' ? rec2.config : null
      const wt2 = cfg2 && cfg2.webToken && typeof cfg2.webToken === 'object' ? cfg2.webToken : null
      const isFastCfg = cfg2 && (cfg2.authMode === 'fast' || cfg2.signinMode === 'fast' || cfg2.persistentSession === true)
      if ((wt2 && (wt2.token || Number.isFinite(Number(wt2.at)))) || isFastCfg) {
        const notRevoked = !(wt2 && wt2.revokedByProvider === true)
        _custody = {
          webTokenAt: Number((wt2 && wt2.at) || (rec2 && rec2.setAt) || Date.now()),
          webTokenExp: (wt2 && Number.isFinite(Number(wt2.exp))) ? Number(wt2.exp) : (Date.now() + 3600 * 1000),
          webTokenAlive: notRevoked,
          persistentSession: notRevoked,
        }
      }
    } catch { /* the custody facts are additive — their absence renders the old line */ }
    return {
      savedId: (sync.transport && sync.transport.id) || sync.transportId || '',
      lastPush: sync.lastPush || null,
      // R90 §1.1 — the configured summary also shows the typed pull ledger.
      lastPull: sync.lastPull || null,
      signinMode,
      webTokenAt: _custody && Number.isFinite(Number(_custody.webTokenAt)) ? Number(_custody.webTokenAt) : 0,
      webTokenExp: _custody && Number.isFinite(Number(_custody.webTokenExp)) ? Number(_custody.webTokenExp) : null,
      webTokenAlive: !!(_custody && _custody.webTokenAlive),
      persistentSession: !!(_custody && _custody.persistentSession),
    }
  } catch { return { savedId: '', lastPush: null, lastPull: null, signinMode: '', webTokenAt: 0, webTokenExp: null, webTokenAlive: false, persistentSession: false } }
}

// R119 (law 0.32) — THE RUNG RECORD: the rung the CURRENT wizard session
// connected on ('fast' | 'guided'), set by the fast CTAs and the existing
// guided connect; the save path carries it into the config (signinMode).
// An empty value means "no connect happened this session" — the stored mode
// is preserved (never silently rewritten by a mere re-save).
let wizardSigninMode = ''
// R172 — the fast prefill carrier (the poison kill's second belt — see
// collectTransportConfig).
let wizardFastPrefill = null
// R172 — THE PURE-PANEL LAW's retirement flag: the global bottom row is
// retired for the ladder transports (their panels carry their own button
// sets); setGuidedVisibility's unhide respects this.
let wizardGlobalRowRetired = false

// R90 §1.1 — the state-aware configured summary. When the wizard opens for
// the transport that is ALREADY configured, it leads with the live state
// (connection mode, last test, last push, last pull) and the actions
// Test / Edit / Disconnect — the guided setup is reachable ONLY behind
// "Edit setup". A completed setup is never re-sold. `wizardEditMode` is
// set by the summary's Edit button and reset when the wizard closes or a
// different transport is opened.
let wizardEditMode = false
let wizardEditTransport = ''

function connectionModeLabel(t, config, locked) {
  // R90 §1.1 — the mode is the transport's real connection shape, read from
  // the stored config while unlocked; while locked the truthful answer is
  // "stored (encrypted)" — never a guessed mode.
  if (locked) return getMessage('tsModeEncrypted', undefined, 'Stored (encrypted) — unlock to see details')
  if (t.id === 'gdrive') {
    // R172 — THE ACTIVE-METHOD LABEL (R-172.4): the label names the method
    // the record actually rides — the fast one-click sign-in is NOT the
    // guided PKCE card; a bridge record never prints the OAuth line. The
    // mode reads the record's non-secret fields (the sealed envelope's
    // plaintext names — law 0.33), so it answers while sealed too.
    const mode = String((config && config.authMode) || '')
    const sig = String((config && config.signinMode) || '')
    if (mode === 'bridge') return getMessage('tsModeBridge', undefined, 'Bridge (Advanced) — user-deployed Apps Script')
    if (mode === 'fast' || sig === 'fast') return getMessage('tsModeFast', undefined, 'One-click sign-in (Fast) — your Google account, nothing to paste')
    if (mode === 'oauth' || sig === 'guided') return getMessage('tsModeOAuth', undefined, 'OAuth (guided) — your Google account via PKCE')
    return getMessage('tsModeOAuth', undefined, 'OAuth (guided) — your Google account via PKCE')
  }
  if (t.id === 'github' || t.id === 'dropbox') {
    return getMessage('tsModeOAuthGeneric', undefined, 'OAuth — your account, no bridge script')
  }
  return getMessage('tsModeDirect', undefined, 'Direct — your own endpoint with your credentials')
}

function ledgerLine(ledger, neverKey, neverFallback) {
  if (!ledger) return getMessage(neverKey, undefined, neverFallback)
  const when = ledger.at ? new Date(ledger.at).toLocaleString() : '—'
  // R171 — THE HONEST ERROR LAW (the E-24 cure, render half): the detail is
  // MATERIALIZED before interpolation — a poisoned historical row (the
  // "[object Promise]" class) renders the typed generic, never an engine
  // shape. The init self-heal (lib/vault.js) rewrites the stored row too;
  // this guard is the eye's last line.
  // R174 — the belt now covers the ONLY poison class that survives storage:
  // a STRING baked by a pre-R171 writer ("[object Promise]") renders the
  // typed generic (healPoisonedUserText — the A3 cure's render half).
  const mat = (v) => healPoisonedUserText(v, { cap: 200, generic: 'The recorded outcome could not be read — the next sync writes a fresh row.' })
  // R174 — THE SELF-IDENTIFYING ROW (R-174.6): the row stamps its own build,
  // so the exhibit identifies its own floor. Rows without a stamp (pre-R174
  // history) render unchanged.
  const buildTag = (ledger && typeof ledger.build === 'string' && ledger.build) ? ` · ${ledger.build}` : ''
  // LAW 0.48 (R133) — the typed lifecycle SKIP is never a red failure: a
  // fresh joiner's push renders its truthful waiting row with the typed next
  // action (law 0.29 — the fix lives where the words live).
  if (ledger.skipped) {
    const mark = '⏳'
    const detail = mat(ledger.error || ledger.message || '')
    // R172 — THE UNCLIPPED-COPY LAW (R-172.6): the row WRAPS, never clips
    // mid-word (the field's "in abou" defect dies here). The materializer's
    // own bound (the cap) governs the length; no render-time slice.
    return `${mark} ${when}${detail ? ' — ' + detail : ''}${buildTag}`
  }
  // LAW 0.49 (R133) — the read-back confirmation rides the push row: a
  // confirmed push names its confirmation; an unconfirmed one carries the
  // typed read-back warning (never a bare ✓ over an unverified copy).
  if (ledger.ok && ledger.confirmed === true && ledger.confirmedAt) {
    const detail = mat(ledger.error || ledger.message || '')
    return `✓ ${when} — cloud copy confirmed ✓${detail ? ' · ' + detail : ''}${buildTag}`
  }
  if (ledger.ok && ledger.confirmed === false && ledger.confirmError) {
    return `✓ ${when} — ${mat(ledger.confirmError)}${buildTag}`
  }
  const mark = ledger.ok ? '✓' : '✗'
  const detail = mat(ledger.error || ledger.message || '')
  return `${mark} ${when}${detail ? ' — ' + detail : ''}${buildTag}`
}

/**
 * R175 — THE ONE CYCLE ROW (R-175.1) — the renderer half. ONE row, every
 * lane named, the ×N quiet-ledger counter (R-175.7) riding the time. The
 * lane words arrive pre-materialized from the engine (the row is
 * self-sufficient); the belt materializes again at render (never a bare
 * engine shape — the E-24 law's last line).
 */
function cycleRowLine(cycle) {
  if (!cycle || !Array.isArray(cycle.lanes)) return ''
  const when = cycle.at ? new Date(cycle.at).toLocaleString() : '—'
  const times = Number(cycle.times) || 1
  const firstAt = Number(cycle.firstAt) || 0
  const timePart = times > 1 && firstAt
    ? `${when} · ×${times} since ${new Date(firstAt).toLocaleTimeString()}`
    : when
  const mark = cycle.verdict === 'ok' ? '✓' : (cycle.verdict === 'failed' ? '✗' : '⏳')
  const lanePart = cycle.lanes.map((l) => {
    const lm = l.ok === true ? '✓' : (l.ok === false ? '✗' : '⏳')
    // R176 — R-176.4 THE RENDER BELT AT THE LAST SEAT: a FAILED lane's words
    // ride the belt — a historical row whose words were the BARE generic
    // arrives NAMED at paint (the belt's tag); every new row arrives
    // fingerprinted at the write (the materializer's R176 cure). A waiting
    // lane's empty words are honest absence (never a failure shape) and
    // ride byte-true.
    const raw = typeof l.words === 'string' ? l.words : ''
    const w = l.ok === false
      ? beltRender(raw, { cap: 220 })
      : healPoisonedUserText(raw, { cap: 200, generic: '' })
    return `${lm} ${escapeHtml(String(l.lane || 'lane'))}${w ? ': ' + w : ''}`
  }).join(' · ')
  const buildTag = (typeof cycle.build === 'string' && cycle.build) ? ` · ${cycle.build}` : ''
  return `${mark} ${timePart} — ${lanePart}${buildTag}`
}

async function renderTransportSummary(t, info) {
  const wrap = $('transportSummary')
  if (!wrap) return
  const saved = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
  const isSaved = saved && saved.id === t.id
  let config = null
  let locked = true
  if (isSaved) {
    try {
      const g = await bgSend('TRANSPORT_GET')
      if (g && g.ok) { locked = !!g.locked; config = g.locked ? null : (g.config || {}) }
    } catch { /* locked rendering is the truthful fallback */ }
  }
  const summaryCfg = config || (isSaved && saved && typeof saved.config === 'object' ? saved.config : null)
  const hasPublicMode = !!(summaryCfg && (summaryCfg.authMode || summaryCfg.signinMode))
  $('tsMode').textContent = isSaved ? connectionModeLabel(t, summaryCfg, locked && !hasPublicMode) : '—'
  // Typed last-test ledger (R90: written by TRANSPORT_TEST on both outcomes).
  let lastTest = null
  try { lastTest = (await chrome.storage.local.get('ucrypt:lastTest'))['ucrypt:lastTest'] || null } catch { lastTest = null }
  if (lastTest && lastTest.transportId && lastTest.transportId !== t.id) lastTest = null
  $('tsLastTest').textContent = ledgerLine(lastTest, 'tsNeverTested', 'Never tested — press Test connection')
  $('tsLastPush').textContent = ledgerLine(info.lastPush, 'tsNeverPushed', 'Never pushed — press Sync now')
  $('tsLastPull').textContent = ledgerLine(info.lastPull, 'tsNeverPulled', 'Never pulled — pulls happen at every unlock')
  wrap.classList.remove('hidden')
}

function setGuidedVisibility(summaryMode) {
  // Summary mode hides EVERY guided surface; edit mode (or a fresh setup)
  // shows them again. One switch — no duplicated truth.
  // R172 — the per-panel law: the global row stays retired for the ladder
  // transports (their panels carry their own sets) — the unhide respects
  // the retirement flag.
  const ids = ['twSteps', 'twFields', 'twGdriveActions', 'twScriptBox', 'twActionsRow', 'twResult', 'twLockedNote', 'twCaveat']
  for (const id of ids) {
    const el = $(id)
    if (!el) continue
    if (summaryMode) el.classList.add('hidden')
    // In guided mode the sub-surfaces (gdrive actions, script box, locked
    // note) are managed by openTransportWizard's own logic — only unhide
    // the ones that are ALWAYS visible in guided mode.
    else if (['twSteps', 'twFields', 'twResult'].includes(id)) el.classList.remove('hidden')
    else if (id === 'twActionsRow' && !wizardGlobalRowRetired) el.classList.remove('hidden')
  }
  // R119 (law 0.32) — the ladder block is a guided surface too: the
  // completed-setup summary never re-sells it; edit mode re-renders it via
  // openTransportWizard's ladder call.
  const ladder = $('twLadder')
  if (ladder && summaryMode) ladder.classList.add('hidden')
}

function transportStateLine(t, info) {
  const configured = info.savedId === t.id
  // R119 (law 0.32) — THE MODE RIDES THE STATE LINE, additively: a
  // configured card speaks its rung ("configured · fast sign-in"). The old
  // lines (push ok/failed/not configured) are byte-identical when the mode
  // is absent — the pre-ladder surfaces render unchanged.
  const modeText = configured && info && isSigninMode(info.signinMode)
    ? ' · ' + getMessage('ladderState' + info.signinMode.charAt(0).toUpperCase() + info.signinMode.slice(1), undefined, { fast: 'fast sign-in', guided: 'own-key sign-in', manual: 'manual sign-in' }[info.signinMode])
    : ''
  // R176 — R-176.7 THE MINT ERA (the self-reconciling modal): when the
  // record's banked custody is NEWER than the failed push (a fresh verified
  // mint landed after the failure), the line speaks the NEW ERA — the
  // burn clock + the bounded retry promise — instead of repeating the old
  // era's warning beside a fresh "✓ Signed in" card. Two eras in one frame
  // without reconciliation is R-172.1's oldest disease; the modal cures it
  // at the line's own writer.
  const mintAt = info && info.webTokenAt && Number.isFinite(Number(info.webTokenAt)) ? Number(info.webTokenAt) : 0
  if (configured && info && mintAt > 0 && info.lastPush && info.lastPush.ok === false &&
      Number(info.lastPush.at || 0) < mintAt) {
    const mintHH = new Date(mintAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    return { cls: 'ok', text: '✓ ' + getMessage('twMintEraLine', undefined, 'Signed in permanently — one click') + ' · ' + mintHH + ' — silent auto-renewal active;' + getMessage('twMintEraRetry', undefined, ' the failed push retries once on the next cycle') + modeText }
  }
  if (configured && info.lastPush && info.lastPush.ok) {
    // LAW 0.49 — a confirmed push names its read-back; an unconfirmed one
    // never masquerades as fully verified.
    if (info.lastPush.confirmed === true) {
      return { cls: 'ok', text: '✓ ' + getMessage('twCardPushOk', undefined, 'Last push OK') + ' — cloud copy confirmed ✓' + modeText }
    }
    return { cls: 'ok', text: '✓ ' + getMessage('twCardPushOk', undefined, 'Last push OK') + modeText }
  }
  if (configured && info.lastPush && info.lastPush.skipped) {
    // LAW 0.48 — the joiner's typed skip: a waiting row, never a failure.
    return { cls: 'warn', text: '⏳ ' + getMessage('twCardPushWaiting', undefined, 'Push waits — this device receives your chain\u2019s data first') + modeText }
  }
  if (configured && info.lastPush && !info.lastPush.ok) {
    // R176 — R-176.7: the failed warning carries its own HOUR (the era is
    // spoken — "Last push failed — 9:51 PM") and the words ride the render
    // belt (R-176.4 — no bare generic at the last seat). The warning stays
    // until a successful push or a fresh verified mint supersedes it.
    const failedHH = info.lastPush.at ? new Date(Number(info.lastPush.at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
    const eraTag = failedHH ? ' — ' + failedHH : ''
    return { cls: 'err', text: '⚠ ' + getMessage('twCardPushFailed', undefined, 'Last push failed') + eraTag + ' — ' + beltRender(String(info.lastPush.error || ''), { cap: 120 }) + modeText }
  }
  if (configured) {
    return { cls: 'ok', text: getMessage('twCardConfigured', undefined, 'Configured') + modeText }
  }
  return { cls: 'dim', text: getMessage('twCardNotConfigured', undefined, 'Not configured') }
}

function transportCard(t, info) {
  const card = document.createElement('button')
  card.className = 'transport-card'
  card.dataset.transport = t.id
  const name = transportName(t.id, t.name)
  card.setAttribute('aria-label', getMessage('twCardAria', [name], `Set up ${t.name}`))
  // R45-B: difficulty stays on a 1–4 scale (a higher value used to throw in
  // String.repeat); developer-console transports carry an explicit ADVANCED
  // badge so no card can masquerade as an easy consumer sign-in.
  const lvl = Math.min(4, Math.max(1, t.difficulty || 1))
  const dots = '★'.repeat(lvl) + '☆'.repeat(4 - lvl)
  const desc = getMessage(twDescKey(t.id), undefined, t.description.split('. ')[0] + '.')
  const stLine = transportStateLine(t, info || { savedId: '', lastPush: null })
  // R178 — G326 THE CONFIGURED BADGE: a configured transport names itself
  // ("CONFIGURED") on the card face — Not-configured vs configured cards no
  // longer share one undifferentiated face (the E-41 owner note).
  const configuredBadge = (info && info.savedId === t.id)
    ? `<em class="transport-configured-badge">${getMessage('twCardConfigured', undefined, 'Configured')}</em>`
    : ''
  card.innerHTML = `
    ${configuredBadge}<span class="transport-icon">${t.icon}</span>
    <span class="transport-name">${name}${t.advanced ? `<em class="transport-advanced">${getMessage('twCardAdvanced', undefined, 'ADVANCED')}</em>` : ''}</span>
    <span class="transport-desc">${desc}</span>
    <span class="transport-state transport-state-${stLine.cls}" title="${String(stLine.text).replace(/"/g, '&quot;')}">${stLine.text}</span>
    <span class="transport-diff" title="${getMessage('twCardDifficulty', undefined, 'Setup difficulty')}">${getMessage('twCardSetup', [dots], `Setup: ${dots}`)}</span>`
  card.addEventListener('click', () => openTransportWizard(t.id))
  return card
}

function renderTransportGrid(activeId) {
  const grid = $('transportGrid')
  if (!grid) return
  grid.innerHTML = ''
  // R87 (§2.3): the state lines render from the live ledger; the grid
  // re-renders state-aware when the state arrives.
  transportStateInfo().then((info) => {
    if (!grid.isConnected || grid.childElementCount > 0) { /* replaced below anyway */ }
    grid.innerHTML = ''
    // R178 — G326 THE PICKER HIERARCHY: the configured transport leads the
    // grid (the owner's working connection is the first face), then the
    // working self-hosted rungs, then the Advanced row — the stable R45-B
    // order holds WITHIN each tier (additions-only reordering by tier).
    const cards = transports.map((t) => ({ t, card: transportCard(t, info) }))
    cards.sort((a, b) => {
      const aCfg = info && a.t.id === info.savedId ? 0 : 1
      const bCfg = info && b.t.id === info.savedId ? 0 : 1
      if (aCfg !== bCfg) return aCfg - bCfg
      return 0 // the house order stands within a tier
    })
    for (const { t, card } of cards) {
      if (t.id === activeId) card.classList.add('active')
      if (info && t.id === info.savedId) card.classList.add('configured')
      grid.appendChild(card)
    }
  })
}

// R119 §2.4 (law 0.32, order §3.4) — THE GUIDED WALKTHROUGH OPENER: the
// "Show me how" one-click lands in the walkthrough overlay (options.html's
// #walkthroughOverlay — the visible ✕ + the focus return ride
// openSyncOverlay/closeSyncOverlay, law 0.30). The extension ID and the
// redirect URI are PUBLIC identifiers — the copy-buttons exist so they are
// never mistyped.
function openLadderWalkthrough(transportId) {
  const t2 = getTransport(transportId)
  if (!t2) return
  openSyncOverlay('walkthroughOverlay')
  renderWalkthrough({
    transportId,
    host: $('walkthroughHost'),
    onGoField: (fieldKey) => {
      closeSyncOverlay('walkthroughOverlay')
      const input = document.querySelector(`#twFields [data-field-key="${fieldKey}"]`)
      if (input) {
        input.scrollIntoView({ behavior: 'smooth', block: 'center' })
        try { input.focus({ preventScroll: true }) } catch { /* best-effort */ }
        input.classList.add('ladder-field-flash')
        setTimeout(() => input.classList.remove('ladder-field-flash'), 1600)
      }
    },
  })
}

// R119 §1 — ONE-CLICK RUNG SWITCHING: each rung's button focuses its own
// surface (guided = the client-ID field; manual = the Advanced fields).
function focusWizardField(fieldKey) {
  // R170 §A3 — the fields live inside the alternative-configuration
  // disclosure: a required action names a seat inside a collapsed area, so
  // the area auto-opens first (the fire exception — R-170.1).
  try {
    const adv = $('twAdvancedConfig')
    if (adv && !adv.open) { adv.open = true; adv.setAttribute('data-fire-revealed', 'true') }
  } catch { /* the focus still proceeds */ }
  const input = document.querySelector(`#twFields [data-field-key="${fieldKey}"]`)
  if (!input) return
  input.scrollIntoView({ behavior: 'smooth', block: 'center' })
  try { input.focus({ preventScroll: true }) } catch { /* best-effort */ }
  input.classList.add('ladder-field-flash')
  setTimeout(() => input.classList.remove('ladder-field-flash'), 1600)
}

const LADDER_GUIDED_FIELD = { gdrive: 'clientId', github: 'oauthClientId', dropbox: 'appKey' }
const LADDER_MANUAL_FIELD = { gdrive: 'authMode', github: 'token', dropbox: 'token' }

async function openTransportWizard(transportId) {
  const t = getTransport(transportId)
  if (!t) return
  // R109 §4.2 — the chooser + guided setups live inside the cloud layer
  // (law 0.25): every entry path (the Symphony's CTA, the chooser card,
  // Edit setup, the checklist) lands in the same focused overlay.
  openSyncOverlay('cloudOverlay')
  currentTransportId = transportId
  // R90 §1.1 — a card for a DIFFERENT transport always starts fresh; the
  // Edit flag survives only within the same transport's summary.
  if (wizardEditTransport !== transportId) wizardEditMode = false
  wizardEditTransport = transportId
  // R119 — a fresh wizard open has NOT connected this session: the stored
  // signinMode governs until a fast/guided connect runs again.
  wizardSigninMode = ''

  $('transportWizard').classList.remove('hidden')
  // R167 — THE PICKER-COLLAPSE LAW (the E-13 printscreen 2 order, verbatim:
  // "as soon the user select one of the options there, collapse this very
  // area and then uncollapse the area bellow it that has the settings for
  // the service"): this function IS the selection — the Cloud transport
  // block (header + help + grid) collapses NOW; the settings area below is
  // the wizard that just uncollapsed. The ghost "Change transport" door
  // re-opens the picker without losing anything typed; every overlay close
  // resets the picker uncollapsed (the fresh-open law).
  try {
    const picker = $('transportPicker')
    if (picker) picker.classList.add('hidden')
  } catch { /* the collapse never blocks the open */ }
  // R132 — the wizard opens fresh: the exit button reads "Cancel" again
  // (it becomes the affirmative "Close" only after a successful save).
  try {
    const cancelBtn = $('twCancelBtn')
    if (cancelBtn) {
      cancelBtn.textContent = getMessage('twCancelBtn', undefined, 'Cancel')
      cancelBtn.classList.add('btn-ghost')
      cancelBtn.classList.remove('btn-outline')
    }
  } catch { /* the reset never blocks the open */ }
  const tName = transportName(t.id, t.name)
  $('twTitle').textContent = getMessage('twWizardTitle', [`${t.icon} ${tName}`], `${t.icon} ${t.name} — guided setup`)
  $('twResult').textContent = ''
  $('twResult').className = 'sync-test-result'

  // R117 §3 (law 0.30; the CEO's S2) — THE LAYER'S HEADER CARRIES THE
  // CARD'S STATUS SUMMARY: configured · last push · last test, the same
  // ledger truth the grid card speaks. The selection lands on a
  // configuration that already tells you where you stand.
  const infoEarly = await transportStateInfo()
  const headState = $('twHeaderState')
  if (headState) {
    const stLine = transportStateLine(t, infoEarly)
    const parts = [stLine.text]
    if (infoEarly.lastTest && infoEarly.lastTest.transportId === t.id) {
      parts.push(ledgerLine(infoEarly.lastTest, 'tsNeverTested', 'Never tested'))
    }
    headState.textContent = parts.filter(Boolean).join(' · ')
    headState.classList.remove('hidden')
  }

  // R90 §1.1 — STATE-AWARE WIZARD: when this transport is the configured
  // one and the user has not pressed "Edit setup", render the summary and
  // hide every guided surface (never re-sell a completed setup).
  const info = await transportStateInfo()
  const summaryMode = info.savedId === transportId && !wizardEditMode
  const summary = $('transportSummary')
  if (summary) {
    if (summaryMode) {
      await renderTransportSummary(t, info)
    } else {
      summary.classList.add('hidden')
    }
  }
  setGuidedVisibility(summaryMode)
  if (summaryMode) {
    // R90 §1.1 — the three summary actions, wired fresh on every render.
    const tsTest = $('tsTestBtn')
    if (tsTest) tsTest.onclick = () => testCurrentTransport($('tsResult'))
    const tsEdit = $('tsEditBtn')
    if (tsEdit) tsEdit.onclick = () => {
      wizardEditMode = true
      openTransportWizard(transportId)
    }
    const tsDisc = $('tsDisconnectBtn')
    if (tsDisc) tsDisc.onclick = async () => {
      const tName2 = transportName(t.id, t.name)
      const ok = confirm(getMessage('tsDisconnectConfirm', [tName2], `Disconnect ${tName2}? UCrypt stops syncing to it on this device; the cloud copy stays.`))
      if (!ok) return
      const r = await bgSend('TRANSPORT_CLEAR')
      const tsRes = $('tsResult')
      if (r && r.ok) {
        wizardEditMode = false
        toast(getMessage('toastTransportDisconnected', [tName2], `${tName2} disconnected — syncing stopped on this device.`), 'info')
        if (tsRes) { tsRes.className = 'sync-test-result ok'; tsRes.textContent = '✓ ' + getMessage('tsDisconnectedDone', undefined, 'Disconnected.') }
        renderTransportGrid('')
        refreshChecklist().catch(() => {})
        setTimeout(() => { $('transportWizard').classList.add('hidden') }, 900)
      } else {
        if (tsRes) { tsRes.className = 'sync-test-result err'; tsRes.textContent = '✗ ' + ((r && r.error) || 'Disconnect failed') }
      }
    }
    // R117 §3 (law 0.30; the CEO's S2) — block:'start' anchors the
    // CONFIGURATION into the dialog's viewport. The old block:'nearest'
    // no-opped whenever the wizard's top edge peeked above the fold — the
    // exact "nowhere" the CEO's screenshot pins. One click: choose →
    // configure, in view.
    $('transportWizard').scrollIntoView({ behavior: 'smooth', block: 'start' })
    return
  }

  // R59-F3 — the owner-ordered Advanced caveat for Custom/presigned URLs:
  // such a URL may itself grant storage access. Shown ONLY for the custom
  // transport; hidden for every other wizard.
  const caveat = $('twCaveat')
  if (caveat) {
    if (t.id === 'custom') {
      caveat.textContent = getMessage('cuAccessCaveat', undefined, 'This URL may itself grant storage access. Keep it private.')
      caveat.classList.remove('hidden')
    } else {
      caveat.textContent = ''
      caveat.classList.add('hidden')
    }
  }

  // Guided steps (R28-i18n: title/text resolve through the per-step keys)
  const steps = $('twSteps')
  steps.innerHTML = ''
  for (const s of t.setupSteps || []) {
    const li = document.createElement('li')
    const [titleKey, textKey] = twStepKeys(t.id, s.step)
    li.innerHTML = `<strong>${getMessage(titleKey, undefined, s.title)}.</strong> ${getMessage(textKey, undefined, s.text)}`
    if (s.link) {
      const a = document.createElement('a')
      a.href = s.link
      a.target = '_blank'
      a.rel = 'noreferrer noopener'
      a.textContent = ' ' + getMessage('twStepOpen', undefined, 'Open ↗')
      li.appendChild(a)
    }
    steps.appendChild(li)
  }

  // Config fields (pre-filled with the saved config when editing the same
  // transport). R45-A §2.5: prefill goes through TRANSPORT_GET — while the
  // vault is UNLOCKED the stored config is decrypted into this page's form;
  // while LOCKED the fields stay empty and the user sees a truthful
  // "stored (encrypted)" note instead of any secret value.
  const saved = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
  const savedMatches = saved?.id === transportId
  let savedConfig = {}
  let storedSecretNote = ''
  if (savedMatches) {
    try {
      const g = await bgSend('TRANSPORT_GET')
      if (g && g.ok) {
        if (g.locked) {
          if (g.status && g.status.hasSecrets) {
            const stored = g.status.hasSecrets.filter(s => s.stored).length
            if (stored > 0) storedSecretNote = getMessage('twLockedSecrets', undefined, 'Credentials are stored (encrypted). Unlock the vault to view or change them.')
          }
        } else if (g.config) {
          savedConfig = g.config
        }
      }
    } catch { /* prefill is best-effort; the wizard still opens */ }
    // UCRYPT-22: Always hydrate non-secret custody fields (authMode, signinMode,
    // webToken, clientId, lane, via, accountHint, persistentSession) from the
    // persisted storage record when savedConfig is empty (e.g. on window reopen)
    // so the wizard never loses fast OAuth state!
    if (saved && saved.config && typeof saved.config === 'object') {
      const rawCfg = saved.config
      const nonSecretKeys = ['authMode', 'signinMode', 'lane', 'via', 'accountHint', 'clientId', 'webToken', 'persistentSession', 'autoRenew']
      for (const nk of nonSecretKeys) {
        if ((savedConfig[nk] === undefined || savedConfig[nk] === null || savedConfig[nk] === '') && rawCfg[nk] !== undefined) {
          savedConfig[nk] = rawCfg[nk]
        }
      }
    }
  }
  let custody = deriveRecordCustody(savedMatches && saved ? saved : null, transportId, Object.keys(savedConfig || {}).length > 0)
  wizardFastPrefill = (savedConfig && (savedConfig.authMode === 'fast' || savedConfig.signinMode === 'fast'))
    ? { ...savedConfig }
    : (custody && (custody.authMode === 'fast' || custody.signinMode === 'fast' || custody.banked) && saved && saved.config)
      ? { ...saved.config, authMode: 'fast', signinMode: 'fast', persistentSession: true }
      : null
  function deriveRecordCustody(rawRecord, forTransportId, savedConfigArrived = null) {
    const matches = !!(rawRecord && rawRecord.id === forTransportId)
    let era = null
    if (matches && rawRecord && rawRecord.config && typeof rawRecord.config === 'object') {
      const cfg = rawRecord.config
      const wt = cfg.webToken && typeof cfg.webToken === 'object' ? cfg.webToken : null
      const hasFastMaterial = String(cfg.authMode || '') === 'fast' || String(cfg.signinMode || '') === 'fast' || cfg.persistentSession === true
      const explicitlyRevoked = !!(wt && wt.revokedByProvider === true)
      if ((hasFastMaterial || (wt && typeof wt.token === 'string' && wt.token)) && !explicitlyRevoked) {
        era = {
          authMode: String(cfg.authMode || 'fast'),
          signinMode: String(cfg.signinMode || 'fast'),
          banked: true,
          alive: true,
          persistentSession: true,
          burnMinutes: (wt && Number.isFinite(Number(wt.exp)) && Number(wt.exp) > Date.now() + 30000)
            ? Math.max(1, Math.floor((Number(wt.exp) - Date.now()) / 60000))
            : 60,
        }
      }
    }
    if (era) era.locked = false
    return era
  }
  // R172 — THE TITLE MATCHES THE ACTIVE METHOD (R-172.4, the E-26/E-27
  // cure): the popup's title speaks the method the owner actually rides —
  // never a generic "guided setup" over a connected fast sign-in.
  try {
    const ttl = $('twTitle')
    if (ttl && savedMatches) {
      // R177 — R-177.1/R-177.3: the connected fact rides the RECORD's
      // custody evidence when the worker's copy is lock-blind — the R-172.4
      // override must never lose its subject to a lock. The reopened modal
      // renders the connected era over a living bank; the fresh-setup face
      // over a verified mint is structurally unreachable.
      const mode = String((savedConfig && savedConfig.authMode) || (custody && custody.authMode) || '')
      const sig = String((savedConfig && savedConfig.signinMode) || (custody && custody.signinMode) || '')
      const connected = Object.keys(savedConfig || {}).length > 0 || !!(custody && (custody.banked || custody.authMode === 'fast' || custody.signinMode === 'fast'))
      const mTitle = mode === 'fast' || sig === 'fast'
        ? (connected ? 'twWizardTitleFastConnected' : 'twWizardTitleFast')
        : mode === 'bridge' || sig === 'manual'
          ? 'twWizardTitleBridge'
          : connected ? 'twWizardTitleGuidedConnected' : null
      if (mTitle) ttl.textContent = getMessage(mTitle, [`${t.icon} ${tName}`], `${t.icon} ${tName} — ${mode === 'fast' ? 'connected with one-click sign-in' : mTitle === 'twWizardTitleBridge' ? 'Bridge (Advanced)' : 'your own key (guided)'}`)
    }
  } catch { /* the base title stands */ }
  const fields = $('twFields')
  fields.innerHTML = ''
  for (const f of t.fields || []) {
    const wrap = document.createElement('div')
    wrap.className = 'form-group'
    const label = document.createElement('label')
    // R28-i18n: field label/help resolve through twField<Id><Field>(Help)
    const [labelKey, helpKey] = twFieldKeys(t.id, f.key)
    label.textContent = getMessage(labelKey, undefined, f.label)
    label.setAttribute('for', 'twf-' + f.key)
    let input
    // R109 §3.2(b/c) — the CEO's S2, law 0.24: a password field whose value
    // is ALREADY STORED (sealed at rest) never renders as a readable inline
    // input. The stored value renders as a masked summary + an eye button
    // that opens the credential popup (passphrase re-auth → the value shown
    // read-only with Copy). The hidden carrier input keeps the stored value
    // so a re-save round-trips the envelope untouched (sealTransportConfig
    // is envelope-idempotent).
    const storedSealed = f.type === 'password' && typeof savedConfig[f.key] === 'string' && savedConfig[f.key]
    if (f.type === 'password' && storedSealed) {
      const carrier = document.createElement('input')
      carrier.type = 'hidden'
      carrier.id = 'twf-' + f.key
      carrier.value = savedConfig[f.key]
      carrier.dataset.fieldKey = f.key
      const rowEl = document.createElement('div')
      rowEl.style.cssText = 'display:flex;gap:6px;align-items:center'
      const summary = document.createElement('input')
      summary.type = 'password'
      summary.readOnly = true
      summary.value = '••••••••••••••••'
      summary.setAttribute('aria-label', label.textContent + ' — stored, sealed. Press the reveal button to view it after your passphrase check.')
      summary.style.cssText = 'flex:1;min-width:0'
      const eyeBtn = document.createElement('button')
      eyeBtn.type = 'button'
      eyeBtn.className = 'btn btn-outline btn-sm'
      eyeBtn.textContent = '👁'
      eyeBtn.style.minWidth = '38px'
      eyeBtn.setAttribute('aria-label', getMessage('credPopupRevealBtnLabel', undefined, 'Reveal after passphrase check'))
      eyeBtn.setAttribute('aria-pressed', 'false')
      eyeBtn.addEventListener('click', async () => {
        // R110 §3 — within the passphrase window this confirmation does not
        // re-prompt: the countdown chip renders next to the eye and the
        // reveal proceeds (the sealed store still enforces unlocked-only).
        const skipped = await confirmWithinWindow(eyeBtn, async () => {})
        let r = skipped ? { ok: true, value: '' } : await UCryptCredPopup.open({
          title: getMessage('credPopupRevealSecretTitle', [label.textContent], 'Confirm your passphrase to reveal "$1"'),
          help: getMessage('credPopupRevealSecretHelp', undefined, 'The value is sealed in your vault on this device. It is shown only here, only now — never logged, never synced, never exported.'),
          mode: 'passphrase',
          confirmLabel: getMessage('credPopupConfirm', undefined, 'Confirm'),
          verify: async (pass) => {
            const v = await bgSend('VERIFY_PASSPHRASE', { passphrase: pass })
            return v && v.ok ? { ok: true } : { ok: false, error: (v && v.error) || getMessage('sdRevealFailed', undefined, 'Wrong master passphrase') }
          },
        })
        if (!r || !r.ok) return // the user's explicit cancel
        const vr = await bgSend('TRANSPORT_REVEAL_SECRET', { field: f.key })
        if (!vr || !vr.ok) {
          toast((vr && vr.error) || getMessage('credPopupRevealFail', undefined, 'Could not open the sealed value.'), 'error')
          return
        }
        await UCryptCredPopup.open({
          title: label.textContent,
          mode: 'passphrase',
          revealValue: vr.value,
          revealNote: getMessage('credPopupRevealNote', undefined, 'Copy it if you need it elsewhere — close when done. Nothing is written to the page.'),
          confirmLabel: getMessage('credPopupConfirm', undefined, 'Confirm'),
        })
      })
      rowEl.appendChild(summary)
      rowEl.appendChild(eyeBtn)
      // The change path stays one click (anti-trim): swap the stored value
      // for a fresh popup entry — the carrier is overwritten, nothing else.
      const changeBtn = document.createElement('button')
      changeBtn.type = 'button'
      changeBtn.className = 'btn btn-ghost btn-sm'
      changeBtn.textContent = getMessage('credPopupEntryChangeStored', undefined, 'Replace…')
      changeBtn.addEventListener('click', async () => {
        const r = await UCryptCredPopup.open({
          title: label.textContent,
          help: getMessage('credPopupSecretEntryHelp', undefined, 'Google requires your client secret for direct sign-in — it stays sealed in your vault on this device, never synced, never logged, never exported.'),
          mode: 'secret',
          placeholder: f.placeholder || '',
          confirmLabel: getMessage('credPopupSave', undefined, 'Save'),
          verify: (v) => {
            const s = String(v || '').trim()
            if (!s) return { ok: false, error: getMessage('credPopupSecretEmpty', undefined, 'Paste the value first — the field is empty.') }
            if (s.length > 256) return { ok: false, error: getMessage('credPopupSecretLong', undefined, 'That value is too long — a client secret is a short string. Check what you pasted.') }
            return { ok: true }
          },
        })
        if (!r || !r.ok) return
        carrier.value = r.value
        summary.value = '•••••••••••••••• (new — sealed on save)'
        summary.setAttribute('aria-label', label.textContent + ' — replaced, sealed on save.')
      })
      rowEl.appendChild(changeBtn)
      wrap.appendChild(label)
      wrap.appendChild(carrier)
      wrap.appendChild(rowEl)
      const help = document.createElement('p')
      help.className = 'card-help'
      help.textContent = getMessage(helpKey, undefined, f.help || '')
      wrap.appendChild(help)
      fields.appendChild(wrap)
      continue
    }
    // R109 §3.2(c) — the CEO's S2: the guided setup's secret ENTRY is a
    // popup layer, not a fixed inline field. The gdrive client secret is
    // the first conversion (his exact arrow): the card shows a single
    // "Add your client secret" action; the popup opens on demand with its
    // one-sentence why; the hidden carrier input feeds TRANSPORT_SAVE
    // unchanged (the worker seals it exactly as before).
    if (f.type === 'password' && f.popupEntry) {
      const carrier = document.createElement('input')
      carrier.type = 'hidden'
      carrier.id = 'twf-' + f.key
      carrier.dataset.fieldKey = f.key
      const rowEl = document.createElement('div')
      rowEl.style.cssText = 'display:flex;gap:6px;align-items:center;flex-wrap:wrap'
      const status = document.createElement('span')
      status.className = 'card-help'
      status.style.margin = '0'
      status.textContent = getMessage('credPopupEntryEmpty', undefined, 'Not set — required only if Google rejects the direct sign-in.')
      const addBtn = document.createElement('button')
      addBtn.type = 'button'
      addBtn.className = 'btn btn-outline btn-sm'
      addBtn.textContent = getMessage('credPopupEntryAdd', [label.textContent], 'Add $1…')
      addBtn.addEventListener('click', async () => {
        const r = await UCryptCredPopup.open({
          title: label.textContent,
          help: getMessage('credPopupSecretEntryHelp', undefined, 'Google requires your client secret for direct sign-in — it stays sealed in your vault on this device, never synced, never logged, never exported.'),
          mode: 'secret',
          placeholder: f.placeholder || '',
          confirmLabel: getMessage('credPopupSave', undefined, 'Save'),
          verify: (v) => {
            const s = String(v || '').trim()
            if (!s) return { ok: false, error: getMessage('credPopupSecretEmpty', undefined, 'Paste the value first — the field is empty.') }
            if (s.length > 256) return { ok: false, error: getMessage('credPopupSecretLong', undefined, 'That value is too long — a client secret is a short string. Check what you pasted.') }
            return { ok: true }
          },
        })
        if (!r || !r.ok) return
        carrier.value = r.value
        status.textContent = getMessage('credPopupEntrySet', undefined, 'Set — it will be sealed in your vault when you save this card.')
        addBtn.textContent = getMessage('credPopupEntryChange', [label.textContent], 'Change $1…')
      })
      rowEl.appendChild(status)
      rowEl.appendChild(addBtn)
      wrap.appendChild(label)
      wrap.appendChild(carrier)
      wrap.appendChild(rowEl)
      const help = document.createElement('p')
      help.className = 'card-help'
      help.textContent = getMessage(helpKey, undefined, f.help || '')
      wrap.appendChild(help)
      fields.appendChild(wrap)
      continue
    }
    if (f.type === 'select') {
      // R85 (§4): the gdrive authMode selector.
      // R172 — THE POISON KILL (the field's root seat, docs/R172-CLOUD-MAP.md
      // P1): the select historically offered only ['oauth','bridge'] — a
      // stored fast record's authMode could not ride the form, the prefill
      // silently demoted it to 'oauth', and a mere Save scrubbed the
      // clientId + dropped the custody (the hollow record the field proved).
      // The select now CARRIES the fast rung when the stored record is fast:
      // the form tells the truth, the round-trip preserves the record, and
      // a demotion can only happen by an EXPLICIT user choice.
      input = document.createElement('select')
      input.id = 'twf-' + f.key
      const optsList = [...(f.options || [])]
      const storedMode = String(savedConfig[f.key] || (custody && custody.authMode) || '')
      if ((storedMode === 'fast' || t.id === 'gdrive') && !optsList.includes('fast')) optsList.unshift('fast')
      for (const opt of optsList) {
        const o = document.createElement('option')
        o.value = opt
        o.textContent = opt === 'fast' ? 'Fast — one-click sign-in (persistent)' : opt === 'oauth' ? 'OAuth (guided — your own key)' : 'Bridge (Advanced)'
        input.appendChild(o)
      }
      input.value = storedMode || savedConfig[f.key] || f.default || (f.options && f.options[0]) || ''
    } else {
      input = document.createElement('input')
      input.id = 'twf-' + f.key
      input.type = f.type === 'password' ? 'password' : (f.type === 'url' ? 'url' : 'text')
      input.placeholder = f.placeholder || ''
      input.value = savedConfig[f.key] || ''
    }
    input.dataset.fieldKey = f.key
    wrap.appendChild(label)
    wrap.appendChild(input)
    const help = document.createElement('p')
    help.className = 'card-help'
    help.textContent = getMessage(helpKey, undefined, f.help || '')
    wrap.appendChild(help)
    fields.appendChild(wrap)
  }

  // R164 Arc B (G183's map, site 3) — THE HONEST COPY (§2 verbatim, ×3
  // locales): one help line inside the EXISTING Drive wizard form — copy,
  // not layout (the canonical UI freeze holds).
  if (transportId === 'gdrive') {
    const copyWrap = document.createElement('div')
    copyWrap.className = 'form-group'
    const copyLine = document.createElement('p')
    copyLine.className = 'card-help'
    copyLine.dataset.i18n = 'driveAppdataCopy'
    copyLine.id = 'gdriveAppdataCopy'
    copyLine.textContent = getMessage('driveAppdataCopy', undefined, 'UCrypt saves backups in its own private Drive folder. The folder is invisible in Google Drive and readable only by UCrypt. You can revoke access at any time at myaccount.google.com/permissions.')
    copyWrap.appendChild(copyLine)
    fields.appendChild(copyWrap)
  }

  // R95 F-95-03 — the joiner-side completion: a full pairing URI handed the
  // wizard its cloud location ('ucrypt:pairingCloud' — provider + a
  // userinfo-stripped address ONLY; the secret-law allowlist decided what
  // rode the payload). Prefill the matching NON-SECRET field, say so, and
  // consume the one-shot handoff. The user still enters their own sign-in —
  // the payload never carried it and never will.
  // R102 (J1) — a COMPLETE code hands over the sign-in too (the labeled
  // opt-in on the origin): the wizard prefills the credential fields, says
  // so, and consumes the ONE-SHOT handoff in the same read (the storage key
  // is removed here regardless of the provider match, so a stale payload can
  // never leak into a later wizard open).
  try {
    const pc = (await chrome.storage.local.get('ucrypt:pairingCloud'))['ucrypt:pairingCloud']
    if (pc) {
      await chrome.storage.local.remove('ucrypt:pairingCloud').catch(() => {})
      if (pc.provider === transportId) {
        const urlInput = fields.querySelector('input[data-field-key="url"]')
        if (urlInput && !urlInput.value && pc.url) urlInput.value = String(pc.url)
        // R106 payload law v1.2 → R108 §2.3 — the PROVIDER-AWARE prefill
        // map. THE FORENSIC'S SECOND ROOT CAUSE: v1.2 wrote the client ID
        // only into "oauthClientId" (GitHub's key), so a Google Drive code
        // could never fill the gdrive card ("clientId") and a Dropbox code
        // never its "appKey"; the bridge URL never reached gdrive's
        // "scriptUrl" either. Now the client ID goes to THIS card's real
        // id-field key and the bridge URL to the bridge address key — with
        // the generic key list as the robust fallback for future providers.
        if (pc.conn && typeof pc.conn === 'object') {
          const idKeys = [PAIRING_CONN_FIELD_TARGETS[transportId], 'clientId', 'oauthClientId', 'appKey'].filter(Boolean)
          if (pc.conn.cid) {
            for (const key of idKeys) {
              const el = fields.querySelector(`input[data-field-key="${key}"]`)
              if (el && !el.value) { el.value = String(pc.conn.cid); break }
            }
          }
          if (pc.conn.b) {
            for (const key of PAIRING_CONN_BRIDGE_TARGETS) {
              const el = fields.querySelector(`input[data-field-key="${key}"]`)
              if (el && !el.value) { el.value = String(pc.conn.b); break }
            }
          }
        }
        if (pc.creds && typeof pc.creds === 'object') {
          const userInput = fields.querySelector('input[data-field-key="user"]')
          const passInput = fields.querySelector('input[data-field-key="pass"]')
          if (userInput && !userInput.value && pc.creds.u) userInput.value = String(pc.creds.u)
          if (passInput && !passInput.value && pc.creds.p) passInput.value = String(pc.creds.p)
          if (userInput || passInput) {
            const result = $('twResult')
            if (result) {
              result.className = 'sync-test-result'
              result.textContent = getMessage('twPairingAttachedComplete', undefined,
                'Complete pairing — the sign-in was attached from the code. It lives only in this form and in the sealed transport store; it is never logged.')
            }
          }
        }
        // R120 §2.3 — THE FAST-RUNG JOINER (payload v1.5): an m:'fast' origin
        // sealed NO credentials (the fast connection is device-local — there
        // was nothing to carry), so the arrival line says exactly that and
        // the ladder block takes the one click: "Sign in with Google — one
        // click" where feature detection allows (on Helium the guided rung
        // stays the face — the honest label, never a dead button).
        if (pc.conn && pc.conn.m === 'fast') {
          const result = $('twResult')
          if (result) {
            result.className = 'sync-test-result'
            result.textContent = getMessage('twPairingAttachedFast', undefined,
              'Complete pairing — the other device signed in with UCrypt\'s shared sign-in. Sign in the same way below — one click where your browser allows it.')
          }
          // the ONE click is immediate: the ladder block (the rungs) is in
          // view when the user looks up from the arrival line (law 0.25 —
          // every feature reachable; the fast CTA is the block's first rung
          // whenever detection allows).
          try {
            const ladderHost = document.getElementById('twLadder')
            if (ladderHost) ladderHost.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
          } catch { /* scroll is best-effort */ }
        }
        const result = $('twResult')
        if (result && !result.textContent) {
          result.className = 'sync-test-result'
          result.textContent = getMessage(
            'twPairingAttached',
            [String(pc.provider)],
            'Cloud setup attached from the pairing code — check the address, then add your own sign-in.',
          )
        }
      }
    }
  } catch { /* handoff is best-effort — the manual path is unchanged */ }

  // R45-A §2.5: while locked, a truthful note that secrets are stored but
  // not readable — the user is never shown a stale or masked fake value.
  const lockedNote = $('twLockedNote')
  if (lockedNote) {
    if (storedSecretNote) {
      lockedNote.textContent = storedSecretNote
      lockedNote.classList.remove('hidden')
    } else {
      lockedNote.classList.add('hidden')
    }
  }

  // R85 (§4): Google Drive — OAuth primary; bridge fallback under Advanced
  // (one-sentence reason: it exists only for browsers/accounts where the
  // OAuth client cannot be registered).
  const scriptBox = $('twScriptBox')
  // R85 (§4): the bridge moves under Advanced with the one-sentence reason.
  const bridgeReason = $('twBridgeReason')
  const gdriveActions = $('twGdriveActions')
  const gdriveRedirect = $('twGdriveRedirect')
  const gdriveVerifyBtn = $('twGdriveVerifyBtn')
  const gdriveVerifyOut = $('twGdriveVerifyOut')
  // R87 (§2.3): GitHub and Dropbox join Drive on the PKCE Connect contract
  // (the same 3-step card, transport-aware copy). GitHub: code + PKCE, scope
  // "gist" only, pasted token under Advanced, three-state gist discovery kept.
  // Dropbox: refresh-token path, no scope widening, no forced reconnects.
  const oauthTransport = (transportId === 'gdrive' || transportId === 'github' || transportId === 'dropbox')
    ? {
        gdrive: {
          msgType: 'TRANSPORT_GDRIVE_CONNECT',
          grantField: 'refreshToken',
          idField: 'clientId',
          preflight: (v) => validateClientIdFormat(v),
          step2HintKey: 'twConnectStep2GuideGdrive',
          // R92 §1.2 — the two-path law in one sentence (the CEO's order).
          step2Hint: 'The client ID ends in .apps.googleusercontent.com. Direct sign-in (paste your secret) or the no-secret Bridge — your choice.',
          statusKey: 'twGdriveNeedsClientId',
          statusFallback: 'Google Drive OAuth requires a client ID from the owner — “How do I get a client ID?” below creates it in about two minutes. Nothing is sent anywhere until you press Connect.',
          connectLabelKey: 'twGdriveConnectBtn',
          connectLabel: 'Connect Google Drive (OAuth)',
        },
        github: {
          msgType: 'TRANSPORT_GITHUB_CONNECT',
          grantField: 'oauthAccessToken',
          idField: 'oauthClientId',
          preflight: (v) => (String(v || '').trim()
            ? { ok: true, message: '' }
            : { ok: false, message: 'Enter the GitHub OAuth app client ID (step 2) — or a personal access token under Advanced.' }),
          step2HintKey: 'twConnectStep2GuideGithub',
          step2Hint: 'The client ID looks like Ov23li… — from your OAuth app. UCrypt requests the “gist” scope only; no client secret.',
          statusKey: 'twConnectNeedsConfigGithub',
          statusFallback: 'GitHub OAuth requires an OAuth app client ID from the owner — create it at github.com/settings/developers. Nothing is sent anywhere until you press Connect.',
          connectLabelKey: 'twConnectBtnGithub',
          connectLabel: 'Connect GitHub (OAuth)',
        },
        dropbox: {
          msgType: 'TRANSPORT_DROPBOX_CONNECT',
          grantField: 'refreshToken',
          idField: 'appKey',
          preflight: (v) => (String(v || '').trim()
            ? { ok: true, message: '' }
            : { ok: false, message: 'Enter the Dropbox app key (step 2) — create the app at dropbox.com/developers/apps.' }),
          step2HintKey: 'twConnectStep2GuideDropbox',
          step2Hint: 'The app key from your Dropbox app console. The grant refreshes itself — no forced reconnects, no scope widening.',
          statusKey: 'twConnectNeedsConfigDropbox',
          statusFallback: 'Dropbox OAuth requires an app key from the owner — create the app at dropbox.com/developers/apps. Nothing is sent anywhere until you press Connect.',
          connectLabelKey: 'twConnectBtnDropbox',
          connectLabel: 'Connect Dropbox (OAuth)',
        },
      }[transportId]
    : null
  if (oauthTransport) {
    // Transport-aware card copy (the shared 3-step card)
    const cardName = { gdrive: 'Google Drive', github: 'GitHub', dropbox: 'Dropbox' }[transportId]
    const step1Title = $('twGdriveStep1Title')
    if (step1Title) step1Title.textContent = getMessage('twConnectCardStep1Title', [cardName], `${cardName} — Step 1 — Copy this exact redirect URI`)
    const step1Guide = $('twGdriveStep1Guide')
    if (step1Guide) step1Guide.textContent = getMessage('twConnectCardStep1Guide', undefined, 'In your OAuth app settings → authorized redirect URIs → paste exactly this URL:')
    const step2Title = $('twGdriveStep2Title')
    if (step2Title) step2Title.textContent = getMessage('twConnectCardStep2Title', [cardName], `${cardName} — Step 2 — Paste your OAuth client ID / app key`)
    const step2Guide = $('twGdriveStep2Guide')
    if (step2Guide) step2Guide.textContent = getMessage(oauthTransport.step2HintKey, undefined, oauthTransport.step2Hint)
    const step3Title = $('twGdriveStep3Title')
    if (step3Title) step3Title.textContent = getMessage('twConnectCardStep3Title', undefined, 'Step 3 — Connect')
    const connectLabelBtn = $('twGdriveConnectBtn')
    if (connectLabelBtn) connectLabelBtn.textContent = getMessage(oauthTransport.connectLabelKey, undefined, oauthTransport.connectLabel)
    // R91 §2.1 (CEO S-C) — MODE-AWARE GUIDANCE, fixed at the reader AND at
    // the render. The authMode control is a <select>: the old reader queried
    // `input[data-field-key="authMode"]`, which can never match a select, so
    // the mode was permanently stuck on 'oauth' — selecting Bridge (Advanced)
    // hid the bridge fields and the script box and kept showing the OAuth
    // card (the owner's S-C screenshot: a mode selection with a stale/blank
    // guidance area, the bridge setup unreachable). Now ONE function derives
    // the mode from the REAL select and renders EVERY guided surface to
    // match: OAuth selected → the 3-step OAuth card only; Bridge selected →
    // the 4-step bridge guide, the bridge fields and the pre-filled script
    // box only. Never both, never neither, never stale.
    const readAuthMode = () => {
      const sel = document.querySelector('#twFields select[data-field-key="authMode"]')
      if (sel && sel.value) return sel.value
      const legacy = document.querySelector('#twFields input[data-field-key="authMode"]')
      return (legacy && legacy.value) || 'oauth'
    }
    const syncFieldGroups = () => {
      const mode = readAuthMode()
      document.querySelectorAll('#twFields [data-field-key]').forEach((input) => {
        const key = input.dataset.fieldKey
        const row = input.closest('.form-group') || input.parentElement
        // R92 §1.2 — the OWN-SECRET fields ride the OAuth group (they are
        // OAuth-mode fields by definition); the bridge group is unchanged.
        const bridgeField = ['scriptUrl', 'secret'].includes(key)
        const oauthField = ['clientId', 'clientSecret', 'refreshToken', 'oauthClientId', 'oauthClientSecret', 'oauthAccessToken', 'appKey', 'appSecret'].includes(key)
        if (row && row.style) {
          if (mode === 'oauth' && bridgeField) row.style.display = 'none'
          else if (mode === 'bridge' && oauthField) row.style.display = 'none'
          else row.style.display = ''
        }
      })
      // The guided steps (twSteps) ARE the bridge guide for Google Drive —
      // they must show exactly when the bridge mode is selected. The OAuth
      // card shows exactly when OAuth is selected.
      const stepsEl = $('twSteps')
      const actionsEl = gdriveActions
      if (mode === 'bridge') {
        if (stepsEl) stepsEl.classList.remove('hidden')
        if (actionsEl) actionsEl.classList.add('hidden')
        scriptBox.classList.remove('hidden')
      } else {
        if (stepsEl) stepsEl.classList.add('hidden')
        if (actionsEl) actionsEl.classList.remove('hidden')
        scriptBox.classList.add('hidden')
      }
    }
    document.querySelectorAll('#twFields [data-field-key]').forEach((input) => {
      input.addEventListener('input', syncFieldGroups)
      input.addEventListener('change', syncFieldGroups)
    })
    syncFieldGroups()
    const secretInput = document.querySelector('#twFields input[data-field-key="secret"]')
    const updateScript = () => {
      $('twScript').textContent = gdriveBridgeScript(secretInput ? secretInput.value : '')
    }
    updateScript()
    if (secretInput) secretInput.addEventListener('input', updateScript)
    if (gdriveActions) gdriveActions.classList.remove('hidden')
    if (gdriveRedirect) gdriveRedirect.textContent = identityRedirect()
    // R87 (§2.1b): the honest status line — when no client ID is configured,
    // the card SAYS so instead of letting the connect button dead-end.
    const statusLine = $('twGdriveStatusLine')
    const guideBox = $('twGdriveGuide')
    const guideBtn = $('twGdriveGuideBtn')
    const recoveryBox = $('twGdriveRecovery')
    const clientIdInput = document.querySelector('#twFields input[data-field-key="clientId"]')
    const renderStatusLine = () => {
      const hasId = !!(clientIdInput && clientIdInput.value.trim())
      if (statusLine) {
        if (hasId) statusLine.classList.add('hidden')
        else {
          statusLine.textContent = getMessage(oauthTransport.statusKey, undefined, oauthTransport.statusFallback)
          statusLine.classList.remove('hidden')
        }
      }
    }
    renderStatusLine()
    if (clientIdInput) clientIdInput.addEventListener('input', renderStatusLine)
    if (guideBtn && guideBox) {
      guideBtn.onclick = () => {
        guideBox.classList.toggle('hidden')
        guideBtn.setAttribute('aria-expanded', guideBox.classList.contains('hidden') ? 'false' : 'true')
      }
      guideBtn.setAttribute('aria-expanded', 'false')
    }
    // The get-a-client-ID guide is Google-specific — GitHub/Dropbox carry the
    // console steps in their hints instead.
    if (guideBtn && transportId !== 'gdrive') guideBtn.classList.add('hidden')
    else if (guideBtn) guideBtn.classList.remove('hidden')
    // R87 (§2.1b): Copy-the-exact-URI affordance.
    const copyBtn = $('twGdriveCopyRedirect')
    if (copyBtn && gdriveRedirect) {
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(gdriveRedirect.textContent.trim())
          copyBtn.textContent = getMessage('twGdriveCopied', undefined, 'Copied ✓')
          setTimeout(() => { copyBtn.textContent = getMessage('twGdriveCopyRedirect', undefined, 'Copy URI') }, 2400)
        } catch {
          // clipboard API blocked — the text remains user-select:all, so the
          // fallback is the selection itself; keep the button truthful.
          copyBtn.textContent = getMessage('twGdriveCopyFail', undefined, 'Select & copy the URI above')
          setTimeout(() => { copyBtn.textContent = getMessage('twGdriveCopyRedirect', undefined, 'Copy URI') }, 2400)
        }
      }
    }
    // R87 (§2.1c): the typed recovery card renderer.
    // S4 (the CEO's brief — R126): the card's one-click recovery is REAL —
    // a [Try again] button re-presses THIS connect (one click, the state is
    // clean by construction) and the popup-settings deep link opens Chrome's
    // popup page directly (the blocked-window card's second door).
    const renderRecovery = (recovery) => {
      if (!recovery || !recoveryBox) return
      const title = $('twGdriveRecoveryTitle')
      const causes = $('twGdriveRecoveryCauses')
      const fix = $('twGdriveRecoveryFix')
      if (title) title.textContent = recovery.title || ''
      if (causes) {
        causes.textContent = ''
        for (const c of (recovery.causes || [])) {
          const li = document.createElement('li')
          li.textContent = c
          causes.appendChild(li)
        }
        // R127 §3.2 (the CEO's S4 — the disabled-client card): the console
        // checklist rides the card's own surface — the two sentences AFTER
        // the causes, before the fix line, so the reading order is
        // cause → the console check → the fix (law 0.26's depth order).
        for (const cn of (recovery.consoleNote || [])) {
          const li = document.createElement('li')
          li.textContent = cn
          causes.appendChild(li)
        }
      }
      if (fix) fix.textContent = recovery.fix || ''
      // S4 — the one-click actions ride INSIDE the card that named the
      // problem (law 0.29: the fix button lives on the surface that named it).
      const old = document.getElementById('twRecoveryActions')
      if (old) old.remove()
      if (recovery.retryLabel && connectBtn) {
        const actions = document.createElement('div')
        actions.id = 'twRecoveryActions'
        actions.className = 'btn-row'
        actions.style.marginTop = '8px'
        // R127 §3.2 — the console deep link is the PRIMARY recovery on the
        // gdrive window cards (the owner's binding order: the primary
        // "Open Google Cloud Console" button; the popup-settings link stays
        // beside it, demoted, when the card carries one).
        if (recovery.consoleLink) {
          const cl = document.createElement('button')
          cl.type = 'button'
          cl.className = 'btn btn-primary btn-sm'
          cl.textContent = recovery.consoleLabel || 'Open Google Cloud Console'
          cl.addEventListener('click', () => { try { chrome.tabs.create({ url: recovery.consoleLink }) } catch { /* the card stays */ } })
          actions.appendChild(cl)
        }
        const retry = document.createElement('button')
        retry.type = 'button'
        retry.className = recovery.consoleLink ? 'btn btn-outline btn-sm' : 'btn btn-primary btn-sm'
        retry.textContent = recovery.retryLabel || 'Try again'
        retry.addEventListener('click', () => { hideRecovery(); connectBtn.click() })
        actions.appendChild(retry)
        if (recovery.deepLink) {
          const dl = document.createElement('button')
          dl.type = 'button'
          dl.className = 'btn btn-outline btn-sm'
          dl.textContent = recovery.deepLinkLabel || 'Open popup settings'
          dl.addEventListener('click', () => { try { chrome.tabs.create({ url: recovery.deepLink }) } catch { /* the card stays */ } })
          actions.appendChild(dl)
        }
        recoveryBox.appendChild(actions)
      }
      recoveryBox.classList.remove('hidden')
    }
    const hideRecovery = () => { if (recoveryBox) recoveryBox.classList.add('hidden') }
    const connectBtn = $('twGdriveConnectBtn')
    if (connectBtn) connectBtn.onclick = async () => {
      const out = gdriveVerifyOut
      out.className = 'sync-test-result'
      hideRecovery()
      // R120 (law 0.33) — THE SWITCH BEFORE THE FLOW: when the stored
      // connection lives on a DIFFERENT rung, the switch is planned and the
      // prior rung's material cleaned (the wizard's own fields — the exact
      // surface the save collects) BEFORE the authorization window opens;
      // the ring records { stage: 'rung-switch' }. Same rung / no prior
      // rung: the plan refuses and this is a no-op — the old path unchanged.
      await beginRungSwitch(transportId, 'guided')
      // R87 (§2.1d/§2.3): pre-flight BEFORE any network round-trip.
      const cid = document.querySelector(`#twFields input[data-field-key="${oauthTransport.idField}"]`)
      const pre = oauthTransport.preflight(cid ? cid.value : '')
      if (!pre.ok) {
        out.className = 'sync-test-result err'
        out.textContent = '✗ ' + pre.message
        return
      }
      // R119 §5 (order §3.4) — THE PREFLIGHT PING: preflightClientId is the
      // ladder's format probe — a stale/malformed client ID says so
      // IMMEDIATELY, as a typed inline card ON the field, and NO window
      // opens (the guided rung rides the probe too).
      const pf = preflightClientId(transportId, cid ? cid.value : '')
      if (!pf.ok) {
        out.className = 'sync-test-result err'
        out.textContent = '✗ ' + getMessage('ladderPreFailTitle', undefined, 'Check your client ID before the sign-in window opens:')
        renderPreflightCard(cid || null, { ok: false, kind: pf.kind, transportId }, {
          onShowHow: () => openLadderWalkthrough(transportId),
        })
        return
      }
      // R115 — THE CONNECT BUTTON'S OWN STATE MACHINE (the audit's suspect
      // (g)): the button is disabled and honestly labelled for the whole
      // flow, and the finally restores it — a double-click can never fire a
      // second authorization window, and no failure leaves a stuck
      // "connecting…" (the 0.26 law: a stuck state IS a defect).
      connectBtn.disabled = true
      const connectLabel = connectBtn.textContent
      connectBtn.textContent = getMessage('twGdriveConnectingBtn', undefined, 'Connecting…')
      out.textContent = getMessage('twGdriveConnecting', undefined, 'Opening the authorization window…')
      try {
        const res = await bgSend(oauthTransport.msgType, { config: collectTransportConfig() })
        if (res && res.ok && (res.refreshToken || res.accessToken)) {
          const grantValue = res.refreshToken || res.accessToken
          const rt = document.querySelector(`#twFields input[data-field-key="${oauthTransport.grantField}"]`)
          if (rt) rt.value = grantValue
          // R119 — THE RUNG RECORD: this grant arrived through the EXISTING
          // guided connect — the save path carries signinMode:'guided'.
          wizardSigninMode = 'guided'
          out.className = 'sync-test-result ok'
          const okGuidedMsg = '✓ ' + getMessage('twGdriveConnected', undefined, 'Grant received and stored into the form — press Save to seal it device-only.')
          out.textContent = okGuidedMsg
          try { toast(okGuidedMsg, 'ok') } catch { /* best-effort */ }
        } else {
          out.className = 'sync-test-result err'
          const errText = String((res && res.error) || '')
          // R115 — THE TYPED INTERRUPTION CARD (the audit's most likely live
          // glitch signature): the MV3 worker can be suspended mid-flow, and
          // the raw engine strings ("The message port closed…", "Receiving
          // end does not exist") used to render raw. Now: the honest
          // interrupted card — nothing was half-saved, the retry starts clean.
          if (/message port closed|receiving end|context invalidated/i.test(errText)) {
            out.textContent = '✗ ' + getMessage('twConnectInterrupted', undefined, 'The connection attempt was interrupted (the browser suspended the background worker) — nothing was half-saved. Press Connect again.')
            renderRecovery({
              title: getMessage('twConnectInterruptedTitle', undefined, 'The authorization was interrupted, not refused.'),
              causes: [getMessage('twConnectInterruptedCause', undefined, 'Chrome suspends background workers it thinks are idle; a long-running authorization can be caught by that sweep. Nothing was exchanged and nothing was written — the retry is clean by construction.')],
              fix: getMessage('twConnectInterruptedFix', undefined, 'Press Connect again. If it keeps happening, press Connect and complete the Google consent within a minute of the window opening.'),
            })
          } else {
            out.textContent = '✗ ' + (errText || getMessage('twGdriveFail', undefined, 'The authorization did not finish.'))
          }
          try { toast(out.textContent, 'error') } catch { /* best-effort */ }
          if (res && res.recovery) renderRecovery(res.recovery)
          // R109 §3.2(c) — the CEO's S2: the secret popup opens only when
          // the direct path NEEDS it. Google's invalid_client is exactly
          // that moment (the client demands its secret); the typed error
          // grows the one-click popup offer with its one-sentence why.
          if (/invalid_client|client secret|unauthorized_client/i.test(errText)) {
            const secretRow = document.createElement('div')
            secretRow.style.marginTop = '6px'
            const offerBtn = document.createElement('button')
            offerBtn.type = 'button'
            offerBtn.className = 'btn btn-outline btn-sm'
            offerBtn.textContent = getMessage('twAddSecretOffer', undefined, 'Add the client secret…')
            offerBtn.addEventListener('click', async () => {
              const carrier = document.querySelector(`#twFields input[data-field-key="${oauthTransport.idField === 'clientId' ? 'clientSecret' : oauthTransport.secretField || 'clientSecret'}"]`)
              if (!carrier) return
              const r = await UCryptCredPopup.open({
                title: getMessage('twSecretPopupTitle', undefined, 'Your Google client secret'),
                help: getMessage('credPopupSecretEntryHelp', undefined, 'Google requires your client secret for direct sign-in — it stays sealed in your vault on this device, never synced, never logged, never exported.'),
                mode: 'secret',
                placeholder: 'GOCSPX-…',
                confirmLabel: getMessage('credPopupSave', undefined, 'Save'),
                verify: (v) => {
                  const s = String(v || '').trim()
                  if (!s) return { ok: false, error: getMessage('credPopupSecretEmpty', undefined, 'Paste the value first — the field is empty.') }
                  if (s.length > 256) return { ok: false, error: getMessage('credPopupSecretLong', undefined, 'That value is too long — a client secret is a short string. Check what you pasted.') }
                  return { ok: true }
                },
              })
              if (r && r.ok) {
                carrier.value = r.value
                out.className = 'sync-test-result'
                out.textContent = getMessage('twSecretStoredRetry', undefined, '✓ The client secret is set — it will be sealed when you save. Press Connect again (or Save first, then Connect).')
              }
            })
            secretRow.appendChild(offerBtn)
            out.appendChild(secretRow)
          }
        }
      } catch (e) {
        out.className = 'sync-test-result err'
        out.textContent = '✗ ' + (e && e.message || e)
      } finally {
        // R115 — the state-reset law: the button comes back EXACTLY as it
        // was, on every path — success, typed failure, or interruption. No
        // connect flow anywhere requires a reload to retry.
        connectBtn.disabled = false
        connectBtn.textContent = connectLabel
      }
    }
    if (gdriveVerifyBtn) gdriveVerifyBtn.onclick = async () => {
      const out = gdriveVerifyOut
      out.className = 'sync-test-result'
      out.textContent = getMessage('twGdriveVerifying', undefined, 'Verifying stage by stage…')
      // R91 §2.1 (S-C): the mode comes from the REAL select — the old input
      // selector could never see it, so Bridge verification verified the
      // wrong mode.
      const mode = readAuthMode()
      try {
        const stages = await bgSend('TRANSPORT_GDRIVE_VERIFY', { config: collectTransportConfig(), mode })
        out.textContent = ''
        for (const st of (stages && stages.stages) || []) {
          const line = document.createElement('div')
          line.textContent = (st.ok ? '✓ ' : '✗ ') + '[' + st.stage + '] ' + st.message
          // R92 §1.4: a version-stage WARNING row (stale deployed script) is
          // truthfully styled as a warning, not an error.
          line.style.color = st.ok ? (st.warning ? 'var(--ucrypt-warn, #b45309)' : 'var(--ucrypt-ok, #2e7d32)') : 'var(--ucrypt-err, #c62828)'
          out.appendChild(line)
          // R92 §1.4 — URL AUTO-CORRECT: a /edit or /dev paste offers the
          // corrected /exec URL as a ONE-CLICK fix (fills the scriptUrl
          // field, re-runs the groups, and re-verifies).
          if (st.correctedUrl) {
            const fixRow = document.createElement('div')
            fixRow.style.marginTop = '4px'
            const fixBtn = document.createElement('button')
            fixBtn.type = 'button'
            fixBtn.className = 'btn btn-outline btn-sm'
            fixBtn.textContent = getMessage('twUseCorrectedUrl', undefined, 'Use corrected URL')
            fixBtn.addEventListener('click', () => {
              const urlInput = document.querySelector('#twFields input[data-field-key="scriptUrl"]')
              if (urlInput) {
                urlInput.value = st.correctedUrl
                urlInput.dispatchEvent(new Event('input', { bubbles: true }))
              }
              fixRow.remove()
              if (gdriveVerifyBtn) gdriveVerifyBtn.click()
            })
            const fixText = document.createElement('span')
            fixText.textContent = ' ' + st.correctedUrl
            fixText.style.fontFamily = 'monospace'
            fixText.style.fontSize = '0.85em'
            fixText.style.userSelect = 'all'
            fixRow.appendChild(fixBtn)
            fixRow.appendChild(fixText)
            out.appendChild(fixRow)
          }
        }
        if (out.textContent === '') out.textContent = getMessage('twGdriveNoStages', undefined, 'Nothing to verify for this mode.')
      } catch (e) {
        out.textContent = '✗ ' + (e && e.message || e)
      }
    }
  } else {
    if (gdriveActions) gdriveActions.classList.add('hidden')
    scriptBox.classList.add('hidden')
  }

  // R119 §1 (law 0.32, order §3.5) — THE LADDER BLOCK: the rungs render
  // ABOVE the guided fields, in order — Fast (ONLY when the platform and
  // the shared client IDs allow it; absence renders nothing — §3.7 the
  // graceful absence), Guided (always), Manual (always, demoted). One
  // click per rung switch; each rung's button focuses its surface.
  const ladderHost = $('twLadder')
  if (ladderHost) {
    if (['gdrive', 'github', 'dropbox'].includes(transportId)) {
      // R178 — R-178.5 ONE MINT, ONE CLOCK, ONE FLOW: the ladder ctx is held
      // in a named const so the completion side-effect can RE-RENDER the
      // block with a FRESH custody era — a mint that landed mid-frame (the
      // CTA press inside the wizard) used to leave the panel's era line
      // speaking the open-time snapshot while the ✓ card and the header
      // spoke the new mint — the twin clocks of E-42 in one frame. The
      // re-render derives the era from the RECORD once, at the same instant
      // as the header's info — one frame, one clock.
      const ladderCtx = {
        host: ladderHost,
        transportId,
        transport: t,
        transportName: tName,
        // R177 — R-177.1/R-177.3: the RECORD's custody facts ride the panel
        // (lock-independent, page-side) — the Fast panel speaks the connected
        // era where the CTA lives; no state-blind first-run face over a
        // living bank. Values never ride — booleans, instants, the clock.
        custodyEra: custody,
        collectConfig: () => collectTransportConfig(),
        // R172 — THE PURE-PANEL SEAMS (R-172.4): each panel's own buttons act
        // through the SAME single test/save doors (one machinery, many
        // panels — never a second implementation), and the Cancel closes the
        // panel it lives in. The rows render into #twResult (the shared
        // result line) so the words live where the press landed.
        testConnection: (outEl) => { testCurrentTransport(outEl).catch(() => {}) },
        saveTransport: () => saveCurrentTransport(),
        cancelPanel: (panel) => {
          try { if (panel && panel.open !== undefined) panel.open = false } catch { /* best-effort */ }
        },
        // R120 (law 0.33) — the fast CTA's COMMIT seam: the switch plan runs
        // against the stored record first (the prior rung's material cleaned
        // out of the wizard's fields AND out of this config — the stale
        // prefill never reaches the sealed envelope), then the existing
        // TRANSPORT_SAVE replaces the envelope wholesale with the new rung's
        // record. Same rung: the plan refuses — the save rides unchanged.
        persist: async (config) => {
          await beginRungSwitch(transportId, String((config && config.signinMode) || 'fast'), { config })
          if (config && (config.authMode === 'fast' || config.signinMode === 'fast')) {
            wizardFastPrefill = { ...config }
          }
          const saveRes = await bgSend('TRANSPORT_SAVE', { transportId, config })
          if (saveRes && saveRes.ok && config && (config.authMode === 'fast' || config.signinMode === 'fast')) {
            wizardFastPrefill = { ...config }
          }
          return saveRes
        },
        onConfigured: async (info = null) => {
          // the completion side-effects mirror saveCurrentTransport's —
          // the grid re-renders state-aware, the checklist flips, the
          // header chip speaks the new rung ("configured · fast sign-in").
          renderTransportGrid(transportId)
          refreshSync()
          refreshChecklist()
          try { renderCloudBackupBlock().catch(() => {}) } catch { /* best-effort */ }
          try {
            const infoEarly = await transportStateInfo()
            const headState = $('twHeaderState')
            if (headState) {
              const stLine = transportStateLine(t, infoEarly)
              headState.textContent = stLine.text
              headState.classList.remove('hidden')
            }
          } catch { /* the chip refresh is best-effort */ }
          // R178 — R-178.5 THE ONE-CLOCK RE-RENDER: the era is re-derived
          // from the RECORD at the same instant as the header's info, and
          // the ladder block re-renders with it — the panel's connected-era
          // line and the header's mint-era line can never disagree again
          // (the frame speaks ONE custody, ONE clock).
          try {
            const gNow = await bgSend('TRANSPORT_GET').catch(() => null)
            const unlockedCfg = (gNow && gNow.ok && !gNow.locked && gNow.config && typeof gNow.config === 'object') ? gNow.config : null
            const recNow = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
            const activeCfg = unlockedCfg || (recNow && recNow.id === transportId && recNow.config ? recNow.config : null)
            if (activeCfg && (activeCfg.authMode === 'fast' || activeCfg.signinMode === 'fast')) {
              wizardFastPrefill = { ...activeCfg, authMode: 'fast', signinMode: 'fast', persistentSession: true }
              const modeSelect = document.querySelector('#twFields select[data-field-key="authMode"]')
              if (modeSelect) {
                if (!Array.from(modeSelect.options).some((o) => o.value === 'fast')) {
                  const fastOpt = document.createElement('option')
                  fastOpt.value = 'fast'
                  fastOpt.textContent = 'Fast — one-click sign-in (persistent)'
                  modeSelect.insertBefore(fastOpt, modeSelect.firstChild)
                }
                modeSelect.value = 'fast'
              }
            }
            const freshEra = deriveRecordCustody(
              recNow && recNow.id === transportId ? recNow : null,
              transportId,
              true
            )
            if (freshEra) renderLadderBlock({ ...ladderCtx, custodyEra: freshEra })
          } catch { /* the era re-render is best-effort — the open-time era stays honest */ }
          // R179 — Explicit user return (toast + wizard result banner) with automatic sync outcome:
          try {
            const autoSync = (info && info.autoSync && typeof info.autoSync === 'object') ? info.autoSync : null
            const syncMsg = (autoSync && autoSync.detail) ? ` — ${autoSync.detail}` : ''
            const okBanner = `✓ Connected to ${tName} (one-click sign-in)${syncMsg}`
            toast(okBanner, 'ok')
            const resEl = $('twResult')
            if (resEl) {
              resEl.hidden = false
              resEl.className = 'sync-test-result ok'
              resEl.textContent = okBanner
            }
          } catch { /* best-effort */ }
        },
        onConnectFailed: (failInfo = null) => {
          try {
            const detail = String((failInfo && failInfo.detail) || 'Sign-in did not complete — check the message below and try again.').slice(0, 220)
            const errBanner = `✗ ${tName} sign-in failed: ${detail}`
            toast(errBanner, 'error')
            const resEl = $('twResult')
            if (resEl) {
              resEl.hidden = false
              resEl.className = 'sync-test-result err'
              resEl.textContent = errBanner
            }
          } catch { /* best-effort */ }
        },
        goToGuided: () => focusWizardField(LADDER_GUIDED_FIELD[transportId] || 'clientId'),
        goManual: () => focusWizardField(LADDER_MANUAL_FIELD[transportId] || 'clientId'),
        openWalkthrough: () => openLadderWalkthrough(transportId),
      }
      renderLadderBlock(ladderCtx)
      ladderHost.classList.remove('hidden')
      // R172 — THE PURE-PANEL LAW (R-172.4, the E-27 cure): the ladder
      // transports' panels each carry their own button set — the GLOBAL
      // bottom row is retired for them (a second identical row outside the
      // panels was the contradiction the owner arrowed). The non-ladder
      // transports keep the global row (it IS their single panel's set).
      try { const ar = $('twActionsRow'); if (ar) { ar.classList.add('hidden'); ar.hidden = true } } catch { /* the row stays for others */ }
      wizardGlobalRowRetired = true
      // R170 §A3 — the alternative configuration's DEFAULT follows the fast
      // rung's presence (the settled-house law): collapsed when Fast is
      // available (the alternative is the fallback), expanded when Fast is
      // absent (the alternative becomes the primary). The persisted choice
      // rides the shared seam.
      try {
        const adv = $('twAdvancedConfig')
        if (adv) await SettledHouse.apply('tw-advanced-config', adv, ladderHost.dataset.fastAvailable !== '1')
      } catch { /* the default shape still applies */ }
    } else {
      ladderHost.innerHTML = ''
      ladderHost.classList.add('hidden')
      // R172 — the non-ladder transports keep the global row (their single
      // panel's set) — the retirement rides the ladder transports only.
      try { const ar = $('twActionsRow'); if (ar) { ar.classList.remove('hidden'); ar.hidden = false } } catch { /* best-effort */ }
      wizardGlobalRowRetired = false
      // R170 §A3 — no fast rung exists for this transport: the alternative
      // configuration IS the primary — it renders expanded by default.
      try {
        const adv = $('twAdvancedConfig')
        if (adv) await SettledHouse.apply('tw-advanced-config', adv, true)
      } catch { /* the default shape still applies */ }
    }
  }

  // R172 — THE ONE-OPEN ACCORDION, the Alternative panel's direction (the
  // same law, both ways): opening the Alternative setup closes the ladder
  // panels; opening a ladder panel closes this one (the ladder block's own
  // toggle handler does that side).
  try {
    const adv = $('twAdvancedConfig')
    if (adv) {
      adv.addEventListener('toggle', () => {
        if (!adv.open) return
        const ladderPanels = document.querySelectorAll('#twLadder details.settled-area')
        for (const sib of ladderPanels) { if (sib.open) { try { sib.open = false } catch { /* best-effort */ } } }
      })
    }
  } catch { /* best-effort — the accordion still rides the ladder side */ }

  // R117 §3 (law 0.30): the guided path anchors the SAME way — the setup
  // area lands at the top of the dialog's viewport, never half-off the fold.
  $('transportWizard').scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function collectTransportConfig() {
  const t = getTransport(currentTransportId)
  if (!t) return {}
  const config = {}
  for (const f of t.fields || []) {
    const input = document.querySelector(`#twFields input[data-field-key="${f.key}"]`)
    const select = document.querySelector(`#twFields select[data-field-key="${f.key}"]`)
    if (input) config[f.key] = input.value.trim()
    else if (select) config[f.key] = select.value.trim()
  }
  // R172 — THE FAST-PRESERVING COLLECT (the poison kill's second belt):
  // when the STORED record is a fast connection and the form's mode select
  // still reads 'fast' (the user changed nothing), the collected config
  // carries the stored fast material — the sealed custody (webToken /
  // refreshToken / lane / via / accountHint / signinMode) is NOT form
  // fields, and a collect that dropped them would destroy the connection
  // on a mere Save. The custody overlays the form; the record round-trips.
  // An explicit mode change (the select moved to oauth/bridge) skips this —
  // the rung-switch machinery owns that path.
  const formMode = String(config.authMode || '')
  const explicitBridge = formMode === 'bridge' || !!String(config.scriptUrl || '').trim()
  const explicitCustomClient = !!String(config.clientId || '').trim() &&
    wizardFastPrefill &&
    String(config.clientId || '').trim() !== String(wizardFastPrefill.clientId || '').trim()
  if (!explicitBridge && !explicitCustomClient && wizardFastPrefill && typeof wizardFastPrefill === 'object') {
    config.authMode = 'fast'
    config.signinMode = 'fast'
    config.persistentSession = true
    config.autoRenew = true
    for (const k of ['clientId', 'webToken', 'refreshToken', 'signinMode', 'lane', 'via', 'accountHint', 'persistentSession', 'autoRenew']) {
      if (wizardFastPrefill[k] !== undefined && wizardFastPrefill[k] !== null && !(k === 'clientId' && String(config.clientId || '').trim())) {
        config[k] = wizardFastPrefill[k]
      }
    }
  }
  return config
}

/** ── R128 §2 (law 0.42 — THE MODE-TRUTH LAW, the CEO's S1/S2 made law) ──
 * THE SAVE'S REQUIRED-SET FOLLOWS THE SELECTED MODE, never the union of all
 * modes' fields. The v2.84.0 save loop demanded EVERY `type:'url'` field no
 * matter the mode — so a Google Drive OAuth connect that had just landed
 * green ("Google grant received… press Save to seal it device-only") met a
 * red save demanding the bridge URL (the CEO's exact hit: "✗ 'Apps Script
 * Web App URL (Advanced — bridge fallback)' is required"). A green connect
 * followed by a red save is a self-contradiction — a P1 by definition.
 *
 * PURE (battery-pinned as a class across every transport's save path):
 *  - a field is demanded at save only if it is a required-by-shape url field
 *    (the legacy rule) that is NOT marked optional and NOT mode-scoped to
 *    the mode that is not selected;
 *  - a mode-scoped field (bridgeField / oauthField) is demanded only when
 *    its own mode is the form's active mode (gdrive: config.authMode —
 *    'oauth' is the field default, so an empty select reads oauth);
 *  - an explicitly-optional field (github/dropbox apiBase — the labels and
 *    help have said "advanced, optional" since birth) is NEVER demanded.
 * The invariant: the save succeeds the moment the connect succeeded —
 * green connect → green save. */
function fieldDemandedAtSave(f, config) {
  if (!f || f.type !== 'url') return false // the legacy demand was url-shaped fields only
  if (f.optional) return false // labeled optional → never demanded (0.42: no union demands)
  const mode = String((config && config.authMode) || '').trim() || 'oauth'
  if (f.bridgeField && mode !== 'bridge') return false // the bridge field rides bridge mode ONLY
  if (f.oauthField && mode === 'bridge') return false // an oauth-scoped url is not a bridge demand
  return true
}

/** ── R116 §2.1/§2.2 (law 0.29; the CEO's S2) — THE TYPED RECOVERY CARD AT
 *  THE WORDS: when a test/save response carries a typed recovery card, it
 *  renders RIGHT HERE under the ✗ line — the title, the causes, the fix
 *  (the owner's two-sentence checklist for a disabled client), and the
 *  one-click buttons (the Cloud Console deep link as the PRIMARY; the
 *  reconnect as the demoted secondary). The fix lives where the words
 *  live — never in another tab, never memory-only.
 */
function renderTypedRecoveryCard(host, recovery, { onReconnect } = {}) {
  if (!host || !recovery || typeof recovery !== 'object') return
  const card = document.createElement('div')
  card.className = 'device-add-box'
  card.style.cssText = 'margin:8px 0 0'
  const title = document.createElement('strong')
  title.textContent = recovery.title || ''
  card.appendChild(title)
  if (Array.isArray(recovery.causes) && recovery.causes.length) {
    const ul = document.createElement('ul')
    ul.style.cssText = 'margin:6px 0 6px 18px;padding:0'
    for (const c of recovery.causes) {
      const li = document.createElement('li')
      li.className = 'card-help'
      li.style.margin = '0 0 3px'
      li.textContent = String(c)
      ul.appendChild(li)
    }
    card.appendChild(ul)
  }
  if (recovery.fix) {
    const fix = document.createElement('p')
    fix.className = 'card-help'
    fix.style.cssText = 'margin:6px 0;white-space:pre-line'
    fix.textContent = String(recovery.fix)
    card.appendChild(fix)
  }
  const row = document.createElement('div')
  row.className = 'btn-row'
  row.style.margin = '6px 0 0'
  if (recovery.consoleUrl) {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'btn btn-primary btn-sm'
    b.textContent = getMessage('attnActionConsole', undefined, 'Open Google Cloud Console')
    b.addEventListener('click', () => { try { chrome.tabs.create({ url: recovery.consoleUrl }) } catch { /* the card stays */ } })
    row.appendChild(b)
  }
  if (typeof onReconnect === 'function') {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'btn btn-outline btn-sm'
    b.textContent = getMessage('attnActionReconnect', undefined, 'Reconnect Google Drive…')
    b.addEventListener('click', onReconnect)
    row.appendChild(b)
  }
  if (row.children.length) card.appendChild(row)
  host.appendChild(card)
}

/** The reconnect one-click behind the card's secondary button: lands in the
 * wizard with the provider's Connect button in reach (edit mode), then
 * offers the click (the wizard's own state machine owns the rest).
 * R153 §5 (Z-2/G118) — THE RECONNECT IS NEVER SILENT: the click opens the
 * wizard in EDIT mode, scrolls it into view, and focuses the Connect
 * control; every failure path renders a typed line — the cure is one click
 * away, never a dead button (LAW #89 family). When the one-click heal
 * cannot run mechanically (a human-input class), the wizard lands on the
 * Edit-setup fields scrolled + focused — the offending field is the first
 * thing on screen. */
function reconnectViaWizard(transportId) {
  let opened = false
  try {
    const t = getTransport(transportId)
    if (!t) throw new Error(`no transport ${String(transportId)} to reconnect`)
    wizardEditMode = true
    wizardEditTransport = transportId // R153: hold EDIT mode across the open (the open resets it per transport)
    openTransportWizard(transportId)
    opened = true
  } catch {
    try {
      const res = $('twResult')
      if (res) {
        res.className = 'sync-test-result err'
        res.textContent = getMessage('attnReconnectFail', undefined, 'The reconnect could not open the setup — use "Edit setup" below; your data was not touched.')
      }
    } catch { /* the card stays */ }
  }
  setTimeout(() => {
    try {
      const wiz = $('transportWizard')
      if (wiz) {
        wiz.classList.remove('hidden')
        try { wiz.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* the open is the signal */ }
      }
      const cb = $('twGdriveConnectBtn')
      if (cb && !cb.disabled) { cb.click(); return }
      // The human-input class: land on the fields themselves (Edit setup).
      const edit = $('tsEditBtn')
      if (edit) {
        try { edit.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* the scroll is the signal */ }
        try { edit.focus({ preventScroll: true }) } catch { try { edit.focus() } catch { /* the scroll is the signal */ } }
      }
      if (!opened) {
        const res2 = $('twResult')
        if (res2 && !res2.textContent) {
          res2.className = 'sync-test-result warn'
          res2.textContent = getMessage('attnReconnectLanded', undefined, 'Edit the setup fields below and save — the connection heals on the next test.')
        }
      }
    } catch { /* the wizard owns its state */ }
  }, 120)
}

async function testCurrentTransport(outEl, opts = null) {
  const el = outEl || $('twResult')
  // R175 — THE LIVING AFFORDANCE (R-175.4): the verdict seat must be VISIBLE
  // — a seat that starts hidden (the Cloud backup card's own test paragraph)
  // unhides the moment the journey starts. A referenced affordance ANSWERS.
  el.hidden = false
  el.className = 'sync-test-result'
  el.textContent = getMessage('twTesting', undefined, 'Testing…')
  try {
    // v2.12.0 — the test runs in the BACKGROUND WORKER (TRANSPORT_TEST), not
    // in this page. Real Chromium enforces the extension page CSP
    // (connect-src 'self' https:), so an in-page fetch cannot reach plain-
    // http:// endpoints — a LAN WebDAV or self-hosted custom URL reported
    // "✗ Failed to fetch" even though actual pushes (which run in the worker)
    // reach it fine. Testing where we fly = the test tells the truth.
    // R90 §1.1 — while the summary is showing, the FIELDS are hidden, so the
    // config comes from the WORKER's stored copy (TRANSPORT_GET), never from
    // the empty form. collectTransportConfig() is only used in edit mode.
    // F-R91-TESTFORM (P1, found LIVE by the R91 matrix): a FRESH guided
    // setup is not in the worker yet — the FORM is the only config there
    // is. The pre-R91 logic skipped the form on every non-edit-mode test, so
    // the very first "Test connection" of a first-time setup always failed
    // with "no url configured" (the stored config is empty until Save). The
    // form values are used whenever the form holds any; the stored copy is
    // the fallback (summary mode / locked, where the form is truthfully
    // empty).
    let config
    const wizEl = $('transportWizard')
    const wizardOpen = !!(wizEl && !wizEl.classList.contains('hidden') && !wizEl.hidden)
    const formConfig = wizardOpen ? collectTransportConfig() : {}
    const hasFormValues = wizardOpen && Object.values(formConfig).some((v) => String(v || '').trim() !== '')
    // R171 — THE TRANSPORT-TRUTH LAW (the E-23 cure, seat half): a test that
    // does not ride the OPEN WIZARD never trusts the form — the wizard's
    // fields exist only when the wizard is open; a force-set wizardEditMode
    // outside it used to ride a hollow form config, and the gdrive transport
    // answered with the BRIDGE class's words ("Add your Apps Script Web App
    // URL first") to an OAuth-connected user. The attention seats pass
    // { formForbidden: true }: the STORED config (the worker's opened copy)
    // answers — the ACTIVE transport's health is what gets tested.
    if (!(opts && opts.formForbidden) && wizardOpen && (wizardEditMode || hasFormValues)) config = formConfig
    else {
      try {
        const g = await bgSend('TRANSPORT_GET')
        config = (g && g.ok && !g.locked && g.config) || undefined
      } catch { /* fall through — the worker re-reads stored secrets itself */ }
    }
    // R176 — R-176.1c + R-176.2 AT THE TEST DOOR (the map's Adjudication 1.3
    // cure — the split reader): the form-first rule keeps its guided-setup
    // purpose (testing a mid-edit paste before saving) but NEVER blinds the
    // custody. The fields the form structurally cannot carry (webToken, the
    // lane/via/accountHint evidence) — and any custody field the form left
    // empty — merge from the STORED record (the one bank, opened worker-side)
    // before any token leg.
    // R179 — Fix stale wizardFastPrefill.webToken overwriting a freshly signed-in
    // stored.webToken: always prefer stored.webToken whenever its expiration is
    // newer than or equal to config.webToken's expiration, and refresh wizardFastPrefill.
    if (config && typeof config === 'object') {
      try {
        const g2 = await bgSend('TRANSPORT_GET').catch(() => null)
        const rawRec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY] || null
        const stored = (g2 && g2.ok && !g2.locked && g2.config)
          ? g2.config
          : ((rawRec && rawRec.config && typeof rawRec.config === 'object') ? rawRec.config : null)
        if (stored && typeof stored === 'object') {
          const custodyKeys = ['webToken', 'authMode', 'signinMode', 'lane', 'via', 'accountHint', 'refreshToken', 'clientId', 'persistentSession', 'autoRenew']
          const storedIsFast = stored.authMode === 'fast' || stored.signinMode === 'fast' || !!(stored.webToken && stored.webToken.token)
          const explicitBridge = config.authMode === 'bridge' || !!String(config.scriptUrl || '').trim()
          const explicitCustomClient = !!String(config.clientId || '').trim() && String(config.clientId || '').trim() !== String(stored.clientId || '').trim()
          for (const k of custodyKeys) {
            const cur = config[k]
            if (k === 'webToken') {
              const sWt = stored.webToken && typeof stored.webToken === 'object' ? stored.webToken : null
              const cWt = cur && typeof cur === 'object' ? cur : null
              if (sWt && String(sWt.token || '').trim()) {
                const sExp = Number(sWt.exp) || 0
                const cExp = (cWt && String(cWt.token || '').trim()) ? (Number(cWt.exp) || 0) : 0
                if (!cWt || !String(cWt.token || '').trim() || sExp >= cExp) {
                  config.webToken = sWt
                  if (wizardFastPrefill && typeof wizardFastPrefill === 'object') wizardFastPrefill.webToken = sWt
                }
              }
              continue
            }
            if ((k === 'authMode' || k === 'signinMode') && storedIsFast && !explicitBridge && !explicitCustomClient) {
              config[k] = 'fast'
              continue
            }
            const empty = cur === undefined || cur === null || cur === ''
            if (empty && stored[k] !== undefined && stored[k] !== null && stored[k] !== '') config[k] = stored[k]
          }
        }
      } catch { /* the stored custody is best-effort — the worker re-reads it anyway */ }
    }
    // R177 — R-177.2/R-177.3 THE ONE CUSTODY ID AT THE TEST DOOR: the id is
    // resolved from THE RECORD (the one custody seat) whenever no wizard
    // context names one. The field's E-39 lie — "Unknown transport: null"
    // beside a connected chip in the SAME frame — rode exactly this hole: the
    // card's Test (pressed outside any wizard open) sent the page-session
    // initial `currentTransportId` (null — options.js:1304) and the worker's
    // registry answered with the alien-config wall while the SAME frame's
    // header read the RECORD and spoke "One-click sign-in (Fast)". A page
    // variable may only NARROW the test to the transport it names (the
    // mid-edit form test, F-R91-TESTFORM byte-true); a stale or null variable
    // never overrides the record. The writer-side single-writer inventory
    // lives in docs/R177-CUSTODY-THAT-SURVIVES-MAP.md (Adjudication 1: all
    // eight writer seats preserve the id — the pointer never dies at rest).
    let testTransportId = currentTransportId
    if (!testTransportId) {
      try {
        const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
        if (rec && typeof rec.id === 'string' && rec.id) testTransportId = rec.id
      } catch { /* the record read never blocks the test — the variable stands */ }
    }
    const r = await bgSend('TRANSPORT_TEST', {
      transportId: testTransportId,
      ...(config ? { config } : {}),
    })
    if (r && r.ok) {
      el.className = 'sync-test-result ok'
      el.textContent = '✓ ' + (r.message || getMessage('twTestOk', undefined, 'Server reachable'))
      // R90 §1.1 — the summary's ledger line updates in place after a test.
      if (el === $('tsResult')) {
        try {
          const lt = (await chrome.storage.local.get('ucrypt:lastTest'))['ucrypt:lastTest']
          if (lt) $('tsLastTest').textContent = ledgerLine(lt, 'tsNeverTested', 'Never tested — press Test connection')
        } catch { /* ledger refresh is best-effort */ }
      }
    } else {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + materializeUserText((r && r.error) || getMessage('twTestFail', undefined, 'Connection failed — check the URL, user and password, then press Test again.'))
      // R116 §2.1 (the CEO's S2, law 0.29) — the typed card renders at the
      // words: the disabled client carries its own checklist + the console
      // deep link, never the bare engine line alone.
      // R177 — R-177.3: the reconnect affordance rides the RESOLVED id (the
      // record's custody), never the stale page variable — the road home
      // cannot repeat the reader lie that raised the card.
      if (r && r.recovery) renderTypedRecoveryCard(el, r.recovery, { onReconnect: () => reconnectViaWizard(testTransportId || currentTransportId) })
      if (el === $('tsResult')) {
        try {
          const lt = (await chrome.storage.local.get('ucrypt:lastTest'))['ucrypt:lastTest']
          if (lt) $('tsLastTest').textContent = ledgerLine(lt, 'tsNeverTested', 'Never tested — press Test connection')
        } catch { /* ledger refresh is best-effort */ }
      }
    }
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + materializeUserText(e)
    // R116 §2.1 — a thrown SyncError can also carry the card (the refresh
    // path's recovery rides the error object); render it at the words.
    // R177 — R-177.3: the resolved id rides the reconnect here too.
    if (e && e.recovery) renderTypedRecoveryCard(el, e.recovery, { onReconnect: () => reconnectViaWizard(testTransportId || currentTransportId) })
  }
}

// ── R120 (law 0.33) — THE RUNG-LIFECYCLE WIRING ──────────────────────────
//
// LAW 0.33 THE RUNG-LIFECYCLE LAW: a connection's rung is switchable at any
// time, and every switch cleans the prior rung's state completely — no orphan
// tokens, no half-grants, no stale refresh timers; the disconnect per rung
// clears exactly that rung's material; the card's state line always tells
// the truth about which rung is live.
//
// The PURE plan lives in lib/ladder.js (planRungSwitch — key NAMES and
// material CLASSES only, never a value: law 0.14). THIS side executes it
// through the seams that already exist:
//   - the wizard's own field inputs (the exact surface saveCurrentTransport's
//     collectTransportConfig reads — clearing what the PRIOR rung put there,
//     while what the user typed for the NEW rung stays), and
//   - the passed fast-connect config (scrubbed of the prior rung's stale
//     prefill BEFORE TRANSPORT_SAVE replaces the stored envelope wholesale),
//   - the evidence ring (recordRing — the same import path ladder-ui.js's
//     rungRingRecord rows use), as { stage: 'rung-switch', from -> to }.
// No new transport path exists here: the NEW rung's own flow (the transports'
// connect methods / the guided connect) starts after the cleanup, and the
// Disconnect button's TRANSPORT_CLEAR remains the whole-record seam.
//
// The gdrive fast bearer lives in Chrome's own token cache — UCrypt never
// stored it, so no UCrypt step can or must drop it; the plan names the
// material class ('chrome-token-cache') and this executor leaves it browser-
// managed (the accessor stops using it the moment the mode changes).

/** The stored record, raw (sealed values stay sealed — PRESENCE is enough
 *  for the rung material; the plan never reads a value, only key names). */
async function storedTransportRecordRaw() {
  try {
    return (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY] || null
  } catch { return null }
}

/** One drop-field step, executed on the wizard's own fields: the field is
 *  cleared ONLY when it still holds what the PRIOR rung put there (the
 *  stored value) — what the user typed for the NEW rung is the new rung's
 *  material and stays. Returns true when a field was actually cleared. */
function clearWizardFieldForSwitch(transportId, key, storedConfig) {
  try {
    const storedVal = String((storedConfig && storedConfig[key] != null) ? storedConfig[key] : '')
    const input = document.querySelector(`#twFields input[data-field-key="${key}"]`)
    if (input) {
      if (String(input.value != null ? input.value : '') !== storedVal) return false
      input.value = ''
      input.dispatchEvent(new Event('input', { bubbles: true }))
      return true
    }
    const select = document.querySelector(`#twFields select[data-field-key="${key}"]`)
    if (select) {
      if (String(select.value != null ? select.value : '') !== storedVal) return false
      const f = (((getTransport(transportId) || {}).fields) || []).find((x) => x && x.key === key)
      select.value = (f && f.default) ? String(f.default) : ''
      select.dispatchEvent(new Event('input', { bubbles: true }))
      select.dispatchEvent(new Event('change', { bubbles: true }))
      return true
    }
  } catch { /* best-effort — the sealed save still replaces the envelope */ }
  return false
}

/**
 * Plan + execute one rung switch (law 0.33). Reads the stored record, asks
 * lib/ladder.js's planRungSwitch for the typed plan, cleans the prior rung's
 * material through the existing seams, and records the switch on the ring.
 * A refused plan (same-rung / unknown-mode / no-live-rung) is a NO-OP —
 * every caller's old path stays byte-identical when no switch happened.
 * @param {string} transportId
 * @param {string} toMode the rung the caller is about to start
 * @param {{ config?: object }} [opts] the config object the caller will save
 *        (the fast CTA's commit) — scrubbed of the prior rung's stale prefill
 * @returns {Promise<{ switched: boolean, plan: object, cleared: number }>}
 */
async function beginRungSwitch(transportId, toMode, opts = {}) {
  const stored = await storedTransportRecordRaw()
  const fromMode = stored ? describeRungState(stored) : 'none'
  const plan = planRungSwitch(fromMode, toMode, stored)
  if (!plan.ok) return { switched: false, plan, cleared: 0 }
  const cfg = (stored && stored.config && typeof stored.config === 'object') ? stored.config : {}
  const liveConfig = (opts && opts.config) || null
  let cleared = 0
  for (const step of plan.cleanup) {
    if (!step || step.kind !== 'drop-field' || !step.key) continue
    if (clearWizardFieldForSwitch(transportId, step.key, cfg)) cleared++
    if (liveConfig && Object.prototype.hasOwnProperty.call(liveConfig, step.key)) {
      // the stale prefill rides the collected config — drop it before the
      // seal; a value the NEW flow just wrote (≠ the stored one) stays
      if (String(liveConfig[step.key] != null ? liveConfig[step.key] : '') === String(cfg[step.key] != null ? cfg[step.key] : '')) {
        try { delete liveConfig[step.key] } catch { /* the seal re-collects clean */ }
      }
    }
  }
  try {
    recordRing({
      flow: 'connect',
      transport: String(transportId || ''),
      stage: 'rung-switch',
      rung: plan.to,
      outcome: 'ok',
      httpKind: 'ladder',
      message: `the rung switched: ${plan.from} -> ${plan.to} (${plan.cleanup.length} material step(s), ${cleared} wizard field(s) cleared)`,
    }).catch(() => {})
  } catch { /* the ring never throws into its caller */ }
  return { switched: true, plan, cleared }
}

/** R119 (law 0.32) — the stored rung record, read from the SEALED record
 *  (signinMode is non-secret and rides the envelope plaintext). */
async function storedSigninModeAsync() {
  try {
    const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
    return String((rec && rec.config && rec.config.signinMode) || '')
  } catch { return '' }
}

async function saveCurrentTransport() {
  const el = $('twResult')
  el.className = 'sync-test-result'
  // R120 (law 0.33) — THE SWITCH AT THE COMMIT: the save is where a
  // form-driven rung change lands (an authMode flip to the Bridge, a pasted
  // PAT over a guided grant). The audit runs BEFORE the collection: when the
  // form is about to seal a DIFFERENT rung than the stored one, the prior
  // rung's material is cleaned out of the wizard's fields first, the switch
  // lands in the ring, and the collection below seals the CLEANED form.
  // Same rung / no prior rung: the plan refuses — everything below resolves
  // exactly as before (the old lines byte-identical when no switch happened).
  let rungSwitchedTo = ''
  if (['gdrive', 'github', 'dropbox'].includes(currentTransportId)) {
    const preConfig = collectTransportConfig()
    const toMode = describeRungState({
      id: currentTransportId,
      config: isSigninMode(wizardSigninMode) ? { ...preConfig, signinMode: wizardSigninMode } : preConfig,
    })
    const sw = await beginRungSwitch(currentTransportId, toMode)
    if (sw.switched) rungSwitchedTo = sw.plan.to
  }
  const config = collectTransportConfig()
  const t = getTransport(currentTransportId)
  const tName = transportName(t.id, t.name) // R28-i18n: localized transport name
  // R119 (law 0.32) — THE RUNG RECORD rides the save: a fast/guided connect
  // in THIS session names its rung; otherwise the stored mode is preserved
  // (a re-save never silently demotes a connection); a first manual/PAT
  // save records 'manual'. Ladder transports only — WebDAV/Custom are
  // untouched by the ladder.
  if (['gdrive', 'github', 'dropbox'].includes(currentTransportId)) {
    // R120 (law 0.33) — a COMMITTED switch is the session's LATEST rung
    // event, so its rung outranks the session's earlier connect record (a
    // connect followed by a Bridge flip names 'manual', never the stale
    // 'guided'); with rungSwitchedTo empty (no switch) the expression
    // resolves exactly as R119 left it (a re-save never silently demotes).
    let mode = rungSwitchedTo || wizardSigninMode || await storedSigninModeAsync()
    if (!isSigninMode(mode)) mode = 'manual'
    config.signinMode = mode
  }
  // R128 §2 (law 0.42 — THE MODE-TRUTH LAW): the demand below is MODE-AWARE.
  // The v2.84.0 loop demanded every `type:'url'` field — an OAuth connect
  // followed by a red bridge-URL demand (the CEO's S1, his flow's last
  // product-side blocker). The form's required-fields follow the selected
  // connection type, never the union of all types' fields.
  for (const f of t.fields || []) {
    if (!fieldDemandedAtSave(f, config) || config[f.key]) continue
    // R170 §A3 — the fire exception: a missing required field is an active
    // error whose seat lives inside the collapsed configuration — the area
    // auto-opens so the named field is visible where the words point.
    try { const adv = $('twAdvancedConfig'); if (adv && !adv.open) { adv.open = true; adv.setAttribute('data-fire-revealed', 'true') } } catch { /* the error still paints */ }
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + getMessage('twFieldRequired', [f.label], `"${f.label}" is required`)
    return
  }
  // R45-A §2.3: the save routes through the WORKER, which seals every secret
  // field into its credential envelope before anything touches storage. The
  // old direct write stored tokens/passwords in PLAINTEXT (R45 audit finding).
  // While locked the worker refuses — surface the truthful locked message.
  let saveResult = null
  try {
    const r = await bgSend('TRANSPORT_SAVE', { transportId: currentTransportId, config })
    saveResult = r || null
    if (!r || !r.ok) {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + ((r && r.error) || getMessage('twTestFail', undefined, 'Could not save the transport'))
      try { toast(el.textContent, 'error') } catch { /* best-effort */ }
      // R116 §2.1 (law 0.29) — the typed card at the words on the save path.
      if (r && r.recovery) renderTypedRecoveryCard(el, r.recovery, { onReconnect: () => reconnectViaWizard(currentTransportId) })
      return
    }
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
    try { toast(el.textContent, 'error') } catch { /* best-effort */ }
    if (e && e.recovery) renderTypedRecoveryCard(el, e.recovery, { onReconnect: () => reconnectViaWizard(currentTransportId) })
    return
  }
  if (config && (config.authMode === 'fast' || config.signinMode === 'fast')) {
    wizardFastPrefill = { ...config }
  }
  el.className = 'sync-test-result ok'
  // v2.8.0 — be explicit about what happens next and what is still missing.
  const hasCode = await bgSend('SYNC_KDF_INFO')
  const codeReady = hasCode && hasCode.ok && hasCode.info && hasCode.info.hasSyncCode
  const autoSyncNote = (saveResult && saveResult.autoSync && saveResult.autoSync.detail)
    ? ` (${saveResult.autoSync.detail})`
    : ''
  el.textContent = '✓ ' + (codeReady
    ? getMessage('twSavedAuto', [tName], `${tName} saved. Every change you make (save, edit, delete, import) is pushed to it automatically — pulls happen at unlock, every 15 min, and on demand below.`) + autoSyncNote
    : getMessage('twSavedNoCode', [tName], `${tName} saved — but no sync code exists yet. Generate or restore your 24-word code above; without it there is no key to encrypt the vault for the cloud.`))
  try { toast(`✓ ${tName} saved${autoSyncNote}`, 'ok') } catch { /* best-effort */ }
  // R132 (the CEO's re-test screenshot 1): after a SUCCESSFUL save the layer
  // names its exit — Cancel becomes an affirmative CLOSE (the same handler:
  // both close the layer; the saved state just deserves the affirmative
  // word). Reset to "Cancel" on the next wizard open.
  try {
    const cancelBtn = $('twCancelBtn')
    if (cancelBtn) {
      cancelBtn.textContent = getMessage('twCloseBtn', undefined, 'Close')
      cancelBtn.classList.remove('btn-ghost')
      cancelBtn.classList.add('btn-outline')
    }
  } catch { /* the label paint never blocks the save */ }
  renderTransportGrid(currentTransportId)
  // R90 §1.1 — the transport is now (re)configured: the next open of this
  // card renders the live summary, never the guided setup again.
  wizardEditMode = false
  refreshSync()
  try { renderCloudBackupBlock().catch(() => {}) } catch { /* best-effort */ }
  // R87 (§2.2): transport-configured completion signal — the checklist flips
  // step 3 in place (S6 state-truth law).
  refreshChecklist()
}

// --- Sync code UI ------------------------------------------------------------

let pendingSyncMnemonic = null

/** R170 §A5 (E-18) — THE SUCCESS VOICE: the sync-code dialog's typed success
 * card. What happened (the head), the proof (the proof line), the next step
 * (the static i18n line) — and the ONLY close is the user's own hand (law
 * 0.8: the dialog never closes itself). The toasts stay (additions-only);
 * this card is the persistent seat the owner asked for. */
function showSyncCodeSuccess({ headKey, headFallback, proof }) {
  const card = $('syncCodeSuccessCard')
  if (!card) return
  const head = $('syncSuccessHead')
  if (head) head.textContent = getMessage(headKey, undefined, headFallback)
  const proofEl = $('syncSuccessProof')
  if (proofEl) proofEl.textContent = proof || ''
  const nextEl = $('syncSuccessNext')
  if (nextEl) nextEl.textContent = getMessage('syncSuccessNext', undefined, 'Your vault is ready to sync. Keep the words safe (you copied them above); press Close when you are done.')
  card.classList.remove('hidden')
  card.hidden = false
}

async function showGeneratedSyncCode() {
  try {
    const code = await generateSyncCode()
    pendingSyncMnemonic = code.mnemonic
    const fingerprint = await syncFingerprint(code.mnemonic)
    const ol = $('syncCodeWords')
    ol.innerHTML = ''
    code.words.forEach((w, i) => {
      const li = document.createElement('li')
      li.innerHTML = `<span class="word-idx">${String(i + 1).padStart(2, '0')}</span>${w}`
      ol.appendChild(li)
    })
    $('syncFingerprint').textContent = fingerprint
    const qr = globalThis.QR ? globalThis.QR.encode(code.qrUri) : null
    if (qr) $('syncCodeQr').src = qr
    $('syncCodePanel').classList.remove('hidden')
    $('syncRestorePanel').classList.add('hidden')
  } catch (e) {
    toast(getMessage('toastGenCodeFailed', [e.message], 'Could not generate sync code: ' + e.message), 'error')
  }
}

async function confirmSyncCode() {
  if (!pendingSyncMnemonic) return
  try {
    const state = await bgSend('GET_STATE')
    if (!state?.ok || !state.state?.isUnlocked) {
      toast(getMessage('syncConfirmLocked', undefined, 'Unlock the vault first (Security tab), then confirm the sync code.'), 'error')
      return
    }
    // R170 §A5 — the fingerprint is captured BEFORE the panel hides: it is
    // the proof the success card shows (E-18: the completion names its proof).
    const fpProof = ($('syncFingerprint') && $('syncFingerprint').textContent) || '—'
    const r = await bgSend('SYNC_CODE_SET', { mnemonic: pendingSyncMnemonic, source: 'generate' })
    if (!r?.ok) throw new Error(r?.error || getMessage('syncSaveFailed', undefined, 'Failed to save sync code — try again; if it repeats, check your cloud transport.'))
    pendingSyncMnemonic = null
    $('syncCodePanel').classList.add('hidden')
    // v2.8.0 — the background now reports what actually happened:
    // a first device pushes its vault; a fresh device adopts the cloud copy.
    const res = r.result || {}
    if (res.pulled) {
      toast(getMessage('syncPulledToast', [String(res.entryCount || 0)], `Sync enabled — ${res.entryCount || 0} entr${res.entryCount === 1 ? 'y' : 'ies'} pulled from the cloud ✓`), 'info')
    } else {
      toast(getMessage('syncEnabledToast', undefined, 'Sync enabled — write those 24 words down!'), 'info')
    }
    // R170 §A5 (E-18) — the completion lands in the PERSISTENT success card:
    // what happened, the proof (the code fingerprint + the adopted count),
    // the next step, and the explicit Close (the ONLY closer — law 0.8).
    showSyncCodeSuccess({
      headKey: 'syncSuccessHeadGen',
      headFallback: '✓ Sync code saved — you\u2019re ready to sync',
      proof: res.pulled
        ? getMessage('syncSuccessProofGen', [fpProof, String(res.entryCount || 0)], `Proof: code fingerprint ${fpProof} · ${res.entryCount || 0} entries pulled from your cloud copy.`)
        : getMessage('syncSuccessProofGenOnly', [fpProof], `Proof: code fingerprint ${fpProof} — the words are stored encrypted with your master passphrase.`),
    })
    refreshSync()
    // R87 (§2.2): completion signal — the checklist re-reads live truth so
    // step 2 (code generated + wrote-it-down confirmed) flips to done NOW,
    // not after the next reload (the S6 stale-state bug).
    refreshChecklist()
  } catch (e) {
    toast(getMessage('syncEnableFailed', [e.message], 'Failed to enable sync: ' + e.message), 'error')
  }
}

async function validateRestore() {
  const el = $('syncRestoreResult')
  const mnemonic = $('syncRestoreWords').value
  el.className = 'sync-test-result'
  el.textContent = getMessage('syncValidating', undefined, 'Validating…')
  try {
    const result = await validateSyncCode(mnemonic)
    if (result.valid) {
      el.className = 'sync-test-result ok'
      const fp = await syncFingerprint(mnemonic)
      el.textContent = getMessage('syncValidOk', [fp], `✓ Valid 24-word code — fingerprint ${fp}`)
    } else {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + result.reason
    }
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
  }
}

async function restoreSyncCode() {
  const mnemonic = $('syncRestoreWords').value.trim()
  const el = $('syncRestoreResult')
  try {
    const result = await validateSyncCode(mnemonic)
    if (!result.valid) {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + result.reason
      return
    }
    const state = await bgSend('GET_STATE')
    if (!state?.ok || !state.state?.isUnlocked) {
      el.className = 'sync-test-result err'
      el.textContent = getMessage('syncRestoreLocked', undefined, '✗ Unlock the vault first (Security tab), then restore.')
      return
    }
    const r = await bgSend('SYNC_CODE_SET', { mnemonic, source: 'adopt' })
    if (!r?.ok) throw new Error(r?.error || getMessage('syncSaveFailed', undefined, 'Failed to save sync code — try again; if it repeats, check your cloud transport.'))
    // R170 §A5 — the fingerprint proof is computed while the words are still
    // in scope (the restore path's honest proof).
    const fpProofRestore = await syncFingerprint(mnemonic)
    $('syncRestorePanel').classList.add('hidden')
    $('syncRestoreWords').value = ''
    el.className = 'sync-test-result ok'
    // v2.8.0 — setSyncCode() PULLS BEFORE IT PUSHES now: an empty device
    // adopts the cloud copy instead of clobbering it. Report what happened.
    const res = r.result || {}
    if (res.pulled) {
      el.textContent = getMessage('syncRestored', [String(res.entryCount || 0)], `✓ Restored ${res.entryCount || 0} entr${res.entryCount === 1 ? 'y' : 'ies'} from your cloud sync.`)
      // R132 (law 0.46 — the join-propagation guidance): the same truth on
      // the restore path — the device's entry rides the next envelope.
      const prop = document.createElement('span')
      prop.className = 'card-help'
      prop.style.display = 'block'
      prop.style.marginTop = '6px'
      prop.textContent = getMessage('joinPropagationLine', undefined, 'Your device\u2019s name now travels to your other devices with the next sync — it appears in their “Your devices” list after one cycle (or one “Sync now” on that device).')
      el.appendChild(document.createElement('br'))
      el.appendChild(prop)
    } else {
      el.textContent = getMessage('syncSavedNoCloud', undefined, '✓ Sync code saved — nothing readable in the cloud yet. This device will push automatically once you add data.')
    }
    // R170 §A5 (E-18) — the restore's completion lands in the PERSISTENT
    // success card too: what happened, the proof, the next step, and the
    // explicit Close (the dialog never closes itself — law 0.8).
    showSyncCodeSuccess({
      headKey: 'syncSuccessHeadRestore',
      headFallback: '✓ Sync restored — your vault is back',
      proof: res.pulled
        ? getMessage('syncSuccessProofRestore', [String(res.entryCount || 0), fpProofRestore], `Proof: ${res.entryCount || 0} entries pulled from your cloud copy · code fingerprint ${fpProofRestore}.`)
        : getMessage('syncSuccessProofRestoreLocal', [fpProofRestore], `Proof: code fingerprint ${fpProofRestore} — saved on this device; nothing readable in the cloud yet.`),
    })
    await bgSend('SYNC_NOW')
    refreshSync()
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
  }
}

// ===========================================================================
// R56-SYNC-DEVICES — Sync & Devices state card + re-authenticated Add-device
// reveal (restoration of the lineage R49/R50 design, adapted to the CURRENT
// canonical security model: a master-passphrase re-entry verified by the
// worker — NO grant subsystem, NO persistence, NO roster, NO leave).
// ===========================================================================

const SECRET_EXPOSURE_MS = 60000 // visible countdown; the create flow's shown-once model is preserved
let _secretExposure = null
// R95 F-95-03 — the currently revealed pairing words + rendered carrier.
// Page memory only; dropped by the same exposure scrub that hides the words.
let _pairingWords = null
let _pairingUri = null

/**
 * Visible-countdown exposure policy (lineage R50 §5.2 port, single surface):
 * a countdown line + "Hide now" button; scrubbing clears the words DOM and
 * the QR image data; re-scrubs on pagehide and on tab-hidden. Fail-closed:
 * every scrub path clears BOTH surfaces.
 */
function startSecretExposure(spec) {
  const wordsEl = spec.wordsEl || null
  const qrEl = spec.qrEl || null
  const host = spec.host || document.body

  const line = document.createElement('div')
  line.className = 'secret-exposure-line'
  line.setAttribute('aria-live', 'polite')
  const label = document.createElement('span')
  const hideBtn = document.createElement('button')
  hideBtn.type = 'button'
  hideBtn.className = 'btn btn-ghost btn-sm'
  hideBtn.textContent = getMessage('secretHideNow', undefined, 'Hide now')
  line.appendChild(label)
  line.appendChild(hideBtn)
  host.insertBefore(line, host.firstChild)

  let remaining = Math.round(SECRET_EXPOSURE_MS / 1000)
  const paint = () => {
    label.textContent = getMessage('secretExposureCountdown', [String(remaining)], `Hidden in ${remaining} s`)
  }
  paint()

  const handle = { scrubbed: false, line }
  const scrub = (reason) => {
    if (handle.scrubbed) return
    handle.scrubbed = true
    clearInterval(timer)
    line.remove()
    if (wordsEl) { wordsEl.innerHTML = ''; wordsEl.hidden = true }
    if (qrEl) { qrEl.removeAttribute('src'); qrEl.hidden = true }
    document.removeEventListener('visibilitychange', onVis)
    window.removeEventListener('pagehide', onPageHide)
    if (spec.onScrub) spec.onScrub(reason)
  }
  const onVis = () => { if (document.hidden) scrub('hidden') }
  const onPageHide = () => scrub('pagehide')
  document.addEventListener('visibilitychange', onVis)
  window.addEventListener('pagehide', onPageHide)

  const timer = setInterval(() => {
    remaining--
    if (remaining <= 0) scrub('timeout')
    else paint()
  }, 1000)
  hideBtn.addEventListener('click', () => scrub('manual'))
  handle.scrub = scrub
  return handle
}

function scrubSecretExposure(reason) {
  if (_secretExposure) { _secretExposure.scrub(reason); _secretExposure = null }
}

// ===========================================================================
// R91 §3.5c (CEO S-E) — BACKUP-VERIFICATION STATE MACHINE.
// "created — backup not verified" must carry its completion path: one click
// opens the verify flow; a real verification act flips the state truthfully
// to "backup verified" and persists (device-local, survives recycle); the
// flag resets when the sync code changes (worker-side, SYNC_CODE_SET).
// No permanent unverified dead-end; no fake verified state.
// ===========================================================================
const BACKUP_VERIFY_KEY = 'ucrypt:backupVerified'

let bvPositions = []

function pickBvPositions() {
  // 4 of the 24 positions, drawn fresh each open — knowing 4 positional
  // words is not knowing the code, but HOLDING the written sheet is the
  // only realistic way to answer them.
  const pool = Array.from({ length: 24 }, (_, i) => i + 1)
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[pool[i], pool[j]] = [pool[j], pool[i]]
  }
  bvPositions = pool.slice(0, 4).sort((a, b) => a - b)
}

function renderBvInputs() {
  const host = $('bvWordInputs')
  if (!host) return
  host.innerHTML = ''
  for (const p of bvPositions) {
    const wrap = document.createElement('div')
    wrap.className = 'form-group'
    const lab = document.createElement('label')
    lab.textContent = getMessage('bvWordLabel', [String(p)], `Word #${p}`)
    lab.setAttribute('for', 'bv-word-' + p)
    const inp = document.createElement('input')
    inp.id = 'bv-word-' + p
    inp.type = 'text'
    inp.autocomplete = 'off'
    inp.spellcheck = false
    inp.dataset.pos = String(p)
    wrap.appendChild(lab)
    wrap.appendChild(inp)
    host.appendChild(wrap)
  }
}

function openBackupVerify() {
  const box = $('backupVerifyBox')
  if (!box) return
  pickBvPositions()
  renderBvInputs()
  const res = $('bvResult')
  if (res) { res.className = 'sync-test-result'; res.textContent = '' }
  box.classList.remove('hidden')
  box.hidden = false
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  const first = box.querySelector('input[data-pos]')
  if (first) first.focus()
}

async function submitBackupVerify() {
  const res = $('bvResult')
  const words = {}
  let filled = 0
  document.querySelectorAll('#bvWordInputs input[data-pos]').forEach((inp) => {
    const v = String(inp.value || '').trim().toLowerCase()
    words[inp.dataset.pos] = v
    if (v) filled++
  })
  if (filled < bvPositions.length) {
    if (res) { res.className = 'sync-test-result err'; res.textContent = '✗ ' + getMessage('bvFillAll', undefined, 'Type all four words from your offline copy.') }
    return
  }
  if (res) { res.className = 'sync-test-result'; res.textContent = getMessage('bvChecking', undefined, 'Checking…') }
  try {
    const r = await bgSend('SYNC_CODE_VERIFY_WORDS', { words })
    if (r && r.ok && r.verified) {
      if (res) { res.className = 'sync-test-result ok'; res.textContent = '✓ ' + getMessage('bvVerified', undefined, 'Backup verified — your offline copy matches the stored sync code.') }
      const kdf = await bgSend('SYNC_KDF_INFO')
      const state = await bgSend('GET_STATE')
      refreshSyncDevicesCard(state, kdf).catch(() => {})
    } else if (r && r.ok) {
      const bad = r.checks
        ? Object.entries(r.checks).filter(([, ok]) => !ok).map(([p]) => '#' + p).join(', ')
        : ''
      if (res) { res.className = 'sync-test-result err'; res.textContent = '✗ ' + getMessage('bvMismatch', [bad], `Not a match yet (word ${bad}). Check your written-down copy — the state stays honest until it verifies.`) }
    } else {
      if (res) { res.className = 'sync-test-result err'; res.textContent = '✗ ' + ((r && r.error) || 'Verification failed') }
    }
  } catch (e) {
    if (res) { res.className = 'sync-test-result err'; res.textContent = '✗ ' + (e && e.message || e) }
  }
}

/**
 * Param-less refresh for the verify flows: fetch the REAL state and re-render
 * the card (the state machine reads the fresh backupVerified flag).
 */
async function refreshSyncDevicesCardFresh() {
  const state = await bgSend('GET_STATE')
  const kdf = await bgSend('SYNC_KDF_INFO')
  await refreshSyncDevicesCard(state, kdf)
}

async function confirmBackupSheet() {
  try {
    const r = await bgSend('SYNC_CODE_BACKUP_CONFIRM', {})
    const btn = $('addDeviceConfirmBackupBtn')
    if (r && r.ok) {
      if (btn) { btn.classList.add('hidden'); btn.disabled = true }
      toast(getMessage('addDeviceConfirmDone', undefined, 'Backup confirmed — the state above is updated.'), 'info')
      await refreshSyncDevicesCardFresh()
    } else {
      toast(getMessage('addDeviceConfirmFailed', [(r && r.error) || 'unknown error'], `Could not confirm: ${(r && r.error) || 'unknown error'}`), 'error')
    }
  } catch (e) {
    toast(getMessage('addDeviceConfirmFailed', [e.message], `Could not confirm: ${e.message}`), 'error')
  }
}

/** ── R116 §2.3 (law 0.29; the CEO's S1/S3) — THE STRIP-LEVEL EXPANDER ───
 *  "Show more" lives ADJACENT to the generic attention words (never in
 *  another tab, never memory-only): one click opens the resolution box
 *  (the diagnosed cause + the fix buttons + the technical detail) right
 *  below the line, and re-diagnoses so the words are always fresh.
 *  The button is idempotent (created once, re-shown per render) and it
 *  hides itself whenever the card leaves the attention state.
 */
function attnShowMoreBtn() {
  let b = $('sdStateMoreBtn')
  if (!b) {
    b = document.createElement('button')
    b.id = 'sdStateMoreBtn'
    b.type = 'button'
    b.className = 'btn btn-outline btn-sm'
    b.style.cssText = 'margin-left:8px;vertical-align:middle'
    b.setAttribute('aria-expanded', 'false')
    b.setAttribute('aria-controls', 'sdAttentionHelp')
    b.addEventListener('click', () => {
      const attn = $('sdAttentionHelp')
      if (!attn) return
      const show = attn.classList.contains('hidden') || attn.hidden
      attn.classList.toggle('hidden', !show)
      attn.hidden = !show
      b.setAttribute('aria-expanded', show ? 'true' : 'false')
      if (show) {
        renderAttentionResolution().catch(() => {})
        attn.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }
    })
    const host = $('sdState') && $('sdState').parentElement
    if (host) host.appendChild(b)
  }
  return b
}
function ensureAttnShowMore() {
  const b = attnShowMoreBtn()
  if (!b) return
  b.classList.remove('hidden')
  b.hidden = false
  const attn = $('sdAttentionHelp')
  const open = !!(attn && !attn.classList.contains('hidden') && !attn.hidden)
  b.textContent = getMessage('sdStateMore', undefined, open ? 'Show less' : 'Show more')
  b.setAttribute('aria-expanded', open ? 'true' : 'false')
}
function hideAttnShowMore() {
  const b = $('sdStateMoreBtn')
  if (b) { b.classList.add('hidden'); b.hidden = true }
}

/** ── R116 §2.1 (the cause-class precision at the STRIP) ──────────────────
 *  The generic "Chain needs attention" line upgrades ITSELF with the
 *  specific cause once the diagnose answers: the disabled client names
 *  itself in the strip (with where the fix lives), the revoked grant
 *  names itself, the expired sign-in names itself. Sequence-guarded so a
 *  stale answer never overwrites a newer render.
 */
let _attnLineSeq = 0
async function applyAttentionSpecificLine(el) {
  const seq = ++_attnLineSeq
  let diag = null
  try { diag = await bgSend('SYNC_ATTN_DIAGNOSE') } catch { diag = null }
  if (seq !== _attnLineSeq || !el || !el.isConnected) return
  const cause = (diag && diag.ok && diag.cause) || 'unknown'
  // R140 §7.3 — the cause line never overwrites the PENDING copy: a specific
  // cause renders only under an evidence-backed attention verdict
  if (diag && diag.derived && diag.derived.verdict === 'pending') return
  if (cause === 'auth_disabled') {
    el.textContent = getMessage('sdStateAttentionDisabled', undefined, 'Chain needs attention — your Google OAuth client is disabled or in testing mode (the fix lives in the Cloud Console)')
  } else if (cause === 'recovered') {
    // R123 §2.2 — the truthful recovered line rides the strip too (BEFORE
    // the stale revoked verdict could win — the owner's S2 contradiction
    // never renders again).
    el.textContent = getMessage('sdStateRecovered', undefined, 'Reconnected — run Sync now to confirm the backup reads')
    el.style.color = 'var(--amber)'
  } else if (cause === 'auth_revoked') {
    el.textContent = getMessage('sdStateAttentionRevoked', undefined, 'Chain needs attention — the saved cloud grant was revoked; reconnect to read your backup')
  } else if (cause === 'auth') {
    el.textContent = getMessage('sdStateAttentionAuth', undefined, 'Chain needs attention — the cloud sign-in expired; re-sign in to read your backup')
  } else if (cause === 'unreachable') {
    el.textContent = getMessage('sdStateAttentionUnreachable', undefined, 'Chain needs attention — the cloud storage could not be reached; test the connection')
  } else if (cause === 'bridge') {
    el.textContent = getMessage('sdStateAttentionBridge', undefined, 'Chain needs attention — the cloud setup answered unexpectedly; check the connection details')
  } else if (cause === 'oauth_reauth') {
    // R172 — THE TYPED CHAIN STATE (R-172.7, the E-26/E-28 cure): the OAuth
    // record's config-class failure names the RE-AUTH cure in the active
    // method's words — "the cloud setup answered unexpectedly" is ABOLISHED
    // as a user-facing terminal on an OAuth surface (the bridge card keeps
    // it for bridge evidence only).
    el.textContent = getMessage('sdStateAttentionOauthReauth', undefined, 'Chain needs attention — the cloud sign-in needs you again; press Connect (one click) to re-sign in')
  } else if (cause === 'unreadable') {
    el.textContent = getMessage('sdStateAttentionUnreadable', undefined, 'Chain needs attention — the cloud backup cannot be read with this chain’s key; the rescue can reseed it')
  }
  ensureAttnShowMore()
}

/** ── R172 — THE ROAD-HOME FORK (R-172.3, the E-25 cure) ──────────────
 * The empty-local + non-empty-remote guard's typed recovery card: the
 * question line + THE THREE DOORS.
 *   [Pull the cloud copy] — the restore road: one click runs the pull
 *     (SYNC_PULL), the vault fills, the chain revives on its own.
 *   [Start fresh on this device] — the overwrite road, behind the
 *     danger-zone DOUBLE CONFIRM: the first press fetches the remote's
 *     date/size (SYNC_REMOTE_INFO — names and numbers only), shows them,
 *     and demands an explicit confirm; the confirm press runs the safe
 *     reseed (SYNC_RESEED_CLOUD — the old copy is ARCHIVED, rename never
 *     delete, then this device's fresh envelope uploads).
 *   [Not now] — the honest dismissal: the doors fold, the question stays.
 * The unlock boundary rides unchanged (R45-A): while locked the doors say
 * so and route to the unlock (the mint completes on unlock).
 */
function renderEmptyVaultFork(host, question) {
  if (!host) return
  host.textContent = ''
  host.appendChild(document.createTextNode(String(question || '')))
  const doors = document.createElement('div')
  doors.className = 'btn-row'
  doors.style.cssText = 'margin:6px 0 0;flex-wrap:wrap'
  doors.dataset.fork = 'empty-vault'
  const mkDoor = (label, cls, fn) => {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'btn ' + cls
    b.textContent = label
    b.addEventListener('click', fn)
    return b
  }
  // DOOR 1 — the restore road (the pull is never silently skipped: the
  // explicit door runs the pull now).
  doors.appendChild(mkDoor(getMessage('forkPullBtn', undefined, 'Pull the cloud copy'), 'btn-primary', async (ev) => {
    const btn = ev && ev.currentTarget
    try { if (btn) btn.disabled = true } catch { /* the door stays honest */ }
    try {
      const r = await bgSend('SYNC_PULL')
      if (r && r.ok) toast(getMessage('sdPullOk', undefined, 'Pull finished — your chain\u2019s data has landed.'), 'ok')
      else toast((r && r.error) || getMessage('cloudBackupSyncFail', undefined, 'Sync failed — see the ledger below.'), 'error')
    } catch (e) {
      toast(String((e && e.message) || e), 'error')
    }
    refreshSyncDevicesCardFresh().catch(() => {})
  }))
  // DOOR 2 — the overwrite road (the danger-zone double confirm).
  doors.appendChild(mkDoor(getMessage('forkStartFreshBtn', undefined, 'Start fresh on this device'), 'btn-outline', async () => {
    await renderStartFreshConfirm(host)
  }))
  // DOOR 3 — the honest dismissal.
  doors.appendChild(mkDoor(getMessage('forkNotNowBtn', undefined, 'Not now'), 'btn-ghost', () => {
    try {
      host.textContent = String(question || '')
    } catch { /* the line stays */ }
  }))
  host.appendChild(doors)
}

/** The start-fresh DOUBLE CONFIRM (R-172.3): the remote's date/size shown
 * BEFORE the commit; the confirm press runs the safe reseed (the old copy
 * is archived — rename, never delete — then the fresh envelope uploads). */
async function renderStartFreshConfirm(host) {
  if (!host) return
  const confirmBox = document.createElement('div')
  confirmBox.className = 'device-add-box'
  confirmBox.style.cssText = 'margin:6px 0 0'
  confirmBox.setAttribute('role', 'alertdialog')
  confirmBox.setAttribute('aria-label', getMessage('forkStartFreshConfirmTitle', undefined, 'Start fresh on this device — confirm'))
  const title = document.createElement('strong')
  title.textContent = getMessage('forkStartFreshConfirmTitle', undefined, 'Start fresh on this device — confirm')
  confirmBox.appendChild(title)
  const infoLine = document.createElement('p')
  infoLine.className = 'card-help'
  infoLine.style.margin = '4px 0'
  infoLine.style.overflowWrap = 'anywhere'
  infoLine.textContent = getMessage('forkStartFreshChecking', undefined, 'Reading the cloud copy\u2019s date and size…')
  confirmBox.appendChild(infoLine)
  const actions = document.createElement('div')
  actions.className = 'btn-row'
  actions.style.cssText = 'margin:6px 0 0;flex-wrap:wrap'
  const renderActions = (info) => {
    actions.textContent = ''
    const metaWords = info && info.present === true
      ? getMessage('forkStartFreshMeta', [String(info.size != null ? info.size : '?'), info.modifiedTime ? new Date(info.modifiedTime).toLocaleString() : '?'], `The cloud copy holds about $1 bytes, last modified $2. Starting fresh archives it (rename, never delete) and uploads this device's vault instead.`)
      : info && info.present === false
        ? getMessage('forkStartFreshMetaEmpty', undefined, 'The cloud storage holds no backup copy yet — starting fresh creates the first one from this device.')
        : getMessage('forkStartFreshMetaUnknown', undefined, 'The cloud copy\u2019s details could not be read on this connection. The old copy would still be archived (rename, never delete) before the fresh upload.')
    infoLine.textContent = metaWords
    const confirmed = document.createElement('button')
    confirmed.type = 'button'
    confirmed.className = 'btn btn-primary fork-confirm-btn'
    confirmed.textContent = getMessage('forkStartFreshConfirmBtn', undefined, 'Yes — archive the old copy and start fresh')
    confirmed.addEventListener('click', async () => {
      try { confirmed.disabled = true } catch { /* the door stays honest */ }
      try {
        const r = await bgSend('SYNC_RESEED_CLOUD')
        if (r && r.ok) toast(getMessage('forkStartFreshDone', undefined, 'Fresh cloud copy created — the chain is live.'), 'ok')
        else toast((r && (r.error || r.userMessage)) || getMessage('cloudBackupSyncFail', undefined, 'Sync failed — see the ledger below.'), 'error')
      } catch (e) {
        toast(String((e && e.message) || e), 'error')
      }
      refreshSyncDevicesCardFresh().catch(() => {})
    })
    const cancel = document.createElement('button')
    cancel.type = 'button'
    cancel.className = 'btn btn-ghost fork-cancel-btn'
    cancel.textContent = getMessage('forkStartFreshCancelBtn', undefined, 'Cancel')
    cancel.addEventListener('click', () => { try { confirmBox.remove() } catch { /* nothing to remove */ } })
    actions.appendChild(confirmed)
    actions.appendChild(cancel)
  }
  try {
    const info = await bgSend('SYNC_REMOTE_INFO')
    if (info && info.ok === false && info.locked) {
      // R-172.3's locked law: the unlock completes the mint — the fork says
      // so and names the unlock as the one-step cure (the R45-A envelope).
      infoLine.textContent = getMessage('forkStartFreshLocked', undefined, 'The vault is locked on this device — unlock once and the doors come back (the connection itself is never touched while locked).')
    } else {
      renderActions(info)
    }
  } catch {
    renderActions(null)
  }
  confirmBox.appendChild(actions)
  host.appendChild(confirmBox)
}

/**
 * The four Sync & Devices card states (R61-A §1.1 — truthful chain wording):
 *   no-chain   — no words: "No sync chain yet."
 *   attention  — words set AND the newest cloud READ failed/unreadable:
 *                "Chain needs attention — upload blocked until cloud copy can
 *                be read." (the three-state leg blocks every upload over an
 *                unobserved remote, so ACTIVE must never show over it)
 *   recovery   — words but no verified encrypted backup. TWO truthful
 *                sub-states since R91 §3.5c (CEO S-E):
 *                  unverified: "Sync code created — backup not verified."
 *                            + the ONE-CLICK completion path (Verify backup…)
 *                  verified:   "Backup verified — cloud copy not confirmed yet."
 *                The verified flag is set ONLY by a real verification act
 *                (positional word check against the sealed code, or an
 *                explicit sheet confirmation after re-auth) and resets when
 *                the sync code changes. Never a fake verified state.
 *   active     — verified upload AND no failed cloud read:
 *                "Chain active — encrypted backup verified."
 * "Active" is NEVER claimed from a local sync code or a configured transport
 * alone — it requires the verified-push evidence (and no read failure).
 */
async function refreshSyncDevicesCard(stateRes, kdfRes) {
  const el = $('sdState')
  if (!el) return
  const sync = (stateRes && stateRes.ok && stateRes.sync) || {}
  const info = (kdfRes && kdfRes.ok && kdfRes.info) || {}
  const hasCode = !!info.hasSyncCode
  const pushOk = !!(sync.lastPush && sync.lastPush.ok)
  // R61-A §1.1 — the pull-outcome ledger (ucrypt:lastPull) records whether the
  // newest cloud read positively observed the remote. attempted && !ok means
  // the device could not read its own backup — that is the attention state.
  const pull = sync.lastPull || null
  // R140 §7.2/§7.3 — THE REACTIVE VERDICT GATE: a failed read row alone can
  // no longer render the banner. The DERIVED truth decides: a pending wake
  // cycle renders the calm pending copy (never an error beside a green
  // pill); any success this cycle AUTO-CLEARS the banner (zero user action —
  // the explainer's own promise, kept by construction); an evidence-backed
  // exhausted-ladder verdict renders the attention branch WITH its cause.
  let readBlocked = !!(pull && pull.attempted && !pull.ok)
  let _chainDerived = null
  if (readBlocked) {
    try {
      const d = await bgSend('SYNC_CHAIN_VERDICT')
      _chainDerived = d && d.ok ? d.derived : null
      if (_chainDerived && _chainDerived.verdict === 'ok') readBlocked = false // auto-clear
    } catch { _chainDerived = null }
  }
  // R109 §4.1 — sdActiveActions was absorbed into the Add-a-device block
  // (the button now lives in #blockAddDevice); the state machine guards the
  // row reads so a removed row can never abort a render mid-branch.
  const noChain = $('sdNoChainActions')
  const recovery = $('sdRecoveryActions')
  const active = $('sdActiveActions')
  const attnBox = $('sdAttentionHelp')
  if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
  // LAW 0.48/0.49 (R133) — every render owns its leftovers: the joiner's
  // lifecycle line and the auto-sync cadence row reset per branch.
  const lifecycleLine = $('sdLifecycleLine')
  const autoSyncRow = $('sdAutoSyncRow')
  const pullNowBtn = $('sdPullNowBtn')
  const setLifecycleLine = (text) => {
    if (!lifecycleLine) return
    if (text) {
      lifecycleLine.textContent = text
      lifecycleLine.classList.remove('hidden')
      lifecycleLine.hidden = false
    } else {
      lifecycleLine.classList.add('hidden')
      lifecycleLine.hidden = true
    }
  }
  const setAutoSyncRow = (on) => {
    if (autoSyncRow) {
      autoSyncRow.classList.toggle('hidden', !on)
      autoSyncRow.hidden = !on
    }
  }
  const setPullNow = (on) => {
    if (pullNowBtn) {
      pullNowBtn.classList.toggle('hidden', !on)
      pullNowBtn.hidden = !on
    }
  }
  // LAW 0.51 (R133, the CEO's F5 — REDUNDANCY-ZERO): "Choose cloud storage"
  // is an entrance, not a second status surface. The Cloud backup card (the
  // transport's own card with Test/Edit/Sync/Disconnect) is the ONE
  // authoritative surface once a transport is configured — the chooser
  // button renders ONLY while nothing is configured (the entrance exists
  // exactly when the thing it opens does not).
  const setChooseCloud = (on) => {
    const b = $('sdChooseCloudBtn')
    if (b) {
      b.classList.toggle('hidden', !on)
      b.hidden = !on
    }
  }
  const transportConfigured = !!(sync.transport && sync.transport.hasConfig)
  // LAW 0.49 — the cadence row renders on every JOINED state (the truth
  // about automation lives beside the state, never in a sub-page).
  const renderAutoSyncRow = () => {
    const st = (stateRes && stateRes.ok && stateRes.sync && stateRes.sync.autoSync) || null
    const nextEl = $('sdAutoSyncNext')
    const input = $('sdAutoSyncMinutes')
    if (st && nextEl) {
      const mins = Number(st.minutes) || 15
      const nextAt = Number(st.nextAt) || 0
      const inMin = nextAt > 0 ? Math.max(0, Math.round((nextAt - Date.now()) / 60000)) : null
      if (st.inFlight) {
        const att = Number(st.retryCount) || 1
        const maxAtt = Number(st.maxRetries) || 6
        nextEl.textContent = `🔄 Retrying automatic cloud sync now (attempt ${att} of ${maxAtt}) · Auto-sync every ${mins} min`
      } else if (st.retrying && Number(st.retryNextAt) > 0) {
        const remSec = Math.max(0, Math.ceil((Number(st.retryNextAt) - Date.now()) / 1000))
        const att = Number(st.retryCount) || 1
        const maxAtt = Number(st.maxRetries) || 6
        const bSec = Number(st.backoffSeconds) || Math.round((Number(st.backoffMs) || 15000) / 1000)
        nextEl.textContent = `⏳ Exponential backoff retry #${att}/${maxAtt} in ${remSec}s (${bSec}s delay) · Auto-sync every ${mins} min`
      } else {
        nextEl.textContent = inMin === null
          ? getMessage('sdAutoSyncNextIdle', [String(mins)], `Auto-sync runs every ${mins} min · pulls also happen at every unlock`)
          : getMessage('sdAutoSyncNextIn', [String(inMin), String(mins)], `Next auto-sync in ${inMin} min · every ${mins} min · pulls also happen at every unlock`)
      }
    }
    if (input && st && document.activeElement !== input) input.value = String(st.minutes || 15)
    renderAutoSyncRetryFeedback(st).catch(() => {})
  }
  // R109 §4.1 — law 0.25's state model: the FRESH state renders exactly the
  // two first-run actions (#syncFreshState); the JOINED state renders the
  // four focused blocks (#syncJoinedBlocks). Every sub-state below (attention
  // / recovery / active) is a JOINED state — the blocks stay, the strip and
  // the typed lines carry the truth.
  const fresh = $('syncFreshState')
  const joined = $('syncJoinedBlocks')
  const setJoined = (on) => {
    if (fresh) { fresh.classList.toggle('hidden', on); fresh.hidden = on }
    if (joined) { joined.classList.toggle('hidden', !on); joined.hidden = !on }
    renderCloudBackupBlock().catch(() => {})
    renderVaultConflictResolver().catch(() => {})
    renderAutoSyncRetryFeedback().catch(() => {})
  }
  if (!hasCode) {
    el.textContent = getMessage('sdStateNoChain', undefined, 'No sync chain yet')
    el.style.color = ''
    hideAttnShowMore()
    setLifecycleLine('')
    setAutoSyncRow(false)
    setPullNow(false)
    setChooseCloud(false)
    // R123 §3 (the audit's kill): every render owns its leftovers — the
    // no-copy / recovered lines hide when the state leaves their branch.
    const nocopyLineStale = $('sdNocopyLine')
    if (nocopyLineStale) { nocopyLineStale.classList.add('hidden'); nocopyLineStale.hidden = true }
    const syncNowStale = $('sdSyncNowRecoveryBtn')
    if (syncNowStale) { syncNowStale.classList.add('hidden'); syncNowStale.hidden = true }
    if (noChain) { noChain.classList.remove('hidden'); noChain.hidden = false }
    if (recovery) { recovery.classList.add('hidden'); recovery.hidden = true }
    if (active) { active.classList.add('hidden'); active.hidden = true }
    setJoined(false)
  } else if (sync.lifecycle && sync.lifecycle.state === 'awaiting-first-pull') {
    // LAW 0.48 (R133) — THE JOINER'S DIRECTION-OF-TRUTH: a brand-new member
    // RECEIVES first. The state is amber-info, never a failure; the primary
    // action is Pull now; the row names exactly what the engine is doing.
    el.textContent = getMessage('sdStateAwaitingFirstPull', undefined, 'This device joined your chain — pulling your data from the cloud copy')
    el.style.color = 'var(--amber)'
    hideAttnShowMore()
    if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
    setLifecycleLine(getMessage('sdLifecycleAwaiting', undefined, 'An empty vault is correct here — this device receives your chain\u2019s data first, then two-way sync begins automatically. Pushing is disabled until the first pull lands (your cloud copy is never touched by an empty device).'))
    setPullNow(true)
    setChooseCloud(false)
    const nocopyLineStale2 = $('sdNocopyLine')
    if (nocopyLineStale2) { nocopyLineStale2.classList.add('hidden'); nocopyLineStale2.hidden = true }
    const syncNowStale2 = $('sdSyncNowRecoveryBtn')
    if (syncNowStale2) { syncNowStale2.classList.add('hidden'); syncNowStale2.hidden = true }
    if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
    if (recovery) { recovery.classList.remove('hidden'); recovery.hidden = false }
    if (active) { active.classList.add('hidden'); active.hidden = true }
    setAutoSyncRow(true)
    renderAutoSyncRow()
    setJoined(true)
  } else if (readBlocked && _chainDerived && _chainDerived.verdict === 'pending') {
    // R140 §7.3 — PENDING BEFORE ERROR: before the first successful probe of
    // a wake cycle the strip shows the calm pending copy — self-updating,
    // informative, NEVER an error beside a green pill. The four-step
    // explainer stays beneath an evidence-backed error only (§7.3's law).
    // R153 §5 (C-3/G117) — THE 41-SECOND BUDGET: the calm line is calm ONLY
    // inside the budget. Past it, the strip STOPS saying "in progress" (the
    // honesty law) and names the cure — the wake ladder (1–16 s, ≤31 s per
    // cycle) must have answered by now; if the card still pends, the
    // connection needs its one click (Sync now = the re-probe).
    const pendSecs = Number(_chainDerived.secondsPending || 0)
    if (pendSecs > 41) {
      el.textContent = getMessage('sdStatePendingOverBudget', [String(pendSecs)], 'The cloud check is still unanswered after 41 s — the wake ladder finished; press Sync now to re-probe, or check the connection details')
      const syncNowOver = $('sdSyncNowRecoveryBtn')
      if (syncNowOver) { syncNowOver.classList.remove('hidden'); syncNowOver.hidden = false }
    } else {
      el.textContent = getMessage('sdStatePending', [String(pendSecs)], _chainDerived.pendingWords || 'Cloud check in progress — verifying your encrypted backup')
    }
    el.style.color = 'var(--amber)'
    hideAttnShowMore()
    if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
    setLifecycleLine('')
    setPullNow(false)
    setAutoSyncRow(true)
    renderAutoSyncRow()
    setChooseCloud(!transportConfigured)
    const nocopyLineP = $('sdNocopyLine')
    if (nocopyLineP) { nocopyLineP.classList.add('hidden'); nocopyLineP.hidden = true }
    const syncNowP = $('sdSyncNowRecoveryBtn')
    if (syncNowP) { syncNowP.classList.add('hidden'); syncNowP.hidden = true }
    if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
    if (recovery) { recovery.classList.remove('hidden'); recovery.hidden = false }
    if (active) { active.classList.add('hidden'); active.hidden = true }
    setJoined(true)
  } else if (readBlocked) {
    // R123 §2.2 (the CEO's S2 — the glitch, captured) — THE TRUTHFUL
    // SUB-STATE SPLIT: a failed read whose row predates the transport's
    // own setAt means the owner ALREADY reconnected — the stale failure
    // must never scream "the grant was revoked" over a working connection
    // (the screenshot's contradiction: the chip said connected, the strip
    // said revoked). The recovered sub-state renders amber, names the
    // completion step, and its one-click Sync now closes the loop.
    let staleFailure = false
    try {
      const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
      const setAt = rec && Number(rec.setAt)
      staleFailure = !!(rec && rec.id && setAt > 0 && pull && Number(pull.at) > 0 && setAt > Number(pull.at))
    } catch { staleFailure = false }
    if (staleFailure) {
      el.textContent = getMessage('sdStateRecovered', undefined, 'Reconnected — run Sync now to confirm the backup reads')
      el.style.color = 'var(--amber)'
      hideAttnShowMore()
      if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
      const nocopyLine = $('sdNocopyLine')
      if (nocopyLine) {
        nocopyLine.classList.remove('hidden')
        nocopyLine.hidden = false
        nocopyLine.textContent = getMessage('sdRecoveredLine', undefined, 'The failed read predates your newest connection — the strip below no longer speaks for it. One Sync now confirms the backup reads and clears this state.')
      }
      const syncNowBtn = $('sdSyncNowRecoveryBtn')
      if (syncNowBtn) { syncNowBtn.classList.remove('hidden'); syncNowBtn.hidden = false }
      if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
      if (recovery) { recovery.classList.remove('hidden'); recovery.hidden = false }
      if (active) { active.classList.add('hidden'); active.hidden = true }
      setJoined(true)
      return
    }
    // R174 — THE ONE-TRUTH FIRST PAINT (R-174.1/R-174.2/R-174.5, the E-29/E-30
    // cure): the strip speaks the pull row's OWN class SYNCHRONOUSLY — the
    // family resolver reads the row's typed fields (kind/status/mode/state/
    // remoteObserved and, as the LAST resort, the row's own materialized
    // words) and names ONE family. The generic read wall ("upload blocked
    // until cloud copy can be read") is UNREACHABLE for a pre-read abort:
    // no read ran (remoteObserved:false), so the abort's own truth rides —
    // the sign-in family names the Connect cure everywhere (the strip, the
    // diagnosed line, the checklist, the footer all render the same story).
    // The wall's lawful home is ONLY a real blocked read (readMaySpeakWall —
    // the fetched-but-unreadable class), which has its own typed DATA card.
    const fam = resolveAttentionFamily(pull)
    const familyLines = {
      [ATTENTION_FAMILIES.SIGNIN]: ['sdFamilySignin', 'Chain needs attention — the cloud sign-in needs you again; press Connect (one click) to re-sign in'],
      [ATTENTION_FAMILIES.NETWORK]: ['sdFamilyNetwork', 'Chain needs attention — the cloud could not be reached this time; Test connection names the next step'],
      [ATTENTION_FAMILIES.STORAGE]: ['sdFamilyStorage', 'Chain needs attention — the cloud storage did not answer as expected; check the connection details'],
      [ATTENTION_FAMILIES.DATA]: ['sdStateAttentionUnreadable', 'Chain needs attention — the cloud backup cannot be read with this chain\u2019s key; the rescue can reseed it'],
    }
    const wallLawful = readMaySpeakWall(pull)
    const [famKey, famFallback] = (familyLines[fam.family] || familyLines[ATTENTION_FAMILIES.NETWORK])
    const autoSt = (stateRes && stateRes.ok && stateRes.sync && stateRes.sync.autoSync) || null
    if (fam.family === ATTENTION_FAMILIES.NETWORK && autoSt && (autoSt.retrying || autoSt.inFlight)) {
      const att = Number(autoSt.retryCount) || 1
      const maxAtt = Number(autoSt.maxRetries) || 6
      const bSec = Number(autoSt.backoffSeconds) || Math.round((Number(autoSt.backoffMs) || 15000) / 1000)
      const remSec = autoSt.retryNextAt ? Math.max(0, Math.ceil((Number(autoSt.retryNextAt) - Date.now()) / 1000)) : bSec
      el.textContent = autoSt.inFlight
        ? `Temporary network issue — retrying automatic sync now (attempt ${att} of ${maxAtt})…`
        : `Temporary network issue — automatic retry #${att}/${maxAtt} in ${remSec}s (${bSec}s exponential backoff)`
      el.style.color = 'var(--amber, #f59e0b)'
    } else if (fam.family === ATTENTION_FAMILIES.SIGNIN || !wallLawful) {
      // the family line — the sign-in family and EVERY no-real-read shape
      el.textContent = getMessage(famKey, undefined, famFallback)
      el.style.color = 'var(--danger, #c0392b)'
    } else {
      // a real read ran and was blocked by a real copy — the wall story is
      // lawful here (R-174.2), and the DATA card below refines it
      el.textContent = getMessage('sdStateAttention', undefined, 'Chain needs attention — upload blocked until cloud copy can be read')
      el.style.color = 'var(--danger, #c0392b)'
    }
    setLifecycleLine('')
    setPullNow(false)
    setAutoSyncRow(true)
    renderAutoSyncRow()
    setChooseCloud(!transportConfigured)
    if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
    if (recovery) { recovery.classList.remove('hidden'); recovery.hidden = false }
    if (active) { active.classList.add('hidden'); active.hidden = true }
    setJoined(true)
    // F-R71-UI-2 — plain-language explanation + numbered fix steps.
    const attn = $('sdAttentionHelp')
    if (attn) { attn.classList.remove('hidden'); attn.hidden = false }
    // R112 §3 (law 0.26) — the DIAGNOSED cause + the one-click action render
    // inside the help box; the chip CTA lands here too (already diagnosed).
    renderAttentionResolution().catch(() => {})
    // R116 §2.3 (law 0.29; the CEO's S1/S3 words made law): the generic
    // strip line grows (a) a "Show more" expander ADJACENT to the words —
    // one click opens the diagnosed cause, the detail and the fix buttons
    // right here; and (b) the SPECIFIC cause in the line itself once the
    // diagnose answers (the disabled client names ITSELF — never a bare
    // "attention"). Both are additions-only; the help box below stays.
    ensureAttnShowMore()
    applyAttentionSpecificLine(el).catch(() => {})
  } else if (!pushOk) {
    hideAttnShowMore()
    if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
    // R91 §3.5c (CEO S-E) — the recovery state carries its completion path:
    // "not verified" renders the ONE-CLICK Verify backup… button; "verified"
    // renders the truthful intermediate (the cloud push has not succeeded
    // yet — the state never claims Active from the flag alone).
    let backupFlag = null
    try { backupFlag = (await chrome.storage.local.get(BACKUP_VERIFY_KEY))[BACKUP_VERIFY_KEY] || null } catch { backupFlag = null }
    const backupVerified = !!(backupFlag && backupFlag.verified)
    const verifyBtn = $('sdVerifyBackupBtn')
    if (verifyBtn) verifyBtn.classList.toggle('hidden', backupVerified)
    // R112 §3.1 — the fourth cause (law 0.26): connected but the cloud copy
    // does not exist YET (never pushed). The state names it and offers the
    // one-click Sync now; a failed push is a different cause (the ledger
    // names it) and never renders as "no copy yet".
    const neverPushed = !(sync.lastPush && sync.lastPush.at)
    const connected = !!(sync.transport && sync.transport.hasConfig)
    const nocopy = backupVerified && connected && neverPushed
    const nocopyLine = $('sdNocopyLine')
    const syncNowBtn = $('sdSyncNowRecoveryBtn')
    if (nocopyLine) {
      nocopyLine.classList.toggle('hidden', !nocopy)
      nocopyLine.hidden = !nocopy
      if (nocopy) nocopyLine.textContent = getMessage('sdNocopyLine', undefined, 'No cloud copy exists yet — press “Sync now” to create the first encrypted backup in your cloud storage.')
    }
    if (syncNowBtn) syncNowBtn.classList.toggle('hidden', !nocopy)
    // LAW 0.48 (R133) — the SYNCED-side empty-vault guard carries its typed
    // recovery question in the state line's companion row (never a dead end).
    // R172 — THE ROAD-HOME FORK (R-172.3, the E-25 cure): the question is no
    // longer words without doors — the fork card renders the THREE doors
    // ([Pull the cloud copy] [Start fresh on this device] [Not now]) right
    // under the question, the start-fresh door rides the danger-zone double
    // confirm (the remote's date/size shown before the commit), and the
    // virgin remote never reaches this fork at all (the guard stands down —
    // the first push proceeds). Every named action resolves (R-172.5).
    const guardRow = $('sdGuardLine')
    const guardHit = !!(sync.lastPush && sync.lastPush.guardClass === 'empty-vault-synced' && sync.lastPush.guardQuestion)
    if (guardRow) {
      guardRow.classList.toggle('hidden', !guardHit)
      guardRow.hidden = !guardHit
      if (guardHit) renderEmptyVaultFork(guardRow, String(sync.lastPush.guardQuestion))
    }
    // LAW 0.49 — an unconfirmed read-back warning rides the recovery line
    // (the push landed but the cloud copy did not verify — retrying).
    if (!guardHit && sync.lastPush && sync.lastPush.ok === false && sync.lastPush.confirmError) {
      setLifecycleLine(String(sync.lastPush.confirmError))
    } else if (!guardHit) {
      setLifecycleLine('')
    }
    setPullNow(false)
    setAutoSyncRow(true)
    renderAutoSyncRow()
    setChooseCloud(!transportConfigured)
    // R175 — THE CONFIRMATION TRUTH (R-175.3, the E-31/E-34 cure): when the
    // newest cycle's typed projection carries a FAILED lane, the banner shows
    // THE SAME typed words as the row (no second voice, no second wording) —
    // the fixed "cloud copy not confirmed yet" can never lie over a named
    // lane failure again. When no cycle row carries the failure (pre-v3.35
    // history, or the failure predates the cycle machinery), the legacy
    // recovery words stand byte-true.
    let cycleFailedLane = null
    try {
      const c = (await chrome.storage.local.get('ucrypt:lastCycle'))['ucrypt:lastCycle']
      if (c && c.verdict === 'failed' && Array.isArray(c.lanes)) cycleFailedLane = c.lanes.find((l) => l.ok === false) || null
    } catch { cycleFailedLane = null }
    if (cycleFailedLane) {
      // R176 — R-176.4: the banner's failed-lane words ride the render belt
      // too (the last seat before the owner's eyes — no bare generic at ANY
      // surface; an unnamed arrival is fingerprinted at paint).
      const laneWords = beltRender(typeof cycleFailedLane.words === 'string' ? cycleFailedLane.words : '', { cap: 220 })
      const laneName = String(cycleFailedLane.lane || '')
      el.textContent = `${laneName ? laneName + ' failed — ' : ''}${laneWords}`
      // R176 — R-176.6: the BANNER offers the road home too — when the
      // failed lane is the auth family, the one-click affordance rides the
      // state line's own row (the words point at it; the affordance IS the
      // pointed-at thing — R-172.5 at banner depth).
      try {
        if (/sign.in|expired|Connect|auth|Google said|banked key/i.test(String(laneWords))) {
          const old = document.getElementById('sdRoadHomeBtn')
          if (old) old.remove()
          const road = document.createElement('button')
          road.id = 'sdRoadHomeBtn'
          road.className = 'btn btn-outline btn-sm'
          road.type = 'button'
          road.style.margin = '0 0 0 10px'
          road.textContent = getMessage('roadHomeOneClick', undefined, 'Sign back in — one click')
          road.addEventListener('click', async () => {
            try {
              const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
              reconnectViaWizard((rec && rec.id) || 'gdrive')
            } catch { openSyncOverlay('cloudOverlay') }
          })
          el.appendChild(road)
        }
      } catch { /* the affordance never perturbs the words */ }
    } else if (backupVerified) {
      el.textContent = getMessage('sdStateRecoveryVerified', undefined, 'Backup verified — cloud copy not confirmed yet')
    } else {
      el.textContent = getMessage('sdStateRecovery', undefined, 'Sync code created — backup not verified')
    }
    el.style.color = 'var(--amber)'
    if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
    if (recovery) { recovery.classList.remove('hidden'); recovery.hidden = false }
    if (active) { active.classList.add('hidden'); active.hidden = true }
    setJoined(true)
  } else {
    if (attnBox) { attnBox.classList.add('hidden'); attnBox.hidden = true }
    // LAW 0.49 (R133) — the ACTIVE state now speaks the read-back truth:
    // a confirmed push reads "Cloud copy confirmed ✓ <time>"; an unconfirmed
    // one stays active but carries the typed verifying line (never a silent
    // downgrade, never a fake confirmation).
    const lp = sync.lastPush || null
    // R175 — THE CONFIRMATION TRUTH (R-175.3): a completed read of a FRESH
    // cloud IS the confirmation — the positive settled truth renders here
    // (the E-29 truth reaching the banner seat at last; a virgin cloud read
    // is a success, never a warning).
    let freshCycle = false
    try {
      const c = (await chrome.storage.local.get('ucrypt:lastCycle'))['ucrypt:lastCycle']
      freshCycle = !!(c && c.verdict === 'ok' && Array.isArray(c.lanes) && c.lanes.some((l) => l.lane === 'pull' && l.ok === true && /fresh/i.test(String(l.words || ''))))
    } catch { freshCycle = false }
    if (freshCycle) {
      el.textContent = getMessage('sdStateFreshConfirmed', undefined, 'Cloud copy confirmed — fresh cloud, this device leads')
    } else if (lp && lp.confirmed === true && lp.confirmedAt) {
      el.textContent = getMessage('sdStateConfirmed', [new Date(lp.confirmedAt).toLocaleString()], `Cloud copy confirmed ✓ ${new Date(lp.confirmedAt).toLocaleString()}`)
    } else if (lp && lp.confirmed === false && lp.confirmError) {
      el.textContent = getMessage('sdStateVerifying', undefined, 'Chain active — verifying the cloud copy (automatic retry running)')
    } else {
      el.textContent = getMessage('sdStateActive', undefined, 'Chain active — encrypted backup verified')
    }
    el.style.color = 'var(--accent)'
    hideAttnShowMore()
    setLifecycleLine('')
    setPullNow(false)
    setAutoSyncRow(true)
    renderAutoSyncRow()
    setChooseCloud(false) // LAW 0.51 — the Cloud backup card is the ONE surface here
    // R123 §3 (the audit's kill): the no-copy / recovered lines are this
    // state machine's own faces — an ACTIVE chain never keeps a stale
    // "press Sync now" line from a previous render (a doubt-creating
    // leftover; the audit's checklist (a)).
    const nocopyLineStale = $('sdNocopyLine')
    if (nocopyLineStale) { nocopyLineStale.classList.add('hidden'); nocopyLineStale.hidden = true }
    const syncNowStale = $('sdSyncNowRecoveryBtn')
    if (syncNowStale) { syncNowStale.classList.add('hidden'); syncNowStale.hidden = true }
    if (noChain) { noChain.classList.add('hidden'); noChain.hidden = true }
    if (recovery) { recovery.classList.add('hidden'); recovery.hidden = true }
    if (active) { active.classList.remove('hidden'); active.hidden = false }
    setJoined(true)
  }
}

/** ── R112 §3 — THE RESOLUTION PATH (law 0.26; the CEO's S1 finding) ─────
 *  The attention state no longer ends at numbered prose: the DIAGNOSED
 *  cause (from the pull ledger's typed fields, via SYNC_ATTN_DIAGNOSE)
 *  renders one young-teen sentence + THE one-click action + the deeper
 *  diagnostic. The chips in the strip are CTAs that land here.
 */
const _ATTN_CAUSE_KEYS = {
  auth: {
    sentenceKey: 'attnCauseAuth',
    fallback: 'Your sign-in to the cloud expired, so UCrypt cannot read its backup. Sign in again — it takes one click and your data is not touched.',
    actionKey: 'attnActionAuth',
    actionFallback: 'Re-sign in…',
  },
  // R116 §2.1/§2.2 (laws 0.26+0.29; the CEO's S2/S3): the AUTH class splits
  // by the recovery card's kind — the DISABLED / testing-mode client is its
  // OWN cause (the owner's two-sentence checklist + the Cloud Console deep
  // link, NEVER the re-sign card), and the revoked grant is its OWN cause
  // (the reconnect card). A disabled client never renders as "expired login".
  auth_disabled: {
    sentenceKey: 'attnCauseDisabled',
    fallback: 'Your Google OAuth client is disabled or in testing mode, so Google refuses the connection. Nothing on this device is broken — the fix lives in Google Cloud Console.',
    actionKey: 'attnActionConsole',
    actionFallback: 'Open Google Cloud Console',
  },
  auth_revoked: {
    sentenceKey: 'attnCauseRevoked',
    fallback: 'The saved Google grant was revoked (or expired after weeks in testing mode) — reconnect Google Drive. One click, and your data is not touched.',
    actionKey: 'attnActionReconnect',
    actionFallback: 'Reconnect Google Drive…',
  },
  // R153 §5 (C-2) — THE OAUTH PRODUCTION LAW: the named provider errors
  // carry their OWN sentence and their OWN cure — never a generic
  // "connection problem" (the contract's S96 acceptance class).
  auth_consent: {
    sentenceKey: 'attnCauseConsent',
    fallback: 'Google refused the consent (access_denied) — in testing mode this usually means this Google account is not on the test-user list. Add it in Cloud Console, then connect again.',
    actionKey: 'attnActionConsole',
    actionFallback: 'Open Google Cloud Console',
  },
  auth_config: {
    sentenceKey: 'attnCauseConfig',
    fallback: 'The OAuth client configuration does not match (redirect_uri_mismatch) — the client type must be "Chrome extension" with this extension\u2019s ID pinned. Fix it in Cloud Console, then connect again.',
    actionKey: 'attnActionConsole',
    actionFallback: 'Open Google Cloud Console',
  },
  auth_admin: {
    sentenceKey: 'attnCauseAdmin',
    fallback: 'Your organization\u2019s admin blocks this app (admin_policy_enforced) — the app must be allowed in the workspace admin console, or connect with a personal Google account.',
    actionKey: 'attnActionConsole',
    actionFallback: 'Open Google Cloud Console',
  },
  // R123 §2.2 — THE RECOVERED CAUSE (the CEO's S2 made truthful): the
  // failed read predates the newest connection — the strip says so and the
  // one-click Sync now completes the recovery. The stale "revoked" scream
  // never renders over a working connection again.
  recovered: {
    sentenceKey: 'attnCauseRecovered',
    fallback: 'The failed read predates your newest connection — you already reconnected. Run Sync now once to confirm the backup reads; your data was never touched.',
    actionKey: 'attnActionSyncNow',
    actionFallback: 'Sync now',
  },
  unreachable: {
    sentenceKey: 'attnCauseUnreachable',
    fallback: 'The cloud storage could not be reached — the internet connection or the server is down. Nothing is broken; test the connection.',
    actionKey: 'attnActionTest',
    actionFallback: 'Test connection',
  },
  bridge: {
    sentenceKey: 'attnCauseBridge',
    fallback: 'The cloud setup answered in a way UCrypt did not expect — the connection details are probably out of date. Check and fix them.',
    actionKey: 'attnActionEdit',
    actionFallback: 'Edit setup…',
  },
  // R172 — THE OAUTH RE-AUTH CAUSE (R-172.7): the named class with the
  // active method's cure — the one-click sign-in, never the bridge words,
  // never "answered unexpectedly".
  oauth_reauth: {
    sentenceKey: 'attnCauseOauthReauth',
    fallback: 'The saved Google sign-in needs you again — the connection is intact, only the sign-in expired. Press Connect (one click) to re-sign in; nothing was lost.',
    actionKey: 'attnActionReconnect',
    actionFallback: 'Reconnect Google Drive…',
  },
  unreadable: {
    sentenceKey: 'attnCauseUnreadable',
    fallback: 'The backup file in your cloud cannot be read with this chain’s key — it may be damaged or from another chain. UCrypt can archive it (never delete) and upload a fresh copy.',
    actionKey: 'attnActionReseed',
    actionFallback: 'Rescue: archive the old copy & upload a fresh one…',
  },
  unknown: {
    // R174 — THE NAMED-FALLBACK LAW (R-174.5, the E-30 cure): "a reason
    // UCrypt could not name" is EXTINCT. The no-typed-evidence class renders
    // the named FAMILY sentence — method-aware, with the diagnostics pointer.
    // The active method rides the transport record (read at render); the
    // words below are the OAuth-active default (the field's method), and
    // applyAttentionChecklistClass keeps the bridge steps unreachable.
    sentenceKey: 'attnCauseFamilySignin',
    fallback: 'The cloud sign-in needs you again — press Connect (one click) to re-sign in. If that does not clear it, Test connection names the next step.',
    actionKey: 'attnActionReconnect',
    actionFallback: 'Reconnect Google Drive…',
  },
}

/** One render per state refresh; a stale render never overwrites a newer. */
let _attnRenderSeq = 0
/** R172 — THE CLASS-AWARE CHECKLIST (R-172.7, the E-28 cure): the static
 * steps under the attention help box speak ONE method. An OAuth-active
 * cause hides the bridge steps ("Choose cloud storage" / "the file was
 * moved or renamed" are structurally unreachable words on an OAuth
 * surface) and shows the OAuth steps; a bridge cause keeps the bridge
 * steps and hides the OAuth ones. Pure DOM toggle, both directions. */
function applyAttentionChecklistClass(cause, activeMode = '') {
  // R174 — THE FAMILY-AWARE TOGGLE (R-174.5, the E-30 cure): the fallback
  // family ('unknown') speaks the ACTIVE method's words — the bridge 4-step
  // ("Choose cloud storage" / "the file was moved or renamed") is
  // structurally unreachable from EVERY class, including the fallback, on a
  // non-bridge surface. The named OAuth classes keep their byte-true toggle.
  const oauthActive = ['oauth_reauth', 'auth', 'auth_revoked', 'auth_disabled', 'auth_consent', 'auth_config', 'auth_admin'].includes(String(cause || ''))
    || (String(cause || '') === 'unknown' && String(activeMode || '') !== 'bridge')
  const bridgeOl = document.getElementById('sdAttentionStepsBridge')
  const oauthOl = document.getElementById('sdAttentionStepsOauth')
  if (bridgeOl) {
    bridgeOl.classList.toggle('hidden', oauthActive)
    bridgeOl.hidden = oauthActive
  }
  if (oauthOl) {
    oauthOl.classList.toggle('hidden', !oauthActive)
    oauthOl.hidden = !oauthActive
  }
}
async function renderAttentionResolution() {
  const box = $('sdAttnResolution')
  if (!box) return
  const seq = ++_attnRenderSeq
  box.textContent = ''
  let diag = null
  try { diag = await bgSend('SYNC_ATTN_DIAGNOSE') } catch { diag = null }
  if (seq !== _attnRenderSeq) return
  const cause = (diag && diag.ok && diag.cause) || 'unknown'
  // R174 — the ACTIVE method rides the toggle (R-174.5): the fallback family
  // speaks the record's own method — the mode fields ride the sealed
  // envelope as plaintext field names (law 0.33), so the sealed record
  // answers truthfully.
  let activeMode = ''
  try {
    const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
    const cfg = (rec && rec.config) || {}
    activeMode = String(cfg.authMode || cfg.signinMode || '')
  } catch { activeMode = '' }
  // R172 — the checklist speaks the active method (both directions).
  applyAttentionChecklistClass(cause, activeMode)
  const ck = _ATTN_CAUSE_KEYS[cause] || _ATTN_CAUSE_KEYS.unknown
  // (a) the cause in one young-teen sentence
  const causeP = document.createElement('p')
  causeP.className = 'card-help'
  causeP.style.margin = '0 0 6px'
  causeP.innerHTML = '<strong>' + escapeHtml(getMessage('attnCauseLabel', undefined, 'Diagnosed:')) + '</strong> ' + escapeHtml(getMessage(ck.sentenceKey, undefined, ck.fallback))
  box.appendChild(causeP)
  // (b) the one-click next action
  const row = document.createElement('div')
  row.className = 'btn-row'
  row.style.margin = '0 0 4px'
  const mkBtn = (label, cls, fn) => {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'btn ' + cls
    b.textContent = label
    b.addEventListener('click', fn)
    return b
  }
  const resultLine = document.createElement('p')
  resultLine.className = 'card-help'
  resultLine.style.margin = '6px 0 0'
  resultLine.id = 'sdAttnResult'
  const refresh = () => { refreshSyncDevicesCardFresh().catch(() => {}) }
  // The connected transport's id (the record carries { id, config: sealed });
  // the CONFIG is sealed at rest — the page never reads values, only the id.
  const connectedId = async () => {
    try {
      const rec = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
      return (rec && rec.id) || null
    } catch { return null }
  }
  if (cause === 'auth') {
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      // The re-sign one-click: the wizard (edit mode) holds the provider's
      // Connect button — one click lands the user in the focused layer with
      // the sign-in visible (the re-sign popup, §3.1).
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        wizardEditMode = true
        openTransportWizard(id)
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'auth_disabled') {
    // R116 §2.2 (law 0.29; the CEO's S2) — the owner's checklist renders
    // INLINE, adjacent to the diagnosed words, BEFORE any deeper surface:
    // the two-sentence fix at 13-year-old level + the Cloud Console deep
    // link as the PRIMARY button + Re-sign in as the demoted secondary
    // (after the console fix some grants still need one fresh consent).
    const checklist = document.createElement('p')
    checklist.className = 'card-help'
    checklist.style.cssText = 'margin:0 0 8px;white-space:pre-line'
    checklist.textContent = getMessage('attnChecklistDisabled', undefined,
      'Your Google OAuth client is disabled or in testing mode. ' +
      'Cloud Console → OAuth consent screen → Publish to production, then Credentials → confirm the client is Enabled — then Connect again.') || ''
    // R116 §2.2 — the worker's canonical checklist text (the exact two
    // sentences the battery pins) beats the page's fallback when it rides.
    if (diag && diag.checklist) checklist.textContent = diag.checklist
    box.insertBefore(checklist, row)
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      try {
        const url = (diag && diag.consoleUrl) || 'https://console.cloud.google.com/apis/credentials'
        await chrome.tabs.create({ url })
        resultLine.textContent = getMessage('attnConsoleOpened', undefined, 'Cloud Console opened in a new tab — publish the consent screen, confirm the client is Enabled, then come back and press Re-sign in.')
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
    row.appendChild(mkBtn(getMessage('attnActionAuth', undefined, 'Re-sign in…'), 'btn-outline', async () => {
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        wizardEditMode = true
        openTransportWizard(id)
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'auth_revoked') {
    // R123 §2.2 (the CEO's S2 recovery polish) — the reconnect CTA rides
    // the connect flow's own machinery: ONE click lands in the wizard with
    // the Connect flow already starting (reconnectViaWizard), the stored
    // fields prefilled (the client ID rides TRANSPORT_GET's prefill) —
    // the fast rung's one-click economics for the recovery path too.
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        reconnectViaWizard(id)
        resultLine.textContent = getMessage('attnReconnectStarted', undefined, 'The connect flow opened — finish the authorization and the next Sync now reads your backup again.')
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'oauth_reauth') {
    // R172 — THE OAUTH RE-AUTH ONE-CLICK (R-172.7): the same reconnect
    // machinery the revoked-grant cause rides — ONE click lands in the
    // wizard with the connect flow starting; the active method's cure.
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        reconnectViaWizard(id)
        resultLine.textContent = getMessage('attnReconnectStarted', undefined, 'The connect flow opened — finish the authorization and the next Sync now reads your backup again.')
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'auth_consent' || cause === 'auth_config' || cause === 'auth_admin') {
    // R153 §5 (C-2/S96) — the NAMED provider error's card: the cause names
    // itself, the checklist names the cure, the Console deep link opens it.
    const checklist = document.createElement('p')
    checklist.className = 'card-help'
    checklist.style.cssText = 'margin:0 0 8px;white-space:pre-line'
    const cures = {
      auth_consent: 'Google Cloud → OAuth consent screen → if Publishing status is Testing, add this Google account under Test users (or Publish to production) — then press Re-sign in below.',
      auth_config: 'Cloud Console → Credentials → the OAuth client → Application type must be "Chrome extension" and the Extension ID must match this browser\u2019s extension ID exactly — then press Re-sign in below.',
      auth_admin: 'Google Admin console → Security → API controls → app access: allow this app for the workspace — or connect a personal Google account (no admin gate).',
    }
    checklist.textContent = getMessage(ck.sentenceKey + 'Cure', undefined, cures[cause] || '') || ''
    box.insertBefore(checklist, row)
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      try {
        const url = cause === 'auth_config'
          ? 'https://console.cloud.google.com/apis/credentials'
          : 'https://console.cloud.google.com/apis/credentials/consent'
        await chrome.tabs.create({ url })
        resultLine.textContent = getMessage('attnConsoleOpenedCure', undefined, 'Cloud Console opened in a new tab — apply the named cure, then come back and press Re-sign in.')
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
    row.appendChild(mkBtn(getMessage('attnActionAuth', undefined, 'Re-sign in…'), 'btn-outline', async () => {
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        reconnectViaWizard(id)
        resultLine.textContent = getMessage('attnReconnectStarted', undefined, 'The connect flow opened — finish the authorization and the next Sync now reads your backup again.')
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'recovered') {
    // R123 §2.2 — the recovery's COMPLETION: the one-click Sync now. The
    // owner already reconnected; this click proves the backup reads and
    // clears the state (the truthful end of the glitch story).
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      resultLine.textContent = getMessage('twTesting', undefined, 'Testing…')
      try {
        const r = await bgSend('SYNC_NOW')
        if (r && r.ok) {
          resultLine.className = 'card-help'
          resultLine.style.margin = '6px 0 0'
          resultLine.textContent = getMessage('attnSyncNowDone', undefined, '✓ The backup reads — the chain is current. This state is cleared.')
          refresh()
        } else {
          resultLine.textContent = '✗ ' + ((r && r.error) || getMessage('dmSyncNowFailed', undefined, 'The sync could not run — try again.'))
        }
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'bridge') {
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        wizardEditMode = true
        openTransportWizard(id)
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
  } else if (cause === 'unreadable') {
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', () => {
      runReseedFlow(resultLine, refresh)
    }))
  } else { // unreachable | unknown
    row.appendChild(mkBtn(getMessage(ck.actionKey, undefined, ck.actionFallback), 'btn-primary', async () => {
      resultLine.textContent = getMessage('twTesting', undefined, 'Testing…')
      try {
        const id = await connectedId()
        if (!id) { resultLine.textContent = getMessage('attnNoTransport', undefined, 'No cloud storage is connected yet — connect one first.') ; return }
        currentTransportId = id
        // R171 — THE TRANSPORT-TRUTH LAW (the E-23 cure): the attention seat
        // tests the ACTIVE transport's health with the STORED config — the
        // wizard form is never trusted here (the wizard is not open; the
        // hollow-form ride was the exact bug that demanded an Apps Script
        // URL from an OAuth-connected user). For an OAuth transport the test
        // is the token state + the Drive round-trip; for a bridge transport
        // the bridge legs — the transport's own machinery decides.
        await testCurrentTransport(resultLine, { formForbidden: true })
      } catch (e) { resultLine.textContent = String(e && e.message || e) }
    }))
    if (cause === 'unknown') {
      row.appendChild(mkBtn(getMessage('attnActionEdit', undefined, 'Edit setup…'), 'btn-outline', async () => {
        try {
          const id = await connectedId()
          if (!id) return
          wizardEditMode = true
          openTransportWizard(id)
        } catch { /* the result line stays */ }
      }))
    }
  }
  box.appendChild(row)
  box.appendChild(resultLine)
  // (c) the deeper diagnostic — the ledger's own technical line + where the
  // full export lives. The line is the same one the ledger shows (no secret
  // ever rides it — the no-secrets law).
  const det = $('sdAttnDetail')
  const detText = $('sdAttnDetailText')
  if (det && detText) {
    const detail = (diag && diag.detail) || null
    if (detail) {
      det.classList.remove('hidden')
      det.hidden = false
      detText.textContent = String(detail)
    } else {
      det.classList.add('hidden')
      det.hidden = true
    }
  }
}

/** §3.1 — the SAFE RESEED's double-confirm flow (the surface owns the two
 * explicit confirms; the worker owns the four legs). Refusals render typed,
 * truthfully, with the next action — a truthful dead end is a defect. */
function runReseedFlow(resultLine, refresh) {
  const first = getMessage('reseedConfirm1', undefined, 'The backup file in your cloud cannot be read with this chain’s key. UCrypt will first save a untouched copy of it next to the file (never delete), then upload a fresh copy of THIS device’s vault. Your local vault is never touched. Continue?')
  if (!confirm(first)) {
    resultLine.textContent = getMessage('reseedCancelled', undefined, 'Cancelled — nothing was changed.')
    return
  }
  const second = getMessage('reseedConfirm2', undefined, 'Last check: the fresh copy replaces the unreadable one in your cloud storage, and the old bytes stay archived under a new name. Other devices will adopt the fresh copy on their next sync. Upload it?')
  if (!confirm(second)) {
    resultLine.textContent = getMessage('reseedCancelled', undefined, 'Cancelled — nothing was changed.')
    return
  }
  resultLine.textContent = getMessage('reseedBusy', undefined, 'Archiving the old copy and uploading a fresh one…')
  bgSend('SYNC_RESEED_CLOUD').then((r) => {
    if (r && r.ok) {
      resultLine.textContent = getMessage('reseedDone', [(r.archivedName || '')], 'Done — the old copy is archived ($1) and a fresh copy is uploaded. The chain unblocks as soon as a read succeeds.')
      toast(getMessage('reseedDoneToast', undefined, 'Cloud copy rescued — a fresh copy is in your cloud storage.'), 'ok')
      refresh()
    } else if (r && r.stage === 'archive' && r.cause === 'bridge-cannot-archive') {
      resultLine.textContent = getMessage('reseedBridgeCant', undefined, 'This bridge connection cannot archive the old copy. Edit setup to reconnect as OAuth — or save a copy of ucrypt-vault.enc from your Drive first, then run the rescue again.')
    } else {
      resultLine.textContent = getMessage('reseedFail', [(r && r.error) || 'unknown'], 'The rescue stopped before anything was replaced: $1')
    }
  }).catch((e) => { resultLine.textContent = String(e && e.message || e) })
}

/** §3.2 — the chips are CTAs. Clicking the chain chip opens the resolution
 * surface with the cause already diagnosed; the cloud chip opens the cloud
 * setup; the Beam chip opens the Beam card. */
function wireSyncChipCtas() {
  const chainChip = $('syncChipChain')
  if (chainChip) {
    chainChip.addEventListener('click', async () => {
      const state = chainChip.dataset.state
      if (state === 'warn') {
        const attn = $('sdAttentionHelp')
        if (attn && !attn.classList.contains('hidden')) {
          renderAttentionResolution().catch(() => {})
          attn.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
          return
        }
      }
      // Not attention: the state card IS the chain surface.
      $('sdState')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    })
  }
  const cloudChip = $('syncChipCloud')
  if (cloudChip) {
    cloudChip.addEventListener('click', () => {
      const block = $('cloudBackupStatus')
      if (block) block.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      else openSyncOverlay('cloudOverlay')
    })
  }
  const beamChip = $('syncChipBeam')
  if (beamChip) {
    beamChip.addEventListener('click', () => {
      const card = $('joinPathBeam') || $('transferCard')
      if (card) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      else switchTab('transfer')
    })
  }
  const conflictChip = $('syncChipConflict')
  if (conflictChip) {
    conflictChip.addEventListener('click', () => {
      try { SettledHouse.reveal('conflict-resolver') } catch { /* best-effort */ }
      const card = $('vaultConflictResolverCard')
      if (card) {
        card.open = true
        card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }
    })
  }
  const retryChip = $('syncChipRetry')
  if (retryChip) {
    retryChip.addEventListener('click', () => {
      const banner = $('sdAutoSyncRetryBanner')
      if (banner && !banner.hidden) {
        banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        $('sdAutoSyncRetryNowBtn')?.focus({ preventScroll: true })
      } else {
        $('sdState')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }
    })
  }
}

/** R109 §4.1(b) — Block 3 (Cloud backup) renders BY STATE (law 0.25):
 *  not connected → ONE "Connect cloud" button opening the chooser layer;
 *  connected → the compact status (provider · mode · last test/push/pull)
 *  plus Test / Edit setup / Disconnect. The recovery path's buttons
 *  (Choose cloud storage / Verify backup) live in the state card's row;
 *  this block is the everyday cloud surface. */
let _cloudBackupRenderSeq = 0
async function renderCloudBackupBlock() {
  const statusEl = $('cloudBackupStatus')
  const actionsEl = $('cloudBackupActions')
  const countEl = $('cloudBackupCount')
  if (!statusEl || !actionsEl) return
  const seq = ++_cloudBackupRenderSeq
  let record = null
  try { record = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY] || null } catch { record = null }
  if (seq !== _cloudBackupRenderSeq) return // a newer render superseded this one
  statusEl.textContent = ''
  actionsEl.textContent = ''
  if (!record || !record.id) {
    statusEl.innerHTML = ''
    const p = document.createElement('p')
    p.className = 'card-help'
    p.style.margin = '0'
    p.textContent = getMessage('cloudBackupNotConnected', undefined, 'Not connected — your encrypted backup lives only on this device until a cloud is connected.')
    statusEl.appendChild(p)
    const btn = document.createElement('button')
    btn.id = 'sdConnectCloudBtn'
    btn.className = 'btn btn-primary'
    btn.type = 'button'
    btn.textContent = getMessage('sdConnectCloudBtn', undefined, 'Connect cloud')
    btn.addEventListener('click', () => openSyncOverlay('cloudOverlay'))
    actionsEl.appendChild(btn)
    if (countEl) countEl.textContent = getMessage('blockCloudCountOff', undefined, 'One action to start: Connect cloud → pick a provider → follow the guided setup.')
    return
  }
  const t = getTransport(record.id)
  const tName = transportName(record.id, (t && t.name) || record.id)
  const info = await transportStateInfo()
  if (seq !== _cloudBackupRenderSeq) return
  const p = document.createElement('p')
  p.className = 'card-help'
  p.style.margin = '0 0 4px'
  // R172 — THE ONE-TRUTH MODE LINE (R-172.1, the E-26 cure, seat R6): the
  // mode reads the record's OWN non-secret mode fields (authMode/signinMode
  // ride the sealed envelope as PLAINTEXT field names — law 0.33) — never an
  // EMPTY config that unconditionally printed "OAuth (recommended)". A
  // bridge record prints Bridge; an OAuth record prints the OAuth line.
  const recModeCfg = (record && record.config && typeof record.config === 'object') ? record.config : {}
  p.innerHTML = `✓ <strong>${escapeHtml(tName)}</strong> — ${escapeHtml(connectionModeLabel(t || { id: record.id }, recModeCfg, false))}`
  statusEl.appendChild(p)
  const ledger = document.createElement('p')
  ledger.className = 'card-help pwm-note'
  ledger.style.margin = '0'
  const pushLine = info.lastPush ? ledgerLine(info.lastPush, 'tsNeverPushed', 'Never pushed') : getMessage('tsNeverPushed', undefined, 'Never pushed')
  const pullLine = info.lastPull ? ledgerLine(info.lastPull, 'tsNeverPulled', 'Never pulled') : getMessage('tsNeverPulled', undefined, 'Never pulled')
  // R175 — THE ONE CYCLE ROW (R-175.1, the E-31/E-32/E-34 cure): the card
  // renders the cycle projection as ONE row naming every lane — the
  // ✓-then-✗ pair within one cycle is UNREPRESENTABLE from this seat on.
  // Pre-v3.35 history (no cycle row yet) keeps the legacy pair byte-true.
  let cycleRow = null
  try { cycleRow = (await chrome.storage.local.get('ucrypt:lastCycle'))['ucrypt:lastCycle'] || null } catch { cycleRow = null }
  ledger.textContent = cycleRow ? cycleRowLine(cycleRow) : (pushLine + ' · ' + pullLine)
  statusEl.appendChild(ledger)
  // R175 — THE LIVING AFFORDANCE (R-175.4, the E-32 cure): Test connection's
  // verdict lands HERE — a VISIBLE seat inside the card (the old pass
  // rendered into #twResult, the closed wizard's hidden element: the owner
  // pressed the button and the answer went nowhere). The press always lands
  // a verdict: the running state, the ✓ row, or the typed ✗ row.
  const testOut = document.createElement('p')
  testOut.className = 'card-help sync-test-result'
  testOut.style.margin = '0'
  testOut.hidden = true
  statusEl.appendChild(testOut)
  // R176 — R-176.6 THE ONE-CLICK ROAD HOME: when the newest cycle's failed
  // lane is the auth family (the sign-in needs the owner again), the ROW
  // ITSELF carries the affordance — "Sign back in — one click" — opening
  // the connect window directly. The road home is one click FROM the
  // failure, never a hunt for the Connect button (R-172.3 at row depth).
  try {
    const c6 = (await chrome.storage.local.get('ucrypt:lastCycle'))['ucrypt:lastCycle']
    const failedLane = c6 && c6.verdict === 'failed' && Array.isArray(c6.lanes) ? c6.lanes.find((l) => l.ok === false) : null
    const failedWords = String((failedLane && failedLane.words) || '')
    const authFamily = /sign.in|expired|Connect|auth|Google said|banked key/i.test(failedWords)
    if (failedLane && failedLane.lane === 'push' && authFamily && record && record.id === 'gdrive') {
      const road = document.createElement('button')
      road.className = 'btn btn-outline btn-sm sync-road-home'
      road.type = 'button'
      road.textContent = getMessage('roadHomeOneClick', undefined, 'Sign back in — one click')
      road.addEventListener('click', () => {
        try { reconnectViaWizard(record.id) } catch { openSyncOverlay('cloudOverlay') }
      })
      const roadRow = document.createElement('p')
      roadRow.className = 'card-help'
      roadRow.style.margin = '4px 0 0'
      roadRow.appendChild(road)
      statusEl.appendChild(roadRow)
    }
  } catch { /* the road home is additive — its absence renders the old card */ }
  // R170 §A1 — the fire exception: a FAILED last push is an active warning
  // whose seat lives inside the collapsed "Cloud backup" area — it reveals.
  if (info.lastPush && info.lastPush.ok === false) {
    try { SettledHouse.reveal('cloud-backup') } catch { /* the ledger still paints */ }
  }
  const mk = (label, fn, cls = 'btn-outline') => {
    const b = document.createElement('button')
    b.className = `btn ${cls} btn-sm`
    b.type = 'button'
    b.textContent = label
    b.addEventListener('click', fn)
    return b
  }
  actionsEl.appendChild(mk(getMessage('cloudBackupTest', undefined, 'Test connection'), () => testCurrentTransport(testOut, { formForbidden: true })))
  actionsEl.appendChild(mk(getMessage('cloudBackupEdit', undefined, 'Edit setup…'), () => {
    wizardEditMode = true
    openTransportWizard(record.id)
  }))
  actionsEl.appendChild(mk(getMessage('cloudBackupSync', undefined, 'Sync now'), async () => {
    try {
      const r = await bgSend('SYNC_NOW')
      if (r && r.result && r.result.conflictDetected) {
        toast(getMessage('vcrToastDetected', undefined, 'Vault hash mismatch detected — choose Local, Cloud, or Smart Merge in Conflict Resolver below.'), 'error')
      } else {
        toast(r && r.ok ? getMessage('cloudBackupSyncOk', undefined, 'Sync finished.') : ((r && r.error) || getMessage('cloudBackupSyncFail', undefined, 'Sync failed — see the ledger below.')), r && r.ok ? 'ok' : 'error')
      }
      renderCloudBackupBlock().catch(() => {})
      renderVaultConflictResolver().catch(() => {})
    } catch (e) { toast(String(e && e.message || e), 'error') }
  }, 'btn-primary'))
  actionsEl.appendChild(mk(getMessage('cloudBackupDisconnect', undefined, 'Disconnect…'), async () => {
    const ok = confirm(getMessage('tsDisconnectConfirm', [tName], `Disconnect ${tName}? UCrypt stops syncing to it on this device; the cloud copy stays.`))
    if (!ok) return
    const r = await bgSend('TRANSPORT_CLEAR')
    if (r && r.ok) {
      toast(getMessage('toastTransportDisconnected', [tName], `${tName} disconnected — syncing stopped on this device.`), 'info')
      renderTransportGrid('')
      refreshChecklist().catch(() => {})
    } else {
      toast((r && r.error) || 'Disconnect failed', 'error')
    }
    renderCloudBackupBlock().catch(() => {})
  }, 'btn-ghost'))
  if (countEl) countEl.textContent = getMessage('blockCloudCountOn', undefined, 'Connected — status at a glance, and four actions: test · edit · sync · disconnect.')
  renderAutoSyncRetryFeedback().catch(() => {})
}

/**
 * UCRYPT-16 / UCRYPT-18 — Vault Hash Mismatch Conflict Resolver UI.
 * Allows users to inspect SHA-256 canonical vault hashes and per-entry diffs
 * when Local and Cloud vaults diverge during merge, and manually choose:
 *   - 'local': Keep Local Vault & overwrite Cloud
 *   - 'cloud': Adopt Cloud Vault & replace Local
 *   - 'merge': Smart Merge & preserve conflicting passwords in entry.history
 */
function shortHash(h) {
  const s = String(h || '').trim()
  if (!s) return '—'
  return s.length > 20 ? `${s.slice(0, 12)}…${s.slice(-8)}` : s
}

let _vcrInitialBootDone = false
let _vcrAutoCheckedOnOpen = false

async function renderVaultConflictResolver() {
  const card = $('vaultConflictResolverCard')
  if (!card) return
  let resp = null
  try { resp = await bgSend('VAULT_CONFLICT_STATUS') } catch { resp = null }
  const policy = (resp && resp.policy) || 'auto'
  const conflict = (resp && resp.conflict) || null
  const toggle = $('vcrManualPolicyToggle')
  if (toggle) toggle.checked = policy === 'manual'

  const badge = $('vcrStateBadge')
  const banner = $('vcrBanner')
  const bannerTitle = $('vcrBannerTitle')
  const bannerPill = $('vcrBannerPill')
  const bannerSub = $('vcrBannerSub')
  const conflictChip = $('syncChipConflict')
  const conflictChipText = $('syncChipConflictText')

  const localHashEl = $('vcrLocalHash')
  const localCountEl = $('vcrLocalCount')
  const localTimeEl = $('vcrLocalTime')
  const cloudHashEl = $('vcrCloudHash')
  const cloudCountEl = $('vcrCloudCount')
  const cloudTimeEl = $('vcrCloudTime')
  const mergedHashEl = $('vcrMergedHash')
  const mergedCountEl = $('vcrMergedCount')

  const btnLocal = $('vcrChooseLocalBtn')
  const btnCloud = $('vcrChooseCloudBtn')
  const btnMerge = $('vcrChooseMergeBtn')
  const btnDeleteCloud = $('vcrDeleteCloudBtn')
  const diffBox = $('vcrDiffBox')
  const diffSummary = $('vcrDiffSummary')
  const diffList = $('vcrDiffList')

  const isActive = !!(conflict && conflict.active)
  const hasUnresolvedMismatch = !!(conflict && (conflict.active || (conflict.hasConflict && !conflict.resolvedAt && !conflict.autoMerged)))
  const canAct = !!(resp ? (resp.canResolve !== false) : true)

  const localHashVal = (conflict && conflict.localHash) || (resp && resp.currentLocalHash) || null
  const localCountVal = (conflict && conflict.localEntryCount != null)
    ? conflict.localEntryCount
    : ((resp && resp.currentLocalCount != null) ? resp.currentLocalCount : null)
  const localTombVal = (conflict && conflict.localTombstoneCount != null)
    ? conflict.localTombstoneCount
    : ((resp && resp.currentLocalTombstoneCount != null) ? resp.currentLocalTombstoneCount : 0)
  const localTimeVal = (conflict && conflict.localUpdatedAt) || (resp && resp.currentLocalLastModified) || null
  const localEntriesLabel = localCountVal != null ? `${localCountVal} entries` : '0 entries'

  // UCRYPT-32: Keep Conflict Resolver collapsed on page load unless there is an active conflict to resolve.
  if (!_vcrInitialBootDone) {
    _vcrInitialBootDone = true
    if (isActive) {
      card.setAttribute('data-fire-revealed', 'true')
      try { SettledHouse.reveal('conflict-resolver') } catch { /* best-effort */ }
      card.open = true
      card.setAttribute('open', '')
    } else {
      card.removeAttribute('data-fire-revealed')
      card.open = false
      card.removeAttribute('open')
    }
  } else if (isActive) {
    card.setAttribute('data-fire-revealed', 'true')
    try { SettledHouse.reveal('conflict-resolver') } catch { /* best-effort */ }
    card.open = true
    card.setAttribute('open', '')
  }

  if (conflictChip) {
    conflictChip.classList.toggle('hidden', !isActive)
    conflictChip.hidden = !isActive
    if (isActive && conflictChipText) {
      const n = Number(conflict.conflictCount || (conflict.conflicts && conflict.conflicts.length) || 1)
      conflictChipText.textContent = `⚠ Hash mismatch (${n} conflict${n === 1 ? '' : 's'}) — resolve`
    }
  }

  if (banner) {
    banner.classList.remove('hidden')
    banner.hidden = false
  }

  if (isActive || hasUnresolvedMismatch) {
    if (badge) {
      badge.textContent = getMessage('vcrStateMismatch', undefined, '⚠ Conflict detected — manual resolution required')
      badge.style.color = '#fbbf24'
      badge.style.background = 'rgba(245,158,11,0.16)'
      badge.style.borderColor = 'rgba(245,158,11,0.45)'
    }
    if (banner) {
      banner.style.border = '1px solid rgba(245,158,11,0.55)'
      banner.style.background = 'rgba(245,158,11,0.12)'
    }
    if (bannerTitle) {
      bannerTitle.style.color = '#fbbf24'
      bannerTitle.textContent = getMessage('vcrBannerTitleActive', undefined, '⚠ CONFLICT DETECTED — Local and Cloud vaults have diverged')
    }
    if (bannerPill) {
      bannerPill.textContent = 'CONFLICT FOUND'
      bannerPill.style.background = 'rgba(245,158,11,0.22)'
      bannerPill.style.color = '#fbbf24'
      bannerPill.style.border = '1px solid rgba(245,158,11,0.45)'
    }
    if (bannerSub) {
      const cCount = Number((conflict && conflict.conflictCount) || 1)
      const dCount = Number((conflict && conflict.diffCount) || cCount)
      bannerSub.textContent = `Local SHA-256 (${shortHash(localHashVal)}) and Cloud SHA-256 (${shortHash(conflict && conflict.remoteHash)}) do not match (${cCount} direct entry conflict${cCount === 1 ? '' : 's'}, ${dCount} total entry diff${dCount === 1 ? '' : 's'}). Choose an action below: Use Local Version, Use Cloud Version, Merge Both, or Delete the Conflicted Cloud Copy.`
    }
  } else {
    if (banner) {
      banner.style.border = '1px solid rgba(34,197,94,0.45)'
      banner.style.background = 'rgba(34,197,94,0.10)'
    }
    if (bannerTitle) {
      bannerTitle.style.color = '#4ade80'
      bannerTitle.textContent = '✓ NO CONFLICT FOUND — Everything is fine. Local and Cloud vaults are in sync.'
    }
    if (bannerPill) {
      bannerPill.textContent = 'NO CONFLICT'
      bannerPill.style.background = 'rgba(34,197,94,0.20)'
      bannerPill.style.color = '#4ade80'
      bannerPill.style.border = '1px solid rgba(34,197,94,0.40)'
    }
    if (conflict && conflict.resolvedAt) {
      const resolvedLabel = conflict.resolvedChoice === 'delete-cloud'
        ? 'Deleted Cloud Copy (Kept Local)'
        : (conflict.resolvedChoice || 'merge')
      if (badge) {
        badge.textContent = `✓ No conflict · Resolved (${resolvedLabel})`
        badge.style.color = '#4ade80'
        badge.style.background = 'rgba(34,197,94,0.14)'
        badge.style.borderColor = 'rgba(34,197,94,0.35)'
      }
      if (bannerSub) {
        bannerSub.textContent = conflict.deletedCloud
          ? `Remote conflicted cloud copy was deleted at ${new Date(conflict.resolvedAt).toLocaleTimeString()}. Your local vault (${localEntriesLabel}, SHA-256 ${shortHash(localHashVal)}) is intact and conflict-free.`
          : `Last conflict was resolved using "${resolvedLabel}" at ${new Date(conflict.resolvedAt).toLocaleTimeString()}. Local and Cloud vaults match (${localEntriesLabel}, SHA-256 ${shortHash(localHashVal)}).`
      }
    } else if (conflict && conflict.autoMerged) {
      if (badge) {
        badge.textContent = `✓ No conflict · Auto-merged (${conflict.conflictCount || 1} saved in history)`
        badge.style.color = '#4ade80'
        badge.style.background = 'rgba(34,197,94,0.14)'
        badge.style.borderColor = 'rgba(34,197,94,0.35)'
      }
      if (bannerSub) {
        bannerSub.textContent = `Automatic Smart Merge unified Local and Cloud changes and preserved ${conflict.conflictCount || 1} conflicting password(s) in entry history. Both vaults are now in sync (SHA-256 ${shortHash(localHashVal)}).`
      }
    } else {
      if (badge) {
        badge.textContent = getMessage('vcrStateClean', undefined, '✓ No conflict — Hashes in sync')
        badge.style.color = '#4ade80'
        badge.style.background = 'rgba(34,197,94,0.14)'
        badge.style.borderColor = 'rgba(34,197,94,0.35)'
      }
      if (bannerSub) {
        if (conflict && conflict.localHash && conflict.remoteHash && conflict.localHash === conflict.remoteHash) {
          bannerSub.textContent = `Verified canonical SHA-256 digest ${shortHash(conflict.localHash)} matches across This Device and Cloud Backup (${localEntriesLabel}). Zero conflicts detected — all vault resolution and cloud management actions below remain unlocked if needed.`
        } else {
          bannerSub.textContent = `Zero vault conflicts detected (${localEntriesLabel}${localHashVal ? ' · Local SHA-256 ' + shortHash(localHashVal) : ''}). Click "Compare Local vs. Cloud Hashes Now" anytime to verify live cloud digests, or use any vault action below.`
        }
      }
    }
  }

  if (localHashEl) {
    localHashEl.textContent = localHashVal ? shortHash(localHashVal) : '—'
    localHashEl.title = localHashVal || ''
  }
  if (localCountEl) {
    localCountEl.textContent = localCountVal != null
      ? `${localCountVal} entries · ${localTombVal} tombstones`
      : '— entries'
  }
  if (localTimeEl) {
    localTimeEl.textContent = localTimeVal
      ? `Updated: ${new Date(localTimeVal).toLocaleString()}`
      : 'Updated: —'
  }

  const remoteDeleted = !!(conflict && conflict.deletedCloud)
  const remoteHashVal = remoteDeleted ? null : ((conflict && conflict.remoteHash) || null)
  const remoteCountVal = remoteDeleted ? null : ((conflict && conflict.remoteEntryCount != null) ? conflict.remoteEntryCount : null)
  const remoteTombVal = (conflict && conflict.remoteTombstoneCount != null) ? conflict.remoteTombstoneCount : 0
  const remoteTimeVal = remoteDeleted ? null : ((conflict && conflict.remoteUpdatedAt) || null)

  if (cloudHashEl) {
    cloudHashEl.textContent = remoteDeleted
      ? 'Deleted (none on cloud)'
      : (remoteHashVal ? shortHash(remoteHashVal) : (localHashVal && conflict && conflict.inSync ? shortHash(localHashVal) : '—'))
    cloudHashEl.title = remoteHashVal || ''
  }
  if (cloudCountEl) {
    cloudCountEl.textContent = remoteDeleted
      ? '0 entries (cloud copy removed)'
      : (remoteCountVal != null
          ? `${remoteCountVal} entries · ${remoteTombVal} tombstones`
          : 'Click "Compare Hashes Now" to inspect')
  }
  if (cloudTimeEl) {
    cloudTimeEl.textContent = remoteDeleted
      ? `Deleted: ${new Date(conflict.resolvedAt).toLocaleString()}`
      : (remoteTimeVal
          ? `Updated: ${new Date(remoteTimeVal).toLocaleString()}`
          : 'Updated: —')
  }

  const mergedHashVal = (conflict && conflict.mergedHash) || localHashVal || null
  const mergedCountVal = (conflict && conflict.mergedEntryCount != null) ? conflict.mergedEntryCount : localCountVal

  if (mergedHashEl) {
    mergedHashEl.textContent = mergedHashVal ? shortHash(mergedHashVal) : '—'
    mergedHashEl.title = mergedHashVal || ''
  }
  if (mergedCountEl) {
    mergedCountEl.textContent = mergedCountVal != null
      ? `${mergedCountVal} entries · conflict passwords kept in history`
      : '— entries (conflict copies preserved)'
  }

  if (btnLocal) btnLocal.disabled = !canAct
  if (btnCloud) btnCloud.disabled = !canAct
  if (btnMerge) btnMerge.disabled = !canAct
  if (btnDeleteCloud) btnDeleteCloud.disabled = !canAct

  const diffs = (conflict && Array.isArray(conflict.diffs) && conflict.diffs.length)
    ? conflict.diffs
    : ((conflict && Array.isArray(conflict.conflicts)) ? conflict.conflicts : [])

  if (diffBox && diffList && diffSummary) {
    if (diffs.length > 0) {
      diffBox.classList.remove('hidden')
      diffBox.hidden = false
      diffSummary.textContent = `Inspecting ${diffs.length} differing entr${diffs.length === 1 ? 'y' : 'ies'} (${conflict.conflictCount || 0} direct hash conflict${(conflict.conflictCount || 0) === 1 ? '' : 's'})`
      diffList.textContent = ''
      for (const d of diffs) {
        const li = document.createElement('li')
        li.style.cssText = 'padding:6px 8px;border-radius:6px;background:rgba(255,255,255,0.03);border:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap'
        const left = document.createElement('div')
        const kindBadge = document.createElement('span')
        kindBadge.style.cssText = 'display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-right:6px;text-transform:uppercase'
        if (d.kind === 'content-mismatch') {
          kindBadge.textContent = 'LOCAL ≠ CLOUD'
          kindBadge.style.background = 'rgba(245,158,11,0.2)'
          kindBadge.style.color = '#fbbf24'
        } else if (d.kind === 'delete-vs-edit') {
          kindBadge.textContent = 'DELETE vs EDIT'
          kindBadge.style.background = 'rgba(239,68,68,0.2)'
          kindBadge.style.color = '#f87171'
        } else if (d.kind === 'local-only') {
          kindBadge.textContent = 'LOCAL ONLY'
          kindBadge.style.background = 'rgba(59,130,246,0.2)'
          kindBadge.style.color = '#60a5fa'
        } else {
          kindBadge.textContent = 'CLOUD ONLY'
          kindBadge.style.background = 'rgba(16,185,129,0.2)'
          kindBadge.style.color = '#34d399'
        }
        left.appendChild(kindBadge)
        const title = document.createElement('strong')
        title.textContent = `${d.domain || '(global)'}${d.username ? ' · ' + d.username : ''}`
        left.appendChild(title)
        const typeSpan = document.createElement('span')
        typeSpan.className = 'card-help'
        typeSpan.style.marginLeft = '6px'
        typeSpan.textContent = `[${d.type || 'login'}]`
        left.appendChild(typeSpan)

        const right = document.createElement('span')
        right.className = 'card-help'
        right.style.fontSize = '11px'
        const parts = []
        if (d.passwordDiffers) parts.push('🔑 Passwords differ (Smart Merge saves both)')
        if (d.localUpdatedAt) parts.push(`Local: ${new Date(d.localUpdatedAt).toLocaleTimeString()}`)
        if (d.remoteUpdatedAt) parts.push(`Cloud: ${new Date(d.remoteUpdatedAt).toLocaleTimeString()}`)
        right.textContent = parts.join(' · ')
        li.appendChild(left)
        li.appendChild(right)
        diffList.appendChild(li)
      }
    } else {
      diffBox.classList.add('hidden')
      diffBox.hidden = true
      diffList.textContent = ''
    }
  }
}

function initVaultConflictResolver() {
  const card = $('vaultConflictResolverCard')
  if (!card || card.dataset.wired === '1') return
  card.dataset.wired = '1'

  const resultEl = $('vcrResult')
  const showResult = (msg, ok = true) => {
    if (!resultEl) return
    resultEl.hidden = false
    resultEl.classList.remove('hidden')
    resultEl.className = `sync-test-result ${ok ? 'ok' : 'err'}`
    resultEl.textContent = msg
  }

  // When user expands Conflict Resolver manually, auto-run a live hash check if not yet compared
  card.addEventListener('toggle', () => {
    if (card.open && !_vcrAutoCheckedOnOpen) {
      _vcrAutoCheckedOnOpen = true
      bgSend('VAULT_CONFLICT_CHECK_NOW')
        .then(() => renderVaultConflictResolver())
        .catch(() => {})
    }
  })

  $('vcrManualPolicyToggle')?.addEventListener('change', async (e) => {
    const manual = !!(e.target && e.target.checked)
    try {
      const r = await bgSend('VAULT_CONFLICT_SET_POLICY', { policy: manual ? 'manual' : 'auto' })
      if (r && r.ok) {
        toast(manual
          ? 'Manual Conflict Resolver enabled — sync will pause on any Local vs Cloud hash mismatch.'
          : 'Auto-merge enabled — conflicting passwords are still preserved in entry history.', 'info')
      }
      await renderVaultConflictResolver()
    } catch (err) {
      toast(String((err && err.message) || err), 'error')
    }
  })

  $('vcrCheckNowBtn')?.addEventListener('click', async () => {
    const btn = $('vcrCheckNowBtn')
    if (btn) btn.disabled = true
    showResult('Checking Local vs Cloud SHA-256 vault hashes…', true)
    try {
      const r = await bgSend('VAULT_CONFLICT_CHECK_NOW')
      if (!r || !r.ok) {
        showResult('✗ ' + ((r && r.error) || 'Could not compare vault hashes — verify your vault is unlocked and cloud is connected.'), false)
      } else if (r.inSync) {
        if (r.noRemoteCopy) {
          showResult(`✓ No conflict found — Local vault has ${r.entryCount || 0} entries (SHA-256 ${shortHash(r.localHash)}). No remote cloud backup exists yet.`, true)
        } else {
          showResult(`✓ NO CONFLICT FOUND — Local and Cloud vaults are in sync (SHA-256 ${shortHash(r.localHash)} · ${r.entryCount || 0} entries).`, true)
        }
      } else if (r.conflict) {
        const c = r.conflict
        if (c.hasConflict) {
          showResult(`⚠ CONFLICT DETECTED: Local (${shortHash(c.localHash)}) ≠ Cloud (${shortHash(c.remoteHash)}) — ${c.conflictCount} entry conflict(s). Choose Local, Cloud, Smart Merge, or Delete Cloud Copy above.`, false)
        } else {
          showResult(`ℹ Local (${shortHash(c.localHash)}) and Cloud (${shortHash(c.remoteHash)}) have ${c.diffCount} non-conflicting addition(s) ready to merge.`, true)
        }
      }
      await renderVaultConflictResolver()
    } catch (err) {
      showResult('✗ ' + String((err && err.message) || err), false)
    } finally {
      if (btn) btn.disabled = false
    }
  })

  const handleResolve = async (choice, label) => {
    const btns = [$('vcrChooseLocalBtn'), $('vcrChooseCloudBtn'), $('vcrChooseMergeBtn'), $('vcrDeleteCloudBtn')]
    btns.forEach(b => { if (b) b.disabled = true })
    showResult(`Applying ${label}…`, true)
    try {
      const r = await bgSend('VAULT_CONFLICT_RESOLVE', { choice })
      if (r && r.ok) {
        if (choice === 'delete-cloud') {
          showResult(`✓ Conflicted cloud vault copy deleted. Local vault kept intact (${r.entryCount ?? 0} entries, SHA-256 ${shortHash(r.hash)}).`, true)
          toast('✓ Cloud vault copy deleted — local vault kept intact.', 'ok')
        } else {
          const pushedNote = r.pushed ? ' and pushed to Cloud' : ''
          showResult(`✓ Vault updated using ${label} (${r.entryCount ?? 0} entries, SHA-256 ${shortHash(r.hash)})${pushedNote}.`, true)
          toast(`✓ Vault resolved (${label}).`, 'ok')
        }
        await renderVaultConflictResolver()
        await renderCloudBackupBlock().catch(() => {})
        await renderSyncStatusStrip().catch(() => {})
        if (typeof refreshVault === 'function') refreshVault()
      } else {
        showResult('✗ ' + ((r && r.error) || 'Could not apply vault resolution action.'), false)
        toast((r && r.error) || 'Vault action failed', 'error')
      }
    } catch (err) {
      showResult('✗ ' + String((err && err.message) || err), false)
    } finally {
      await renderVaultConflictResolver().catch(() => {})
    }
  }

  $('vcrChooseLocalBtn')?.addEventListener('click', () => handleResolve('local', 'Local Device Version'))
  $('vcrChooseCloudBtn')?.addEventListener('click', () => handleResolve('cloud', 'Cloud Backup Version'))
  $('vcrChooseMergeBtn')?.addEventListener('click', () => handleResolve('merge', 'Smart Merge (with conflict history)'))
  $('vcrDeleteCloudBtn')?.addEventListener('click', async () => {
    const ok = await confirmAction(
      'Delete Cloud Vault Copy?',
      'This will delete the encrypted vault copy currently stored in your cloud backup while keeping your Local Vault on this device completely intact. Continue?'
    )
    if (!ok) return
    await handleResolve('delete-cloud', 'Delete Cloud Conflicted Copy (Keep Local)')
  })

  try {
    if (chrome && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && (changes['ucrypt:vaultConflict'] || changes['ucrypt:vaultConflictPolicy'])) {
          renderVaultConflictResolver().catch(() => {})
        }
      })
    }
    if (chrome && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg && msg.type === 'UCRYPT_VAULT_CONFLICT_CHANGED') {
          renderVaultConflictResolver().catch(() => {})
        }
      })
    }
  } catch { /* best-effort listener wiring */ }

  renderVaultConflictResolver().catch(() => {})
}

/**
 * UCRYPT-19 / UCRYPT-20 — Exponential Backoff Retry Visual Feedback & Live Controls
 * Renders live status across the Cloud sync status section (#sdAutoSyncRetryBanner,
 * #syncChipRetry, #sdAutoSyncNext, #cloudBackupRetryStatus, and #sdState) when
 * automatic syncs fail due to temporary network issues.
 */
let _autoSyncRetryCountdownTimer = null
let _lastAutoSyncStateCache = null

function stopAutoSyncRetryTicker() {
  if (_autoSyncRetryCountdownTimer) {
    clearInterval(_autoSyncRetryCountdownTimer)
    _autoSyncRetryCountdownTimer = null
  }
}

function paintAutoSyncRetryDom(autoSync) {
  const st = autoSync || _lastAutoSyncStateCache || null
  if (autoSync) _lastAutoSyncStateCache = autoSync

  const banner = $('sdAutoSyncRetryBanner')
  const spinner = $('sdAutoSyncRetrySpinner')
  const headline = $('sdAutoSyncRetryHeadline')
  const badge = $('sdAutoSyncRetryBadge')
  const detail = $('sdAutoSyncRetryDetail')
  const schedRow = $('sdAutoSyncRetryScheduleRow')
  const retryNowBtn = $('sdAutoSyncRetryNowBtn')
  const cancelBtn = $('sdAutoSyncRetryCancelBtn')
  const retryChip = $('syncChipRetry')
  const retryChipText = $('syncChipRetryText')
  const cloudBackupRetry = $('cloudBackupRetryStatus')
  const nextEl = $('sdAutoSyncNext')

  const inFlight = !!(st && st.inFlight)
  const retrying = !!(st && st.retrying && Number(st.retryNextAt) > 0)
  const exhausted = !!(st && st.exhausted)
  const active = inFlight || retrying || exhausted

  const attempt = Math.max(1, Number(st && st.retryCount) || 1)
  const maxRetries = Math.max(1, Number(st && st.maxRetries) || 6)
  const backoffSec = Number(st && st.backoffSeconds) || Math.max(15, Math.round((Number(st && st.backoffMs) || 15000) / 1000))
  const retryNextAt = Number(st && st.retryNextAt) || 0
  const remainSec = retryNextAt > 0 ? Math.max(0, Math.ceil((retryNextAt - Date.now()) / 1000)) : 0
  const errWords = String((st && st.lastError) || 'Temporary network failure').trim()
  const schedule = (st && Array.isArray(st.scheduleSeconds) && st.scheduleSeconds.length)
    ? st.scheduleSeconds
    : [15, 30, 60, 120, 240, 480]

  if (retryChip) {
    retryChip.classList.toggle('hidden', !active)
    retryChip.hidden = !active
    if (active && retryChipText) {
      if (inFlight) {
        retryChip.dataset.state = 'warn'
        retryChipText.textContent = `🔄 Auto-sync retrying now (attempt ${attempt}/${maxRetries})…`
      } else if (retrying) {
        retryChip.dataset.state = 'warn'
        retryChipText.textContent = `⏳ Auto-sync retry #${attempt}/${maxRetries} in ${remainSec}s (${backoffSec}s backoff)`
      } else {
        retryChip.dataset.state = 'err'
        retryChipText.textContent = `⚠ Auto-sync retries exhausted (${maxRetries}/${maxRetries}) — click to retry`
      }
    }
  }

  if (cloudBackupRetry) {
    cloudBackupRetry.classList.toggle('hidden', !active)
    cloudBackupRetry.hidden = !active
    if (active) {
      if (inFlight) {
        cloudBackupRetry.textContent = `🔄 Exponential backoff retry in progress: running attempt ${attempt} of ${maxRetries} now…`
      } else if (retrying) {
        cloudBackupRetry.textContent = `⏳ Temporary network issue (${errWords}) — automatic exponential backoff retry #${attempt} of ${maxRetries} scheduled in ${remainSec}s (${backoffSec}s delay).`
      } else {
        cloudBackupRetry.textContent = `⚠ Automatic sync paused after ${maxRetries} exponential backoff attempts (${errWords}). Press “Sync now” below or “Retry sync now” above.`
      }
    } else {
      cloudBackupRetry.textContent = ''
    }
  }

  if (!banner) return

  if (!active) {
    banner.classList.add('hidden')
    banner.hidden = true
    stopAutoSyncRetryTicker()
    return
  }

  banner.classList.remove('hidden')
  banner.hidden = false

  if (schedRow) {
    const stepsText = schedule.map((sec, idx) => {
      const stepNum = idx + 1
      if (exhausted) return `${sec}s ✓`
      if (stepNum < attempt) return `${sec}s ✓`
      if (stepNum === attempt) return `[#${stepNum}: ${sec}s]`
      return `${sec}s`
    }).join(' → ')
    schedRow.textContent = `Backoff schedule: ${stepsText}`
  }

  if (inFlight) {
    if (spinner) spinner.textContent = '🔄'
    if (headline) headline.textContent = getMessage('sdRetryHeadlineInFlight', [String(attempt), String(maxRetries)], `Retrying automatic cloud sync now (attempt ${attempt} of ${maxRetries})…`)
    if (badge) badge.textContent = `Attempt ${attempt} of ${maxRetries} · in progress`
    if (detail) detail.textContent = `Re-probing cloud connection after temporary network failure (${errWords}).`
    if (retryNowBtn) {
      retryNowBtn.disabled = true
      retryNowBtn.textContent = getMessage('sdRetryNowBusy', undefined, 'Retrying…')
    }
    if (cancelBtn) {
      cancelBtn.hidden = false
      cancelBtn.classList.remove('hidden')
    }
  } else if (retrying) {
    if (spinner) spinner.textContent = '⏳'
    if (headline) {
      headline.textContent = remainSec > 0
        ? getMessage('sdRetryHeadlineCountdown', [String(remainSec)], `Automatic sync retry in ${remainSec}s — waiting for network recovery`)
        : getMessage('sdRetryHeadlineFiring', undefined, 'Automatic sync retry firing now…')
    }
    if (badge) badge.textContent = `Attempt ${attempt} of ${maxRetries} · ${backoffSec}s backoff`
    if (detail) {
      detail.textContent = `Temporary network issue detected (${errWords}). UCrypt is automatically retrying with exponential backoff so your encrypted vault syncs as soon as the network recovers.`
    }
    if (retryNowBtn) {
      retryNowBtn.disabled = false
      retryNowBtn.textContent = getMessage('sdRetryNowBtn', undefined, '↻ Retry sync now')
    }
    if (cancelBtn) {
      cancelBtn.hidden = false
      cancelBtn.classList.remove('hidden')
      cancelBtn.textContent = getMessage('sdRetryCancelBtn', undefined, 'Cancel automatic retry')
    }
  } else if (exhausted) {
    if (spinner) spinner.textContent = '⚠'
    if (headline) headline.textContent = getMessage('sdRetryHeadlineExhausted', [String(maxRetries)], `Automatic sync retries exhausted (${maxRetries} of ${maxRetries} attempts)`)
    if (badge) badge.textContent = `Paused · ${maxRetries}/${maxRetries} attempts`
    if (detail) {
      detail.textContent = `Temporary network issue persisted across ${maxRetries} exponential backoff attempts (${errWords}). Check your internet connection and press “Retry sync now”.`
    }
    if (retryNowBtn) {
      retryNowBtn.disabled = false
      retryNowBtn.textContent = getMessage('sdRetryNowBtn', undefined, '↻ Retry sync now')
    }
    if (cancelBtn) {
      cancelBtn.hidden = false
      cancelBtn.classList.remove('hidden')
      cancelBtn.textContent = getMessage('sdRetryDismissBtn', undefined, 'Dismiss')
    }
  }

  if (nextEl && st) {
    const mins = Number(st.minutes) || 15
    if (inFlight) {
      nextEl.textContent = `🔄 Retrying automatic cloud sync now (attempt ${attempt} of ${maxRetries}) · Auto-sync every ${mins} min`
    } else if (retrying) {
      nextEl.textContent = `⏳ Exponential backoff retry #${attempt}/${maxRetries} in ${remainSec}s (${backoffSec}s delay) · Auto-sync every ${mins} min`
    }
  }

  if (retrying && retryNextAt > Date.now()) {
    if (!_autoSyncRetryCountdownTimer) {
      _autoSyncRetryCountdownTimer = setInterval(() => {
        if (!_lastAutoSyncStateCache || !_lastAutoSyncStateCache.retrying) {
          stopAutoSyncRetryTicker()
          return
        }
        paintAutoSyncRetryDom(_lastAutoSyncStateCache)
      }, 1000)
    }
  } else {
    stopAutoSyncRetryTicker()
  }
}

async function renderAutoSyncRetryFeedback(autoSyncOverride = null) {
  let st = autoSyncOverride
  if (!st) {
    try {
      const r = await bgSend('AUTO_SYNC_RETRY_STATUS')
      if (r && r.ok && r.autoSync) st = r.autoSync
    } catch { st = null }
  }
  if (!st) {
    try {
      const raw = (await chrome.storage.local.get('ucrypt:autoSyncState'))['ucrypt:autoSyncState']
      if (raw && typeof raw === 'object') {
        const retryCount = Number(raw.retryCount) || 0
        const retryNextAt = raw.retryNextAt ? Date.parse(raw.retryNextAt) : 0
        const backoffMs = Number(raw.backoffMs) || 0
        st = {
          minutes: 15,
          retryCount,
          maxRetries: 6,
          retrying: retryCount > 0 && retryNextAt > 0 && !raw.exhausted,
          inFlight: !!raw.inFlight,
          exhausted: !!raw.exhausted,
          backoffMs,
          backoffSeconds: backoffMs ? Math.round(backoffMs / 1000) : 0,
          retryNextAt: Number.isFinite(retryNextAt) ? retryNextAt : 0,
          lastError: String(raw.lastError || ''),
          lastErrorKind: String(raw.lastErrorKind || ''),
          scheduleSeconds: [15, 30, 60, 120, 240, 480],
        }
      }
    } catch { st = null }
  }
  paintAutoSyncRetryDom(st)
}

function initAutoSyncRetryControls() {
  const banner = $('sdAutoSyncRetryBanner')
  if (!banner || banner.dataset.wired === '1') return
  banner.dataset.wired = '1'

  $('sdAutoSyncRetryNowBtn')?.addEventListener('click', async () => {
    const btn = $('sdAutoSyncRetryNowBtn')
    if (btn) {
      btn.disabled = true
      btn.textContent = getMessage('sdRetryNowBusy', undefined, 'Retrying…')
    }
    try {
      const r = await bgSend('AUTO_SYNC_RETRY_NOW')
      if (r && r.ok) {
        toast(getMessage('sdRetryToastOk', undefined, '✓ Automatic cloud sync succeeded — exponential backoff cleared.'), 'ok')
      } else {
        const nextWait = r && r.retry && r.retry.backoffSeconds ? ` Next retry in ${r.retry.backoffSeconds}s.` : ''
        toast(((r && r.error) || 'Cloud sync retry could not reach the server.') + nextWait, 'error')
      }
    } catch (e) {
      toast(String((e && e.message) || e), 'error')
    } finally {
      await renderAutoSyncRetryFeedback().catch(() => {})
      await renderCloudBackupBlock().catch(() => {})
      await renderSyncStatusStrip().catch(() => {})
      refreshSyncDevicesCardFresh().catch(() => {})
    }
  })

  $('sdAutoSyncRetryCancelBtn')?.addEventListener('click', async () => {
    try {
      await bgSend('AUTO_SYNC_RETRY_CANCEL')
      toast(getMessage('sdRetryCancelledToast', undefined, 'Automatic backoff retry cancelled — regular auto-sync schedule remains active.'), 'info')
    } catch (e) {
      toast(String((e && e.message) || e), 'error')
    } finally {
      await renderAutoSyncRetryFeedback().catch(() => {})
      refreshSyncDevicesCardFresh().catch(() => {})
    }
  })

  try {
    if (chrome && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes['ucrypt:autoSyncState']) {
          renderAutoSyncRetryFeedback().catch(() => {})
        }
      })
    }
    if (chrome && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg && msg.type === 'UCRYPT_AUTO_SYNC_RETRY_STATE') {
          renderAutoSyncRetryFeedback().catch(() => {})
        }
      })
    }
  } catch { /* best-effort listener wiring */ }

  renderAutoSyncRetryFeedback().catch(() => {})
}

/**
 * R77-C — Direct-transfer availability card. Mirrors the LITERAL worker
 * transfer-plane status (availability window, expiry). Never optimistic: the
 * state text comes from the worker's own TRANSFER_STATUS answer, and the
 * buttons enable/disable that single source of truth.
 */
async function refreshDirectTransferCard() {
  const state = $('dtState')
  const enableBtn = $('dtEnableBtn')
  const disableBtn = $('dtDisableBtn')
  if (!state || !enableBtn || !disableBtn) return
  let st = null
  try { st = (await bgSend('TRANSFER_STATUS')) || null } catch { st = null }
  const avail = !!(st && st.ok && st.availability && st.availability.enabled)
  if (avail) {
    const until = st.availability.expiresAt ? new Date(st.availability.expiresAt).toLocaleTimeString() : ''
    state.textContent = getMessage('dtStateOn', undefined, `Available until ${until}`)
    state.style.color = 'var(--accent)'
    enableBtn.classList.add('hidden'); enableBtn.hidden = true
    disableBtn.classList.remove('hidden'); disableBtn.hidden = false
  } else {
    state.textContent = getMessage('dtStateOff', undefined, 'Off')
    state.style.color = ''
    enableBtn.classList.remove('hidden'); enableBtn.hidden = false
    disableBtn.classList.add('hidden'); disableBtn.hidden = true
  }
  // A locked vault cannot enable availability — the worker answers with
  // locked error; surface the disabled buttons state truthfully.
  enableBtn.disabled = !!(st && st.ok === false)
}

async function initDirectTransferCard() {
  // R129 GRAND AUDIT (the code-quality pass — CQ-ORPHAN-LISTENER): the R77-C
  // options-page availability card is DORMANT since R118's two-tab law — the
  // availability capability's live door is the transfer page's own card
  // (transfer.html: the Enable/Off controls + the auto-arm strip). The three
  // dead bindings below targeted ids that exist in NO HTML — every click
  // silently no-opped behind the optional chaining. They are REMOVED (the
  // capability untouched — its live door verified first, 0.31; nothing
  // removed but dead wiring, 0.4).
  // R118 §2.3 — the slim Cloud Sync pointer's click handler is GONE with the
  // pointer card itself (the S1 removal; law 0.31 — the menu's two transfer
  // tabs are the canonical doors; a removed door leaves no hidden wiring).
}

/** Open the add-device box (auth row first; words only appear after the
 *  passphrase re-entry succeeds). */
function addDeviceFlow() {
  const box = $('addDeviceBox')
  // R110 v1.4 (CEO-pinned, law 0.15) — the "Include sign-in credentials"
  // toggle DEFAULTS ON at every sheet arm: the whole credential is the new
  // default behavior; unchecking is the user's explicit config-only choice
  // (the security sentence renders while it is checked).
  const includeToggle = $('pairIncludeCloud')
  if (includeToggle) includeToggle.checked = true
  if (!box) return
  scrubSecretExposure('reopen')
  $('addDeviceAuthRow').classList.remove('hidden')
  $('addDeviceAuthRow').hidden = false
  $('addDeviceAuthResult').className = 'sync-test-result'
  $('addDeviceAuthResult').textContent = ''
  box.classList.remove('hidden')
  box.hidden = false
  // R109 §4.2 — the pairing sheet is a FOCUSED LAYER now (law 0.25): the
  // box lives inside #pairingOverlay; opening the flow opens the layer.
  openSyncOverlay('pairingOverlay')
  $('addDeviceRevealBtn').focus()
}

// === R109 §4.2 — the focused-layer helpers (law 0.25) ======================
// Every sync flow (pairing sheet, join wizard, transport chooser, create
// layer) renders inside a .dialog-overlay. The overlay closes ONLY on the
// user's explicit action (its Close button, a Cancel button wired to
// closeSyncOverlay, or Esc) — law 0.8: no auto-dismiss, no backdrop-click
// dismissal. Focus moves to the dialog on open and restores on close.
let _syncOverlayRestoreFocus = null
function openSyncOverlay(id) {
  const ov = $(id)
  if (!ov) return
  if (!_syncOverlayRestoreFocus) _syncOverlayRestoreFocus = document.activeElement
  ov.classList.remove('hidden')
  ov.hidden = false
  // R170 §A5 — every open of the sync-code dialog starts from the settled
  // state: the success card hides again (it named the PREVIOUS completion;
  // a fresh session of the dialog must not inherit a stale success).
  if (id === 'createOverlay') {
    const sc = $('syncCodeSuccessCard')
    if (sc) { sc.classList.add('hidden'); sc.hidden = true }
  }
  const first = ov.querySelector('button, input, [tabindex]:not([tabindex="-1"])')
  setTimeout(() => { try { first && first.focus() } catch { /* best-effort */ } }, 30)
}
function closeSyncOverlay(id) {
  // R177 — R-177.6 THE CLOSE THAT KEEPS: this seat is READER-ONLY by law —
  // no teardown, no custody clear, no storage write of any kind. The field's
  // owner note ("as soon I close this window it says that I need to sign in
  // again") made every close-time write a suspect; the audit found the close
  // ALREADY clean (it hides DOM and restores focus — nothing else), and the
  // law pins it: a custody clear must prove death (the banked exp truly
  // past) or ride the owner's explicit Disconnect — default KEEP. Nothing is
  // lost by keeping; everything is lost by clearing. The reopen face's
  // honesty is the reopen reader's duty (R-177.1 — openTransportWizard's
  // custody-truth read), never this seat's burden.
  const ov = $(id)
  if (!ov) return
  ov.classList.add('hidden')
  ov.hidden = true
  // R167 — the picker-collapse law's fresh-open state: when the cloud layer
  // closes, the Cloud transport block resets UNCOLLAPSED and the wizard
  // hides — the next open starts uncollapsed, exactly the owner's order.
  if (id === 'cloudOverlay') {
    try {
      const picker = $('transportPicker')
      if (picker) picker.classList.remove('hidden')
    } catch { /* the reset never throws into the close */ }
  }
  if (_syncOverlayRestoreFocus && typeof _syncOverlayRestoreFocus.focus === 'function') {
    try { _syncOverlayRestoreFocus.focus() } catch { /* the opener may be gone */ }
  }
  _syncOverlayRestoreFocus = null
}
function wireSyncOverlays() {
  $('addDeviceClose')?.addEventListener('click', () => closeSyncOverlay('pairingOverlay'))
  $('joinOverlayClose')?.addEventListener('click', () => closeSyncOverlay('joinOverlay'))
  $('cloudOverlayClose')?.addEventListener('click', () => closeSyncOverlay('cloudOverlay'))
  $('createOverlayClose')?.addEventListener('click', () => closeSyncOverlay('createOverlay'))
  // R170 §A5 (E-18) — the success card's explicit Close: the ONLY closer of
  // the sync-code dialog's success state (popup sovereignty — law 0.8: the
  // dialog never closes itself; the user's own hand does).
  $('syncSuccessCloseBtn')?.addEventListener('click', () => closeSyncOverlay('createOverlay'))
  // R119 §2.4 (law 0.30) — the walkthrough overlay's visible ✕ close + the
  // focus return ride the SAME machinery as the other sync layers.
  $('walkthroughOverlayClose')?.addEventListener('click', () => closeSyncOverlay('walkthroughOverlay'))
  $('openSyncCodeLayerBtn')?.addEventListener('click', () => {
    openSyncOverlay('createOverlay')
    $('syncCodePanel').classList.add('hidden')
    $('syncRestorePanel').classList.add('hidden')
  })
  // Esc closes the TOPMOST open sync overlay — an explicit user action (0.8).
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return
    // R119 — the walkthrough overlay opens ON TOP of the cloud layer, so it
    // is checked FIRST (the topmost layer is the one Esc closes).
    // R122 — the acceptance walkthrough opens ON TOP of everything (the
    // re-test's focused layer) — it is checked before them all.
    for (const id of ['acceptOverlay', 'walkthroughOverlay', 'pairingOverlay', 'joinOverlay', 'cloudOverlay', 'createOverlay']) {
      const ov = $(id)
      if (ov && !ov.hidden) { e.preventDefault(); closeSyncOverlay(id); return }
    }
  })
}

/** ── R123 §2.1 (law 0.24's amendment; the CEO's S1) — THE ONE SHARED
 *  RE-AUTH GATE ─────────────────────────────────────────────────────────
 *  EVERY path on this page that needs the passphrase proof consults THIS
 *  gate — never its own ad-hoc check. The gate:
 *    1. consults the WORKER's 60-second window first (a chrome.storage
 *       check can never miss the window's mark — the worker is the only
 *       authority, the page can never fake it);
 *    2. within the window → NO popup at all (the window is honored on
 *       every path — the frequency cap by construction);
 *    3. out of the window → the credential popup ONCE per action; a
 *       verified confirm re-opens the window (markPassphraseConfirmed),
 *       so the next action within 60s skips it again;
 *    4. the reveal itself rides the same two-leg rule as the sheet:
 *       SYNC_CODE_REVEAL_WINDOW inside the window, SYNC_CODE_REVEAL with
 *       the typed passphrase outside it.
 *  R123 — THE DEAD-CLICK FIX: the sheet's carrier buttons (Copy pairing
 *  code / Download QR / Copy QR image) used to return SILENTLY once the
 *  exposure scrub had dropped the rendered payload — the CEO's S1 dead
 *  click. Now every carrier action goes through this gate first: the
 *  payload re-reveals (with the window's own popup economics) and the
 *  clicked action then RUNS. A button's label is its contract (audit (b)).
 */
/** The gate's result: { ok:true, revealed } | { ok:false, cancelled? }.
 *  revealed = the worker's { words, qrUri } — the callers render their own
 *  faces of it (the sheet's word list; the carrier buttons' re-render). */
async function revealPairingCarrier() {
  const w = await passphraseWindowActive()
  let popup = null
  if (w.withinWindow) {
    popup = { ok: true, value: '' }
  } else {
    popup = await UCryptCredPopup.open({
      title: getMessage('credPopupRevealTitle', undefined, 'Confirm your passphrase to reveal the sync code'),
      help: getMessage('credPopupRevealHelp', undefined, 'The words are the key to your sync chain — UCrypt re-checks your master passphrase first.'),
      mode: 'passphrase',
      confirmLabel: getMessage('credPopupConfirm', undefined, 'Confirm'),
      verify: async (pass) => {
        const v = await bgSend('VERIFY_PASSPHRASE', { passphrase: pass })
        return v && v.ok ? { ok: true } : { ok: false, error: (v && v.error) || getMessage('sdRevealFailed', undefined, 'Wrong master passphrase') }
      },
    })
  }
  if (!popup || !popup.ok) return { ok: false, cancelled: true }
  try {
    const r = w.withinWindow
      ? await bgSend('SYNC_CODE_REVEAL_WINDOW')
      : await bgSend('SYNC_CODE_REVEAL', { passphrase: popup.value })
    if (!r || !r.ok || !r.revealed) return { ok: false, error: (r && r.error) || '' }
    return { ok: true, revealed: r.revealed }
  } catch (e) { return { ok: false, error: String((e && e.message) || e) } }
}

/** THE CARRIER ACTIONS' GATE (the dead-click fix, the CEO's S1): when the
 *  Copy/Download/Copy-QR buttons are clicked and the rendered payload is
 *  gone (the exposure scrub dropped it, or the sheet was reopened), this
 *  re-proves the human through the SAME shared gate and re-renders the
 *  payload — then the clicked action RUNS. Never a silent return. */
async function ensurePairingCarrier() {
  if (_pairingWords && _pairingWords.length === 24 && _pairingUri) return true
  const g = await revealPairingCarrier()
  if (!g || !g.ok) {
    if (g && !g.cancelled && g.error) toast('✗ ' + g.error, 'error')
    return false
  }
  _pairingWords = g.revealed.words
  renderPairingPayload()
  // The re-reveal restarts the exposure scrub — the words and the carrier
  // stay governed by the same visibility law as the first reveal.
  const ol = $('addDeviceWords')
  const qrImg = $('addDeviceQr')
  scrubSecretExposure('restart')
  _secretExposure = startSecretExposure({
    wordsEl: ol,
    qrEl: qrImg,
    host: (ol && ol.parentElement) || $('addDeviceBox'),
    onScrub: () => {
      _secretExposure = null
      _pairingWords = null
      _pairingUri = null
      const copyBtn = $('pairCopyCodeBtn')
      if (copyBtn) { copyBtn.hidden = true }
    },
  })
  return true
}

/** Re-auth + reveal: R109 §3.2(a) — the CEO's S3. The fixed passphrase field
 *  is GONE from the sheet; the reveal opens the credential popup layer
 *  (law 0.24): typed title, masked input with show-toggle, verify against
 *  the vault (VERIFY_PASSPHRASE — pure, zero state mutation), truthful typed
 *  errors INSIDE the popup, closes only on the user's action. On success the
 *  popup's verified passphrase drives the REAL SYNC_CODE_REVEAL (the worker
 *  re-verifies — defense in depth), then the exposure countdown starts.
 *  R123 §2.1 — the sheet's reveal now rides the ONE shared gate
 *  (revealPairingCarrier): the window honored on every path, the popup
 *  economics identical everywhere. The sheet's own result line + the
 *  confirmed-backup row + the word list render stay HERE (they are the
 *  sheet's faces of the same reveal). */
async function addDeviceReveal() {
  const resultEl = $('addDeviceAuthResult')
  resultEl.className = 'sync-test-result'
  // R110 §3 — within the passphrase window the sheet's reveal does not
  // re-prompt: the countdown renders in the sheet's own result line and the
  // SYNC_CODE_REVEAL runs with the WORKER's own sealed copy (the passphrase
  // is only ever needed to prove the human — the worker verifies from its
  // own unlocked state).
  const w = await passphraseWindowActive()
  if (w.withinWindow) {
    resultEl.textContent = getMessage('passWindowActive', [String(w.secondsLeft)], `Passphrase confirmed — valid for ${w.secondsLeft}s`)
    // R110 §3 — the visible, unobtrusive indicator PERSISTS during the window:
    // the chip lives in the SHEET BODY (addDeviceBox — visible while the sheet
    // is open) until expiry, so the behavior is never mysterious even after
    // the auth row completes and hides.
    const sheetBox = $('addDeviceBox')
    if (sheetBox) showPassWindowChip(w.secondsLeft, sheetBox)
  }
  // R123 §2.1 — BOTH branches ride the ONE shared gate (the window honored
  // on every path; the popup once per action; a verified confirm re-opens
  // the window for the next action). Within the window the gate prompts
  // NOTHING and reveals from the worker's sealed copy (R110 §3); outside
  // it the popup proves the human first. The sheet renders its own faces
  // of the same revealed record (the word list, the confirmed-backup row).
  resultEl.textContent = getMessage('sdAddVerifying', undefined, 'Verifying…')
  const g = await revealPairingCarrier()
  if (!g || !g.ok) {
    if (g && g.cancelled) { resultEl.className = 'sync-test-result'; resultEl.textContent = '' }
    else {
      resultEl.className = 'sync-test-result err'
      resultEl.textContent = '✗ ' + ((g && g.error) || getMessage('sdRevealFailed', undefined, 'Could not reveal the sync code — check your master passphrase and try again.'))
    }
    return
  }
  const r = { ok: true, revealed: g.revealed }
  try {
    if (!r || !r.ok || !r.revealed) {
      resultEl.className = 'sync-test-result err'
      resultEl.textContent = '✗ ' + ((r && r.error) || getMessage('sdRevealFailed', undefined, 'Could not reveal the sync code — check your master passphrase and try again.'))
      return
    }
    resultEl.className = 'sync-test-result ok'
    resultEl.textContent = getMessage('sdAddRevealed', undefined, '✓ Verified. The words hide automatically — write them down now.')
    // R91 §3.5c — the sheet confirmation path: after THIS re-authenticated
    // reveal the user can mark the backup verified in one click.
    const confirmBtn = $('addDeviceConfirmBackupBtn')
    if (confirmBtn) {
      const flag = (await chrome.storage.local.get(BACKUP_VERIFY_KEY).catch(() => ({})))[BACKUP_VERIFY_KEY]
      confirmBtn.classList.toggle('hidden', !!(flag && flag.verified))
      confirmBtn.disabled = false
    }
    const { words, qrUri } = r.revealed
    const ol = $('addDeviceWords')
    ol.innerHTML = ''
    words.forEach((w, i) => {
      const li = document.createElement('li')
      li.innerHTML = `<span class="word-idx">${String(i + 1).padStart(2, '0')}</span>${escapeHtml(w)}`
      ol.appendChild(li)
    })
    ol.hidden = false
    // R95 F-95-03: the revealed words feed the OPTIONAL full-pairing renderer;
    // the words-only QR (qrUri) stays the default carrier byte-identical to
    // the seal format until the user opts in.
    _pairingWords = words
    renderPairingPayload()
    const qrImg = $('addDeviceQr')
    $('addDeviceAuthRow').classList.add('hidden')
    $('addDeviceAuthRow').hidden = true
    scrubSecretExposure('restart')
    _secretExposure = startSecretExposure({
      wordsEl: ol,
      qrEl: qrImg,
      host: ol.parentElement || $('addDeviceBox'),
      onScrub: () => {
        _secretExposure = null
        // R95 F-95-03: the exposure scrub also drops the pairing payload
        // (the copied carrier must never outlive the visible words).
        _pairingWords = null
        _pairingUri = null
        const copyBtn = $('pairCopyCodeBtn')
        if (copyBtn) { copyBtn.hidden = true }
      },
    })
  } catch (e) {
    resultEl.className = 'sync-test-result err'
    resultEl.textContent = '✗ ' + e.message
  }
}

// ===========================================================================
// R61-A §1.2 — pairing dialog device-type tabs. PURE UI: both tabs expose the
// SAME already-revealed words/QR; they never extend the exposure countdown,
// never bypass re-auth, and never touch the scrub policy.
// ===========================================================================
// R95 F-95-03 — the full-pairing renderer. R108 §2.3 — PAYLOAD LAW v1.3
// (the CEO's direct command, law 0.23): the NON-SECRET connection parameters
// (the provider, its address, the public OAuth client ID, the bridge /exec
// URL) ride the pairing code ALWAYS — no opt-in stands in front of them, on
// either carrier (the copied code and the QR are the same URI). The ONE
// labeled opt-in gates ONLY the credential (the WebDAV sign-in), exactly as
// 0.14 v1.3 words it. Secrets are categorically excluded — 0.14 stands
// unchanged; the allowlist in lib/sync.js IS the law. The words-only carrier
// survives exactly when this device has no cloud transport configured.
async function renderPairingPayload() {
  const qrImg = $('addDeviceQr')
  const toggle = $('pairIncludeCloud')
  const row = $('pairCloudRow')
  const copyBtn = $('pairCopyCodeBtn')
  const note = $('pairCloudNote')
  if (!qrImg || !toggle || !row) return
  if (!_pairingWords || _pairingWords.length !== 24) return
  // R108 — the transport record is read UNCONDITIONALLY (the embed-always
  // law); the credential projection is only built when the opt-in is checked
  // AND the provider actually holds a stored sign-in (the R102 law: the
  // worker refuses credentials for every non-WebDAV transport by
  // construction).
  let transportRecord = null
  try {
    transportRecord = (await chrome.storage.local.get(TRANSPORT_KEY))[TRANSPORT_KEY]
  } catch { transportRecord = null }
  let completeCloud = null
  try {
    const r = await bgSend('PAIRING_COMPLETE_CLOUD')
    if (r && r.ok && r.cloud && r.cloud.provider) completeCloud = r.cloud
  } catch { completeCloud = null }
  // R110 v1.4 — the toggle covers ALL credentials present on the origin:
  // the WebDAV sign-in (/c/), the gdrive client secret AND the OAuth grant
  // (the /k/ segment's transit-sealed s/g blobs). The page sees PRESENCE
  // only — the blobs are opaque strings built in the worker.
  const wholeCreds = !!(completeCloud && completeCloud.conn && (completeCloud.conn.s || completeCloud.conn.g))
  const canComplete = !!(completeCloud && (completeCloud.creds || wholeCreds))
  // R108 — ONE opt-in: pairIncludeCloud IS the credential opt-in now (its
  // label says exactly that). The row shows only when there is a sign-in to
  // include; the superseded second checkbox is gone from the sheet.
  const credOptRow = $('pairCredOptRow')
  if (credOptRow) credOptRow.style.display = canComplete ? 'flex' : 'none'
  const wantComplete = !!(canComplete && toggle.checked)
  const completeWarn = $('pairCompleteWarn')
  if (completeWarn) {
    completeWarn.hidden = !wantComplete
    if (wantComplete) completeWarn.textContent = getMessage('pairCompleteWarn', undefined,
      'Anyone with this code can read your cloud backup — like Brave\'s sync code. Keep it only where you keep passwords.')
  }
  let cloud = null
  if (transportRecord) {
    try {
      // R110 v1.4 — toggle ON (the CEO-pinned default) → the WHOLE credential
      // projection (the worker's sealed blobs); toggle OFF → the config-only
      // code (provider + address + public client ID/bridge — labeled so).
      cloud = wantComplete ? completeCloud : safeCloudForPairing(transportRecord, { complete: false })
    } catch { cloud = null }
    if (cloud && !cloud.provider) cloud = null
  }
  const uri = buildPairingUri(_pairingWords, cloud)
  _pairingUri = uri
  // R108 §2.5 — the origin's carried-segments ring (flags only). R110 v1.4 —
  // the ring names the sealed segments too (booleans: secret-carried /
  // grant-carried — never values).
  notePairingSegments(cloud ? cloud.provider : '', {
    conn: !!(cloud && cloud.conn),
    creds: !!(cloud && cloud.creds),
    secret: !!(cloud && cloud.conn && cloud.conn.s),
    grant: !!(cloud && cloud.conn && cloud.conn.g),
    carrier: 'sheet',
  }).catch(() => {})
  // R108 §2.4 — THE QR CAPACITY LAW: the COPIED code always carries the
  // full URI (nothing is ever truncated). The QR is the bounded carrier
  // (the v15/412-byte band — the spec-exact table the encoder pins, never
  // widened by guesswork). When the full carrier exceeds the band, the QR
  // degrades down a TRUTHFUL fallback ladder — full → without the bridge
  // URL → without the address (the client ID always survives; the CEO's
  // core ask) → words-only — each step NAMED on the surface (R109 §2.3:
  // the rung line + the Download caption + the alt text), and the copied
  // code keeps everything either way. R109 §2.2 — the ladder order is the
  // LAW: the client ID is the LAST segment dropped (after the bridge URL
  // and the address); when even words+client-ID cannot fit, the QR says so
  // explicitly and points at "Copy pairing code — it always carries
  // everything". Never an unreadable QR, never a silent drop.
  const qrCandidates = []
  if (cloud) {
    qrCandidates.push({ uri, rung: 'full', alt: cloud.creds ? 'pairQrAltComplete' : (wholeCreds ? 'pairQrAltWhole' : 'pairQrAltConn') })
    // R110 §2.2 — the QR CAPACITY LADDER, the PINNED drop order (0.14):
    // address → grant → secret → client ID → words-only. The address class
    // drops in two named steps (the bridge URL, then the /u/ address —
    // R109's granularity preserved); the client ID stays the LAST named
    // segment to drop; words-only is the floor. The COPIED code always
    // carries everything — every rung says so.
    if (cloud.conn && cloud.conn.b) {
      const noBridge = { ...cloud, conn: { ...cloud.conn, b: undefined } }
      delete noBridge.conn.b
      qrCandidates.push({ uri: buildPairingUri(_pairingWords, noBridge), rung: 'no-bridge', alt: wholeCreds ? 'pairQrAltWhole' : 'pairQrAltConn' })
    }
    if (cloud.url) {
      const noAddr = { ...cloud, url: null }
      delete noAddr.url
      qrCandidates.push({ uri: buildPairingUri(_pairingWords, noAddr), rung: 'no-address', alt: wholeCreds ? 'pairQrAltWhole' : 'pairQrAltConn' })
    }
    if (cloud.conn && cloud.conn.g) {
      const noGrant = { ...cloud, conn: { ...cloud.conn } }
      delete noGrant.conn.g
      qrCandidates.push({ uri: buildPairingUri(_pairingWords, noGrant), rung: 'no-grant', alt: 'pairQrAltWhole' })
    }
    if (cloud.conn && cloud.conn.s) {
      const noSecret = { ...cloud, conn: { ...cloud.conn } }
      delete noSecret.conn.s
      qrCandidates.push({ uri: buildPairingUri(_pairingWords, noSecret), rung: 'no-secret', alt: wholeCreds ? 'pairQrAltWhole' : 'pairQrAltConn' })
    }
    if (cloud.conn && cloud.conn.cid) {
      qrCandidates.push({ uri: buildPairingUri(_pairingWords, { provider: cloud.provider, conn: { cid: cloud.conn.cid } }), rung: 'id-only', alt: 'pairQrAltConn' })
    }
    qrCandidates.push({ uri: buildPairingUri(_pairingWords, null), rung: 'words', alt: 'sdQrAltWords' })
  }
  qrCandidates.push({ uri: buildPairingUri(_pairingWords, null), rung: 'words', alt: 'sdQrAltWords' })
  let qr = null
  let qrAltKey = qrCandidates[0].alt
  let qrRung = qrCandidates[0].rung
  for (const cand of qrCandidates) {
    try {
      const m = globalThis.QR ? globalThis.QR.encode(cand.uri) : null
      if (m) { qr = m; qrAltKey = cand.alt; qrRung = cand.rung; break }
    } catch { qr = null }
  }
  if (qr) { qrImg.src = qr; qrImg.hidden = false } else { qrImg.hidden = true }
  qrImg.alt = cloud
    ? getMessage(qrAltKey, undefined, qrAltKey === 'sdQrAltWords'
      ? 'Sync code QR — words only, no cloud data'
      : 'Pairing QR — recovery words + the cloud connection settings (no passwords, no tokens, no sign-in)')
    : getMessage('sdQrAltWords', undefined, 'Sync code QR — words only, no cloud data')
  // R109 §2.2/§2.3 — the rung line + the Download caption: the QR's truth in
  // one glance, at BOTH ends of the ladder (the transparency clause of the
  // prefill law — a silent gap between sent and received is a defect).
  const rungLine = $('pairQrRungLine')
  const dlCaption = $('pairQrDownloadCaption')
  const rungText = cloud
    ? (qrRung === 'full'
      ? (wholeCreds
        ? getMessage('pairQrRungFullWhole', undefined, 'The QR carries the same complete code as the copy — your words, the cloud connection, and the sign-in credentials sealed inside (only these words open them).')
        : getMessage('pairQrRungFull', undefined, 'The QR carries the same complete code as the copy — your words plus the cloud connection settings (never passwords, tokens, or sign-ins).'))
      : qrRung === 'no-bridge'
        ? getMessage('pairQrRungNoBridge', undefined, 'The QR is smaller than the copy: it carries your words + the client ID + the address. The bridge URL rides the copied code only — press "Copy pairing code" to send everything.')
        : qrRung === 'no-address'
          ? getMessage('pairQrRungNoAddress', undefined, 'The QR is smaller than the copy: it carries your words + the client ID + the sign-in credentials. The address rides the copied code only — press "Copy pairing code" to send everything.')
          : qrRung === 'no-grant'
            ? getMessage('pairQrRungNoGrant', undefined, 'The QR is smaller than the copy: it carries your words + the client ID + the client secret. The Google grant rides the copied code only — press "Copy pairing code" to send everything (the joiner then signs in once).')
            : qrRung === 'no-secret'
              ? getMessage('pairQrRungNoSecret', undefined, 'The QR is smaller than the copy: it carries your words + the client ID. The client secret rides the copied code only — press "Copy pairing code" to send everything (the joiner then signs in once).')
              : qrRung === 'id-only'
                ? getMessage('pairQrRungIdOnly', undefined, 'The QR is smaller than the copy: it carries your words + the client ID. The address rides the copied code only — press "Copy pairing code" to send everything.')
                : getMessage('pairQrRungWords', undefined, 'This QR could not carry the connection settings — one QR cannot hold that much. "Copy pairing code" ALWAYS carries everything — paste the code on the other device instead of scanning.'))
    : getMessage('pairQrRungWordsOnlyNoCloud', undefined, 'The QR carries your recovery words — this device has no cloud connected, so there is nothing else to carry.')
  if (rungLine) {
    rungLine.textContent = rungText
    rungLine.hidden = false
  }
  // R160 ARC C′ (G164) — THE SHARE SUMMARY: the ten classes with live
  // counts (the summary-before-commit discipline — the offeror sees exactly
  // what the beam carries; masked, advisory, never blocks the sheet).
  try {
    const er = await bgSend('GET_ENTRIES')
    const summary = buildShareSummary((er && er.ok && er.entries) || [], { historyIncluded: true, formsIncluded: false })
    const countsEl = $('pairScopeCounts')
    if (countsEl) {
      countsEl.replaceChildren(...summary.classes.map((c) => {
        const li = document.createElement('li')
        const k = 'cls' + c.key.charAt(0).toUpperCase() + c.key.slice(1)
        li.textContent = `${getMessage(k, undefined, c.label)}: ${c.count}${c.included ? '' : ' — not included'}`
        return li
      }))
      countsEl.hidden = false
    }
  } catch { /* the census is advisory — never blocks the sheet */ }
  if (dlCaption) {
    dlCaption.textContent = cloud
      ? (qrRung === 'full'
        ? getMessage('pairQrDlFull', undefined, 'The downloaded QR = the complete code (words + connection settings).')
        : getMessage('pairQrDlDegraded', undefined, 'The downloaded QR is the degraded rung — the copied code carries more. When in doubt, "Copy pairing code" always carries everything.'))
      : getMessage('pairQrDlFull', undefined, 'The downloaded QR = the complete code (words + connection settings).')
    dlCaption.hidden = !cloud || qrImg.hidden
  }
  row.hidden = false
  if (note) {
    // R110 v1.4 — the note names the WHOLE credential when it rides.
    note.textContent = cloud
      ? (cloud.creds
        ? getMessage('pairCloudNoteComplete', [String(cloud.provider)], 'Complete: provider $1 + address + sign-in. OAuth tokens, the vault and your master passphrase never ride the code.')
        : (cloud.conn && (cloud.conn.s || cloud.conn.g))
          ? getMessage('pairCloudNoteWhole', [String(cloud.provider)], 'Complete: $1 + client ID + sign-in credentials included (sealed — only these words open them). The new device connects without signing in if the grant is valid.')
          : getMessage('pairCloudNoteConn', [String(cloud.provider)], 'Attached: $1 — the code carries the cloud type and its public connection settings (the client ID or bridge URL — not secrets). The new device only signs in.'))
      : getMessage('pairCloudNoteOff', undefined, 'No cloud is configured on this device — the QR carries the recovery words only.')
  }
  // The contains/never lines, truthful for the CURRENT carrier (R102 J2,
  // extended by R108 for the always-on connection settings). R109 §2.3 —
  // the transparency clause: the carried-segments line NAMES each segment
  // ("your 24 words · Google Drive · the client ID · the address"), so the
  // CEO can see at a glance whether the origin sent the configuration —
  // the mixed-build class becomes self-evident on either machine.
  const containsEl = $('pairContainsLine')
  const neverEl = $('pairNeverLine')
  if (containsEl) {
    containsEl.hidden = false
    const segs = [getMessage('pairSegWords', undefined, 'your 24 words')]
    if (cloud) {
      segs.push(transportName(cloud.provider, String(cloud.provider || '')))
      if (cloud.conn && cloud.conn.cid) segs.push(getMessage('pairSegClientId', undefined, 'the client ID'))
      if (cloud.url || (cloud.conn && cloud.conn.b)) segs.push(getMessage('pairSegAddress', undefined, 'the address'))
      // R119 v1.5 — THE LADDER RUNG NAMED ALOUD (the transparency clause):
      // when the origin's connection carries its signinMode, the carried
      // line says which rung produced this code — and a FAST origin's line
      // can never name the sealed credentials (the v1.5 discipline drops
      // them at the builder; the list mirrors pairingSegmentNames in
      // lib/sync.js — the same truth computed in both modules).
      if (cloud.conn && isSigninMode(cloud.conn.m)) {
        segs.push(getMessage(
          cloud.conn.m === 'fast' ? 'pairSegModeFast' : cloud.conn.m === 'guided' ? 'pairSegModeGuided' : 'pairSegModeManual',
          undefined,
          cloud.conn.m === 'fast' ? 'the shared sign-in (fast — the new device signs in with one click)'
            : cloud.conn.m === 'guided' ? 'your own-key sign-in (guided)'
            : 'the manual sign-in'))
      }
      // R110 v1.4 — the carried line names the credential segments item by
      // item (the transparency clause: what-carried is visible at BOTH ends).
      // R119 v1.5 — on a fast origin s/g never ride (dropped at the builder);
      // these lines simply stay silent there.
      if (cloud.conn && cloud.conn.s) segs.push(getMessage('pairSegSecret', undefined, 'the client secret (sealed)'))
      if (cloud.conn && cloud.conn.g) segs.push(getMessage('pairSegGrant', undefined, 'the sign-in grant (sealed)'))
      if (cloud.creds) segs.push(getMessage('pairSegSignIn', undefined, 'the WebDAV sign-in'))
    }
    containsEl.textContent = getMessage('pairCarriesLine', [segs.join(getMessage('pairSegJoiner', undefined, ' · '))], 'This code carries: $SEGS$ — never your vault or master passphrase; the sealed segments open only with these words.')
  }
  if (neverEl) {
    neverEl.hidden = false
    neverEl.textContent = getMessage('pairNeverLine', undefined,
      'It never contains: your vault or your master passphrase. The sign-in rides SEALED — only the words in this code open it, and anyone with this code signs in as you, like Brave\'s sync code.')
  }
  if (copyBtn) copyBtn.hidden = false
  // R102 (J2) — the QR file round-trip buttons ride the same carrier.
  const dlBtn = $('pairDownloadQrBtn')
  const cpBtn = $('pairCopyQrBtn')
  if (dlBtn) dlBtn.hidden = false
  if (cpBtn) cpBtn.hidden = !(navigator.clipboard && typeof ClipboardItem !== 'undefined')
}

// --- R102 (J2) — the QR file round-trip --------------------------------------
// R106 (F-R106-QR-2 FIX): the export NEVER resamples the on-screen render
// again. The forensic proved the old path — an <img> SVG drawn onto a fixed
// 512×512 canvas — shipped artifacts carrying 13–17% antialiased gray edge
// pixels, and the mapped dead class (cs=4 geometries) refused BOTH the raw
// decode AND the full repair ladder on the owner's path. The export now
// rasterizes the QR MATRIX directly (QR.matrix → QR.exportGrid): integer
// 8px modules, pure #000 on #fff, an explicit 4-module white quiet zone —
// lossless PNG via putImageData, theme-independent by construction (the
// grid takes no theme input), forever. The on-screen SVG is untouched.

async function pairingQrPngBlob() {
  const qrImg = $('addDeviceQr')
  if (!qrImg || qrImg.hidden || !_pairingUri) return null
  const m = globalThis.QR ? globalThis.QR.matrix(_pairingUri) : null
  if (!m || !m.modules) return null
  const grid = globalThis.QR.exportGrid(m)
  const canvas = document.createElement('canvas')
  canvas.width = grid.dim
  canvas.height = grid.dim
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  const imgData = ctx.createImageData(grid.dim, grid.dim)
  for (let i = 0; i < grid.px.length; i++) {
    const v = grid.px[i]
    const o = i * 4
    imgData.data[o] = v
    imgData.data[o + 1] = v
    imgData.data[o + 2] = v
    imgData.data[o + 3] = 255
  }
  ctx.putImageData(imgData, 0, 0)
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b), 'image/png'))
}

function pairingQrFilename() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `ucrypt-pairing-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.png`
}

async function downloadPairingQr() {
  try {
    // R123 §2.1 — the carrier gate: a scrubbed payload re-reveals through
    // the shared gate (the window honored; the popup once) — the download
    // then RUNS instead of the old misleading 'no QR rendered' error.
    if (!_pairingUri) {
      const ok = await ensurePairingCarrier()
      if (!ok || !_pairingUri) return
    }
    const blob = await pairingQrPngBlob()
    if (!blob) throw new Error('no QR rendered')
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = pairingQrFilename()
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 4000)
    toast(getMessage('pairQrDownloaded', [a.download], `QR saved as $1 — send it to the other device, then drop the file on its join panel.`))
  } catch (e) {
    toast(getMessage('pairQrDownloadFailed', [e.message], `Could not save the QR: ${e.message}`), 'error')
  }
}

async function copyPairingQrImage() {
  try {
    if (!navigator.clipboard || typeof ClipboardItem === 'undefined') throw new Error('unsupported')
    // R123 §2.1 — the carrier gate (the dead-click fix): re-reveal, then copy.
    if (!_pairingUri) {
      const ok = await ensurePairingCarrier()
      if (!ok || !_pairingUri) return
    }
    const blob = await pairingQrPngBlob()
    if (!blob) throw new Error('no QR rendered')
    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })])
    toast(getMessage('pairQrCopied', undefined, 'QR image copied — paste it into an email or chat with the other device.'))
  } catch {
    toast(getMessage('pairQrCopyUnsupported', undefined, 'This browser\'s clipboard cannot carry images — use Download QR instead.'), 'error')
  }
}

function initPairingPayload() {
  const copyBtn = $('pairCopyCodeBtn')
  // R108 §2.3 — pairIncludeCloud IS the credential opt-in now (the
  // embed-always law needs no toggle); flipping it re-renders the carrier.
  $('pairIncludeCloud')?.addEventListener('change', () => { if (_pairingWords) renderPairingPayload() })
  copyBtn?.addEventListener('click', async () => {
    // R123 §2.1 (law 0.24's amendment; the CEO's S1) — THE DEAD-CLICK FIX:
    // when the payload is gone (the exposure scrub dropped it), the click
    // re-proves the human through the ONE shared gate and the copy RUNS —
    // never a silent return. A button's label is its contract.
    if (!_pairingUri) {
      const ok = await ensurePairingCarrier()
      if (!ok || !_pairingUri) return // cancelled or no code exists
    }
    try {
      await navigator.clipboard.writeText(_pairingUri)
      // R97 (F-R96-1): the pairing URI carries the 24 sync-code words —
      // vault-key material — so this copy ARMS the clipboard guard.
      if (globalThis.UCryptClipGuard) globalThis.UCryptClipGuard.arm()
      toast(getMessage('pairCopiedToast', undefined, 'Pairing code copied — it carries the words (and, if you opted in, the cloud sign-in only)'))
    } catch {
      toast(getMessage('pairCopyFailedToast', undefined, 'Could not access the clipboard — select and copy the words instead'), 'error')
    }
  })
  // R102 (J2) — the QR file round-trip.
  $('pairDownloadQrBtn')?.addEventListener('click', downloadPairingQr)
  $('pairCopyQrBtn')?.addEventListener('click', copyPairingQrImage)
}

function initPairingTabs() {
  const phone = $('pairTabPhone')
  const comp = $('pairTabComputer')
  const stepsPhone = $('pairStepsPhone')
  const stepsComp = $('pairStepsComputer')
  if (!phone || !comp || !stepsPhone || !stepsComp) return
  const select = (which) => {
    const phoneOn = which === 'phone'
    phone.classList.toggle('active', phoneOn)
    phone.setAttribute('aria-selected', String(phoneOn))
    comp.classList.toggle('active', !phoneOn)
    comp.setAttribute('aria-selected', String(!phoneOn))
    stepsPhone.classList.toggle('hidden', !phoneOn)
    stepsPhone.hidden = !phoneOn
    stepsComp.classList.toggle('hidden', phoneOn)
    stepsComp.hidden = phoneOn
  }
  phone.addEventListener('click', () => select('phone'))
  comp.addEventListener('click', () => select('computer'))
}

// ===========================================================================
// R61-A §1.3 — "Join existing chain": first-class guided route.
// Safety-ordered sequence with NO initial blind push:
//   1. local vault setup/unlock (wizard refuses to proceed locked);
//   2. validate EXACTLY 24 normalized words CLIENT-SIDE (no network touched);
//   3. connect the SAME cloud storage (delegates to the existing chooser);
//   4. SYNC_CODE_SET pulls the encrypted envelope FIRST (setSyncCode pull-
//      before-push), decrypts/validates/merges under THIS device's own
//      passphrase; the push is deferred while the remote is unobservable;
//   5. render the restored count + cloud state; sync becomes eligible only
//      after a readable pull/merge. Device B's master passphrase is its own.
// ===========================================================================
let _joinWordsValidated = false
// R102 (F-R102-4) — the typed attach line's survivor flag: set when a parsed
// payload attaches its cloud location, honored by refreshJoinCloudState until
// the transport truly connects or the panel reopens.
let _joinCloudAttached = ''

// R108 §2.5 — the carried-segments ring (metadata ONLY: provider + presence
// flags + which carrier; never the words, never the values — the diagnostics
// export reads it, the no-secrets gate machine-checks the boundary).
async function notePairingSegments(provider, { conn = false, creds = false, carrier = '' } = {}) {
  try {
    await chrome.storage.session.set({
      'ucrypt:pairing:lastSegments': { at: Date.now(), provider: String(provider || ''), carriedConn: !!conn, carriedCreds: !!creds, carrier: String(carrier || '').slice(0, 16) },
    })
  } catch { /* the ring is best-effort diagnostics */ }
}

/** R128 §4 (the CEO's S3 — THE JOIN RE-ENTRY): the last attempted join code
 * survives the panel's close and a failed attempt — the re-opened door hands
 * the words back for editing (law 0.36: input is never destroyed by a
 * refresh; here the door itself preserves the work). The draft is page-local
 * memory only — never written to disk; a SUCCESSFUL join retires it. */
let _joinWordsDraft = ''

function openJoinChain() {
  const panel = $('joinChainPanel')
  if (!panel) return
  // R109 §4.2 — the join wizard is a focused layer now (law 0.25).
  openSyncOverlay('joinOverlay')
  panel.classList.remove('hidden')
  panel.hidden = false
  // R128 §4 (0.36): the previously attempted code comes BACK for editing —
  // the v2.84.0 open wiped the field on every re-entry, so a failed join's
  // retry demanded retyping 24 words from scratch (the CEO's exact ask: the
  // user must be able to EDIT the join code when it already tried).
  $('joinWords').value = _joinWordsDraft
  $('joinValidateResult').className = 'sync-test-result'
  $('joinValidateResult').textContent = ''
  $('joinResult').className = 'sync-test-result'
  $('joinResult').textContent = ''
  _joinWordsValidated = false
  _joinCloudAttached = ''
  $('joinCommitBtn').disabled = true
  // R108 §2.3 — the conn CTA resets with the panel (never a stale card open).
  const connCta = $('joinCloudConnectCta')
  if (connCta) connCta.hidden = true
  // R102 (J7/J5) — a fresh panel starts with a clean stage strip and no
  // checklist: the Symphony renders its own truth, never a stale run's.
  const strip = $('joinStageStrip')
  if (strip) { strip.innerHTML = ''; strip.hidden = true }
  stopJoinStripMirror()
  const done = $('joinDoneChecklist')
  if (done) done.hidden = true
  ;(async () => {
    const st = await bgSend('GET_STATE')
    const hasVault = !!(st && st.ok && st.state && st.state.hasMaster)
    const unlocked = !!(st && st.ok && st.state && st.state.isUnlocked)
    const lockedRow = $('joinLockedRow')
    const ready = hasVault && unlocked
    if (!ready) {
      lockedRow.className = 'sync-test-result err'
      lockedRow.textContent = getMessage('joinLocked', undefined, 'Create or unlock your local vault first (Security tab), then join.')
      lockedRow.hidden = false
    } else {
      lockedRow.hidden = true
    }
    $('joinWords').disabled = !ready
    $('joinValidateBtn').disabled = !ready
    $('joinCloudChooseBtn').disabled = !ready
    await refreshJoinCloudState()
  })().catch(() => { /* state probe failure keeps the fields disabled-safe */ })
}

async function refreshJoinCloudState() {
  const el = $('joinCloudState')
  if (!el) return
  try {
    const st = await bgSend('GET_STATE')
    const t = (st && st.ok && st.sync && st.sync.transport) || null
    if (t && t.hasConfig) {
      // Connected — the attach note has served its purpose.
      _joinCloudAttached = ''
      el.textContent = '✓ ' + transportName(t.id, t.id)
      el.style.color = 'var(--ok, #1e8e3e)'
      // R108 §2.3 — connected means the one-step CTA's job is done.
      const connCta = $('joinCloudConnectCta')
      if (connCta) connCta.hidden = true
    } else if (_joinCloudAttached) {
      // R102 (F-R102-4, found live): the typed attach line survives the
      // chooser's state refresh — the user's feedback is never stomped
      // while the transport is still unconfigured.
      el.textContent = _joinCloudAttached
      el.style.color = 'var(--ok, #1e8e3e)'
    } else {
      el.textContent = getMessage('joinCloudMissing', undefined, 'not connected')
      el.style.color = 'var(--amber)'
    }
  } catch { el.textContent = '' }
}

// ── R101 (§2.1/§2.3 — the CEO's S4/S5 commands) ────────────────────────────
// The typed status strip + the three-path panel. Every state below renders
// REAL, live truth (the transport record, the chain state, the Beam phase) —
// never a guess, never a dead end (law 0.13 extended to the sync surface).

/** The live Beam phase as the strip/panel see it (set by the beam stage). */
let _beamPathState = { state: 'off', text: '' }

function setChip(id, state, text) {
  const chip = $(id)
  if (!chip) return
  chip.dataset.state = state
  const label = $(id + 'Text')
  if (label) label.textContent = text
}

/** §2.3 — the status strip: chain joined? cloud connected? Beam ready? */
async function renderSyncStatusStrip() {
  const strip = $('syncStatusStrip')
  if (!strip) return
  strip.classList.remove('hidden')
  strip.hidden = false
  try {
    const st = await bgSend('GET_STATE')
    const sync = (st && st.ok && st.sync) || {}
    const joined = !!(sync.syncEnabled || (st && st.ok && st.state && st.state.hasMaster && sync.syncEnabled))
    setChip('syncChipChain', joined ? 'ok' : 'off',
      joined ? getMessage('stripChainJoined', undefined, 'Sync chain: joined')
        : getMessage('stripChainNone', undefined, 'Sync chain: not set up'))
    const t = sync.transport || null
    setChip('syncChipCloud', t && t.hasConfig ? 'ok' : 'warn',
      t && t.hasConfig
        ? getMessage('stripCloudOn', [transportName(t.id, t.id)], 'Cloud: connected ($1)')
        : getMessage('stripCloudOff', undefined, 'Cloud: not connected'))
    if (_beamPathState.text) {
      setChip('syncChipBeam', _beamPathState.state, _beamPathState.text)
    } else {
      // R127 §6 (the CEO's S7 — never a dead state, law 0.26): the chip
      // names the arm affordance in its own label — one click opens the
      // Beam card where the Add-device window + the availability toggle
      // arm it. The chip's title carries the two-sentence truth (what the
      // beam is; what it needs).
      setChip('syncChipBeam', 'off', getMessage('stripBeamOffActionable', undefined, 'Sync Beam: off — click to arm'))
      const beamChipEl = $('syncChipBeam')
      if (beamChipEl) {
        beamChipEl.title = getMessage('stripBeamOffTitle', undefined, 'Direct device-to-device sync: your devices find each other while UCrypt is open. Click to open the Beam card and arm this device.')
      }
    }
    await renderTestingExpiryCard()
    await renderVaultConflictResolver()
    await renderAutoSyncRetryFeedback((sync && sync.autoSync) || null)
  } catch { /* the strip is advisory — a failed probe leaves the last truth */ }
}

/** R160 ARC A′ (G162) — THE PROACTIVE TESTING-EXPIRY CARD. ONE writer: the
 * typed evidence (chrome.storage, written by the gdrive hooks) + the
 * dismissal derive ONE state (lib/cloud/testing-card.js); the renderer
 * writes ONLY that state's lines. The card never blocks manual sync while
 * the token lives; it never closes itself (the user dismisses it); a
 * dismissed reminder returns after 24 h or on a new evidence event; a dead
 * grant ignores dismissal (the honest-error discipline). Zero console. */
async function renderTestingExpiryCard() {
  const card = $('testingExpiryCard')
  if (!card) return
  try {
    const store = await chrome.storage.local.get([TESTING_EVIDENCE_KEY, TESTING_DISMISSAL_KEY])
    const derived = deriveTestingCard({
      evidence: store[TESTING_EVIDENCE_KEY] || null,
      dismissal: store[TESTING_DISMISSAL_KEY] || null,
      now: Date.now(),
    })
    if (!derived.show) {
      card.hidden = true
      card.classList.add('hidden')
      return
    }
    const dead = derived.level === 'dead'
    card.dataset.level = derived.level
    card.hidden = false
    card.classList.remove('hidden')
    const title = $('testingExpiryTitle')
    const body = $('testingExpiryBody')
    if (title) title.textContent = dead
      ? getMessage('testingCardDeadTitle', undefined, 'Cloud Sync can\u2019t connect \u2014 the Google grant expired (Testing mode)')
      : getMessage('testingCardTitle', undefined, 'Your Google token will expire \u2014 publish to Production')
    if (body) body.textContent = getMessage(dead ? 'testingCardDeadBody' : 'testingCardBody', undefined,
      'UCrypt detected the Testing-mode signature: Google expires Cloud Sync grants about 7 days after you sign in. After it expires, Cloud Sync cannot connect until you publish the app or reconnect.')
  } catch { /* advisory — the card never blocks the strip */ }
}

/** The card's two actions (wired once): the dismissal (the ONLY way the
 * card leaves — popup sovereignty) and the reconnect (the existing
 * affordance — the same surface the cloud chip opens). */
function initTestingExpiryCard() {
  const card = $('testingExpiryCard')
  if (!card || card.dataset.wired === '1') return
  card.dataset.wired = '1'
  $('testingExpiryDismissBtn')?.addEventListener('click', async () => {
    try {
      const level = card.dataset.level === 'dead' ? 'dead' : 'reminder'
      await chrome.storage.local.set({ [TESTING_DISMISSAL_KEY]: { at: Date.now(), level } })
    } catch { /* a dead store never blocks the dismissal */ }
    card.hidden = true
    card.classList.add('hidden')
  })
  $('testingExpiryReconnectBtn')?.addEventListener('click', () => {
    const block = $('cloudBackupStatus')
    if (block) block.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    else if (typeof openSyncOverlay === 'function') openSyncOverlay('cloudOverlay')
  })
}

/** §2.1 — the Beam card's live state (the red dead-end box is retired: an
 * unavailable Beam is INFORMATIONAL — it teaches the two-device choreography
 * in one sentence and names the next action). */
function updateBeamPathState(state, text) {
  _beamPathState = { state, text }
  const card = $('joinPathBeam')
  if (card) card.dataset.state = state
  const el = $('joinPathBeamState')
  if (el) el.textContent = text
  setChip('syncChipBeam', state, state === 'off'
    ? getMessage('stripBeamOff', undefined, 'Sync Beam: off')
    : getMessage('stripBeamLive', undefined, 'Sync Beam: ') + text)
}

/** §2.1 — the three-path panel, revealed after the sync code commits. Each
 * card's state is the LIVE truth at render time. */
async function showJoinNextPaths() {
  const panel = $('joinNextPaths')
  if (!panel) return
  panel.classList.remove('hidden')
  panel.hidden = false
  try {
    const st = await bgSend('GET_STATE')
    const t = (st && st.ok && st.sync && st.sync.transport) || null
    const cloudCard = $('joinPathCloud')
    const cloudState = $('joinPathCloudState')
    if (t && t.hasConfig) {
      if (cloudCard) cloudCard.dataset.state = 'ok'
      if (cloudState) cloudState.textContent = '✓ ' + transportName(t.id, t.id)
    } else {
      if (cloudCard) cloudCard.dataset.state = 'warn'
      const pcCloud = (await chrome.storage.local.get('ucrypt:pairingCloud'))['ucrypt:pairingCloud']
      if (cloudState) {
        cloudState.textContent = pcCloud && pcCloud.provider
          ? getMessage('joinPathCloudPrefilled', [String(pcCloud.provider)], '$1 is pre-filled — add your sign-in')
          : getMessage('joinPathCloudNotConnected', undefined, 'Not connected yet')
      }
    }
    if (!_beamPathState.text) {
      updateBeamPathState('warn', getMessage('joinPathBeamWaitingOrigin', undefined,
        'Lights up when the origin device opens “Add a device” — keep that device unlocked with its window open.'))
    }
    const manualState = $('joinPathManualState')
    if (manualState) manualState.textContent = getMessage('joinPathManualReady', undefined, 'Available anytime — works offline')
  } catch { /* the panel renders with the last truth — never a guess */ }
  await renderSyncStatusStrip().catch(() => {})
}

/** The panel's three buttons — wired once (wireJoinChain calls this). */
function wireJoinNextPaths() {
  $('joinPathCloudBtn')?.addEventListener('click', () => {
    // The join flow's OWN cloud chooser — one click, prefill-aware.
    $('joinCloudChooseBtn')?.click()
    refreshJoinCloudState().catch(() => {})
  })
  $('joinPathBeamBtn')?.addEventListener('click', () => {
    // A truthful retry: the Beam lights up when the origin is announcing.
    beamJoinerStart().catch(() => { /* the stage shows its own truth */ })
  })
  $('joinPathManualBtn')?.addEventListener('click', () => {
    // The hand-carry path: the manual first-contact affordance, in view.
    const stage = $('beamJoinStage')
    if (stage) {
      stage.classList.remove('hidden')
      stage.hidden = false
    }
    const row = $('beamJoinManualPresenceRow')
    if (row) {
      row.classList.remove('hidden')
      row.hidden = false
    }
    $('beamJoinManualPresenceSignal')?.focus()
  })
}

async function joinValidateWords(opts = {}) {
  const el = $('joinValidateResult')
  let raw = $('joinWords').value.trim()
  el.className = 'sync-test-result'
  el.textContent = getMessage('syncValidating', undefined, 'Validating…')
  try {
    // R95 F-95-03 (CEO finding): accept the FULL pairing URI (and the
    // scheme-prefixed words-only form) — parse FIRST, then validate the
    // extracted words. A parsed cloud attach (provider + non-secret address,
    // the secret-law allowlist) is surfaced truthfully; the user still signs
    // in themselves — nothing secret ever rode the payload.
    // R102 (J1): a COMPLETE pairing code (the /c/ segment, the labeled
    // opt-in on the origin) is recognized and typed aloud here — and when
    // the words validate, the Symphony auto-runs (J3).
    const parsed = parsePairingUri(raw)
    // R101 (§2.2 — cases ii+iii): a WORDS-ONLY pairing CARRIER (its scheme
    // rode the code) says its truth — the origin device has no cloud
    // connected, or the code is an older format. Joining works either way;
    // the cloud address simply is not attached. Hand-typed bare words (no
    // scheme) are not a carrier — no note, the user typed what they typed.
    const pairingNote = $('joinPairingNote')
    if (pairingNote) {
      if (parsed && !parsed.provider && /^ucrypt-sync:\/\//i.test(raw)) {
        pairingNote.textContent = getMessage('joinPairingWordsOnly', undefined,
          'This pairing code carries the sync code only — the origin device has no cloud connected (or the code is an older format). Joining still works; connect your cloud storage to receive the backup.')
        pairingNote.hidden = false
      } else {
        pairingNote.textContent = ''
        pairingNote.hidden = true
      }
    }
    if (parsed) {
      if (parsed.provider) attachJoinCloud(parsed)
      // R108 §2.5 — the joiner's carried-segments ring (flags only).
      // R110 v1.4 — the sealed segments are named by boolean only.
      // R119 v1.5 — the rung rides the ring note (the mode is the payload's
      // own fact — the joiner's paste names which ladder produced it).
      notePairingSegments(parsed.provider, {
        conn: !!parsed.conn,
        creds: !!parsed.creds,
        secret: !!(parsed.conn && parsed.conn.s),
        grant: !!(parsed.conn && parsed.conn.g),
        mode: (parsed.conn && isSigninMode(parsed.conn.m)) ? parsed.conn.m : '',
        carrier: 'code',
      }).catch(() => {})
      raw = parsed.words.join(' ')
      $('joinWords').value = raw // normalize the box to the bare words
    }
    // Normalize separators FIRST, then require exactly 24 words — all
    // client-side, BEFORE any network step (R61-A §1.3 ordering rule).
    const words = raw.split(/[\s-]+/).filter(Boolean)
    if (words.length !== 24) {
      throw new Error(getMessage('joinWordCount', [String(words.length)], `Expected 24 words — got ${words.length}.`))
    }
    const result = await validateSyncCode(words.join(' '))
    if (!result.valid) throw new Error(result.reason || 'invalid words')
    const fp = await syncFingerprint(words.join(' '))
    _joinWordsValidated = true
    $('joinCommitBtn').disabled = false
    el.className = 'sync-test-result ok'
    if (parsed && parsed.conn && (parsed.conn.s || parsed.conn.g)) {
      // R110 §2.3 (payload law v1.4) — the WHOLE code: the arrival line names
      // EVERYTHING, verbatim per the CEO's order.
      el.textContent = getMessage('joinValidWhole', [fp, transportName(parsed.provider, parsed.provider)],
        `✓ Complete code — fingerprint ${fp}. Vault key, $2, client ID, sign-in credentials included — connecting automatically.`)
    } else if (parsed && parsed.creds) {
      // R102 (J1/J3) — the complete code: typed, honest, and the trigger for
      // the automatic sequence (the same one-sentence warning as the origin).
      el.textContent = getMessage('joinValidComplete', [fp, transportName(parsed.provider, parsed.provider)],
        `✓ Complete pairing code — fingerprint ${fp}. Includes the cloud connection for $2 — connecting automatically.`)
    } else if (parsed && parsed.conn && parsed.conn.m === 'fast') {
      // R119 (payload law v1.5) — THE FAST CODE: the origin connected through
      // the shared sign-in (device-local — no credentials ever ride). The
      // arrival line says so in one sentence: this device signs in with one
      // click from the shared client ID that rode the code.
      el.textContent = getMessage('joinValidFast', [fp, transportName(parsed.provider, parsed.provider)],
        `✓ Valid 24-word code — fingerprint ${fp}. The $2 connection rode the code with the shared one-click sign-in — connecting automatically.`)
    } else if (parsed && parsed.conn) {
      // R108 §2.3 — the v1.3 conn-carrying code (the CEO's S1/S2 target UX,
      // verbatim): the connection settings rode the code, so the card is
      // ready and the sign-in is the ONLY step left.
      el.textContent = getMessage('joinValidConn', [fp, transportName(parsed.provider, parsed.provider)],
        `✓ Valid 24-word code — fingerprint ${fp}. The $2 connection settings rode the code — the sign-in is the only step left.`)
    } else {
      el.textContent = getMessage('syncValidOk', [fp], `✓ Valid 24-word code — fingerprint ${fp}`)
    }
    // R102 (J3) — THE AUTO-EXECUTION. A complete code runs the whole
    // Symphony by itself (cloud → join → beam), every stage typed.
    // R108 §2.3 — a conn-carrying code (the v1.3 default) auto-runs too:
    // the prefilled card opens, the join proceeds, and the one remaining
    // user action is the sign-in. A location-only or words-only code keeps the manual button
    // (the three-path panel stands; nothing is forced).
    // R110 v1.4 — the whole code (s/g rode) auto-runs with ZERO sign-ins
    // when the grant verifies; the one-click sign-in card is the fallback.
    if (parsed && (parsed.creds || parsed.conn)) {
      runJoinSymphony(parsed).catch(() => { /* the strip shows the truth */ })
    } else if (opts && opts.autoCommit && _joinWordsValidated) {
      // §5.3 (R133 — the QR pairing is SELF-COMPLETING): a machine-read QR
      // that validated as words-only auto-commits — the 0.48 lifecycle arms,
      // the first pull starts, and the typed line says what is happening.
      // The hand-typed path keeps its explicit button (typo protection).
      joinCommit().catch(() => { /* the result line names the failure */ })
    }
  } catch (e) {
    _joinWordsValidated = false
    $('joinCommitBtn').disabled = true
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
  }
}

// R95 F-95-03 — surface the cloud setup that rode a full pairing URI, and
// hand it to the transport wizard (one-shot, non-secret: provider id + a
// userinfo-stripped address for user-typed-URL providers). The joiner still
// enters their own sign-in — the payload cannot and must not carry it.
// R102 (J1) — a COMPLETE code additionally hands over the sign-in (the
// labeled opt-in on the origin) under the SAME one-shot key; the wizard
// prefills the credentials and the Symphony connects automatically.
async function attachJoinCloud(parsed) {
  try {
    const cloud = {
      provider: String(parsed.provider),
      ...(parsed.url ? { url: String(parsed.url) } : {}),
      // The creds ride the one-shot handoff EXACTLY once — consumed by the
      // wizard's prefill and removed from storage on first read.
      ...(parsed.creds ? { creds: { u: String(parsed.creds.u), p: String(parsed.creds.p) } } : {}),
      // R106 payload law v1.2 — the NON-SECRET connection parameters (the
      // public OAuth client id, the bridge URL) ride the same one-shot
      // handoff so the joiner's transport card prefills them (one click).
      ...(parsed.conn ? { conn: parsed.conn } : {}),
    }
    await chrome.storage.local.set({ 'ucrypt:pairingCloud': cloud })
    const el = $('joinCloudState')
    if (el) {
      const where = cloud.url ? ` (${cloud.url})` : ''
      el.textContent = cloud.creds
        ? getMessage('joinCloudAttachedComplete', [cloud.provider + where], 'Complete cloud connection attached: $1 — connecting automatically.')
        : (cloud.conn
          ? getMessage('joinCloudAttachedConn', [transportName(cloud.provider, cloud.provider) + where], 'Cloud setup attached: $1 — ready. The connection settings are filled in; the sign-in is the only step left.')
          : getMessage('joinCloudAttached', [cloud.provider + where], 'Cloud setup attached: $1 — check it, then sign in.'))
      _joinCloudAttached = el.textContent
      el.style.color = 'var(--ok, #1e8e3e)'
    }
    // R108 §2.3 — the ONE-CLICK next action (0.13: never prose alone): the
    // conn-carrying code opens the prefilled wizard card on one press.
    const cta = $('joinCloudConnectCta')
    if (cta && cloud.conn && !cloud.creds) {
      cta.hidden = false
      cta.onclick = async () => {
        try { await openTransportWizard(String(cloud.provider)) } catch { /* the chooser stays the fallback */ }
      }
    }
  } catch { /* handoff is best-effort — the manual path is unchanged */ }
}

// ===========================================================================
// R102 — THE JOIN SYMPHONY (J3 + J7): the joiner's automatic sequence.
// After a COMPLETE pairing code validates, this runs the whole experience by
// itself — cloud connection → chain join → beam — with every stage typed
// into #joinStageStrip and updated IN PLACE. Failures NAME THE FIX and the
// sequence continues (never a dead end); nothing auto-dismisses (law 0.8).
// ===========================================================================

const JOIN_STAGES = ['cloud', 'join', 'beam']

function joinStripEl(id) {
  return document.querySelector(`#joinStageStrip li[data-stage="${id}"]`)
}

function joinStageSet(id, state, text) {
  const strip = $('joinStageStrip')
  if (!strip) return
  strip.hidden = false
  let li = joinStripEl(id)
  if (!li) {
    li = document.createElement('li')
    li.dataset.stage = id
    strip.appendChild(li)
    // Keep the canonical order regardless of append order.
    for (const s of JOIN_STAGES) {
      const el = joinStripEl(s)
      if (el) strip.appendChild(el)
    }
  }
  li.dataset.state = state
  li.className = state === 'done' ? 'join-stage-done' : state === 'active' ? 'join-stage-active' : state === 'fail' ? 'join-stage-fail' : 'join-stage-pending'
  li.textContent = text
}

async function runJoinSymphony(parsed) {
  const creds = parsed.creds
  const wholeCreds = !!(parsed.conn && (parsed.conn.s || parsed.conn.g))
  const provider = String(parsed.provider || '')
  const tName = transportName(provider, provider)
  // ── Stage 1: the cloud connection ──
  if (provider && wholeCreds && !creds) {
    // R110 §2.3 (payload law v1.4) — THE WHOLE-CREDENTIAL ARRIVAL: the
    // sealed segments open in the WORKER with the words the code carried,
    // re-seal under THIS vault's key, and the connection verifies with the
    // arrived grant — ZERO sign-ins when the grant is valid. The honest
    // one-liner renders on success; the one-click sign-in card is the
    // typed fallback on any failure. Booleans cross the boundary — the
    // page never sees the values.
    joinStageSet('cloud', 'active', getMessage('joinStageWholeArriving', [tName],
      `Opening the sign-in that rode the code for $1…`))
    let arrival = null
    try {
      arrival = await bgSend('PAIRING_CREDENTIALS_OPEN', {
        provider,
        clientId: (parsed.conn && parsed.conn.cid) || '',
        s: (parsed.conn && parsed.conn.s) || '',
        g: (parsed.conn && parsed.conn.g) || '',
        words: (parsed.words || []).join(' '),
      })
    } catch { arrival = null }
    if (!arrival || !arrival.ok) {
      const why = (arrival && arrival.error) || 'the sealed segments did not open'
      joinStageSet('cloud', 'fail', getMessage('joinStageWholeFail', [tName, why],
        `⚠ The sign-in did not arrive intact for $1 ($2) — the one-click sign-in card is below. Everything else continues.`))
      try { openTransportWizard(provider) } catch { /* the chooser stays the fallback */ }
    } else {
      // The arrival stored sealed — verify the connection with the arrived
      // grant (the fake-tier live per the egress verdict; the real grant
      // verifies the same way on the CEO's machines).
      let testOk = false
      let testWhy = ''
      try {
        const g = await bgSend('TRANSPORT_GET')
        const cfg = g && g.ok ? g.config : null
        const tr = await bgSend('TRANSPORT_TEST', { transportId: provider, config: cfg })
        testOk = !!(tr && tr.ok)
        if (!testOk) testWhy = (tr && tr.error) || ''
      } catch (e) { testWhy = (e && e.message) || '' }
      if (testOk) {
        joinStageSet('cloud', 'done', getMessage('joinStageWholeDone', [tName],
          `✓ $1 connected with the origin's sign-in — zero sign-ins for you. This device received the origin's sign-in — revoke it any time from Google.`))
        const cta = $('joinCloudConnectCta')
        if (cta) cta.hidden = true
      } else {
        // The grant did not verify (revoked/expired/environment): the typed
        // failure + the ONE-CLICK sign-in card (at most one sign-in remains).
        joinStageSet('cloud', 'fail', getMessage('joinStageWholeReauth', [tName, testWhy || getMessage('joinStageCloudUnreachable', undefined, 'the cloud is unreachable from this device')],
          `⚠ $1 did not verify with the arrived sign-in ($2) — press Connect in the card below to sign in once. Joining continues.`))
        try { openTransportWizard(provider) } catch { /* the chooser stays the fallback */ }
      }
    }
  } else if (provider && creds) {
    joinStageSet('cloud', 'active', getMessage('joinStageCloudConnecting', [tName], `Connecting your cloud ($1)…`))
    // Open the wizard for this provider — the one-shot handoff prefills the
    // URL AND the credentials (the transport record is stored by the wizard
    // itself, sealed by the worker — the page never persists secrets).
    // AWAITED: the prefill is async (TRANSPORT_GET) and the auto-Test below
    // reads the form — the order matters.
    try { await openTransportWizard(provider) } catch { /* the stage below still runs */ }
    // Auto-Test → auto-Connect with the prefilled form. Both helpers report
    // through the wizard's result element (they never throw on failure) —
    // the ELEMENT CLASS is the truth, so that is what the Symphony reads.
    try { await testCurrentTransport() } catch { /* result element carries it */ }
    const testOk = ($('twResult')?.className || '').includes('ok')
    let savedOk = false
    if (testOk) {
      try { await saveCurrentTransport() } catch { /* result element carries it */ }
      savedOk = ($('twResult')?.className || '').includes('ok')
    }
    if (testOk && savedOk) {
      joinStageSet('cloud', 'done', getMessage('joinStageCloudDone', [tName], `✓ Cloud connected — $1. Ongoing sync is on.`))
    } else {
      // The typed failure NAMES THE FIX and the Symphony CONTINUES — the
      // beam does not need the cloud, and the wizard stays open with the
      // prefilled fields so the user can correct and retry.
      const why = ($('twResult')?.textContent || '').replace(/^[✗✓]\s*/, '')
      joinStageSet('cloud', 'fail', getMessage('joinStageCloudFail', [tName, why || getMessage('joinStageCloudUnreachable', undefined, 'the cloud is unreachable from this device')],
        `⚠ $1 could not be connected ($2) — check the address and sign-in in the form below, then Test again. Joining continues without it; the beam carries your vault.`))
    }
  } else if (provider && !creds) {
    // R108 §2.3 — the conn-carrying code (the v1.3 default): the card is
    // ALREADY FILLED (the provider-aware prefill put the client ID / bridge
    // URL in place) — the CEO's verbatim target, typed in place: the one
    // step left is the sign-in. The location-only code (no conn segment)
    // keeps the add-your-own-sign-in guidance. Neither is a dead end.
    if (parsed.conn) {
      joinStageSet('cloud', 'active', getMessage('joinStageCloudOneStep', [tName],
        `$1 is ready — the connection settings are filled in the card below. Press Connect and sign in; that is the only step left.`))
    } else {
      joinStageSet('cloud', 'fail', getMessage('joinStageCloudManual', [tName],
        `The code carries the $1 location — add your own sign-in in the form below, then Test and Join. Nothing was connected for you.`))
    }
    try { openTransportWizard(provider) } catch { /* best-effort */ }
  }
  // ── Stage 2: the chain join (pull-first, unchanged semantics) ──
  joinStageSet('join', 'active', getMessage('joinStageJoining', undefined, 'Joining the chain — pulling the encrypted vault…'))
  await joinCommit()
  // joinCommit rendered its own result and started the beam stage (S8.1) —
  // mirror its live state into the strip (J7) from here on.
  const res = ($('joinResult')?.className || '').includes('ok')
  joinStageSet('join', res ? 'done' : 'active', res
    ? getMessage('joinStageJoined', undefined, '✓ Chain joined.')
    : getMessage('joinStageJoinPending', undefined, 'The join is in progress — see the status line below.'))
  // ── Stage 3: the beam (mirrored live) ──
  joinStageSet('beam', 'active', getMessage('joinStageBeam', undefined, 'Waiting for the origin device to accept…'))
  startJoinStripMirror()
}

// J7 — the strip's beam row mirrors the beam stage's live text (phase +
// progress) so ONE surface tells the whole story. A terminal beam state
// (landed/declined/stopped) flips the row's state; nothing auto-dismisses.
let joinStripMirrorTimer = null
function startJoinStripMirror() {
  stopJoinStripMirror()
  joinStripMirrorTimer = setInterval(async () => {
    // R102 (F-R102-3, found live): the beam can LAND through the transfer
    // surface (a different page), so the options-page result element is not
    // the only truth. The mirror reads THE VAULT ITSELF: a live chain with
    // entries IS the landing — the checklist then renders from the same
    // truth. A page-local 'ok' result is the second signal.
    try {
      const st = await bgSend('GET_STATE')
      const live = !!(st && st.ok && st.sync && st.sync.syncEnabled
        && st.state && typeof st.state.entryCount === 'number' && st.state.entryCount > 0)
      if (live) {
        joinStageSet('beam', 'done', getMessage('joinStageBeamLandedCount', [String(st.state.entryCount)],
          `✓ The beam landed — $1 entries are live on this device.`))
        stopJoinStripMirror()
        renderJoinDoneChecklist()
        return
      }
    } catch { /* the next tick retries — never a dead strip */ }
    const phase = $('beamJoinPhase')?.textContent || ''
    const recv = $('beamJoinProgressText')?.textContent || ''
    const landed = ($('beamJoinResult')?.className || '').includes('ok')
    if (landed) {
      joinStageSet('beam', 'done', $('beamJoinResult')?.textContent || getMessage('joinStageBeamDone', undefined, '✓ The beam landed — your vault is live.'))
      stopJoinStripMirror()
      renderJoinDoneChecklist()
      return
    }
    // The mirror NEVER freezes on a transient error — the zero-transport
    // beam legitimately recovers (the manual first contact) after a typed
    // failure, so the row keeps mirroring the LIVE phase/progress.
    if (recv && recv.trim()) joinStageSet('beam', 'active', recv.trim())
    else if (phase && phase.trim()) joinStageSet('beam', 'active', phase.trim())
  }, 700)
}
function stopJoinStripMirror() {
  if (joinStripMirrorTimer) { clearInterval(joinStripMirrorTimer); joinStripMirrorTimer = null }
}

// J5 — the joiner's success checklist. Rendered after a verified landing
// (beam adopt or a verified cloud pull): every row typed, nothing claimed
// silently; the two named offers ride below.
async function renderJoinDoneChecklist() {
  const box = $('joinDoneChecklist')
  const rows = $('joinDoneRows')
  if (!box || !rows) return
  let entryCount = 0
  let cloudLine = ''
  try {
    const st = await bgSend('GET_STATE')
    if (st && st.ok && st.state && typeof st.state.entryCount === 'number') entryCount = st.state.entryCount
  } catch { /* the count row renders truthfully empty */ }
  try {
    const t = (await bgSend('GET_STATE'))?.sync?.transport || null
    const pcCloud = (await chrome.storage.local.get('ucrypt:pairingCloud'))['ucrypt:pairingCloud']
    cloudLine = (t && t.hasConfig)
      ? getMessage('joinDoneCloudOk', undefined, '✓ Cloud backup connected — ongoing sync is on.')
      : (pcCloud && pcCloud.conn
        ? getMessage('joinDoneCloudOneStep', [transportName(String(pcCloud.provider), String(pcCloud.provider))], '— $1 is ready: the connection settings rode the code and are filled in. One step left: press Connect and sign in.')
        : getMessage('joinDoneCloudMissing', undefined, '— Cloud backup not connected yet: add the same storage the origin uses, then Sync now.'))
  } catch { cloudLine = '' }
  const entries = entryCount > 0
    ? getMessage('joinDoneEntries', [String(entryCount)], `✓ Vault live — $1 entries restored and encrypted under this device's own passphrase.`)
    : getMessage('joinDoneEntriesZero', undefined, '✓ Vault live (empty chain) — entries arriving from the other device will appear here.')
  rows.innerHTML = ''
  for (const line of [entries, cloudLine, getMessage('joinDoneLane', undefined, '✓ Direct lane ready — future joins and beams go device-to-device.')]) {
    const li = document.createElement('li')
    li.textContent = line
    rows.appendChild(li)
  }
  // R108 §3.1 — the "Name this device" row (the joiner's own naming moment;
  // the origin's Accept dialog names it from the other side — mutual).
  try {
    const ts = await bgSend('TRANSFER_STATUS')
    const mine = ts && ts.ok && Array.isArray(ts.peers) ? ts.peers.find((x) => x.mine) : null
    const selfLabel = (mine && mine.label) || ''
    const li = document.createElement('li')
    const known = !!selfLabel && selfLabel !== getMessage('beamUnknownDevice', undefined, 'A UCrypt device')
    if (known) {
      li.textContent = getMessage('joinDoneNamed', [selfLabel], `✓ This device is named “${selfLabel}”.`)
    } else {
      li.textContent = getMessage('joinDoneNameHint', undefined, '— Optional: give this device a name so the others recognize it.')
      const wrap = document.createElement('span')
      wrap.style.cssText = 'display:inline-flex;gap:6px;margin-left:8px;vertical-align:middle'
      const inp = document.createElement('input')
      inp.type = 'text'
      inp.maxLength = 40
      inp.placeholder = sensibleDeviceName() || getMessage('deviceListRenamePlaceholder', undefined, 'This device’s name (e.g. “DELL-01”)')
      inp.setAttribute('aria-label', getMessage('deviceListRename', undefined, 'Rename'))
      inp.style.cssText = 'min-width:140px;padding:3px 8px;border:1px solid var(--border, rgba(128,128,128,.35));border-radius:6px;background:transparent;color:inherit'
      const save = document.createElement('button')
      save.className = 'btn btn-outline btn-sm'
      save.type = 'button'
      save.textContent = getMessage('deviceListRenameSave', undefined, 'Save')
      save.addEventListener('click', async () => {
        const r = await bgSend('TRANSFER_SET_DEVICE_LABEL', { label: inp.value })
        if (r && r.ok) {
          li.textContent = getMessage('joinDoneNamed', [r.label || inp.value.trim()], `✓ This device is named “${r.label || inp.value.trim()}”.`)
          renderDeviceMgmt()
        } else {
          toast(getMessage('deviceListRenameFailed', undefined, 'Could not save the name — try again.'), 'error')
        }
      })
      wrap.appendChild(inp)
      wrap.appendChild(save)
      li.appendChild(wrap)
    }
    rows.appendChild(li)
  } catch { /* the naming row is additive — its absence never blocks the checklist */ }
  box.hidden = false
}

async function joinCommit() {
  const el = $('joinResult')
  if (!_joinWordsValidated) return
  const mnemonic = $('joinWords').value.trim().split(/[\s-]+/).filter(Boolean).join(' ')
  el.className = 'sync-test-result'
  el.textContent = getMessage('joinPulling', undefined, 'Pulling and decrypting the cloud copy…')
  try {
    // SYNC_CODE_SET → setSyncCode(): pulls the encrypted envelope FIRST,
    // decrypts/validates/merges locally, persists under THIS device's own
    // master passphrase, and DEFERS the push when the transport is
    // unreachable (R28 semantics — no blind push, ever).
    const r = await bgSend('SYNC_CODE_SET', { mnemonic, source: 'adopt' })
    if (!r?.ok) throw new Error(r?.error || getMessage('syncSaveFailed', undefined, 'Failed to save sync code — try again; if it repeats, check your cloud transport.'))
    const res = r.result || {}
    if (res.pulled) {
      el.className = 'sync-test-result ok'
      el.textContent = getMessage('joinJoined', [String(res.entryCount || 0)], `✓ Joined — restored ${res.entryCount || 0} entr${res.entryCount === 1 ? 'y' : 'ies'} from the verified cloud copy.`)
      // R132 (law 0.46 — the JOIN-PROPAGATION guidance; the CEO's S1): the
      // joiner's completion says the truth about BOTH rosters — this device
      // is marked roster-dirty, so its entry rides the very next envelope;
      // the origin's side gains it on its next pull (or one Sync now there).
      // The typed line names the timeline — never a silent wait.
      const prop = document.createElement('span')
      prop.className = 'card-help'
      prop.style.display = 'block'
      prop.style.marginTop = '6px'
      prop.textContent = getMessage('joinPropagationLine', undefined, 'Your device\u2019s name now travels to your other devices with the next sync — it appears in their “Your devices” list after one cycle (or one “Sync now” on that device).')
      el.appendChild(document.createElement('br'))
      el.appendChild(prop)
      // R102 (J5) — the cloud-pull landing is a completion too: the
      // checklist renders here (the beam landing renders it via the mirror).
      renderJoinDoneChecklist().catch(() => { /* best-effort */ })
    } else {
      // NO join claim until a readable pull/decrypt succeeds (R61-A §1.4).
      // R100 (the CEO's own run, shot 4): this state must never be a DEAD
      // END — the words are saved, so the ONE next action (connect the same
      // storage) is offered INLINE, one click away, with the pairing-payload
      // prefill note when the QR carried the cloud setup.
      el.className = 'sync-test-result warn'
      el.textContent = getMessage('joinNoCloudYet', undefined, 'Words saved. Nothing readable in the cloud yet — connect the same storage Device A uses, then Sync now. This device uploads nothing until a readable copy is confirmed.')
      const cta = document.createElement('button')
      cta.id = 'joinConnectCloudCta'
      cta.className = 'btn btn-primary btn-sm'
      cta.type = 'button'
      cta.style.marginTop = '8px'
      const pcCloud = (await chrome.storage.local.get('ucrypt:pairingCloud'))['ucrypt:pairingCloud']
      cta.textContent = pcCloud && pcCloud.provider
        ? getMessage('joinConnectCloudCtaPrefilled', [String(pcCloud.provider)], 'Connect the same storage now ($1 is already pre-filled — add your sign-in)')
        : getMessage('joinConnectCloudCta', undefined, 'Connect the same cloud storage now')
      cta.addEventListener('click', () => {
        $('sdChooseCloudBtn')?.click()
        refreshJoinCloudState().catch(() => {})
      })
      // R153 §6 (U-1) — the CTA rides its own full-width row: a long label
      // WRAPS inside the dialog (the Z-4 class cure) instead of painting
      // across the modal's bounds.
      const ctaRow = document.createElement('div')
      ctaRow.className = 'btn-row'
      ctaRow.style.cssText = 'margin-top:8px'
      cta.style.maxWidth = '100%'
      ctaRow.appendChild(cta)
      el.appendChild(ctaRow)
    }
    // R98 (S8.1) — THE BEAM: when the origin device is simultaneously open
    // (its Add-device surface armed), the join now travels device-to-device —
    // the sealed join record goes out and the vault envelope comes straight
    // back over the direct channel. The cloud stays the durable backup.
    try { await beamJoinerStart() } catch { /* the beam stage shows its own truth */ }
    // R101 (§2.1 — the CEO's S4 command): the three-path panel — the joiner's
    // truthful map forward, revealed on BOTH commit branches.
    await showJoinNextPaths().catch(() => { /* the panel is additive truth */ })
    $('joinWords').value = ''
    // R128 §4 — a SUCCESSFUL join retires the draft (the door's memory is
    // for FAILED/abandoned attempts only).
    _joinWordsDraft = ''
    _joinWordsValidated = false
    $('joinCommitBtn').disabled = true
    await refreshSync()
    await refreshJoinCloudState()
  } catch (e) {
    // R128 §4 (the CEO's S3 — the failed-join terminal is a DOOR, never a
    // dead end): the typed failure keeps the attempted words in the draft
    // and rides a one-click recovery — the panel re-opens with the code
    // back in the field, ready to EDIT and retry (0.26/0.29/0.37).
    el.className = 'sync-test-result err'
    el.textContent = getMessage('joinFailed', [e.message], `✗ Join failed: ${e.message}. Nothing was uploaded.`)
    const retry = document.createElement('button')
    retry.className = 'btn btn-outline btn-sm'
    retry.type = 'button'
    retry.style.marginTop = '8px'
    retry.textContent = getMessage('joinRetryEditCta', undefined, 'Edit the code and try again')
    retry.addEventListener('click', () => { openJoinChain() })
    el.appendChild(document.createElement('br'))
    el.appendChild(retry)
  }
}

function wireJoinChain() {
  $('joinValidateBtn')?.addEventListener('click', joinValidateWords)
  // R128 §4 (law 0.36) — the join draft tracks the field while the user
  // types: a closed panel, a failed attempt, or a page refresh inside the
  // session never destroys in-progress input.
  $('joinWords')?.addEventListener('input', () => { _joinWordsDraft = $('joinWords').value })
  // R101 (§2.1): the three-path panel's buttons — one primary action each.
  wireJoinNextPaths()

  // R97 §4 — the pairing QR scan (paste or file → the SAME trust boundary).
  async function scanJoinImage(blob) {
    const el = $('joinValidateResult')
    if (el) { el.className = 'sync-test-result'; el.textContent = getMessage('qrScanning', undefined, 'Reading the image…') }
    const r = await globalThis.UCryptQrScan.decodeFromBlob(blob)
    if (!r.ok) {
      el.className = 'sync-test-result err'
      const codes = { 'not-image': 'qrErrNotImage', 'too-large': 'qrErrTooLarge', 'unreadable': 'qrErrUnreadable', 'no-qr': 'qrErrNoQr' }
      const key = codes[r.code] || 'qrErrUnreadable'
      el.textContent = '✗ ' + getMessage(key, undefined, 'The image could not be used — try a sharper screenshot.')
      return
    }
    const kind = globalThis.UCryptQrScan.classify(r.text)
    if (kind === 'otpauth') {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + getMessage('qrErrWrongKindPair', undefined, "That QR code holds a 2FA code — scan it in the popup's 2FA tab.")
      return
    }
    if (kind !== 'pairing') {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + getMessage('qrErrNotPairing', undefined, 'That QR code is not a UCrypt pairing code.')
      return
    }
    $('joinWords').value = r.text
    el.className = 'sync-test-result'
    el.textContent = getMessage('qrScanOkPair', undefined, 'Pairing code read from the image — validating…')
    // §5.3 (R133) — the QR path AUTO-COMMITS: pairing → pull is
    // self-completing (the 0.48 lifecycle arms on the commit; the pull
    // lands the chain's data without a second click).
    await joinValidateWords({ autoCommit: true })
  }
  $('joinQrScanBtn')?.addEventListener('click', () => $('joinQrFile')?.click())
  $('joinQrFile')?.addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0]
    e.target.value = '' // allow re-picking the same file
    if (f) await scanJoinImage(f)
  })
  document.addEventListener('paste', async (e) => {
    const btn = $('joinQrScanBtn')
    if (!btn || btn.offsetParent === null) return // the join card is not on screen
    const items = e.clipboardData && e.clipboardData.items
    if (!items) return
    for (const it of items) {
      if (it.kind === 'file' && /^image\//.test(it.type || '')) {
        const blob = it.getAsFile()
        if (blob) { e.preventDefault(); await scanJoinImage(blob); return }
      }
    }
  })

  // R97 (F-R96-1) — the clipboard guard + its truthful toast.
  if (globalThis.UCryptClipGuard) {
    globalThis.UCryptClipGuard.install()
    window.addEventListener('ucrypt:clipCleared', () => {
      toast(getMessage('toastClipCleared', undefined, 'Clipboard cleared — the vault is locked.'))
    })
  }
  $('joinWords')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); joinValidateWords() }
  })
  $('joinCommitBtn')?.addEventListener('click', joinCommit)
  $('joinCancelBtn')?.addEventListener('click', () => {
    const panel = $('joinChainPanel')
    if (panel) { panel.classList.add('hidden'); panel.hidden = true }
    // R109 §4.2 — the Cancel button closes the focused layer (the user's
    // explicit action; 0.8 holds).
    closeSyncOverlay('joinOverlay')
  })
  // R109 §4.2 — wire the focused layers (open/close/Esc, focus restore).
  wireSyncOverlays()
  // R102 (J2) — the camera-less path is first-class: the drop zone opens
  // the picker, takes a drag-and-drop file, and highlights on dragover.
  // Everything funnels into the SAME scanJoinImage trust boundary.
  const drop = $('joinQrDrop')
  if (drop) {
    drop.addEventListener('click', () => $('joinQrFile')?.click())
    drop.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('joinQrFile')?.click() }
    })
    ;['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault()
      e.stopPropagation()
      drop.style.borderColor = 'var(--ucrypt-ok, #2e7d32)'
      drop.style.background = 'rgba(46,125,50,.06)'
    }))
    ;['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault()
      e.stopPropagation()
      drop.style.borderColor = ''
      drop.style.background = ''
    }))
    drop.addEventListener('drop', async (e) => {
      // R104 (F-R104-QR-1) — NO SILENT DEAD ENDS: a File scans directly; a
      // drag that only carries an image URL (a picture dragged from a web
      // page) is fetched (http/https only — the CSP's own scheme set) and
      // scanned through the SAME ladder; anything else gets the typed error
      // instead of the old silent no-op.
      const dt = e.dataTransfer
      const f = dt && dt.files && dt.files[0]
      if (f) { await scanJoinImage(f); return }
      const el = $('joinValidateResult')
      const url = globalThis.UCryptQrScan.pickDropUrl({
        uriList: dt ? dt.getData('text/uri-list') : '',
        html: dt ? dt.getData('text/html') : '',
      })
      if (url) {
        if (el) { el.className = 'sync-test-result'; el.textContent = getMessage('qrFetchingImage', undefined, 'Fetching the dropped image…') }
        try {
          const resp = await fetch(url, { mode: 'cors' })
          const blob = await resp.blob()
          if (blob.size > (globalThis.UCryptQrScan.MAX_IMAGE_BYTES || 8 * 1024 * 1024)) throw new Error('too-large')
          await scanJoinImage(blob)
        } catch {
          if (el) {
            el.className = 'sync-test-result err'
            el.textContent = '✗ ' + getMessage('qrFetchFailed', undefined, 'The image could not be fetched from that link — save it as a file and drop the file here.')
          }
        }
        return
      }
      if (el) {
        el.className = 'sync-test-result err'
        el.textContent = '✗ ' + getMessage('qrDropNoFile', undefined, 'Nothing scannable in that drop — drop the QR image file itself (PNG/JPG).')
      }
    })
  }
  // R102 (J5) — the completion checklist's offer routes to the REAL surface
  // (the R92 restore card) — never a dead-end promise.
  $('joinDoneBookmarksBtn')?.addEventListener('click', () => {
    try {
      const card = $('bookmarkRestoreCard') || $('icRestoreCard')
      ;(card || $('importCard') || document.body).scrollIntoView({ behavior: 'smooth', block: 'center' })
    } catch { /* best-effort */ }
  })
  // R107 §2.5 — THE POST-JOIN HAND-OFF: the checklist's "Open direct
  // transfer" opens the worker's canonical transfer window (popup → tab
  // fallback); the join → first-use loop closes here.
  $('joinDoneTransferBtn')?.addEventListener('click', async () => {
    try {
      const r = await bgSend('TRANSFER_OPEN_WINDOW', {})
      if (!r || !r.ok) throw new Error((r && (r.error || r.detail)) || 'open failed')
    } catch { /* the typed failure renders where the checklist lives */ }
  })
  // R107 §2.5 — the origin's sheet: the same hand-off after Accept.
  $('beamJoinTransferBtn')?.addEventListener('click', async () => {
    try {
      await bgSend('TRANSFER_OPEN_WINDOW', {})
    } catch { /* best-effort — the dialog stays truthful */ }
  })
  // R107 §2.2 — the transfer window's truth-panel deep links land HERE:
  // the options page switches to the named tab (the bounded relay the
  // transfer page drives via tabs.sendMessage).
  try {
    chrome.runtime.onMessage.addListener((m) => {
      if (m && m.type === 'UCRYPT_OPTIONS_FOCUS_TAB' && m.tab) {
        try {
          const btn = document.querySelector(`.opts-tab[data-tab="${String(m.tab).replace(/[^a-z-]/gi, '')}"]`)
          if (btn) btn.click()
        } catch { /* best-effort focus */ }
      }
      return false
    })
  } catch { /* listener unavailable — the plain open still works */ }
  // R169 G228 — THE ORPHAN-SWEEP CURE (the E-5/E-6 class: zero dispatched
  // events without a listener): the background's two broadcasts finally get
  // their ONE listener seat. UCRYPT_STARTUP_CHECK (the startup status row)
  // and UCRYPT_SYNC_RUN (a sync cycle's outcome) both mean "the sync truth
  // may have moved" — the open Sync tab refreshes. Best-effort: the refresh
  // is guarded by its own bounds; nothing here throws into the message bus.
  try {
    chrome.runtime.onMessage.addListener((m) => {
      if (m && (m.type === 'UCRYPT_STARTUP_CHECK' || m.type === 'UCRYPT_SYNC_RUN')) {
        try { refreshSync() } catch { /* the tab refreshes on its own cadence */ }
      }
      return false
    })
  } catch { /* listener unavailable — the tab refreshes on its own cadence */ }
  // R175 — THE ONE-EVENT-ALL-SURFACES WIRE (R-175.1/R-175.6): every cycle
  // row write re-renders the checklist, the banner, and the Cloud backup
  // card — the ONE projection reaching EVERY seat in the same tick, and the
  // "Run first sync" step closing the moment its completion evidence lands.
  try {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local' || !changes || !changes['ucrypt:lastCycle']) return
      try { refreshChecklist() } catch { /* best-effort */ }
      // refreshSync fetches the real state and fans out to the banner (the
      // state card) and the Cloud backup card — never a null-state render.
      try { refreshSync() } catch { /* best-effort */ }
    })
  } catch { /* listener unavailable — the surfaces render on their own cadence */ }
  // Same cloud storage = the SAME chooser the rest of the card uses.
  $('joinCloudChooseBtn')?.addEventListener('click', () => {
    $('sdChooseCloudBtn')?.click()
    refreshJoinCloudState().catch(() => {})
  })
}

// ===========================================================================
// R56-IMPORT-DETECT — Import Center browser detection banner + override
// (restoration of the lineage design: honest UA-CH brand detection; the
// override re-runs the SAME detection with the user's selection as evidence).
// ===========================================================================

const IC_BROWSER_CHOICES = ['chrome', 'edge', 'brave', 'opera', 'vivaldi', 'helium']
let icRecommendedId = null

/** Detect the current Chromium-family browser. Honest by construction: only
 *  signals that are actually present are reported; anything else is
 *  "Chromium". Never fabricates a brand. */
function detectImportBrowser(uaData, nav) {
  const brands = (uaData && Array.isArray(uaData.brands))
    ? uaData.brands.map((b) => String(b.brand || '').toLowerCase()) : []
  const ua = String((nav && nav.userAgent) || '')
  const has = (s) => brands.some((b) => b.includes(s)) || ua.toLowerCase().includes(s)
  // R127 §5.1 (the CEO's S3 — the census covers the INSTALLED Chromium
  // family): the family list grows Helium (the CEO's own browser — his S3
  // screenshot ran undetected as "Chromium") and the checks keep the
  // fork-specific markers BEFORE the generic chrome/chromium fallbacks, so
  // every family member is named as itself. Brave keeps its navigator.brave
  // probe first (the strongest signal); Edge/Opera/Vivaldi/Helium ride
  // their UA / brand markers.
  if (nav && nav.brave) return { id: 'brave', name: 'Brave' }
  if (has('microsoft edge') || /\bedg\//i.test(ua)) return { id: 'edge', name: 'Microsoft Edge' }
  if (has('opera') || /\bopr\//i.test(ua)) return { id: 'opera', name: 'Opera' }
  if (has('vivaldi')) return { id: 'vivaldi', name: 'Vivaldi' }
  if (has('helium')) return { id: 'helium', name: 'Helium' }
  if (has('chromium')) return { id: 'chrome', name: 'Chromium' }
  if (has('chrome') || uaData) return { id: 'chrome', name: 'Google Chrome' }
  return null
}

/** The override re-runs detection with a SYNTHETIC brand — the same honest
 *  pipeline, just with the user's selection as the evidence. */
function syntheticBrowserFor(id) {
  const names = { chrome: 'Google Chrome', edge: 'Microsoft Edge', brave: 'Brave', opera: 'Opera', vivaldi: 'Vivaldi', helium: 'Helium' }
  return { id, name: names[id] || id }
}

function applyImportBrowserRecommendation(det) {
  icRecommendedId = det ? det.id : null
  const banner = $('icBrowserBanner')
  if (!banner) return
  if (det) {
    banner.hidden = false
    banner.classList.remove('hidden')
    $('icBrowserDetected').textContent = getMessage(
      'icBrowserDetected', [det.name],
      `Detected browser: ${det.name} — the matching sources below are marked ★.`
    )
  } else {
    banner.hidden = true
    banner.classList.add('hidden')
  }
  renderImportSources()
}

async function initImportBrowserBanner() {
  const sel = $('icBrowserOverride')
  if (sel) {
    sel.textContent = ''
    const auto = document.createElement('option')
    auto.value = ''
    auto.textContent = getMessage('icBrowserAuto', undefined, 'Auto-detect')
    sel.appendChild(auto)
    for (const id of IC_BROWSER_CHOICES) {
      const o = document.createElement('option')
      o.value = id
      o.textContent = syntheticBrowserFor(id).name
      sel.appendChild(o)
    }
    sel.addEventListener('change', () => {
      applyImportBrowserRecommendation(sel.value ? syntheticBrowserFor(sel.value) : detectImportBrowser(navigator.userAgentData, navigator))
    })
  }
  applyImportBrowserRecommendation(detectImportBrowser(navigator.userAgentData, navigator))
}

async function refreshSync() {
  // R101 (§2.3): the typed status strip rides every sync refresh — the three
  // chips (chain / cloud / Beam) always carry the live truth.
  renderSyncStatusStrip().catch(() => { /* advisory — never blocks refresh */ })
  // Vault-level sync status
  const r = await bgSend('GET_STATE')
  if (r && r.ok) {
    const sync = r.sync || {}
    $('syncConn').textContent = sync.syncEnabled
      ? getMessage('statusSyncSet', undefined, '✓ Sync code set')
      : getMessage('syncNotSetUp', undefined, 'Not set up')
    const t = sync.transport
    if (t) {
      const meta = getTransport(t.id)
      $('syncTransport').textContent = meta ? `${meta.icon} ${transportName(t.id, meta.name)}` : t.id
      renderTransportGrid(t.id)
    } else {
      $('syncTransport').textContent = getMessage('statusNoTransport', undefined, 'None (manual export/import only)')
      renderTransportGrid(null)
    }
    $('syncLast').textContent = sync.lastModified
      ? new Date(sync.lastModified).toLocaleString()
      : '—'
    $('syncEntries').textContent = String(sync.entryCount || 0)
    // v2.8.0 — the real cloud story: when the encrypted vault last reached
    // the transport, or why it didn't.
    const pushEl = $('syncPushState')
    if (pushEl) {
      const lp = sync.lastPush
      if (!lp || (!lp.at && !lp.error)) {
        pushEl.textContent = '—'
        pushEl.style.color = ''
      } else if (lp.ok) {
        pushEl.textContent = `✓ ${lp.at ? new Date(lp.at).toLocaleString() : ''}`
        pushEl.style.color = 'var(--accent)'
      } else {
        pushEl.textContent = '⚠ ' + getMessage('statusPushRetry', [lp.error || getMessage('statusNotPushed', undefined, 'not pushed yet')], `⚠ ${lp.error || 'not pushed yet'} — retrying every 15 min`)
        pushEl.style.color = 'var(--amber)'
      }
    }
  }

  // v2.3.0 — sync-key KDF version + upgrade offer
  const kdf = await bgSend('SYNC_KDF_INFO')
  const info = (kdf && kdf.ok && kdf.info) || null
  const kdfEl = $('syncKdfState')
  const upgradeBtn = $('kdfUpgradeBtn')
  if (info && info.hasSyncCode) {
    kdfEl.textContent = `PBKDF2-SHA256 · ${info.iterations.toLocaleString()} ${getMessage(info.isCurrent ? 'statusKdfCurrent' : 'statusKdfLegacy', undefined, info.isCurrent ? '(current)' : '(legacy)')}`
    kdfEl.style.color = info.isCurrent ? 'var(--accent)' : 'var(--amber)'
    upgradeBtn.classList.toggle('hidden', info.isCurrent)
  } else {
    kdfEl.textContent = '—'
    kdfEl.style.color = ''
    upgradeBtn.classList.add('hidden')
  }

  // R56-SYNC-DEVICES — the state card mirrors the chain truth every refresh
  refreshSyncDevicesCard(r, kdf)

  // R77-C — the direct-transfer availability row mirrors the worker truth.
  await refreshDirectTransferCard()

  const { [TRANSPORT_KEY]: saved } = await chrome.storage.local.get(TRANSPORT_KEY)
  if (saved?.id) renderTransportGrid(saved.id)
}

async function upgradeKdfAction() {
  const el = $('syncNowResult')
  el.className = 'sync-test-result'
  el.textContent = getMessage('kdfUpgrading', undefined, 'Re-deriving the sync key at 600k iterations…')
  try {
    const r = await bgSend('SYNC_KDF_UPGRADE')
    if (r && r.ok && r.result && r.result.upgraded) {
      el.className = 'sync-test-result ok'
      el.textContent = getMessage('kdfUpgraded', undefined, '✓ Sync key upgraded to 600k iterations and re-pushed. Other devices should update to v2.3.0+ before their next sync.')
    } else {
      el.className = 'sync-test-result ok'
      el.textContent = (r && r.result && r.result.reason) || getMessage('kdfUpToDate', undefined, 'Already up to date')
    }
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + (e.message || getMessage('kdfFailed', undefined, 'Upgrade failed — unlock the vault once and try again.'))
  }
  refreshSync()
}

async function syncNowAction() {
  const el = $('syncNowResult')
  el.className = 'sync-test-result'
  el.textContent = getMessage('syncNowBusy', undefined, 'Syncing…')
  try {
    const r = await bgSend('SYNC_NOW')
    if (r && r.ok) {
      const res = r.result || {}
      // v2.17.0 — R26-F9: the row used to render a green ✓ with an EMPTY
      // transport segment when the push failed (a failed push carries .error,
      // not .reason) — failures were invisible here while the popup showed
      // them. Every outcome is now truthful.
      if (res.remoteObserved === false) {
        // v2.19.0 — R28-F5 (audit 27a-9): the garbage-skip pull exit carries
        // remoteObserved:false with NO transportError and used to fall
        // through to the green ✓ ("Remote storage returned unusable data…"
        // rendered as a success). Unreadable-but-present remote data is a
        // failure state for the PUSH decision — render it as one.
        el.className = 'sync-test-result err'
        el.textContent = `✗ ${res.reason || getMessage('statusUnreadable', undefined, 'The remote could not be verified')}${res.transportError ? ' — ' + res.transportError : ''}`
      } else if (res.push && !res.push.ok && res.push.error) {
        el.className = 'sync-test-result err'
        el.textContent = getMessage('syncPushFailedLine', [res.reason || getMessage('statusPullFinished', undefined, 'Pull finished'), res.push.error], `⚠ ${res.reason || 'Pull finished'} — push failed: ${res.push.error}`)
      } else {
        el.className = 'sync-test-result ok'
        const base = `✓ ${res.reason || getMessage('statusInSync', undefined, 'In sync')}`
        el.textContent = res.push?.pushed
          ? base + getMessage('statusPushedSuffix', undefined, ' · pushed to transport')
          : (res.push ? base + getMessage('statusTransportSuffix', [res.push.reason || ''], ` · transport: ${res.push.reason || ''}`) : base)
      }
    } else {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + ((r && r.error) || getMessage('statusSyncFailed', undefined, 'Sync failed — press Sync now to try again.'))
    }
    refreshSync()
    // R87 (§2.2): first-push completion signal — the checklist flips step 4 in place.
    refreshChecklist()
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
  }
}

async function pullSyncAction() {
  const el = $('syncNowResult')
  el.className = 'sync-test-result'
  el.textContent = getMessage('statusPulling', undefined, 'Pulling…')
  try {
    // v2.17.0 — R26-F9: the button SAID "Pull from cloud" but sent SYNC_NOW,
    // which pulls AND pushes. It now sends the pull-only message so the
    // button does exactly what its label promises.
    const r = await bgSend('SYNC_DRIVE')
    if (r && r.ok) {
      const res = r.result || {}
      if (res.transportError) {
        el.className = 'sync-test-result err'
        el.textContent = `✗ ${res.reason} — ${res.transportError}`
      } else {
        el.className = 'sync-test-result ' + (res.synced ? 'ok' : '')
        el.textContent = res.synced ? `✓ ${res.reason}` : getMessage('statusUpToDate', [res.reason || ''], 'Already up to date: ' + (res.reason || ''))
      }
    } else {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + ((r && r.error) || getMessage('statusPullFailed', undefined, 'Pull failed — press Sync now to try again; nothing was uploaded.'))
    }
    refreshSync()
  } catch (e) {
    el.className = 'sync-test-result err'
    el.textContent = '✗ ' + e.message
  }
}

// --- Breach check ----------------------------------------------------------

async function runBreachCheck() {
  const r = await bgSend('RUN_BREACH_CHECK')
  if (r && r.ok) {
    toast(getMessage('toastBreachDone', undefined, 'Breach check complete — see notification if any matches'))
  } else {
    toast((r && r.error) || getMessage('toastBreachFailed', undefined, 'Breach check failed'), 'error')
  }
}

// UCrypt — R72 GENERATOR LAB (options.js engine)
// One canonical engine for the manager surface. Every generation, copy,
// reveal, save, use and export is an EXPLICIT user action; session secrets
// live only in these variables' memory; nothing here persists or transmits
// them. See docs/feature-change-approvals/R72-generator-lab.md.

const LAB_GENERATING_MODES = ['random', 'passphrase', 'pin', 'pronounceable']
let labPrefs = mergeLabPrefs(null)
let labMode = 'random'
let labSecret = null // the current generated secret OBJECT (session memory only)
let labRevealed = true
let labAutoHideTimer = null
let labSessionHistory = [] // redacted metadata ONLY — never values
let labBulk = [] // current bulk batch (session memory only)
let labPendingConfirm = null // resolver for the high-risk confirm dialog

function labSyncSwitches() {
  document.querySelectorAll('[data-toggle]').forEach(cb => {
    const sw = cb.parentElement.querySelector('.switch')
    if (sw) sw.classList.toggle('on', cb.checked)
  })
}

// ── Lab tab strip (accessible: roving tabindex + arrow/Home/End) ────────────

function switchLab(mode, { focusTab = false } = {}) {
  if (!['random', 'passphrase', 'pin', 'pronounceable', 'bulk', 'analyze', 'mnemonic'].includes(mode)) mode = 'random'
  // R72 §4 — leaving Analyze CLEARS the typed secret immediately.
  if (labMode === 'analyze' && mode !== 'analyze') labClearAnalyze()
  // Leaving a generating mode keeps its secret in memory only if still displayed.
  labMode = mode
  document.querySelectorAll('#labTabs .lab-tab').forEach((b, _, all) => {
    const active = b.dataset.lab === mode
    b.classList.toggle('active', active)
    b.setAttribute('aria-selected', String(active))
    b.tabIndex = active ? 0 : -1
    if (active && focusTab) b.focus()
  })
  document.querySelectorAll('.lab-panel').forEach(p => {
    p.classList.toggle('hidden', p.id !== 'labpanel-' + mode)
  })
  $('labOutputCard').style.display = LAB_GENERATING_MODES.includes(mode) ? '' : 'none'
  if ($('genHeroStateText') && !LAB_GENERATING_MODES.includes(mode)) {
    if (mode === 'analyze') {
      $('genHeroStateText').textContent = 'Offline Entropy Analyzer active · 100% client-side · nothing leaves this device'
    } else if (mode === 'bulk') {
      $('genHeroStateText').textContent = 'Bulk Secret Generator active · generate 2–100 secrets in one batch'
    }
  }
  if (labPrefs.managerMode !== mode) {
    labPrefs.managerMode = mode
    persistLabPrefs()
  }
  // R72 §3.1 — entering a generating mode produces that mode's secret right
  // away (the owner's reference UX: every tab shows a current secret).
  if (LAB_GENERATING_MODES.includes(mode)) labGenerate({ silent: true })
}

function labTabKeydown(e) {
  const tabs = [...document.querySelectorAll('#labTabs .lab-tab')]
  const i = tabs.findIndex(t => t.dataset.lab === labMode)
  let next = null
  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = tabs[(i + 1) % tabs.length]
  else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = tabs[(i - 1 + tabs.length) % tabs.length]
  else if (e.key === 'Home') next = tabs[0]
  else if (e.key === 'End') next = tabs[tabs.length - 1]
  if (next) {
    e.preventDefault()
    switchLab(next.dataset.lab, { focusTab: true })
  }
}

// ── Lab prefs (one shared option store; per-surface mode memories) ──────────

function readLabForm() {
  return {
    managerMode: labMode,
    autoHideSeconds: parseInt($('labAutoHide').value, 10) || 0,
    showComposition: true,
    bulkCount: Math.max(2, Math.min(100, parseInt($('bulkCount').value, 10) || 10)),
    bulkMode: $('bulkMode').value,
    historyEnabled: $('labHistoryEnabled').checked,
  }
}

async function persistLabPrefs() {
  const prefs = await loadPrefs()
  prefs.lab = mergeLabPrefs({ ...(prefs.lab || {}), ...readLabForm() })
  await savePrefs(prefs)
}

async function saveGeneratorSettings() {
  // The Lab's Save button persists EVERY mode's controls in one atomic write.
  const prefs = await loadPrefs()
  prefs.random = readGeneratorForm()
  prefs.passphrase = {
    ...(prefs.passphrase || {}),
    wordCount: parseInt($('ppWordsOpt').value, 10) || 6,
    wordlist: $('ppWordlist').value,
    separator: $('ppSeparatorOpt').value,
    capitalize: $('ppCapitalizeOpt').checked,
    addNumber: $('ppAddNumberOpt').checked,
    addSymbol: $('ppAddSymbolOpt').checked,
    padBetweenWords: $('ppPadOpt').checked,
    minWordLength: parseInt($('ppMinLen').value, 10) || 0,
    maxWordLength: parseInt($('ppMaxLen').value, 10) || 0,
    excludePattern: $('ppExcludePat').value || '',
  }
  prefs.pin = {
    length: parseInt($('pinLengthOpt').value, 10) || 6,
    noRepeats: $('pinNoRepeatsOpt').checked,
    noSequences: $('pinNoSequencesOpt').checked,
  }
  prefs.pronounceable = {
    syllables: parseInt($('prSyllables').value, 10) || 4,
    capitalize: $('prCapitalize').checked,
    addNumber: $('prAddNumber').checked,
    addSymbol: $('prAddSymbol').checked,
  }
  prefs.lab = mergeLabPrefs({ ...(prefs.lab || {}), ...readLabForm() })
  await savePrefs(prefs)
  labPrefs = prefs.lab
  toast(getMessage('toastGenSaved', undefined, 'Generator settings saved'))
  if (LAB_GENERATING_MODES.includes(labMode)) labGenerate()
}

function readGeneratorForm() {
  return {
    length: Math.max(4, Math.min(256, parseInt($('randLength').value, 10) || 20)),
    lowercase: $('randLower').checked,
    uppercase: $('randUpper').checked,
    numbers: $('randNumbers').checked,
    symbols: $('randSymbols').checked,
    excludeAmbiguous: $('randExcludeAmbiguous').checked,
    noDuplicates: $('randNoDuplicates').checked,
    noSequences: $('randNoSequences').checked,
    excludeChars: $('randExcludeChars').value,
    customSymbols: ($('randCustomSymbols').value || '').trim(),
    firstCharLetter: $('randFirstLetter').checked,
  }
}

async function refreshGenerator() {
  const prefs = await loadPrefs()
  labPrefs = mergeLabPrefs(prefs.lab)
  const o = { ...DEFAULT_RANDOM, ...(prefs.random || {}) }
  $('randLength').value = o.length
  $('randLengthVal').textContent = String(o.length)
  $('randLower').checked = o.lowercase
  $('randUpper').checked = o.uppercase
  $('randNumbers').checked = o.numbers
  $('randSymbols').checked = o.symbols
  $('randExcludeAmbiguous').checked = o.excludeAmbiguous
  $('randNoDuplicates').checked = o.noDuplicates
  $('randNoSequences').checked = o.noSequences
  $('randExcludeChars').value = o.excludeChars || ''
  $('randCustomSymbols').value = o.customSymbols || ''
  $('randFirstLetter').checked = !!o.firstCharLetter
  // passphrase
  const pp = prefs.passphrase || {}
  $('ppWordsOpt').value = pp.wordCount || 6
  $('ppWordsOptVal').textContent = String(pp.wordCount || 6)
  $('ppWordlist').value = pp.wordlist || 'large'
  $('ppSeparatorOpt').value = pp.separator !== undefined ? pp.separator : '-'
  $('ppCapitalizeOpt').checked = pp.capitalize !== false
  $('ppAddNumberOpt').checked = pp.addNumber !== false
  $('ppAddSymbolOpt').checked = pp.addSymbol !== false
  $('ppPadOpt').checked = !!pp.padBetweenWords
  $('ppMinLen').value = pp.minWordLength || 0
  $('ppMaxLen').value = pp.maxWordLength || 0
  $('ppExcludePat').value = pp.excludePattern || ''
  updatePpWlStatus()
  // pin
  const pin = prefs.pin || {}
  $('pinLengthOpt').value = pin.length || 6
  $('pinLengthOptVal').textContent = String(pin.length || 6)
  $('pinNoRepeatsOpt').checked = pin.noRepeats !== false
  $('pinNoSequencesOpt').checked = pin.noSequences !== false
  // pronounceable
  const pr = prefs.pronounceable || {}
  $('prSyllables').value = pr.syllables || 4
  $('prSyllablesVal').textContent = String(pr.syllables || 4)
  $('prCapitalize').checked = pr.capitalize !== false
  $('prAddNumber').checked = pr.addNumber !== false
  $('prAddSymbol').checked = pr.addSymbol !== false
  // lab output card
  $('labAutoHide').value = String(labPrefs.autoHideSeconds || 0)
  $('bulkCount').value = String(labPrefs.bulkCount || 10)
  $('bulkMode').value = labPrefs.bulkMode || 'random'
  $('labHistoryEnabled').checked = !!labPrefs.historyEnabled
  labSyncSwitches()
  renderLabHistory()
  if (labPrefs.historyEnabled && $('labHistoryBox')) {
    $('labHistoryBox').open = true
    try { SettledHouse.reveal('gen-session-history').catch(() => {}) } catch { /* non-fatal */ }
  }
  switchLab(labPrefs.managerMode || 'random')
  if (LAB_GENERATING_MODES.includes(labMode) && !labSecret) await labGenerate()
}

function updatePpWlStatus() {
  const el = $('ppWlStatus')
  if (!el) return
  const wl = $('ppWordlist').value
  if (wl === 'custom') {
    loadCustomWordlist().then(words => {
      if (words && words.length) {
        el.textContent = getMessage('ppWlCustomOk', [String(words.length)], `Custom wordlist: ${words.length} words on this device (never synced).`)
      } else {
        el.textContent = getMessage('ppWlCustomEmpty', undefined, 'No custom wordlist on this device yet — build one on the Wordlists tab.')
      }
    })
  } else {
    el.textContent = getMessage('ppWlStatus', undefined, 'EFF wordlists are bundled offline. Build a custom list on the Wordlists tab.')
  }
}

async function applyPreset(name) {
  const p = PRESETS[name]
  if (!p || !p.random) return
  const prefs = await loadPrefs()
  prefs.random = { ...prefs.random, ...p.random }
  await savePrefs(prefs)
  await refreshGenerator()
  switchLab('random')
  toast(getMessage('toastPresetApplied', [name], `Applied preset: ${name}`))
}

// ── Generation ──────────────────────────────────────────────────────────────

function labOptionsFor(mode) {
  switch (mode) {
    case 'random': return readGeneratorForm()
    case 'passphrase': return {
      wordCount: parseInt($('ppWordsOpt').value, 10) || 6,
      wordlist: $('ppWordlist').value,
      separator: $('ppSeparatorOpt').value,
      capitalize: $('ppCapitalizeOpt').checked,
      addNumber: $('ppAddNumberOpt').checked,
      addSymbol: $('ppAddSymbolOpt').checked,
      padBetweenWords: $('ppPadOpt').checked,
      minWordLength: parseInt($('ppMinLen').value, 10) || 0,
      maxWordLength: parseInt($('ppMaxLen').value, 10) || 0,
      excludePattern: $('ppExcludePat').value || '',
    }
    case 'pin': return {
      length: parseInt($('pinLengthOpt').value, 10) || 6,
      noRepeats: $('pinNoRepeatsOpt').checked,
      noSequences: $('pinNoSequencesOpt').checked,
    }
    case 'pronounceable': return {
      syllables: parseInt($('prSyllables').value, 10) || 4,
      capitalize: $('prCapitalize').checked,
      addNumber: $('prAddNumber').checked,
      addSymbol: $('prAddSymbol').checked,
    }
  }
  return {}
}

let labFilterResolve = null
function askRelaxFilters(info) {
  return new Promise((resolve) => {
    labFilterResolve = resolve
    $('labFilterBody').textContent = getMessage('labFilterBody', [String(info.filteredSize), String(info.wordCount)], `Only ${info.filteredSize} words match the current filters, but ${info.wordCount} words are needed. Relax the filters for this one generation (the unfiltered list is used) or cancel?`)
    $('labFilterDialog').classList.remove('hidden')
    $('labFilterRelax').focus()
  })
}

let labGenSeq = 0
async function labGenerate({ relaxFilters = false, silent = false } = {}) {
  const seq = ++labGenSeq // latest-wins guard: a newer request supersedes an in-flight one
  const mode = LAB_GENERATING_MODES.includes(labMode) ? labMode : 'random'
  try {
    await ensureBreachCorpus()
    if (mode === 'passphrase') {
      await ensureWordlists()
      if ($('ppWordlist').value === 'custom') {
        const words = await loadCustomWordlist()
        if (!words || words.length < 10) {
          toast(getMessage('ppWlCustomEmpty', undefined, 'No custom wordlist on this device yet — build one on the Wordlists tab.'), 'error')
          return
        }
      }
    }
    const options = labOptionsFor(mode)
    if (mode === 'passphrase' && options.wordlist === 'custom') {
      const words = await loadCustomWordlist()
      options.customWords = words || []
    }
    if (relaxFilters) { options.minWordLength = 0; options.maxWordLength = 0; options.excludePattern = '' }
    const result = await generateSecret({ mode, options, source: 'full-manager' })
    if (seq !== labGenSeq) return // a newer generation already took over
    renderLabSecret(result)
  } catch (e) {
    if (e instanceof PassphraseFilterError) {
      if (seq !== labGenSeq) return
      const relax = await askRelaxFilters({ filteredSize: e.filteredSize, wordCount: e.wordCount })
      if (relax) await labGenerate({ relaxFilters: true })
      return
    }
    if (!silent) toast(e.message, 'error')
  }
}

// ── Output rendering ────────────────────────────────────────────────────────

function maskOutput(v) {
  const s = String(v)
  return s.length <= 48 ? '•'.repeat(s.length) : '•'.repeat(48) + '…'
}

function renderComposition(meta) {
  const el = $('labComposition')
  const comp = meta && meta.composition
  if (!comp || !labPrefs.showComposition) { el.classList.add('hidden'); el.innerHTML = ''; return }
  const segs = [
    ['lower', 'a-z', '#84cc16'],
    ['upper', 'A-Z', '#10b981'],
    ['digit', '0-9', '#f59e0b'],
    ['symbol', '!@#', '#38bdf8'],
  ]
  const total = comp.lower + comp.upper + comp.digit + comp.symbol
  if (!total) { el.classList.add('hidden'); el.innerHTML = ''; return }
  el.innerHTML = segs.map(([k, label, color]) => {
    const n = comp[k] || 0
    if (!n) return ''
    return `<span class="lab-comp-seg" style="width:${(n / total) * 100}%;background:${color}"></span>`
  }).join('') +
    `<div class="lab-comp-legend">${segs.map(([k, label, color]) =>
      (comp[k] ? `<span><i style="background:${color}"></i>${label} ×${comp[k]}</span>` : '')).join('')}</div>`
  el.classList.remove('hidden')
}

function renderLabSecret(result) {
  labSecret = result
  labRevealed = true
  const isMn = result.kind === 'mnemonic'
  $('labOutput').textContent = result.value
  $('labOutput').classList.remove('lab-masked')
  $('labRevealBtn').textContent = getMessage('entryHideBtn', undefined, 'Hide')
  $('labRevealBtn').setAttribute('aria-pressed', 'true')
  $('labBits').textContent = getMessage('labBitsLine', [result.kind, String(Math.round(result.entropyBits))], `${result.kind} · ≈${Math.round(result.entropyBits)} bits`)
  if ($('genHeroStateText')) {
    $('genHeroStateText').textContent = `WebCrypto CSPRNG · Active mode: ${result.kind} (≈${Math.round(result.entropyBits)} bits) · 100% offline`
  }
  if (isMn) {
    $('labStrengthBadge').hidden = true
    $('labStrengthFill').style.width = '100%'
    $('labStrengthFill').style.background = '#10b981'
    $('labCrack').textContent = getMessage('labMnCrack', undefined, '128+ bits of entropy — offline brute force is not the threat model; handle the words accordingly.')
    renderComposition(null)
  } else {
    const a = analyzePassword(result.value)
    // R74 §4 (F-R74-GEN-1): a GENERATED secret is judged by the canonical
    // constrained model bits — the model-blind char-level re-derivation can
    // EXCEED them (digits-only noSequences L13: 43.2 naive vs 37.0 canonical;
    // a 5-word passphrase: ~141 char-level vs 51.6 canonical) and the badge
    // and crack estimate must never claim more than the model permits.
    if (a) a.effective = result.entropyBits
    const badge = strengthBadge(a)
    $('labStrengthBadge').hidden = false
    $('labStrengthBadge').textContent = badge.label
    $('labStrengthBadge').style.background = badge.color
    $('labStrengthBadge').setAttribute('aria-label', getMessage('strengthBadgeAria', [badge.label], badge.aria))
    $('labStrengthFill').style.width = badge.score + '%'
    $('labStrengthFill').style.background = badge.color
    $('labCrack').textContent = getMessage('labCrackLine', [crackTime(a.effective)], `${crackTime(a.effective)} offline (estimate)`)
    renderComposition(result.metadata)
  }
  $('labCopyBtn').disabled = false
  $('labUseBtn').disabled = false
  $('labSaveBtn').disabled = false
  scheduleAutoHide()
  pushLabHistory(result)
}

function scheduleAutoHide() {
  if (labAutoHideTimer) { clearTimeout(labAutoHideTimer); labAutoHideTimer = null }
  const secs = parseInt($('labAutoHide').value, 10) || 0
  if (!secs || !labSecret || !labRevealed) return
  // R72 §3.2 — display-only masking. It never closes a consent/review
  // dialog and never erases clipboard or history.
  labAutoHideTimer = setTimeout(() => {
    if (labSecret && labRevealed) labSetRevealed(false)
  }, secs * 1000)
}

function labSetRevealed(revealed) {
  if (!labSecret) return
  labRevealed = revealed
  if (revealed) {
    $('labOutput').textContent = labSecret.value
    $('labOutput').classList.remove('lab-masked')
    $('labRevealBtn').textContent = getMessage('entryHideBtn', undefined, 'Hide')
    $('labRevealBtn').setAttribute('aria-pressed', 'true')
    scheduleAutoHide()
  } else {
    $('labOutput').textContent = maskOutput(labSecret.value)
    $('labOutput').classList.add('lab-masked')
    $('labRevealBtn').textContent = getMessage('entryRevealBtn', undefined, 'Show')
    $('labRevealBtn').setAttribute('aria-pressed', 'false')
    if (labAutoHideTimer) { clearTimeout(labAutoHideTimer); labAutoHideTimer = null }
  }
}

// ── Copy (canonical compare-before-clear guard) ─────────────────────────────

async function labCopy() {
  if (!labSecret) return
  const value = labSecret.value
  const ok = await copy(value)
  if (!ok) { toast(getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), 'error'); return }
  toast(getMessage('toastCopiedAutoClear', undefined, 'Copied — clears in 20 s unless you replace it'))
  setTimeout(async () => {
    try {
      const cur = await navigator.clipboard.readText().catch(() => '')
      if (cur === value) await navigator.clipboard.writeText('')
    } catch { /* compare-before-clear: keep whatever the user copied */ }
  }, 20000)
}

// ── QR (explicit reveal; high-risk confirm for mnemonics) ───────────────────

async function labQr() {
  if (!labSecret) return
  if (labSecret.kind === 'mnemonic') {
    const ok = await labConfirm(getMessage('labQrMnConfirm', undefined, 'A QR code of your wallet seed phrase contains the ENTIRE wallet secret. Anyone who sees or screenshots the image can take the funds. Show it?'))
    if (!ok) return
  }
  const r = await bgSend('QR_ENCODE', { text: labSecret.value })
  if (r && r.ok && r.dataUrl) {
    $('labQrImg').src = r.dataUrl
    $('labQrWrap').classList.remove('hidden')
  } else {
    toast((r && r.error) || getMessage('labQrFailed', undefined, 'QR encoding failed — the words are still valid; copy them instead.'), 'error')
  }
}

function labQrPng() {
  const img = $('labQrImg')
  if (!img || !img.src) return
  const a = document.createElement('a')
  a.href = img.src
  a.download = labSecret && labSecret.kind === 'mnemonic' ? 'ucrypt-wallet-seed-QR.png' : 'ucrypt-secret-QR.png'
  a.click()
}

// ── Save / Use on page (explicit actions only; never auto-submit) ───────────

function labSave() {
  if (!labSecret) return
  // Existing atomic save path: prefill the entry dialog; the user names the
  // entry and presses Save (SAVE_ENTRY with strength/breach warnings).
  openEntryDialog(null)
  const pw = $('entryPassword')
  pw.value = labSecret.value
  pw.type = 'password'
  const reveal = $('entryRevealBtn')
  reveal.textContent = getMessage('entryRevealBtn', undefined, 'Show')
  reveal.setAttribute('aria-pressed', 'false')
  updateEntryStrength()
  $('entryDomain').focus()
}

async function labUse() {
  if (!labSecret) return
  const r = await bgSend('USE_GENERATED_SECRET', { value: labSecret.value })
  if (r && r.ok) {
    toast(getMessage('labUseFilled', undefined, 'Filled on the page — nothing was submitted'))
  } else {
    toast((r && r.error) || getMessage('labUseNoField', undefined, 'No eligible password field found on the current page'), 'error')
  }
}

// ── High-risk confirm dialog (never auto-dismissed) ─────────────────────────

function labConfirm(body) {
  return new Promise((resolve) => {
    labPendingConfirm = resolve
    $('labConfirmBody').textContent = body
    $('labConfirm').classList.remove('hidden')
    $('labConfirmOk').focus()
  })
}

function labConfirmResolve(v) {
  if (labPendingConfirm) {
    const r = labPendingConfirm
    labPendingConfirm = null
    $('labConfirm').classList.add('hidden')
    r(v)
  }
}

// ── Bulk mode ───────────────────────────────────────────────────────────────

async function bulkGenerate() {
  const mode = $('bulkMode').value
  const count = Math.max(2, Math.min(100, parseInt($('bulkCount').value, 10) || 10))
  $('bulkCount').value = String(count)
  try {
    await ensureBreachCorpus()
    if (mode === 'passphrase') await ensureWordlists()
    const options = labOptionsFor(mode)
    if (mode === 'passphrase' && options.wordlist === 'custom') {
      const words = await loadCustomWordlist()
      options.customWords = words || []
    }
    const results = []
    for (let i = 0; i < count; i++) {
      results.push(await generateSecret({ mode, options, source: 'bulk' }))
    }
    labBulk = results
    renderBulk()
  } catch (e) {
    if (e instanceof PassphraseFilterError) {
      const relax = await askRelaxFilters({ filteredSize: e.filteredSize, wordCount: e.wordCount })
      if (relax) {
        const o = labOptionsFor(mode)
        o.minWordLength = 0; o.maxWordLength = 0; o.excludePattern = ''
        if (o.wordlist === 'custom') o.customWords = (await loadCustomWordlist()) || []
        labBulk = []
        for (let i = 0; i < count; i++) labBulk.push(await generateSecret({ mode, options: o, source: 'bulk' }))
        renderBulk()
      }
      return
    }
    toast(e.message, 'error')
  }
}

function renderBulk() {
  const list = $('bulkList')
  list.textContent = ''
  $('bulkExportBtn').disabled = labBulk.length === 0
  $('bulkClearBtn').disabled = labBulk.length === 0
  if (!labBulk.length) {
    list.classList.add('hidden')
    $('bulkMeta').classList.add('hidden')
    return
  }
  list.classList.remove('hidden')
  $('bulkMeta').classList.remove('hidden')
  $('bulkMeta').textContent = getMessage('bulkMeta', [String(labBulk.length)], `${labBulk.length} secrets in this session — not saved anywhere until you export.`)
  // DOM is bounded by the 2–100 cap; the container scrolls.
  labBulk.forEach((r, i) => {
    const row = document.createElement('div')
    row.className = 'bulk-row'
    row.setAttribute('role', 'listitem')
    const num = document.createElement('span')
    num.className = 'bulk-num'
    num.textContent = String(i + 1)
    const val = document.createElement('code')
    val.className = 'bulk-val'
    val.textContent = r.value
    val.title = `${r.kind} · ≈${Math.round(r.entropyBits)} bits`
    const btn = document.createElement('button')
    btn.className = 'btn btn-outline btn-sm'
    btn.textContent = getMessage('copyBtn', undefined, 'Copy')
    btn.onclick = async () => {
      const ok = await copy(r.value)
      if (ok) toast(getMessage('toastCopiedAutoClear', undefined, 'Copied — clears in 20 s unless you replace it'))
      else toast(getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), 'error')
    }
    row.appendChild(num)
    row.appendChild(val)
    row.appendChild(btn)
    list.appendChild(row)
  })
}

async function bulkExport() {
  if (!labBulk.length) return
  // R72 §5 — export requires an explicit plaintext warning + confirmation.
  const ok = confirm(getMessage('bulkExportWarn', [String(labBulk.length)], `Export ${labBulk.length} secrets as PLAINTEXT? The file is not encrypted — anyone who can read it has every secret. Delete it immediately after use.`))
  if (!ok) return
  const text = labBulk.map(r => r.value).join('\n') + '\n'
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'ucrypt-bulk-secrets.txt'
  a.click()
  URL.revokeObjectURL(url)
  toast(getMessage('bulkExported', undefined, 'Exported — the file is PLAINTEXT, delete it after use'))
}

function bulkClear() {
  labBulk = []
  renderBulk()
}

// ── Analyze mode (extension-local; cleared on tab change/lock/close) ────────

async function analyzeRun() {
  const pw = $('anInput').value
  const el = $('anResult')
  if (!pw) { toast(getMessage('anNeedInput', undefined, 'Type or paste a password to analyze'), 'error'); return }
  try {
    await ensureBreachCorpus()
    const a = analyzePassword(pw)
    const badge = strengthBadge(a)
    const rows = []
    rows.push(`<div class="label-row"><span class="vault-strength" style="background:${badge.color};color:#fff">${badge.label}</span><span>${getMessage('labBitsLine', ['password', String(Math.round(a.effective))], `password · ≈${Math.round(a.effective)} bits`)}</span></div>`)
    rows.push(`<p>${getMessage('anNaiveLine', [String(Math.round(a.naive)), String(Math.round(a.effective))], `Naive alphabet entropy ≈${Math.round(a.naive)} bits · after patterns ≈${Math.round(a.effective)} bits`)}</p>`)
    rows.push(`<p>${getMessage('anCrackLine', [crackTime(a.effective)], `Offline estimate: ${crackTime(a.effective)} at 10¹³ guesses/s — an estimate, never a guarantee.`)}</p>`)
    if (a.patterns.length) {
      rows.push(`<ul>${a.patterns.map(p => `<li>${p}</li>`).join('')}</ul>`)
    } else {
      rows.push(`<p>${getMessage('anNoPatterns', undefined, 'No common patterns detected.')}</p>`)
    }
    rows.push(`<ul>${a.recs.map(r => `<li>${r}</li>`).join('')}</ul>`)
    el.innerHTML = rows.join('')
    el.classList.remove('hidden')
  } catch (e) {
    toast(e.message, 'error')
  }
}

function labClearAnalyze() {
  // R72 §4 — the typed password NEVER survives the tab, lock, close or Clear.
  const inp = $('anInput')
  if (inp) inp.value = ''
  const res = $('anResult')
  if (res) { res.textContent = ''; res.classList.add('hidden') }
  const chk = $('mnCheckInput')
  if (chk) chk.value = ''
  const chkR = $('mnCheckResult')
  if (chkR) { chkR.textContent = ''; chkR.classList.add('hidden') }
}

// ── Mnemonic mode (high-risk, isolated) ─────────────────────────────────────

// R154 §6 (B.2) — the INLINE render (the owner's E-2 spec): the phrase goes
// DIRECTLY BELOW the Generate button. DOM-only — the R72 law holds (never
// persisted, never logged, cleared by navigation); the shared lab output
// still renders for congruence, but THIS block is the primary surface.
let mnPhraseValue = ''

function mnShowPhrase(result) {
  mnPhraseValue = String(result.value || '')
  const card = $('mnPhraseCard')
  const text = $('mnPhraseText')
  const meta = $('mnPhraseMeta')
  if (!card || !text) return
  text.textContent = mnPhraseValue
  card.classList.remove('hidden')
  if (meta) meta.textContent = getMessage('mnPhraseMeta', [String(result.wordCount || ''), String(Math.round(result.entropyBits || 0))], `${result.wordCount || ''} words · ≈${Math.round(result.entropyBits || 0)} bits — select-all friendly, never saved.`)
}

function mnHidePhrase() {
  // THE HIDE: the words leave the DOM — nothing is stored anywhere (the R72
  // boundary). The shared lab output's own reveal state is untouched.
  mnPhraseValue = ''
  const card = $('mnPhraseCard')
  const text = $('mnPhraseText')
  if (text) text.textContent = ''
  if (card) card.classList.add('hidden')
}

async function mnCopyPhrase() {
  if (!mnPhraseValue) return
  try {
    await ensureBip39()
    const ok = await labConfirm(getMessage('labMnConfirm', undefined, 'You are about to copy a wallet seed phrase. Anyone with these words can take the funds. Never share it, never paste it into a website. Copy it now?'))
    if (!ok) return
    const done = await copy(mnPhraseValue)
    const btn = $('mnPhraseCopyBtn')
    if (done && btn) {
      btn.textContent = getMessage('mnPhraseCopied', undefined, 'Copied ✓')
      setTimeout(() => { try { btn.textContent = getMessage('mnPhraseCopy', undefined, 'Copy phrase') } catch { /* the label returns */ } }, 2500)
    }
  } catch (e) {
    mnShowPhraseError(e)
  }
}

function mnShowPhraseError(e) {
  // LAW #89 — never a silent no-op: the failure surfaces as a NAMED inline
  // error at the very place the phrase would have rendered.
  const el = $('mnPhraseError')
  if (!el) return
  el.textContent = String((e && e.message) || e).slice(0, 220)
  el.classList.remove('hidden')
}

async function mnemonicGenerate() {
  const errEl = $('mnPhraseError')
  if (errEl) errEl.classList.add('hidden')
  try {
    await ensureBip39()
    const words = parseInt($('mnLength').value, 10) || 12
    const result = await generateSecret({ mode: 'mnemonic', options: { words }, source: 'full-manager' })
    const ok = await labConfirm(getMessage('labMnConfirm', undefined, 'You are about to reveal a wallet seed phrase. Anyone with these words can take the funds. Never share it, never paste it into a website. Reveal it now?'))
    if (!ok) return // the phrase is discarded — never rendered, never stored
    switchLab('mnemonic')
    mnShowPhrase(result) // R154: DIRECTLY BELOW the button — first
    renderLabSecret(result)
  } catch (e) {
    mnShowPhraseError(e)
    toast(e.message, 'error')
  }
}

async function mnemonicCheck() {
  const el = $('mnCheckResult')
  const phrase = $('mnCheckInput').value
  if (!phrase.trim()) { toast(getMessage('anNeedInput', undefined, 'Type or paste a password to analyze'), 'error'); return }
  try {
    await ensureBip39()
    const r = await validateMnemonic(phrase)
    let msg
    if (r.valid) {
      msg = getMessage('mnCheckOk', [String(r.wordCount), String(r.entropyBits)], `✓ Valid BIP-39 phrase — ${r.wordCount} words, ≈${r.entropyBits} bits. Checksum OK.`)
    } else if (r.reason === 'bad-length') {
      msg = getMessage('mnCheckBadLength', undefined, '✗ Not a valid BIP-39 length (12/15/18/21/24 words).')
    } else if (r.reason === 'unknown-word') {
      msg = getMessage('mnCheckUnknown', [r.unknownWords.join(', ')], `✗ Unknown word(s): ${r.unknownWords.join(', ')}`)
    } else {
      msg = getMessage('mnCheckBadChecksum', undefined, '✗ Words are known but the BIP-39 checksum does not match — a word is likely mistyped or out of order.')
    }
    el.textContent = msg
    el.classList.remove('hidden')
  } catch (e) {
    toast(e.message, 'error')
  }
}

// ── Session history (redacted metadata, default off, never values) ──────────

function pushLabHistory(result) {
  if (!result || result.kind === 'mnemonic') return // NEVER listed
  const cb = $('labHistoryEnabled')
  if (!cb || !cb.checked) return
  const valStr = String(result.value || '')
  if (!valStr) return
  // Avoid pushing duplicate consecutive entries for the exact same secret
  const last = labSessionHistory[labSessionHistory.length - 1]
  if (last && last.value === valStr && last.kind === result.kind) {
    renderLabHistory()
    return
  }
  labSessionHistory.push({
    kind: result.kind,
    bits: Math.round(result.entropyBits || 0),
    at: Date.now(),
    preview: valStr.slice(0, 2) + '…' + valStr.length + ' chars',
    value: valStr,
  })
  if (labSessionHistory.length > 100) labSessionHistory.shift()
  renderLabHistory()
}

function renderLabHistory() {
  const list = $('labHistoryList')
  const badge = $('labHistoryCountBadge')
  const emptyEl = $('labHistoryEmptyState')
  const enabled = !!($('labHistoryEnabled') && $('labHistoryEnabled').checked)
  const sw = $('labHistorySwitch')
  if (sw) sw.classList.toggle('on', enabled)

  if (badge) {
    badge.textContent = enabled
      ? `${labSessionHistory.length} saved`
      : 'Off'
    badge.style.color = enabled ? 'var(--accent, #22c55e)' : 'var(--muted)'
    badge.style.borderColor = enabled ? 'rgba(34,197,94,0.35)' : 'var(--border)'
  }

  if (emptyEl) {
    if (!enabled) {
      emptyEl.hidden = false
      emptyEl.textContent = 'Toggle "Keep this session" ON to record secrets generated during this session (auto-wiped when locked or closed).'
    } else if (labSessionHistory.length === 0) {
      emptyEl.hidden = false
      emptyEl.textContent = 'Session history is ON — click Regenerate to record secrets here.'
    } else {
      emptyEl.hidden = true
    }
  }

  if (!list) return
  list.textContent = ''
  for (const h of [...labSessionHistory].reverse()) {
    const li = document.createElement('li')
    li.className = 'lab-history-row'
    li.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 8px;border-radius:6px;background:rgba(255,255,255,0.03);border:1px solid var(--border);margin-bottom:4px'
    const meta = document.createElement('span')
    meta.textContent = `${h.preview} · ${h.kind} · ${h.bits} bits · ${new Date(h.at).toLocaleTimeString()}`
    li.appendChild(meta)
    if (h.value) {
      const copyBtn = document.createElement('button')
      copyBtn.type = 'button'
      copyBtn.className = 'btn sm ghost'
      copyBtn.style.cssText = 'padding:2px 8px;font-size:11px'
      copyBtn.textContent = getMessage('genCopyBtn', undefined, 'Copy')
      copyBtn.addEventListener('click', async () => {
        await copyAndScheduleClear(h.value)
        toast(getMessage('toastCopiedAutoClear', undefined, 'Copied to clipboard (auto-clears in 30s)'))
      })
      li.appendChild(copyBtn)
    }
    list.appendChild(li)
  }
}

function labClearHistory() {
  labSessionHistory = []
  renderLabHistory()
}

/** R72 §4/§8 — page lifecycle scrub: typed analysis input, session history
 *  metadata and the in-memory secrets never survive close/bfcache/lock. */
function labScrubSession() {
  labClearAnalyze()
  labSessionHistory = []
  labBulk = []
  labSecret = null
  labRevealed = true
  if (labAutoHideTimer) { clearTimeout(labAutoHideTimer); labAutoHideTimer = null }
  $('labOutput').textContent = '—'
  $('labCopyBtn').disabled = true
  $('labUseBtn').disabled = true
  $('labSaveBtn').disabled = true
  $('labStrengthBadge').hidden = true
  $('labStrengthFill').style.width = '0'
  $('labBits').textContent = '—'
  $('labCrack').textContent = '—'
  renderComposition(null)
  const qrWrap = $('labQrWrap')
  if (qrWrap) qrWrap.classList.add('hidden')
}



// --- URL scraper (direct fetch — no proxy, host_permissions grants CORS) --

// R72 §7 — the wordlist fetch now runs in the SERVICE WORKER (WORDLIST_FETCH):
// HTTPS-only, credentials omitted, no auth headers, cache-bypassed, 15 s
// timeout, 2 MB cap, text/HTML/JSON validation, deterministic extraction and
// NO proxy fallback. The page only previews and saves the result.
async function scrapeWordlist() {
  const url = $('scrapeUrl').value.trim()
  const resultEl = $('scrapeResult')
  resultEl.classList.remove('hidden')
  resultEl.innerHTML = '<div class="spinner"></div> ' + getMessage('wlScraping', undefined, 'Scraping…')
  if (!url) {
    resultEl.innerHTML = `<span class="err">${getMessage('wlEnterUrl', undefined, 'Please enter a URL.')}</span>`
    return
  }
  const r = await bgSend('WORDLIST_FETCH', { url })
  if (r && r.ok) {
    const unique = r.words || []
    await saveCustomWordlist(unique)
    resultEl.innerHTML =
      `<span class="ok">${getMessage('wlScrapedOk', [String(unique.length)], `✓ Scraped <strong>${unique.length}</strong> unique words`)}</span>` +
      `<div class="word-preview">${getMessage('wlSample', [unique.slice(0, 30).join(', ')], `Sample: ${unique.slice(0, 30).join(', ')}…`)}</div>` +
      `<div class="card-help card-help-subtle">${getMessage('wlLocalNote', undefined, 'Stored on this device only — custom wordlists are never synced.')}</div>`
    $('exportWordlistBtn').disabled = false
    $('deleteWordlistBtn').disabled = false
    refreshWlEmptyState()
    refreshWlHeroStatus(unique.length)
    updatePpWlStatus()
    toast(getMessage('toastWlSaved', [String(unique.length)], `Saved ${unique.length} words`))
  } else {
    const err = (r && r.error) || 'Fetch failed'
    const hint = (r && r.hint) || getMessage('wlImportHint', undefined, 'You can import a .json wordlist file or paste text below instead.')
    resultEl.innerHTML = `<span class="err">✗ ${err}</span><div class="card-help card-help-subtle">${hint}</div>`
  }
}

async function exportWordlist() {
  const words = await loadCustomWordlist()
  if (!words || !words.length) return
  const blob = new Blob([JSON.stringify(words, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'ucrypt-custom-wordlist.json'
  a.click()
  URL.revokeObjectURL(url)
  toast(getMessage('toastWlExported', undefined, 'Wordlist exported'))
}

function importWordlist(file) {
  const reader = new FileReader()
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result)
      if (!Array.isArray(data)) throw new Error(getMessage('wlNotArray', undefined, 'Not an array'))
      const words = data.filter(w => typeof w === 'string' && w.length >= 2 && w.length <= 20)
      if (words.length < 10) throw new Error(getMessage('wlNeedTen', undefined, 'Need at least 10 valid words'))
      await saveCustomWordlist(words)
      const resultEl = $('scrapeResult')
      resultEl.classList.remove('hidden')
      resultEl.innerHTML = `<span class="ok">${getMessage('wlImportedOk', [String(words.length)], `✓ Imported <strong>${words.length}</strong> words`)}</span>`
      $('exportWordlistBtn').disabled = false
      $('deleteWordlistBtn').disabled = false
      refreshWlEmptyState()
      refreshWlHeroStatus(words.length)
      updatePpWlStatus()
      toast(getMessage('toastWlImported', [String(words.length)], `Imported ${words.length} words`))
    } catch (err) {
      toast(getMessage('toastImportFailed', [err.message], 'Import failed: ' + err.message), 'error')
    }
  }
  reader.readAsText(file)
}

function refreshWlHeroStatus(count = 0) {
  const n = Number(count) || 0
  const stateEl = $('wlHeroStateText')
  if (stateEl) {
    stateEl.textContent = n > 0
      ? `EFF Large (7,776) & Short (1,296) active · Custom list: ${n} words stored locally`
      : 'EFF Large (7,776 words) & Short (1,296 words) bundled offline · No custom list yet'
  }
  const chipEl = $('wlChipScrapeText')
  if (chipEl) {
    chipEl.textContent = n > 0 ? `Custom list: ${n} words` : 'HTTPS URL / Text Builder'
  }
}

function extractCustomWordsFromText(rawText) {
  const tokens = String(rawText || '').toLowerCase().match(/[a-z]{3,16}/g) || []
  const seen = new Set()
  const unique = []
  for (const w of tokens) {
    if (!seen.has(w)) {
      seen.add(w)
      unique.push(w)
      if (unique.length >= 20000) break
    }
  }
  return unique
}

const SAMPLE_CUSTOM_WORDLIST_TEXT = [
  'albedo', 'altair', 'amber', 'anchor', 'andromeda', 'apogee', 'aquamarine', 'arbor', 'arcturus', 'argon',
  'astrolabe', 'aurora', 'azimuth', 'basalt', 'beacon', 'beryl', 'bismuth', 'blizzard', 'borealis', 'bramble',
  'cadence', 'caldera', 'canopy', 'canyon', 'capella', 'caravel', 'cascade', 'cassini', 'cedar', 'celestial',
  'centauri', 'cerulean', 'chalice', 'chronicle', 'cipher', 'cirrus', 'citadel', 'cobalt', 'comet', 'compass',
  'conifer', 'constellation', 'copper', 'corona', 'cosmos', 'crater', 'crescent', 'crimson', 'crystal', 'cygnus',
  'delta', 'deneb', 'diadem', 'digest', 'dolphin', 'draco', 'dynamo', 'eclipse', 'edifice', 'emerald',
  'emblem', 'ember', 'enigma', 'entropy', 'equinox', 'estuary', 'falcon', 'feldspar', 'filament', 'fjord',
  'flint', 'fortress', 'fresco', 'galaxy', 'galleon', 'garnet', 'gazelle', 'gemini', 'geode', 'glacier',
  'granite', 'gravity', 'halcyon', 'harbor', 'harmony', 'helios', 'horizon', 'hyperion', 'igneous', 'indigo',
  'ionosphere', 'iridium', 'island', 'jasper', 'juniper', 'kestrel', 'kinetic', 'krypton', 'lagoon', 'lantern',
  'lapis', 'latitude', 'lattice', 'legend', 'lichen', 'lithium', 'lodestar', 'lumen', 'lyra', 'magnetar',
  'malachite', 'addendum', 'mariner', 'meadow', 'meridian', 'meteor', 'mirage', 'monolith', 'monsoon', 'nebula'
].join(' ')

async function buildCustomWordlistFromPaste(rawText) {
  const resultEl = $('scrapeResult')
  const unique = extractCustomWordsFromText(rawText)
  if (unique.length < 10) {
    if (resultEl) {
      resultEl.classList.remove('hidden')
      resultEl.innerHTML = `<span class="err">✗ Need at least 10 unique words (3–16 letters each). Found ${unique.length}.</span>`
    }
    toast(getMessage('wlNeedTen', undefined, 'Need at least 10 valid words'), 'error')
    return
  }
  await saveCustomWordlist(unique)
  if (resultEl) {
    resultEl.classList.remove('hidden')
    resultEl.innerHTML =
      `<span class="ok">✓ Built custom wordlist with <strong>${unique.length}</strong> unique words</span>` +
      `<div class="word-preview">${getMessage('wlSample', [unique.slice(0, 30).join(', ')], `Sample: ${unique.slice(0, 30).join(', ')}…`)}</div>` +
      `<div class="card-help card-help-subtle">${getMessage('wlLocalNote', undefined, 'Stored on this device only — custom wordlists are never synced.')}</div>`
  }
  $('exportWordlistBtn').disabled = false
  $('deleteWordlistBtn').disabled = false
  refreshWlEmptyState()
  refreshWlHeroStatus(unique.length)
  updatePpWlStatus()
  toast(getMessage('toastWlSaved', [String(unique.length)], `Saved ${unique.length} words`))
}

// R173 §Arc B (B8) — the Wordlists tab speaks its empty state on arrival
// (the reference pattern: every tab names where it stands).
function refreshWlEmptyState() {
  const line = $('wlEmptyState')
  if (line) line.hidden = !$('exportWordlistBtn').disabled
}

async function deleteCustomWordlist() {
  if (!confirm(getMessage('confirmDeleteWl', undefined, 'Delete the custom wordlist?'))) return
  await removeCustomWordlist()
  $('scrapeResult').classList.add('hidden')
  $('exportWordlistBtn').disabled = true
  $('deleteWordlistBtn').disabled = true
  refreshWlEmptyState()
  refreshWlHeroStatus(0)
  updatePpWlStatus()
  toast(getMessage('toastWlDeleted', undefined, 'Custom wordlist deleted'))
}

// --- Export / Import vault (encrypted .json) ------------------------------

async function exportVault() {
  // Read the raw encrypted blob from chrome.storage.local
  const keys = ['ucrypt:vault', 'ucrypt:vaultSalt']
  const data = await new Promise((r) => chrome.storage.local.get(keys, r))
  const blob = data['ucrypt:vault']
  const salt = data['ucrypt:vaultSalt']
  if (!blob || !salt) {
    toast(getMessage('toastExportEmpty', undefined, 'Vault is empty — nothing to export'), 'error')
    return
  }
  const payload = JSON.stringify({
    format: 'ucrypt-vault-v1',
    encrypted: blob,
    salt,
    exportedAt: new Date().toISOString(),
  }, null, 2)
  // R165 ARC G — THE EXPORT DOOR: the journal row (additive; the receipt
  // cites what left, when — counts only, never contents).
  try {
    const j = await new Promise((r) => chrome.storage.local.get('ucrypt:door:journal', r))
    const arr = Array.isArray(j['ucrypt:door:journal']) ? j['ucrypt:door:journal'] : []
    arr.push({ kind: 'encrypted-backup', at: new Date().toISOString(), bytes: payload.length, confirmations: 0 })
    await new Promise((r) => chrome.storage.local.set({ 'ucrypt:door:journal': arr.slice(-8) }, r))
  } catch { /* the journal never blocks the export */ }
  const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = 'ucrypt-vault-export.json'
  a.click()
  URL.revokeObjectURL(url)
  toast(getMessage('toastExportDone', undefined, 'Encrypted vault exported ✓'))
}

function importVault(file) {
  const reader = new FileReader()
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result)
      if (data.format !== 'ucrypt-vault-v1' || !data.encrypted || !data.salt) {
        throw new Error(getMessage('impNotUcrypt', undefined, 'Not a UCrypt vault export'))
      }
      if (!confirm(getMessage('confirmImportOverwrite', undefined, 'Importing will overwrite the current vault on this device. Continue?'))) return
      await new Promise((r) => chrome.storage.local.set({
        'ucrypt:vault': data.encrypted,
        'ucrypt:vaultSalt': data.salt,
      }, r))
      // v2.13.0 — R22-F5: ask the worker to drop its in-memory vault and
      // re-read storage. The old chrome.runtime.reload() restarted the WHOLE
      // extension: it killed every open popup/options page and, observed
      // clinically on Chromium 153, the replacement worker never booted.
      let refreshed = false
      try {
        const r = await bgSend('VAULT_IMPORT_APPLIED')
        refreshed = !!(r && r.ok)
      } catch { /* handled below */ }
      if (refreshed) {
        toast(getMessage('toastImportLocked', undefined, 'Vault imported — it is locked until you unlock it'))
      } else {
        toast(getMessage('toastImportStale', undefined, 'Vault imported, but the background could not refresh — reload the extension once (chrome://extensions)'), 'error')
      }
      refreshVault()
    } catch (err) {
      toast(getMessage('toastImportFailed', [err.message], 'Import failed: ' + err.message), 'error')
    }
  }
  reader.readAsText(file)
}

// --- v2.7.0: Import Center (universal browser/manager migration) ------------

// ═══════════════════════════════════════════════════════════════════════════
// R90 §2.2 — DIRECT browser-history import with a date-range selector
// (canonical completion, original R42 law). This REPLACES the whole-file /
// MAX_HISTORY=5000 behavior: history rows in dropped export files are now
// skipped with a typed pointer to this surface. The law:
//   - the user picks 7, 30, or 90 days (DEFAULT 30 — enforced in the UI)
//   - hard cap 20,000 rows per import
//   - ONE explicit chrome.history.search({ text:'', startTime, endTime,
//     maxResults }) — no incremental scanning, no deletions, ever
//   - PREVIEW before write; the write goes through IMPORT_ENTRIES →
//     saveEntriesBatch (one persist, one eligible push)
//   - pseudo-domain __history__ (never autofill material)
//   - the copy says this does NOT restore address-bar suggestions on
//     another device (the browser history stays device-local)
// The pure decision lives here as testable helpers; the chrome.* calls are
// wired at the bottom of this section.
// ═══════════════════════════════════════════════════════════════════════════

// R90 §2.2 — the PURE decision lives in lib/importers.js (unit tested,
// imported above as HISTORY_LAW); options.js wires the chrome.* calls and
// the DOM.

let historyState = { entries: [], days: 30 }

async function icHistoryHasPermission() {
  try { return await chrome.permissions.contains({ permissions: ['history'] }) } catch { return false }
}

async function icHistoryRequestPermission() {
  try { return await chrome.permissions.request({ permissions: ['history'] }) } catch { return false }
}

function icHistoryReset() {
  historyState = { entries: [], days: HISTORY_LAW.defaultDays }
  $('icHistPreview').classList.add('hidden')
  $('icHistPreview').textContent = ''
  $('icHistActions').classList.add('hidden')
  $('icHistGrant').classList.add('hidden')
}

async function icHistoryPreview(days) {
  const range = historyRangeOrDefault(days)
  historyState.days = range
  const perm = await icHistoryHasPermission()
  if (!perm) {
    // The grant button is the user-gesture affordance chrome.permissions
    // requires; the preview cannot run without it (typed, never silent).
    $('icHistGrant').classList.remove('hidden')
    $('icHistPreview').classList.remove('hidden')
    $('icHistPreview').textContent = getMessage('icHistNeedsPerm', undefined, 'History access is off — press "Grant history access" to continue.')
    $('icHistActions').classList.add('hidden')
    return
  }
  $('icHistGrant').classList.add('hidden')
  // ONE explicit search — the exact canonical call shape.
  const endTime = Date.now()
  const startTime = endTime - range * 24 * 60 * 60 * 1000
  let items
  try {
    items = await chrome.history.search({ text: '', startTime, endTime, maxResults: HISTORY_LAW.cap + 1 })
  } catch (e) {
    $('icHistPreview').classList.remove('hidden')
    $('icHistPreview').textContent = '✗ ' + (e && e.message ? e.message : 'history.search failed')
    return
  }
  const truncated = Array.isArray(items) && items.length > HISTORY_LAW.cap
  const entries = historyItemsToEntries(truncated ? items.slice(0, 0) : items)
  const summary = historyPreviewSummary(entries, { truncated })
  historyState.entries = entries
  const pv = $('icHistPreview')
  pv.classList.remove('hidden')
  pv.textContent = ''
  const line = document.createElement('div')
  line.textContent = truncated ? `✗ ${summary.message}` : (summary.count ? `✓ ${summary.message}` : summary.message)
  pv.appendChild(line)
  if (summary.count) {
    const span = document.createElement('div')
    span.className = 'card-help'
    span.textContent = getMessage('icHistPreviewSpan',
      [new Date(summary.oldest).toLocaleString(), new Date(summary.newest).toLocaleString(), String(range)],
      `From ${new Date(summary.oldest).toLocaleString()} to ${new Date(summary.newest).toLocaleString()} (last ${range} days) — preview only; nothing saved yet.`)
    pv.appendChild(span)
    const note = document.createElement('div')
    note.className = 'card-help'
    note.textContent = getMessage('icHistNoSuggestions', undefined, 'This saves a private record in your vault; it does not restore address-bar suggestions on another device.')
    pv.appendChild(note)
    $('icHistActions').classList.remove('hidden')
    const btn = $('icHistImportBtn')
    btn.textContent = getMessage('icHistImportN', [String(summary.count)], `Import ${summary.count} pages`)
  } else {
    $('icHistActions').classList.add('hidden')
  }
}

async function icHistoryApply() {
  if (!historyState.entries.length) return
  const btn = $('icHistImportBtn')
  btn.disabled = true
  try {
    // R175 — THE IMPORT THAT ENDS (R-175.5): the history journey is BOUNDED
    // (a live beat, a typed landing, the controls restored on every exit).
    const r = await boundedImport(() => bgSend('IMPORT_ENTRIES', { entries: historyState.entries }), {
      onTick: (secs) => { try { if (btn && !btn.dataset.landed) btn.textContent = `${secs}s…` } catch { /* never throws */ } },
    })
    const pv = $('icHistPreview')
    if (btn) delete btn.dataset.landed
    if (r && r.watchdog) {
      pv.classList.remove('hidden')
      pv.textContent = '⏳ ' + watchdogLandingWords(Number(r.timeoutMs) || undefined)
      return
    }
    if (r && r.ok) {
      const pushNote = r.push ? (r.push.ok ? ' · ' + getMessage('icHistPushed', undefined, 'pushed to your cloud transport') : ' · ' + getMessage('icHistPushFailed', undefined, 'cloud push failed — will retry')) : ''
      pv.classList.remove('hidden')
      pv.textContent = '✓ ' + getMessage('icHistDone', [String(r.added)], `${r.added} pages imported into the encrypted vault.${pushNote}`)
      toast(getMessage('icHistDoneToast', [String(r.added)], `${r.added} history pages imported`), 'info')
      icHistoryResetSoft()
      refreshSync()
    } else {
      pv.classList.remove('hidden')
      pv.textContent = '✗ ' + ((r && r.error) || getMessage('icHistFail', undefined, 'The history import failed — check the file and try again.'))
    }
  } catch (e) {
    const pv = $('icHistPreview')
    pv.classList.remove('hidden')
    pv.textContent = '✗ ' + e.message
  } finally {
    btn.disabled = false
  }
}

function icHistoryResetSoft() {
  historyState = { entries: [], days: HISTORY_LAW.defaultDays }
  $('icHistActions').classList.add('hidden')
}

// ═══════════════════════════════════════════════════════════════════════════
// R101 §3 — THE MIGRATION WIZARD (S3, "Take your stuff with you").
// Orchestration of proven engines in ONE flow — no new import paths (the
// standing law): bookmarks (chrome.bookmarks.getTree → flattenBookmarkTree),
// history (the ic* engine's exact chrome.history.search under HISTORY_LAW),
// passwords (the browser's own export page + the CSV → parseImportFile).
// Preview before write; ONE confirm; IMPORT_ENTRIES → saveEntriesBatch.
// The 13-year-old law: ≤5 user actions for bookmarks+history, typed failures
// that name the fix, no dead ends. The passkeys/cookies/autofill footer
// states the honest boundary.
// ═══════════════════════════════════════════════════════════════════════════

const mwState = {
  browserId: null,
  csvItems: [],      // the passwords CSV's parsed items (logins)
  csvFileName: '',   // the reminder names it
  plan: null,        // the buildFullPlan output (the preview + the confirm)
  historyEntries: [],// the R90 engine's direct entries (its own proven shape)
}

function mwSetBrowser(det) {
  mwState.browserId = det ? det.id : 'chrome'
  const banner = $('migBrowserBanner')
  if (!banner) return
  if (det) {
    banner.hidden = false
    banner.classList.remove('hidden')
    $('migBrowserDetected').textContent = getMessage('migBrowserDetected', [det.name], `Detected browser: ${det.name}`)
  } else {
    banner.hidden = true
    banner.classList.add('hidden')
  }
}

async function mwInit() {
  const card = $('migWizardCard')
  if (!card) return
  // The detection (the R40 engine) + the honest override.
  mwSetBrowser(detectImportBrowser(navigator.userAgentData, navigator))
  const sel = $('migBrowserOverride')
  if (sel) {
    sel.textContent = ''
    for (const id of MIGRATION_BROWSER_IDS) {
      const o = document.createElement('option')
      o.value = id
      o.textContent = (MIGRATION_BROWSERS[id] || {}).name || id
      sel.appendChild(o)
    }
    sel.value = mwState.browserId || 'chrome'
    sel.addEventListener('change', () => {
      const id = sel.value
      mwSetBrowser(id ? { id, name: (MIGRATION_BROWSERS[id] || {}).name || id } : null)
      mwRenderPasswordsLink()
    })
  }
  mwRenderPasswordsLink()
  // The passwords deep link: open the browser's OWN export page (the typed
  // truth names it; the attempt never pretends to read the store).
  $('migPasswordsLinkBtn')?.addEventListener('click', () => {
    const { link, note } = passwordsExportLink(mwState.browserId || 'chrome')
    if (link && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: link }, () => { void chrome.runtime.lastError })
      toast(getMessage('migPasswordsOpened', [link], `Opening ${link} — export the passwords as CSV there.`))
    } else {
      toast(getMessage('migPasswordsManual', [note || 'your browser\'s settings'], `Open ${note || 'your browser\'s settings'} and export the passwords as CSV.`))
    }
  })
  $('migPasswordsCsvBtn')?.addEventListener('click', () => $('migPasswordsCsvFile').click())
  $('migPasswordsCsvFile')?.addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0]
    e.target.value = ''
    if (!f) return
    try {
      const text = await f.text()
      const parsed = parseImportFile(text, f.name)
      const items = (parsed && parsed.items) ? parsed.items.filter((it) => it.category === 'login') : []
      mwState.csvItems = items
      mwState.csvFileName = f.name
      const out = $('migPasswordsParsed')
      if (out) {
        out.hidden = false
        out.textContent = items.length
          ? getMessage('migPasswordsParsedN', [String(items.length), f.name], `${items.length} password rows read from ${f.name} — they join the preview below. Delete this CSV when the import is done.`)
          : getMessage('migPasswordsParsedNone', [f.name], `No password rows found in ${f.name} — check the export format (a passwords CSV).`)
      }
    } catch (err) {
      const out = $('migPasswordsParsed')
      if (out) {
        out.hidden = false
        out.textContent = '✗ ' + getMessage('migPasswordsParseFail', undefined, 'The CSV could not be read — export it again from the browser\'s password settings.')
      }
    }
  })
  $('migPreviewBtn')?.addEventListener('click', () => mwPreview().catch(() => {}))
  $('migCancelBtn')?.addEventListener('click', () => mwReset())
  $('migConfirmBtn')?.addEventListener('click', () => mwApply().catch(() => {}))
}

function mwRenderPasswordsLink() {
  const btn = $('migPasswordsLinkBtn')
  if (!btn) return
  const { link, note } = passwordsExportLink(mwState.browserId || 'chrome')
  btn.hidden = !link && !note
  btn.title = link || note || ''
}

function mwReset() {
  mwState.plan = null
  mwState.historyEntries = []
  mwState.csvItems = []
  mwState.csvFileName = ''
  $('migPreview').textContent = ''
  $('migPreview').className = 'sync-test-result'
  $('migConfirmRow').classList.add('hidden')
  $('migConfirmRow').hidden = true
  $('migDone').textContent = ''
  $('migDone').className = 'sync-test-result'
  const p = $('migPasswordsParsed')
  if (p) { p.hidden = true; p.textContent = '' }
}

/** The ONE canonical history call (the ic* engine's exact shape) — the
 * wizard adds no second path, it REUSES the R90 law. */
async function mwHistoryItems(days) {
  const range = historyRangeOrDefault(days)
  const endTime = Date.now()
  const startTime = endTime - range * 24 * 60 * 60 * 1000
  const items = await chrome.history.search({ text: '', startTime, endTime, maxResults: HISTORY_LAW.cap + 1 })
  const truncated = Array.isArray(items) && items.length > HISTORY_LAW.cap
  return { entries: historyItemsToEntries(truncated ? [] : items), truncated, range }
}

async function mwPreview() {
  const pv = $('migPreview')
  const btn = $('migPreviewBtn')
  btn.disabled = true
  pv.className = 'sync-test-result'
  pv.textContent = getMessage('migPreviewing', undefined, 'Gathering…')
  try {
    const wantBookmarks = !!$('migWantBookmarks')?.checked
    const wantHistory = !!$('migWantHistory')?.checked
    const items = []            // bookmark + CSV items → the plan (dedupe-aware)
    let historyEntries = []     // history → the ic* engine's proven direct shape
    let bmNote = ''
    let histTruncated = false
    let histRange = HISTORY_LAW.defaultDays
    if (wantBookmarks) {
      if (typeof chrome === 'undefined' || !chrome.bookmarks || !chrome.bookmarks.getTree) {
        bmNote = getMessage('migNoBookmarksApi', undefined, 'The bookmarks API is unavailable in this browser context — bookmarks were skipped.')
      } else {
        const tree = await chrome.bookmarks.getTree()
        const bmItems = flattenBookmarkTree(tree)
        items.push(...bmItems)
        bmNote = getMessage('migBookmarksFound', [String(bmItems.length)], `${bmItems.length} bookmarks read from this browser.`)
      }
    }
    if (wantHistory) {
      const perm = await (async () => { try { return await chrome.permissions.contains({ permissions: ['history'] }) } catch { return false } })()
      if (!perm) {
        // The typed fix (0.13): the Import Center's grant button is the
        // user-gesture affordance — the wizard names it, never a dead end.
        pv.className = 'sync-test-result warn'
        pv.textContent = getMessage('migHistNeedsPerm', undefined, 'History access is off — press "Grant history access" in the Import Center below (one click), then press Preview again. Bookmarks were already gathered.')
        if ($('icHistGrant')) {
          $('icHistGrant').scrollIntoView({ behavior: 'smooth', block: 'center' })
        }
        btn.disabled = false
        return
      }
      const days = Number($('migHistDays')?.value) || HISTORY_LAW.defaultDays
      const hist = await mwHistoryItems(days)
      histTruncated = hist.truncated
      histRange = hist.range
      historyEntries = hist.entries // the EXACT vault entries the R90 engine writes
    }
    // The passwords CSV items join the SAME plan (one import, one confirm).
    items.push(...mwState.csvItems)
    if (!items.length && !historyEntries.length) {
      pv.className = 'sync-test-result warn'
      pv.textContent = getMessage('migNothingFound', undefined, 'Nothing to import was found — tick at least one row above, or drop a passwords CSV.')
      btn.disabled = false
      return
    }
    const all = await bgSend('GET_ALL_ENTRIES')
    const existing = (all && all.ok && Array.isArray(all.entries)) ? all.entries : []
    const plan = items.length ? buildFullPlan(items, existing, {}) : { additions: [], stats: {} }
    mwState.plan = plan
    mwState.historyEntries = historyEntries
    const adds = Array.isArray(plan.additions) ? plan.additions : []
    const counts = adds.length + historyEntries.length
    const summary = items.length ? planSummary(plan.stats) : ''
    pv.className = 'sync-test-result'
    pv.textContent = ''
    const head = document.createElement('div')
    head.textContent = `✓ ${getMessage('migPreviewHead', [String(counts)], `${counts} item(s) will be saved into the encrypted vault`)}${summary ? ` (${summary})` : ''}.`
    pv.appendChild(head)
    const detail = document.createElement('div')
    detail.className = 'card-help'
    const parts = []
    if (bmNote) parts.push(bmNote)
    if (wantHistory) parts.push(getMessage('migHistoryFound', [String(histRange)], `History: the last ${histRange} days (a private record — it does not restore address-bar suggestions elsewhere).`))
    if (mwState.csvItems.length) parts.push(getMessage('migCsvPart', [String(mwState.csvItems.length)], `${mwState.csvItems.length} password rows from the CSV.`))
    detail.textContent = parts.join(' ')
    pv.appendChild(detail)
    if (histTruncated) {
      const t = document.createElement('div')
      t.className = 'card-help'
      t.textContent = getMessage('migHistCap', [String(HISTORY_LAW.cap)], `Over the ${HISTORY_LAW.cap}-page cap — narrow the range and import in parts.`)
      pv.appendChild(t)
    }
    const row = $('migConfirmRow')
    row.classList.remove('hidden')
    row.hidden = false
    const confirmBtn = $('migConfirmBtn')
    confirmBtn.textContent = getMessage('migConfirmN', [String(counts)], `Import ${counts} item(s)`)
  } catch (e) {
    pv.className = 'sync-test-result err'
    pv.textContent = '✗ ' + ((e && e.message) || getMessage('migPreviewFail', undefined, 'The preview failed — check the browser permissions and try again.'))
  } finally {
    btn.disabled = false
  }
}

async function mwApply() {
  const plan = mwState.plan
  const historyEntries = mwState.historyEntries || []
  const planAdds = (plan && Array.isArray(plan.additions)) ? plan.additions : []
  if (!planAdds.length && !historyEntries.length) return
  const btn = $('migConfirmBtn')
  btn.disabled = true
  const done = $('migDone')
  try {
    // The EXISTING engines' write path — one persist, one eligible push:
    // the plan's items ride itemToVaultEntry, history rides its own proven
    // entry shape (the R90 engine's exact output).
    // R175 — THE IMPORT THAT ENDS (R-175.5): the wizard's journey is BOUNDED.
    const planEntries = planAdds.map((a) => itemToVaultEntry(a.item))
    const r = await boundedImport(() => bgSend('IMPORT_ENTRIES', { entries: [...planEntries, ...historyEntries] }), {
      onTick: (secs) => { try { if (btn && !btn.dataset.landed) btn.textContent = `${secs}s…` } catch { /* never throws */ } },
    })
    if (btn) delete btn.dataset.landed
    if (r && r.watchdog) {
      done.className = 'sync-test-result'
      done.textContent = '⏳ ' + watchdogLandingWords(Number(r.timeoutMs) || undefined)
      return
    }
    if (r && r.ok) {
      const pushNote = r.push ? (r.push.ok ? ' · ' + getMessage('icHistPushed', undefined, 'pushed to your cloud transport') : ' · ' + getMessage('icHistPushFailed', undefined, 'cloud push failed — will retry')) : ''
      done.className = 'sync-test-result ok'
      done.textContent = '✓ ' + getMessage('migDoneN', [String(r.added)], `${r.added} item(s) imported into the encrypted vault.${pushNote}`)
      if (mwState.csvItems.length && mwState.csvFileName) {
        done.textContent += ' ' + getMessage('migDeleteCsv', [mwState.csvFileName], `Now delete ${mwState.csvFileName} — passwords CSVs are plaintext on disk until you do.`)
      }
      toast(getMessage('migDoneToast', [String(r.added)], `${r.added} items imported`), 'info')
      mwState.plan = null
      mwState.csvItems = []
      mwState.csvFileName = ''
      const row = $('migConfirmRow')
      row.classList.add('hidden')
      row.hidden = true
      $('migPreview').textContent = ''
      refreshSync()
    } else {
      done.className = 'sync-test-result err'
      done.textContent = '✗ ' + ((r && r.error) || getMessage('migApplyFail', undefined, 'The import failed — nothing was changed; try the preview again.'))
    }
  } catch (e) {
    done.className = 'sync-test-result err'
    done.textContent = '✗ ' + ((e && e.message) || getMessage('migApplyFail', undefined, 'The import failed — nothing was changed; try the preview again.'))
  } finally {
    btn.disabled = false
  }
}

const IC_GROUPS = [
  { id: 'browsers', label: 'Browsers', labelKey: 'icGroupBrowsers' },
  { id: 'managers', label: 'Password managers', labelKey: 'icGroupManagers' },
  { id: 'data', label: 'Other data', labelKey: 'icGroupData' },
]

// v2.18.0 — R27 (i18n wave 1): the category labels resolve through the
// catalogs with the English literal as the hard fallback (the i18n.js
// convention — English is the source of truth, never wiped).
const IC_CATEGORY_LABEL = {
  login: '🔑 Logins', totp: '📱 2FA tokens', note: '📝 Secure notes',
  card: '💳 Cards', address: '🏠 Identities', bookmark: '🔖 Bookmarks',
  history: '🕘 History', form: '📋 Form data',
}
const IC_CATEGORY_KEY = {
  login: 'icCatLogins', totp: 'icCatTotp', note: 'icCatNotes',
  card: 'icCatCards', address: 'icCatAddresses', bookmark: 'icCatBookmarks',
  history: 'icCatHistory', form: 'icCatForms',
}
function icCatLabel(cat) {
  return getMessage(IC_CATEGORY_KEY[cat] || '', undefined, IC_CATEGORY_LABEL[cat] || cat)
}
// Import-source card keys derive from the stable id: chrome → icSrcChrome*
// (label / step1..3 / hint) — the SOURCES literals stay as fallbacks.
const icSrcKey = (id) => `icSrc${id[0].toUpperCase()}${id.slice(1)}`

let icState = {
  sourceId: null,
  items: [],
  plan: null,
  selected: null, // {category: bool}
}

function renderImportSources() {
  const wrap = $('icSources')
  wrap.innerHTML = ''
  for (const group of IC_GROUPS) {
    const sources = SOURCES.filter(s => s.group === group.id)
    if (!sources.length) continue
    const g = document.createElement('div')
    g.className = 'ic-group'
    const gl = document.createElement('div')
    gl.className = 'ic-group-label'
    gl.textContent = getMessage(group.labelKey, undefined, group.label)
    g.appendChild(gl)
    const grid = document.createElement('div')
    grid.className = 'ic-grid'
    for (const s of sources) {
      const b = document.createElement('button')
      b.type = 'button'
      b.className = 'ic-source' + (icState.sourceId === s.id ? ' ic-source-active' : '') + (icRecommendedId === s.id ? ' ic-source-rec' : '')
      b.dataset.sourceId = s.id
      b.setAttribute('role', 'option')
      b.setAttribute('aria-selected', String(icState.sourceId === s.id))
      const recMark = icRecommendedId === s.id ? ' <span class="ic-source-rec-mark" title="Recommended for this browser" aria-label="Recommended for this browser">★</span>' : ''
      b.innerHTML = `<span class="ic-source-icon" aria-hidden="true">${s.icon}</span><span>${escapeHtml(getMessage(`${icSrcKey(s.id)}Label`, undefined, s.label))}${recMark}</span>`
      b.addEventListener('click', () => selectImportSource(s.id))
      grid.appendChild(b)
    }
    g.appendChild(grid)
    wrap.appendChild(g)
  }
}

function selectImportSource(id) {
  icState.sourceId = id
  const src = SOURCES.find(s => s.id === id)
  $('icHowto').classList.remove('hidden')
  $('icHowtoName').textContent = src ? getMessage(`${icSrcKey(id)}Label`, undefined, src.label) : id
  const steps = $('icHowtoSteps')
  steps.innerHTML = ''
  for (const [i, step] of (src ? src.steps : []).entries()) {
    const li = document.createElement('li')
    li.textContent = getMessage(`${icSrcKey(id)}Step${i + 1}`, undefined, step)
    steps.appendChild(li)
  }
  $('icHowtoHint').textContent = src ? getMessage(`${icSrcKey(id)}Hint`, undefined, src.hint) : ''
  renderImportSources()
  $('icDropzone').focus()
}

async function icRunImportText(text, label) {
  return icRunImportBatch([{ text, label }])
}

/** R127 §5.2 (the CEO's S3 — THE MULTI-TYPE PASS): the Import Center's
 *  dropzone accepts SEVERAL export files in one gesture — a bookmarks HTML,
 *  a passwords CSV, and a history export land together, each parsed by its
 *  own dialect (parseImportFile is content-typed, never extension-typed),
 *  ONE merged preview, ONE confirm, ONE IMPORT_ENTRIES (the single
 *  saveEntriesBatch law holds — one persist, one eligible push). A single
 *  file takes the exact historical path (byte-identical behavior). */
async function icRunImportBatch(parts) {
  const list = (Array.isArray(parts) ? parts : []).filter(p => p && typeof p.text === 'string')
  if (list.length <= 1) {
    const p0 = list[0] || { text: '', label: '' }
    return icRunImportTextSingle(p0.text, p0.label)
  }
  const report = $('icReport')
  const preview = $('icPreview')
  const actions = $('icPreviewActions')
  report.classList.add('hidden')
  preview.classList.remove('hidden')
  preview.innerHTML = `<div class="ic-loading">${getMessage('icParsing', undefined, '⏳ Parsing…')}</div>`

  // Vault must be unlocked (the same gate, the same words).
  const state = await bgSend('GET_STATE')
  if (!state || !state.ok || !state.state || !state.state.isUnlocked) {
    preview.classList.add('hidden')
    actions.classList.add('hidden')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icVaultLockedHead', undefined, 'Vault is locked')}</div><div>${getMessage('icVaultLockedBody', undefined, 'Unlock it in the Vault tab (or set up the master passphrase first), then import again.')}</div>`
    return
  }
  await new Promise(r => setTimeout(r, 0)) // let the spinner paint

  // The honest merged-total guard: the per-file caps hold inside each parse;
  // the BATCH total gets its own typed refusal (never a silent truncation).
  const merged = { items: [], warnings: [], droppedRows: [], labels: [], failed: [] }
  for (const part of list) {
    const parsed = parseImportFile(part.text)
    if (!parsed.ok) {
      merged.failed.push({ label: part.label, error: parsed.error })
      continue
    }
    merged.items.push(...parsed.items)
    if (Array.isArray(parsed.warnings)) merged.warnings.push(...parsed.warnings)
    if (Array.isArray(parsed.droppedRows)) merged.droppedRows.push(...parsed.droppedRows)
    merged.labels.push({ label: part.label, dialect: parsed.detected.label, count: parsed.items.length })
  }
  if (!merged.items.length) {
    preview.classList.add('hidden')
    actions.classList.add('hidden')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    const first = merged.failed[0]
    report.innerHTML = `<div class="csv-stats">${getMessage('icCouldNotRead', [first ? first.label : list.length + ' files'], first ? `Could not read ${first.label}` : 'Could not read the files')}</div>` +
      `<div>${first ? escapeHtml(first.error) : ''}</div>` +
      (merged.failed.length > 1 ? `<div>${escapeHtml(getMessage('icMultiFailedMore', [String(merged.failed.length - 1)], `${merged.failed.length - 1} more file(s) also failed — import them one at a time to see each error.`))}</div>` : '')
    return
  }
  if (merged.items.length > LIMITS.MAX_ITEMS) {
    preview.classList.add('hidden')
    actions.classList.add('hidden')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icFileTooLargeHead', undefined, 'File too large')}</div><div>${escapeHtml(getMessage('icMultiTooMany', [String(merged.items.length), String(LIMITS.MAX_ITEMS)], `${merged.items.length} items across the files — together they exceed the ${LIMITS.MAX_ITEMS}-item import cap. Drop fewer files at once and import in batches.`))}</div>`
    return
  }

  const all = await bgSend('GET_ALL_ENTRIES')
  const entries = (all && all.ok && Array.isArray(all.entries)) ? all.entries : []
  const plan = buildFullPlan(merged.items, entries, { droppedRows: merged.droppedRows })
  icState.items = merged.items
  icState.plan = plan
  icState.selected = {}
  for (const [cat, s] of Object.entries(plan.stats.byCategory)) {
    if (s.total > 0) icState.selected[cat] = true
  }
  // The merged detected label names EVERY file's dialect — the multi-type
  // pass's honesty: the user reads exactly what landed, file by file.
  const multiLabel = merged.labels
    .map((l) => `${l.label}: ${l.dialect} (${l.count})`)
    .join(' · ')
  const parsedMerged = {
    items: merged.items,
    warnings: merged.warnings,
    droppedRows: merged.droppedRows,
    detected: { label: getMessage('icMultiTypeLabel', undefined, 'Multi-file import') + ' — ' + multiLabel },
    fileLines: merged.labels,
    failedFiles: merged.failed,
  }
  renderImportPreview(parsedMerged, plan)
}

/** The historical single-file path (byte-identical; the batch delegates here). */
async function icRunImportTextSingle(text, label) {
  const report = $('icReport')
  const preview = $('icPreview')
  const actions = $('icPreviewActions')
  report.classList.add('hidden')
  preview.classList.remove('hidden')
  preview.innerHTML = `<div class="ic-loading">${getMessage('icParsing', undefined, '⏳ Parsing…')}</div>`

  // Vault must be unlocked
  const state = await bgSend('GET_STATE')
  if (!state || !state.ok || !state.state || !state.state.isUnlocked) {
    preview.classList.add('hidden')
    actions.classList.add('hidden')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icVaultLockedHead', undefined, 'Vault is locked')}</div><div>${getMessage('icVaultLockedBody', undefined, 'Unlock it in the Vault tab (or set up the master passphrase first), then import again.')}</div>`
    return
  }

  await new Promise(r => setTimeout(r, 0)) // let the spinner paint
  const parsed = parseImportFile(text)
  if (!parsed.ok) {
    preview.classList.add('hidden')
    actions.classList.add('hidden')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icCouldNotRead', [label], `Could not read ${label}`)}</div><div>${escapeHtml(parsed.error)}</div>`
    return
  }

  const all = await bgSend('GET_ALL_ENTRIES')
  const entries = (all && all.ok && Array.isArray(all.entries)) ? all.entries : []
  // v2.18.0 — R27-F11: rows the parsers could not represent now ride into
  // the plan (plan.skipped, marked dropped:true) and show in the report —
  // nothing a user drops into the Import Center vanishes without a trace.
  const plan = buildFullPlan(parsed.items, entries, { droppedRows: parsed.droppedRows })
  icState.items = parsed.items
  icState.plan = plan
  icState.selected = {}
  for (const [cat, s] of Object.entries(plan.stats.byCategory)) {
    if (s.total > 0) icState.selected[cat] = true
  }
  renderImportPreview(parsed, plan)
}

function renderImportPreview(parsed, plan) {
  const preview = $('icPreview')
  const actions = $('icPreviewActions')
  const report = $('icReport')
  report.classList.add('hidden')
  preview.classList.remove('hidden')
  actions.classList.remove('hidden')

  const cats = Object.entries(plan.stats.byCategory).filter(([, s]) => s.total > 0)
  const chips = cats.map(([cat, s]) => {
    const checked = icState.selected[cat] ? 'checked' : ''
    return `<label class="ic-cat-chip${s.added > 0 ? '' : ' ic-cat-dim'}">` +
      `<input type="checkbox" data-ic-cat="${cat}" ${checked} ${s.added === 0 ? 'disabled' : ''} /> ` +
      `${icCatLabel(cat)} <strong>${s.added}</strong><span class="ic-cat-sub">${s.total}</span></label>`
  }).join('')

  const warnings = (parsed.warnings || []).map(w => `<div class="ic-warn">⚠️ ${escapeHtml(w)}</div>`).join('')

  // R127 §5.2 — the multi-type pass's per-file lines: each file's dialect +
  // count, and any file that failed names itself with its reason (nothing a
  // user drops vanishes without a trace — the R27-F11 law, batch edition).
  const fileLines = Array.isArray(parsed.fileLines) && parsed.fileLines.length
    ? `<div class="ic-cat-table"><div class="ic-cat-title">${getMessage('icMultiFilesHead', undefined, 'Files in this import')}</div>` +
      parsed.fileLines.map((l) => `<div class="ic-multi-file-line">📄 ${escapeHtml(l.label)} — ${escapeHtml(l.dialect)} · ${l.count}</div>`).join('') +
      ((parsed.failedFiles || []).map((f) => `<div class="ic-multi-file-line ic-multi-failed">⚠️ ${escapeHtml(f.label)} — ${escapeHtml(String(f.error || '').slice(0, 120))}</div>`).join('')) +
      `</div>`
    : ''

  // Preview rows (first 6 per selected category)
  const tables = cats.map(([cat]) => {
    const rows = plan.additions.filter(a => a.item.category === cat).slice(0, 6)
    if (!rows.length) return ''
    const items = rows.map(({ item: it }) => {
      const main = it.title || it.username || it.url || it.domain || getMessage('icUntitled', undefined, '(untitled)')
      const sub = it.url || it.domain || it.note?.slice(0, 60) || ''
      const badge = it.totp ? ' <span class="chip chip-accent">2FA</span>' : ''
      const meta = it.category === 'history' && it.meta?.visitCount ? ` · ${getMessage('icVisitsCount', [String(it.meta.visitCount)], `${it.meta.visitCount} visits`)}` : ''
      const folder = it.meta?.folder ? ` · 📁 ${escapeHtml(it.meta.folder)}` : ''
      return `<tr><td class="ic-td-main">${escapeHtml(main)}${badge}</td><td class="ic-td-sub">${escapeHtml(sub)}${meta}${folder}</td></tr>`
    }).join('')
    return `<div class="ic-cat-table"><div class="ic-cat-title">${icCatLabel(cat)}</div>` +
      `<table><tbody>${items}</tbody></table>` +
      (plan.additions.filter(a => a.item.category === cat).length > 6 ? `<div class="ic-more">${getMessage('icMore', undefined, '…and more')}</div>` : '') +
      '</div>'
  }).join('')

  const s = plan.stats
  const footerBits = [
    getMessage('icDupCount', [String(s.duplicates)], `${s.duplicates} duplicate${s.duplicates === 1 ? '' : 's'}`),
    getMessage('icConflictCount', [String(s.conflicts)], `${s.conflicts} conflict${s.conflicts === 1 ? '' : 's'}`),
    getMessage('icInvalidCount', [String(s.invalid)], `${s.invalid} unusable`),
  ].join(' · ')

  preview.innerHTML =
    `<div class="ic-preview-head">${getMessage('icDetectedLine', [escapeHtml(parsed.detected.label), String(s.total)], `Detected: <strong>${escapeHtml(parsed.detected.label)}</strong> · ${s.total} item${s.total === 1 ? '' : 's'} scanned`)}</div>` +
    fileLines +
    warnings +
    `<div class="ic-cats">${chips}</div>` +
    tables +
    `<div class="ic-preview-foot">${getMessage('icPreviewFoot', [footerBits], `${footerBits} — existing entries are never overwritten.`)}</div>` +
    renderImportConflicts(plan)

  preview.querySelectorAll('input[data-ic-cat]').forEach(cb => {
    cb.addEventListener('change', () => {
      icState.selected[cb.dataset.icCat] = cb.checked
      updateImportButtonLabel()
    })
  })
  updateImportButtonLabel()
}

function updateImportButtonLabel() {
  const plan = icState.plan
  if (!plan) return
  const n = plan.additions.filter(a => icState.selected[a.item.category]).length
  $('icImportBtn').textContent = getMessage('icImportCount', [String(n)], `Import ${n} item${n === 1 ? '' : 's'}`)
  $('icImportBtn').disabled = n === 0
}

function renderImportConflicts(plan) {
  const items = [
    ...plan.conflicts.map(c => ({ title: c.title, why: c.detail })),
    ...plan.skipped.map(s2 => ({ title: s2.title, why: s2.reason })),
  ]
  if (!items.length) return ''
  const rows = items.slice(0, 50).map(i =>
    `<div class="csv-conflict-row"><code>${escapeHtml(i.title || '—')}</code><span>${escapeHtml(i.why)}</span></div>`
  ).join('')
  const more = items.length > 50 ? `<div>${getMessage('icMoreCount', [String(items.length - 50)], `…and ${items.length - 50} more`)}</div>` : ''
  return `<div class="csv-conflicts"><div><strong>${getMessage('icReviewHead', [String(items.length)], `Review (${items.length}):`)}</strong></div>${rows}${more}</div>`
}

function icReadFile(file) {
  return icReadFiles([file])
}

/** R127 §5.2 — THE MULTI-TYPE READER: every file ≤20 MB reads in parallel;
 *  the batch (each file's text + name) hands to icRunImportBatch — one
 *  merged preview, one confirm, one saveEntriesBatch. Oversized files name
 *  themselves in the report (nothing vanishes without a trace). */
function icReadFiles(files) {
  const list = (Array.isArray(files) ? files : []).filter(Boolean)
  if (!list.length) return
  const oversized = list.filter((f) => f.size > 20 * 1024 * 1024)
  const ok = list.filter((f) => f.size <= 20 * 1024 * 1024)
  if (oversized.length && !ok.length) {
    const report = $('icReport')
    report.classList.remove('hidden', 'csv-ok', 'csv-warn')
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icFileTooLargeHead', undefined, 'File too large')}</div><div>${getMessage('icFileTooLargeBody', undefined, 'Exports larger than 20 MB are not accepted — split the file and import in batches.')}</div>`
    return
  }
  if (oversized.length) {
    toast(getMessage('icMultiOversizedSkipped', [String(oversized.length)], `${oversized.length} file(s) skipped — exports larger than 20 MB are not accepted.`), 'error')
  }
  if (!ok.length) return
  let pending = ok.length
  const parts = []
  let settled = false
  const proceed = () => {
    if (settled || pending > 0) return
    settled = true
    icRunImportBatch(parts)
  }
  for (const f of ok) {
    const reader = new FileReader()
    reader.onload = (e) => {
      parts.push({ text: String(e.target.result || ''), label: f.name || 'the file' })
      pending--
      proceed()
    }
    reader.onerror = () => {
      pending--
      toast(getMessage('icReadFailedToast', undefined, 'Could not read the file — pick it again or choose a different file.') + ` (${f.name || '?'})`, 'error')
      proceed()
    }
    reader.readAsText(f)
  }
}

async function runImport() {
  const plan = icState.plan
  if (!plan || !plan.additions.length) return
  const btn = $('icImportBtn')
  btn.disabled = true
  btn.textContent = getMessage('icImporting', undefined, 'Importing…')

  const entries = plan.additions
    .filter(a => icState.selected[a.item.category])
    .map(a => a.entry)

  // R175 — THE IMPORT THAT ENDS (R-175.5): the Import Center's journey is
  // BOUNDED — a live progress beat, a typed landing, the controls restored
  // on every exit. "Importing…" is a bounded state, never a residence.
  const r = await boundedImport(() => bgSend('IMPORT_ENTRIES', { entries }), {
    onTick: (secs) => {
      try {
        if (btn && !btn.dataset.landed) btn.textContent = `${getMessage('icImporting', undefined, 'Importing…')} ${secs}s`
      } catch { /* the beat never throws into its caller */ }
    },
  })
  const report = $('icReport')
  report.classList.remove('hidden', 'csv-ok', 'csv-warn', 'csv-err')
  $('icPreview').classList.add('hidden')
  $('icPreviewActions').classList.add('hidden')
  if (btn) delete btn.dataset.landed

  if (r && r.watchdog) {
    report.classList.add('csv-warn')
    report.textContent = watchdogLandingWords(Number(r.timeoutMs) || undefined)
    btn.disabled = false
    btn.textContent = getMessage('icImportCount', ['0'], 'Import 0 items')
    return
  }
  if (!r || !r.ok) {
    report.classList.add('csv-err')
    report.innerHTML = `<div class="csv-stats">${getMessage('icImportFailed', undefined, 'Import failed — check the file format and try again.')}</div><div>${escapeHtml((r && r.error) || getMessage('icUnknownError', undefined, 'unknown error'))}</div>`
    btn.disabled = false
    return
  }

  const byCat = {}
  for (const e of entries) {
    const cat = e.type || 'login'
    byCat[cat] = (byCat[cat] || 0) + 1
  }
  const addedLine = Object.entries(byCat).map(([c, n]) => `${n} ${icCatLabel(c)}`).join(', ')
  const dupCount = Number(r.duplicates) || 0
  const conflictCount = Number(r.conflicts) || 0
  const statBits = []
  if (dupCount) statBits.push(getMessage('icDupSkipped', [String(dupCount)], `${dupCount} duplicate${dupCount === 1 ? '' : 's'} skipped`))
  if (conflictCount) statBits.push(getMessage('icConflictKept', [String(conflictCount)], `${conflictCount} conflict${conflictCount === 1 ? '' : 's'} kept vault copies`))
  const skipLine = (r.skipped || []).length
    ? `<div class="ic-warn">${statBits.join(' · ')}${statBits.length ? ' · ' : ''}${getMessage('icSkippedLine', [String(r.skipped.length), escapeHtml(r.skipped.slice(0, 3).map(s2 => s2.reason).join('; ')) + (r.skipped.length > 3 ? '…' : '')], `${r.skipped.length} skipped: ${escapeHtml(r.skipped.slice(0, 3).map(s2 => s2.reason).join('; '))}${r.skipped.length > 3 ? '…' : ''}`)}</div>`
    : ''

  const transportNames = {
    gdrive: 'Google Drive', dropbox: 'Dropbox', github: 'GitHub Gist',
    webdav: 'WebDAV', custom: 'Custom URL',
  }
  const sync = r.sync || {}
  // v2.8.0 — TRUTHFUL cloud line. The push is awaited by the background, so
  // we KNOW whether the encrypted vault reached the transport. No more
  // claiming "pushed to Google Drive" on a guess.
  // R28-i18n: the transport display name resolves through the twName* keys.
  const push = r.push || null
  const tName = (id) => {
    const key = id || sync.transport
    return transportName(key, transportNames[key]) || key || getMessage('syncYourTransport', undefined, 'your cloud transport')
  }
  let syncLine = ''
  if (!sync.enabled) {
    syncLine = `<div class="ic-warn">${getMessage('icSyncNotConfigured', undefined, '☁️ Cloud Sync is not configured yet — the import is stored encrypted on this device. Set up the <a href="#sync" data-goto="sync">Cloud Sync</a> (24-word sync code + Google Drive / Dropbox / GitHub / WebDAV) to mirror it everywhere.')}</div>`
  } else if (push && push.pushed) {
    syncLine = `<div class="ic-sync-ok" id="icSyncLine">${getMessage('icSyncPushed', [escapeHtml(tName(push.transportId))], `☁️ Encrypted vault pushed to <strong>${escapeHtml(tName(push.transportId))}</strong> — all devices with the same sync code receive the import.`)}</div>` +
      `<div class="btn-row"><button id="icSyncNowBtn" class="btn btn-outline btn-sm" type="button">${getMessage('icSyncAgainBtn', undefined, 'Sync again now')}</button></div><div id="icSyncResult" class="sync-test-result"></div>`
  } else if (push && push.error) {
    syncLine = `<div class="ic-warn">${getMessage('icSyncPushFailed', [escapeHtml(push.error)], `⚠️ Cloud push failed: ${escapeHtml(push.error)} — the import is safe locally and UCrypt retries the push automatically (every 15 min and at the next unlock), or use <a href="#sync" data-goto="sync">Cloud Sync</a> → “Sync now”.`)}</div>`
  } else if (!sync.transport) {
    syncLine = `<div class="ic-warn">${getMessage('icSyncNoTransport', undefined, '☁️ Sync code is set, but no cloud transport is configured — the import lives in this browser\'s encrypted vault and Chrome\'s built-in profile sync only. Add <a href="#sync" data-goto="sync">Google Drive / Dropbox / GitHub / WebDAV</a> to mirror it beyond this browser profile.')}</div>`
  } else {
    syncLine = `<div class="ic-warn">${getMessage('icSyncNothingTodo', undefined, '☁️ The import is saved encrypted; nothing new needed a cloud push (everything was already up to date).')}</div>`
  }

  report.classList.add(plan.conflicts.length || skipLine ? 'csv-warn' : 'csv-ok')
  // v2.18.0 — R27-F11: the Review block (conflicts + skipped rows incl. the
  // newly-reported unrepresentable rows) used to live ONLY in the preview —
  // which is hidden the moment the import completes. The final report now
  // carries it too: nothing the user dropped ever disappears from view.
  report.innerHTML =
    `<div class="csv-stats"><span>${getMessage('icReportAdded', [String(r.added)], `✓ ${r.added} imported`)}</span><span>${addedLine || getMessage('icNothingNew', undefined, 'nothing new')}</span></div>` +
    skipLine + renderImportConflicts(plan) + syncLine

  const syncBtn = $('icSyncNowBtn')
  if (syncBtn) {
    syncBtn.addEventListener('click', async () => {
      syncBtn.disabled = true
      syncBtn.textContent = getMessage('icSyncing', undefined, 'Syncing…')
      const res = await bgSend('SYNC_NOW')
      const out = $('icSyncResult')
      if (out) out.textContent = res && res.ok
        ? getMessage('icSyncOk', [String((res.result && res.result.reason) || res.reason || getMessage('icSyncComplete', undefined, 'Sync complete'))], `✓ ${(res.result && res.result.reason) || res.reason || 'Sync complete'}`)
        : `✗ ${((res && res.error) || getMessage('icSyncFailed', undefined, 'sync failed'))}`
      syncBtn.disabled = false
      syncBtn.textContent = getMessage('icSyncAgainBtn', undefined, 'Sync again now')
    })
  }

  toast(getMessage('icImportDoneToast', [String(r.added)], `Import complete: ${r.added} item${r.added === 1 ? '' : 's'} added ✓`))
  icReset()
  refreshVault()
}

function icReset() {
  icState = { sourceId: icState.sourceId, items: [], plan: null, selected: null }
  $('icPreview').classList.add('hidden')
  $('icPreview').innerHTML = ''
  $('icPreviewActions').classList.add('hidden')
  $('icPasteWrap').classList.add('hidden')
  $('icPaste').value = ''
  // v2.7.0 QA fix — the report STAYS visible after a completed import: it
  // carries the per-category totals and the cloud-sync status. It is only
  // replaced by the next parse or an explicit "Start over".
}

function importOtherDataSection(entries) {
  const card = $('otherDataCard')
  if (!card) return
  const count = entries.length
  $('otherDataCount').textContent = String(count)
  card.classList.toggle('hidden', count === 0)
  const list = $('otherDataList')
  if (card.classList.contains('ic-open') && count) {
    const TYPE_ICON = { note: '📝', card: '💳', address: '🏠', bookmark: '🔖', history: '🕘', form: '📋' }
    list.innerHTML = entries.slice(0, 200).map(e => {
      const url = e.meta?.url || ''
      const when = e.updatedAt || e.createdAt || 0
      // v2.18.0 — R27: EVERY other-data type is editable now (history/form
      // gain title+URL; card/address gain their structured fields).
      const canEdit = true
      return `<div class="vault-entry other-entry">` +
        `<div class="vault-entry-meta">` +
        `<div class="vault-entry-domain">${TYPE_ICON[e.type] || '📦'} ${escapeHtml(e.type || '')}</div>` +
        `<div class="vault-entry-user">${escapeHtml(e.username || getMessage('icUntitled', undefined, '(untitled)'))}${url ? ` — ${escapeHtml(url.slice(0, 80))}` : ''}</div>` +
        `<div class="vault-entry-date">${when ? new Date(when).toLocaleDateString() : ''}</div>` +
        `</div>` +
        `<div class="vault-entry-actions">` +
        // v2.10.0 QA FIX — the key used to ride in ONE attribute joined with
        // NUL separators: the HTML parser replaces NUL with U+FFFD inside
        // attributes, so the split back on '\u0000' never matched and BOTH
        // the Edit button AND the Delete button in this pane silently did
        // nothing for entries with real titles. Three attributes cannot lie.
        (canEdit
          ? `<button class="btn btn-outline btn-sm" data-od-edit="1" data-od-domain="${escapeHtml(e.domain)}" data-od-username="${escapeHtml(e.username || '')}" data-od-type="${escapeHtml(e.type)}" aria-label="${escapeHtml(getMessage('odEditAria', [e.type || '', e.username || ''], `Edit ${e.type} ${e.username || ''}`))}">${getMessage('rowBtnEdit', undefined, 'Edit')}</button> `
          : '') +
        `<button class="btn btn-danger btn-sm" data-od-del="1" data-od-domain="${escapeHtml(e.domain)}" data-od-username="${escapeHtml(e.username || '')}" data-od-type="${escapeHtml(e.type)}">${getMessage('rowBtnDelete', undefined, 'Delete')}</button>` +
        `</div></div>`
    }).join('') + (entries.length > 200 ? `<div class="vault-empty">${getMessage('icMoreCount', [String(entries.length - 200)], `…and ${entries.length - 200} more`)}</div>` : '')
    list.querySelectorAll('button[data-od-del]').forEach(b => {
      b.addEventListener('click', async () => {
        const domain = b.dataset.odDomain, username = b.dataset.odUsername, type = b.dataset.odType
        if (!confirm(getMessage('odDeleteConfirm', [type, username], `Delete this imported ${type} ("${username}")? Cloud sync will remove it everywhere.`))) return
        // v2.8.0 — type-aware delete: never take a same-key login sibling.
        // v2.10.0 — the entry type rides as `entryType`: a payload `type`
        // field would collide with the message type on the wire (see bgSend).
        const r = await bgSend('DELETE_ENTRY', { domain, username, entryType: type })
        if (r && r.ok) {
          toast(getMessage('toastOdDeleted', undefined, 'Deleted ✓'))
          refreshVault()
        } else {
          toast(getMessage('toastDeleteFailed', undefined, 'Delete failed — try again; the entry is still in your vault.'), 'error')
        }
      })
    })
    // v2.10.0 — Edit: an atomic UPDATE_OTHER_ENTRY replaces the old
    // delete-and-reimport workaround for a mistyped title or a moved bookmark.
    list.querySelectorAll('button[data-od-edit]').forEach(b => {
      b.addEventListener('click', () => {
        const domain = b.dataset.odDomain, username = b.dataset.odUsername, type = b.dataset.odType
        const entry = entries.find(e => e.domain === domain && e.username === username && e.type === type)
        if (entry) openOdEditDialog(entry)
      })
    })
  } else if (!count) {
    list.innerHTML = ''
  }
}

// --- v2.10.0 — Other-data edit dialog ---------------------------------------
// v2.18.0 — R27: full structured editing. The R25-recorded coverage hole —
// card number/expiry/CVC, identity fields and custom fields[] were NOT
// editable, and history/form entries had NO edit button at all — is closed:
// every other-data type is now editable with type-aware fields, and the
// save path round-trips through updateOtherEntry's {...prev} patch pattern
// (unpatched fields are preserved byte-faithfully).

let odEditRef = null // { domain, username, type } of the entry being edited

const OD_ADDR_FIELDS = ['email', 'phone', 'org', 'street', 'city', 'state', 'zip', 'country', 'ssn']

function renderOdFieldsEditor(fields) {
  const list = $('odEditFieldsList')
  list.innerHTML = ''
  for (const f of (Array.isArray(fields) ? fields : [])) {
    addOdFieldRow(String(f?.name || ''), String(f?.value ?? ''))
  }
}

function addOdFieldRow(name = '', value = '') {
  const list = $('odEditFieldsList')
  if (list.children.length >= 50) return // matches the vault-side cap
  const row = document.createElement('div')
  row.className = 'od-field-row'
  const nameInput = document.createElement('input')
  nameInput.type = 'text'
  nameInput.placeholder = getMessage('odFieldNamePlaceholder', undefined, 'Name')
  nameInput.maxLength = 100
  nameInput.value = name
  nameInput.setAttribute('aria-label', getMessage('odFieldNameAria', undefined, 'Field name'))
  const valueInput = document.createElement('input')
  valueInput.type = 'text'
  valueInput.placeholder = getMessage('odFieldValuePlaceholder', undefined, 'Value')
  valueInput.maxLength = 1000
  valueInput.value = value
  valueInput.setAttribute('aria-label', getMessage('odFieldValueAria', undefined, 'Field value'))
  const del = document.createElement('button')
  del.type = 'button'
  del.className = 'btn btn-outline btn-sm'
  del.textContent = '×'
  del.setAttribute('aria-label', getMessage('odRemoveFieldAria', undefined, 'Remove field'))
  del.onclick = () => row.remove()
  row.appendChild(nameInput)
  row.appendChild(valueInput)
  row.appendChild(del)
  list.appendChild(row)
}

function collectOdFields() {
  return [...$('odEditFieldsList').children]
    .map(row => ({
      name: row.children[0].value.trim(),
      value: row.children[1].value,
    }))
    .filter(f => f.name)
}

// v2.42.8 — R71-P §5.3: the odEdit dialog doubles as the profile CREATE
// form ("Add identity"). In create mode the save routes through the atomic
// IMPORT_ENTRIES batch (one persist, one eligible sync — the canonical path);
// every typed address key incl. the manual-only ssn stays available here.
let odEditCreating = false

function openOdIdentityCreate() {
  odEditCreating = true
  openOdEditDialog({ domain: '', username: '', type: 'address', address: {}, fields: [] })
  odEditCreating = true // openOdEditDialog resets it — set again
  $('odEditTitle').textContent = getMessage('odAddDialogTitle', undefined, 'New profile (identity)')
  $('odEditUsername').focus()
}

function openOdEditDialog(entry) {
  dialogReturnFocus = document.activeElement
  odEditCreating = false
  odEditRef = { domain: entry.domain, username: entry.username, type: entry.type }
  $('odEditTitle').textContent = getMessage('odEditTitle', [entry.type], `Edit ${entry.type}`)
  $('odEditUsername').value = entry.username || ''
  const isBookmark = entry.type === 'bookmark'
  const hasUrl = ['bookmark', 'history', 'form'].includes(entry.type)
  const hasNote = ['note', 'card', 'address'].includes(entry.type)
  const isCard = entry.type === 'card'
  const isAddress = entry.type === 'address'
  const hasFields = ['note', 'card', 'address', 'form'].includes(entry.type)
  $('odEditUrlGroup').classList.toggle('hidden', !hasUrl)
  $('odEditFolderGroup').classList.toggle('hidden', !isBookmark)
  $('odEditNoteGroup').classList.toggle('hidden', !hasNote)
  $('odEditCardGroup').classList.toggle('hidden', !isCard)
  $('odEditAddressGroup').classList.toggle('hidden', !isAddress)
  $('odEditFieldsGroup').classList.toggle('hidden', !hasFields)
  if (hasUrl) $('odEditUrl').value = entry.meta?.url || ''
  if (isBookmark) $('odEditFolder').value = entry.meta?.folder || ''
  if (hasNote) $('odEditNote').value = entry.note || ''
  if (isCard) {
    $('odEditCardBrand').value = entry.card?.brand || ''
    $('odEditCardNumber').value = entry.card?.number || ''
    $('odEditCardExpM').value = entry.card?.expMonth || ''
    $('odEditCardExpY').value = entry.card?.expYear || ''
    $('odEditCardCode').value = entry.card?.code || ''
  }
  if (isAddress) {
    for (const k of OD_ADDR_FIELDS) {
      const el = $(`odEditAddr${k[0].toUpperCase()}${k.slice(1)}`)
      if (el) el.value = entry.address?.[k] || ''
    }
  }
  if (hasFields) renderOdFieldsEditor(entry.fields || [])
  $('odEditError').classList.add('hidden')
  $('odEditDialog').classList.remove('hidden')
  $('odEditUsername').focus()
}

function closeOdEditDialog() {
  $('odEditDialog').classList.add('hidden')
  if (dialogReturnFocus && document.contains(dialogReturnFocus)) dialogReturnFocus.focus()
  dialogReturnFocus = null
  odEditRef = null
  odEditCreating = false
}

async function saveOdEdit() {
  if (!odEditRef) return
  const t = odEditRef.type
  const patch = { username: $('odEditUsername').value }
  if (t === 'bookmark' || t === 'history' || t === 'form') {
    patch.url = $('odEditUrl').value
  }
  if (t === 'bookmark') {
    patch.folder = $('odEditFolder').value
  }
  if (['note', 'card', 'address'].includes(t)) {
    patch.note = $('odEditNote').value
  }
  // v2.18.0 — R27: structured payloads. The vault layer validates every key
  // and only overwrites what actually changed; the Title field stays the
  // single source of the cardholder/identity name (synced on both layers).
  if (t === 'card') {
    patch.card = {
      brand: $('odEditCardBrand').value,
      number: $('odEditCardNumber').value,
      expMonth: $('odEditCardExpM').value,
      expYear: $('odEditCardExpY').value,
      code: $('odEditCardCode').value,
    }
  }
  if (t === 'address') {
    patch.address = {}
    for (const k of OD_ADDR_FIELDS) {
      const el = $(`odEditAddr${k[0].toUpperCase()}${k.slice(1)}`)
      if (el) patch.address[k] = el.value
    }
  }
  if (['note', 'card', 'address', 'form'].includes(t)) {
    patch.fields = collectOdFields()
  }
  const btn = $('odEditSaveBtn')
  btn.disabled = true
  let r
  if (odEditCreating) {
    // CREATE — one address entry via the atomic batch. The global profile
    // (domain '') is offered by the page picker on every compatible site.
    const entry = { type: 'address', domain: '__profiles__', username: patch.username, address: patch.address || {} }
    if (patch.note) entry.note = patch.note
    if (Array.isArray(patch.fields) && patch.fields.length) entry.fields = patch.fields
    r = await bgSend('IMPORT_ENTRIES', { entries: [entry] })
    if (r && r.ok && !r.added) {
      r = { ok: false, error: (r.skipped && r.skipped[0] && r.skipped[0].reason) || getMessage('odCreateDuplicate', undefined, 'A profile with this title already exists') }
    }
  } else {
    r = await bgSend('UPDATE_OTHER_ENTRY', {
      origDomain: odEditRef.domain,
      origUsername: odEditRef.username,
      entryType: t,
      ...patch,
    })
  }
  btn.disabled = false
  if (r && r.ok) {
    closeOdEditDialog()
    toast(getMessage('toastOdSaved', undefined, 'Saved ✓ — encrypted and pushed like every vault change'))
    refreshVault()
  } else {
    const err = $('odEditError')
    err.textContent = (r && r.error) || getMessage('odSaveFailed', undefined, 'Could not save the change — try again; if it repeats, unlock the vault once and retry.')
    err.classList.remove('hidden')
  }
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]))
}

// ─── v2.40.1 — R53: in-extension owner acceptance route ─────────────────────
// Displays the exact build identity (BUILD.json packed by releases/pack.mjs),
// the #121 cloud-safety outcome, and the last operation ledger. This route is
// deliberately INCAPABLE of approving anything: approved:true lives only in
// releases/acceptance/ACCEPTANCE-2.97.0.json and only the owner sets it. It

// also never fabricates an in-session cloud-safety pass — the static outcome
// line reflects the pinned differential evidence; the in-session state always
// says a controlled fixture is required. The Channel A decision screen is
// owner-only: it stages an UNSIGNED decision record locally and never starts
// any Google Cloud Console / OAuth flow.
const CHANNEL_A_RECORD_KEY = 'ucrypt:channelA:decisionRecord'

// R122 — the ONE BUILD.json read site (the CSP battery's page-tier fetch
// inventory counts self-URL fetch sites; both the acceptance route and the
// walkthrough's build-check step share THIS one).
let _ucryptBuildJson = null
async function readBuildJson() {
  if (_ucryptBuildJson) return _ucryptBuildJson
  try {
    const res = await fetch(chrome.runtime.getURL('BUILD.json'))
    if (res.ok) _ucryptBuildJson = await res.json()
  } catch { /* unpacked copy — the typed null renders */ }
  return _ucryptBuildJson
}

function accRow(label, value, mono = true) {
  return `<dt>${escapeHtml(label)}</dt><dd${mono ? ' class="acc-mono"' : ''}>${escapeHtml(value)}</dd>`
}

async function initAcceptanceRoute() {
  const grid = $('accIdentityGrid')
  const unavailable = $('accIdentityUnavailable')
  if (!grid) return

  // 1. Build identity from BUILD.json (injected by releases/pack.mjs).
  const build = await readBuildJson()

  if (!build || !build.version || !build.payloadSha256) {
    unavailable && unavailable.classList.remove('hidden')
  } else {
    const archiveShaHint = getMessage('accArchiveShaHint', undefined, 'Published in releases/RELEASES.json — verify externally.')
    grid.innerHTML = [
      '<dl style="display:contents">',
      accRow(getMessage('accVersionLabel', undefined, 'Version'), build.version),
      accRow(getMessage('accChannelLabel', undefined, 'Channel'), `${build.channel || 'preview'} / ${build.channelName || 'Channel B'}`, false),
      accRow(getMessage('accPayloadHashLabel', undefined, 'Build payload hash'), build.payloadSha256),
      accRow(getMessage('accRuntimeIdLabel', undefined, 'Runtime extension ID'), (chrome.runtime && chrome.runtime.id) || 'n/a'),
      accRow(getMessage('accArchiveShaLabel', undefined, 'Archive SHA-256'), archiveShaHint, false),
      '</dl>',
    ].join('')
  }

  // 2. Last operation ledger — display the REAL recorded outcomes only.
  const ledger = $('accLedger')
  if (ledger) {
    try {
      const st = await bgSend('SYNC_STATUS')
      const rows = []
      const fmt = (t) => (t ? new Date(t).toLocaleString() : '—')
      const lastPush = st && st.status && st.status.lastPush
      const hop = st && st.status && st.status.syncHop
      if (lastPush) {
        rows.push(`<div class="acc-ledger-row"><span class="${lastPush.ok ? 'acc-ledger-ok' : 'acc-ledger-fail'}">${lastPush.ok ? '✓' : '✗'} cloud push</span><span>${escapeHtml(String(lastPush.transportId || '—'))} · ${escapeHtml(fmt(lastPush.at))}${lastPush.error ? ' · ' + escapeHtml(String(lastPush.error)) : ''}</span></div>`)
      }
      if (hop) {
        rows.push(`<div class="acc-ledger-row"><span class="${hop.ok ? 'acc-ledger-ok' : 'acc-ledger-fail'}">${hop.ok ? '✓' : '⚠'} built-in sync hop</span><span>${hop.chunks != null ? escapeHtml(String(hop.chunks)) + ' chunks · ' : ''}${escapeHtml(fmt(hop.at))}${hop.error ? ' · ' + escapeHtml(String(hop.error)) : ''}</span></div>`)
      }
      ledger.innerHTML = rows.length ? rows.join('') : `<div class="acc-ledger-row"><span>${escapeHtml(getMessage('accLedgerEmpty', undefined, 'No sync operations recorded yet.'))}</span></div>`
    } catch { ledger.innerHTML = '' }
  }

  // 3. Channel A owner decision (owner-only screen; two buttons; no OAuth).
  const authorizeBtn = $('accChannelAAuthorizeBtn')
  const keepBtn = $('accChannelAKeepBtn')
  const status = $('accChannelAStatus')
  if (!authorizeBtn || !keepBtn || !status) return

  const showStatus = (msgKey, fallback, withCopy, record) => {
    status.textContent = getMessage(msgKey, undefined, fallback)
    status.classList.remove('hidden')
    const existing = document.getElementById('accChannelACopyBtn')
    if (existing) existing.remove()
    if (withCopy && record) {
      const copy = document.createElement('button')
      copy.id = 'accChannelACopyBtn'
      copy.type = 'button'
      copy.className = 'btn btn-outline btn-sm'
      copy.style.marginTop = '6px'
      copy.textContent = getMessage('accChannelACopy', undefined, 'Copy decision record')
      copy.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(JSON.stringify(record, null, 2))
          copy.textContent = '✓'
          setTimeout(() => { copy.textContent = getMessage('accChannelACopy', undefined, 'Copy decision record') }, 1500)
        } catch { copy.textContent = '✗' }
      })
      status.after(copy)
    }
  }

  authorizeBtn.addEventListener('click', async () => {
    // Unsigned decision record — staged locally; the owner copies it into
    // releases/acceptance/CHANNEL-A-DECISION.json. NO Google Cloud Console
    // flow, NO OAuth window, NO network call is started here.
    const record = {
      schema: 'ucrypt:channel-a:decision:v1',
      decision: 'authorize-setup',
      signed: false,
      approvedBy: null,
      stagedAt: new Date().toISOString(),
      version: build && build.version ? build.version : 'unknown',
      payloadSha256: build && build.payloadSha256 ? build.payloadSha256 : null,
      commitments: {
        publicClientOnly: true,
        noClientSecret: true,
        driveFileScopeOnly: true,
        dedicatedScratchTestAccount: true,
        stableManifestKeyConfirmed: false,
        runtimeRedirectRegistered: false,
      },
    }
    try { await chrome.storage.local.set({ [CHANNEL_A_RECORD_KEY]: record }) } catch { /* display-only */ }
    showStatus('accChannelAStaged', 'Unsigned decision record created (staged locally).', true, record)
  })

  keepBtn.addEventListener('click', () => {
    showStatus('accChannelAKept', 'Channel B Preview kept — Drive stays disabled; no implied deadline.', false, null)
  })
}

// --- Wire up ---------------------------------------------------------------

/**
 * v2.7.0 — init is idempotent and runs whether the module finished loading
 * before or after DOMContentLoaded (a slow import chain must not leave the
 * page unwired).
 */
async function init() {
  // S8.9 completion (R100): the options page is a beam executor while open.
  registerBeamExecutor('options')
  // R160 ARC A′ — the expiry card's two actions (the dismissal + the
  // reconnect); the card's RENDER rides the status strip's cadence.
  initTestingExpiryCard()
  initVaultConflictResolver()
  // Apply saved theme
  const theme = await loadTheme()
  document.documentElement.setAttribute('data-theme', theme)

  // v2.10.0 — localize the static UI (no-op when chrome.i18n is unavailable;
  // the English HTML content is the source of truth and never wiped).
  applyI18n()

  // R170 — THE SETTLED HOUSE: apply the persisted open/closed state to every
  // disclosure area on the page (the defaults follow R-170.1: one primary
  // expanded per surface; every alternative, advanced, and danger seat
  // collapsed). The user's choice persists per area across sessions.
  try { await SettledHouse.applyAll(document) } catch { /* the defaults still apply */ }

  // R88 (§5, CEO-ordered) — the ONE-TIME identity migration note. Shows until
  // the user explicitly acknowledges it (law 0.8: dismiss-only-by-action —
  // there is no timer, no TTL, no auto-dismiss anywhere on this surface).
  try {
    const MIGRATION_KEY = 'ucrypt:migrationNote2.47.0'
    const { [MIGRATION_KEY]: acked } = await chrome.storage.local.get(MIGRATION_KEY)
    const banner = $('identityMigrationNote')
    if (banner) banner.hidden = !(acked && acked.pending === true)
    $('migrationNoteAck')?.addEventListener('click', async () => {
      await chrome.storage.local.set({ [MIGRATION_KEY]: { ackedAt: Date.now() } })
      if (banner) banner.hidden = true
    })
  } catch { /* storage unavailable — the note stays honest-hidden rather than flapping */ }

  // v2.16.0 — reflect the REAL auto-lock interval (the vault state is the
  // source of truth; 0 = never) and the shared vault sort mode.
  try {
    const st = await bgSend('GET_STATE')
    if (st && st.ok) {
      const mins = Math.round((st.state?.lockTimeoutMs ?? 0) / 60000)
      $('autoLockSelect').value = String(mins)
    }
  } catch { /* select keeps the HTML default */ }
  try {
    vaultSortMode = await getVaultSort()
    $('vaultSortSelect').value = vaultSortMode
  } catch { /* select keeps the HTML default */ }

  // Tab switching
  document.querySelectorAll('.opts-tab').forEach(b => {
    b.addEventListener('click', () => switchTab(b.dataset.tab))
  })
  // R173 §Arc B (B10) — THE MAIN BAR SPEAKS TABLIST (keyboard): arrow keys
  // move + activate (the house pattern from #labTabs), Home/End jump. The
  // state class stays the source of truth; ARIA rides switchTab.
  const tabBar = document.querySelector('.opts-tabs')
  if (tabBar && tabBar.dataset.tablistWired !== '1') {
    tabBar.dataset.tablistWired = '1'
    tabBar.addEventListener('keydown', (e) => {
      const tabs = [...tabBar.querySelectorAll('.opts-tab')]
      const idx = tabs.indexOf(document.activeElement)
      if (idx < 0) return
      let next = null
      if (e.key === 'ArrowRight') next = tabs[(idx + 1) % tabs.length]
      else if (e.key === 'ArrowLeft') next = tabs[(idx - 1 + tabs.length) % tabs.length]
      else if (e.key === 'Home') next = tabs[0]
      else if (e.key === 'End') next = tabs[tabs.length - 1]
      if (!next) return
      e.preventDefault()
      next.focus()
      switchTab(next.dataset.tab)
    })
  }

  // v2.40.1 — R53: the in-extension owner acceptance route (identity + ledger
  // + Channel A decision). Initialized with the rest of the page so the
  // identity grid, ledger rows and decision buttons are wired exactly once.
  initAcceptanceRoute()

  // Theme toggle
  $('themeToggle').addEventListener('click', toggleTheme)

  // R56-POPUP-WINDOW — "Vault window ↗" opens the quick vault in a resizable
  // window layer (truthful fallback toast when windows are unavailable).
  // R95 F-95-02 (CEO finding, heuristic audit H3): the header button is
  // STATE-AWARE — "Open vault window ↗" when no vault window is open,
  // "Close window" when one is (the CEO's R95 screenshot instruction). The
  // Open affordance is preserved (the toggle flips back — anti-trim law);
  // closing a window is not destructive and never confirms, consistent with
  // the popup's own Close-window affordance (R91 label-truth law). The state
  // is re-validated by the worker on every query, so the label is truthful
  // even when the window was closed by its own ✕.
  const vwBtn = $('openVaultWindow')
  const vwLabel = {
    open: () => getMessage('optsVaultWindowLink', undefined, 'Open vault window ↗'),
    openTitle: () => getMessage('optsVaultWindowTitle', undefined, 'Opens the quick vault in a resizable window'),
    close: () => getMessage('optsVaultWindowClose', undefined, 'Close window'),
    closeTitle: () => getMessage('optsVaultWindowCloseTitle', undefined, 'Close the open vault window'),
  }
  const renderVaultWindowState = async () => {
    if (!vwBtn) return
    let open = false
    try {
      const r = await bgSend('VAULT_WINDOW_STATE')
      open = !!(r && r.ok && r.open)
    } catch { open = false }
    vwBtn.dataset.windowOpen = open ? '1' : '0'
    vwBtn.textContent = open ? vwLabel.close() : vwLabel.open()
    vwBtn.title = open ? vwLabel.closeTitle() : vwLabel.openTitle()
    vwBtn.setAttribute('aria-label', vwBtn.title)
  }
  vwBtn?.addEventListener('click', async () => {
    const isOpen = vwBtn.dataset.windowOpen === '1'
    if (isOpen) {
      try { await bgSend('CLOSE_VAULT_WINDOW') } catch { /* the state render below stays truthful */ }
    } else {
      const r = await bgSend('OPEN_VAULT_WINDOW')
      if (r && r.ok && r.fallback) {
        toast(getMessage('toastVaultWindowFallback', undefined, 'Resizable windows are unavailable here — the vault opened in a tab instead'))
      }
    }
    await renderVaultWindowState()
  })
  // Live truth: refresh on load, on focus, and while the page is visible.
  // A status label poll — law 0.8 untouched (nothing interactive ever
  // auto-dismisses; this only keeps a label honest).
  renderVaultWindowState()
  window.addEventListener('focus', renderVaultWindowState)
  document.addEventListener('visibilitychange', () => { if (!document.hidden) renderVaultWindowState() })
  setInterval(() => { if (!document.hidden) renderVaultWindowState() }, 3000)
  // R56-SYNC-DEVICES — card actions (Create delegates to the sync-code
  // surface; R61-A: Join now opens the first-class guided join wizard — the
  // legacy restore panel stays available for power users, nothing trimmed).
  $('sdCreateBtn')?.addEventListener('click', () => {
    // R109 §4.1(a)/§4.2 — "Start a new chain" opens the CREATE layer (the
    // sync code card as a focused dialog) and starts the generate flow.
    openSyncOverlay('createOverlay')
    $('syncCodePanel').classList.add('hidden')
    $('syncRestorePanel').classList.add('hidden')
    $('genSyncCodeBtn')?.click()
  })
  $('sdJoinBtn')?.addEventListener('click', openJoinChain)
  // R77-C — direct-transfer card actions + literal availability status.
  await initDirectTransferCard()
  $('sdChooseCloudBtn')?.addEventListener('click', () => {
    // R109 §4.1(b) — the recovery path's cloud chooser is the same focused
    // layer (one surface, one law).
    openSyncOverlay('cloudOverlay')
  })
  for (const id of ['sdShowWordsBtn', 'sdShowWordsBtn2']) {
    $(id)?.addEventListener('click', addDeviceFlow)
  }
  initPairingTabs()
  initPairingPayload()
  wireJoinChain()
  // R98 — the Sync Beam (S8): the origin's dialog, the joiner's stage and the
  // consolidated device surface. All rails already exist; this wires them.
  wireBeam()
  wireLivingSync()
  $('addDeviceRevealBtn')?.addEventListener('click', addDeviceReveal)
  // R91 §3.5c — after a re-authenticated reveal, the user can confirm the
  // sheet in one click (the second truthful path to "backup verified").
  $('addDeviceConfirmBackupBtn')?.addEventListener('click', confirmBackupSheet)
  // R91 §3.5c — the ONE-CLICK completion path from the "backup not verified"
  // state, plus the verify-box actions.
  $('sdVerifyBackupBtn')?.addEventListener('click', openBackupVerify)
  // R112 §2 — Direct Share (the two transfer cards; R118: their own tab).
  wireDirectShare()
  // R112 §3.1 — the recovery state's fourth cause: the one-click Sync now
  // (connected + verified + never pushed → create the first cloud copy).
  $('sdSyncNowRecoveryBtn')?.addEventListener('click', async () => {
    const line = $('sdNocopyLine')
    try {
      if (line) line.textContent = getMessage('syncNowBusy', undefined, 'Syncing…')
      const r = await bgSend('SYNC_NOW')
      if (r && r.ok) {
        toast(getMessage('cloudBackupSyncOk', undefined, 'Sync finished.'), 'ok')
      } else {
        toast((r && r.error) || getMessage('cloudBackupSyncFail', undefined, 'Sync failed — see the ledger below.'), 'error')
      }
    } catch (e) {
      toast(String(e && e.message || e), 'error')
    }
    refreshSyncDevicesCardFresh().catch(() => {})
  })
  // LAW 0.52 (R133) — the toast's explicit close (the user's own exit; the
  // timer expiry remains for the informational case).
  $('toastClose')?.addEventListener('click', () => {
    const el = $('toast')
    if (el) { clearTimeout(toast._t); el.classList.add('hidden') }
  })
  // LAW 0.48 (R133) — the joiner's typed primary action: Pull now.
  $('sdPullNowBtn')?.addEventListener('click', async () => {
    const line = $('sdLifecycleLine')
    try {
      if (line) line.textContent = getMessage('sdPullBusy', undefined, 'Pulling your chain\u2019s data…')
      const r = await bgSend('SYNC_PULL')
      if (r && r.ok) {
        toast(getMessage('sdPullOk', undefined, 'Pull finished — your chain\u2019s data has landed.'), 'ok')
      } else {
        toast((r && r.error) || getMessage('cloudBackupSyncFail', undefined, 'Sync failed — see the ledger below.'), 'error')
        if (line) line.textContent = getMessage('sdPullRetry', undefined, 'The pull could not complete — it retries automatically at the next sync cycle.')
      }
    } catch (e) {
      toast(String(e && e.message || e), 'error')
    }
    refreshSyncDevicesCardFresh().catch(() => {})
  })
  // LAW 0.49 (R133) — the user-configurable auto-sync cadence (committed on
  // change or Enter; the worker re-derives the interval alarm immediately).
  $('sdAutoSyncMinutes')?.addEventListener('change', async (ev) => {
    const raw = Number(ev.target && ev.target.value)
    if (!Number.isFinite(raw) || raw < 1) return
    try {
      const r = await bgSend('AUTO_SYNC_SET', { minutes: raw })
      if (r && r.ok) toast(getMessage('sdAutoSyncSet', [String(r.minutes)], `Auto-sync runs every ${r.minutes} min now.`), 'ok')
      else toast((r && r.error) || getMessage('sdAutoSyncSetFail', undefined, 'Could not save the auto-sync interval.'), 'error')
    } catch (e) {
      toast(String(e && e.message || e), 'error')
    }
    refreshSyncDevicesCardFresh().catch(() => {})
  })
  // R112 §3.2 — the chips are CTAs (law 0.26).
  wireSyncChipCtas()
  initVaultConflictResolver()
  initAutoSyncRetryControls()
  $('bvCheckBtn')?.addEventListener('click', submitBackupVerify)
  $('bvReshuffleBtn')?.addEventListener('click', () => { pickBvPositions(); renderBvInputs() })
  $('bvShowSheetBtn')?.addEventListener('click', () => addDeviceFlow())
  $('addDeviceClose')?.addEventListener('click', () => {
    scrubSecretExposure('close')
    $('addDeviceBox').classList.add('hidden')
    $('addDeviceBox').hidden = true
  })

  // R56-POPUP-WINDOW — running as the resizable MANAGER WINDOW
  // (options.html?window=1&surface=manager): report geometry so the next open
  // restores it (device-local only).
  try {
    const params = new URLSearchParams(location.search)
    if (params.get('window') === '1') {
      document.documentElement.classList.add('vault-window')
      let boundsTimer = null
      const sendBounds = () => {
        clearTimeout(boundsTimer)
        boundsTimer = setTimeout(() => {
          bgSend('VAULT_WINDOW_BOUNDS', {
            surface: 'manager',
            bounds: {
              width: window.innerWidth,
              height: window.innerHeight,
              left: window.screenX,
              top: window.screenY,
            },
          })
        }, 400)
      }
      window.addEventListener('resize', sendBounds)
      sendBounds()
    }
  } catch { /* not a window surface — nothing to persist */ }

  // Vault
  // v2.21.0 — R30-F3: the search box re-renders from the local cache instead
  // of re-running the full refreshVault() round-trip per keystroke.
  $('vaultSearch').addEventListener('input', () => renderVault(vaultLoginCache))

  // R86 (§6): the local-only vault health panel — one render per vault tab
  // boot; reuses the worker's HEALTH_REPORT (no extra analysis pass here).
  async function renderVaultHealthPanel() {
    const scoreEl = $('vhScore')
    if (!scoreEl) return
    try {
      const res = await bgSend('HEALTH_REPORT')
      if (!res || !res.ok || !res.report) return
      const r = res.report
      // R88 (R88-CEO-LOAD-1): the vh* catalog messages now declare their
      // placeholders, so the values flow as proper chrome.i18n subs. The
      // trailing .replace() lines stay as harmless no-ops that keep the
      // QA-stub/fallback path (interpolateFallback) byte-identical.
      scoreEl.textContent = getMessage('vhScoreLabel', [String(r.score ?? '—')], 'Health: $SCORE$/100').replace('$SCORE$', String(r.score ?? '—'))
      $('vhWeak').textContent = getMessage('vhWeakLabel', [String(r.weak ?? 0)], 'Weak: $N$').replace('$N$', String(r.weak ?? 0))
      $('vhReused').textContent = getMessage('vhReusedLabel', [String(r.reusedEntries ?? 0)], 'Reused: $N$').replace('$N$', String(r.reusedEntries ?? 0))
      $('vhStale').textContent = getMessage('vhStaleLabel', [String(r.stale ?? 0)], 'Stale (>180d): $N$').replace('$N$', String(r.stale ?? 0))
      const marks = $('vhMarks')
      marks.textContent = ''
      const items = []
      for (const g of (r.reuseGroups || []).slice(0, 3)) {
        items.push(getMessage('vhMarkReused', [String(g.count), (g.sites || []).join(', ')], 'Reused on $N$ sites: $SITES$').replace('$N$', String(g.count)).replace('$SITES$', (g.sites || []).join(', ')))
      }
      for (const w of (r.worst || []).slice(0, 3)) {
        const d = w.entry && (w.entry.domain || w.entry.name) || '(entry)'
        items.push(getMessage('vhMarkWeak', [String(d), String(w.bits ?? '?')], 'Weak — $D$ ($B$ bits)').replace('$D$', String(d)).replace('$B$', String(w.bits ?? '?')))
      }
      if ((r.stale ?? 0) > 0) items.push(getMessage('vhMarkStale', [String(r.stale)], '$N$ entrie(s) not updated in over 180 days — rotate them when you next sign in.').replace('$N$', String(r.stale)))
      for (const text of items) {
        const li = document.createElement('li')
        li.textContent = text
        marks.appendChild(li)
      }
    } catch { /* the panel stays honest-blank when the worker is unavailable */ }
  }
  renderVaultHealthPanel().catch(() => {})

  // R134 §6 — PASSWORD HEALTH (the dashboard renderer, LOCAL-ONLY): the
  // three heuristics render as counts + drill-in lists; every row's Edit
  // button is the ONE-TAP REMEDIATION (opens the item editor). Scrollable
  // lists (max-h + overflow) per the long-list law.
  // R173 §Arc B (B2/B3) — the health dashboard's failure is TYPED: the card
  // names the truth (the vault data is safe) and offers the retry — never a
  // silent swallow (the R-172.5 referenced-affordance law; the Success-Voice).
function renderPhHealthError() {
  const line = $('phErrorLine')
  if (!line) return
  line.hidden = false
  line.textContent = getMessage('phHealthError', undefined, 'The health dashboard could not refresh just now — your vault data is safe. Press Refresh to try again.')
}

async function renderPasswordHealthDashboard() {
    const weakList = $('phWeakList')
    if (!weakList) return
    try {
      const res = await bgSend('HEALTH_DASHBOARD')
      if (!res || !res.ok) return
      const dash = res.dashboard
      const locked = !!res.locked || !dash
      $('phWeakCount').textContent = getMessage('phWeakCountLabel', [String(dash ? dash.counts.weak : '—')], 'Weak: $N$')
      $('phReusedCount').textContent = getMessage('phReusedCountLabel', [String(dash ? dash.counts.reused : '—')], 'Reused: $N$')
      $('phStaleCount').textContent = getMessage('phStaleCountLabel', [String(dash ? dash.counts.stale : '—')], 'Stale: $N$')
      $('phTotalCount').textContent = getMessage('phTotalCountLabel', [String(dash ? dash.counts.total : '—')], 'Entries: $N$')
      if (locked) {
        $('phLists').classList.add('hidden')
        $('phEmptyNote').hidden = true
        return
      }
      const editLabel = getMessage('phEditBtn', undefined, 'Edit')
      const rowFor = (item) => {
        const li = document.createElement('li')
        const span = document.createElement('span')
        span.className = 'ph-row-label'
        span.textContent = `${item.domain} — ${item.username}`
        const btn = document.createElement('button')
        btn.className = 'btn btn-outline btn-sm ph-edit-btn'
        btn.type = 'button'
        btn.textContent = editLabel
        btn.setAttribute('aria-label', getMessage('phEditAria', [item.domain], 'Edit entry for $D$'))
        btn.addEventListener('click', () => {
          // ONE-TAP REMEDIATION: resolve the full entry from the page's own
          // vault cache (no second round-trip, no passwords on the wire) and
          // open the SAME item editor the vault manager uses.
          const entry = (typeof vaultLoginCache !== 'undefined' ? vaultLoginCache : []).find((e) => e && e.id === item.id)
          if (entry) openEntryDialog(entry)
        })
        li.appendChild(span)
        li.appendChild(btn)
        return li
      }
      weakList.textContent = ''
      for (const item of (dash.weakList || []).slice(0, 20)) weakList.appendChild(rowFor(item))
      const reusedList = $('phReusedList')
      reusedList.textContent = ''
      for (const g of (dash.reuseGroups || []).slice(0, 10)) {
        for (const item of g.entries.slice(0, 5)) reusedList.appendChild(rowFor(item))
      }
      const staleList = $('phStaleList')
      staleList.textContent = ''
      for (const item of (dash.staleList || []).slice(0, 20)) staleList.appendChild(rowFor(item))
      const empty = !(dash.counts.weak || dash.counts.reused || dash.counts.stale)
      $('phEmptyNote').hidden = !empty
      $('phLists').classList.toggle('hidden', empty)
    } catch { /* the card stays honest-blank when the worker is unavailable */ }
  }
  renderPasswordHealthDashboard().catch(() => renderPhHealthError())
  $('phRefreshBtn')?.addEventListener('click', () => { renderPasswordHealthDashboard().catch(() => renderPhHealthError()) })

  // v2.42.8 — R71-P §5.3: "Add identity" — full-manager profile CREATE.
  $('odAddIdentityBtn')?.addEventListener('click', () => {
    openOdIdentityCreate()
  })
  $('otherDataToggle').addEventListener('click', () => {
    const card = $('otherDataCard')
    const list = $('otherDataList')
    const open = !card.classList.contains('ic-open')
    card.classList.toggle('ic-open', open)
    list.classList.toggle('hidden', !open)
    // v2.18.0 — R27-i18n: localized other-data toggle
    $('otherDataToggle').textContent = open ? getMessage('odToggleHide', undefined, 'Hide') : getMessage('odToggleShow', undefined, 'Show')
    $('otherDataToggle').setAttribute('aria-expanded', String(open))
    refreshVault()
  })
  $('newEntryBtn').addEventListener('click', () => openEntryDialog(null))
  $('entryCancelBtn').addEventListener('click', closeEntryDialog)
  $('entrySaveBtn').addEventListener('click', saveEntryFromDialog)
  $('entryGenBtn').addEventListener('click', generateForEntry)
  $('entryRevealBtn').addEventListener('click', toggleEntryReveal)
  // v2.17.0 — R26-B4: live strength meter + Enter-to-save + focus trap.
  $('entryPassword').addEventListener('input', updateEntryStrength)
  $('entryDialog').addEventListener('keydown', (e) => {
    // v2.19.0 — R28-F8 (audit): Enter on a focused <summary> used to SAVE the
    // dialog instead of toggling the disclosure (history/form URL groups).
    if (e.key === 'Enter' && e.target && e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON' && e.target.tagName !== 'SUMMARY') {
      // Enter saves (the note textarea keeps its newline).
      e.preventDefault()
      saveEntryFromDialog()
      return
    }
    if (e.key === 'Tab') {
      // Focus trap: Tab/Shift+Tab cycle inside the dialog.
      const focusables = Array.from(
        $('entryDialog').querySelectorAll('input, textarea, button, select, summary, [tabindex]:not([tabindex="-1"])')
      ).filter(el => !el.disabled && el.offsetParent !== null)
      if (!focusables.length) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
  })
  // v2.10.0 — other-data edit dialog
  $('odEditCancelBtn').addEventListener('click', closeOdEditDialog)
  $('odEditSaveBtn').addEventListener('click', saveOdEdit)
  // v2.18.0 — R27: custom-fields row editor (card/identity/note/form dialogs)
  $('odEditFieldAddBtn').addEventListener('click', () => addOdFieldRow())
  $('odEditDialog').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') return closeOdEditDialog()
    // v2.19.0 — R28-F8 (audit 28a-8): the other-data editor had NEITHER the
    // Enter-to-save NOR the Tab focus trap its sibling entryDialog has had
    // since R26-B4 — Tab escaped into the page behind the modal.
    if (e.key === 'Enter' && e.target && e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON' && e.target.tagName !== 'SUMMARY') {
      e.preventDefault()
      saveOdEdit()
      return
    }
    if (e.key === 'Tab') {
      const focusables = Array.from(
        $('odEditDialog').querySelectorAll('input, textarea, button, select, summary, [tabindex]:not([tabindex="-1"])')
      ).filter(el => !el.disabled && el.offsetParent !== null)
      if (!focusables.length) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
  })
  $('optsUnlockBtn').addEventListener('click', optsUnlock)
  $('optsUnlockPass').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') optsUnlock()
  })

  // Security
  $('saveMasterBtn').addEventListener('click', saveMaster)
  $('removeMasterBtn').addEventListener('click', removeMaster)
  $('runBreachBtn').addEventListener('click', runBreachCheck)
  $('wipeBtn').addEventListener('click', wipeAll)
  // v2.16.0 — user-configurable auto-lock (applies immediately in the worker)
  $('autoLockSelect').addEventListener('change', async (e) => {
    const r = await bgSend('SET_AUTOLOCK', { minutes: Number(e.target.value) })
    if (r && r.ok) {
      toast(r.minutes === 0
        ? getMessage('toastAutoLockOff', undefined, 'Auto-lock disabled')
        : getMessage('toastAutoLockSet', [String(r.minutes)], `Vault auto-locks after ${r.minutes} min of inactivity`))
    } else {
      toast((r && r.error) || getMessage('toastAutoLockFailed', undefined, 'Could not change auto-lock — pick the value again.'), 'error')
    }
  })

  // v2.17.0 — R26-B2: global behavior toggles (Brave parity). Defaults ON —
  // the historical behavior — so the HTML renders the same state the worker
  // assumes before any read resolves.
  getBehaviorPrefs().then((b) => {
    $('offerSaveToggle').checked = b.offerSave
    $('autoFillToggle').checked = b.autoFill
    $('pickerIdToggle').checked = b.showIdentifiers !== false
    if ($('profileFillToggle')) $('profileFillToggle').checked = b.profileFill !== false
    if ($('profileCaptureToggle')) $('profileCaptureToggle').checked = b.profileCapture !== false
  }).catch(() => { /* checkboxes keep the HTML default (checked) */ })
  $('offerSaveToggle').addEventListener('change', async (e) => {
    const next = await saveBehaviorPrefs({ offerSave: e.target.checked })
    toast(next.offerSave
      ? getMessage('toastOfferSaveOn', undefined, 'UCrypt will offer to save passwords again')
      : getMessage('toastOfferSaveOff', undefined, 'Save prompts are off — use the right-click menu to save manually'))
  })
  $('autoFillToggle').addEventListener('change', async (e) => {
    const next = await saveBehaviorPrefs({ autoFill: e.target.checked })
    toast(next.autoFill
      ? getMessage('toastAutoFillOn', undefined, 'UCrypt will offer to fill saved logins on pages')
      : getMessage('toastAutoFillOff', undefined, 'Auto sign-in is off — fill from the popup instead'))
  })
  // R59-F1 — device-local picker identifier disclosure (default ON).
  $('pickerIdToggle').addEventListener('change', async (e) => {
    const next = await saveBehaviorPrefs({ showIdentifiers: e.target.checked })
    toast(next.showIdentifiers
      ? getMessage('toastPickerIdOn', undefined, 'The website picker shows account usernames')
      : getMessage('toastPickerIdOff', undefined, 'The website picker masks account identifiers'))
  })

  // v2.42.8 — R71-P: profile fill/capture toggles (same device-local key).
  const profileFillToggle = $('profileFillToggle')
  const profileCaptureToggle = $('profileCaptureToggle')
  if (profileFillToggle) profileFillToggle.addEventListener('change', async (e) => {
    const next = await saveBehaviorPrefs({ profileFill: e.target.checked })
    toast(next.profileFill
      ? getMessage('toastProfileFillOn', undefined, 'UCrypt will offer your saved profiles on compatible forms')
      : getMessage('toastProfileFillOff', undefined, 'Profile offers are off — the right-click menu still fills profiles'))
  })
  if (profileCaptureToggle) profileCaptureToggle.addEventListener('change', async (e) => {
    const next = await saveBehaviorPrefs({ profileCapture: e.target.checked })
    toast(next.profileCapture
      ? getMessage('toastProfileCaptureOn', undefined, 'UCrypt will ask before saving profile details — never automatically')
      : getMessage('toastProfileCaptureOff', undefined, 'Profile capture offers are off — the right-click menu still saves profiles'))
  })

  // R45-C — native-manager card (Security tab): literal browser status.
  const nmToggle = $('nmOptionsToggle')
  const nmState = $('nmOptionsState')
  async function refreshNmOptionsCard() {
    if (!nmToggle || !nmState) return
    const r = await bgSend('NATIVE_MANAGER_GET')
    const st = (r && r.ok && r.status) || null
    // R133 §6 — the suppression card renders from the SAME status via the
    // pure governor (the honest duty matrix — never a silent claim).
    renderAutofillSuppressionCard(st).catch(() => {})
    if (!st) {
      nmToggle.disabled = true
      nmState.textContent = getMessage('nmUnavailable', undefined, 'Native-manager control is not available here.')
      return
    }
    nmToggle.disabled = false
    if (!st.permission) {
      nmState.textContent = getMessage('nmStateOffPermission', undefined, 'Off — turning on asks for the optional privacy permission and switches the browser save prompt to UCrypt.')
    } else if (!st.supported) {
      nmToggle.disabled = true
      nmState.textContent = getMessage('nmStateNoApi', undefined, 'This browser does not expose the password-saving setting to extensions.')
    } else if (st.levelOfControl === 'not_controllable') {
      nmToggle.disabled = true
      nmState.textContent = getMessage('nmStateNotControllable', undefined, 'Your organization or browser policy manages this setting — UCrypt cannot change it.')
    } else if (st.levelOfControl === 'controlled_by_other_extensions') {
      nmToggle.disabled = true
      nmState.textContent = getMessage('nmStateOtherExt', undefined, 'Another extension controls this setting. Disable it there first if you want UCrypt to take over.')
    } else if (st.controlling) {
      nmState.textContent = getMessage('nmStateOnLong', undefined, 'ON — the browser save-password prompt is off; UCrypt offers its own Save/Update prompt. UCrypt cannot read or delete passwords the browser already saved.')
    } else {
      nmState.textContent = getMessage('nmStateOff', undefined, 'Off — the browser keeps its own save-password prompt.')
    }
    nmToggle.checked = !!st.controlling
  }
  if (nmToggle) {
    nmToggle.addEventListener('change', async (e) => {
      const wantOn = e.target.checked
      nmToggle.disabled = true
      try {
        if (!wantOn) {
          const r = await bgSend('NATIVE_MANAGER_DISABLE')
          if (!r?.ok) toast(r?.error || getMessage('nmFailed', undefined, 'Could not change the setting — reload the page and try again.'), 'error')
          else toast(getMessage('nmDisabledToast', undefined, 'Browser save prompt restored'))
        } else {
          let granted = false
          try {
            granted = await chrome.permissions.request({ permissions: ['privacy'] })
          } catch { granted = false }
          if (!granted) {
            toast(getMessage('nmPermissionDenied', undefined, 'Without the privacy permission UCrypt cannot manage the browser save prompt — enable it in your browser settings.'), 'error')
          } else {
            const r = await bgSend('NATIVE_MANAGER_ENABLE')
            if (!r?.ok) toast(r?.error || getMessage('nmFailed', undefined, 'Could not change the setting — reload the page and try again.'), 'error')
            else toast(getMessage('nmEnabledToast', undefined, 'UCrypt now handles new password saves'))
          }
        }
      } finally {
        nmToggle.disabled = false
        await refreshNmOptionsCard()
      }
    })
    await refreshNmOptionsCard()
    try {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg && msg.type === 'NATIVE_MANAGER_CHANGED' && msg.status) refreshNmOptionsCard()
      })
    } catch { /* poll-based refresh only */ }
  }

  // v2.16.0 — vault sort selector (shared with the popup)
  // v2.21.0 — R30-F3: re-renders from the local cache (no round-trip — the
  // data did not change, only the order).
  $('vaultSortSelect').addEventListener('change', async (e) => {
    vaultSortMode = e.target.value
    await setVaultSort(vaultSortMode)
    renderVault(vaultLoginCache)
  })
  // v2.9.0 — per-site save exceptions (Security tab)
  $('neverSaveAddBtn').addEventListener('click', addNeverSaveFromInput)
  // ── R133 §6 — the autofill & sign-in section (law 0.52's consent model) ──

  async function renderAutofillSuppressionCard(st) {
    const card = $('afSuppressionCard')
    if (!card) return
    const { suppressionPlan } = await import('./lib/autofill-governor.js')
    // the detected browser family names the deep link (the guided card's
    // Step 1 is THE USER'S browser's own settings page).
    const ua = String(navigator.userAgent || '')
    const fam = /Edg\//.test(ua) ? 'edge' : /OPR\//.test(ua) ? 'opera' : /Vivaldi/.test(ua) ? 'vivaldi' : /Brave/.test(ua) ? 'brave' : 'chrome'
    const plan = suppressionPlan({
      apiAvailable: !!(st && st.supported),
      levelOfControl: (st && st.levelOfControl) || null,
      controlling: !!(st && st.controlling),
      browserFamily: fam,
    })
    const rows = $('afSuppressionRows')
    const stateEl = $('afSuppressionState')
    const link = $('afSuppressionLink')
    if (plan.kind === 'controlled') {
      card.classList.add('hidden')
      card.hidden = true
      return
    }
    card.classList.remove('hidden')
    card.hidden = false
    if (rows) {
      rows.textContent = ''
      for (const r of plan.rows) {
        const li = document.createElement('li')
        li.className = 'card-help'
        li.style.margin = '0 0 4px'
        li.textContent = r
        rows.appendChild(li)
      }
    }
    if (link && plan.deepLink) {
      link.href = plan.deepLink
      link.addEventListener('click', (ev) => {
        // the browser blocks the top-level navigation from an extension page;
        // the typed note explains the honest path (copy the link).
        ev.preventDefault()
        try {
          navigator.clipboard.writeText(plan.deepLink).then(() => {
            if (stateEl) stateEl.textContent = getMessage('afLinkCopied', [plan.deepLink], `Copied: ${plan.deepLink} — paste it into the address bar.`)
          }).catch(() => {
            if (stateEl) stateEl.textContent = plan.deepLink
          })
        } catch { if (stateEl) stateEl.textContent = plan.deepLink }
      })
    }
    if (stateEl && plan.kind !== 'guided') {
      stateEl.textContent = plan.rows[0] || ''
    }
  }

  // ── R85 (§6): autofill MODE (auto | prompt) — exact CEO strings ----------

  async function refreshAutofillMode() {
    const b = await getBehaviorPrefs()
    const auto = $('autofillModeAuto')
    const prompt = $('autofillModePrompt')
    if (auto) auto.checked = b.autofillMode !== 'prompt'
    if (prompt) prompt.checked = b.autofillMode === 'prompt'
  }

  async function setAutofillMode(mode) {
    const next = await saveBehaviorPrefs({ autofillMode: mode })
    toast(mode === 'prompt'
      ? getMessage('toastAutofillModePrompt', undefined, 'Prompt mode: UCrypt waits for your explicit selection before filling.')
      : getMessage('toastAutofillModeAuto', undefined, 'Auto mode: saved passwords fill automatically when exactly one account matches.'))
    return next
  }

  // --- R85 (§6): never-fill list (mirror of the never-save UI) --------------

  async function refreshNeverFill() {
    const box = $('neverFillList')
    if (!box) return
    const r = await bgSend('NEVER_FILL_LIST')
    const sites = (r && r.ok && Array.isArray(r.sites)) ? r.sites : []
    box.textContent = ''
    if (sites.length === 0) {
      const empty = document.createElement('div')
      empty.className = 'never-save-empty'
      empty.textContent = getMessage('nfEmpty', undefined, 'No exceptions — UCrypt fills on every site per the mode above.')
      box.appendChild(empty)
      return
    }
    for (const site of sites) {
      const row = document.createElement('div')
      row.className = 'never-save-row'
      const name = document.createElement('span')
      name.className = 'never-save-site'
      name.textContent = site
      const rm = document.createElement('button')
      rm.className = 'btn btn-outline btn-sm'
      rm.textContent = getMessage('nsRemoveBtn', undefined, 'Remove')
      rm.setAttribute('aria-label', getMessage('nfRemoveAria', [site], `Remove ${site} from the never-fill list`))
      rm.onclick = async () => {
        const res = await bgSend('NEVER_FILL_REMOVE', { domain: site })
        if (res && res.ok) {
          toast(getMessage('toastNfRemoved', [site], `Removed ${site} — UCrypt will fill there again`))
          refreshNeverFill()
        } else {
          toast((res && res.error) || getMessage('toastRemoveFailed', undefined, 'Remove failed — try again; the token is still in your vault.'), 'error')
        }
      }
      row.appendChild(name)
      row.appendChild(rm)
      box.appendChild(row)
    }
  }

  async function addNeverFillFromInput() {
    const input = $('neverFillInput')
    const domain = (input.value || '').trim()
    if (!domain) { toast(getMessage('toastNfEnterSite', undefined, 'Enter a website address'), 'error'); return }
    const r = await bgSend('NEVER_FILL_ADD', { domain })
    if (r && r.ok) {
      toast(r.already
        ? getMessage('toastNfAlready', [r.added || domain], `${r.added || domain} is already on the list`)
        : getMessage('toastNfAdded', [r.added], `Added ${r.added} — UCrypt will never fill there`))
      input.value = ''
      refreshNeverFill()
    } else {
      toast((r && r.error) || getMessage('toastAddFailed', undefined, 'Add failed'), 'error')
    }
  }

  // --- R85 (§6): "Make UCrypt your password manager" adoption card ----------

  async function refreshAdoptionCard() {
    const box = $('adoptionRows')
    if (!box) return
    box.textContent = ''
    // Privacy API observation (Chromium): the stock save/auto sign-in switches
    // CAN be read and set where the browser exposes chrome.privacy. Where the
    // API is absent (de-Googled builds), the row says so and offers the deep
    // link instead — never a fake "done" state.
    const privacy = (globalThis.chrome && chrome.privacy && chrome.privacy.services) || null
    const deepLinks = {
      passwords: 'chrome://settings/passwords',
      autofill: 'chrome://settings/passwords',
    }
    async function privacyState(api) {
      if (!api || typeof api.get !== 'function') return 'unavailable'
      try {
        const d = await api.get({})
        if (d && d.value === true) return 'on'
        if (d && d.value === false) return 'off'
        if (d && d.levelOfControl && String(d.levelOfControl).includes('not_controllable')) return 'not-controllable'
        return 'unavailable'
      } catch { return 'unavailable' }
    }
    async function makeRow(titleKey, titleFallback, helpKey, helpFallback, observe, act) {
      const row = document.createElement('div')
      row.className = 'form-group'
      const title = document.createElement('p')
      title.style.fontWeight = '600'
      title.textContent = getMessage(titleKey, undefined, titleFallback)
      const help = document.createElement('p')
      help.className = 'card-help'
      help.textContent = getMessage(helpKey, undefined, helpFallback)
      const stateLine = document.createElement('p')
      stateLine.className = 'card-help'
      const state = await observe()
      stateLine.textContent = getMessage(
        state === 'off' ? 'adoptionStateOff' : state === 'on' ? 'adoptionStateOn' : 'adoptionStateUnavailable',
        undefined,
        state === 'off' ? 'Observed: OFF — confirmed.' : state === 'on' ? 'Observed: still ON.' : 'Not observable on this browser — use the link and confirm by hand.',
      )
      stateLine.style.fontWeight = state === 'off' ? '600' : 'normal'
      row.appendChild(title); row.appendChild(help); row.appendChild(stateLine)
      const actions = document.createElement('div')
      actions.className = 'btn-row'
      if (act && state === 'on') {
        const b = document.createElement('button')
        b.className = 'btn btn-outline btn-sm'
        b.type = 'button'
        b.textContent = getMessage('adoptionTurnOff', undefined, 'Turn off')
        b.onclick = async () => {
          const res = await act()
          if (res) { toast(getMessage('toastAdoptionOff', undefined, 'Done — the browser switch is off.')); refreshAdoptionCard() }
          else toast(getMessage('toastAdoptionDenied', undefined, 'This browser would not let UCrypt change that switch — use the deep link.'), 'error')
        }
        actions.appendChild(b)
      }
      const link = document.createElement('a')
      link.href = deepLinks.passwords
      link.textContent = getMessage('adoptionDeepLink', undefined, 'Open browser settings')
      link.style.alignSelf = 'center'
      link.addEventListener('click', (e) => {
        // Deep links cannot be opened as normal pages — attempt, then be
        // honest that the user must paste the address if it is blocked.
        e.preventDefault()
        try { chrome.tabs.create({ url: deepLinks.passwords }) } catch { /* the copy below is the fallback */ }
        toast(getMessage('toastAdoptionLink', [deepLinks.passwords], `If nothing opened, paste: $URL$`))
      })
      actions.appendChild(link)
      row.appendChild(actions)
      box.appendChild(row)
    }
    await makeRow(
      'adoptionSaveTitle', 'Stock "offer to save passwords" — off',
      'adoptionSaveHelp', 'The browser\u2019s own save bubble duplicates UCrypt\u2019s prompt. Where Chromium exposes the privacy switch, UCrypt can turn it off; otherwise use the link.',
      () => privacyState(privacy && privacy.passwordSavingEnabled),
      privacy && privacy.passwordSavingEnabled
        ? async () => { try { await privacy.passwordSavingEnabled.set({ value: false }); return true } catch { return false } }
        : null,
    )
    await makeRow(
      'adoptionAutofillTitle', 'Stock autofill of passwords — off',
      'adoptionAutofillHelp', 'The browser has no API for third parties to switch its autofill off — this is a per-browser setting. Use the link and disable "Offer to save passwords" / "Auto sign-in" there.',
      async () => 'unavailable',
      null,
    )
    await makeRow(
      'adoptionAutologinTitle', 'Stock automatic sign-in — off',
      'adoptionAutologinHelp', 'Chromium\u2019s "auto sign-in" switch lets sites sign you in without a click. Where the privacy API exposes it, UCrypt can turn it off; otherwise use the link.',
      () => privacyState(privacy && privacy.autologinEnabled),
      privacy && privacy.autologinEnabled
        ? async () => { try { await privacy.autologinEnabled.set({ value: false }); return true } catch { return false } }
        : null,
    )
  }

  // R85 (§6) wiring
  $('autofillModeAuto')?.addEventListener('change', (e) => { if (e.target.checked) setAutofillMode('auto') })
  $('autofillModePrompt')?.addEventListener('change', (e) => { if (e.target.checked) setAutofillMode('prompt') })
  $('neverFillAddBtn')?.addEventListener('click', addNeverFillFromInput)
  $('neverFillInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') addNeverFillFromInput() })
  refreshAutofillMode()
  refreshNeverFill()
  refreshAdoptionCard()

  // --- R85 (§5): front-door wiring + roster + leave/delete ------------------
  // R129 GRAND AUDIT: sdAddDevicePrimary and popupAddDeviceRoute bound to ids
  // that exist in NO HTML (dead bindings — the add-device flow's live doors
  // are dmAddDeviceBtn + the sdShowWords pair + the popup's own doors) —
  // removed; the flow untouched.
  $('sdJoinAlways')?.addEventListener('click', () => openJoinChain())

  async function refreshDeviceRoster() {
    const box = $('deviceRosterList')
    if (!box) return
    box.textContent = ''
    const st = await bgSend('TRANSFER_STATUS')
    const peers = (st && st.ok && Array.isArray(st.peers)) ? st.peers : []
    if (!peers.length) {
      const empty = document.createElement('div')
      empty.className = 'never-save-empty'
      empty.textContent = getMessage('rosterEmpty', undefined, 'No devices have connected through direct transfer yet.')
      box.appendChild(empty)
      return
    }
    for (const p of peers) {
      const row = document.createElement('div')
      row.className = 'never-save-row'
      const name = document.createElement('span')
      name.className = 'never-save-site'
      const seen = p.lastSeen ? new Date(p.lastSeen).toLocaleString() : getMessage('rosterNeverSeen', undefined, 'not seen yet')
      name.textContent = `${p.label || getMessage('transferDeviceUnknown', undefined, 'Device')} · ${seen}`
      const rm = document.createElement('button')
      rm.className = 'btn btn-outline btn-sm'
      rm.textContent = getMessage('rosterRemoveBtn', undefined, 'Remove')
      rm.setAttribute('aria-label', getMessage('rosterRemoveAria', [p.label || p.deviceId], `Forget ${p.label || p.deviceId} on this device`))
      rm.onclick = async () => {
        const r = await bgSend('TRANSFER_PEER_REMOVE', { deviceId: p.deviceId })
        if (r && r.ok) toast(getMessage('toastRosterRemoved', undefined, 'Removed from this device\'s registry'))
        else toast((r && r.error) || getMessage('toastRemoveFailed', undefined, 'Remove failed — try again; the token is still in your vault.'), 'error')
        refreshDeviceRoster()
      }
      row.appendChild(name)
      row.appendChild(rm)
      box.appendChild(row)
    }
  }
  refreshDeviceRoster()
  window.refreshDeviceRoster = refreshDeviceRoster

  // R85 (§5): the popup's Add-another-device handoff → auto-open the reveal.
  try {
    chrome.storage.local.get('ucrypt:openAddDevice', async (r) => {
      if (r && r['ucrypt:openAddDevice']) {
        await chrome.storage.local.remove('ucrypt:openAddDevice')
        if (state.state && state.state.hasMaster) addDeviceFlow()
      }
    })
  } catch { /* handoff is best-effort */ }

  // R129 GRAND AUDIT (FINDING R129-A1 — the grand audit's headline find): the
  // device-management card's "Leave this device…" (dmLeaveBtn — LIVE at
  // options.html) delegated to $('leaveDeviceBtn') — an id that exists in NO
  // HTML (the R77-era Cloud Sync page's leave button, lost in a surface
  // rework). The optional-chaining click() silently no-opped: the CEO's
  // Leave button did NOTHING. THE FIX: the real leave logic extracted to
  // leaveThisDevice() — the delegate calls it DIRECTLY (no phantom element),
  // and the typed terminal surfaces where the click happened (the toast) AND
  // in the Advanced block's leaveCloudResult (0.26: the result names itself
  // in both places; 0.4: the wrapped logic unchanged).
  async function leaveThisDevice() {
    const out = $('leaveCloudResult')
    const r = await bgSend('SYNC_LEAVE_DEVICE', {})
    if (out) out.textContent = r && r.ok
      ? getMessage('toastLeftDevice', undefined, 'This device left the chain — the local vault stays, the cloud copy was not touched. Reload the page.')
      : ((r && r.error) || 'Failed')
    if (out && r && r.ok) out.className = 'sync-test-result ok'
    toast(r && r.ok
      ? getMessage('toastLeftDevice', undefined, 'This device left the chain — the local vault stays, the cloud copy was not touched. Reload the page.')
      : ((r && r.error) || 'Failed'), r && r.ok ? 'info' : 'error')
    refreshSync()
  }
  __registerLeaveThisDevice(leaveThisDevice)

  $('deleteCloudBtn')?.addEventListener('click', () => {
    $('deleteCloudRow')?.classList.remove('hidden')
    $('deleteCloudConfirm')?.focus()
  })
  $('deleteCloudCancel')?.addEventListener('click', () => $('deleteCloudRow')?.classList.add('hidden'))
  $('deleteCloudGo')?.addEventListener('click', async () => {
    const out = $('leaveCloudResult')
    const confirmVal = ($('deleteCloudConfirm')?.value || '').trim()
    const r = await bgSend('SYNC_DELETE_CLOUD', { confirm: confirmVal })
    if (out) {
      if (r && r.ok) {
        out.className = 'sync-test-result ok'
        out.textContent = getMessage('toastCloudDeleted', undefined, 'The encrypted cloud copy was deleted. Devices that still sync keep their own local vault.')
      } else {
        out.className = 'sync-test-result err'
        out.textContent = '✗ ' + ((r && r.error) || getMessage('toastCloudDeleteFail', undefined, 'The cloud copy could not be deleted — remove it manually in your provider\'s console.'))
      }
    }
    $('deleteCloudRow')?.classList.add('hidden')
    refreshSync()
  })

  // --- R92 §3 — BOOKMARK RESTORE-TO-BROWSER (the R42 canonical item) ------
  // The law (battery-pinned): NEVER automatic — preview + explicit confirm;
  // no duplicate creation (URL + folder); folder paths preserved.
  let bmRestorePlan = null
  $('bmRestoreBtn')?.addEventListener('click', async () => {
    const out = $('bmRestoreResult')
    const preview = $('bmRestorePreview')
    const body = $('bmRestorePreviewBody')
    if (out) { out.textContent = ''; out.className = 'sync-test-result' }
    if (typeof chrome === 'undefined' || !chrome.bookmarks || !chrome.bookmarks.getTree) {
      if (out) { out.className = 'sync-test-result err'; out.textContent = '✗ The bookmarks API is unavailable in this browser context.' }
      return
    }
    const all = await bgSend('GET_ALL_ENTRIES')
    const entries = (all && all.ok && Array.isArray(all.entries)) ? all.entries : []
    // Duplicate matching needs the LIVE tree — fetch it first, build once.
    let bar = null
    try {
      const tree = await chrome.bookmarks.getTree()
      bar = tree && tree[0] && Array.isArray(tree[0].children)
        ? tree[0].children.find(n => n.id === '1') || null
        : null
    } catch { /* no duplicate knowledge — the preview says so */ }
    bmRestorePlan = buildBookmarkRestorePlan(entries, bar)
    if (!bmRestorePlan || !bmRestorePlan.total) {
      if (out) { out.className = 'sync-test-result err'; out.textContent = '✗ ' + getMessage('bmRestoreEmpty', undefined, 'No bookmarks in the vault — import a bookmarks HTML file first (Import Center).') }
      preview?.classList.add('hidden')
      return
    }
    if (body) {
      const lines = []
      const head = document.createElement('div')
      head.textContent = getMessage('bmRestorePreviewHead', [String(bmRestorePlan.creates.length), String(bmRestorePlan.total), String(bmRestorePlan.duplicates)], `${bmRestorePlan.creates.length} of ${bmRestorePlan.total} vault bookmarks will be created (${bmRestorePlan.duplicates} already in this browser — skipped). Folder paths are preserved under "UCrypt restored bookmarks".`)
      head.style.fontWeight = '600'
      lines.push(head)
      const list = document.createElement('ul')
      list.style.marginTop = '6px'
      for (const c of bmRestorePlan.creates.slice(0, 200)) {
        const li = document.createElement('li')
        li.textContent = `${c.path} → ${c.title}`
        list.appendChild(li)
      }
      if (bmRestorePlan.creates.length > 200) {
        const more = document.createElement('li')
        more.textContent = `… and ${bmRestorePlan.creates.length - 200} more`
        list.appendChild(more)
      }
      lines.push(list)
      body.textContent = ''
      for (const el of lines) body.appendChild(el)
    }
    preview?.classList.remove('hidden')
  })
  $('bmRestoreCancel')?.addEventListener('click', () => {
    $('bmRestorePreview')?.classList.add('hidden')
    bmRestorePlan = null
  })
  $('bmRestoreGo')?.addEventListener('click', async () => {
    const out = $('bmRestoreResult')
    if (!bmRestorePlan || !bmRestorePlan.creates.length) return
    const findChild = (parent, title) => ((parent && parent.children) || []).find(c => !c.url && String(c.title || '').trim() === title)
    try {
      const tree = await chrome.bookmarks.getTree()
      const bar = tree[0].children.find(n => n.id === '1')
      const rootTitle = bmRestorePlan.rootTitle
      let root = findChild(bar, rootTitle)
      if (!root) root = await chrome.bookmarks.create({ parentId: bar.id, title: rootTitle })
      // A node map keyed by plan path, seeded with the ROOT itself: plan
      // paths are "<rootTitle>/<folder…>" (the same shape the duplicate
      // matcher compares against browser paths), so the first segment must
      // resolve to the root node — never create a nested duplicate root
      // (F-R92-BMROOT, caught live by the R92 restore row: the first draft
      // created "…/UCrypt restored bookmarks/UCrypt restored bookmarks/…").
      const nodeByPath = new Map([[rootTitle, root], ['', root]])
      const ensureFolder = async (path) => {
        if (nodeByPath.has(path)) return nodeByPath.get(path)
        const parts = path.split('/')
        const parentPath = parts.slice(0, -1).join('/')
        const parent = await ensureFolder(parentPath)
        const title = parts[parts.length - 1]
        let node = findChild(parent, title)
        if (!node) node = await chrome.bookmarks.create({ parentId: parent.id, title })
        nodeByPath.set(path, node)
        return node
      }
      // Folders first (shortest first), then bookmarks — the plan's order law.
      // The root's own segment is already in the map (seeded above).
      const folderPaths = new Set()
      for (const c of bmRestorePlan.creates) {
        const parts = c.path.split('/')
        for (let i = 1; i < parts.length; i++) folderPaths.add(parts.slice(0, i).join('/'))
      }
      for (const fp of [...folderPaths].sort((a, b) => a.split('/').length - b.split('/').length)) await ensureFolder(fp)
      let created = 0
      for (const c of bmRestorePlan.creates) {
        const parent = await ensureFolder(c.path)
        await chrome.bookmarks.create({ parentId: parent.id, title: c.title, url: c.url })
        created++
      }
      if (out) {
        out.className = 'sync-test-result ok'
        out.textContent = '✓ ' + getMessage('bmRestoreDone', [String(created)], `${created} bookmarks restored into this browser. Run it again on any device that joins the chain — duplicates are skipped automatically.`)
      }
    } catch (e) {
      if (out) {
        out.className = 'sync-test-result err'
        out.textContent = '✗ ' + ((e && e.message) || 'The restore failed — no partial duplicates were created for the skipped rows.')
      }
    }
    $('bmRestorePreview')?.classList.add('hidden')
    bmRestorePlan = null
  })

  $('neverSaveInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addNeverSaveFromInput()
  })

  // R45-E — diagnostic summary + recovery sheet
  $('copyDiagBtn').addEventListener('click', copyDiagnosticSummary)
  $('printRecoverySheetBtn').addEventListener('click', printRecoverySheet)

  // R93 §5 — "Verify my setup": read-only checks, typed rows, no auto-fixes.
  // English fallbacks for every typed detail sentence (the i18n layer
  // overrides these per locale; a red row ALWAYS names its fix).
  const DETAIL_FALLBACK = {
    scTransportOk: 'Connected and reachable.',
    scTransportFail: 'The cloud transport did not answer — open the Sync tab, press Test on your transport card, and follow the typed fix.',
    scTransportNone: 'No cloud transport configured — cloud sync is optional; add one on the Sync tab when you want it.',
    scTransportLocked: 'The vault is locked — unlock to let the check test the transport.',
    scChainOk: 'This device has a sync code (chain joined).',
    scChainNone: 'No sync chain — generate a sync code on the Sync tab, or join an existing one from your other device.',
    scBackupOk: 'Backup verified.',
    scBackupNone: 'Back up your sync code — run the backup verification on the Sync tab so a lost device never means a lost vault.',
    scCaptureOk: 'Save-prompt pipeline armed.',
    scCaptureFail: 'Capture is not fully armed — reinstall the extension (load the unzipped folder again) and check that this site is not in the Never-save list.',
    scBadgeOk: 'Badge computed per the law.',
    scBadgeFail: 'The badge decision is off-law — lock and unlock once; if it persists, report it with the acceptance protocol.',
    scStorageOk: 'All structures inside their caps.',
    scStorageFail: 'A stored structure is above its cap — run Sync once and reopen Settings; if it persists, report it.',
    scGrantsOk: 'Sealed on this device.',
    scGrantsFail: 'A stored credential is NOT sealed — lock and unlock the vault once (the migration seals it), then run this check again.',
    scGrantsNone: 'No grants stored on this device yet.',
    scLadderOk: 'Connected — the last connect attempt on this rung succeeded.',
    scLadderFail: 'The last connect attempt failed — press Connect to retry in one click, or climb the guided rung: your own key always works.',
    scLadderNone: 'Not connected on this transport — press Connect (one click where your browser allows it) or walk the guided walkthrough.',
    scSpineArmed: 'ARMED — the persistent sign-in is available: press Connect and one last window mints it; after that UCrypt reconnects by itself, even after a restart.',
    scSpineUnarmed: 'Not armed yet — the Console Item-ID row for the persistent sign-in client is not live (the fix is named on the row). Until then Connect rides today\u2019s one-click path unchanged.',
    scSpineOffline: 'The spine probe could not reach Google — the network is offline or blocked. Press Verify my setup again once the network returns.',
    scSpineNone: 'The spine probe is not available in this context.',
    scSpineUntyped: 'Google answered with an unexpected shape — press Verify my setup again to re-run the probe.',
  }
  $('selfCheckBtn').addEventListener('click', async () => {
    const btn = $('selfCheckBtn')
    const res = $('selfCheckResult')
    const list = $('selfCheckRows')
    btn.disabled = true
    res.className = 'sync-test-result'
    res.textContent = getMessage('scRunning', undefined, 'Running the read-only checks…')
    try {
      const r = await bgSend('SELF_CHECK_RUN', {})
      if (!r || !r.ok || !r.result) {
        res.className = 'sync-test-result err'
        res.textContent = '✗ ' + getMessage('scFail', undefined, 'The check could not run — reopen Settings and try again.')
        return
      }
      const { rows, green, red, info } = r.result
      const LABEL = {
        transport: getMessage('scTransport', undefined, 'Cloud transport reachable'),
        chain: getMessage('scChain', undefined, 'Sync chain joined'),
        backup: getMessage('scBackup', undefined, 'Sync code backup verified'),
        capture: getMessage('scCapture', undefined, 'Capture pipeline armed'),
        badge: getMessage('scBadge', undefined, 'Toolbar badge compute'),
        storage: getMessage('scStorage', undefined, 'Storage within its caps'),
        grants: getMessage('scGrants', undefined, 'Grants and secrets sealed'),
        ladder: getMessage('scLadder', undefined, 'Sign-in ladder'),
        // R171 — the spine row's label (the unbroken spine's verdict).
        spine: getMessage('scSpine', undefined, 'Persistent sign-in (the spine)'),
      }
      list.innerHTML = ''
      for (const row of rows) {
        const li = document.createElement('li')
        li.className = 'sc-row ' + (row.ok === true ? 'sc-ok' : row.ok === false ? 'sc-bad' : 'sc-info')
        const mark = row.ok === true ? '✓' : row.ok === false ? '✗' : 'ℹ'
        let detail = ''
        if (row.ok === false) detail = getMessage(row.detailKey, undefined, DETAIL_FALLBACK[row.detailKey] || '') + (row.detail ? ' — ' + row.detail : '')
        else if (row.ok === true) detail = getMessage(row.detailKey, undefined, DETAIL_FALLBACK[row.detailKey] || '') + (row.detail ? ' — ' + row.detail : '')
        else detail = getMessage(row.detailKey, undefined, DETAIL_FALLBACK[row.detailKey] || '')
        li.textContent = `${mark} ${LABEL[row.id] || row.id}: ${detail}`
        list.appendChild(li)
      }
      res.className = 'sync-test-result ' + (red === 0 ? 'ok' : 'err')
      res.textContent = red === 0
        ? '✓ ' + getMessage('scAllGreen', [String(green), String(info)], `${green} of ${green + info} checks green${info ? ` (${info} informational — optional setup steps)` : ''}. Nothing was changed.`)
        : '✗ ' + getMessage('scReds', [String(red)], `${red} check(s) need attention — every red row above names the fix. Nothing was changed.`)
    } finally {
      btn.disabled = false
    }
  })

  // === R122 §2 — THE ACCEPTANCE WALKTHROUGH (the re-test becomes a product)
  // ========================================================================
  // A declarative step-walk in ONE focused overlay (law 0.25): the pack's
  // steps are data (lib/walkthrough.js), this renderer draws one step at a
  // time, the OWNER advances (law 0.8 — nothing auto-dismisses, nothing
  // times out), progress persists in chrome.storage.local and survives
  // closes. Entry points: the self-check surface's CTA (above) + the Help
  // area (law 0.31 — both open the IDENTICAL surface). The summary paste
  // reuses the diagnostics no-secrets discipline (0.14) and is machine-
  // scanned before Copy ever lights.
  const AW_FALLBACK = {
    awProgress: 'Step $1 of $2',
    awPackAcceptance: 'Acceptance — protocol v17 · resumable',
    awPackWelcome: 'Welcome — your first five minutes',
    awBack: '← Back',
    awSkip: 'Skip this step (recorded honestly in the summary)',
    awConfirmGeneric: 'Confirm — it worked as described',
    awRouteOpen: 'Open it now',
    awProvidedOk: '✓ That looks like a UCrypt sync code ($1 words). Nothing you typed was saved — paste it in the Join wizard next.',
    awProvidedBad: 'That does not look like a UCrypt sync code — a code is 24 words (or a pairing line that starts with “m:”). Nothing was saved — check the code on your other machine, or skip this step and finish it there.',
    awCheckBtn: 'Check the code’s shape (local-only)',
    awCaptureBtn: 'Capture the self-check at this step',
    awCaptureOk: '✓ Captured: $1 green / $2 red / $3 informational rows',
    awCaptureFail: 'The capture could not run right now — you can still confirm the step by eye, or press “Verify my setup” on the Security tab.',
    awCopy: 'Copy the summary',
    awCopyOk: 'Summary copied — paste it to your contact. It carries no secrets.',
    awCopyFail: 'Copy blocked — select the text below and copy it manually.',
    awDone: 'Finish the walkthrough',
    awDoneLine: 'Walkthrough complete. This panel stays open until you close it — your summary is still copyable, and your progress is saved.',
    awScanRed: 'The summary text did not pass the no-secrets scan — Copy stays off. This is a product defect, not your fault: use Help → Export diagnostics instead.',
    awResumeLine: 'Walkthrough in progress: step $1 of $2 ($3). Reopening continues from there.',
    awResumeCta: 'Resume',
    // — step keys (the packs' full fallback table; the locale catalogs are
    // the source of truth, these keep the walk usable in QA stubs) —
    aw0Title: 'Step 0 — the build check (both machines)',
    aw0Body: 'This machine runs UCrypt $1 (build $2…). On your OTHER machine, open UCrypt → Settings → Security → “Owner acceptance & release identity” and check the same version and build. Both machines must run THE EXACT SAME VERSION — that is what makes this test mean anything.',
    aw0Detail: 'This walkthrough itself runs on:',
    aw0Fix: 'If the versions differ: install the same release on both machines before continuing — every later step depends on it.',
    aw0Confirm: 'Both machines run the same version',
    aw1Title: 'Step 1 — the cloud console visit',
    aw1Body: 'Sign in to your Google Cloud console once. Check: the Drive API is enabled, your OAuth client exists, and the publishing status is “In production” (the Testing status expires keys and breaks sync weeks later — publishing to production is the one-time fix).',
    aw1Link: 'Open console.cloud.google.com → APIs & Services → Credentials',
    aw1Link2: 'Open the OAuth consent screen',
    aw1Fix: 'If the console shows “Testing”: press “Publish app” on the consent screen — no verification review is needed for a personal app only you use.',
    aw1Confirm: 'The console is checked (or my cloud needs no console)',
    aw2Title: 'Step 2 — the ladder on this machine',
    aw2Body: 'Open Cloud Sync and look at your transport: the Sign-In Ladder shows which rung you are on. Fast (one click, where your browser allows) → Guided (your own key, illustrated walkthroughs) → Manual (paste a token). Press “Verify my setup” to see the rung rows.',
    aw2See: 'What you should see: the transport card names its rung; the Verify rows show one ladder line per transport, and a connected transport never shows a red row for a missing fast rung.',
    aw2Fix: 'If nothing is connected yet: press Connect on the Cloud Sync tab — one click where your browser allows it, or follow the guided walkthrough (the “Show me how” link) with your own key.',
    aw2Confirm: 'The rung state is visible and truthful',
    aw3Title: 'Step 3 — the join (from your other machine)',
    aw3Body: 'On your OTHER machine, generate the sync code (Cloud Sync → “Create sync code”), then paste it below to check its shape. The check stays in this box — nothing is stored. Then open the Join wizard here and paste it for real: the arrival line names your cloud and the ladder appears.',
    aw3Placeholder: 'Paste the 24-word code (or the m: pairing line)',
    aw3InputHelp: 'The check is local-only: it reads the shape (word count / m: prefix) and forgets the words.',
    aw3See: 'What you should see: the Join wizard’s arrival line — “attached to your cloud”, the transport named, the ladder block in view.',
    aw3Fix: 'If the arrival line never appears: the code may have a typo (a checksum mismatch names it), or the cloud was not pushed yet — run “Sync now” on the other machine first.',
    aw3Skip: 'Skip this step (finish the join later — recorded honestly)',
    aw4Title: 'Step 4 — the visible save crossing',
    aw4Body: 'On your OTHER machine, create a new entry (any site, any username). Watch THIS machine: within a moment (a save, a pull, or the 15-minute cycle) the same entry appears in the vault list here.',
    aw4See: 'What you should see: the new entry appears here without you touching anything — that is the crossing you are confirming.',
    aw4Fix: 'If it never appears: press “Sync now” here once. If it still never appears, the cloud leg is the suspect — run “Test connection” on both machines and note which side errs.',
    aw4Confirm: 'The entry crossed and appeared here',
    aw5Title: 'Step 5 — a config change travels',
    aw5Body: 'On your OTHER machine, change one setting that syncs (for example the auto-lock time or a clipboard preference). Watch this machine apply the same change on its next pull.',
    aw5See: 'What you should see: the setting matches on both machines after a pull — no manual copying.',
    aw5Fix: 'If the change never travels: some settings are device-local on purpose (the transport choice itself, for one). Try a different setting and note which one refused — that is a finding worth reporting.',
    aw5Confirm: 'The change traveled',
    aw6Title: 'Step 6 — the friend-test (Direct Share)',
    aw6Body: 'Direct Share sends a file to any UCrypt user with NO chain, NO cloud, NO account: you mint an invitation, they accept it, one hop, done. If they are offline when the invitation is about to expire, the card offers to hold the file for pickup on YOUR cloud — one click, and they pick it up later with a code. Mint one from the Direct Share tab and receive it on the other machine (or with a friend).',
    aw6See: 'What you should see: the share code travels through any messenger; the receiver accepts and the file arrives digest-verified. The share can never join your chain — that separation is structural.',
    aw6Fix: 'If the handshake stalls: both sides must keep the window open until the transfer completes; the invitation expires after 10 minutes by design — mint a fresh one.',
    aw6Confirm: 'A share crossed one hop',
    aw7Title: 'Step 7 — rename both ways + a tab transfer',
    aw7Body: 'Rename one entry here and see the rename arrive on the other machine; rename there and see it arrive here. Then send a small file from the Device Transfer tab (files move between YOUR synced devices, end-to-end encrypted, no cloud copy).',
    aw7See: 'What you should see: renames travel both directions; the transfer lands with a digest check.',
    aw7Fix: 'If a rename collides with an edit on the other side, UCrypt keeps BOTH (tombstones, never deletes) — the resolution line names it. A stalled transfer: both windows open, then retry.',
    aw7Confirm: 'Renames crossed; the tab transfer landed',
    aw8Title: 'Step 8 — the browser import',
    aw8Body: 'Bring your browser’s own passwords in: Export / Import → “Take your stuff with you” walks the CSV drop with a preview and ONE confirm. The CSV lands nowhere but the vault — delete it from your Downloads after the import (the wizard reminds you).',
    aw8See: 'What you should see: the preview names the count; one confirm saves them; the entries sit in the vault and sync from now on.',
    aw8Fix: 'If your browser refuses to export a CSV: every browser hides it behind its own settings search (“passwords”) — the wizard links each browser’s exact page.',
    aw8Confirm: 'An import landed in the vault',
    aw9Title: 'Step 9 — the self-check and the summary',
    aw9Body: 'Capture the self-check one last time, then copy the summary: it lists every step as ok / skipped, any findings in the step · expected · observed shape, and the exact build both machines ran. It carries NO secrets — paste it as your re-test report.',
    aw9See: 'What you should see: the summary text below — structured, honest about skipped steps, and scan-clean.',
    aw9Fix: 'If Copy is blocked by the browser, select the summary text and copy it manually — the panel never hides it.',
    aw9Capture: 'Capture the self-check',
    aw9Copy: 'Copy the summary',
    aw9Done: 'Finish the walkthrough',
    // — welcome pack —
    wl0Title: 'Welcome — your vault',
    wl0Body: 'UCrypt keeps your passwords and 2FA tokens in an encrypted vault that lives in THIS browser and syncs to YOUR own cloud — nobody’s server in the middle. Set a master passphrase and you are in.',
    wl0See: 'What you should see: the Vault tab with your (for now empty) list, ready for its first entry.',
    wl0Fix: 'If you are locked out: the master passphrase has no recovery — that is the point. Use Emergency wipe and start fresh; your data was only what you had already.',
    wl0Confirm: 'My vault exists and opens',
    wl1Title: 'Your sync code — back it up',
    wl1Body: 'The 24-word sync code is the ONE key to your cloud copy: lose the browser and the code restores everything. Write it on paper and keep it safe — a password manager that syncs should never gatekeep its own backup.',
    wl1See: 'What you should see: Cloud Sync → “Create sync code” shows 24 words and a copy button.',
    wl1Fix: 'If you already have a code (restoring a device): press “I already have one” instead — the words pull your vault down from your cloud.',
    wl1Confirm: 'My code is written down somewhere safe',
    wl2Title: 'Connect your own cloud',
    wl2Body: 'UCrypt seals your vault and stores it in YOUR Google Drive, Dropbox, GitHub Gist or any WebDAV server. The Sign-In Ladder gives you the fastest sign-in your browser allows, illustrated guided steps for your own key, and a manual paste — your cloud, your rules.',
    wl2Link: 'Open Cloud Sync',
    wl2Fix: 'If the fast one-click is not offered: that is the honest graceful absence — your browser or account setup does not allow it yet. The guided rung always works.',
    wl2Confirm: 'My cloud is connected (or I know where the door is)',
    wl3Title: 'Bring your stuff with you',
    wl3Body: 'Passwords from any browser (the CSV walk), bookmarks, history — the migration wizard previews everything and saves with ONE confirm.',
    wl3Link: 'Open the migration wizard',
    wl3Fix: 'If your browser hides its CSV export: the wizard links every browser’s exact settings page.',
    wl3Confirm: 'My stuff is in (or I will do it later)',
    wl4Title: 'The two transfer tabs',
    wl4Body: 'Device Transfer sends files between YOUR synced devices — no cloud copy. Direct Share sends a file to any UCrypt user through a one-hop encrypted handshake — no chain, no account. Both live in their own tabs, one click away.',
    wl4See: 'What you should see: the two tabs in the top menu, each with its own audience line.',
    wl4Fix: 'A transfer that stalls: both sides keep their window open; Direct Share invitations expire after 10 minutes by design — mint a fresh one.',
    wl4Confirm: 'I know where both tabs are',
    wl5Title: 'Done — your first five minutes',
    wl5Body: 'That is the whole tour: vault → code → cloud → import → the two tabs. Copy the summary if you want a record of your setup tour, or just close and start using UCrypt.',
    wl5Copy: 'Copy the tour summary',
    wl5Done: 'Start using UCrypt',
  }
  const awMsg = (key, subs) => getMessage(key, subs, AW_FALLBACK[key] || key)
  const AW_ROUTES = { 'tab-vault': 'optsTabVault', 'tab-security': 'optsTabSecurity', 'tab-sync': 'optsTabSync', 'tab-transfer': 'optsTabDevices', 'tab-share': 'optsTabShare', 'tab-data': 'optsTabData' }
  let _awPack = null
  let _awProgress = null
  let _awBuild = null
  let _awInputShape = null

  async function awReadBuild() {
    if (_awBuild) return _awBuild
    _awBuild = await readBuildJson()
    return _awBuild || null
  }

  /** The input step's LOCAL shape check (0.14: reads the shape, keeps nothing). */
  function awCodeShape(v) {
    const t = String(v || '').trim().toLowerCase()
    if (!t) return null
    if (/^m:(fast|guided|manual):/.test(t)) return { kind: 'pairing', label: 'm:' }
    const words = t.split(/[\s,]+/).filter(Boolean)
    if (words.length === 24) return { kind: 'words24', label: '24' }
    if (words.length === 12) return { kind: 'words12', label: '12' }
    return { kind: 'unknown', label: String(words.length) }
  }

  function awBtn(label, cls, action) {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = cls
    b.textContent = label
    b.addEventListener('click', action)
    return b
  }

  function awP(text, cls) {
    const p = document.createElement('p')
    p.className = cls || 'card-help'
    p.style.margin = '6px 0'
    p.textContent = text
    return p
  }

  async function awCaptureSelfCheck() {
    try {
      const r = await bgSend('SELF_CHECK_RUN', {})
      if (r && r.ok && r.result) {
        const { green, red, info } = r.result
        return { kind: 'self-check', ok: red === 0, green, red, info, note: awMsg('awCaptureOk', [String(green), String(red), String(info)]) }
      }
    } catch { /* typed degradation below */ }
    return null
  }

  function awBuildSummaryText(pack, progress) {
    const titles = {}
    for (const s of pack.steps) titles[s.id] = awMsg(s.titleKey)
    const findings = []
    for (const s of pack.steps) {
      if (progress.skipped && progress.skipped[s.id]) {
        findings.push({ stepId: s.id, expected: awMsg(s.titleKey), observed: awMsg('awSkip'), captureNote: '' })
      }
    }
    const caps = Object.values(progress.captures || {}).filter((c) => c && c.ok === false)
    for (const c of caps) findings.push({ stepId: 'capture', expected: awMsg('awCaptureOk', [String(c.green), '0', String(c.info)]), observed: c.note || '', captureNote: c.kind })
    return Walk.buildSummary(pack, progress, {
      build: { version: (_awBuild && _awBuild.version) || '', payloadSha256: (_awBuild && _awBuild.payloadSha256) || '' },
      titles,
      labels: {
        versionLabel: 'build', packLabel: 'pack', startedLabel: 'started', finishedLabel: 'finished',
        confirmed: 'confirmed', skipped: 'skipped', findingsHead: 'findings',
        expected: 'expected', observed: 'observed', capturePrefix: 'capture',
        noFindings: '- none — every confirmed step matched its what-you-should-see',
        resumeNote: 'This walk resumes from its saved step — reopen the walkthrough any time; confirmed steps stay confirmed.',
        noSecretsNote: 'NO SECRETS: this summary carries no codes, no words, no credentials — nothing was collected that could unlock anything.',
      },
      findings,
    })
  }

  function renderAcceptStep() {
    const host = $('acceptHost')
    const prog = $('acceptProgress')
    const packLabel = $('acceptPackLabel')
    if (!host || !_awPack || !_awProgress) return
    const step = Walk.currentStep(_awPack, _awProgress)
    const totals = Walk.walkTotals(_awPack, _awProgress)
    prog.textContent = awMsg('awProgress', [String(_awProgress.index + 1), String(_awPack.steps.length)])
    packLabel.textContent = awMsg(_awPack.id === Walk.PACK_IDS.welcome ? 'awPackWelcome' : 'awPackAcceptance')
    host.innerHTML = ''
    const h = document.createElement('h3')
    h.style.margin = '4px 0 6px'
    h.textContent = awMsg(step.titleKey)
    host.appendChild(h)
    const body = awMsg(step.bodyKey)
    // the build-check's body carries the LIVE build numbers (0.34)
    if (step.type === 'build-check') {
      const v = (_awBuild && _awBuild.version) || '?'
      const sha = (_awBuild && _awBuild.payloadSha256) || ''
      host.appendChild(awP(awMsg(step.bodyKey, [v, sha ? sha.slice(0, 8) : '?']), 'card-help'))
      if (sha) {
        const mono = document.createElement('p')
        mono.className = 'acc-mono card-help'
        mono.style.margin = '6px 0'
        mono.style.wordBreak = 'break-all'
        mono.textContent = `${awMsg('aw0Detail')} UCrypt ${v} · ${sha}`
        host.appendChild(mono)
      }
    } else {
      host.appendChild(awP(body, 'card-help'))
    }
    if (step.seeKey) host.appendChild(awP(awMsg(step.seeKey), 'card-help'))

    // The capture verdict line (a captured step shows its typed verdict)
    const cap = _awProgress.captures && _awProgress.captures[step.id]
    if (cap) host.appendChild(awP(cap.note || '', cap.ok ? 'sync-test-result ok' : 'sync-test-result err'))

    // The type-specific body
    if (step.type === 'link-out') {
      const row = document.createElement('div')
      row.className = 'btn-row'
      if (step.url) {
        row.appendChild(awBtn(awMsg(step.linkLabelKey || 'awRouteOpen'), 'btn btn-outline', () => { try { chrome.tabs.create({ url: step.url }) } catch { /* typed toast below */ } }))
      }
      if (step.link2) {
        row.appendChild(awBtn(awMsg(step.link2LabelKey || 'awRouteOpen'), 'btn btn-outline', () => { try { chrome.tabs.create({ url: step.link2 }) } catch { /* typed toast below */ } }))
      }
      if (step.route) {
        row.appendChild(awBtn(awMsg('awRouteOpen') + ' — ' + awMsg(AW_ROUTES[step.route] || step.route), 'btn btn-outline', () => switchTab(step.route.replace(/^tab-/, ''))))
      }
      host.appendChild(row)
    }
    if (step.type === 'input') {
      const field = document.createElement('input')
      field.type = 'password'
      field.className = 'input'
      field.placeholder = awMsg(step.placeholderKey)
      field.autocomplete = 'off'
      field.setAttribute('aria-label', awMsg(step.placeholderKey))
      field.style.margin = '6px 0'
      field.id = 'awInputField'
      host.appendChild(field)
      host.appendChild(awP(awMsg(step.inputHelpKey || 'aw3InputHelp'), 'card-help'))
      const verdict = awP('', 'sync-test-result')
      verdict.id = 'awInputVerdict'
      if (_awInputShape && _awInputShape.kind && _awInputShape.kind !== 'unknown') {
        // the checked state re-renders with its verdict intact (the owner
        // pressed Check — the surface keeps telling that truth)
        verdict.className = 'sync-test-result ok'
        verdict.textContent = awMsg('awProvidedOk', [_awInputShape.kind === 'pairing' ? 'm:' : _awInputShape.label])
      }
      host.appendChild(verdict)
      // law 0.14 — the value exists ONLY inside this field: on any confirm
      // the shape is read, the verdict renders, and the field CLEARS.
      field.addEventListener('input', () => { _awInputShape = null; verdict.className = 'sync-test-result'; verdict.textContent = '' })
    }
    if (step.type === 'summary') {
      const text = awBuildSummaryText(_awPack, _awProgress)
      const scan = Walk.scanSummary(text)
      if (step.captureKind) {
        const crow = document.createElement('div')
        crow.className = 'btn-row'
        crow.appendChild(awBtn(awMsg(step.captureKey || 'awCaptureBtn'), 'btn btn-outline', async (e) => {
          const btn = e.currentTarget
          btn.disabled = true
          const c = await awCaptureSelfCheck()
          btn.disabled = false
          if (c) {
            _awProgress = Walk.advance(_awPack, _awProgress, { capture: c })
            await Walk.saveProgress(_awProgress, WalkIo)
            renderAcceptStep()
          } else {
            toast(awMsg('awCaptureFail'), 'error')
          }
        }))
        host.appendChild(crow)
      }
      const out = document.createElement('textarea')
      out.rows = 10
      out.readOnly = true
      out.className = 'hidden'
      out.setAttribute('aria-label', awMsg(step.copyKey || 'awCopy'))
      out.style.width = '100%'
      out.style.fontSize = '12px'
      out.value = text
      host.appendChild(out)
      const brow = document.createElement('div')
      brow.className = 'btn-row'
      const copyBtn = awBtn(awMsg(step.copyKey || 'awCopy'), 'btn btn-primary', async () => {
        if (!scan.ok) { toast(awMsg('awScanRed'), 'error'); return }
        const ok = await copy(text)
        toast(ok ? awMsg('awCopyOk') : awMsg('awCopyFail'), ok ? 'ok' : 'error')
        if (!ok) out.classList.remove('hidden')
      })
      if (!scan.ok) copyBtn.disabled = true // the scan gate — Copy never lights on red
      brow.appendChild(copyBtn)
      brow.appendChild(awBtn(awMsg(step.doneKey || 'awDone'), 'btn btn-outline', async () => {
        _awProgress = Walk.advance(_awPack, _awProgress, {}, Date.now())
        await Walk.saveProgress(_awProgress, WalkIo)
        host.innerHTML = ''
        host.appendChild(awP(awMsg('awDoneLine'), 'sync-test-result ok'))
        // the summary outlives the Finish (0.8) — re-render it read-only
        const keep = document.createElement('textarea')
        keep.rows = 10
        keep.readOnly = true
        keep.style.width = '100%'
        keep.style.fontSize = '12px'
        keep.value = awBuildSummaryText(_awPack, _awProgress)
        host.appendChild(keep)
        refreshAcceptResume()
      }))
      host.appendChild(brow)
      if (!scan.ok) host.appendChild(awP(awMsg('awScanRed'), 'card-help'))
    }

    // The footer: Back + the step's mover (+ Skip for input). The input
    // step's mover is the SHAPE CHECK; the walk's advance appears as its own
    // button ONLY after a valid check — the owner's click is always the
    // mover (0.8), and Skip keeps the step dead-end-free (0.13).
    const foot = document.createElement('div')
    foot.className = 'btn-row'
    foot.style.marginTop = '10px'
    if (_awProgress.index > 0) foot.appendChild(awBtn(awMsg('awBack'), 'btn btn-ghost', async () => {
      _awProgress = Walk.goBack(_awPack, _awProgress)
      await Walk.saveProgress(_awProgress, WalkIo)
      renderAcceptStep()
    }))
    if (step.type === 'input') {
      foot.appendChild(awBtn(awMsg('awSkip'), 'btn btn-ghost', async () => {
        _awProgress = Walk.advance(_awPack, _awProgress, { skipped: true })
        await Walk.saveProgress(_awProgress, WalkIo)
        renderAcceptStep()
      }))
      foot.appendChild(awBtn(awMsg('awCheckBtn'), 'btn btn-outline', () => {
        const field = document.getElementById('awInputField')
        const shape = awCodeShape(field ? field.value : '')
        const verdict = document.getElementById('awInputVerdict')
        if (field) field.value = '' // consumed — the words never persist (0.14)
        if (shape && shape.kind !== 'unknown') {
          if (verdict) { verdict.className = 'sync-test-result ok'; verdict.textContent = awMsg('awProvidedOk', [shape.kind === 'pairing' ? 'm:' : shape.label]) }
          _awInputShape = shape
          renderAcceptStep() // re-render: the advance button lights (see below)
        } else {
          _awInputShape = null
          if (verdict) { verdict.className = 'sync-test-result err'; verdict.textContent = awMsg('awProvidedBad') }
        }
      }))
    }
    if (step.type !== 'summary') {
      const isInput = step.type === 'input'
      if (!isInput) {
        const label = awMsg(step.confirmKey || 'awConfirmGeneric')
        foot.appendChild(awBtn(label, 'btn btn-primary', async () => {
          let capture = null
          if (typeof step.captureKind === 'string') capture = await awCaptureSelfCheck()
          _awProgress = Walk.advance(_awPack, _awProgress, { capture: capture || undefined })
          await Walk.saveProgress(_awProgress, WalkIo)
          renderAcceptStep()
        }))
      } else if (_awInputShape && _awInputShape.kind !== 'unknown') {
        // The advance lights ONLY after a valid shape check — the owner's
        // click records the join and moves on (never an auto-advance, 0.8).
        foot.appendChild(awBtn(awMsg(step.confirmKey || 'awConfirmGeneric'), 'btn btn-primary', async () => {
          _awProgress = Walk.advance(_awPack, _awProgress, { provided: true })
          await Walk.saveProgress(_awProgress, WalkIo)
          _awInputShape = null
          renderAcceptStep()
        }))
      }
    }
    host.appendChild(foot)
  }

  const WalkIo = { storage: chrome.storage.local }

  async function openAcceptWalk(packId) {
    const pack = Walk.getPack(packId)
    if (!pack) return
    const bad = Walk.validatePack(pack)
    if (!bad.ok) { console.error('[UCrypt] walkthrough pack invalid', bad.errors); return }
    _awPack = pack
    _awInputShape = null
    const saved = await Walk.loadProgress(packId, WalkIo)
    _awProgress = Walk.resumeProgress(pack, saved)
    await Walk.saveProgress(_awProgress, WalkIo)
    await awReadBuild()
    openSyncOverlay('acceptOverlay')
    renderAcceptStep()
  }

  /** The honest resume line under the CTA (the saved walk speaks). A
   * finished walk clamps to the final step (never "step 11 of 10"). */
  async function refreshAcceptResume() {
    const el = $('acceptWalkResume')
    if (!el) return
    const saved = await Walk.loadProgress(Walk.PACK_IDS.acceptance, WalkIo)
    if (!saved || (!Object.keys(saved.confirmed || {}).length && !saved.index)) { el.hidden = true; return }
    const resumed = Walk.resumeProgress(Walk.ACCEPTANCE_PACK, saved)
    const totals = Walk.walkTotals(Walk.ACCEPTANCE_PACK, resumed)
    const stepNo = Math.min(totals.confirmed + 1, totals.total)
    el.hidden = false
    const done = Walk.currentStep(Walk.ACCEPTANCE_PACK, resumed)
    el.textContent = awMsg('awResumeLine', [String(stepNo), String(totals.total), awMsg(done.titleKey)])
  }

  /** The welcome offer (order §3): pending × fresh-vault only; the two
   * buttons are the only closers (0.8) and the choice persists. */
  async function refreshWelcomeOffer() {
    const el = $('welcomeOffer')
    if (!el) return
    const st = await Walk.loadWelcomeOffer(WalkIo)
    if (st !== Walk.WELCOME_OFFER_STATES.pending) { el.hidden = true; return }
    let fresh = false
    try {
      const s = await bgSend('GET_STATE', {})
      fresh = !!(s && s.ok && s.state && (!s.state.hasMaster || (typeof s.state.entryCount === 'number' && s.state.entryCount === 0)))
    } catch { fresh = false }
    el.hidden = !fresh
  }

  $('acceptWalkBtn').addEventListener('click', () => openAcceptWalk(Walk.PACK_IDS.acceptance))
  $('acceptWalkBtn2')?.addEventListener('click', () => openAcceptWalk(Walk.PACK_IDS.acceptance))
  $('acceptOverlayClose')?.addEventListener('click', () => closeSyncOverlay('acceptOverlay'))
  $('welcomeOfferStart')?.addEventListener('click', async () => {
    await Walk.saveWelcomeOffer(Walk.WELCOME_OFFER_STATES.accepted, WalkIo)
    $('welcomeOffer').hidden = true
    openAcceptWalk(Walk.PACK_IDS.welcome)
  })
  $('welcomeOfferDismiss')?.addEventListener('click', async () => {
    await Walk.saveWelcomeOffer(Walk.WELCOME_OFFER_STATES.dismissed, WalkIo)
    $('welcomeOffer').hidden = true
  })
  refreshAcceptResume()
  refreshWelcomeOffer()

  // Sync (v2.2.0 — real wizard)
  $('genSyncCodeBtn').addEventListener('click', showGeneratedSyncCode)
  $('restoreSyncCodeBtn').addEventListener('click', () => {
    $('syncRestorePanel').classList.toggle('hidden')
    $('syncCodePanel').classList.add('hidden')
  })
  $('confirmSyncCodeBtn').addEventListener('click', confirmSyncCode)
  $('cancelSyncCodeBtn').addEventListener('click', () => {
    pendingSyncMnemonic = null
    $('syncCodePanel').classList.add('hidden')
  })
  $('copySyncCodeBtn').addEventListener('click', async () => {
    if (!pendingSyncMnemonic) return
    const ok = await copy(pendingSyncMnemonic)
    toast(ok ? getMessage('toastCodeCopied', undefined, '24 words copied') : getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), ok ? 'info' : 'error')
  })
  $('validateSyncBtn').addEventListener('click', validateRestore)
  $('restoreConfirmBtn').addEventListener('click', restoreSyncCode)
  $('restoreCancelBtn').addEventListener('click', () => $('syncRestorePanel').classList.add('hidden'))
  $('twTestBtn').addEventListener('click', () => testCurrentTransport())
  $('twSaveBtn').addEventListener('click', saveCurrentTransport)
  // R172 — THE PURE-PANEL LAW (R-172.4): the Alternative setup panel's own
  // set — the SAME single test/save doors (one machinery, many panels).
  // R176 — R-176.5 THE ANSWERING LABEL-CLASS: the Alternative panel's Test
  // answers IN ITS OWN VISIBLE CONTEXT — a seat created inside the panel
  // (below its own button row), unhidden and scrolled to at press. The old
  // default (#twResult, the retired global seat outside the collapsed
  // details) was the dead-seat class the inventory named (map Adjudication 4).
  $('twAltTestBtn')?.addEventListener('click', () => {
    try {
      const adv = $('twAdvancedConfig')
      if (adv && !adv.open) adv.open = true // the fire exception: the answer lands OPEN
      const host = $('twAltActionsRow') && $('twAltActionsRow').parentElement
      let out = host && host.querySelector(':scope > .panel-test-result')
      if (!out && host) {
        out = document.createElement('p')
        out.className = 'sync-test-result panel-test-result'
        out.setAttribute('role', 'status')
        out.hidden = true
        const row = $('twAltActionsRow')
        if (row.nextSibling) host.insertBefore(out, row.nextSibling)
        else host.appendChild(out)
      }
      if (out) {
        out.hidden = false
        try { out.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) } catch { /* the scroll never blocks the test */ }
      }
      testCurrentTransport(out)
    } catch { testCurrentTransport() }
  })
  $('twAltSaveBtn')?.addEventListener('click', saveCurrentTransport)
  $('twAltCancelBtn')?.addEventListener('click', () => {
    // the panel's Cancel closes ITS panel (the one-open accordion's door)
    try { const adv = $('twAdvancedConfig'); if (adv) adv.open = false } catch { /* best-effort */ }
  })
  $('twCancelBtn').addEventListener('click', () => {
    // R90 §1.1 — leaving the wizard resets Edit mode; the next open of a
    // configured transport shows the summary again (never a stuck editor).
    wizardEditMode = false
    wizardEditTransport = ''
    $('transportWizard').classList.add('hidden')
    // R167 — the picker-collapse law: cancelling the wizard uncollapses the
    // Cloud transport block again (the picker is the layer's resting state).
    try {
      const picker = $('transportPicker')
      if (picker) picker.classList.remove('hidden')
      renderTransportGrid(currentTransportId || '')
    } catch { /* the reset never blocks the cancel */ }
  })
  // R167 — the "Change transport" door (the picker-collapse law's exit):
  // uncollapse the Cloud transport block, hide the wizard — nothing typed
  // in the fields is destroyed, and picking another provider re-opens the
  // wizard fresh on that provider.
  $('twChangeTransportBtn')?.addEventListener('click', () => {
    try {
      const picker = $('transportPicker')
      if (picker) picker.classList.remove('hidden')
      $('transportWizard').classList.add('hidden')
      renderTransportGrid(currentTransportId || '')
    } catch { /* the door never throws */ }
  })
  $('copyScriptBtn').addEventListener('click', async () => {
    const ok = await copy($('twScript').textContent)
    toast(ok ? getMessage('toastScriptCopied', undefined, 'Apps Script copied — paste it at script.google.com') : getMessage('toastClipboardBlocked', undefined, 'Clipboard blocked — select the value and copy it manually.'), ok ? 'info' : 'error')
  })
  $('syncNowBtn').addEventListener('click', syncNowAction)
  $('pullSyncBtn').addEventListener('click', pullSyncAction)

  // Generator Lab (R72)
  document.querySelectorAll('#labTabs .lab-tab').forEach(b => {
    b.addEventListener('click', () => switchLab(b.dataset.lab))
  })
  $('labTabs').addEventListener('keydown', labTabKeydown)
  $('randLength').addEventListener('input', (e) => {
    $('randLengthVal').textContent = String(e.target.value)
    if (labMode === 'random') labGenerate({ silent: true })
  })
  document.querySelectorAll('[data-toggle]').forEach(cb => {
    cb.addEventListener('change', () => {
      const sw = cb.parentElement.querySelector('.switch')
      if (sw) sw.classList.toggle('on', cb.checked)
      if (cb.id === 'labHistoryEnabled') return
      if (LAB_GENERATING_MODES.includes(labMode)) labGenerate({ silent: true })
    })
  })
  $('randExcludeChars').addEventListener('input', () => { if (labMode === 'random') labGenerate({ silent: true }) })
  $('randCustomSymbols').addEventListener('input', () => { if (labMode === 'random') labGenerate({ silent: true }) })
  $('randFirstLetter').addEventListener('change', () => { if (labMode === 'random') labGenerate({ silent: true }) })
  $('saveGenBtn').addEventListener('click', saveGeneratorSettings)
  $('labRegenBtn').addEventListener('click', () => labGenerate())
  $('labCopyBtn').addEventListener('click', labCopy)
  $('labRevealBtn').addEventListener('click', () => labSetRevealed(!labRevealed))
  $('labOutput').addEventListener('click', () => {
    // Click-to-reveal after auto-hide (popup parity; masking is display-only, §3.2)
    if (labSecret && !labRevealed) labSetRevealed(true)
  })
  $('labUseBtn').addEventListener('click', labUse)
  $('labSaveBtn').addEventListener('click', labSave)
  $('labQrBtn').addEventListener('click', labQr)
  $('labQrPngBtn').addEventListener('click', labQrPng)
  $('labAutoHide').addEventListener('change', () => { persistLabPrefs(); scheduleAutoHide() })
  document.querySelectorAll('.preset').forEach(b => {
    b.addEventListener('click', () => applyPreset(b.dataset.preset))
  })
  // passphrase sliders/fields — live value pill + regenerate on change
  $('ppWordsOpt').addEventListener('input', (e) => {
    $('ppWordsOptVal').textContent = String(e.target.value)
    if (labMode === 'passphrase') labGenerate({ silent: true })
  })
  for (const id of ['ppSeparatorOpt', 'ppWordlist', 'ppCapitalizeOpt', 'ppAddNumberOpt', 'ppAddSymbolOpt', 'ppPadOpt', 'ppMinLen', 'ppMaxLen', 'ppExcludePat']) {
    $(id).addEventListener('change', () => {
      if (id === 'ppWordlist') updatePpWlStatus()
      if (labMode === 'passphrase') labGenerate({ silent: true })
    })
  }
  // pin
  $('pinLengthOpt').addEventListener('input', (e) => {
    $('pinLengthOptVal').textContent = String(e.target.value)
    if (labMode === 'pin') labGenerate({ silent: true })
  })
  for (const id of ['pinNoRepeatsOpt', 'pinNoSequencesOpt']) {
    $(id).addEventListener('change', () => { if (labMode === 'pin') labGenerate({ silent: true }) })
  }
  // pronounceable
  $('prSyllables').addEventListener('input', (e) => {
    $('prSyllablesVal').textContent = String(e.target.value)
    if (labMode === 'pronounceable') labGenerate({ silent: true })
  })
  for (const id of ['prCapitalize', 'prAddNumber', 'prAddSymbol']) {
    $(id).addEventListener('change', () => { if (labMode === 'pronounceable') labGenerate({ silent: true }) })
  }
  // bulk
  $('bulkGenerateBtn').addEventListener('click', bulkGenerate)
  $('bulkExportBtn').addEventListener('click', bulkExport)
  $('bulkClearBtn').addEventListener('click', bulkClear)
  // analyze
  $('anRunBtn').addEventListener('click', analyzeRun)
  $('anClearBtn').addEventListener('click', labClearAnalyze)
  $('anRevealBtn').addEventListener('click', () => {
    const inp = $('anInput')
    const showing = inp.type === 'text'
    inp.type = showing ? 'password' : 'text'
    $('anRevealBtn').textContent = showing ? getMessage('entryRevealBtn', undefined, 'Show') : getMessage('entryHideBtn', undefined, 'Hide')
    $('anRevealBtn').setAttribute('aria-pressed', String(!showing))
  })
  // mnemonic
  $('mnGenerateBtn').addEventListener('click', mnemonicGenerate)
  $('mnCheckBtn').addEventListener('click', mnemonicCheck)
  $('mnCheckClearBtn').addEventListener('click', labClearAnalyze)
  // R154 §6 (B.2) — the inline phrase card's actions
  $('mnPhraseCopyBtn').addEventListener('click', mnCopyPhrase)
  $('mnPhraseRegenBtn').addEventListener('click', mnemonicGenerate)
  $('mnPhraseHideBtn').addEventListener('click', mnHidePhrase)
  // dialogs
  $('labConfirmOk').addEventListener('click', () => labConfirmResolve(true))
  $('labConfirmCancel').addEventListener('click', () => labConfirmResolve(false))
  $('labFilterRelax').addEventListener('click', () => { if (labFilterResolve) { labFilterResolve(true); labFilterResolve = null } $('labFilterDialog').classList.add('hidden') })
  $('labFilterCancel').addEventListener('click', () => { if (labFilterResolve) { labFilterResolve(false); labFilterResolve = null } $('labFilterDialog').classList.add('hidden') })
  // session history (UCRYPT-31: prevent <summary> from swallowing toggle clicks,
  // auto-open history drawer when enabled, and immediately record current secret)
  $('labHistoryToggleLabel')?.addEventListener('click', (e) => {
    e.stopPropagation()
  })
  $('labHistoryEnabled').addEventListener('change', () => {
    const enabled = $('labHistoryEnabled').checked
    const sw = $('labHistorySwitch')
    if (sw) sw.classList.toggle('on', enabled)
    if (!enabled) {
      labSessionHistory = []
    } else {
      const box = $('labHistoryBox')
      if (box) box.open = true
      try { SettledHouse.reveal('gen-session-history').catch(() => {}) } catch { /* non-fatal */ }
      if (labSecret && labSecret.kind !== 'mnemonic' && labSessionHistory.length === 0) {
        pushLabHistory(labSecret)
      }
    }
    renderLabHistory()
    persistLabPrefs()
  })
  $('labClearHistoryBtn').addEventListener('click', labClearHistory)
  // R72 lifecycle scrub — pagehide (close/bfcache): nothing typed or
  // generated in the Lab survives the page. Tab-hidden: only the TYPED
  // analyze/mnemonic-check inputs are scrubbed (§4); the displayed
  // generated secret is governed by auto-hide instead.
  window.addEventListener('pagehide', labScrubSession)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') labClearAnalyze()
  })

  // Wordlists
  $('scrapeBtn').addEventListener('click', scrapeWordlist)
  $('exportWordlistBtn').addEventListener('click', exportWordlist)
  $('deleteWordlistBtn').addEventListener('click', deleteCustomWordlist)
  $('importWordlistBtn').addEventListener('click', () => $('wordlistFile').click())
  $('wordlistFile').addEventListener('change', (e) => {
    const f = e.target.files[0]
    if (f) importWordlist(f)
    e.target.value = ''
  })
  $('wlPasteBuildBtn')?.addEventListener('click', () => {
    const raw = $('wlPasteInput') ? $('wlPasteInput').value : ''
    buildCustomWordlistFromPaste(raw)
  })
  $('wlPasteSampleBtn')?.addEventListener('click', () => {
    if ($('wlPasteInput')) $('wlPasteInput').value = SAMPLE_CUSTOM_WORDLIST_TEXT
    buildCustomWordlistFromPaste(SAMPLE_CUSTOM_WORDLIST_TEXT)
  })

  // Export / import vault
  $('exportBtn').addEventListener('click', exportVault)
  $('importBtn').addEventListener('click', () => $('importFile').click())
  $('importFile').addEventListener('change', (e) => {
    const f = e.target.files[0]
    if (f) importVault(f)
    e.target.value = ''
  })
  // v2.9.0 — plaintext CSV export (migration OUT; double-confirmed)
  $('exportCsvBtn').addEventListener('click', exportCsvMigrate)

  // R165 ARC G — THE CARRIES (the data-door receipts section): the
  // export-door receipt, the OFFLINE health report, the gap survey.
  ;(async () => {
    const doorState = document.getElementById('doorState')
    const say = (t) => { if (doorState) doorState.textContent = t }
    const copyOrShow = async (text, okMsg) => {
      try {
        await navigator.clipboard.writeText(text)
        say(okMsg)
      } catch {
        say(getMessage('syncDoctorExportFallback', undefined, 'Clipboard unavailable — the receipt is shown below; copy it manually.'))
        const out = document.createElement('textarea')
        out.value = text
        out.rows = 10
        out.style.width = '100%'
        out.readOnly = true
        doorState.after(out)
      }
    }
    const doorBtn = document.getElementById('doorReceiptBtn')
    if (doorBtn) doorBtn.addEventListener('click', async () => {
      try {
        const Door = await import('./lib/export-door.js')
        const j = await new Promise((r) => chrome.storage.local.get('ucrypt:door:journal', r))
        const arr = Array.isArray(j['ucrypt:door:journal']) ? j['ucrypt:door:journal'] : []
        const lastEnc = [...arr].reverse().find((e) => e && e.kind === 'encrypted-backup') || null
        const lastCsv = [...arr].reverse().find((e) => e && e.kind === 'consented-csv') || null
        const enc = lastEnc ? { ok: true, receipt: { bytes: lastEnc.bytes } } : (arr.length ? { ok: false, error: 'no encrypted-backup export recorded yet on this device' } : null)
        const csv = lastCsv ? { ok: true, consent: { rows: lastCsv.rows, confirmations: lastCsv.confirmations, warning: 'the file is NOT encrypted — anyone who can read it has every password' } } : (arr.length ? { ok: false, error: 'no consented-CSV export recorded yet on this device' } : null)
        const text = Door.buildExportDoorReceipt({
          encrypted: enc,
          csv,
          at: new Date().toISOString(),
        })
        if (!arr.length) {
          await copyOrShow(text + '\n(no export has run yet on this device — the door is closed)', getMessage('doorReceiptEmpty', undefined, 'The export-door receipt was copied — no export has run yet.'))
          return
        }
        await copyOrShow(text, getMessage('doorReceiptCopied', undefined, 'The export-door receipt was copied — counts and hashes only, never contents.'))
      } catch (e) {
        say(String((e && e.message) || e).slice(0, 160))
      }
    })
    const healthBtn = document.getElementById('healthOfflineBtn')
    if (healthBtn) healthBtn.addEventListener('click', async () => {
      try {
        const H = await import('./lib/health-offline.js')
        const r = await bgSend('GET_ALL_ENTRIES')
        if (!r || !r.ok || r.locked) {
          say(getMessage('toastUnlockFirst', undefined, 'Unlock the vault first'))
          return
        }
        const { analyzePassword } = await import('./lib/analyzer.js')
        const built = H.buildOfflineHealthReport(r.entries || [], analyzePassword, { at: new Date().toISOString() })
        if (!built.ok) { say(String(built.error || 'the report could not be built')); return }
        await copyOrShow(built.text, getMessage('healthOfflineCopied', undefined, 'The offline health report was copied — computed on this device; no password ever rides it.'))
      } catch (e) {
        say(String((e && e.message) || e).slice(0, 160))
      }
    })
    const gapBtn = document.getElementById('gapSurveyBtn')
    if (gapBtn) gapBtn.addEventListener('click', async () => {
      try {
        const G = await import('./lib/gap-survey.js')
        let version = ''
        try { version = String((await fetch('BUILD.json').then((r) => r.json())).version || '') } catch { version = String(chrome.runtime.getManifest().version || '') }
        const text = G.buildGapSurveyReceipt({ at: new Date().toISOString(), version })
        await copyOrShow(text, getMessage('gapSurveyCopied', undefined, 'The gap survey was copied — the build\u2019s known gaps, typed and dated.'))
      } catch (e) {
        say(String((e && e.message) || e).slice(0, 160))
      }
    })
  })()

  // R105 §2.2 — Help > Export diagnostics (the bounded UI exception)
  $('exportDiagBtn').addEventListener('click', exportDiagnostics)
  // LAW (R133 — the version-truth row): the running build's version + seal
  // provenance in one line, read from the sealed BUILD.json (never a guess,
  // never a stale literal — the perception fix).
  ;(async () => {
    const row = $('versionTruthRow')
    if (!row) return
    try {
      const b = await fetch('BUILD.json').then((r) => r.json())
      const shortSha = b && typeof b.payloadSha256 === 'string' ? b.payloadSha256.slice(0, 12) + '…' : ''
      row.textContent = getMessage('versionTruth', [String((b && b.version) || ''), shortSha], `You are running v${(b && b.version) || '?'} — the latest sealed candidate (sha ${shortSha}). See RELEASES.json for history.`)
    } catch {
      try {
        row.textContent = getMessage('versionTruthFallback', [String(chrome.runtime.getManifest().version)], `You are running v${chrome.runtime.getManifest().version} — see RELEASES.json for history.`)
      } catch { row.textContent = '' }
    }
  })()

  // v2.7.0 — Import Center (universal browser/manager migration)
  renderImportSources()
  initImportBrowserBanner() // R56-IMPORT-DETECT — browser-aware banner + override
  mwInit() // R101 §3 — the S3 "Take your stuff with you" wizard
  $('icDropzone').addEventListener('click', () => $('icFile').click())
  $('icDropzone').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      $('icFile').click()
    }
  })
  ;['dragenter', 'dragover'].forEach(ev => $('icDropzone').addEventListener(ev, (e) => {
    e.preventDefault()
    e.stopPropagation()
    $('icDropzone').classList.add('ic-dragover')
  }))
  ;['dragleave', 'drop'].forEach(ev => $('icDropzone').addEventListener(ev, (e) => {
    e.preventDefault()
    e.stopPropagation()
    $('icDropzone').classList.remove('ic-dragover')
  }))
  $('icDropzone').addEventListener('drop', (e) => {
    // R127 §5.2 — the multi-type pass: EVERY dropped file joins the batch
    // (one gesture → one merged preview → one confirm). A single file takes
    // the exact historical path.
    const fs = (e.dataTransfer && e.dataTransfer.files) ? [...e.dataTransfer.files] : []
    if (fs.length) icReadFiles(fs)
  })
  $('icFile').addEventListener('change', (e) => {
    const fs = e.target.files ? [...e.target.files] : []
    if (fs.length) icReadFiles(fs)
    e.target.value = ''
  })
  $('icPasteBtn').addEventListener('click', () => {
    $('icPasteWrap').classList.toggle('hidden')
    if (!$('icPasteWrap').classList.contains('hidden')) $('icPaste').focus()
  })
  $('icParsePasteBtn').addEventListener('click', () => {
    const text = $('icPaste').value || ''
    if (!text.trim()) {
      toast(getMessage('icPasteEmpty', undefined, 'Paste the export content first'), 'error')
      return
    }
    icRunImportText(text, getMessage('icPasteLabel', undefined, 'pasted content'))
  })
  $('icImportBtn').addEventListener('click', runImport)
  $('icCancelBtn').addEventListener('click', icReset)

  // R90 §2.2 — direct history import wiring: range buttons preview (never
  // write), the grant button requests the OPTIONAL permission from this
  // user gesture, Import applies through IMPORT_ENTRIES, Start over resets.
  for (const btn of document.querySelectorAll('#icHistRanges [data-range]')) {
    btn.addEventListener('click', () => icHistoryPreview(btn.dataset.range))
  }
  $('icHistGrant').addEventListener('click', async () => {
    const ok = await icHistoryRequestPermission()
    if (ok) {
      icHistoryReset()
      icHistoryPreview(historyState.days || HISTORY_LAW.defaultDays)
    } else {
      $('icHistPreview').classList.remove('hidden')
      $('icHistPreview').textContent = getMessage('icHistDenied', undefined, 'History access was not granted — the direct import stays off. You can still import a history export file from another device via its browser.')
    }
  })
  $('icHistImportBtn').addEventListener('click', icHistoryApply)
  $('icHistCancelBtn').addEventListener('click', icHistoryReset)

  // v2.3.0 — checklist links, dismiss, sync-key KDF upgrade
  // R87 (§2.2): state-aware Open routing — every step's Open button lands on
  // the surface that actually advances THAT step (no dead buttons):
  //   master    → Security tab (passphrase creation)
  //   syncCode  → Sync tab; with a code → the reveal/add-device flow (behind
  //               unlock), without → the generator focused
  //   transport → Sync tab, transport grid in view
  //   firstSync → Sync tab, Sync-now in focus
  document.querySelectorAll('.check-link[data-goto]').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault()
      const step = a.closest('li[data-step]')
      const key = step && step.dataset.step
      switchTab(a.dataset.goto)
      if (key === 'syncCode') {
        if (lastChecklistState.hasSyncCode) {
          // the code exists — land on the reveal flow (re-auth protected)
          const reveal = $('revealSyncCodeBtn') || $('addDeviceBtn')
          if (reveal) { reveal.scrollIntoView({ behavior: 'smooth', block: 'center' }); reveal.focus({ preventScroll: true }) }
        } else {
          const gen = $('genSyncCodeBtn')
          if (gen) { gen.scrollIntoView({ behavior: 'smooth', block: 'center' }); gen.focus({ preventScroll: true }) }
        }
      } else if (key === 'transport') {
        const grid = $('transportGrid')
        if (grid) { grid.scrollIntoView({ behavior: 'smooth', block: 'center' }) }
      } else if (key === 'firstSync') {
        const now = $('syncNowBtn')
        if (now) { now.scrollIntoView({ behavior: 'smooth', block: 'center' }); now.focus({ preventScroll: true }) }
      }
    })
  })
  $('checklistDismiss').addEventListener('click', async () => {
    await chrome.storage.local.set({ [CHECKLIST_KEY]: true })
    $('checklistCard').classList.add('hidden')
  })
  $('kdfUpgradeBtn').addEventListener('click', upgradeKdfAction)

  // Close dialog on overlay click
  $('entryDialog').addEventListener('click', (e) => {
    if (e.target.id === 'entryDialog') closeEntryDialog()
  })

  // Keyboard: Esc closes dialog
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('entryDialog').classList.contains('hidden')) {
      closeEntryDialog()
    }
  })

  // If we have a saved custom wordlist, enable the export/delete buttons
  const w = await loadCustomWordlist()
  if (w && w.length) {
    $('exportWordlistBtn').disabled = false
    $('deleteWordlistBtn').disabled = false
    refreshWlEmptyState()
    refreshWlHeroStatus(w.length)
    $('scrapeResult').classList.remove('hidden')
    $('scrapeResult').innerHTML =
      `<span class="ok">${getMessage('wlHasWords', [String(w.length)], `✓ Custom wordlist has <strong>${w.length}</strong> words`)}</span>`
  } else {
    refreshWlHeroStatus(0)
  }

  refreshVault()
  refreshGenerator()
  refreshNeverSave()

  // v2.3.0 — resolve the initial tab (hash > popup handoff > default) LAST,
  // so all per-tab refreshers above have already primed their data.
  const initialTab = await resolveInitialTab()
  switchTab(initialTab)

  // R61-A §1.3 — options.html#join deep link: the first-class guided join
  // route, reachable from first-run, the popup Sync tab, and shared notes.
  if (_openJoinOnBoot) openJoinChain()

  // R155 §8 (D.4, LAW #98) — options.html#sync-cloud deep link: the cloud
  // setup overlay opens scrolled + focused on top of the Sync tab.
  if (_openCloudOnBoot) openSyncOverlay('cloudOverlay')

  // R155 §8 (D.4) — LIVE deep links: a hash change on an already-open page
  // (the embedded transfer page's Connect Cloud Sync handoff lands HERE)
  // switches the tab and opens the cloud overlay — the boot resolution,
  // kept current for the session's lifetime.
  window.addEventListener('hashchange', () => {
    const h = (location.hash || '').replace('#', '')
    if (h === 'sync-cloud') { switchTab('sync'); openSyncOverlay('cloudOverlay'); return }
    const valid = ['vault', 'security', 'sync', 'transfer', 'share', 'generator', 'wordlists', 'data']
    if (valid.includes(h)) switchTab(h)
  })

  // R59-F1 — the picker's "All logins…" hands the origin over via a
  // device-local storage key; land on the Vault tab with that filter applied
  // (the key is consumed and cleared — no stale filter on the next open).
  try {
    const { 'ucrypt:vaultOriginFilter': origin } = await chrome.storage.local.get('ucrypt:vaultOriginFilter')
    if (origin) {
      await chrome.storage.local.remove('ucrypt:vaultOriginFilter')
      switchTab('vault')
      const f = $('vaultFilter')
      if (f) {
        f.value = String(origin)
        if (typeof renderAllEntries === 'function') renderAllEntries()
      }
    }
  } catch { /* handoff is best-effort */ }
}

// ===========================================================================
// R98 — THE SYNC BEAM (S8): direct join, device-to-device.
// Origin side: the beam window arms with the Add-device surface (S8.3), the
// join dialog lands on the poll (S8.5), Accept fires the envelope transfer
// over the EXISTING WebRTC file plane (S8.6 — this page is the RTC host).
// Joiner side: the join wizard publishes the sealed join record (S8.4),
// awaits the origin's answer, answers the beam offer, adopts the envelope
// (digest verify → pull-first adopt → vault live), and names the backup step.
// Law 0.8 holds everywhere: the join dialog and the beam stage never
// auto-dismiss; every terminal renders truthfully and stays.
// ===========================================================================

const BEAM_POLL_MS = 3000
const BEAM_CHUNK_BYTES = 16384 // MUST match the transfer plane's CHUNK_SIZE
const BEAM_CHANNEL_LOW_WATER = 128 * 1024

const beamRtc = { pc: null, channel: null, role: '', transferId: '', active: false, cancelFlag: false }
let beamOriginPollTimer = null
let beamJoinPollTimer = null
let beamCurrentJoin = null
let beamWindowEnd = ''
let beamManualMode = false // the publish failed — the offer/answer ride by hand (S8.8)
let beamManualAnswer = null // {record, sdp} — set by the dialog's paste box

/** R113 §3.1 — the device-type helpers: a small stroke icon (currentColor —
 * theme-safe) and the localized label, for the roster rows. */
function deviceTypeLabel(t) {
  const map = {
    phone: getMessage('deviceTypePhone', undefined, 'Phone'),
    tablet: getMessage('deviceTypeTablet', undefined, 'Tablet'),
    computer: getMessage('deviceTypeComputer', undefined, 'Computer'),
  }
  return map[t] || ''
}

function deviceTypeIcon(t) {
  const paths = {
    phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><line x1="10.5" y1="18.5" x2="13.5" y2="18.5"/>',
    tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><line x1="10" y1="18.5" x2="14" y2="18.5"/>',
    computer: '<rect x="2.5" y="4" width="19" height="12.5" rx="2"/><line x1="8" y1="20.5" x2="16" y2="20.5"/><line x1="12" y1="16.5" x2="12" y2="20.5"/>',
  }
  if (!paths[t]) return null
  const wrap = document.createElement('span')
  wrap.style.cssText = 'flex:none;display:inline-flex;width:16px;height:16px;color:inherit;opacity:.8'
  wrap.setAttribute('aria-hidden', 'true')
  wrap.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" role="img">${paths[t]}</svg>`
  return wrap
}

function beamFmtRelative(ms) {
  if (!ms || ms <= 0) return getMessage('beamLastActiveNever', undefined, 'not seen yet')
  const s = Math.max(1, Math.round((Date.now() - ms) / 1000))
  if (s < 60) return getMessage('beamLastActiveSecs', [String(s)], `${s}s ago`)
  const m = Math.round(s / 60)
  if (m < 60) return getMessage('beamLastActiveMin', [String(m)], `${m} min ago`)
  const h = Math.round(m / 60)
  if (h < 24) return getMessage('beamLastActiveHour', [String(h)], `${h} h ago`)
  const d = Math.round(h / 24)
  return getMessage('beamLastActiveDay', [String(d)], `${d} d ago`)
}

function beamFmtClock(iso) {
  try { return new Date(iso).toLocaleTimeString() } catch { return String(iso || '') }
}

// ── S8.3 — the beam window arms with the Add-device surface ────────────────

async function armBeamForSheet() {
  const line = $('addDeviceBeamLine')
  try {
    const r = await bgSend('TRANSFER_BEAM_ARM', {})
    if (r && r.ok && r.beam && r.beam.armed) {
      beamWindowEnd = r.beam.windowEnd || ''
      if (line) {
        // R102 (J4) — the two-device dance in one sentence, on the sheet:
        // keep the origin open until the new device appears, then Accept.
        line.textContent = getMessage('beamArmedLineSymphony', [beamFmtClock(beamWindowEnd)],
          `Beam is on until ${beamFmtClock(beamWindowEnd)} — a joining device can find this one now. Keep this window open until the new device appears, then Accept. Closing this sheet turns the beam off.`)
      }
      startBeamOriginPoll()
      startBeamArmTicker()
    } else if (line) {
      line.textContent = getMessage('beamArmFailedLine', undefined,
        'Beam is off — unlock the vault (and set up the sync chain) to let a new device find this one.')
    }
  } catch {
    if (line) {
      line.textContent = getMessage('beamArmFailedLine', undefined,
        'Beam is off — unlock the vault (and set up the sync chain) to let a new device find this one.')
    }
  }
}

// R102 (J4) — the truthful countdown: the armed line re-renders with the
// remaining minutes (a live clock, never a stale promise), and flips to the
// expired terminal when the window ends. Nothing auto-dismisses — the line
// simply tells the truth as time passes.
let beamArmTickerTimer = null
function startBeamArmTicker() {
  stopBeamArmTicker()
  beamArmTickerTimer = setInterval(() => {
    if (!beamWindowEnd) { stopBeamArmTicker(); return }
    const end = Date.parse(beamWindowEnd)
    if (!Number.isFinite(end)) { stopBeamArmTicker(); return }
    const line = $('addDeviceBeamLine')
    if (!line) { stopBeamArmTicker(); return }
    const remainMs = end - Date.now()
    if (remainMs <= 0) {
      line.textContent = getMessage('beamArmExpiredLine', undefined,
        'The beam window has ended — this device stopped announcing itself. Open "Add a device" again to start a new window.')
      stopBeamArmTicker()
      return
    }
    const mins = Math.max(1, Math.round(remainMs / 60000))
    line.textContent = getMessage('beamArmedTickerLine', [String(mins)],
      `Beam is on — a joining device can find this one for about $1 more minute(s). Keep this window open until the new device appears, then Accept.`)
  }, 30000)
}
function stopBeamArmTicker() {
  if (beamArmTickerTimer) { clearInterval(beamArmTickerTimer); beamArmTickerTimer = null }
}

async function disarmBeamForSheet() {
  beamWindowEnd = ''
  stopBeamArmTicker()
  stopBeamOriginPoll()
  closeBeamJoinDialog(true)
  try { await bgSend('TRANSFER_BEAM_DISARM', {}) } catch { /* the window expiry governs regardless */ }
  const line = $('addDeviceBeamLine')
  if (line) line.textContent = getMessage('beamDisarmedLine', undefined, 'Beam is off — this device is no longer announcing itself.')
  renderDeviceMgmt()
}

function startBeamOriginPoll() {
  stopBeamOriginPoll()
  beamOriginPollTimer = setInterval(() => { beamOriginPoll().catch(() => {}) }, BEAM_POLL_MS)
  beamOriginPoll().catch(() => {})
}

function stopBeamOriginPoll() {
  if (beamOriginPollTimer) { clearInterval(beamOriginPollTimer); beamOriginPollTimer = null }
}

// ── S8.5 — the origin's moment: the join poll and the dialog ───────────────

let beamPendingJoins = []

async function beamOriginPoll() {
  if (document.hidden && !beamCurrentJoin) return
  const r = await bgSend('TRANSFER_BEAM_POLL_JOINS', {})
  if (!r || !r.ok) return
  const armed = !!(r.beam && r.beam.armed)
  beamWindowEnd = (r.beam && r.beam.windowEnd) || ''
  beamPendingJoins = Array.isArray(r.joins) ? r.joins : []
  // The pending banner (the origin-was-closed case) — truthful in both
  // states. R102 (J3/J4): the banner now names the requester and the
  // requested time inline, so the card itself answers "who, when" before
  // the dialog even opens; Review still opens the one-click Accept dialog.
  const banner = $('beamPendingBanner')
  if (banner) {
    const show = beamPendingJoins.length > 0 && !beamCurrentJoin
    banner.classList.toggle('hidden', !show)
    banner.hidden = !show
    // R170 §A1 — THE FIRE EXCEPTION: a pending join is a required action
    // whose seat lives inside the collapsed "Your devices" area — the area
    // auto-reveals (no card hides a fire).
    if (show) { try { SettledHouse.reveal('your-devices') } catch { /* the banner still paints */ } }
    if (show) {
      const newest = beamPendingJoins[0]
      const textEl = banner.querySelector('[data-i18n="beamPendingBannerText"]')
      if (textEl) {
        textEl.textContent = getMessage('beamPendingBannerWho', [newest.label || getMessage('beamUnknownDevice', undefined, 'a device'), beamFmtClock(newest.timeIso || newest.expiresAt)],
          '$1 wants to join your sync chain (requested $2).')
      }
    }
    // R110 §4.1 — the status strip's CTA appears ONLY while a join is
    // pending, and it POINTS at the one canonical review surface (the
    // pending banner in "Your devices") — never a second entry point.
    const stripCta = $('stripJoinPendingCta')
    if (stripCta) {
      stripCta.classList.toggle('hidden', !show)
      stripCta.hidden = !show
    }
  }
  if (armed) startBeamOriginPoll.refresh = true
  // A live dialog continues rendering; otherwise land the newest request.
  if (!beamCurrentJoin && beamPendingJoins.length) openBeamJoinDialog(beamPendingJoins[0])
}

function openBeamJoinDialog(join) {
  beamCurrentJoin = join
  const overlay = $('beamJoinDialogOverlay')
  if (!overlay) return
  const shownLabel = join.label || getMessage('beamUnknownDevice', undefined, 'A UCrypt device')
  $('beamJoinDialogLabel').textContent = shownLabel
  // R108 §3.1 — the optional name field: prefilled with the name the device
  // already chose, else the sensible default (browser + OS shape), editable.
  const nameInput = $('beamJoinNameInput')
  if (nameInput) {
    nameInput.value = (join.label && join.label !== getMessage('beamUnknownDevice', undefined, 'A UCrypt device')) ? join.label : sensibleDeviceName()
  }
  $('beamJoinDialogTime').textContent = beamFmtClock(join.timeIso || join.expiresAt)
  $('beamJoinDialogFingerprint').textContent = join.fingerprint || ''
  $('beamJoinDialogSub').textContent = getMessage('beamJoinDialogSub', undefined,
    'It holds your sync code\'s words and asked to join this chain. Compare the fingerprint on both screens, then decide.')
  $('beamJoinDialogResult').textContent = ''
  $('beamJoinDialogResult').className = 'sync-test-result'
  $('beamJoinDialogProgress').classList.add('hidden')
  $('beamJoinDialogProgress').hidden = true
  $('beamAcceptBtn').disabled = false
  $('beamDeclineBtn').disabled = false
  $('beamCloseDialogBtn').classList.add('hidden')
  overlay.classList.remove('hidden')
  overlay.hidden = false
  try { $('beamAcceptBtn').focus() } catch { /* focus is best-effort */ }
}

function closeBeamJoinDialog(silent = false) {
  beamCurrentJoin = null
  const overlay = $('beamJoinDialogOverlay')
  if (overlay) {
    overlay.classList.add('hidden')
    overlay.hidden = true
  }
  if (!silent) renderDeviceMgmt()
}

/** R108 §3.1 — the Accept dialog's optional name: a non-empty value that
 * differs from the device's current name becomes a peer rename (one press,
 * part of the accept — never a separate chore). */
async function applyJoinDialogRename(join) {
  const input = $('beamJoinNameInput')
  if (!input) return
  const want = String(input.value || '').trim()
  if (!want) return
  const current = String(join.label || '')
  if (want === current) return
  const deviceId = String(join.deviceId || join.from || '')
  if (!deviceId) return
  const r = await bgSend('TRANSFER_SET_DEVICE_LABEL', { label: want, deviceId })
  if (r && r.ok) {
    $('beamJoinDialogLabel').textContent = r.label || want
  }
}

/** R108 §3.1 — the sensible default device name (browser + OS shape). */
function sensibleDeviceName() {
  try {
    const ua = navigator.userAgent || ''
    const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : 'Chromium'
    const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : /Mac OS/.test(ua) ? 'macOS' : ''
    return [browser, os].filter(Boolean).join(' · ')
  } catch { return '' }
}

async function acceptBeamJoin() {
  if (!beamCurrentJoin) return
  const join = beamCurrentJoin
  $('beamAcceptBtn').disabled = true
  $('beamDeclineBtn').disabled = true
  const r = await bgSend('TRANSFER_BEAM_ACCEPT', { join })
  if (!r || !r.ok) {
    $('beamJoinDialogResult').className = 'sync-test-result err'
    $('beamJoinDialogResult').textContent = '✗ ' + ((r && (r.detail || r.reason || r.error)) || getMessage('beamAcceptFailed', undefined, 'The beam could not start — the request may have expired.'))
    $('beamCloseDialogBtn').classList.remove('hidden')
    return
  }
  if (r.oversized) {
    // S8.6 — the typed cloud fallback (the joiner was told with its own copy).
    const mb = (r.sizeBytes / (1024 * 1024)).toFixed(1)
    $('beamJoinDialogResult').className = 'sync-test-result warn'
    $('beamJoinDialogResult').textContent = getMessage('beamOversizedOrigin', [mb],
      `The vault is ${mb} MB — larger than the 20 MB beam cap. The joining device was told to use the cloud path instead.`)
    $('beamCloseDialogBtn').classList.remove('hidden')
    return
  }
  if (r.empty) {
    $('beamJoinDialogResult').className = 'sync-test-result ok'
    $('beamJoinDialogResult').textContent = getMessage('beamEmptyOrigin', undefined,
      'This device\'s vault is empty — the new device is joining a fresh chain. Nothing needed to travel.')
    $('beamCloseDialogBtn').classList.remove('hidden')
    await applyJoinDialogRename(join)
    return
  }
  // R108 §3.1 — the optional name rides with the accept: the peer rename is
  // stamped into the sealed map NOW (the roster augmenter carries it to the
  // chain with the next sync).
  await applyJoinDialogRename(join)
  // Fire the beam transfer (S8.6): the envelope rides the WebRTC file plane.
  $('beamJoinDialogProgress').classList.remove('hidden')
  $('beamJoinDialogProgress').hidden = false
  try {
    await beamSendEnvelope(join, r.envelope, r.beamHint)
  } catch (e) {
    $('beamJoinDialogResult').className = 'sync-test-result err'
    $('beamJoinDialogResult').textContent = '✗ ' + ((e && e.message) || getMessage('beamSendFailed', undefined, 'The beam was interrupted — nothing partial was delivered. Try again.'))
    $('beamCloseDialogBtn').classList.remove('hidden')
  }
}

/** S8.8 — the offer signal hand-carry. Shown after Accept: when the cloud
 * publish failed the copy is REQUIRED; when it may still arrive the copy is
 * the deterministic fallback for a slow or absent rendezvous. The joiner's
 * answer is pasted back through the answer box. */
function showBeamManualOffer(offerB64, required) {
  const box = $('beamManualOfferRow')
  if (box) {
    box.classList.remove('hidden')
    box.hidden = false
    const ta = $('beamManualOfferSignal')
    if (ta) ta.value = String(offerB64 || '')
  }
  const answerRow = $('beamManualAnswerRow')
  if (answerRow) {
    answerRow.classList.remove('hidden')
    answerRow.hidden = false
  }
  const res = $('beamJoinDialogResult')
  res.className = required ? 'sync-test-result warn' : 'sync-test-result'
  res.textContent = required
    ? getMessage('beamManualOfferNote', undefined,
      'No cloud rendezvous reachable — copy the signal below and paste it in Manual signaling on the joining device. The beam continues from there.')
    : getMessage('beamManualOfferOptional', undefined,
      'The offer was delivered through the cloud. If the direct route does not connect within a moment, hand-carry the signal below instead.')
}

async function declineBeamJoin() {
  if (!beamCurrentJoin) return
  const join = beamCurrentJoin
  $('beamAcceptBtn').disabled = true
  $('beamDeclineBtn').disabled = true
  const r = await bgSend('TRANSFER_BEAM_DECLINE', { join, reason: '' })
  $('beamJoinDialogResult').className = (r && r.ok) ? 'sync-test-result warn' : 'sync-test-result err'
  $('beamJoinDialogResult').textContent = (r && r.ok)
    ? getMessage('beamDeclinedOrigin', undefined, 'Declined — the joining device was told.')
    : getMessage('beamDeclineFailed', undefined, 'Could not reach the joining device — it will see its request expire.')
  $('beamCloseDialogBtn').classList.remove('hidden')
}

// ── S8.6 — the origin's sender driver (the WebRTC file plane) ──────────────

async function beamSendEnvelope(join, envelope, beamHint) {
  await beamRtcCleanup()
  beamRtc.role = 'origin'
  beamRtc.active = true
  beamRtc.cancelFlag = false
  const pct = $('beamJoinDialogPct')
  const text = $('beamJoinDialogProgressText')
  try {
    // NO relay (the standing owner order): host candidates only.
    const pc = new RTCPeerConnection({ iceServers: [] })
    beamRtc.pc = pc
    pc.onicecandidate = (e) => { if (e.candidate) beamCollectCandidate(pc, e.candidate) }
    beamRtcCandidates.set(pc, [])
    const channel = pc.createDataChannel('ucrypt-xfer', { ordered: true })
    channel.binaryType = 'arraybuffer'
    beamRtc.channel = channel
    beamRtc.transferId = ''
    const drained = () => new Promise((resolve) => {
      const t = setTimeout(resolve, 25)
      try { channel.addEventListener('bufferedamountlow', () => { clearTimeout(t); resolve() }, { once: true }) }
      catch { clearTimeout(t); resolve() }
    })
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    await beamWaitIce(pc)
    const created = await bgSend('TRANSFER_CREATE_OFFER', {
      to: join.from,
      file: { name: envelope.name, size: envelope.size, sha256hex: envelope.sha256hex },
      sdp: pc.localDescription.sdp,
      beamHint: beamHint || await beamOwnCloudHint(),
    })
    if (!created || !created.ok) throw new Error((created && (created.detail || created.error)) || 'offer refused')
    beamRtc.transferId = created.transferId
    // Publish the sealed offer to the joiner's mailbox (cloud path) — and
    // ALWAYS surface the hand-carry signal (S8.8): when the rendezvous is
    // slow or absent, the exact sealed record is copyable right here and the
    // beam continues wherever the answer comes from.
    // F-R99-1 (R99): the hand-carry copy is surfaced the INSTANT the sealed
    // offer exists (the optional copy), and the copy is REQUIRED only when
    // the publish actually fails — under a hostile network the fallback
    // never waits out the retry ladder.
    showBeamManualOffer(created.recordB64 || '', false)
    let publishOk = true
    try { await bgSend('TRANSFER_PUBLISH_RECORD', { record: created.record, to: join.from }) }
    catch { publishOk = false }
    beamManualMode = !publishOk
    if (!publishOk) showBeamManualOffer(created.recordB64 || '', true)
    text.textContent = getMessage('beamProgressConnecting', undefined, 'Request sent — connecting directly to the joining device…')
    // Await the answer through the normal poll.
    const answered = await beamAwaitAnswer(pc, created.transferId)
    if (!answered) throw new Error(getMessage('beamSendExpired', undefined, 'The joining device did not answer in time — the request expired safely.'))
    await bgSend('TRANSFER_OPEN_ANSWER', { record: answered.record })
    // Late ICE candidates (the robustness net — the SDP carries the hosts).
    for (const c of (beamRtcCandidates.get(pc) || [])) {
      try {
        const sealedIce = await bgSend('TRANSFER_SEAL_RECORD', { kind: 'ice', to: join.from, transferId: created.transferId, payload: { candidate: JSON.stringify(c) } })
        if (sealedIce && sealedIce.ok) await bgSend('TRANSFER_PUBLISH_RECORD', { record: sealedIce.record, to: join.from })
      } catch { /* best-effort */ }
    }
    beamRtcCandidates.delete(pc)
    // Pump the envelope: seal chunk i → send chunk i → then seal i+1
    // (the ONE-sequential-pump discipline, backpressure honored).
    channel.bufferedAmountLowThreshold = BEAM_CHANNEL_LOW_WATER
    const totalChunks = Math.ceil(envelope.size / BEAM_CHUNK_BYTES)
    for (let seq = 0; seq < totalChunks; seq++) {
      if (beamRtc.cancelFlag) throw new Error(getMessage('beamSendCancelled', undefined, 'The beam was stopped — nothing partial was delivered.'))
      if (channel.readyState !== 'open') throw new Error(getMessage('beamSendNoRoute', undefined, 'The direct route closed before the beam finished — try again.'))
      const chunkMsg = await bgSend('TRANSFER_BEAM_ENVELOPE_CHUNK', { offset: seq * BEAM_CHUNK_BYTES, length: BEAM_CHUNK_BYTES })
      if (!chunkMsg || !chunkMsg.ok) throw new Error((chunkMsg && chunkMsg.error) || 'envelope slice unavailable')
      const sealed = await bgSend('TRANSFER_SEAL_CHUNK', {
        transferId: beamRtc.transferId, seq, totalChunks, totalBytes: envelope.size, bytesB64: chunkMsg.bytesB64,
      })
      if (!sealed || !sealed.ok) throw new Error((sealed && sealed.error) || 'chunk seal failed')
      while (!beamRtc.cancelFlag && channel.readyState === 'open' && channel.bufferedAmount > BEAM_CHANNEL_LOW_WATER) await drained()
      channel.send(JSON.stringify(sealed.frame))
      const done = Math.min(envelope.size, (seq + 1) * BEAM_CHUNK_BYTES)
      const p = Math.round((done / envelope.size) * 100)
      if (pct) pct.textContent = `${p}%`
      if (text) text.textContent = getMessage('beamProgressSend', [`${done}`, `${envelope.size}`], `${done} of ${envelope.size} bytes sent`)
    }
    // Await the receiver's completion notice (the digest-verified adopt).
    text.textContent = getMessage('beamProgressVerifying', undefined, 'Beam delivered — waiting for the joining device to verify…')
    const completed = await beamAwaitComplete(created.transferId, 60000)
    await bgSend('TRANSFER_BEAM_ENVELOPE_DROP', {}).catch(() => {})
    if (completed) {
      $('beamJoinDialogResult').className = 'sync-test-result ok'
      $('beamJoinDialogResult').textContent = getMessage('beamLandedOrigin', [join.label || getMessage('beamUnknownDevice', undefined, 'the device')],
        `The beam landed — ${join.label || 'the device'} is live and joined the chain.`)
    } else {
      $('beamJoinDialogResult').className = 'sync-test-result warn'
      $('beamJoinDialogResult').textContent = getMessage('beamLandedUnverified', undefined, 'The beam was delivered but the confirmation timed out — the joining device may still verify it.')
    }
    $('beamCloseDialogBtn').classList.remove('hidden')
    // R107 §2.5 — the origin's post-accept hand-off: the transfer window is
    // one click away the moment the chain gains its new device.
    const handoff = $('beamJoinTransferBtn')
    if (handoff) { handoff.hidden = false; handoff.classList.remove('hidden') }
  } finally {
    beamRtc.active = false
  }
}

async function beamAwaitAnswer(pc, transferId, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (beamRtc.cancelFlag) return null
    // S8.8: the answer may arrive by hand (the paste box) — never blocked on
    // a dead rendezvous alone.
    if (beamManualAnswer) {
      const manual = beamManualAnswer
      beamManualAnswer = null
      try { await pc.setRemoteDescription({ type: 'answer', sdp: String(manual.sdp || '') }) } catch { return null }
      return { record: manual.record, sdp: manual.sdp }
    }
    const r = await bgSend('TRANSFER_POLL', {})
    if (r && r.ok) {
      for (const a of (r.answers || [])) {
        if (a.transferId === transferId) {
          try { await pc.setRemoteDescription({ type: 'answer', sdp: String(a.sdp || '') }) } catch { return null }
          return a
        }
      }
      for (const ice of (r.ices || [])) {
        if (ice.transferId === transferId && ice.candidate) {
          try { await pc.addIceCandidate(typeof ice.candidate === 'string' ? JSON.parse(ice.candidate) : ice.candidate) } catch { /* others may connect */ }
        }
      }
      for (const cid of (r.cancels || [])) { if (cid === transferId) return null }
      for (const did of (r.declines || [])) { if (did === transferId) return null }
    }
    await new Promise((res) => setTimeout(res, BEAM_POLL_MS))
    if (pc.connectionState === 'failed') return null
  }
  return null
}

async function beamAwaitComplete(transferId, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const r = await bgSend('TRANSFER_POLL', {})
    if (r && r.ok) {
      for (const cid of (r.completes || [])) { if (cid === transferId) return true }
      for (const cid of (r.cancels || [])) { if (cid === transferId) return false }
    }
    await new Promise((res) => setTimeout(res, BEAM_POLL_MS))
  }
  return false
}

async function beamOwnCloudHint() {
  // The origin's hint rides the offer (S8.6); the worker builds the safe
  // projection (provider + stripped URL) — the page never touches credentials.
  return null
}

async function beamWaitIce(pc, capMs = 3000) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve()
    let done = false
    const finish = () => { if (!done) { done = true; resolve() } }
    pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') finish() })
    setTimeout(finish, capMs)
  })
}

async function beamRtcCleanup() {
  try { if (beamRtc.channel) beamRtc.channel.close() } catch { /* already closed */ }
  try { if (beamRtc.pc) beamRtc.pc.close() } catch { /* already closed */ }
  beamRtc.pc = null
  beamRtc.channel = null
  beamRtc.active = false
  if (beamRtc.transferId) { try { await bgSend('TRANSFER_CANCEL', { transferId: beamRtc.transferId }) } catch { /* terminal anyway */ } }
  beamRtc.transferId = ''
}

// ── The joiner's beam stage (S8.4 → S8.6 → S8.7) ───────────────────────────

async function beamJoinerStart(label) {
  const stage = $('beamJoinStage')
  if (!stage) return
  stage.classList.remove('hidden')
  stage.hidden = false
  $('beamJoinBackupRow').classList.add('hidden')
  $('beamJoinBackupRow').hidden = true
  $('beamJoinProgressRow').classList.add('hidden')
  $('beamJoinProgressRow').hidden = true
  $('beamJoinManualCopyBtn').classList.add('hidden')
  $('beamJoinManualNote').textContent = ''
  $('beamJoinResult').textContent = ''
  $('beamJoinResult').className = 'sync-test-result'
  const phase = $('beamJoinPhase')
  phase.textContent = getMessage('beamJoinPhaseStarting', undefined, 'Announcing this device…')
  const r = await bgSend('TRANSFER_BEAM_JOIN_START', { label: label || '' })
  if (!r || !r.ok) {
    // R101 (§2.1 — the CEO's S4 command): the RED DEAD-END BOX IS RETIRED.
    // An unavailable Beam is not an error — it is the honest state of the
    // two-device choreography: the lane lights up when the ORIGIN opens
    // "Add a device" (unlocked, window armed). The three-path panel carries
    // that sentence; the manual hand-carry affordance stays one click away.
    phase.textContent = getMessage('beamJoinPhaseUnavailable', undefined, 'Unavailable right now — no rendezvous is reachable yet. Connect the same cloud storage above (or paste the join signal below) and this device-to-device lane lights up.')
    updateBeamPathState('warn', getMessage('joinPathBeamWaitingOrigin', undefined,
      'Lights up when the origin device opens “Add a device” — keep that device unlocked with its window open.'))
    await renderSyncStatusStrip().catch(() => {})

    // S8.8: no rendezvous → the manual first contact affordance appears.
    const manualRow = $('beamJoinManualPresenceRow')
    if (manualRow) {
      manualRow.classList.remove('hidden')
      manualRow.hidden = false
    }
    return
  }
  if (r.needsChoice) {
    phase.textContent = getMessage('beamJoinPhaseChoice', undefined, 'More than one device is announcing itself — this flow joins the first available one after you close the others.')
    return
  }
  const join = r.join || {}
  beamJoinJoinId = join.joinMessageId || ''
  $('beamJoinOriginLine').textContent = getMessage('beamJoinOriginLine', [join.origin && join.origin.label || getMessage('beamUnknownDevice', undefined, 'the other device')],
    'Asking $1 to accept this device.')
  $('beamJoinFingerprint').textContent = join.myFingerprint || ''
  $('beamJoinManualCopyBtn').classList.toggle('hidden', !r.stagedManualB64)
  if (r.stagedManualB64) {
    $('beamJoinManualCopyBtn').dataset.signal = r.stagedManualB64
    $('beamJoinManualNote').textContent = getMessage('beamJoinManualNote', undefined,
      'No cloud rendezvous reachable — copy the join signal below onto the other device (Manual signaling) to hand it over.')
  }
  phase.textContent = join.published
    ? getMessage('beamJoinPhaseAwaiting', undefined, 'Waiting for the other device…')
    : getMessage('beamJoinPhaseManual', undefined, 'Waiting — deliver the join signal by hand first.')
  updateBeamPathState('warn', join.published
    ? getMessage('joinPathBeamAwaiting', undefined, 'Asking the other device to accept this join…')
    : getMessage('joinPathBeamManualWait', undefined, 'Waiting — deliver the join signal by hand first.'))
  startBeamJoinPoll()
}

function startBeamJoinPoll() {
  stopBeamJoinPoll()
  beamJoinPollTimer = setInterval(() => { beamJoinerPoll().catch(() => {}) }, BEAM_POLL_MS)
  beamJoinerPoll().catch(() => {})
}

function stopBeamJoinPoll() {
  if (beamJoinPollTimer) { clearInterval(beamJoinPollTimer); beamJoinPollTimer = null }
}

async function beamJoinerPoll() {
  const r = await bgSend('TRANSFER_BEAM_JOIN_POLL', {})
  if (!r || !r.ok) return
  const refusals = Array.isArray(r.refusals) ? r.refusals : []
  for (const refusal of refusals) {
    if (refusal.joinMessageId && beamJoinJoinId && refusal.joinMessageId !== beamJoinJoinId) continue
    stopBeamJoinPoll()
    const phase = $('beamJoinPhase')
    if (refusal.reason === 'oversized') {
      phase.textContent = getMessage('beamJoinPhaseOversized', undefined, 'Too large for the direct beam.')
      const mb = refusal.sizeBytes ? (refusal.sizeBytes / (1024 * 1024)).toFixed(1) : ''
      $('beamJoinResult').className = 'sync-test-result warn'
      $('beamJoinResult').textContent = getMessage('beamJoinOversized', [mb],
        `The vault is larger than the 20 MB beam cap${mb ? ` (${mb} MB)` : ''} — use the cloud path instead: connect the same cloud storage and Sync now.`)
      if (refusal.cloudHint && refusal.cloudHint.provider) {
        $('beamJoinResult').textContent += ' ' + getMessage('beamJoinCloudHint', [refusal.cloudHint.provider + (refusal.cloudHint.url ? ` (${refusal.cloudHint.url})` : '')], `The other device uses: $1.`)
      }
    } else {
      phase.textContent = getMessage('beamJoinPhaseDeclined', undefined, 'The other device declined.')
      $('beamJoinResult').className = 'sync-test-result err'
      $('beamJoinResult').textContent = getMessage('beamJoinDeclined', undefined,
        'The other device declined this join. You can still use the cloud path — connect the same storage and Sync now.')
    }
    return
  }
  const offer = r.offer
  if (offer && !beamRtc.active) {
    stopBeamJoinPoll()
    await beamJoinerAnswerOffer(offer)
  }
}

let beamJoinJoinId = ''
// The beam offer's sender device id (the completion notice's target).
let beamOfferFrom = ''

function offerFromId() {
  return beamOfferFrom
}

async function beamJoinerAnswerOffer(offer) {
  const phase = $('beamJoinPhase')
  const pct = $('beamJoinProgressPct')
  const text = $('beamJoinProgressText')
  $('beamJoinProgressRow').classList.remove('hidden')
  $('beamJoinProgressRow').hidden = false
  phase.textContent = getMessage('beamJoinPhaseConnecting', undefined, 'Accepted — connecting directly…')
  await beamRtcCleanup()
  beamRtc.role = 'joiner'
  beamRtc.active = true
  beamRtc.transferId = offer.transferId
  beamOfferFrom = offer.from || ''
  try {
    const pc = new RTCPeerConnection({ iceServers: [] })
    beamRtc.pc = pc
    beamRtcCandidates.set(pc, [])
    pc.onicecandidate = (e) => { if (e.candidate) beamCollectCandidate(pc, e.candidate) }
    pc.ondatachannel = (e) => {
      const channel = e.channel
      if (!channel || channel.label !== 'ucrypt-xfer') return
      channel.binaryType = 'arraybuffer'
      beamRtc.channel = channel
      channel.onmessage = (ev) => { beamIngestFrame(ev.data).catch(() => {}) }
    }
    await pc.setRemoteDescription({ type: 'offer', sdp: String(offer.sdp || '') })
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await beamWaitIce(pc)
    const res = await bgSend('TRANSFER_ACCEPT_OFFER', { offerId: offer.offerId, sdp: pc.localDescription.sdp })
    if (!res || !res.ok) throw new Error((res && res.error) || 'answer refused')
    try { await bgSend('TRANSFER_PUBLISH_RECORD', { record: res.answerRecord, to: offer.from }) } catch { /* staged/manual fallback */ }
    // Late ICE candidates (the robustness net — the SDP carries the hosts).
    const cands = beamRtcCandidates.get(pc) || []
    for (const c of cands) {
      try {
        const sealed = await bgSend('TRANSFER_SEAL_RECORD', { kind: 'ice', to: offer.from, transferId: offer.transferId, payload: { candidate: JSON.stringify(c) } })
        if (sealed && sealed.ok) await bgSend('TRANSFER_PUBLISH_RECORD', { record: sealed.record, to: offer.from })
      } catch { /* best-effort */ }
    }
    beamRtcCandidates.delete(pc)
    text.textContent = getMessage('beamProgressRecvConnecting', undefined, 'Connected — the vault arrives over the direct channel…')
  } catch (e) {
    beamRtc.active = false
    phase.textContent = getMessage('beamJoinPhaseFailed', undefined, 'The beam could not connect.')
    $('beamJoinResult').className = 'sync-test-result err'
    $('beamJoinResult').textContent = '✗ ' + ((e && e.message) || 'connection failed')
  }
}

const beamRtcCandidates = new WeakMap()

function beamCollectCandidate(pc, candidate) {
  const buf = beamRtcCandidates.get(pc)
  if (buf) buf.push(candidate.toJSON ? candidate.toJSON() : candidate)
}

async function beamIngestFrame(data) {
  let frame = null
  try { frame = typeof data === 'string' ? JSON.parse(data) : null } catch { frame = null }
  if (!frame) return
  const res = await bgSend('TRANSFER_INGEST_FRAME', { transferId: beamRtc.transferId, frame })
  if (!res || !res.ok) return
  const pct = Math.round((res.received / Math.max(1, res.total)) * 100)
  $('beamJoinProgressPct').textContent = `${pct}%`
  $('beamJoinProgressText').textContent = getMessage('beamProgressRecv', [`${res.received}`, `${res.total}`], `${res.received} of ${res.total} bytes received`)
  if (res.received >= res.total && res.total > 0) await beamFinalizeAdopt()
}

async function beamFinalizeAdopt() {
  const phase = $('beamJoinPhase')
  const fin = await bgSend('TRANSFER_FINALIZE', { transferId: beamRtc.transferId })
  if (!fin || !fin.ok) {
    phase.textContent = getMessage('beamJoinPhaseVerifyFail', undefined, 'Verification failed — nothing was adopted.')
    $('beamJoinResult').className = 'sync-test-result err'
    $('beamJoinResult').textContent = '✗ ' + ((fin && fin.error) || getMessage('beamDigestFail', undefined, 'The received bytes did not verify — nothing was adopted; resend the beam.'))
    return
  }
  phase.textContent = getMessage('beamJoinPhaseAdopting', undefined, 'Verified — adopting the vault…')
  // ONE-SHOT export: the worker wipes its plaintext copy after this read.
  const exp = await bgSend('TRANSFER_EXPORT_INBOX', { transferId: beamRtc.transferId })
  if (!exp || !exp.ok) {
    phase.textContent = getMessage('beamJoinPhaseVerifyFail', undefined, 'Verification failed — nothing was adopted.')
    return
  }
  const adopt = await bgSend('TRANSFER_BEAM_ADOPT', { bytesB64: exp.bytesB64, sha256hex: fin.sha256 })
  beamRtc.active = false
  // The completion notice (the R83 ladder's final rung): only after the
  // adopt did the joiner's vault actually become live — only now does the
  // origin's dialog get to say "the beam landed".
  try {
    const sealed = await bgSend('TRANSFER_SEAL_RECORD', { kind: 'complete', to: offerFromId(), transferId: beamRtc.transferId, payload: {} })
    if (sealed && sealed.ok) await bgSend('TRANSFER_PUBLISH_RECORD', { record: sealed.record, to: offerFromId() })
  } catch { /* best-effort — the origin's timeout copy stays truthful */ }
  try { await bgSend('TRANSFER_FINISH', { transferId: beamRtc.transferId }) } catch { /* terminal cleanup */ }
  if (adopt && adopt.ok) {
    phase.textContent = getMessage('beamJoinPhaseLive', undefined, 'Done — this vault is live.')
    $('beamJoinResult').className = 'sync-test-result ok'
    $('beamJoinResult').textContent = getMessage('beamJoinLanded', [String(adopt.entryCount || 0)],
      `✓ The beam landed — ${adopt.entryCount || 0} entries are live on this device.`)
    // R101 (§2.1): the Beam path card goes green — the choreography worked.
    updateBeamPathState('ok', getMessage('joinPathBeamLanded', [String(adopt.entryCount || 0)], `Landed — ${adopt.entryCount || 0} entries are live.`))
    await renderSyncStatusStrip().catch(() => {})
    // S8.7 — the backup step: the named next action (never a dead end).
    const hint = (exp && exp.beamCloudHint) || null
    $('beamJoinBackupRow').classList.remove('hidden')
    $('beamJoinBackupRow').hidden = false
    $('beamJoinBackupText').textContent = getMessage('beamJoinBackupText', undefined,
      'One step left: connect the same cloud storage the other device uses so your vault keeps a durable backup.')
    if (hint && hint.provider) {
      $('beamJoinBackupText').textContent += ' ' + getMessage('beamJoinCloudHint', [hint.provider + (hint.url ? ` (${hint.url})` : '')], `The other device uses: $1.`)
    }
    try { if (typeof refreshSync === 'function') await refreshSync() } catch { /* status refresh is best-effort */ }
  } else {
    phase.textContent = getMessage('beamJoinPhaseAdoptFail', undefined, 'The beam did not land.')
    $('beamJoinResult').className = 'sync-test-result err'
    $('beamJoinResult').textContent = '✗ ' + ((adopt && (adopt.reason || adopt.error)) || getMessage('beamAdoptFail', undefined, 'The received envelope could not be adopted — nothing was changed.'))
  }
}

// ── §4 — the consolidated device list ──────────────────────────────────────

/** S8.9 (R99) — THE LIVING BEAM truth surface (law 3.5): both legs, real
 * timestamps, claimed PER-LEDGER. "Direct: <label> · <time>" / "Cloud:
 * <transport> · <time>"; a leg with no record yet says so truthfully —
 * never a global "synced" feeling. */
async function renderSyncLegs() {
  const directEl = $('syncLegsDirect')
  const cloudEl = $('syncLegsCloud')
  if (!directEl || !cloudEl) return
  const st = await bgSend('TRANSFER_BEAMSYNC_STATUS')
  if (!st || !st.ok) {
    directEl.textContent = ''
    cloudEl.textContent = ''
    return
  }
  const when = (iso) => {
    if (!iso) return ''
    const t = Date.parse(iso)
    if (!Number.isFinite(t)) return ''
    return relativeTime(t)
  }
  const legs = Array.isArray(st.direct) ? st.direct : []
  const okLegs = legs.filter((l) => l.ok)
  const lastOk = okLegs.length ? okLegs.reduce((a, b) => (Date.parse(a.at) >= Date.parse(b.at) ? a : b)) : null
  const lastAny = legs.length ? legs.reduce((a, b) => (Date.parse(a.at) >= Date.parse(b.at) ? a : b)) : null
  if (lastOk) {
    directEl.textContent = getMessage('beamSyncLegsDirect', [lastOk.label || getMessage('beamUnknownDevice', undefined, 'the other device'), when(lastOk.at)], `Direct: $1 · $2`)
    directEl.className = 'card-help'
  } else if (lastAny && lastAny.reason === 'oversized') {
    directEl.textContent = getMessage('beamSyncLegsOversized', undefined, 'Direct: the vault is larger than the 20 MB beam cap — the cloud path carries it.')
    directEl.className = 'card-help'
  } else if (lastAny && lastAny.reason === 'no_peers') {
    directEl.textContent = getMessage('beamSyncLegsNoPeers', undefined, 'Direct: no chain device is known on this device yet — join a device and it syncs directly.')
    directEl.className = 'card-help'
  } else if (lastAny && lastAny.reason === 'no_executor') {
    // R100 §2.2 — the ladder's typed third leg: no executor page was open.
    directEl.textContent = getMessage('beamSyncLegsNoExecutor', undefined, 'Direct: no UCrypt window is open on this device — the cloud path carried the last sync. Open any UCrypt window and the next sync rides the direct lane.')
    directEl.className = 'card-help'
  } else if (lastAny && lastAny.reason === 'no_rtc_context') {
    directEl.textContent = getMessage('beamSyncLegsNoRtc', undefined, 'Direct: this browser\'s background context cannot open direct channels right now — the cloud path carries the sync, and the Sync Beam works from any open UCrypt window.')
    directEl.className = 'card-help'
  } else if (lastAny && !lastAny.ok) {
    directEl.textContent = getMessage('beamSyncLegsDirectFail', [when(lastAny.at)], `Direct: the last attempt did not connect ($1) — the cloud path carried it.`)
    directEl.className = 'card-help'
  } else {
    directEl.textContent = getMessage('beamSyncLegsDirectNone', undefined, 'Direct: no direct sync yet — it happens automatically while devices are on.').replace('$1', '')
    directEl.className = 'card-help'
  }
  const cloud = st.cloud || null
  if (cloud && cloud.at) {
    cloudEl.textContent = cloud.ok
      ? getMessage('beamSyncLegsCloudOk', [cloud.transport || getMessage('beamSyncLegsCloudGeneric', undefined, 'cloud storage'), when(cloud.at)], `Cloud: $1 · $2`)
      : getMessage('beamSyncLegsCloudFail', [when(cloud.at)], `Cloud: the last push did not land ($1) — it retries automatically.`)
  } else {
    cloudEl.textContent = getMessage('beamSyncLegsCloudNone', undefined, 'Cloud: no cloud push yet on this unlock.')
  }
  // S8.9 completion (R100): the executor lane's truth — the real count of
  // open pages hosting the transport. Empty registry = the honest sentence,
  // never a blended "direct" claim.
  const execEl = $('syncLegsExecutors')
  if (execEl) {
    const exs = Array.isArray(st.executors) ? st.executors : []
    if (exs.length) {
      const pages = [...new Set(exs.map((e) => String(e.page || 'page')))].join(', ')
      execEl.textContent = getMessage('beamSyncExecutors', [String(exs.length), pages], `Direct lane: $1 open UCrypt page(s) hosting the beam transport ($2).`)
    } else {
      execEl.textContent = getMessage('beamSyncExecutorsNone', undefined, 'Direct lane: no UCrypt window is open — open any UCrypt window to let this device sync directly.')
    }
  }
}

// ═══ R111 — §3.2 THE SYNC ACTIVITY LEDGER + §2 S9 THE CHAIN'S CONNECTION ═══
//
// The living chain, visible: every landed change writes ONE persisted ledger
// line (the toast may expire per law 0.8 — these lines persist), and the
// chain's shared connection renders by state with the typed notice, the
// one-click conflict, the labeled credential trade, and the per-device
// override. All reads are BOOLEANS and public fields (0.14).

const CHAIN_PROVIDER_NAMES = {
  gdrive: 'Google Drive', github: 'GitHub Gist', dropbox: 'Dropbox',
  webdav: 'WebDAV', custom: 'Custom URL',
}

async function renderSyncActivity() {
  const box = $('syncLedgerBox')
  const rows = $('syncLedgerRows')
  if (!box || !rows) return
  const res = await bgSend('SYNC_MOMENT_LEDGER')
  const ledger = (res && res.ok && Array.isArray(res.ledger)) ? res.ledger : []
  rows.innerHTML = ''
  if (!ledger.length) {
    box.classList.add('hidden')
    box.hidden = true
    return
  }
  box.classList.remove('hidden')
  box.hidden = false
  for (const m of ledger.slice(0, 8)) {
    const line = document.createElement('p')
    line.className = 'card-help'
    line.style.cssText = 'margin:0'
    const lane = m.lane === 'direct'
      ? getMessage('deviceRowLaneDirect', undefined, 'direct')
      : getMessage('deviceRowLaneCloud', undefined, 'cloud')
    const what = (Number(m.added) > 0)
      ? getMessage('syncMomentAdded', [String(m.added)], '$1 new login(s) arrived')
      : getMessage('syncMomentUpdated', [String(m.updated)], '$1 update(s) arrived')
    const by = m.by ? ' ' + getMessage('syncMomentFrom', [m.by], 'from $1') : ''
    line.textContent = `${what}${by} · ${lane} · ${beamFmtRelative(m.at)}`
    rows.appendChild(line)
  }
}

async function renderChainState() {
  const card = $('chainStateCard')
  if (!card) return
  const st = await bgSend('GET_STATE')
  const unlocked = !!(st && st.ok && st.state && st.state.isUnlocked)
  const hasChain = !!(st && st.ok && st.sync && st.sync.syncEnabled)
  const res = await bgSend('CHAIN_STATE_STATUS')
  if (!res || !res.ok || !hasChain) {
    card.classList.add('hidden')
    card.hidden = true
    return
  }
  card.classList.remove('hidden')
  card.hidden = false
  const view = res.local || res.mirror || null
  const providerName = view ? (CHAIN_PROVIDER_NAMES[view.provider] || view.provider) : null
  $('chainStateProvider').textContent = providerName || '—'
  $('chainStateEndpoint').textContent = (view && view.endpoint) ? view.endpoint : '—'
  $('chainStateClientId').textContent = (view && view.clientId) ? view.clientId : '—'
  const creds = $('chainStateCreds')
  if (view && (view.hasSecret || view.hasGrant)) {
    creds.textContent = res.shareCredentials
      ? getMessage('chainStateCredsShared', undefined, 'Yes — sealed end to end')
      : getMessage('chainStateCredsSharedOff', undefined, 'Present on this device — not shared (sharing is off)')
  } else {
    creds.textContent = getMessage('chainStateCredsNone', undefined, 'No credentials to share')
  }
  const change = $('chainStateChange')
  if (res.mirror && res.mirror.rev) {
    const who = res.mirror.setBy ? ` · ${String(res.mirror.setBy).slice(0, 8)}…` : ''
    change.textContent = `#${res.mirror.rev}${who} · ${beamFmtRelative(res.mirror.setAt || 0)}`
  } else {
    change.textContent = getMessage('chainStateChangeNone', undefined, 'No shared change yet')
  }
  // The notice (S9.4) — one typed line per state; the conflict gets the box.
  const noticeEl = $('chainStateNotice')
  const conflictBox = $('chainStateConflictBox')
  conflictBox.classList.add('hidden')
  conflictBox.hidden = true
  noticeEl.classList.add('hidden')
  const n = res.notice
  const showNotice = (cls, text) => {
    noticeEl.className = 'sync-test-result ' + cls
    noticeEl.textContent = text
    noticeEl.classList.remove('hidden')
  }
  if (n && n.kind === 'conflict' && res.conflict) {
    conflictBox.classList.remove('hidden')
    conflictBox.hidden = false
    const theirsName = res.conflict.theirs ? (CHAIN_PROVIDER_NAMES[res.conflict.theirs.provider] || res.conflict.theirs.provider) : '?'
    const mineName = res.conflict.mine ? (CHAIN_PROVIDER_NAMES[res.conflict.mine.provider] || res.conflict.mine.provider) : '?'
    $('chainStateConflictText').textContent = getMessage('chainStateConflictText',
      [theirsName, String(res.conflict.theirs ? res.conflict.theirs.rev : 0), mineName],
      `Another device set the chain's connection to $1 (change #$2) while this device set $3. Pick which one wins — one click, nothing is lost.`)
  } else if (n && n.kind === 'adopted') {
    showNotice('ok', getMessage('chainStateNoticeAdopted', [CHAIN_PROVIDER_NAMES[n.provider] || n.provider], `The chain's $1 connection was updated — using it now.`))
  } else if (n && n.kind === 'pending-override') {
    showNotice('warn', getMessage('chainStateNoticePending', [CHAIN_PROVIDER_NAMES[n.provider] || n.provider], `The chain's $1 connection changed — this device is still using its own sign-in. Rejoin below when you want it.`))
  } else if (n && n.kind === 'resolved-mine') {
    showNotice('ok', getMessage('chainStateNoticeMine', undefined, `This device kept its own connection — it wins the chain's next sync.`))
  }
  // The opt-in toggle + the override button — render by state (0.25).
  const toggle = $('chainShareCredsToggle')
  if (toggle) toggle.checked = !!res.shareCredentials
  const overrideBtn = $('chainStateOverrideBtn')
  if (overrideBtn) {
    overrideBtn.textContent = res.override
      ? getMessage('chainStateOverrideOff', undefined, 'Rejoin the chain\u2019s connection')
      : getMessage('chainStateOverrideBtn', undefined, 'Use my own sign-in on this device')
  }
}

function wireLivingSync() {
  // §3.2 — THE MOMENT MADE VISIBLE: an arriving change toasts (informational
  // — it may expire per 0.8) and the persistent surfaces re-render live.
  try {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg && msg.type === 'UCRYPT_SYNC_MOMENT') {
        const lane = msg.lane === 'direct'
          ? getMessage('deviceRowLaneDirect', undefined, 'direct')
          : getMessage('deviceRowLaneCloud', undefined, 'cloud')
        const what = (Number(msg.added) > 0)
          ? getMessage('syncMomentAdded', [String(msg.added)], '$1 new login(s) arrived')
          : getMessage('syncMomentUpdated', [String(msg.updated)], '$1 update(s) arrived')
        const by = msg.by ? ' ' + getMessage('syncMomentFrom', [msg.by], 'from $1') : ''
        toast(`${what}${by} · ${lane}`)
        renderSyncActivity().catch(() => {})
        renderDeviceMgmt().catch(() => {})
      }
    })
  } catch { /* the listener is best-effort; the ledger persists regardless */ }
  // §3.1 — the block's Sync now: the SAME single-flight cycle the auto-sync
  // runs (pull-first, then the push; typed outcomes).
  $('dmSyncNowBtn')?.addEventListener('click', async () => {
    const btn = $('dmSyncNowBtn')
    try {
      if (btn) btn.disabled = true
      const r = await bgSend('SYNC_NOW')
      if (r && r.ok) {
        const res = r.result || {}
        // R172 — THE HONEST SYNC RESULT (R-172.2): "Nothing to change" is
        // reserved for a sync that RAN and found zero deltas. A SKIPPED sync
        // tells the truth: it did not run, the named reason, the protection
        // rule that caused the skip, and the cure (the attention card below
        // the state line carries [Retry] / [Fix connection] — the toast
        // names the pause and the surfaces carry the doors).
        if (res.synced) {
          toast(getMessage('dmSyncNowDone', undefined, 'Sync complete — the chain is current.'))
        } else if (res.syncSkipped) {
          toast('⏸ ' + getMessage('dmSyncNowSkipped', [String(res.reason || '')], `Sync paused — $1 Press Sync now again after the connection answers, or check the connection details.`))
        } else {
          toast(getMessage('dmSyncNowCurrent', [String(res.reason || '')], `Nothing to change ($1).`))
        }
      } else {
        toast('✗ ' + ((r && r.error) || getMessage('dmSyncNowFailed', undefined, 'The sync could not run — try again.')), 'error')
      }
    } catch (e) {
      toast('✗ ' + ((e && e.message) || 'The sync could not run'), 'error')
    } finally {
      if (btn) btn.disabled = false
      renderDeviceMgmt().catch(() => {})
      renderChainState().catch(() => {})
    }
  })
  // R127 §2 (law 0.41) — the visibility row's two actions: Refresh devices
  // (the real pull + re-render) and Connect your cloud (the single door the
  // join and the cloud block share — never a second entrance, 0.31).
  $('deviceRosterRefreshBtn')?.addEventListener('click', (ev) => {
    refreshDevicesRoster(ev && ev.currentTarget)
  })
  $('deviceRosterConnectBtn')?.addEventListener('click', () => {
    // The single door: the same chooser the join's finish-joining CTA opens.
    $('sdChooseCloudBtn')?.click()
    const block = $('cloudBackupStatus') || $('sdChooseCloudBtn')
    if (block && block.scrollIntoView) {
      try { block.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) } catch { /* best-effort */ }
    }
  })
  // S9.5 — the labeled credential toggle (the trade line lives beside it).
  $('chainShareCredsToggle')?.addEventListener('change', async (ev) => {
    const on = !!(ev && ev.target && ev.target.checked)
    const r = await bgSend('CHAIN_STATE_SHARE', { on })
    if (r && r.ok) {
      toast(on
        ? getMessage('chainShareOn', undefined, 'The chain\u2019s credentials now ride the shared record — sealed end to end.')
        : getMessage('chainShareOff', undefined, 'Credential sharing is off — the connection still shares, the secrets do not.'))
      renderChainState().catch(() => {})
    } else {
      toast(getMessage('chainShareFailed', undefined, 'Could not save the setting — try again.'), 'error')
      if (ev && ev.target) ev.target.checked = !on
    }
  })
  // S9.5 — the per-device override, one click each way.
  $('chainStateOverrideBtn')?.addEventListener('click', async () => {
    const st = await bgSend('GET_STATE')
    if (!(st && st.ok && st.state && st.state.isUnlocked)) {
      toast(getMessage('chainStateLocked', undefined, 'Unlock the vault to change the chain connection.'), 'error')
      return
    }
    const cur = await bgSend('CHAIN_STATE_STATUS')
    const turningOn = !(cur && cur.ok && cur.override)
    const r = await bgSend('CHAIN_STATE_OVERRIDE', { on: turningOn })
    if (r && r.ok) {
      toast(turningOn
        ? getMessage('chainOverrideOn', undefined, 'This device now uses its own sign-in — the chain\u2019s changes wait for you.')
        : (r.adopted
          ? getMessage('chainOverrideOffAdopted', undefined, 'This device rejoined the chain\u2019s connection.')
          : getMessage('chainOverrideOff', undefined, 'Override off — the chain\u2019s newest connection arrives with the next sync.')))
      renderChainState().catch(() => {})
    } else {
      toast('✗ ' + ((r && (r.reason || r.error)) || getMessage('chainShareFailed', undefined, 'Could not save the setting — try again.')), 'error')
    }
  })
  // S9.4 — the conflict, one click each.
  $('chainStateUseChainBtn')?.addEventListener('click', async () => {
    const r = await bgSend('CHAIN_STATE_RESOLVE', { choice: 'chain' })
    if (r && r.ok) {
      toast(getMessage('chainResolvedChain', undefined, 'This device now uses the chain\u2019s connection.'))
    } else {
      toast('✗ ' + ((r && (r.reason || r.error)) || 'Could not apply the chain\u2019s connection'), 'error')
    }
    renderChainState().catch(() => {})
  })
  $('chainStateKeepMineBtn')?.addEventListener('click', async () => {
    const r = await bgSend('CHAIN_STATE_RESOLVE', { choice: 'mine' })
    if (r && r.ok) {
      toast(getMessage('chainResolvedMine', undefined, 'This device kept its own connection — it wins the next sync.'))
    } else {
      toast('✗ ' + ((r && (r.reason || r.error)) || 'Could not save the choice'), 'error')
    }
    renderChainState().catch(() => {})
  })
  // §4.2 door 1 — the fresh state's import door switches to the Data tab
  // (the standing wizard; NO new import path — the front door the engine has).
  $('sdImportBtn')?.addEventListener('click', () => {
    switchTab('data')
    try { $('icSources')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* best-effort */ }
  })
}

// R123 §2.3 (law 0.36 — THE INPUT-PRESERVATION LAW; the CEO's S3) — THE
// ROSTER EDIT-LOCK. The 15-second presence re-render (and the focus /
// visibilitychange renders) used to rebuild the roster DOM with
// host.innerHTML = '' — destroying the rename input mid-typing (the CEO's
// exact capture: "the UCrypt page keeps refreshing in a short amount of
// time, canceling the renaming process"). THE LAW: while a roster edit is
// active (the rename input, or the type selector focused), every BACKGROUND
// render SKIPS the rebuild — presence data still refreshes in memory and
// on every non-edit surface; the roster DOM is touched only by the user's
// own actions (Save / Cancel / Esc / Remove → force). The focused element
// and its state survive every refresh cycle — a UI that eats the user's
// typing is a P1 by definition.
let _rosterEdit = null

async function renderDeviceMgmt(opts = {}) {
  const host = $('deviceListRows')
  if (!host) return
  renderSyncLegs().catch(() => {}) // S8.9 (R99): the legs truth refreshes with the card — never blocks the list
  renderSyncActivity().catch(() => {}) // R111 §3.2: the ledger lines refresh with the card
  renderChainState().catch(() => {}) // R111 §2: the chain's connection renders by state
  // THE EDIT-LOCK: background refreshes never rebuild the roster while an
  // edit is active. opts.force = the user's own action (the edit's own
  // finish) — it may rebuild.
  if (_rosterEdit && !opts.force) return
  const st = await bgSend('GET_STATE')
  const hasChain = !!(st && st.ok && st.sync && st.sync.syncEnabled)
  const unlocked = !!(st && st.ok && st.state && st.state.isUnlocked)
  host.innerHTML = ''
  if (!hasChain) {
    const p = document.createElement('p')
    p.className = 'card-help'
    p.textContent = getMessage('deviceListNoChain', undefined, 'No sync chain on this device yet — create or join one and it shows up here.')
    host.appendChild(p)
    return
  }
  if (!unlocked) {
    const p = document.createElement('p')
    p.className = 'card-help'
    p.textContent = getMessage('deviceListLocked', undefined, 'Unlock the vault to see this device\'s list.')
    host.appendChild(p)
    return
  }
  const res = await bgSend('TRANSFER_LIST_PEERS')
  const peers = (res && res.ok && Array.isArray(res.peers)) ? res.peers : []
  if (!peers.length) {
    const p = document.createElement('p')
    p.className = 'card-help'
    p.textContent = getMessage('deviceListEmpty', undefined, 'No other device is known here yet — "Add a device" pairs one.')
    host.appendChild(p)
    return
  }
  for (const p of peers) {
    const row = document.createElement('div')
    row.className = 'device-list-row'
    row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border, rgba(128,128,128,.25));border-radius:8px'
    // R113 §3.1 — THE DEVICE-TYPE AWARENESS (the CEO's final cosmetic row):
    // a small icon + label per device, SELF-DECLARED (phone/tablet/computer),
    // merged everywhere by the label law (per-entry last-writer by
    // typeSetAt). The self row carries the selector; peer rows render the
    // icon + label they self-declared (absent = the honest "no type yet").
    const typeIcon = deviceTypeIcon(p.deviceType)
    if (typeIcon) row.appendChild(typeIcon)
    const name = document.createElement('strong')
    name.textContent = p.label || getMessage('beamUnknownDevice', undefined, 'A UCrypt device')
    row.appendChild(name)
    if (p.mine) {
      const me = document.createElement('span')
      me.className = 'card-help'
      me.textContent = getMessage('deviceListThisDevice', undefined, '(this device)')
      row.appendChild(me)
      // The self selector — the ONE place a type is declared (self-only law).
      const sel = document.createElement('select')
      sel.style.cssText = 'font-size:11.5px;padding:2px 6px;border:1px solid var(--border, rgba(128,128,128,.35));border-radius:6px;background:transparent;color:inherit;margin:0'
      sel.setAttribute('aria-label', getMessage('deviceTypeAria', undefined, 'This device\u2019s type'))
      const optUnset = document.createElement('option')
      optUnset.value = ''
      optUnset.textContent = getMessage('deviceTypeUnset', undefined, 'Type\u2026')
      sel.appendChild(optUnset)
      for (const t of ['phone', 'tablet', 'computer']) {
        const o = document.createElement('option')
        o.value = t
        o.textContent = deviceTypeLabel(t)
        if (p.deviceType === t) o.selected = true
        sel.appendChild(o)
      }
      sel.addEventListener('change', async () => {
        const r = await bgSend('TRANSFER_SET_DEVICE_TYPE', { deviceType: sel.value })
        if (r && r.ok) {
          toast(getMessage('deviceTypeSet', [deviceTypeLabel(sel.value)], `This device is now a “$1”.`))
        } else {
          toast(getMessage('deviceTypeFailed', undefined, 'Could not save the type \u2014 try again.'), 'error')
        }
        renderDeviceMgmt({ force: true })
      })
      // R123 §2.3 (law 0.36) — the type selector is an in-progress edit too:
      // while it holds focus, background refreshes skip the rebuild (an open
      // dropdown would be closed by a DOM rebuild — the same eating-typing
      // class). Blur without change releases the lock silently.
      sel.addEventListener('focus', () => { _rosterEdit = { deviceId: p.deviceId, kind: 'type' } })
      sel.addEventListener('blur', () => { if (_rosterEdit && _rosterEdit.kind === 'type') _rosterEdit = null })
      row.appendChild(sel)
    } else if (p.deviceType) {
      const tl = document.createElement('span')
      tl.className = 'card-help'
      tl.textContent = deviceTypeLabel(p.deviceType)
      row.appendChild(tl)
    }
    // R100 (the CEO's Brave-style list): name THIS device. R108 §3.2 (the
    // CEO's S5) — MUTUAL RENAME: every roster row gains the affordance — any
    // device can rename any other device; the rename stamps the peer map
    // (per-entry last-writer) and the roster augmenter carries it to the
    // whole chain with the next sync. One input law: 1–40 characters.
    const rn = document.createElement('button')
    rn.className = 'btn btn-ghost btn-sm'
    rn.type = 'button'
    rn.textContent = getMessage('deviceListRename', undefined, 'Rename')
    rn.setAttribute('aria-label', getMessage('deviceListRenameAria', [name.textContent], `Rename ${name.textContent}`))
    rn.addEventListener('click', () => {
      const current = p.label || ''
      const nameInput = document.createElement('input')
      nameInput.type = 'text'
      nameInput.maxLength = 40
      nameInput.value = current === getMessage('beamUnknownDevice', undefined, 'A UCrypt device') ? '' : current
      nameInput.placeholder = p.mine
        ? getMessage('deviceListRenamePlaceholder', undefined, 'This device’s name (e.g. “DELL-01”)')
        : getMessage('deviceListRenamePlaceholderPeer', undefined, 'A name for that device (e.g. “Living-room PC”)')
      nameInput.style.cssText = 'flex:1;min-width:120px;padding:4px 8px;border:1px solid var(--border, rgba(128,128,128,.35));border-radius:6px;background:transparent;color:inherit'
      nameInput.setAttribute('aria-label', getMessage('deviceListRename', undefined, 'Rename'))
      const save = document.createElement('button')
      save.className = 'btn btn-primary btn-sm'
      save.type = 'button'
      save.textContent = getMessage('deviceListRenameSave', undefined, 'Save')
      const cancel = document.createElement('button')
      cancel.className = 'btn btn-ghost btn-sm'
      cancel.type = 'button'
      cancel.textContent = getMessage('deviceListRenameCancel', undefined, 'Cancel')
      const finish = () => { _rosterEdit = null; renderDeviceMgmt({ force: true }) }
      save.addEventListener('click', async () => {
        const r = p.mine
          ? await bgSend('TRANSFER_SET_DEVICE_LABEL', { label: nameInput.value })
          : await bgSend('TRANSFER_SET_DEVICE_LABEL', { label: nameInput.value, deviceId: p.deviceId })
        if (r && r.ok) {
          toast(p.mine
            ? getMessage('deviceListRenamed', [r.label || nameInput.value.trim()], `This device is now named “${r.label || nameInput.value.trim()}”.`)
            : getMessage('deviceListRenamedPeer', [r.label || nameInput.value.trim()], `Renamed to “${r.label || nameInput.value.trim()}” — it will show on that device after the next sync.`))
        } else {
          toast(getMessage('deviceListRenameFailed', undefined, 'Could not save the name — try again.'), 'error')
        }
        finish()
      })
      cancel.addEventListener('click', finish)
      nameInput.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') save.click(); if (ev.key === 'Escape') finish() })
      // R123 §2.3 (law 0.36) — the edit begins: the lock rises BEFORE the
      // row's children are replaced, so no poll in the same tick can win.
      _rosterEdit = { deviceId: p.deviceId, kind: 'rename' }
      row.replaceChildren(...[nameInput, save, cancel])
      nameInput.focus()
    })
    row.appendChild(rn)
    const lastWrap = document.createElement('span')
    lastWrap.style.cssText = 'margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:1px;min-width:0'
    // R113 §3.1 — the SELF row never renders a presence line for itself
    // (its own row is anchored by "(this device)" + the type selector; the
    // always-present self projection carries lastSeen 0 by law).
    if (!p.mine) {
      const last = document.createElement('span')
      last.className = 'card-help'
      // R132 (law 0.46 — THE PRESENCE-HONESTY LAW; the CEO's S1): the
      // annotation is TRUTHFUL about what it knows — the three states derive
      // from the transport's rendezvous capability (the R127 S1 derivation):
      //   'online'  — the rendezvous confirms it (the beam/DAV plane answers);
      //   'offline' — the rendezvous EXISTS and says so (with the last-seen);
      //   'unknown' — no rendezvous on this transport: "online status
      //               unknown … last synced N ago" — NEVER a fabricated
      //               "offline" for a live device.
      // The worker's projection carries the per-row state (presenceState);
      // the pure law renders it (rows from an older projection — the field
      // absent — re-derive here from the same inputs).
      const anno = p.presenceState
        ? { state: p.presenceState }
        : presenceAnnotation(p, { rendezvousAvailable: !!(res && res.rendezvous && res.rendezvous.available) })
      const rendered = anno.state === PRESENCE_STATES.ONLINE
        ? getMessage('deviceListActiveNow', undefined, 'available now')
        : anno.state === PRESENCE_STATES.OFFLINE
          ? getMessage('deviceListLastSeen', [beamFmtRelative(p.lastSeen)], `offline — last seen ${beamFmtRelative(p.lastSeen)}`)
          : (Number(p.syncAt) || Number(p.lastSeen))
            ? getMessage('deviceListPresenceUnknown', [beamFmtRelative(Number(p.syncAt) || Number(p.lastSeen))], `online status unknown — this chain's cloud doesn't support live presence — last synced ${beamFmtRelative(Number(p.syncAt) || Number(p.lastSeen))}`)
            : getMessage('deviceListPresenceUnknownBare', undefined, 'online status unknown — this chain\u2019s cloud doesn\u2019t support live presence')
      last.textContent = rendered
      // The tone: a datum, not an alarm — unknown renders in the help tone
      // (the same class it always had), offline dims, online stays.
      try { last.dataset.presence = presenceTone(anno.state) } catch { /* paint only */ }
      lastWrap.appendChild(last)
    }
    // R111 §3.1 — THE PER-DEVICE SYNC LINE (the living chain made visible):
    // the peer's self-declared last sync — "direct · just now" / "cloud ·
    // 2 min ago" — plus the entry count it holds. Old peers (no stamp) show
    // the last-seen line only — the honest degradation.
    if (p.syncAt) {
      const lane = p.syncLane === 'direct'
        ? getMessage('deviceRowLaneDirect', undefined, 'direct')
        : getMessage('deviceRowLaneCloud', undefined, 'cloud')
      const count = (p.entryCount === null || p.entryCount === undefined) ? null : Number(p.entryCount)
      const line = count === null
        ? `${lane} · ${beamFmtRelative(p.syncAt)}`
        : getMessage('deviceRowSyncLine', [lane, beamFmtRelative(p.syncAt), String(count)], `${lane} · $2 · $3 logins`)
      const sl = document.createElement('span')
      sl.className = 'card-help'
      sl.style.fontSize = '11px'
      sl.style.opacity = '0.85'
      sl.textContent = line
      lastWrap.appendChild(sl)
    }
    row.appendChild(lastWrap)
    if (!p.mine) {
      const rm = document.createElement('button')
      rm.className = 'btn btn-ghost btn-sm'
      rm.type = 'button'
      rm.textContent = getMessage('deviceListRemove', undefined, 'Remove…')
      rm.addEventListener('click', () => { beamRemovePeer(p) })
      row.appendChild(rm)
    }
    host.appendChild(row)
  }
  // R127 §2 (law 0.41 — THE CHAIN-VISIBILITY LAW; the CEO's S2/S5): the
  // roster's truthful visibility row. A chain member is never invisible for
  // the lack of a rendezvous — the list lives in the synced envelope; the
  // ONE thing that can leave it blind on THIS device is a cloud read that
  // never landed. The row names that state with the fix inline (0.26/0.29):
  // Connect your cloud (the single door) or Refresh devices (a real
  // sync-now pull + re-render — the CEO's "resync" affordance). When the
  // chain already shows every member, the row stays quiet (no noise).
  renderRosterVisibilityRow({ hasChain, unlocked, peers })
}

/** R127 §2 (law 0.41) — THE VISIBILITY STATE MACHINE (pure; battery-pinned).
 *  Decides what the devices card says when the roster cannot show the chain.
 *  @param {{hasChain:boolean, unlocked:boolean, peers:Array, hasTransport:boolean,
 *          lastPull:{ok?:boolean, remoteObserved?:boolean, error?:string}|null}} s
 *  @returns {{state:string, textKey:string, text:string, showConnect:boolean, showRefresh:boolean}}
 *  States: no-chain / locked / ready (quiet) / no-transport (Connect) /
 *  pull-failed (Refresh + the reason) / alone (Refresh + the honest line). */
function rosterVisibilityState(s) {
  const { hasChain, unlocked, peers } = s
  if (!hasChain) {
    return { state: 'no-chain', textKey: 'deviceListNoChain', text: getMessage('deviceListNoChain', undefined, 'No sync chain on this device yet — create or join one and it shows up here.'), showConnect: false, showRefresh: false }
  }
  if (!unlocked) {
    return { state: 'locked', textKey: 'deviceListLocked', text: getMessage('deviceListLocked', undefined, 'Unlock the vault to see this device\'s list.'), showConnect: false, showRefresh: false }
  }
  const others = (Array.isArray(peers) ? peers : []).filter(p => !p.mine)
  if (others.length) {
    // Every learned member renders — the family portrait is complete. Quiet.
    return { state: 'ready', textKey: '', text: '', showConnect: false, showRefresh: false }
  }
  if (!s.hasTransport) {
    // THE FORENSIC'S ROOT (law 0.41): the chain's device list lives in the
    // synced envelope — with no cloud on THIS device, nothing ever lands.
    // The fix is one click away (the same single door the join offers).
    return {
      state: 'no-transport',
      textKey: 'deviceRosterNoTransport',
      text: getMessage('deviceRosterNoTransport', undefined, 'Your cloud isn\'t connected on this device — the chain\'s device list travels inside your encrypted cloud copy. Connect the same cloud your other device uses, then Refresh devices.'),
      showConnect: true, showRefresh: true,
    }
  }
  const lp = s.lastPull || null
  const pullFailed = !!(lp && lp.at && lp.ok === false)
  if (pullFailed) {
    // R172 — THE CLASS-PURE FOOTNOTE (R-172.7): the footnote rides the same
    // class the chain state rides. An OAuth-active ledger row renders the
    // ACTIVE method's words — the stored guided/bridge copy (a historical
    // row from the poison seat) never reaches an OAuth surface again.
    // Rows without the stamp (the legacy shape) keep the byte-true old line.
    const mode = String((lp && lp.transportMode) || '')
    if (mode === 'fast' || mode === 'guided') {
      return {
        state: 'pull-failed',
        textKey: 'deviceRosterPullFailedOauth',
        text: getMessage('deviceRosterPullFailedOauth', undefined, `The last cloud read didn't land — the saved sign-in needs you again. Press Connect (one click) in the connection details, then Refresh devices to try now.`),
        showConnect: false, showRefresh: true,
      }
    }
    const reason = String(lp.error || '').slice(0, 120)
    return {
      state: 'pull-failed',
      textKey: 'deviceRosterPullFailed',
      text: getMessage('deviceRosterPullFailed', [reason], `The last cloud read didn't land ($1) — your devices appear here the moment a read succeeds. Refresh devices to try now.`),
      showConnect: false, showRefresh: true,
    }
  }
  return {
    state: 'alone',
    textKey: 'deviceRosterAlone',
    text: getMessage('deviceRosterAlone', undefined, 'Only this device is on the list so far. If another device joined the chain, its name arrives inside the next cloud read — Refresh devices to check now.'),
    showConnect: false, showRefresh: true,
  }
}

/** R127 §2 (law 0.41) — render the visibility row + wire its two actions. */
function renderRosterVisibilityRow({ hasChain, unlocked, peers }) {
  const box = $('deviceRosterState')
  if (!box) return
  const txt = $('deviceRosterStateText')
  const connectBtn = $('deviceRosterConnectBtn')
  const refreshBtn = $('deviceRosterRefreshBtn')
  if (!txt || !connectBtn || !refreshBtn) return
  let hasTransport = false
  let lastPull = null
  try {
    // The transport + pull ledger are read synchronously from the last
    // GET_STATE the card already holds where possible; a fresh read keeps
    // the row truthful when the card renders on its own schedule.
    chrome.storage.local.get(['ucrypt:transport', 'ucrypt:lastPull']).then((o) => {
      hasTransport = !!(o && o['ucrypt:transport'] && o['ucrypt:transport'].id)
      lastPull = (o && o['ucrypt:lastPull']) || null
      paint()
    }).catch(() => paint())
  } catch { paint() }
  const paint = () => {
    const v = rosterVisibilityState({ hasChain, unlocked, peers, hasTransport, lastPull })
    if (v.state === 'ready') { box.classList.add('hidden'); box.hidden = true; return }
    box.classList.remove('hidden'); box.hidden = false
    txt.textContent = v.text
    // The Connect affordance renders ONLY when it is the fix (0.29 — the
    // fix button lives on the surface that named the problem).
    if (v.showConnect) {
      connectBtn.classList.remove('hidden'); connectBtn.hidden = false
      // R170 §A1 — the fire exception: the Connect-your-cloud affordance is
      // a required action inside the collapsed devices area — it reveals.
      try { SettledHouse.reveal('your-devices') } catch { /* the row still paints */ }
    } else {
      connectBtn.classList.add('hidden'); connectBtn.hidden = true
    }
    refreshBtn.classList.toggle('hidden', !v.showRefresh)
    refreshBtn.hidden = !v.showRefresh
  }
}

/** R127 §2 (law 0.41) — REFRESH DEVICES (the CEO's "resync" affordance):
 *  one click runs the SAME single-flight sync cycle the Sync now button
 *  runs (pull-first — the read is what lets the roster learn), then
 *  re-renders the roster with force (the edit-lock yields to the user's own
 *  action). The result is typed and truthful — never a silent spin. */
async function refreshDevicesRoster(btn) {
  try { if (btn) btn.disabled = true } catch { /* paint only */ }
  try {
    const r = await bgSend('SYNC_NOW')
    if (r && r.ok) {
      const res = r.result || {}
      toast(res.synced
        ? getMessage('deviceRosterRefreshDone', undefined, 'Devices refreshed from the chain.')
        : getMessage('deviceRosterRefreshCurrent', [String(res.reason || '')], `Nothing new ($1) — the roster is current.`))
    } else {
      toast('✗ ' + ((r && r.error) || getMessage('deviceRosterRefreshFailed', undefined, 'The refresh could not run — check your cloud connection and try again.')), 'error')
    }
  } catch (e) {
    toast('✗ ' + getMessage('deviceRosterRefreshFailed', undefined, 'The refresh could not run — check your cloud connection and try again.'), 'error')
  }
  await renderDeviceMgmt({ force: true })
  try { if (btn) btn.disabled = false } catch { /* paint only */ }
}

async function beamRemovePeer(p) {
  const label = p.label || getMessage('beamUnknownDevice', undefined, 'this device')
  // Typed confirm — the honest consequence: this device forgets the other
  // one; nothing is revoked remotely (UCrypt runs no server).
  const ok = window.confirm(getMessage('deviceListRemoveConfirm', [label],
    `Remove ${label} from this device's list? It keeps working independently — this only makes THIS device forget it.`))
  if (!ok) return
  const r = await bgSend('TRANSFER_PEER_REMOVE', { deviceId: p.deviceId })
  if (r && r.ok) {
    toast(getMessage('deviceListRemoved', [label], `${label} was removed from this device's list.`))
  } else {
    toast(getMessage('deviceListRemoveFailed', undefined, 'Could not remove the device — try again.'), 'error')
  }
  renderDeviceMgmt()
}

function wireBeam() {
  // The device surface's CTA arms the beam and opens the pairing sheet.
  $('dmAddDeviceBtn')?.addEventListener('click', () => { addDeviceFlow(); armBeamForSheet() })
  // The legacy Add-device buttons arm the beam too (S8.3: the SURFACE arms it).
  // R129 GRAND AUDIT: the sdAddDeviceBtn binding is REMOVED — the id exists in
  // NO HTML (a dead binding; the live add-device doors are dmAddDeviceBtn and
  // the sdShowWords pair, both beam-armed at their own sites).
  $('sdShowWordsBtn')?.addEventListener('click', () => { armBeamForSheet() })
  $('sdShowWordsBtn2')?.addEventListener('click', () => { armBeamForSheet() })
  // The sheet's close disarms (S8.3: closing withdraws the tombstone).
  $('addDeviceClose')?.addEventListener('click', () => { disarmBeamForSheet() })
  // The consolidated card's Leave/Delete reuse the EXISTING typed flows.
  // R129 GRAND AUDIT (R129-A1): the Leave button calls the REAL leave logic
  // directly (the extracted leaveThisDevice — registered by the sync wiring)
  // instead of the severed phantom-element chain that silently no-opped.
  $('dmLeaveBtn')?.addEventListener('click', () => {
    if (typeof _leaveThisDevice === 'function') _leaveThisDevice()
    else {
      // Never a dead end (0.26): the bridge unset would be a wiring fault —
      // the leave still executes through the direct typed path.
      bgSend('SYNC_LEAVE_DEVICE', {}).then((r) => {
        toast(r && r.ok
          ? getMessage('toastLeftDevice', undefined, 'This device left the chain — the local vault stays, the cloud copy was not touched. Reload the page.')
          : ((r && r.error) || 'Failed'), r && r.ok ? 'info' : 'error')
      }).catch(() => { /* the typed error already surfaced above */ })
    }
  })
  $('dmDeleteCloudBtn')?.addEventListener('click', () => {
    try {
      // R109 §4.1(b) — the cloud-copy tools live in the Advanced block now;
      // open it (and the card is reachable — the anti-trim law).
      const adv = $('blockAdvanced')
      if (adv && adv.tagName === 'DETAILS') adv.open = true
      $('cloudCopyCard').scrollIntoView({ behavior: 'smooth', block: 'center' })
      $('deleteCloudBtn')?.click()
    } catch { /* best-effort */ }
  })
  // S8.9 (R99) — the explicit fan-out action beside the truth surface.
  $('beamSyncNowBtn')?.addEventListener('click', async () => {
    const btn = $('beamSyncNowBtn')
    try {
      if (btn) btn.disabled = true
      const r = await bgSend('TRANSFER_BEAMSYNC_FANOUT', { reason: 'manual' })
      if (r && r.ok && r.oversized) {
        toast(getMessage('beamSyncOversizedToast', undefined, 'The vault is larger than the 20 MB beam cap — use the cloud path (Sync now).'), 'error')
      } else if (r && r.busy) {
        toast(getMessage('beamSyncBusyToast', undefined, 'A beam sync is already running — it will pick up this change.'))
      } else {
        toast(getMessage('beamSyncStartedToast', undefined, 'The beam is synchronizing directly with your devices.'))
      }
    } catch (e) {
      toast('✗ ' + ((e && e.message) || 'The beam sync could not start'), 'error')
    } finally {
      if (btn) btn.disabled = false
      renderSyncLegs().catch(() => {})
    }
  })

  // The join dialog (S8.5).
  $('beamAcceptBtn')?.addEventListener('click', acceptBeamJoin)
  $('beamDeclineBtn')?.addEventListener('click', declineBeamJoin)
  $('beamCloseDialogBtn')?.addEventListener('click', () => closeBeamJoinDialog(false))
  $('beamPendingShowBtn')?.addEventListener('click', () => { if (beamPendingJoins.length) openBeamJoinDialog(beamPendingJoins[0]) })
  // R110 §4.1 — the strip CTA scrolls the ONE canonical surface into view
  // and opens the same dialog (a pointer, not a second door).
  $('stripJoinPendingCta')?.addEventListener('click', () => {
    // R170 §A1 — the CTA points INTO the collapsed "Your devices" area:
    // the area auto-reveals before the scroll so the pointer lands on a
    // visible seat (the fire exception — a required action).
    try { SettledHouse.reveal('your-devices') } catch { /* the scroll still proceeds */ }
    const banner = $('beamPendingBanner')
    if (banner && !banner.hidden) {
      try { banner.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* best-effort */ }
    }
    if (beamPendingJoins.length) openBeamJoinDialog(beamPendingJoins[0])
  })
  // The joiner stage controls.
  $('beamJoinCancelBtn')?.addEventListener('click', async () => {
    stopBeamJoinPoll()
    beamRtc.cancelFlag = true
    await beamRtcCleanup()
    await bgSend('TRANSFER_BEAM_JOIN_CLEAR', {}).catch(() => {})
    $('beamJoinPhase').textContent = getMessage('beamJoinPhaseStopped', undefined, 'Stopped — you can retry any time.')
    $('beamJoinResult').className = 'sync-test-result warn'
    $('beamJoinResult').textContent = getMessage('beamJoinStoppedNote', undefined, 'The beam wait was stopped. The other device was not changed; the request simply expires.')
  })
  $('beamJoinManualCopyBtn')?.addEventListener('click', async (e) => {
    const b64 = e.target.dataset.signal || ''
    if (!b64) return
    try { await navigator.clipboard.writeText(b64); toast(getMessage('beamJoinManualCopied', undefined, 'Join signal copied — paste it in Manual signaling on the other device.')) }
    catch { toast(getMessage('beamJoinManualCopyFail', undefined, 'Clipboard unavailable — select and copy the staged signal on the transfer page.'), 'error') }
  })
  $('beamJoinCloudBtn')?.addEventListener('click', () => {
    // The named next step (S8.7): land on the transport grid.
    try { switchTab('sync'); $('transportGrid')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* best-effort */ }
  })
  // ── S8.8 — the zero-transport beam wiring ──
  // The origin: paste the joiner's hand-carried join signal.
  // R132 (law 0.47 — the owner's-eye sweep CLOSED the gap): the paste is
  // classified the moment it lands — the right code confirms, a wrong code
  // names its home. A JOIN record is the CORRECT code on this box.
  $('beamManualJoinSignal')?.addEventListener('input', () => {
    const el = $('beamManualJoinSignal'); const out = $('beamManualJoinResult')
    if (!el || !out) return
    const t = String(el.value || '').trim()
    if (!t) { out.textContent = ''; out.className = 'sync-test-result'; return }
    const c = classifyPastedSignal(t)
    const ok = c.cls === PASTE_CLASSES.JOIN
    out.className = ok ? 'sync-test-result ok' : 'sync-test-result warn'
    out.textContent = getMessage(ok ? 'pasteGuideJoinOk' : c.guidanceKey, undefined,
      ok ? 'This is a join request — press \u201COpen join signal\u201D to open the accept dialog.' : c.guidanceFallback)
  })
  $('beamManualJoinGo')?.addEventListener('click', async () => {
    const el = $('beamManualJoinResult')
    const signal = ($('beamManualJoinSignal')?.value || '').trim()
    if (!signal) return
    try {
      const r = await bgSend('TRANSFER_OPEN_MANUAL', { signal })
      if (r && r.ok && r.kind === 'join') {
        el.className = 'sync-test-result ok'
        el.textContent = getMessage('beamManualJoinOk', [r.join.label || getMessage('beamUnknownDevice', undefined, 'a device')], `✓ Join signal opened — $1 now appears in the join dialog.`)
        openBeamJoinDialog(r.join)
      } else {
        el.className = 'sync-test-result err'
        el.textContent = '✗ ' + ((r && (r.detail || r.error || r.userMessageKey)) || getMessage('beamManualJoinBad', undefined, 'This signal is not a valid join signal — copy it again on the joining device.'))
      }
    } catch (e) {
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + (e && e.message)
    }
  })
  // The origin: copy the staged offer signal.
  $('beamManualOfferCopy')?.addEventListener('click', async () => {
    const v = $('beamManualOfferSignal')?.value || ''
    try { await navigator.clipboard.writeText(v); toast(getMessage('beamManualOfferCopied', undefined, 'Offer signal copied — paste it in Manual signaling on the joining device.')) }
    catch { toast(getMessage('beamJoinManualCopyFail', undefined, 'Clipboard unavailable — select and copy the signal text directly.'), 'error') }
  })
  // The origin: paste the joiner's hand-carried answer.
  // R132 (law 0.47): an ANSWER record is the CORRECT code on this box —
  // every other paste names its home (never a silent dead end).
  $('beamManualAnswerSignal')?.addEventListener('input', () => {
    const el = $('beamManualAnswerSignal')
    if (!el) return
    const t = String(el.value || '').trim()
    if (!t) return
    const c = classifyPastedSignal(t)
    if (c.cls === PASTE_CLASSES.ANSWER) {
      toast(getMessage('pasteGuideAnswerOk', undefined, 'This is the joining device\u2019s reply — press \u201COpen answer signal\u201D.'), 'info')
    } else if (c.cls !== PASTE_CLASSES.EMPTY) {
      toast(getMessage(c.guidanceKey, undefined, c.guidanceFallback), 'error')
    }
  })
  $('beamManualAnswerGo')?.addEventListener('click', async () => {
    const signal = ($('beamManualAnswerSignal')?.value || '').trim()
    if (!signal) return
    const r = await bgSend('TRANSFER_OPEN_MANUAL', { signal })
    if (r && r.ok && r.kind === 'answer') {
      beamManualAnswer = { record: r.answer && r.answer.record, sdp: r.answer && r.answer.sdp }
      toast(getMessage('beamManualAnswerOk', undefined, 'Answer signal accepted — the direct channel is being negotiated.'))
      const row = $('beamManualAnswerRow')
      if (row) { row.classList.add('hidden'); row.hidden = true }
    } else {
      toast(getMessage('beamManualAnswerBad', undefined, 'This signal is not a valid answer signal — copy it again on the joining device.'), 'error')
    }
  })
  // The joiner: paste the origin's hand-carried availability signal.
  // R132 (law 0.47): a PRESENCE record is the CORRECT code on this box.
  $('beamJoinManualPresenceSignal')?.addEventListener('input', () => {
    const el = $('beamJoinManualPresenceSignal')
    if (!el) return
    const t = String(el.value || '').trim()
    if (!t) return
    const c = classifyPastedSignal(t)
    if (c.cls === PASTE_CLASSES.PRESENCE) {
      toast(getMessage('pasteGuidePresenceOk', undefined, 'This is their signal — press \u201COpen\u201D to learn the origin device.'), 'info')
    } else if (c.cls !== PASTE_CLASSES.EMPTY) {
      toast(getMessage(c.guidanceKey, undefined, c.guidanceFallback), 'error')
    }
  })
  $('beamJoinManualPresenceGo')?.addEventListener('click', async () => {
    const signal = ($('beamJoinManualPresenceSignal')?.value || '').trim()
    if (!signal) return
    const r = await bgSend('TRANSFER_BEAM_JOIN_START', { manualPresenceB64: signal })
    if (r && r.ok) {
      const join = r.join || {}
      beamJoinJoinId = join.joinMessageId || ''
      $('beamJoinOriginLine').textContent = getMessage('beamJoinOriginLine', [join.origin && join.origin.label || getMessage('beamUnknownDevice', undefined, 'the other device')], 'Asking $1 to accept this device.')
      $('beamJoinFingerprint').textContent = join.myFingerprint || ''
      $('beamJoinManualCopyBtn').classList.toggle('hidden', !r.stagedManualB64)
      if (r.stagedManualB64) $('beamJoinManualCopyBtn').dataset.signal = r.stagedManualB64
      $('beamJoinPhase').textContent = join.published ? getMessage('beamJoinPhaseAwaiting', undefined, 'Waiting for the other device…') : getMessage('beamJoinPhaseManual', undefined, 'Waiting — deliver the join signal by hand first.')
      startBeamJoinPoll()
    } else {
      const el = $('beamJoinResult')
      el.className = 'sync-test-result err'
      el.textContent = '✗ ' + ((r && r.error) || getMessage('beamManualPresenceBad', undefined, 'This signal is not a valid availability signal — copy it again on the other device.'))
    }
  })
  // First render + the truthful live loop (status labels only — law 0.8
  // untouched: nothing interactive auto-dismisses).
  renderDeviceMgmt({ force: true })
  window.addEventListener('focus', () => { renderDeviceMgmt() })
  document.addEventListener('visibilitychange', () => { if (!document.hidden) renderDeviceMgmt() })
  // R123 §2.3 (law 0.36) — the 15s presence re-render is a BACKGROUND
  // render: while the roster edit-lock is active it refreshes everything
  // EXCEPT the roster rows (the edit's typing survives every cycle).
  setInterval(() => { if (!document.hidden) renderDeviceMgmt() }, 15000)
}

// ═══════════════════════════════════════════════════════════════════════════
// R112 §2 — DIRECT SHARE (D1–D10). The handshake is the product.
// The page hosts the whole session: the MV3 worker has no RTCPeerConnection
// (measured, R99), and the share needs NO vault, NO cloud, NO account —
// the separation law (0.27) makes that a feature, not a shortcut.
// Every terminal is typed and truthful (0.8/0.13/0.26): no interactive
// surface auto-dismisses; the doors wait for a human forever.
// ═══════════════════════════════════════════════════════════════════════════

const _dsSend = { session: null, timer: null, qrFrames: [], qrIdx: 0, files: [] }
const _dsRecv = { session: null, invite: null, replyText: '', file: null, received: [] }

/** R113 §2.2 — the D11 share ledger's render (render-by-state, 0.25): the
 * empty state names its missing precondition with the exact truth; rows are
 * frozen-shape entries from lib/share.js (no peer identity — there is none). */
async function dsRenderLedger() {
  const listEl = $('dsLedgerList')
  const emptyEl = $('dsLedgerEmpty')
  const capEl = $('dsLedgerCap')
  if (!listEl || !emptyEl) return
  let entries = []
  try { entries = await Share.shareLedgerList() } catch { entries = [] }
  dsShow(emptyEl, entries.length === 0)
  dsShow(listEl, entries.length > 0)
  if (capEl) dsShow(capEl, entries.length >= Share.SHARE_LEDGER_CAP)
  listEl.replaceChildren(...entries.map((e) => {
    const li = document.createElement('li')
    li.className = 'ds-ledger-row ds-ledger-row--clickable'
    // R124 §2 (D13) — the pickup's dirs render their own honest faces:
    // held (⏳ up, amber-ish) and pickedup (⬇, ok) join sent/received — the
    // same identity-free rows, the same frozen shape.
    const dirFace = {
      sent: { glyph: '\u2191', key: 'dsLedgerSent', cls: ' ds-dir-sent' },
      received: { glyph: '\u2193', key: 'dsLedgerReceived', cls: ' ds-dir-recv' },
      held: { glyph: '\u231b', key: 'dsLedgerHeld', cls: ' ds-dir-sent' },
      pickedup: { glyph: '\u2b07', key: 'dsLedgerPickedUp', cls: ' ds-dir-recv' },
    }[e.dir] || { glyph: '\u2191', key: 'dsLedgerSent', cls: ' ds-dir-sent' }
    const arrow = document.createElement('span')
    arrow.className = 'ds-ledger-dir' + dirFace.cls
    arrow.textContent = dirFace.glyph
    arrow.setAttribute('aria-label', getMessage(dirFace.key, undefined, dirFace.key === 'dsLedgerSent' ? 'Sent' : dirFace.key === 'dsLedgerReceived' ? 'Received' : dirFace.key === 'dsLedgerHeld' ? 'Held for pickup' : 'Picked up'))
    const name = document.createElement('span')
    name.className = 'ds-ledger-name'
    name.textContent = e.name
    name.title = e.name
    const meta = document.createElement('span')
    meta.className = 'ds-ledger-meta'
    meta.textContent = `${dsFmtSize(e.size)} \u00b7 ${dsLedgerWhen(e.at)}`
    li.replaceChildren(arrow, name, meta)
    // R117 §3.2 (law 0.30) — THE LEDGER ROW OPENS ITS DETAILS: a click on a
    // row reveals the file's details inline (name, size, time, direction —
    // the four lawful fields). The DIGEST is deliberately NOT here: the
    // ledger's frozen shape {name,size,at,dir} is the identity-free
    // guarantee (law 0.27's privacy face) — a persisted content fingerprint
    // would be a record beyond what D11 promises. The details carry the
    // full timestamp, which the meta line abbreviates.
    const details = document.createElement('p')
    details.className = 'ds-ledger-details hidden'
    details.setAttribute('aria-live', 'polite')
    const whenFull = (() => { try { return new Date(Number(e.at)).toLocaleString() } catch { return String(e.at) } })()
    details.textContent = getMessage('dsLedgerDetails', [getMessage(dirFace.key, undefined, 'Shared'), dsFmtSize(e.size), whenFull], '$1$ · $2$ · $3$ (local time)')
    li.appendChild(details)
    li.setAttribute('role', 'button')
    li.tabIndex = 0
    li.setAttribute('aria-expanded', 'false')
    li.setAttribute('aria-label', getMessage('dsLedgerRowAria', [e.name], `Details of ${e.name}`))
    const toggle = () => {
      const open = details.classList.toggle('hidden') === false
      li.setAttribute('aria-expanded', open ? 'true' : 'false')
    }
    li.addEventListener('click', toggle)
    li.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle() } })
    return li
  }))
}

function dsLedgerWhen(at) {
  try {
    const d = new Date(Number(at))
    const today = new Date(); today.setHours(0, 0, 0, 0)
    return d >= today
      ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  } catch { return '' }
}

/** The share engine's breadcrumbs (stage names only — never a value, never a
 * key; the 0.10 harness lesson: a silent async leg must be observable). */
function dsTrace(m) {
  try { (window.__dsTrace = window.__dsTrace || []).push(String(m).slice(0, 80)) } catch { /* noop */ }
}

function dsFmtSize(n) {
  const b = Number(n) || 0
  if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB'
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB'
  return b + ' B'
}

function dsShow(el, on) {
  if (!el) return
  el.classList.toggle('hidden', !on)
  el.hidden = !on
}

function dsSendStatus(text) {
  const el = $('dsSendStatus')
  if (el) { el.textContent = text || ''; dsShow(el, !!text) }
}

function dsRecvStatus(text) {
  const el = $('dsRecvStatus')
  if (el) { el.textContent = text || ''; dsShow(el, !!text) }
}

/** The sender's typed terminal: every button state reset, the session dead.
 * R113 §2.1/§2.4 — the expired terminal gains the ONE-CLICK "Generate a new
 * code" (the invitation regenerates fresh; the old code stays dead — the
 * replay-proof is the TTL itself); the shared terminal gains "Share another"
 * under the fresh-session law (new keys, new words, zero state reuse). */
function dsSenderTerminal(kind, detail) {
  // F-R113-DS-TERMRACE-1 (0.26): THE FIRST CAUSE WINS — the teardown's own
  // close re-enters here; the latch keeps the first typed cause until the next mint.
  if (_dsSend.terminalized) return
  _dsSend.terminalized = true
  // The done-file facts are captured BEFORE the session dies — the D11 ledger
  // needs name+size, and after destroyKeys nothing readable remains.
  // D12: every file of a completed batch gets its own ledger line.
  const doneFiles = (_dsSend.session && Array.isArray(_dsSend.session.files)
    ? _dsSend.session.files
    : (_dsSend.session && _dsSend.session.file ? [{ file: _dsSend.session.file }] : [])
  ).filter((f) => f && f.file).map((f) => ({ name: f.file.name, size: f.file.size }))
  if (_dsSend.timer) { clearInterval(_dsSend.timer); _dsSend.timer = null }
  // R124 §2 (D13) — the offer retires at the terminal; a LIVE hold outlives
  // the invitation on purpose (the held box carries it truthfully).
  dsShow($('dsHoldOffer'), false)
  if (_dsSend.session) { Share.destroyKeys(_dsSend.session) }
  try { _dsSend.session && _dsSend.session.pc && _dsSend.session.pc.close() } catch { /* already closed */ }
  try { _dsSend.session && _dsSend.session.channel && _dsSend.session.channel.close() } catch { /* already closed */ }
  _dsSend.session = null
  _dsSend.qrFrames = []
  _dsSend.qrIdx = 0
  dsShow($('dsQrBox'), false)
  const cd = $('dsCountdown')
  if (cd) cd.classList.remove('ds-urgent')
  const lines = {
    expired: getMessage('dsExpired', undefined, 'Request expired — no reply or declined.'),
    cancelled: getMessage('dsCancelled', undefined, 'Invitation cancelled — nothing was shared.'),
    shared: getMessage('dsSharedDone', undefined, 'Sent. The ephemeral keys are destroyed — nothing remains to prove what moved.'),
    interrupted: getMessage('dsInterrupted', undefined, 'Interrupted — the vault was locked, so the share was stopped and the keys destroyed.'),
    failed: getMessage('dsFailed', undefined, 'The connection failed before the file could move.'),
    tampered: getMessage('dsTampered', undefined, 'The invitation or the reply was modified — the connection was refused before any file moved.'),
  }
  dsSendStatus(lines[kind] || detail || lines.failed)
  // The card returns to its idle row: pick again is one click.
  dsShow($('dsCancelBtn'), false)
  dsShow($('dsReplyBox'), false)
  dsShow($('dsMakeBtn'), false)
  dsShow($('dsPickBtn'), true)
  // R113 §2.1/§2.4 — the maturity buttons (each terminal names its next step).
  const again = $('dsAgainBtn')
  if (again) {
    const show = (kind === 'expired' || kind === 'shared')
    dsShow(again, show)
    if (show) again.textContent = kind === 'expired'
      ? getMessage('dsAgainNewCode', undefined, 'Generate a new code')
      : getMessage('dsShareAnother', undefined, 'Share another')
    again.setAttribute('aria-label', again.textContent)
    again.dataset.dsAgain = kind // the engine reads the terminal that raised it
  }
  if (kind === 'expired' || kind === 'cancelled' || kind === 'interrupted') {
    dsShow($('dsInviteBox'), false)
  }
  if (kind === 'shared' && doneFiles.length) {
    // D11 — the ONE history a share keeps: local-only, capped, identity-free.
    // D12: a batch appends ONE line PER FILE (the frozen shape is unchanged).
    Promise.all(doneFiles.map((f) => Share.shareLedgerAppend({ dir: 'sent', name: f.name, size: f.size, at: Date.now() })))
      .then(() => dsRenderLedger()).catch(() => { /* the ledger never blocks the terminal */ })
  }
  if (kind === 'shared' || kind === 'cancelled') {
    // The fresh-session law: zero state reuse — the next share starts clean.
    _dsSend.files = []
    dsShow($('dsInviteBox'), false)
    dsShow($('dsFileInfo'), false)
    dsShow($('dsNoteGroup'), false)
    dsShow($('dsLabelGroup'), false)
    // Zero stale codes: the dead invitation and its input slot never outlive
    // their session (a stale paste can never stand in for a fresh handshake).
    try { $('dsInviteText').value = '' } catch { /* noop */ }
    try { $('dsReplyInput').value = '' } catch { /* noop */ }
    try { $('dsFileInput').value = '' } catch { /* noop */ }
  }
}

/** The receiver's typed terminal. */
function dsReceiverTerminal(kind, detail) {
  // F-R113-DS-TERMRACE-1 — THE FIRST CAUSE WINS (0.26): the receiver's own
  // teardown re-enters through the channel's close event; the latch keeps
  // the first typed cause (the detail override rides the FIRST call only).
  if (_dsRecv.terminalized) return
  _dsRecv.terminalized = true
  if (_dsRecv.session) { Share.destroyKeys(_dsRecv.session) }
  try { _dsRecv.session && _dsRecv.session.pc && _dsRecv.session.pc.close() } catch { /* already closed */ }
  try { _dsRecv.session && _dsRecv.session.channel && _dsRecv.session.channel.close() } catch { /* already closed */ }
  _dsRecv.session = null
  _dsRecv.file = null
  _dsRecv.invite = null // the queue re-opens: one at a time, and this one is done
  // R113 — zero stale state: the reply box's old code never outlives its
  // session (a stale code pasted by a harness or a half-click can never
  // stand in for a fresh handshake).
  try { $('dsReplyText').value = '' } catch { /* noop */ }
  const lines = {
    declined: getMessage('dsDeclined', undefined, 'Declined — nothing was received and nothing was sent.'),
    received: getMessage('dsSavedReady', undefined, 'Received — save it to keep it. The ephemeral keys are destroyed.'),
    failed: getMessage('dsRecvFailed', undefined, 'The share ended before the file arrived — nothing was saved.'),
    tampered: getMessage('dsSafetyMismatch', undefined, 'The safety words did not match — the reply code was modified or corrupted. Nothing was received.'),
    replayed: getMessage('dsReplay', undefined, 'This invitation was already used — share codes work exactly once.'),
    rate: getMessage('dsRateLimited', undefined, 'Too many accepts in a short time — wait a few minutes and ask again.'),
  }
  // R113 fix (F-R113-DS-LOCKCOPY-1): an explicit detail OVERRIDES the kind's
  // default line — the lock terminal must say "Interrupted — the vault was
  // locked…", never the generic "the share ended" copy.
  dsRecvStatus(detail || lines[kind] || lines.failed)
  dsShow($('dsDoor1'), false)
  dsShow($('dsDoor2'), false)
  dsShow($('dsReplyOut'), false)
}

/** Wire once at init. */
function wireDirectShare() {
  dsTrace('wired:begin')
  // ── SENDER ──
  $('dsPickBtn')?.addEventListener('click', () => $('dsFileInput')?.click())
  $('dsFileInput')?.addEventListener('change', async () => {
    const picked = Array.from(($('dsFileInput').files) || [])
    if (!picked.length) return
    dsSendStatus('')
    // D12 — the batch bounds fire TYPED before anything is created (0.13):
    // the 5-file cap, the per-file 20 MB cap, the 50 MB session total.
    const v = Share.validateBatch(picked)
    if (!v.ok) {
      const map = {
        too_many: getMessage('dsBatchTooMany', [String(v.have), String(v.max)], 'You picked $1 files — Direct Share carries up to $2 at once. Remove some and try again.'),
        file_too_big: getMessage('dsBatchFileTooBig', [(v.name || '').slice(0, 60)], '“$1” is over the 20 MB per-file limit — remove it and try again.'),
        session_too_big: getMessage('dsBatchTotalTooBig', [dsFmtSize(v.total)], 'The files total $1 — a share carries at most 50 MB in one go. Remove something and try again.'),
      }
      dsSendStatus(map[v.code] || getMessage('dsBatchTooMany', [String(v.have || '?'), String(v.max || 5)], 'You picked $1 files — Direct Share carries up to $2 at once. Remove some and try again.'))
      _dsSend.files = []
      dsShow($('dsMakeBtn'), false)
      return
    }
    _dsSend.files = picked.map((f) => ({ file: f }))
    const info = $('dsFileInfo')
    if (picked.length === 1) {
      info.textContent = getMessage('dsFileChosen', [picked[0].name, dsFmtSize(picked[0].size)], 'Selected: $1 ($2)')
    } else {
      info.textContent = getMessage('dsFilesChosen', [String(picked.length), dsFmtSize(v.total)], 'Selected $1 files ($2 total)')
    }
    dsShow(info, true)
    dsShow($('dsMakeBtn'), true)
    dsShow($('dsNoteGroup'), true)
    dsShow($('dsLabelGroup'), true)
  })
  $('dsMakeBtn')?.addEventListener('click', () => { dsCreateInvitation().catch((e) => dsSendStatus(String(e && e.message || e))) })
  $('dsCancelBtn')?.addEventListener('click', () => dsSenderTerminal('cancelled'))
  // R113 §2.1/§2.4 — "Generate a new code" (after expiry: the SAME file, a
  // FRESH invitation — new keys, new words, a new sid; the old code is dead
  // by the TTL) and "Share another" (after Done: the fresh-session law — the
  // file is cleared, zero state reuse; the pick is one click).
  $('dsAgainBtn')?.addEventListener('click', () => {
    const kind = $('dsAgainBtn')?.dataset.dsAgain
    if (kind === 'expired' && _dsSend.files.length) {
      dsShow($('dsAgainBtn'), false)
      dsCreateInvitation().catch((e) => dsSendStatus(String(e && e.message || e)))
    } else {
      // 'shared' (or no file): the fresh-session idle — pick a file again.
      dsShow($('dsAgainBtn'), false)
      dsSendStatus('')
    }
  })
  $('dsCopyBtn')?.addEventListener('click', async () => {
    const t = $('dsInviteText').value || ''
    try { await navigator.clipboard.writeText(t) } catch {
      $('dsInviteText').select(); document.execCommand('copy')
    }
    toast(getMessage('dsCopiedToast', undefined, 'Invitation copied — paste it in any messenger.'), 'ok')
  })
  $('dsConnectBtn')?.addEventListener('click', () => { dsConnectReply().catch((e) => dsSendStatus(String(e && e.message || e))) })
  // R132 (law 0.47 — THE PASTE-GUIDANCE LAW; the CEO's S2): the classifier
  // rides the Direct Share inputs — the reply box (sender side) and the
  // invitation box (receiver side) type every paste the moment it lands:
  // the right code in the right box CONFIRMS; the right code in the wrong
  // box names its home; a non-code says what IS valid.
  $('dsReplyInput')?.addEventListener('input', () => {
    const el = $('dsReplyInput'); const guide = $('dsReplyGuide')
    if (!el || !guide) return
    const t = String(el.value || '').trim()
    if (!t) { guide.textContent = ''; guide.classList.add('hidden'); return }
    const c = refineForShareBox(classifyPastedSignal(t), { box: 'reply' })
    guide.textContent = getMessage(c.guidanceKey, undefined, c.guidanceFallback)
    guide.classList.remove('hidden')
  })
  $('dsPasteInvite')?.addEventListener('input', () => {
    const el = $('dsPasteInvite'); const guide = $('dsPasteGuide')
    if (!el || !guide) return
    const t = String(el.value || '').trim()
    if (!t) { guide.textContent = ''; guide.classList.add('hidden'); return }
    const c = refineForShareBox(classifyPastedSignal(t), { box: 'invitation' })
    guide.textContent = getMessage(c.guidanceKey, undefined, c.guidanceFallback)
    guide.classList.remove('hidden')
  })
  $('dsQrBtn')?.addEventListener('click', () => { dsShowQrFrame(0) })
  $('dsQrPrev')?.addEventListener('click', () => dsShowQrFrame(_dsSend.qrIdx - 1))
  $('dsQrNext')?.addEventListener('click', () => dsShowQrFrame(_dsSend.qrIdx + 1))
  $('dsQrClose')?.addEventListener('click', () => dsShow($('dsQrBox'), false))

  // ── R124 §2 (D13) — THE ASYNC PICKUP's wiring (the offer, the layer, the
  // held box, the door). Every listener is user-action-only (0.8: nothing
  // here auto-dismisses anything) and the layer's Esc/✕ close is honest.
  $('dsHoldOffer')?.addEventListener('click', () => { pickupOpenLayer().catch((e) => dsSendStatus(String(e && e.message || e))) })
  $('pickupLayerClose')?.addEventListener('click', () => pickupCloseLayer())
  $('pickupHoldBtn')?.addEventListener('click', () => { pickupDoHold().catch((e) => dsSendStatus(String(e && e.message || e))) })
  $('pickupNoticeCopy')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('pickupNoticeText').value || '') } catch {
      $('pickupNoticeText').select(); document.execCommand('copy')
    }
    toast(getMessage('pickupNoticeCopiedToast', undefined, 'Notice copied — send it in the same messenger.'), 'ok')
  })
  $('pickupCancelBtn')?.addEventListener('click', () => { pickupSweepHold('cancelled').catch(() => {}) })
  $('pickupDoorSave')?.addEventListener('click', () => { dsPickupDoorSave().catch((e) => dsRecvStatus(String(e && e.message || e))) })
  $('pickupDoorDiscard')?.addEventListener('click', () => dsPickupDoorDiscard())
  // The reload/heal path: a persisted hold re-renders truthfully (an expired
  // one is swept with its typed terminal — law 0.37, no silent stall).
  pickupRestoreHolds().catch(() => { /* the empty state is the honest default */ })

  // ── RECEIVER ──
  $('dsPasteBtn')?.addEventListener('click', () => { dsAcceptInvitation().catch((e) => dsRecvStatus(String(e && e.message || e))) })
  $('dsScanBtn')?.addEventListener('click', () => $('dsScanInput')?.click())
  $('dsScanInput')?.addEventListener('change', async () => {
    const f = $('dsScanInput').files && $('dsScanInput').files[0]
    if (!f) return
    try {
      const r = await globalThis.UCryptQrScan.decodeFromBlob(f)
      if (!r || !r.ok) {
        dsRecvStatus(getMessage('dsScanUnreadable', undefined, 'That image has no readable QR — ask for the invitation text instead.'))
        return
      }
      $('dsPasteInvite').value = r.text
      dsAcceptInvitation().catch((e) => dsRecvStatus(String(e && e.message || e)))
    } catch {
      dsRecvStatus(getMessage('dsScanUnreadable', undefined, 'That image has no readable QR — ask for the invitation text instead.'))
    }
  })
  $('dsDoor1Accept')?.addEventListener('click', () => { dsDoor1Accept().catch((e) => dsRecvStatus(String(e && e.message || e))) })
  $('dsDoor1Decline')?.addEventListener('click', () => dsDoorDecline())
  $('dsDoor2Decline')?.addEventListener('click', () => dsDoorDecline())
  $('dsDoor2Accept')?.addEventListener('click', () => { dsDoor2Accept().catch((e) => dsRecvStatus(String(e && e.message || e))) })
  $('dsReplyCopyBtn')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('dsReplyText').value || '') } catch {
      $('dsReplyText').select(); document.execCommand('copy')
    }
    toast(getMessage('dsReplyCopiedToast', undefined, 'Reply copied — send it back in the same messenger.'), 'ok')
  })
  $('dsSaveBtn')?.addEventListener('click', () => dsSaveReceived())
  // §2.3 — THE SHARE BACK (D12 polish): one click from the receiver's done
  // view to the sender card — the friendship flows both ways. The queue law
  // holds: a share in progress is named, never silently replaced.
  $('dsShareBackBtn')?.addEventListener('click', () => {
    if (_dsSend.session) {
      dsRecvStatus(getMessage('dsQueueBusy', undefined, 'A share is already in progress — finish or decline it first; shares go one at a time.'))
      return
    }
    const card = $('dsShareCard')
    if (card && card.scrollIntoView) card.scrollIntoView({ behavior: 'smooth', block: 'start' })
    const pick = $('dsPickBtn')
    if (pick) { try { pick.focus({ preventScroll: true }) } catch { /* focus is best-effort */ } }
    dsRecvStatus(getMessage('dsShareBackHint', undefined, 'Pick a file on the sender card above — the code works the same way in reverse.'))
  })
  // D9 — the lock kills the session keys (typed interrupted), both sides.
  window.addEventListener('ucrypt:vault-locked', () => {
    if (_dsSend.session) dsSenderTerminal('interrupted')
    if (_dsRecv.session) dsReceiverTerminal('failed', getMessage('dsInterrupted', undefined, 'Interrupted — the vault was locked, so the share was stopped and the keys destroyed.'))
  })
  // D11 — the ledger renders at init (render-by-state) and after every append.
  dsRenderLedger().catch(() => { /* the empty state is the honest default */ })
  dsTrace('wired:done')
}

/** SENDER leg 1 — the file(s) chosen; mint the invitation (D2). D12: up to
 * five files ride ONE invitation — one handshake, one session key. */
async function dsCreateInvitation() {
  if (!_dsSend.files.length) return
  // R113 §2.4 — ZERO STALE STATE at the mint (F-R113-DS-STALEINV-1): a dead
  // invitation's text must never linger looking live; the box clears BEFORE
  // the new code exists, so a failed mint leaves an EMPTY box, never a
  // resurrected dead code (0.25 render-by-state).
  try { $('dsInviteText').value = '' } catch { /* noop */ }
  dsShow($('dsInviteBox'), false)
  _dsSend.terminalized = false // a fresh session may speak its own terminal
  dsSendStatus(getMessage('dsMaking', undefined, 'Creating the invitation…'))
  // D12 — buffer EVERY file and digest it now (the digests ride the batch
  // descriptor; the bytes stay in this page's memory only — 0.27).
  const files = []
  for (const f of _dsSend.files) {
    const buf = new Uint8Array(await f.file.arrayBuffer())
    files.push({ file: f.file, buf, digest: await ShareSha256Hex(buf) })
  }
  // THE SEPARATION (0.27): nothing here touches the vault — the files, their
  // digests and the ephemeral keys live only in this page's memory.
  const eph = await Share.generateShareKeys() // THE session's ephemeral identity
  const transport = await Share.createOfferTransport() // the WebRTC offer + ICE
  const note = ($('dsNote')?.value || '').slice(0, Share.SHARE_NOTE_CAP)
  const inv = await Share.createInvitation({ sdp: { epk: eph.pubJwk, sdp: transport.sdp }, note })
  _dsSend.session = {
    role: 'sender', pc: transport.pc, channel: transport.channel,
    keys: eph, sessionKey: null, files,
    // single-file compat (the QR/terminal paths read file/buf/digest):
    file: files[0].file, buf: files[0].buf, digest: files[0].digest,
    sid: inv.sid, invitation: inv.invitation, shareCodeWords: inv.words,
    createdAt: inv.createdAt, expiresAt: inv.createdAt + Share.SHARE_TTL_MS,
    replyText: '', safetyWords: '', label: ($('dsLabel')?.value || '').slice(0, Share.SHARE_LABEL_CAP),
    dead: false,
  }
  $('dsInviteText').value = inv.invitation
  dsShow($('dsInviteBox'), true)
  dsShow($('dsMakeBtn'), false)
  dsShow($('dsQrBtn'), true)
  dsShow($('dsCancelBtn'), true)
  dsShow($('dsReplyBox'), true)
  $('dsWaitLine').textContent = getMessage('dsWaitReply', undefined, 'Waiting for the reply… paste this in a messenger, then paste THEIR reply below when it arrives.')
  dsSendStatus('')
  // The visible countdown (D2); expiry is a typed terminal; the pickup's
  // offer rides the same tick (D13: the offer appears ONLY near expiry).
  if (_dsSend.timer) clearInterval(_dsSend.timer)
  _dsSend.timer = setInterval(() => {
    const s = _dsSend.session
    if (!s) { clearInterval(_dsSend.timer); _dsSend.timer = null; return }
    const left = s.expiresAt - Date.now()
    if (left <= 0) {
      dsUpdateHoldOffer(0)
      dsSenderTerminal('expired')
      return
    }
    const m = Math.floor(left / 60000)
    const ss = String(Math.floor((left % 60000) / 1000)).padStart(2, '0')
    const cd = $('dsCountdown')
    if (cd) {
      cd.textContent = getMessage('dsCountdown', [String(m), ss], 'Expires in $1:$2')
      // R113 §2.4 — the last 60 seconds are highlighted (the typed urgency,
      // both themes): the receiver still has time, the sender sees it shrink.
      cd.classList.toggle('ds-urgent', left <= 60 * 1000)
    }
    // R124 §2 (D13) — THE OFFER'S WINDOW: the hold appears in the last 3
    // minutes (near expiry) — never cluttering the normal flow.
    dsUpdateHoldOffer(left)
  }, 500)
  // The QR frames (the in-person mode — chunked, capped, ordered).
  _dsSend.qrFrames = Share.qrChunksOf(inv.invitation)
  _dsSend.qrIdx = 0
  if (!_dsSend.qrFrames.length) {
    // The typed dead end (0.13): the QR path is unavailable for THIS string —
    // the pasteable invitation always works.
    toast(getMessage('dsQrTooBig', undefined, 'The QR mode cannot carry this invitation — use the messenger paste instead.'), 'info')
  }
}

/** SENDER leg 2 — the reply arrives; bind, derive, send. (D3/D4/D5) */
async function dsConnectReply() {
  const s = _dsSend.session
  if (!s || s.dead) {
    // R113 §2.4 — a reply to a cancelled/expired invitation is TYPED, never
    // silent: the honest dead end names the fix (0.26).
    dsSendStatus(getMessage('dsErrNoSession', undefined, 'There is no active invitation — the code was cancelled or expired. Pick the file and generate a new code.'))
    return
  }
  const pasted = ($('dsReplyInput')?.value || '').trim()
  if (!pasted) return
  const parsed = await Share.parseReply(pasted, s.sid)
  if (!parsed.ok) {
    const map = {
      not_reply: getMessage('dsErrNotReply', undefined, 'That is not a Direct Share reply — copy the code that starts with UCRYPT-SHARE1R:.'),
      foreign: getMessage('dsErrForeign', undefined, 'That reply belongs to a different invitation.'),
      malformed: getMessage('dsErrMalformed', undefined, 'The reply is damaged — have it copied again.'),
      version: getMessage('dsErrVersion', undefined, 'That reply uses a different Direct Share version — update UCrypt on both sides.'),
    }
    dsSendStatus(map[parsed.code] || getMessage('dsErrMalformed', undefined, 'The reply is damaged — have it copied again.'))
    return
  }
  s.replyText = pasted
  dsSendStatus(getMessage('dsConnecting', undefined, 'Connecting…'))
  try {
    await Share.acceptAnswer(s.pc, parsed.sdp)
    // THE SAFETY WORDS (D8) — over the full transcript.
    s.safetyWords = await Share.deriveSafetyWords(s.invitation, pasted)
    // THE NINTH KEY (D4).
    s.sessionKey = await Share.deriveSessionKey(s.keys.privJwk, parsed.epk, s.shareCodeWords.join('-'))
  } catch (e) {
    dsSenderTerminal('tampered')
    return
  }
  // The channel must open within the window (typed failure otherwise).
  const opened = await new Promise((resolve) => {
    const ch = s.channel
    if (ch.readyState === 'open') return resolve(true)
    const t = setTimeout(() => resolve(false), 30000)
    ch.onopen = () => { clearTimeout(t); resolve(true) }
    ch.onerror = () => { clearTimeout(t); resolve(false) }
    s.pc.onconnectionstatechange = () => {
      if (s.pc.connectionState === 'failed' || s.pc.connectionState === 'disconnected' || s.pc.connectionState === 'closed') {
        clearTimeout(t); resolve(false)
      }
    }
  })
  if (!opened || s.channel.readyState !== 'open') {
    // R113 §2.3 — THE ICE-FAILURE RETRY LADDER (D9); R114 §2.2 — the ladder
    // HARDENED (the soak's ~7% first-attempt miss under maximum churn): a
    // SECOND tier now re-runs the restart after a FRESH candidate-gathering
    // window — tier 1 re-arms checks on the exchanged candidates; tier 2
    // gives the gather state machine a real second chance to surface a late
    // host/srflx pair before ANY typed dead end. No new keys, no new code at
    // either tier (the session identity is the handshake — only the wire
    // struggles). The typed guidance stays the honest fallback, naming both
    // escape hatches (the same network / the QRs).
    dsSendStatus(getMessage('dsIceRetry', undefined, 'The direct connection is struggling — trying one restart…'))
    const waitOpen = (ms) => new Promise((resolve) => {
      try { s.pc.restartIce() } catch { resolve(false); return }
      const ch = s.channel
      if (ch.readyState === 'open') return resolve(true)
      const t = setTimeout(() => resolve(ch.readyState === 'open'), ms)
      ch.onopen = () => { clearTimeout(t); resolve(true) }
    })
    const tier1 = await waitOpen(8000)
    let tier2 = tier1
    if (!tier1) {
      dsSendStatus(getMessage('dsIceRetry2', undefined, 'Still struggling — trying once more with fresh candidates…'))
      // The fresh-candidate tier: re-arm restart AND wait a fresh gather
      // cycle (the gather usually completes in ~100 ms; 10 s is the ceiling).
      try { await new Promise((r) => setTimeout(r, 250)) } catch { /* noop */ }
      tier2 = await waitOpen(10000)
    }
    if (!tier2 || s.channel.readyState !== 'open') {
      dsSenderTerminal('failed', getMessage('dsHolePunchFail', undefined, 'The devices could not connect directly. Try the same network — or in person with the QRs (an ICE restart helps too).'))
      return
    }
  }
  await dsSendDescriptor()
}

/** SENDER leg 3 — the sealed descriptor, the Door-2 accept wait, the stream.
 * D12: the descriptor is the BATCH (one file = a batch of 1); the frames cross
 * SEQUENTIALLY file by file; every chunk's AAD binds (fileIndex, per-file
 * totals, per-file digest) and its nonce is uint64be(fileIndex·2³² + chunk) —
 * (key, nonce) never repeats across the whole session. */
async function dsSendDescriptor() {
  const s = _dsSend.session
  const ch = s.channel
  const np = s.sessionKey.noncePrefix
  // The control frames (descriptor / accept / done) seal under the SAME key
  // with a NEGATIVE chunk index — their own AAD domain, no chunk can collide.
  const ctrlMeta = (idx) => ({ shareId: s.sid, chunkIndex: idx, totalChunks: 0, totalBytes: 0, digest: '', noncePrefix: np })
  // D12 — ONE batch descriptor carries EVERY file (name, size, digest, the
  // honest total, the per-file high-risk flag). A single file is a batch of 1.
  const batch = Share.buildBatchDescriptor({
    label: s.label,
    files: s.files.map((f) => ({
      name: f.file.name,
      size: f.buf.length,
      digest: f.digest,
      highRisk: Share.executableOrArchiveWarning(f.file.name),
    })),
  })
  try {
    ch.send(JSON.stringify(await Share.sealShareFrame(s.sessionKey.key, ctrlMeta(-1), new TextEncoder().encode(JSON.stringify(batch)))))
  } catch { dsSenderTerminal('failed'); return }
  // D8 — the safety words ride the sender's progress view too (both screens
  // show the same four words; the voice check works in person).
  dsSendStatus(getMessage('dsWaitDoor2', undefined, 'Connected. Waiting for the receiver to accept the file…') + ' ' + getMessage('dsSafetyWords', [s.safetyWords], 'Safety words: $1'))
  // Wait for the SEALED accept frame (a decline is SILENT — a close is the
  // only signal, and it is honestly ambiguous: expired-or-declined, D7).
  let accepted = false
  await new Promise((resolve) => {
    const to = setTimeout(() => { if (!accepted) { dsSenderTerminal('expired'); resolve(false) } }, Share.SHARE_TTL_MS)
    ch.onclose = () => { clearTimeout(to); if (!accepted) { dsSenderTerminal('expired'); resolve(false) } }
    ch.onerror = () => { clearTimeout(to); if (!accepted) { dsSenderTerminal('failed'); resolve(false) } }
    ch.onmessage = async (ev) => {
      try {
        const frame = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        const plain = await Share.openShareFrame(s.sessionKey.key, ctrlMeta(-1), frame)
        const msg = JSON.parse(new TextDecoder().decode(plain))
        if (msg.kind === 'accept') { accepted = true; clearTimeout(to); resolve(true) }
      } catch {
        // A frame we cannot open: the session key differs (a tampered reply)
        // — the typed refusal, before any file byte moves (D8's automated half).
        clearTimeout(to)
        dsSenderTerminal('tampered')
        resolve(false)
      }
    }
  }).catch(() => false)
  if (!accepted) return
  // D12 — the SEQUENTIAL batch stream: file by file, in descriptor order.
  // The global ack window rides the GLOBAL chunk counter (file i's chunk j is
  // counter i·2³²+j); every file's FINAL chunk always awaits its ack (the
  // F-R113-DS-ACKTAIL-1 law, per file now).
  const batchTotalBytes = batch.total || s.files.reduce((a, f) => a + f.buf.length, 0)
  let sentBytes = 0
  for (let fi = 0; fi < s.files.length; fi++) {
    const f = s.files[fi]
    const base = fi * 4294967296 // the nonce/seq counter space of file fi
    const meta = { shareId: s.sid, fileIndex: fi, totalChunks: Share.chunkCountFor(f.buf.length), totalBytes: f.buf.length, digest: f.digest, noncePrefix: np }
    const total = meta.totalChunks
    for (let i = 0; i < total; i++) {
      if (s.dead || ch.readyState !== 'open') { dsSenderTerminal('failed'); return }
      const plain = f.buf.subarray(i * Share.CHUNK_SIZE, Math.min((i + 1) * Share.CHUNK_SIZE, f.buf.length))
      const frame = await Share.sealShareFrame(s.sessionKey.key, { ...meta, chunkIndex: base + i }, plain)
      ch.send(JSON.stringify(frame))
      sentBytes += plain.length
      // R113 §2.5 (the soak's finding, F-R113-DS-ACKTAIL-1): the FINAL window
      // is ALWAYS awaited — a partial tail (e.g. a one-chunk file) can never be
      // blasted unacked into an imminent close (SCTP drops the tail). D12: the
      // rule is PER FILE — every file's last chunk waits, windows slide between.
      if ((i + 1) % Share.SHARE_ACK_WINDOW === 0 || (i + 1) === total) {
        const got = await new Promise((resolve) => {
          const to = setTimeout(() => resolve(false), 30000)
          ch.onmessage = (ev) => {
            try {
              const f = JSON.parse(ev.data)
              if (f.kind === 'ack') { clearTimeout(to); resolve(true) }
            } catch { clearTimeout(to); resolve(false) }
          }
        })
        if (!got) { dsSenderTerminal('failed'); return }
        const pct = batchTotalBytes ? Math.round((sentBytes / batchTotalBytes) * 100) : 100
        dsSendStatus(getMessage('dsSafetyWords', [s.safetyWords], 'Safety words: $1') + ' — ' + getMessage('dsSendingPct', [String(pct)], 'Sending… $1%'))
      }
    }
  }
  // The done frame (sealed; the receiver's per-file digest gates are the last word).
  try {
    ch.send(JSON.stringify(await Share.sealShareFrame(s.sessionKey.key, ctrlMeta(-2), new TextEncoder().encode(JSON.stringify({ kind: 'done' })))))
  } catch { /* the receiver's digest gates are the last word anyway */ }
  // R113 §2.5 — the graceful tail: a short grace lets the done frame flush
  // before the terminal's channel.close() (the digest gate stays the last
  // word either way; the grace only stops the close from racing the wire).
  await new Promise((r) => setTimeout(r, 250))
  dsSenderTerminal('shared')
}

/** The in-person QR: the invitation in ≤8 ordered frames (each a scannable QR). */
function dsShowQrFrame(idx) {
  const frames = _dsSend.qrFrames || []
  if (!frames.length) return
  _dsSend.qrIdx = Math.max(0, Math.min(frames.length - 1, idx))
  const frame = frames[_dsSend.qrIdx]
  // QR.encode returns the SVG data-URL string (the R106 v2 module's shape).
  const dataUrl = globalThis.QR ? globalThis.QR.encode(frame) : null
  const box = $('dsQrImage')
  if (dataUrl && box) box.innerHTML = `<img src="${dataUrl}" alt="Direct Share QR frame ${_dsSend.qrIdx + 1} of ${frames.length}" width="240" height="240">`
  $('dsQrFrameLine').textContent = getMessage('dsQrFrameLine', [String(_dsSend.qrIdx + 1), String(frames.length)], 'Frame $1 of $2 — they scan them in order.')
  dsShow($('dsQrBox'), true)
}

// ── RECEIVER ──

/** RECEIVER leg 1 — parse the pasted text; THE PICKUP PREFIX IS RECOGNIZED
 * FIRST (D13: the input owns both grammars), then the live invitation.
 * DOOR 1 (the channel — D5). */
async function dsAcceptInvitation() {
  const pastedRaw = $('dsPasteInvite')?.value || ''
  // R124 §2 (D13) — THE ASYNC PICKUP: the UCRYPT-PICKUP1 prefix routes to the
  // pickup flow (download → decrypt → the two-door consent → save). The
  // prefix OWNS ITSELF (0.31): a pickup-prefixed paste that fails the code
  // check answers the PICKUP's typed refusal — it never falls through to the
  // share parser's "not an invitation". The pickup is per-notice, one-time,
  // and NEVER a live session — the queue law still guards it: a live share
  // in progress refuses politely.
  const pk = Pickup.parsePickupNotice(pastedRaw)
  if (pk.ok || String(pastedRaw).trim().startsWith(Pickup.PICKUP_PREFIX)) {
    if (_dsRecv.invite || _dsRecv.session) {
      dsRecvStatus(getMessage('dsQueueBusy', undefined, 'A share is already in progress — finish or decline it first; shares go one at a time.'))
      return
    }
    dsPickupFlow(pastedRaw).catch((e) => dsRecvStatus(String(e && e.message || e)))
    return
  }
  if (_dsRecv.invite || _dsRecv.session) {
    dsRecvStatus(getMessage('dsQueueBusy', undefined, 'A share is already in progress — finish or decline it first; shares go one at a time.'))
    return
  }
  dsRecvStatus('')
  dsShow($('dsDoor1'), false)
  dsShow($('dsDoor2'), false)
  dsShow($('dsReplyOut'), false)
  dsShow($('dsRecvDone'), false)
  const guard = await Share.readShareGuard()
  const inv = await Share.parseInvitation($('dsPasteInvite')?.value || '', {
    now: Date.now(), consumed: guard.consumed,
  })
  if (!inv.ok) {
    const map = {
      not_invitation: getMessage('dsErrNotInvite', undefined, 'That is not a Direct Share invitation — it should start with UCRYPT-SHARE1:.'),
      malformed: getMessage('dsErrMalformedR', undefined, 'The invitation is damaged — have it sent again.'),
      bad_code: getMessage('dsErrBadCode', undefined, 'The 8 share words are not valid — the invitation was mistyped or altered.'),
      expired: getMessage('dsExpiredR', undefined, 'This invitation has expired (they last 10 minutes) — ask for a fresh one.'),
      replayed: getMessage('dsReplay', undefined, 'This invitation was already used — share codes work exactly once.'),
      version: getMessage('dsErrVersion', undefined, 'That invitation uses a different Direct Share version — update UCrypt on both sides.'),
    }
    dsRecvStatus(map[inv.code] || getMessage('dsErrMalformedR', undefined, 'The invitation is damaged — have it sent again.'))
    return
  }
  _dsRecv.invite = inv
  _dsRecv.replyText = ''
  // DOOR 1 — the channel consent. Nothing readable commits; the door NEVER
  // auto-dismisses (0.8): no timer touches it.
  dsShow($('dsDoor1'), true)
}

/** RECEIVER leg 2 — accepted Door 1: the reply code + the channel + the sealed descriptor → DOOR 2. */
async function dsDoor1Accept() {
  const inv = _dsRecv.invite
  if (!inv) return
  // One-time consumption is stamped at Door 1 (D9 replay-proof).
  await Share.markConsumed(inv.sid)
  // The user's OWN accept closes Door 1 immediately (0.8: this is the
  // user's action, not an auto-dismiss) — the reply is being prepared.
  dsShow($('dsDoor1'), false)
  dsRecvStatus(getMessage('dsPreparing', undefined, 'Preparing the reply…'))
  let transport
  try {
    transport = await Share.createAnswerTransport(inv.sdp)
  } catch {
    dsRecvStatus(getMessage('dsHolePunchFail', undefined, 'The devices could not connect directly. Try the same network — or in person with the QRs (an ICE restart helps too).'))
    return
  }
  const eph = await Share.generateShareKeys()
  const replyText = await Share.createReply(inv.sid, { epk: eph.pubJwk, sdp: transport.sdp })
  _dsRecv.terminalized = false // a fresh handshake may speak its own terminal
  _dsRecv.session = {
    role: 'receiver', pc: transport.pc, keys: eph, sessionKey: null,
    invite: inv, shareCodeWords: inv.words, replyText,
    safetyWords: '', file: null, dead: false,
  }
  // THE REPLY (D3) — generated + auto-copied with "send this back".
  $('dsReplyText').value = replyText
  dsShow($('dsReplyOut'), true)
  try { await navigator.clipboard.writeText(replyText) } catch { /* the textarea is select-all */ }
  // THE SAFETY WORDS (D8) — shown at Door 2 AND derivable now.
  _dsRecv.session.safetyWords = await Share.deriveSafetyWords(inv.raw, replyText)
  dsRecvStatus(getMessage('dsWaitConnect', undefined, 'Send the reply back — the connection starts when they use it.'))
  // Derive the session key NOW (both public keys are known; the code rode the invitation).
  _dsRecv.session.sessionKey = await Share.deriveSessionKey(eph.privJwk, inv.epk, inv.shareCode)
  // The channel + the sealed descriptor (D5).
  let channel
  try {
    channel = await transport.channelPromise
  } catch {
    // R113 §2.3 — the receiver's connect failure is a TYPED TERMINAL (0.26):
    // the guidance names both fallbacks, the dead session is destroyed and
    // cleared — a failed connect can never wedge the one-at-a-time queue.
    dsReceiverTerminal('failed', getMessage('dsHolePunchFail', undefined, 'The devices could not connect directly. Try the same network — or in person with the QRs (an ICE restart helps too).'))
    return
  }
  _dsRecv.session.channel = channel
  await dsWaitDescriptor()
}

/** RECEIVER leg 3 — open the sealed descriptor; DOOR 2 (the file — D5, never auto-dismissing).
 * D12: the descriptor is the BATCH (every file, its size, its digest, the
 * total); the legacy 'desc' (a v2.71.0 peer) maps to a batch of 1. ONE
 * consent moves the whole batch. */
async function dsWaitDescriptor() {
  const s = _dsRecv.session
  const ch = s.channel
  const np = s.sessionKey.noncePrefix
  const ctrlMeta = (idx) => ({ shareId: s.invite.sid, chunkIndex: idx, totalChunks: 0, totalBytes: 0, digest: '', noncePrefix: np })
  dsRecvStatus(getMessage('dsWaitDesc', undefined, 'Connected — waiting for the file details…'))
  const desc = await new Promise((resolve) => {
    const to = setTimeout(() => resolve(null), 45000)
    ch.onmessage = async (ev) => {
      try {
        const frame = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        const plain = await Share.openShareFrame(s.sessionKey.key, ctrlMeta(-1), frame)
        const msg = JSON.parse(new TextDecoder().decode(plain))
        if (msg.kind === 'desc' || msg.kind === 'batch') { clearTimeout(to); resolve(msg) }
      } catch {
        clearTimeout(to)
        resolve(null) // the session key disagrees — tamper or corruption
      }
    }
    ch.onclose = () => { clearTimeout(to); resolve(null) }
  })
  if (!desc) {
    dsReceiverTerminal('tampered')
    return
  }
  // D12 — normalize: a legacy single-file descriptor is a batch of 1.
  const batch = desc.kind === 'batch'
    ? desc
    : { kind: 'batch', label: desc.label || '', count: 1, total: Number(desc.size) || 0, files: [{ name: desc.name, size: Number(desc.size) || 0, digest: desc.digest, highRisk: Share.executableOrArchiveWarning(desc.name) }] }
  _dsRecv.desc = desc
  s.desc = desc // the session carries it too — dsDoor2Accept reads s.desc
  s.batch = batch
  // The per-file chunk plan: file i's chunks occupy the global counter range
  // [start_i, start_i + chunks_i) — the SAME sparse base the sender uses
  // (start_i = i·2³², so the nonce/seq space and this plan agree exactly;
  // F-R114-DS-PLANBASE-1: the dense cursor silently dropped every file after
  // the first — the receiver typed 'failed' while the sender waited forever).
  const plan = []
  for (let i = 0; i < batch.files.length; i++) {
    const f = batch.files[i]
    const chunks = Share.chunkCountFor(f.size)
    plan.push({ start: i * 4294967296, chunks, size: f.size, digest: String(f.digest || ''), name: f.name })
  }
  _dsRecv.plan = plan
  _dsRecv.chunks = plan.map((p) => new Array(p.chunks).fill(null))
  _dsRecv.received = [] // the files that fully land + pass the digest gate
  dsTrace(`door2:desc-opened rendered kind=${desc.kind} count=${batch.count}`)
  // DOOR 2 — the batch facts + the safety words. NEVER auto-dismisses (0.8).
  const meta = $('dsDoor2Meta')
  const from = batch.label || getMessage('dsUnknownSender', undefined, 'A UCrypt user')
  if (batch.count > 1) {
    meta.textContent = [
      getMessage('dsDoor2From', [from], 'From: $1'),
      getMessage('dsDoor2Files', [String(batch.count), dsFmtSize(batch.total)], 'Files: $1 ($2 total)'),
    ].join(' · ')
  } else {
    meta.textContent = [
      getMessage('dsDoor2From', [from], 'From: $1'),
      getMessage('dsDoor2Name', [batch.files[0].name], 'File: $1'),
      getMessage('dsDoor2Size', [dsFmtSize(batch.files[0].size)], 'Size: $1'),
    ].join(' · ')
  }
  // The batch list (D12): every file's name + size + its own risk flag — the
  // whole batch is stated BEFORE the ONE consent (the 13-year-old law: nothing
  // is hidden behind the Accept button).
  const listEl = $('dsDoor2Files')
  if (listEl) {
    if (batch.count > 1) {
      listEl.replaceChildren(...batch.files.map((f) => {
        const li = document.createElement('li')
        li.className = 'ds-batch-row'
        const nm = document.createElement('span')
        nm.className = 'ds-batch-name'
        nm.textContent = f.name
        nm.title = f.name
        const sz = document.createElement('span')
        sz.className = 'ds-batch-size'
        sz.textContent = dsFmtSize(f.size)
        li.replaceChildren(nm, sz)
        if (f.highRisk) {
          const warn = document.createElement('span')
          warn.className = 'ds-batch-risk'
          warn.textContent = '⚠ ' + getMessage('dsHighRiskShort', undefined, 'can run code')
          li.appendChild(warn)
        }
        return li
      }))
      dsShow(listEl, true)
    } else dsShow(listEl, false)
  }
  const noteEl = $('dsDoor2Note')
  if (s.invite.note) {
    noteEl.textContent = getMessage('dsDoor2Note', [s.invite.note], 'Note: $1')
    dsShow(noteEl, true)
  } else dsShow(noteEl, false)
  $('dsDoor2Safety').textContent = getMessage('dsSafetyWords', [s.safetyWords], 'Safety words: $1')
  const risk = $('dsDoor2Risk')
  const risky = batch.files.filter((f) => f.highRisk)
  if (risky.length === 1) {
    risk.textContent = getMessage('dsHighRisk', [risky[0].name.split('.').pop().toUpperCase()], 'This file type can run code ($1). Only save it if you trust the sender.')
    dsShow(risk, true)
  } else if (risky.length > 1) {
    risk.textContent = getMessage('dsHighRiskMany', [String(risky.length)], '$1 of these files can run code. Only accept if you trust the sender.')
    dsShow(risk, true)
  } else dsShow(risk, false)
  dsShow($('dsDoor2'), true)
  dsRecvStatus('')
}

/** RECEIVER leg 4 — Door 2 accepted: the guard, the stream, the PER-FILE
 * digest gate (D12). One consent, one guard hit; the files cross sequentially;
 * each file's digest gates the moment its last chunk lands. A mid-batch close
 * keeps the files that FULLY arrived and states the partial truth. */
async function dsDoor2Accept() {
  const s = _dsRecv.session
  dsTrace(`door2:enter session=${!!s} desc=${!!(s && s.desc)}`)
  if (!s || !s.desc) return
  dsTrace('door2:guard-hash')
  // THE GUARD (D9): the hourly cap + the per-sender backoff. The sender key
  // is a hash of the inviter's EPHEMERAL public key — never a device identity.
  // D12: a batch is ONE session — exactly ONE accept is recorded.
  // R130-F2: the check and the record are ONE atomic serialized unit — a
  // parallel rush can no longer slip past the cap between the two steps.
  const senderKey = (await ShareSha256Hex(new TextEncoder().encode(JSON.stringify(s.invite.epk)))).slice(0, 32)
  const gate = await Share.acceptIfAllowed(senderKey)
  dsTrace(`door2:gate ok=${gate && gate.ok} code=${gate && gate.code}`)
  if (!gate.ok) { dsReceiverTerminal('rate'); return }
  dsTrace('door2:accept-recorded')
  dsShow($('dsDoor2'), false)
  const ch = s.channel
  try {
    ch.send(JSON.stringify(await Share.sealShareFrame(s.sessionKey.key, { shareId: s.invite.sid, chunkIndex: -1, totalChunks: 0, totalBytes: 0, digest: '', noncePrefix: s.sessionKey.noncePrefix }, new TextEncoder().encode(JSON.stringify({ kind: 'accept' })))))
  } catch { dsReceiverTerminal('failed'); return }
  // THE STREAM (D12) — every chunk sealed; the receiver acks ONCE per window
  // boundary AND at every file's last chunk (the sender's per-file tail-await
  // mirror); each file's digest gate is that file's last word.
  const np = s.sessionKey.noncePrefix
  const plan = _dsRecv.plan || []
  const batch = s.batch || { count: 1, files: [] }
  const total = plan.reduce((a, p) => a + p.chunks, 0)
  const rangeFor = (seq) => {
    for (let i = 0; i < plan.length; i++) {
      if (seq >= plan[i].start && seq < plan[i].start + plan[i].chunks) return i
    }
    return -1
  }
  let got = 0
  // F-R114-DS-ZEROBATCH-1 (R114): a 0-byte file has ZERO chunks — the stream
  // never fires its last-chunk gate, so the old engine's end-of-stream merge
  // was the only gate it ever got. The batch engine gates at 'done' any file
  // the stream could not gate (0-byte files, and a truncated tail), so every
  // file in the descriptor is either digest-verified or the batch dies typed.
  const gated = new Array(plan.length).fill(false)
  // The per-file gate: merge the file's bytes, compare the digest; on a pass
  // the file is KEPT (the partial-cancel honesty stands on this list).
  const gateFile = async (fi) => {
    const p = plan[fi]
    const merged = new Uint8Array(p.size)
    let off = 0
    for (const c of _dsRecv.chunks[fi]) { merged.set(c, off); off += c.length }
    const hex = await ShareSha256Hex(merged)
    if (hex !== p.digest.toLowerCase()) return false
    _dsRecv.received.push({ bytes: merged, name: p.name, size: p.size, digest: hex })
    gated[fi] = true
    return true
  }
  dsRecvStatus(batch.count > 1
    ? getMessage('dsRecvProgressFile', ['1', String(batch.count), '0'], 'Receiving file $1 of $2… $3%')
    : getMessage('dsProgress', ['0'], 'Receiving… $1%'))
  const streamResult = await new Promise((resolve) => {
    const fail = () => { resolve({ how: 'failed' }) }
    const to = setTimeout(fail, 120000 + total * 400)
    ch.onmessage = async (ev) => {
      try {
        const frame = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        if (frame && frame.v === 1 && Number(frame.seq) === -2) {
          // THE SEALED DONE frame (its own negative-index domain).
          const plain = await Share.openShareFrame(s.sessionKey.key, { shareId: s.invite.sid, chunkIndex: -2, totalChunks: 0, totalBytes: 0, digest: '', noncePrefix: np }, frame)
          JSON.parse(new TextDecoder().decode(plain)) // must parse as {kind:'done'}
          clearTimeout(to)
          resolve({ how: 'done' })
          return
        }
        const idx = Number(frame.seq)
        const fi = rangeFor(idx)
        if (!Number.isInteger(idx) || idx < 0 || fi < 0 || _dsRecv.chunks[fi][idx - plan[fi].start]) { clearTimeout(to); fail(); return }
        const p = plan[fi]
        _dsRecv.chunks[fi][idx - p.start] = await Share.openShareFrame(s.sessionKey.key, { shareId: s.invite.sid, fileIndex: fi, chunkIndex: idx, totalChunks: p.chunks, totalBytes: p.size, digest: p.digest, noncePrefix: np }, frame)
        got++
        const local = idx - p.start + 1
        if ((local % Share.SHARE_ACK_WINDOW === 0) || local === p.chunks || (idx + 1) === total) {
          // R113 §2.5 — the FINAL chunk ALWAYS acks (per file now, D12); the
          // window slides between the boundaries.
          try { ch.send(JSON.stringify({ kind: 'ack', seq: idx })) } catch { /* the window slides on */ }
        }
        if (local === p.chunks && !gated[fi]) {
          // THIS file's last chunk — the per-file digest gate fires NOW.
          const okFile = await gateFile(fi)
          if (!okFile) {
            clearTimeout(to)
            resolve({ how: 'tampered', file: fi })
            return
          }
          // The per-file ledger line (D11 frozen shape; one line per file).
          Share.shareLedgerAppend({ dir: 'received', name: p.name, size: p.size, at: Date.now() })
            .then(() => dsRenderLedger()).catch(() => { /* the ledger never blocks */ })
        }
        if (got % 4 === 0 || got === total) {
          const pct = total ? Math.round((got / total) * 100) : 100
          dsRecvStatus(batch.count > 1
            ? getMessage('dsRecvProgressFile', [String(fi + 1), String(batch.count), String(pct)], 'Receiving file $1 of $2… $3%')
            : getMessage('dsProgress', [String(pct)], 'Receiving… $1%'))
        }
      } catch {
        clearTimeout(to)
        resolve({ how: 'tampered', file: -1 })
      }
    }
    ch.onclose = () => { clearTimeout(to); if (got < total) resolve({ how: 'closed' }) }
  })
  if (streamResult.how === 'tampered') {
    // A file failed its digest gate: the batch dies typed (D8's automated
    // half). What ALREADY passed stays savable — the partial honesty holds.
    dsRecvStatus(getMessage('dsRecvFileTampered', [String((streamResult.file + 1) || '?')], 'File $1 did not match its fingerprint — the share stopped. Nothing else will arrive. The keys are destroyed.'))
    dsReceiverBatchDone('tampered')
    return
  }
  if (streamResult.how === 'failed') { dsReceiverTerminal('failed'); return }
  if (streamResult.how === 'closed') {
    // MID-BATCH CLOSE (the sender cancelled, the network died, or the lock):
    // the typed partial truth — the files that fully arrived are kept.
    const kept = _dsRecv.received.length
    if (kept > 0) {
      dsRecvStatus(getMessage('dsRecvPartial', [String(kept), String(batch.count)], 'Interrupted — $1 of $2 files arrived intact; the rest never came. The keys are destroyed.'))
      dsReceiverBatchDone('partial')
    } else {
      dsReceiverTerminal('failed')
    }
    return
  }
  // how === 'done' — the whole batch landed. Gate any file the stream could
  // not (F-R114-DS-ZEROBATCH-1: a 0-byte file has no last chunk to gate it).
  for (let i = 0; i < plan.length; i++) {
    if (gated[i]) continue
    const okFile = await gateFile(i)
    if (!okFile) {
      dsRecvStatus(getMessage('dsRecvFileTampered', [String(i + 1)], 'File $1 did not match its fingerprint — the share stopped. Nothing else will arrive. The keys are destroyed.'))
      dsReceiverBatchDone('tampered')
      return
    }
    Share.shareLedgerAppend({ dir: 'received', name: plan[i].name, size: plan[i].size, at: Date.now() })
      .then(() => dsRenderLedger()).catch(() => { /* the ledger never blocks */ })
  }
  _dsRecv.file = { bytes: _dsRecv.received[0].bytes, name: _dsRecv.received[0].name }
  dsReceiverBatchDone('done')
  dsRecvStatus('')
  // THE WORDS DIE (D7): the keys are destroyed the moment the batch lands.
  Share.destroyKeys(s)
  try { ch.close() } catch { /* already closing */ }
  try { s.pc.close() } catch { /* already closing */ }
  // R113 §2.3 — the queue re-opens after a COMPLETED receive: the session
  // and the invitation are dead references the moment the keys die.
  _dsRecv.session = null
  _dsRecv.invite = null
  _dsRecv.desc = null
  _dsRecv.chunks = null
  _dsRecv.plan = null
}

/** The done/partial view (D12): the file list, the save-all button, the
 * partial-honesty note. `flavor`: 'done' | 'partial' | 'tampered'. */
function dsReceiverBatchDone(flavor) {
  const s = _dsRecv.session
  const batch = (s && s.batch) || { count: _dsRecv.received.length }
  const kept = _dsRecv.received.length
  if (flavor === 'partial') {
    $('dsDoneLine').textContent = getMessage('dsDonePartialLine', [String(kept), String(batch.count)], 'Received $1 of $2 files — the fingerprints checked out; the rest never arrived.')
  } else if (flavor === 'tampered') {
    $('dsDoneLine').textContent = getMessage('dsDoneTamperedLine', [String(kept), String(batch.count)], 'Stopped — $1 of $2 files arrived intact. The mismatched file was refused.')
  } else {
    $('dsDoneLine').textContent = batch.count > 1
      ? getMessage('dsDoneMany', [String(batch.count)], 'Received $1 files — every fingerprint checked out.')
      : getMessage('dsDone', undefined, 'Received — the file’s fingerprint checks out.')
  }
  renderDoneFiles()
  const part = $('dsDonePartial')
  if (flavor !== 'done' && part) {
    part.textContent = getMessage('dsDonePartialNote', undefined, 'The share ended early — the keys are destroyed, the missing files will never arrive. What you see here is everything that did.')
    dsShow(part, true)
  } else if (part) dsShow(part, false)
  if (_dsRecv.received[0]) {
    $('dsDigestLine').textContent = getMessage('dsDigest', [_dsRecv.received[0].digest], 'SHA-256: $1')
  }
  // The save button names the truth: one file → "Save as…", many → "Save all N".
  const save = $('dsSaveBtn')
  if (save) {
    if (kept > 1) {
      save.textContent = getMessage('dsSaveAll', [String(kept)], 'Save all $1 files')
    } else {
      save.textContent = getMessage('dsSaveBtn', undefined, 'Save as…')
    }
    save.setAttribute('aria-label', save.textContent)
  }
  dsShow($('dsRecvDone'), true)
  // THE WORDS DIE (D7) — also on the partial paths.
  if (s) {
    Share.destroyKeys(s)
    try { s.channel && s.channel.close() } catch { /* already closing */ }
    try { s.pc && s.pc.close() } catch { /* already closing */ }
    _dsRecv.session = null
    _dsRecv.invite = null
    _dsRecv.desc = null
    _dsRecv.chunks = null
    _dsRecv.plan = null
  }
}

/** Render the done view's file list (D12) — one row per received file. */
function renderDoneFiles() {
  const listEl = $('dsDoneFiles')
  if (!listEl) return
  const files = _dsRecv.received || []
  if (files.length > 1) {
    listEl.replaceChildren(...files.map((f) => {
      const li = document.createElement('li')
      li.className = 'ds-batch-row ds-batch-ok'
      const nm = document.createElement('span')
      nm.className = 'ds-batch-name'
      nm.textContent = '✓ ' + f.name
      nm.title = f.name
      const sz = document.createElement('span')
      sz.className = 'ds-batch-size'
      sz.textContent = dsFmtSize(f.size)
      li.replaceChildren(nm, sz)
      return li
    }))
    dsShow(listEl, true)
  } else dsShow(listEl, false)
}

/** THE SILENT DECLINE (D7): nothing crosses the wire — no decline signal exists. */
function dsDoorDecline() {
  dsReceiverTerminal('declined')
}

/** Collision-safe save: the browser's own dedupe names the copy; never silent-overwrite.
 * D12: every received file saves — a batch downloads file by file (staggered
 * so the browser's download manager keeps the order). */
function dsSaveReceived() {
  const files = (_dsRecv.received && _dsRecv.received.length)
    ? _dsRecv.received
    : (_dsRecv.file ? [_dsRecv.file] : [])
  if (!files.length) return
  files.forEach((f, i) => {
    setTimeout(() => {
      const blob = new Blob([f.bytes], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = f.name || 'received-file'
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 30000)
    }, i * 350)
  })
  const st = $('dsRecvStatus')
  if (st) {
    st.textContent = files.length > 1
      ? getMessage('dsSavedMany', [String(files.length)], 'Saving $1 files — the browser dedupes any name collisions.')
      : getMessage('dsSaved', [files[0].name], 'Saved to $1.')
    dsShow(st, true)
  }
  toast(getMessage('dsSavedToast', undefined, 'File saved — the share left no other trace.'), 'ok')
}

async function ShareSha256Hex(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

// ═══════════════════════════════════════════════════════════════════════════
// R124 §2 (D13) — THE ASYNC PICKUP: the last deferred feature.
// The hold is OPT-IN, PER-SHARE, DEFAULT OFF — the live share's behavior is
// untouched (0.38). The offer appears ONLY on the sender's waiting card when
// the invitation is near expiry (the last 3 minutes of the 10-minute
// window) — never cluttering the normal flow. The held file rides the
// SENDER'S OWN cloud under the pickup key (HKDF, ucrypt:pickup:v1,
// domain-separated); the cloud sees only ciphertext under a neutral name;
// the messenger sees only the link and the code. The separation law (0.27)
// holds absolutely — nothing here touches the vault's surfaces.
// ═══════════════════════════════════════════════════════════════════════════

/** The sender-side holds record (the page's OWN key — never the vault's):
 * the public cleanup ref + the expiry, so a reload keeps the truth and the
 * expiry sweep can still reach the cloud. Capped at 10. */
const PICKUP_HOLDS_KEY = 'ucrypt:pickup:holds'
const PICKUP_HOLDS_CAP = 10
/** The offer's threshold: the offer appears in the invitation's LAST 3 minutes. */
const PICKUP_OFFER_WINDOW_MS = 3 * 60 * 1000
const _pickupHold = { active: null, timer: null } // the CURRENT hold (the held box's state)

async function pickupHoldsList() {
  try {
    const g = (await chrome.storage.local.get(PICKUP_HOLDS_KEY))[PICKUP_HOLDS_KEY]
    return Array.isArray(g) ? g : []
  } catch { return [] }
}

async function pickupHoldsSave(list) {
  try { await chrome.storage.local.set({ [PICKUP_HOLDS_KEY]: list.slice(0, PICKUP_HOLDS_CAP) }) } catch { /* best-effort */ }
}

/** The pickup ring rows (0.28 — flow 'pickup'; stage names only). */
function pickupRing(stage, outcome, message, transport) {
  recordRing({
    flow: 'pickup',
    transport: String(transport || 'share').slice(0, 24),
    stage,
    outcome: outcome === 'ok' ? 'ok' : 'fail',
    httpKind: 'pickup',
    message: String(message || '').slice(0, 120),
  }).catch(() => { /* the ring never throws into its caller */ })
}

/** The TTL choice's human words (the three bounded choices only — 0.15). */
function pickupTtlWords(ms) {
  if (ms === 3600000) return getMessage('pickupTtl1h', undefined, '1 hour')
  if (ms === 7 * 86400000) return getMessage('pickupTtl7d', undefined, '7 days')
  return getMessage('pickupTtl24h', undefined, '24 hours')
}

/** The visible remaining-time words (the sender's held line + the receiver's door). */
function pickupRemainingWords(ms) {
  const m = Math.max(0, Math.round(ms / 60000))
  if (m >= 60 * 24) {
    const days = Math.round(m / (60 * 24))
    return getMessage('pickupRemainDays', [String(days)], '~$1 day(s) left')
  }
  if (m >= 60) return getMessage('pickupRemainHours', [String(Math.round(m / 60))], '~$1 hour(s) left')
  return getMessage('pickupRemainMinutes', [String(m)], '~$1 minute(s) left')
}

/** THE OFFER HOOK — called from the waiting countdown's tick. The offer
 * appears ONLY in the last 3 minutes (near expiry); it never clutters the
 * healthy flow; it hides at the terminal (the held box outlives it). */
function dsUpdateHoldOffer(leftMs) {
  const btn = $('dsHoldOffer')
  if (!btn) return
  const waiting = _dsSend.session && !_dsSend.terminalized
  const show = !!waiting && Number.isFinite(leftMs) && leftMs > 0 && leftMs <= PICKUP_OFFER_WINDOW_MS && !_pickupHold.active
  dsShow(btn, show)
  if (show) {
    btn.setAttribute('aria-label', getMessage('pickupOfferWhy', undefined, 'They haven\u2019t answered — hold the file on YOUR cloud so they can pick it up later.'))
  }
}

/** The hold layer: the focused popup (0.24). Opens with the transport's
 * honest-support verdict ALREADY rendered — the label says what is possible
 * before anything is promised (0.29: the fix or the fallback, named). */
async function pickupOpenLayer() {
  const files = _dsSend.session && Array.isArray(_dsSend.session.files) ? _dsSend.session.files : (_dsSend.files || [])
  if (!files.length) {
    dsSendStatus(getMessage('pickupHoldFailed', ['no file'], 'The hold failed — $1'))
    return
  }
  const layer = $('pickupLayer')
  if (!layer) return
  dsShow($('pickupLayerErr'), false)
  dsShow($('pickupLayerBusy'), false)
  $('pickupHoldBtn').disabled = false
  $('pickupTtlSelect').value = String(Pickup.PICKUP_TTL_DEFAULT_MS)
  $('pickupLayerExpl').textContent = getMessage('pickupLayerExpl', [pickupTtlWords(Pickup.PICKUP_TTL_DEFAULT_MS)], 'Held on YOUR cloud, encrypted — they pick it up with this code. Expires in $1.')
  layer.classList.remove('hidden'); layer.hidden = false
  try { $('pickupHoldBtn').focus({ preventScroll: true }) } catch { /* best-effort */ }
  // The transport's honest-support verdict (the worker answers; the page
  // never touches credentials — law 0.14).
  let resp = null
  try { resp = await chrome.runtime.sendMessage({ type: 'PICKUP_SUPPORT' }) } catch { resp = { ok: false } }
  const line = $('pickupLayerTransport')
  if (!resp || !resp.ok || resp.locked) {
    line.textContent = getMessage('pickupNoTransport', undefined, 'No cloud transport is available — connect one in the Sync tab first (or unlock the vault).')
    $('pickupHoldBtn').disabled = true
    return
  }
  const s = resp.support || { supported: false, reason: 'unknown' }
  if (!s.supported) {
    line.textContent = getMessage('pickupNotSupported', [s.label || s.reason || 'This transport'], '$1 cannot hold a pickup — the live share still works when you\u2019re both online.')
    $('pickupHoldBtn').disabled = true
    pickupRing(Pickup.PICKUP_STAGES.HOLD_OFFER, 'fail', `the honest absence: ${s.reason || 'unsupported'}`)
    return
  }
  line.textContent = getMessage('pickupLayerTransport', [s.label], 'Held on YOUR $1 — the link grants only this file\u2019s ciphertext; no credentials ride the code.')
  pickupRing(Pickup.PICKUP_STAGES.HOLD_OFFER, 'ok', 'the hold layer opened', resp.provider)
}

function pickupCloseLayer() {
  const layer = $('pickupLayer')
  if (layer) { layer.classList.add('hidden'); layer.hidden = true }
}

/** THE HOLD — seal → upload → link → notice. One click; the honest labels
 * ride every state; the ledger records 'held' (the same identity-free shape). */
async function pickupDoHold() {
  const files = _dsSend.session && Array.isArray(_dsSend.session.files) ? _dsSend.session.files : (_dsSend.files || [])
  if (!files.length) return
  const ttlMs = Number($('pickupTtlSelect')?.value || Pickup.PICKUP_TTL_DEFAULT_MS)
  const busy = $('pickupLayerBusy')
  const errEl = $('pickupLayerErr')
  dsShow(errEl, false)
  $('pickupHoldBtn').disabled = true
  busy.textContent = getMessage('pickupHoldBusy', undefined, 'Sealing and uploading…')
  dsShow(busy, true)
  pickupRing(Pickup.PICKUP_STAGES.HOLD_CREATE, 'ok', `the hold starts (${files.length} file(s), ttl ${pickupTtlWords(ttlMs)})`)
  try {
    const staged = []
    for (const f of files) {
      const buf = f.buf instanceof Uint8Array ? f.buf : new Uint8Array(await f.file.arrayBuffer())
      staged.push({ name: f.file.name, bytes: buf })
    }
    const note = ($('dsNote')?.value || '').slice(0, Pickup.PICKUP_NOTE_CAP)
    const sealed = await Pickup.sealPickup({ files: staged, note, ttlMs })
    // THE UPLOAD — the worker's leg (the credentials never cross to this page).
    const resp = await chrome.runtime.sendMessage({ type: 'PICKUP_HOLD_UPLOAD', blob: sealed.blob })
    if (!resp || !resp.ok || resp.locked) {
      const why = (resp && (resp.userMessage || resp.error)) || 'the cloud refused'
      throw new Error(why)
    }
    const notice = Pickup.buildPickupNotice({ link: resp.link, code: sealed.code })
    _pickupHold.active = {
      notice, code: sealed.code, expiresAt: sealed.expiresAt, ttlMs,
      cleanupRef: resp.cleanupRef, provider: resp.provider,
      files: staged.map((f) => ({ name: f.name, size: f.bytes.length })),
    }
    // The persisted truth (a reload keeps the box and the sweep lawful).
    const holds = await pickupHoldsList()
    holds.unshift({ notice: _pickupHold.active.notice, expiresAt: sealed.expiresAt, ttlMs, cleanupRef: resp.cleanupRef, provider: resp.provider, files: _pickupHold.active.files })
    await pickupHoldsSave(holds)
    pickupCloseLayer()
    pickupRenderHeld()
    // THE LEDGER — one 'held' line per file (the frozen identity-free shape).
    for (const f of _pickupHold.active.files) {
      Share.shareLedgerAppend({ dir: 'held', name: f.name, size: f.size, at: Date.now() })
        .then(() => dsRenderLedger()).catch(() => { /* the ledger never blocks */ })
    }
    pickupRing(Pickup.PICKUP_STAGES.HOLD_UPLOADED, 'ok', 'the ciphertext is on the sender\u2019s cloud', resp.provider)
    pickupRing(Pickup.PICKUP_STAGES.NOTICE_ISSUED, 'ok', 'the notice issued (link + code only)', resp.provider)
    // The offer retires — the hold is made.
    dsShow($('dsHoldOffer'), false)
  } catch (e) {
    const why = String((e && e.message) || e).slice(0, 140)
    errEl.textContent = getMessage('pickupHoldFailed', [why], 'The hold failed — $1')
    dsShow(errEl, true)
    pickupRing(Pickup.PICKUP_STAGES.HOLD_CREATE, 'fail', why)
  } finally {
    dsShow(busy, false)
    $('pickupHoldBtn').disabled = false
  }
}

/** The held box's truthful state (render-by-state, 0.25): the notice + the
 * visible TTL + the cancel. The box NEVER auto-dismisses (0.8). */
function pickupRenderHeld() {
  const box = $('pickupHeldBox')
  if (!box) return
  const hold = _pickupHold.active
  if (!hold) { dsShow(box, false); return }
  $('pickupNoticeText').value = hold.notice
  dsShow(box, true)
  pickupTickHeldLine()
  if (_pickupHold.timer) { clearInterval(_pickupHold.timer); _pickupHold.timer = null }
  _pickupHold.timer = setInterval(() => {
    if (!_pickupHold.active) { clearInterval(_pickupHold.timer); _pickupHold.timer = null; return }
    if (Pickup.pickupTtlState(_pickupHold.active.expiresAt) === 'expired') {
      // THE SENDER'S EXPIRY TERMINAL (law 0.37 — no silent stall): the hold
      // is swept (the ciphertext leaves the cloud) and the box says so.
      pickupSweepHold('expired')
      return
    }
    pickupTickHeldLine()
  }, 30000)
}

function pickupTickHeldLine() {
  const hold = _pickupHold.active
  if (!hold) return
  const left = Pickup.pickupTtlRemaining(hold.expiresAt)
  const el = $('pickupHeldLine')
  if (el) el.textContent = getMessage('pickupHeldLine', [pickupRemainingWords(left)], 'Waiting for pickup — expires in $1.')
}

/** THE CANCEL / THE SWEEP — the hold dies on demand or at expiry: the
 * ciphertext leaves the cloud (the typed result is rendered — never a silent
 * "probably gone"), the box closes, the timer stops. */
async function pickupSweepHold(reason) {
  const hold = _pickupHold.active
  if (!hold) return
  _pickupHold.active = null
  if (_pickupHold.timer) { clearInterval(_pickupHold.timer); _pickupHold.timer = null }
  let verdict = { ok: true, code: 'no_ref' }
  if (hold.cleanupRef) {
    try { verdict = await chrome.runtime.sendMessage({ type: 'PICKUP_HOLD_CANCEL', cleanupRef: hold.cleanupRef }) || { ok: false, code: 'no_answer' } } catch { verdict = { ok: false, code: 'no_answer' } }
  }
  pickupRing(Pickup.PICKUP_STAGES.CANCEL, verdict.ok ? 'ok' : 'fail', `${reason}: ${verdict.code || ''}`, hold.provider)
  const box = $('pickupHeldBox')
  if (box) dsShow(box, false)
  const st = $('dsSendStatus')
  if (st) {
    st.textContent = verdict.ok
      ? getMessage('pickupCancelled', undefined, 'The hold is cancelled — the file is gone from your cloud.')
      : getMessage('pickupCancelFailed', [verdict.code || 'error'], 'The hold\u2019s removal did not confirm — delete the file named ucrypt-pickup in your cloud\u2019s trash. ($1)')
    dsShow(st, true)
  }
}

// ── THE RECEIVER'S PICKUP FLOW (download → decrypt → the two doors → save) ──

const _pickupRecv = { open: null } // { notice, link, files, desc, expiresAt }

/** The pasted notice's journey. Every failure is TYPED (0.13/0.26) and every
 * terminal names the fix; the TTL's expiry renders its own terminal. */
async function dsPickupFlow(noticeText) {
  const notice = String(noticeText || '').trim()
  dsShow($('dsDoor1'), false)
  dsShow($('dsDoor2'), false)
  dsShow($('pickupDoor'), false)
  dsShow($('dsRecvDone'), false)
  const p = Pickup.parsePickupNotice(notice)
  if (!p.ok) {
    dsRecvStatus(getMessage('pickupBadCode', undefined, 'The pickup code is not 8 valid words — the notice was mistyped.'))
    return
  }
  pickupRing(Pickup.PICKUP_STAGES.NOTICE_PASTED, 'ok', 'a pickup notice was pasted')
  // THE ONE-TIME GUARD (the code dies on completion — replay-proof).
  if (await Pickup.isPickupConsumed(notice)) {
    dsRecvStatus(getMessage('pickupConsumed', undefined, 'This pickup was already picked up here.'))
    return
  }
  // THE DOWNLOAD — bare fetch: no credentials, no account, nothing but the link.
  dsRecvStatus(getMessage('pickupRecvDownloading', undefined, 'Downloading from their cloud — no account needed\u2026'))
  const dl = await Pickup.downloadPickup(p.link)
  pickupRing(Pickup.PICKUP_STAGES.DOWNLOAD, dl.ok ? 'ok' : 'fail', dl.ok ? `the ciphertext arrived (${dl.bytes.length} B)` : dl.code, 'cloud')
  if (!dl.ok) {
    const map = {
      gone: getMessage('pickupGone', undefined, 'This pickup is no longer available — ask them to share again.'),
      cloud_page: getMessage('pickupCloudPage', undefined, 'The cloud answered with a web page, not the file — ask them to hold it again.'),
      cloud_error: getMessage('pickupCloudPage', undefined, 'The cloud answered with a web page, not the file — ask them to hold it again.'),
      network: getMessage('pickupNetwork', undefined, 'The cloud could not be reached — check your connection and try again.'),
    }
    dsRecvStatus(map[dl.code] || map.network)
    return
  }
  // THE DECRYPT — the key derives from the pasted code; the descriptor
  // becomes readable ONLY here (the messenger never learned what was shared).
  dsRecvStatus(getMessage('pickupRecvDecrypting', undefined, 'Decrypting with your code\u2026'))
  const opened = await Pickup.openPickup(dl.bytes, p.code)
  pickupRing(Pickup.PICKUP_STAGES.DECRYPT, opened.ok ? 'ok' : 'fail', opened.ok ? 'the descriptor opened' : opened.code, 'cloud')
  if (!opened.ok) {
    const map = {
      expired: getMessage('pickupExpired', undefined, 'This pickup expired — ask them to share again.'),
      tampered: getMessage('pickupTampered', undefined, 'The code doesn\u2019t match this file — the notice was mistyped or altered.'),
      bad_code: getMessage('pickupBadCode', undefined, 'The pickup code is not 8 valid words — the notice was mistyped.'),
      malformed: getMessage('pickupTampered', undefined, 'The code doesn\u2019t match this file — the notice was mistyped or altered.'),
    }
    dsRecvStatus(map[opened.code] || map.tampered)
    return
  }
  // DOOR 1 — the descriptor reveals itself. NEVER auto-dismisses (0.8).
  _pickupRecv.open = { notice, link: p.link, files: opened.files, desc: opened.desc, expiresAt: opened.expiresAt }
  dsRecvStatus('')
  dsPickupDoorShow()
}

function dsPickupDoorShow() {
  const hold = _pickupRecv.open
  if (!hold) return
  const meta = $('pickupDoorMeta')
  const files = hold.files
  const total = files.reduce((a, f) => a + f.size, 0)
  if (files.length > 1) {
    meta.textContent = getMessage('pickupDoorFiles', [String(files.length), dsFmtSize(total)], 'Files: $1 ($2 total)')
  } else {
    meta.textContent = getMessage('pickupDoorFile', [files[0].name, dsFmtSize(files[0].size)], 'File: $1 ($2)')
  }
  const listEl = $('pickupDoorFiles')
  if (files.length > 1) {
    listEl.replaceChildren(...files.map((f) => {
      const li = document.createElement('li')
      li.className = 'ds-batch-row'
      const nm = document.createElement('span')
      nm.className = 'ds-batch-name'
      nm.textContent = f.name
      nm.title = f.name
      const sz = document.createElement('span')
      sz.className = 'ds-batch-size'
      sz.textContent = dsFmtSize(f.size)
      li.replaceChildren(nm, sz)
      if (f.highRisk) {
        const warn = document.createElement('span')
        warn.className = 'ds-batch-risk'
        warn.textContent = '⚠ ' + getMessage('dsHighRiskShort', undefined, 'can run code')
        li.appendChild(warn)
      }
      return li
    }))
    dsShow(listEl, true)
  } else dsShow(listEl, false)
  const noteEl = $('pickupDoorNote')
  if (hold.desc.note) {
    noteEl.textContent = getMessage('pickupDoorNote', [hold.desc.note], 'Note: $1')
    dsShow(noteEl, true)
  } else dsShow(noteEl, false)
  const ttlEl = $('pickupDoorTtl')
  ttlEl.textContent = getMessage('pickupDoorTtl', [pickupRemainingWords(Pickup.pickupTtlRemaining(hold.expiresAt))], 'Expires in $1.')
  const risky = files.filter((f) => f.highRisk)
  const risk = $('pickupDoorRisk')
  if (risky.length === 1) {
    risk.textContent = getMessage('dsHighRisk', [risky[0].name.split('.').pop().toUpperCase()], 'This file type can run code ($1). Only save it if you trust the sender.')
    dsShow(risk, true)
  } else if (risky.length > 1) {
    risk.textContent = getMessage('dsHighRiskMany', [String(risky.length)], '$1 of these files can run code. Only accept if you trust the sender.')
    dsShow(risk, true)
  } else dsShow(risk, false)
  dsShow($('pickupDoor'), true)
  pickupRing(Pickup.PICKUP_STAGES.CONSENT, 'ok', `the door renders (${files.length} file(s))`)
}

/** DOOR 2 — the Save: EVERY file's digest gates the save (the same
 * digest-verified discipline the live share carries); the pickup code dies
 * on completion; the ledger records 'pickedup'; the decrypted files are the
 * ONLY thing this device keeps. */
async function dsPickupDoorSave() {
  const hold = _pickupRecv.open
  if (!hold) return
  // THE DIGEST GATES — each file's SHA-256 must match the sealed descriptor.
  const good = []
  for (const f of hold.files) {
    const hex = await ShareSha256Hex(f.bytes)
    if (f.digest && hex !== String(f.digest).toLowerCase()) {
      dsRecvStatus(getMessage('dsRecvFileTampered', [f.name], 'File $1 did not match its fingerprint — the share stopped. Nothing else will arrive. The keys are destroyed.'))
      pickupRing(Pickup.PICKUP_STAGES.SAVE, 'fail', `the digest gate refused ${f.name}`)
      _pickupRecv.open = null
      dsShow($('pickupDoor'), false)
      return
    }
    good.push({ bytes: f.bytes, name: f.name, size: f.size, digest: hex })
  }
  // THE SAVE — the browser's own download flow (the collision-safe pattern).
  good.forEach((f, i) => {
    setTimeout(() => {
      const blob = new Blob([f.bytes], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = f.name || 'picked-up-file'
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 30000)
    }, i * 350)
  })
  // THE CODE DIES (0.38) — the completion marks the notice consumed.
  await Pickup.markPickupConsumed(hold.notice)
  for (const f of good) {
    Share.shareLedgerAppend({ dir: 'pickedup', name: f.name, size: f.size, at: Date.now() })
      .then(() => dsRenderLedger()).catch(() => { /* the ledger never blocks */ })
  }
  pickupRing(Pickup.PICKUP_STAGES.SAVE, 'ok', `${good.length} file(s) saved; the pickup code died`)
  dsShow($('pickupDoor'), false)
  dsRecvStatus(getMessage('pickupSaved', undefined, 'Saved — the pickup code is now dead.'))
  toast(getMessage('pickupSavedToast', undefined, 'File saved — the pickup left no other trace.'), 'ok')
  _pickupRecv.open = null
}

/** DOOR 2's Discard — nothing is kept, nothing is marked consumed (the
 * notice may still be picked up here later, honestly). */
function dsPickupDoorDiscard() {
  _pickupRecv.open = null
  dsShow($('pickupDoor'), false)
  dsRecvStatus('')
}

/** The reload/heal path: the persisted holds render truthfully — an expired
 * one is swept (the ciphertext leaves the cloud), a live one re-shows. */
async function pickupRestoreHolds() {
  const holds = await pickupHoldsList()
  if (!holds.length) return
  const live = []
  for (const h of holds) {
    if (Pickup.pickupTtlState(h.expiresAt) === 'expired') {
      // The sweep is best-effort (the transport may be gone) — the record
      // drops either way: the sender's UI never lies about a live hold.
      try {
        if (h.cleanupRef) await chrome.runtime.sendMessage({ type: 'PICKUP_HOLD_CANCEL', cleanupRef: h.cleanupRef })
      } catch { /* best-effort */ }
      continue
    }
    live.push(h)
  }
  await pickupHoldsSave(live)
  if (live.length) {
    _pickupHold.active = live[0]
    pickupRenderHeld()
  }
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey || e.metaKey) return
  const activeTag = document.activeElement ? document.activeElement.tagName : ''
  if (['INPUT', 'SELECT', 'TEXTAREA'].includes(activeTag) && !e.altKey) return
  const tabMap = {
    '1': 'vault',
    '2': 'security',
    '3': 'sync',
    '4': 'transfer',
    '5': 'share',
    '6': 'generator',
    '7': 'wordlists',
    '8': 'data',
  }
  if (e.key === '/' && !e.altKey) {
    e.preventDefault()
    const vaultBtn = document.querySelector('.opts-tab[data-tab="vault"]')
    if (vaultBtn) vaultBtn.click()
    setTimeout(() => { document.getElementById('vaultSearch')?.focus() }, 20)
    return
  }
  if (tabMap[e.key]) {
    const btn = document.querySelector(`.opts-tab[data-tab="${tabMap[e.key]}"]`)
    if (btn) btn.click()
  }
})

// UCRYPT-23: Seamless auto-resizing for the embedded Device Transfer frame so
// it integrates into #tab-transfer with the exact Cloud Sync card flow and
// zero nested scrollbars.
window.addEventListener('message', (e) => {
  const d = e && e.data
  if (!d || typeof d !== 'object') return
  if (d.type === 'UCRYPT_TRANSFER_FRAME_HEIGHT') {
    const frame = document.getElementById('fileTransferFrame')
    const h = Number(d.height)
    if (frame && Number.isFinite(h) && h >= 420) {
      frame.style.height = `${Math.ceil(h)}px`
    }
  }
})

// UCRYPT-26: Wire interactive Cloud Sync hero chips, quick-action toolbars,
// and Settled-House disclosures across Vault, Security, Direct Share,
// Generator, Wordlists, and Export/Import tabs so every area shares the same
// navigability, usability, and intuitiveness as Cloud Sync.
function wireUnifiedTabHeroes() {
  if (document.body && document.body.dataset.unifiedHeroesWired === '1') return
  if (document.body) document.body.dataset.unifiedHeroesWired = '1'

  try {
    SettledHouse.applyAll(document).catch(() => {})
  } catch { /* non-fatal */ }

  const openAndFocusCard = (cardId, settledAreaId = null, focusSelector = null) => {
    if (settledAreaId) {
      try { SettledHouse.reveal(settledAreaId).catch(() => {}) } catch { /* non-fatal */ }
    }
    const el = document.getElementById(cardId)
    if (!el) return
    if (el.tagName === 'DETAILS') {
      el.open = true
      el.setAttribute('open', '')
    }
    try { el.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* non-fatal */ }
    if (focusSelector) {
      setTimeout(() => {
        try {
          const target = el.querySelector(focusSelector) || document.querySelector(focusSelector)
          if (target && typeof target.focus === 'function') target.focus()
        } catch { /* non-fatal */ }
      }, 80)
    }
  }

  const switchMainTab = (tabName) => {
    const btn = document.querySelector(`.opts-tab[data-tab="${tabName}"]`)
    if (btn && typeof btn.click === 'function') btn.click()
  }

  // 1. Vault tab hero chips & quick actions
  document.getElementById('vaultChipEncryption')?.addEventListener('click', () => {
    openAndFocusCard('vaultMgrCard', null, '#vaultSearch')
  })
  document.getElementById('vaultChipHealth')?.addEventListener('click', () => {
    openAndFocusCard('passwordHealthCard', 'password-health', '#phRefreshBtn')
  })
  document.getElementById('vaultChipSync')?.addEventListener('click', () => {
    switchMainTab('sync')
  })
  document.getElementById('vaultHeroAddBtn')?.addEventListener('click', () => {
    const addBtn = document.getElementById('newEntryBtn')
    if (addBtn && !addBtn.disabled) addBtn.click()
    else openAndFocusCard('vaultMgrCard', null, '#optsUnlockPass')
  })
  document.getElementById('vaultHeroSearchBtn')?.addEventListener('click', () => {
    openAndFocusCard('vaultMgrCard', null, '#vaultSearch')
  })
  document.getElementById('vaultHeroHealthBtn')?.addEventListener('click', () => {
    openAndFocusCard('passwordHealthCard', 'password-health', '#phRefreshBtn')
  })
  document.getElementById('vaultHeroSyncBtn')?.addEventListener('click', () => {
    switchMainTab('sync')
  })

  // 2. Security tab hero chips & quick actions
  document.getElementById('secChipMaster')?.addEventListener('click', () => {
    openAndFocusCard('secMasterCard', null, '#curMaster')
  })
  document.getElementById('secHeroMasterBtn')?.addEventListener('click', () => {
    openAndFocusCard('secMasterCard', null, '#curMaster')
  })
  document.getElementById('secChipAutoLock')?.addEventListener('click', () => {
    openAndFocusCard('secAutoLockCard', null, '#autoLockSelect')
  })
  document.getElementById('secHeroAutoLockBtn')?.addEventListener('click', () => {
    openAndFocusCard('secAutoLockCard', null, '#autoLockSelect')
  })
  document.getElementById('secChipBreach')?.addEventListener('click', () => {
    openAndFocusCard('secBreachCard', 'sec-breach', '#runBreachBtn')
  })
  document.getElementById('secHeroBreachBtn')?.addEventListener('click', () => {
    openAndFocusCard('secBreachCard', 'sec-breach', '#runBreachBtn')
    setTimeout(() => { document.getElementById('runBreachBtn')?.click() }, 120)
  })
  document.getElementById('secChipDoctor')?.addEventListener('click', () => {
    openAndFocusCard('syncDoctorCard', 'sec-sync-doctor', '#syncDoctorRun')
  })
  document.getElementById('secHeroVerifyBtn')?.addEventListener('click', () => {
    openAndFocusCard('secVerifyCard', 'sec-verify', '#selfCheckBtn')
  })

  // Keep #secChipAutoLockText synced with #autoLockSelect
  const syncAutoLockChip = () => {
    const sel = document.getElementById('autoLockSelect')
    const chipTxt = document.getElementById('secChipAutoLockText')
    if (sel && chipTxt) {
      const val = Number(sel.value)
      chipTxt.textContent = val > 0 ? `Auto-lock: ${val} min` : 'Auto-lock: disabled'
    }
  }
  document.getElementById('autoLockSelect')?.addEventListener('change', syncAutoLockChip)
  setTimeout(syncAutoLockChip, 250)

  // 3. Direct Share tab hero chips & quick actions
  document.getElementById('dsChipSend')?.addEventListener('click', () => {
    openAndFocusCard('dsShareCard', null, '#dsPickBtn')
  })
  document.getElementById('dsHeroPickBtn')?.addEventListener('click', () => {
    openAndFocusCard('dsShareCard', null, '#dsPickBtn')
    document.getElementById('dsPickBtn')?.click()
  })
  document.getElementById('dsChipReceive')?.addEventListener('click', () => {
    openAndFocusCard('dsHaveCard', null, '#dsPasteInvite')
  })
  document.getElementById('dsHeroPasteBtn')?.addEventListener('click', () => {
    openAndFocusCard('dsHaveCard', null, '#dsPasteInvite')
  })
  document.getElementById('dsChipLedger')?.addEventListener('click', () => {
    openAndFocusCard('dsLedgerCard', 'ds-ledger')
  })
  document.getElementById('dsHeroLedgerBtn')?.addEventListener('click', () => {
    openAndFocusCard('dsLedgerCard', 'ds-ledger')
  })

  // 4. Generator Lab tab hero chips & quick actions
  const clickLabTab = (labMode, focusSel = null) => {
    const btn = document.querySelector(`#labTabs .lab-tab[data-lab="${labMode}"]`)
    if (btn && typeof btn.click === 'function') btn.click()
    if (focusSel) {
      setTimeout(() => { document.querySelector(focusSel)?.focus() }, 60)
    }
  }
  document.getElementById('genChipPassword')?.addEventListener('click', () => clickLabTab('random', '#randLength'))
  document.getElementById('genChipPassphrase')?.addEventListener('click', () => clickLabTab('passphrase', '#ppWordsOpt'))
  document.getElementById('genChipAnalyze')?.addEventListener('click', () => clickLabTab('analyze', '#anInput'))
  document.getElementById('genChipMnemonic')?.addEventListener('click', () => clickLabTab('mnemonic', '#mnLength'))
  document.getElementById('genHeroRegenBtn')?.addEventListener('click', () => {
    document.getElementById('labRegenBtn')?.click()
  })
  document.getElementById('genHeroCopyBtn')?.addEventListener('click', () => {
    const copyBtn = document.getElementById('labCopyBtn')
    if (copyBtn && !copyBtn.disabled) copyBtn.click()
    else {
      document.getElementById('labRegenBtn')?.click()
      setTimeout(() => { document.getElementById('labCopyBtn')?.click() }, 60)
    }
  })
  document.getElementById('genHeroAnalyzeBtn')?.addEventListener('click', () => clickLabTab('analyze', '#anInput'))

  // 5. Wordlists tab hero chips & quick actions
  document.getElementById('wlChipEff')?.addEventListener('click', () => {
    switchMainTab('generator')
    setTimeout(() => clickLabTab('passphrase', '#ppWordlist'), 60)
  })
  document.getElementById('wlHeroOpenGenBtn')?.addEventListener('click', () => {
    switchMainTab('generator')
    setTimeout(() => clickLabTab('passphrase', '#ppWordlist'), 60)
  })
  document.getElementById('wlChipScrape')?.addEventListener('click', () => {
    document.getElementById('scrapeUrl')?.focus()
  })
  document.getElementById('wlHeroScrapeFocusBtn')?.addEventListener('click', () => {
    const urlInput = document.getElementById('scrapeUrl')
    if (urlInput && urlInput.value.trim()) document.getElementById('scrapeBtn')?.click()
    else urlInput?.focus()
  })
  document.getElementById('wlChipJson')?.addEventListener('click', () => {
    document.getElementById('importWordlistBtn')?.click()
  })
  document.getElementById('wlHeroImportBtn')?.addEventListener('click', () => {
    document.getElementById('importWordlistBtn')?.click()
  })

  // 6. Export / Import tab hero chips & quick actions
  document.getElementById('dataChipBackup')?.addEventListener('click', () => {
    openAndFocusCard('dataUnifiedHeaderCard', null, '#exportBtn')
  })
  document.getElementById('dataChipMigrate')?.addEventListener('click', () => {
    openAndFocusCard('migWizardCard', null, '#migPreviewBtn')
  })
  document.getElementById('dataHeroMigBtn')?.addEventListener('click', () => {
    openAndFocusCard('migWizardCard', null, '#migPreviewBtn')
  })
  document.getElementById('dataChipImportCenter')?.addEventListener('click', () => {
    const icEl = document.getElementById('icSources')
    if (icEl) {
      const card = icEl.closest('.card')
      if (card) {
        try { card.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* non-fatal */ }
      }
    }
  })
  document.getElementById('dataHeroIcBtn')?.addEventListener('click', () => {
    const icEl = document.getElementById('icSources')
    if (icEl) {
      const card = icEl.closest('.card')
      if (card) {
        try { card.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* non-fatal */ }
      }
    }
  })
  document.getElementById('dataChipDiag')?.addEventListener('click', () => {
    openAndFocusCard('diagCard', 'data-diagnostics', '#exportDiagBtn')
  })
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    init().catch(e => console.error('[UCrypt] options init failed:', e))
    wireUnifiedTabHeroes()
  })
} else {
  init().catch(e => console.error('[UCrypt] options init failed:', e))
  wireUnifiedTabHeroes()
}

// R135 (v2.92.0) — the additions-only surfaces (Sync Doctor, Chain Data
// Types, Cross-browser Import). The module is self-guarding: a missing card
// or a failed import can never break the core flows (the catch is the whole
// surface's blast radius).
import('./lib/r135-ui.js').catch(e => console.warn('[UCrypt] R135 surfaces unavailable:', e && e.message ? e.message : e))

// ═══ R139 §6 — THE APPS SCRIPT WIZARD (the CEO's S-164909 command) ═══
// The setup cliff removed: a step-by-step wizard for the Drive bridge —
// create (one button copies the exact script) → deploy (each screen NAMED,
// with the 'Who has access: Anyone' silent-killer warning) → paste the URL →
// run Test connection LIVE (the real verifyBridgeStages: url/ping/version/
// read) → the completion bar with a Close button that closes ONLY by the
// user's hand (the iron law: nothing auto-closes). The push-failure row
// deep-links here (D3: no truncated paths, the fix opens at the right step).
// Self-guarding: a missing mount can never break the core flows.
import('./lib/apps-script-wizard.js').then(async (WIZ) => {
  const wizardHost = document.getElementById('twWizardPanel')
  if (!wizardHost) return // the mount is additive — absent host, absent wizard
  const msg = (k, s, fb) => { try { return chrome.i18n.getMessage(k, s) || fb || k } catch { return fb || k } }
  let state = { stepIndex: 0, url: '', testSteps: [], testOk: false }

  function render() {
    wizardHost.textContent = ''
    const heading = document.createElement('h4')
    heading.textContent = msg('wizardHead', undefined, 'Set up the Google Drive bridge — step by step')
    wizardHost.appendChild(heading)
    WIZ.WIZARD_STEPS.forEach((step, i) => {
      const box = document.createElement('div')
      box.className = 'device-add-box'
      box.style.cssText = 'margin:6px 0 0'
      const label = document.createElement('strong')
      label.textContent = msg(step.key, undefined, step.fallback)
      box.appendChild(label)
      if (step.warning) {
        const warn = document.createElement('p')
        warn.className = 'sync-test-result'
        warn.style.display = 'block'
        warn.textContent = msg(step.warning, undefined, step.warningFallback)
        box.appendChild(warn)
      }
      if (step.copyButton) {
        const copy = document.createElement('button')
        copy.className = 'btn btn-outline btn-sm'
        copy.type = 'button'
        copy.textContent = msg('wizardCopyScript', undefined, 'Copy the script')
        copy.addEventListener('click', async () => {
          const btn = document.getElementById('twCopyBridgeScript') || document.getElementById('twCopyScript')
          if (btn) btn.click()
          else try { await navigator.clipboard.writeText('UCrypt Apps Script — use the script shown in the bridge card') } catch { /* manual copy */ }
          copy.textContent = msg('wizardCopied', undefined, 'Copied — paste it at script.google.com')
        })
        box.appendChild(copy)
      }
      if (step.input === 'url') {
        const input = document.createElement('input')
        input.type = 'url'
        input.placeholder = 'https://script.google.com/macros/s/…/exec'
        input.value = state.url
        input.style.cssText = 'width:100%;margin:6px 0'
        input.addEventListener('input', () => { state.url = input.value.trim() })
        box.appendChild(input)
      }
      if (step.action === 'test-connection') {
        const run = document.createElement('button')
        run.className = 'btn btn-primary btn-sm'
        run.type = 'button'
        run.textContent = msg('wizardRunTest', undefined, 'Run Test connection')
        run.addEventListener('click', async () => { await runTest(); render() })
        box.appendChild(run)
        for (const s of state.testSteps) {
          const row = document.createElement('p')
          row.style.cssText = 'margin:4px 0 0;font-size:12px'
          row.textContent = `${s.ok ? '✓' : '✗'} ${s.stage} — ${s.message}`
          box.appendChild(row)
        }
      }
      if (step.completionBar) {
        const bar = document.createElement('div')
        bar.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap'
        const live = document.createElement('span')
        live.textContent = state.testOk
          ? msg('wizardCompletionOk', undefined, 'Connection proven — you can close this wizard when ready.')
          : msg('wizardCompletionPending', undefined, 'The connection test has not passed yet — the bar stays with the failing step named.')
        bar.appendChild(live)
        const close = document.createElement('button')
        close.className = 'btn btn-ghost btn-sm'
        close.type = 'button'
        close.textContent = msg('wizardClose', undefined, 'Close')
        close.addEventListener('click', () => { wizardHost.hidden = true }) // closes ONLY by the user's hand
        bar.appendChild(close)
        box.appendChild(bar)
      }
      wizardHost.appendChild(box)
    })
  }

  async function runTest() {
    state.testSteps = []
    state.testOk = false
    try {
      const { verifyBridgeStages } = await import('./lib/transports/gdrive.js')
      const cfg = { scriptUrl: state.url }
      const secretField = document.querySelector('#twFields input[data-field-key="secret"]')
      if (secretField && secretField.value) cfg.secret = secretField.value.trim()
      const stages = await verifyBridgeStages(cfg)
      state.testSteps = stages
      state.testOk = stages.length > 0 && stages.every((s) => s.ok)
    } catch (e) {
      state.testSteps = [{ stage: 'test', ok: false, message: String((e && e.message) || e).slice(0, 160) }]
    }
  }

  // the D3 deep link: the wizard opens at the step named by the failure
  window.ucryptOpenAppsScriptWizard = function (atStep) {
    const idx = WIZ.WIZARD_STEPS.findIndex((s) => s.id === String(atStep || 'create'))
    state.stepIndex = idx >= 0 ? idx : 0
    wizardHost.hidden = false
    render()
    try { wizardHost.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* the scroll is enhancement */ }
  }

  render()
}).catch(e => console.warn('[UCrypt] R139 wizard unavailable:', e && e.message ? e.message : e))
