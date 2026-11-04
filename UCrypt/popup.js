/**
 * UCrypt — Popup logic (v2.5.0 — tabbed workbench + TOTP authenticator + health).
 *
 * Loaded as an ES module via <script type="module">.
 *
 * v2.3.0 redesign: the popup is now the primary "cryptographic toolbench":
 *   ┌ Generate ─ full 3-mode generator (password / passphrase / PIN) with
 *   │            inline options, presets, entropy readout and crack time.
 *   ├ Vault   ─ per-site entries + searchable all-entries list with
 *   │            copy-user / copy-pass / fill-this-row actions.
 *   ├ 2FA     ─ (v2.4.0) TOTP authenticator: tokens stored INSIDE the
 *   │            encrypted vault, live codes with countdown rings, QR move-
 *   │            to-phone export (+ PNG export since v2.5.0), otpauth://
 *   │            URI or manual enrollment.
 *   ├ Health  ─ (v2.5.0) vault-wide password health report: breach matches,
 *   │            weak entropy, reuse groups, score + worst-offenders list.
 *   └ Sync    ─ live sync status, one-click "Sync now", and the guided
 *              3-step setup handoff (sync code → cloud → sync).
 *
 * Everything runs locally; the only network ever touched is the user's own
 * cloud transport during an explicit sync.
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
      openOptionsPage: () => {},
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
  PassphraseFilterError,
  PRESETS,
} from './lib/generator.js'
import { analyzePassword, strengthBucket, strengthBadge, crackTime } from './lib/analyzer.js'
import { ensureBreachCorpus, ensureBip39, ensureWordlists } from './lib/corpus.js'
import { applyI18n, getMessage } from './lib/i18n.js'
import { registerBeamExecutor } from './lib/beam-executor-page.js'
import { mergePopupPrefs, applyPickedPrefs, mergeLabPrefs, getVaultSort, setVaultSort, vaultSortComparator, getPopupUi, savePopupUi, getBehaviorPrefs, BEHAVIOR_KEY } from './lib/prefs.js'
import {
  totp as computeTotp,
  parseOtpauthUri,
  isValidBase32Secret,
  normalizeSecret,
  buildOtpauthUri,
} from './lib/totp.js'

const STORAGE_KEY = 'ucrypt:prefs:popup'
const WORDLIST_KEY = 'ucrypt:customWordlist'

// v2.3.1: defaults + merging live in lib/prefs.js so the popup can no longer
// silently drop options-page settings (noDuplicates / noSequences /
// excludeChars) when it saves its own subset of fields.
const DEFAULTS = {
  random: {
    length: 20,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: true,
    // R56-GEN-POPUP-OPTIONS: the popup now RENDERS these three (engine +
    // manager + prefs shape always supported them); defaults match
    // lib/prefs.js POPUP_PREFS_DEFAULTS.
    noDuplicates: false,
    noSequences: false,
    excludeChars: '',
  },
  passphrase: {
    wordCount: 6,
    separator: '-',
    capitalize: true,
    addNumber: true,
    addSymbol: true,
  },
  pin: {
    length: 6,
    noRepeats: true,
    noSequences: true,
  },
}

let prefs = { ...DEFAULTS }
let lastResult = null
let allEntriesCache = []

// --- DOM helpers -----------------------------------------------------------

function $(id) { return document.getElementById(id) }

function toast(msg, kind = 'info') {
  const el = $('popupToast')
  if (!el) return
  // LAW 0.52 (R133) — the text rides its own span; the ✕ close is always present.
  const textEl = $('popupToastText')
  if (textEl) textEl.textContent = msg
  else el.textContent = msg
  el.className = 'popup-toast' + (kind === 'error' ? ' popup-toast-error' : '')
  // force reflow to restart animation
  void el.offsetWidth
  el.classList.remove('hidden')
  clearTimeout(toast._t)
  toast._t = setTimeout(() => el.classList.add('hidden'), 2500)
}

function show(el, on = true) {
  if (el) el.classList.toggle('hidden', !on)
}

// LAW 0.52 (R133) — the toast's explicit close (the user's own exit).
$('popupToastClose')?.addEventListener('click', () => {
  const el = $('popupToast')
  if (el) { clearTimeout(toast._t); el.classList.add('hidden') }
})

function setView(view) {
  show($('setupView'), view === 'setup')
  show($('lockedView'), view === 'locked')
  show($('unlockedView'), view === 'unlocked')
  show($('lockRow'), view === 'unlocked')
  show($('firstRunChoiceView'), view === 'firstRun')
  const dot = $('lockDot')
  const status = $('popupStatus')
  if (view === 'unlocked') {
    dot.style.background = 'var(--accent)'
    dot.title = getMessage('pDotUnlockTitle', undefined, 'Unlocked — click to lock')
    status.textContent = getMessage('pStatusUnlocked', undefined, 'Vault unlocked')
  } else if (view === 'locked') {
    dot.style.background = 'var(--amber)'
    dot.title = getMessage('pDotLockTitle', undefined, 'Locked')
    status.textContent = getMessage('pStatusLocked', undefined, 'Vault locked')
  } else {
    dot.style.background = 'var(--muted)'
    dot.title = getMessage('pDotNoVaultTitle', undefined, 'No vault set up')
    status.textContent = getMessage('pStatusSetup', undefined, 'Set up master passphrase')
  }
}

// --- Background messaging --------------------------------------------------

function bgSend(type, data = {}) {
  return new Promise((resolve) => {
    try {
      // v2.10.0 — payload spread FIRST so a data `type` field can never clobber
      // the message type on the wire (protocol fix, matches options.js bgSend).
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

async function loadPrefs() {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEY, (r) => {
      const saved = r && r[STORAGE_KEY]
      resolve(mergePopupPrefs(saved))
    })
  })
}

async function savePrefs() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEY]: prefs }, () => resolve())
  })
}

// --- Clipboard -------------------------------------------------------------

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    // R97 (F-R96-1): every vault-secret copy arms the lock-moment clipboard
    // guard (lib/clipguard.js — installed in init below).
    if (globalThis.UCryptClipGuard) globalThis.UCryptClipGuard.arm()
    return true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.cssText = 'position:fixed;left:-9999px;opacity:0'
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

async function copyWithToast(text, label = 'Copied — auto-clears in 20s') {
  const ok = await copy(text)
  if (ok) {
    toast(label)
    // Auto-clear clipboard after 20s if it still holds our value.
    setTimeout(async () => {
      try {
        const cur = await navigator.clipboard.readText().catch(() => '')
        if (cur === text) await navigator.clipboard.writeText('')
      } catch { /* the clipboard wipe is best-effort — a closed clipboard never perturbs the copy it cleans (named-swallow law, R169 C1) */ }
    }, 20000)
  } else {
    toast('Clipboard blocked — select the text to copy manually', 'error')
  }
  return ok
}

// --- Current tab/domain helper --------------------------------------------

function currentTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs && tabs[0])
    })
  })
}

function domainFromTab(tab) {
  if (!tab || !tab.url) return null
  try {
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) return null
    const u = new URL(tab.url)
    return u.hostname.replace(/^www\./, '')
  } catch {
    return null
  }
}

// --- Tabs ------------------------------------------------------------------

let activeTab = 'generate'

function switchTab(name) {
  activeTab = name
  document.querySelectorAll('.popup-tab').forEach(btn => {
    const on = btn.dataset.tab === name
    btn.classList.toggle('active', on)
    btn.setAttribute('aria-selected', String(on))
  })
  document.querySelectorAll('.popup-panel').forEach(p => {
    const on = p.id === `tab-${name}`
    p.classList.toggle('active', on)
    if (on) p.removeAttribute('hidden')
    else p.setAttribute('hidden', '')
  })
  if (name === 'vault') refreshVaultTab()
  if (name === 'sync') refreshSyncTab()
  if (name === 'totp') refreshTotpTab()
  if (name === 'health') refreshHealthTab()
}

// --- Generator modes -------------------------------------------------------

let activeMode = 'random'

/** Announce the current mode to assistive tech (#modeStatus live region). */
function announceMode(mode) {
  const el = $('modeStatus')
  if (!el) return
  const label = document.querySelector('.popup-seg[data-mode="' + mode + '"]')
  el.textContent = getMessage('modeStatusNow', [label ? label.textContent.trim() : mode], 'Generator mode: ' + (label ? label.textContent.trim() : mode))
}

/** R76 (F-R76-POPUP-1) — WAI-ARIA tabs keyboard model: roving tabindex +
 *  Arrow/Home/End, no focus trap; activation follows focus (automatic
 *  activation — the recommended pattern for this widget size). Ported from
 *  the R75 design the lost session regressed. */
function wireTablistKeyboard() {
  const tabs = [...document.querySelectorAll('.popup-seg')]
  for (const tab of tabs) {
    tab.addEventListener('keydown', (e) => {
      const idx = tabs.findIndex(t => t === e.currentTarget)
      let next = -1
      if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length
      else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length
      else if (e.key === 'Home') next = 0
      else if (e.key === 'End') next = tabs.length - 1
      if (next < 0) return
      e.preventDefault()
      e.stopPropagation()
      switchMode(tabs[next].dataset.mode)
      tabs[next].focus()
    })
  }
}

function switchMode(mode) {
  // R74 — the popup strip carries ALL SEVEN modes (owner screenshot
  // 20261001_192534); every mode runs the same canonical core as the Lab.
  if (!['random', 'passphrase', 'pin', 'pronounceable', 'bulk', 'analyze', 'mnemonic'].includes(mode)) mode = 'random'
  const leavingMnemonic = activeMode === 'mnemonic' && mode !== 'mnemonic'
  activeMode = mode
  prefs.lastMode = mode
  savePrefs()
  // R76 — a mnemonic NEVER outlives its mode: leaving Mnemonic drops the
  // in-memory result (the generic output clear below scrubs the words).
  if (leavingMnemonic) lastResult = null
  // R45: a mode switch clears the previous mode's output — leaving the old
  // random password on screen after switching to passphrase/PIN reads as a
  // result for the NEW mode and raced the journey reads too.
  const out = $('genOutput')
  if (out) out.textContent = getMessage('genOutputHint', undefined, 'Click generate ↓')
  const bits = $('genBits')
  if (bits) bits.textContent = ''
  const fill = $('genStrength')
  if (fill) fill.style.width = '0'
  const crack = $('genCrack')
  if (crack) crack.textContent = ''
  const copy = $('copyBtn')
  if (copy) copy.disabled = true
  document.querySelectorAll('.popup-seg').forEach(seg => {
    const on = seg.dataset.mode === mode
    seg.classList.toggle('active', on)
    // R76 (F-R76-POPUP-1): WAI-ARIA tabs semantics restored (the lost session
    // regressed them to aria-pressed buttons) — aria-selected + roving
    // tabindex, with the live #modeStatus announcing the current mode.
    seg.setAttribute('aria-selected', String(on))
    seg.setAttribute('tabindex', on ? '0' : '-1')
  })
  announceMode(mode)
  show($('opt-random'), mode === 'random')
  show($('opt-passphrase'), mode === 'passphrase')
  show($('opt-pin'), mode === 'pin')
  show($('opt-pronounceable'), mode === 'pronounceable')
  show($('opt-bulk'), mode === 'bulk')
  show($('opt-mnemonic'), mode === 'mnemonic')
  show($('presetRow'), mode === 'random')
  // R74 — mode-specific panels: analyze replaces the output with an input
  // (auto-scrubbed); bulk replaces it with the session-only list; mnemonic
  // shares the output but NEVER offers Use/Save.
  show($('analyzePanel'), mode === 'analyze')
  show($('bulkListPanel'), mode === 'bulk')
  show($('mnCheckPanel'), mode === 'mnemonic')
  if (out) show(out, mode !== 'bulk' && mode !== 'analyze')
  // Hide the single-secret action rows in analyze/bulk/mnemonic modes.
  const useBtn = $('useBtn')
  const saveBtn = $('saveGenEntryBtn')
  const actionRows = useBtn && saveBtn ? [useBtn.parentElement, saveBtn.parentElement] : []
  actionRows.forEach(row => show(row, mode === 'random' || mode === 'passphrase' || mode === 'pin' || mode === 'pronounceable'))
  // Auto-scrub the analyze input when leaving the Analyze tab.
  if (mode !== 'analyze') scrubAnalyzeInput()
  if (mode === 'bulk') popupBulkRender()
  const genBtn = $('genBtn')
  if (genBtn) {
    const labelKey = mode === 'bulk' ? 'bulkGenerate' : mode === 'analyze' ? 'anBtn' : mode === 'mnemonic' ? 'mnGenerateBtn' : 'genBtn'
    genBtn.textContent = getMessage(labelKey, undefined, mode === 'bulk' ? 'Generate all' : mode === 'analyze' ? 'Analyze' : mode === 'mnemonic' ? 'Generate phrase' : 'Generate')
  }
  // Open the options box by default for the new modes (their controls matter).
  const box = $('optionsBox')
  if (box && (mode === 'bulk' || mode === 'mnemonic')) box.open = true
}

function analyzeModeSafe() { /* reserved: no global analysis state in the popup */ }
void analyzeModeSafe

// --- R56-GEN-POPUP-OPTIONS helpers -----------------------------------------

/** Normalize the exclude-chars input: unique characters, spaces preserved
 *  deliberately (they ARE a valid pool character), length-capped. Pure. */
function sanitizeExcludeChars(raw) {
  const s = typeof raw === 'string' ? raw.slice(0, 64) : ''
  return [...new Set([...s])].join('')
}

/** Show which characters will actually be excluded (deduped) — an honest
 *  preview so the user sees the effective set before generating. */
function updateExcludeHint() {
  const hint = $('randExcludeHint')
  if (!hint) return
  const eff = sanitizeExcludeChars($('randExcludeChars').value)
  if (!eff) { hint.classList.add('hidden'); hint.textContent = ''; return }
  hint.classList.remove('hidden')
  hint.textContent = getMessage('genExcludeHint', [eff], `Will avoid: ${eff}`)
}

function prefsFromUI() {
  if (activeMode === 'random') {
    prefs = applyPickedPrefs(prefs, 'random', {
      length: +$('randLength').value,
      lowercase: $('randLower').checked,
      uppercase: $('randUpper').checked,
      numbers: $('randNumbers').checked,
      symbols: $('randSymbols').checked,
      excludeAmbiguous: $('randExcludeAmbiguous').checked,
      // R56-GEN-POPUP-OPTIONS: restored controls (same fields the manager
      // Generator tab persists; applyPickedPrefs keeps unknown extras).
      noDuplicates: $('randNoDuplicates').checked,
      noSequences: $('randNoSequences').checked,
      excludeChars: sanitizeExcludeChars($('randExcludeChars').value),
    })
    return prefs.random
  }
  if (activeMode === 'passphrase') {
    prefs = applyPickedPrefs(prefs, 'passphrase', {
      wordCount: +$('ppWords').value,
      separator: $('ppSeparator').value,
      capitalize: $('ppCapitalize').checked,
      addNumber: $('ppAddNumber').checked,
      addSymbol: $('ppAddSymbol').checked,
      // R72: wordlist choice + padding travel with the shared prefs
      wordlist: $('ppWordlistSel').value,
      padBetweenWords: $('ppPadBetween').checked,
    })
    return prefs.passphrase
  }
  if (activeMode === 'pronounceable') {
    prefs = applyPickedPrefs(prefs, 'pronounceable', {
      syllables: +$('prSyl').value,
      capitalize: $('prCap').checked,
      addNumber: $('prNum').checked,
      addSymbol: $('prSym').checked,
    })
    return prefs.pronounceable
  }
  prefs = applyPickedPrefs(prefs, 'pin', {
    length: +$('pinLength').value,
    noRepeats: $('pinNoRepeats').checked,
    noSequences: $('pinNoSequences').checked,
  })
  return prefs.pin
}

// R74 — bulk/mnemonic popup prefs (per-surface memory, unknown fields survive)
function popupBulkPrefsFromUI() {
  prefs = applyPickedPrefs(prefs, 'bulk', {
    count: Math.max(2, Math.min(100, parseInt($('bulkCount').value, 10) || 10)),
    mode: $('bulkMode').value,
  })
  return prefs.bulk
}

function popupMnemonicPrefsFromUI() {
  const len = parseInt($('mnWords').value, 10) || 12
  prefs = applyPickedPrefs(prefs, 'mnemonic', { length: len })
  return prefs.mnemonic
}

function prefsToUI() {
  // password
  $('randLength').value = prefs.random.length
  $('randLengthVal').textContent = prefs.random.length
  $('randLower').checked = prefs.random.lowercase
  $('randUpper').checked = prefs.random.uppercase
  $('randNumbers').checked = prefs.random.numbers
  $('randSymbols').checked = prefs.random.symbols
  $('randExcludeAmbiguous').checked = prefs.random.excludeAmbiguous
  // R56-GEN-POPUP-OPTIONS: restored controls reflect the STORED prefs (values
  // previously set in the manager Generator tab now show up here too).
  $('randNoDuplicates').checked = !!prefs.random.noDuplicates
  $('randNoSequences').checked = !!prefs.random.noSequences
  $('randExcludeChars').value = typeof prefs.random.excludeChars === 'string' ? prefs.random.excludeChars : ''
  updateExcludeHint()
  // passphrase
  $('ppWords').value = prefs.passphrase.wordCount
  $('ppWordsVal').textContent = prefs.passphrase.wordCount
  $('ppSeparator').value = prefs.passphrase.separator
  $('ppCapitalize').checked = prefs.passphrase.capitalize
  $('ppAddNumber').checked = prefs.passphrase.addNumber
  $('ppAddSymbol').checked = prefs.passphrase.addSymbol
  // pin
  $('pinLength').value = prefs.pin.length
  $('pinLengthVal').textContent = prefs.pin.length
  $('pinNoRepeats').checked = prefs.pin.noRepeats
  $('pinNoSequences').checked = prefs.pin.noSequences
  // R74 — bulk + mnemonic popup prefs restore (per-surface memory)
  if (prefs.bulk) {
    $('bulkCount').value = String(Math.max(2, Math.min(100, parseInt(prefs.bulk.count, 10) || 10)))
    $('bulkCountVal').textContent = $('bulkCount').value
    $('bulkMode').value = ['random', 'passphrase', 'pin', 'pronounceable'].includes(prefs.bulk.mode) ? prefs.bulk.mode : 'random'
  }
  if (prefs.mnemonic) $('mnWords').value = String([12, 15, 18, 21, 24].includes(parseInt(prefs.mnemonic.length, 10)) ? parseInt(prefs.mnemonic.length, 10) : 12)
  // pronounceable (R72)
  const pr = prefs.pronounceable || {}
  $('prSyl').value = pr.syllables || 4
  $('prSylVal').textContent = String(pr.syllables || 4)
  $('prCap').checked = pr.capitalize !== false
  $('prNum').checked = pr.addNumber !== false
  $('prSym').checked = pr.addSymbol !== false
  // passphrase R72 extras
  $('ppWordlistSel').value = prefs.passphrase.wordlist || 'large'
  $('ppPadBetween').checked = !!prefs.passphrase.padBetweenWords
  // mode + presets visibility
  switchMode(prefs.lastMode || 'random')
}

// --- Generate --------------------------------------------------------------

let popupAutoHideTimer = null
let popupMasked = false

function popupSetMasked(masked) {
  popupMasked = masked
  const out = $('genOutput')
  if (!out || !lastResult) return
  if (masked) {
    out.textContent = '•'.repeat(Math.min(String(lastResult.value).length, 32))
    out.classList.add('lab-masked')
    out.title = getMessage('popupMaskedTitle', undefined, 'Hidden automatically — click to show again')
  } else {
    out.textContent = lastResult.value
    out.classList.remove('lab-masked')
    out.title = ''
  }
}

async function handleGenerate() {
  // R74 — the three analysis/multi modes route to their own flows; the four
  // generating modes share the canonical single-secret path below.
  if (activeMode === 'bulk') return popupBulkGenerate()
  if (activeMode === 'analyze') return runAnalyze()
  if (activeMode === 'mnemonic') return popupMnemonicGenerate()
  const opts = prefsFromUI()
  try {
    // v2.21.0 — R30-F1: the corpora load lazily on first use (the popup no
    // longer parses ~211 KB on every open). Passphrase mode needs the
    // wordlists; every mode's strength meter needs the breach corpus.
    if (activeMode === 'passphrase') {
      await ensureWordlists()
      if (opts.wordlist === 'custom') {
        const { [WORDLIST_KEY]: w } = await chrome.storage.local.get(WORDLIST_KEY)
        let words = null
        try { words = w ? (Array.isArray(w) ? w : JSON.parse(w)) : null } catch { words = null }
        if (!words || words.length < 10) {
          toast(getMessage('ppWlCustomEmpty', undefined, 'No custom wordlist on this device yet — build one in the Generator Lab.'), 'error')
          return
        }
        opts.customWords = words
      }
    }
    await ensureBreachCorpus()
    let result
    if (activeMode === 'passphrase') result = generatePassphrase(opts)
    else if (activeMode === 'pin') result = generatePin(opts)
    else if (activeMode === 'pronounceable') result = generatePronounceable(opts)
    else result = generateRandomPassword(opts)
    lastResult = result
    popupSetMasked(false)
    $('genOutput').textContent = result.value
    $('genBits').textContent = `≈ ${Math.round(result.entropyBits)} bits · ${result.kind}`
    const analysis = analyzePassword(result.value)
    // R74 §4 (F-R74-GEN-1): a GENERATED secret is judged by the canonical
    // constrained model bits — the model-blind char-level re-derivation can
    // EXCEED them (digits-only noSequences L13: 43.2 naive vs 37.0 canonical;
    // a 5-word passphrase: ~141 char-level vs 51.6 canonical) and the badge
    // and crack estimate must never claim more than the model permits.
    if (analysis) analysis.effective = result.entropyBits
    const badge = strengthBadge(analysis)
    const fill = $('genStrength')
    fill.style.width = badge.score + '%'
    fill.style.background = badge.color
    fill.title = `${badge.label} · ${crackTime(analysis.effective)} to crack (offline estimate)`
    $('genCrack').textContent = `${badge.label} · ${crackTime(analysis.effective)} offline`
    $('genCrack').setAttribute('aria-label', `${badge.label}, offline crack estimate ${crackTime(analysis.effective)}`)
    $('copyBtn').disabled = false
    $('useBtn').disabled = false
    $('saveGenEntryBtn').disabled = false
    genResultHints()
    // R72 §3.2 — display-only auto-hide (the Lab's setting; masking
    // only — never closes anything, never touches the clipboard).
    if (popupAutoHideTimer) clearTimeout(popupAutoHideTimer)
    let autoHide = 30
    try {
      const { [STORAGE_KEY]: saved } = await chrome.storage.local.get(STORAGE_KEY)
      autoHide = mergeLabPrefs(saved && saved.lab).autoHideSeconds
    } catch { /* default 30 s */ }
    if (autoHide > 0) {
      popupAutoHideTimer = setTimeout(() => { if (lastResult) popupSetMasked(true) }, autoHide * 1000)
    }
    // Touch the vault (keep it unlocked)
    bgSend('TOUCH').catch(() => {})
  } catch (e) {
    if (e instanceof PassphraseFilterError) {
      toast(getMessage('labFilterToast', [String(e.filteredSize), String(e.wordCount)], `Filters leave only ${e.filteredSize} words — relax them in the Generator Lab (needs ${e.wordCount}).`), 'error')
      return
    }
    toast(e.message, 'error')
  }
}

// --- R74 §5 — Bulk (popup parity with the Generator Lab) --------------------

let popupBulk = [] // session memory only — same contract as the Lab's batch

/** Options for an ARBITRARY mode from the popup's own option groups (the
 *  fields keep their last-used values even when another tab is active). */
function collectModeOptions(mode) {
  if (mode === 'random') {
    return {
      length: +$('randLength').value,
      lowercase: $('randLower').checked,
      uppercase: $('randUpper').checked,
      numbers: $('randNumbers').checked,
      symbols: $('randSymbols').checked,
      excludeAmbiguous: $('randExcludeAmbiguous').checked,
      noDuplicates: $('randNoDuplicates').checked,
      noSequences: $('randNoSequences').checked,
      excludeChars: sanitizeExcludeChars($('randExcludeChars').value),
    }
  }
  if (mode === 'passphrase') {
    return {
      wordCount: +$('ppWords').value,
      separator: $('ppSeparator').value,
      capitalize: $('ppCapitalize').checked,
      addNumber: $('ppAddNumber').checked,
      addSymbol: $('ppAddSymbol').checked,
      wordlist: $('ppWordlistSel').value,
      padBetweenWords: $('ppPadBetween').checked,
    }
  }
  if (mode === 'pronounceable') {
    return {
      syllables: +$('prSyl').value,
      capitalize: $('prCap').checked,
      addNumber: $('prNum').checked,
      addSymbol: $('prSym').checked,
    }
  }
  if (mode === 'pin') {
    return {
      length: +$('pinLength').value,
      noRepeats: $('pinNoRepeats').checked,
      noSequences: $('pinNoSequences').checked,
    }
  }
  return {}
}

async function loadCustomWords() {
  const { [WORDLIST_KEY]: w } = await chrome.storage.local.get(WORDLIST_KEY)
  try {
    const words = w ? (Array.isArray(w) ? w : JSON.parse(w)) : null
    return words && words.length >= 10 ? words : null
  } catch { return null }
}

async function popupBulkGenerate() {
  const bp = popupBulkPrefsFromUI()
  const count = Math.max(2, Math.min(100, parseInt($('bulkCount').value, 10) || bp.count || 10))
  $('bulkCount').value = String(count)
  const mode = $('bulkMode').value
  try {
    if (mode === 'passphrase') await ensureWordlists()
    await ensureBreachCorpus()
    const base = collectModeOptions(mode)
    if (mode === 'passphrase' && base.wordlist === 'custom') {
      const words = await loadCustomWords()
      if (!words) {
        toast(getMessage('ppWlCustomEmpty', undefined, 'No custom wordlist on this device yet — build one in the Generator Lab.'), 'error')
        return
      }
      base.customWords = words
    }
    popupBulk = []
    for (let i = 0; i < count; i++) {
      let r
      if (mode === 'passphrase') r = generatePassphrase(base)
      else if (mode === 'pin') r = generatePin(base)
      else if (mode === 'pronounceable') r = generatePronounceable(base)
      else r = generateRandomPassword(base)
      popupBulk.push(r)
    }
    popupBulkRender()
  } catch (e) {
    toast(e.message, 'error')
  }
}

function popupBulkRender() {
  const list = $('bulkList')
  if (!list) return
  list.textContent = ''
  const has = popupBulk.length > 0
  $('bulkCopyAllBtn').disabled = !has
  $('bulkDownloadBtn').disabled = !has
  $('bulkClearBtn').disabled = !has
  popupBulk.forEach((r, i) => {
    const row = document.createElement('div')
    row.className = 'popup-bulk-row'
    row.setAttribute('role', 'listitem')
    const num = document.createElement('span')
    num.className = 'popup-bulk-num'
    num.textContent = String(i + 1)
    const val = document.createElement('span')
    val.className = 'popup-bulk-val'
    val.textContent = r.value
    val.title = `≈${Math.round(r.entropyBits)} bits · ${r.kind}`
    row.append(num, val)
    list.appendChild(row)
  })
}

async function popupBulkCopyAll() {
  if (!popupBulk.length) return
  try {
    await navigator.clipboard.writeText(popupBulk.map(r => r.value).join('\n'))
    toast(getMessage('bulkCopiedToast', [String(popupBulk.length)], `${popupBulk.length} secrets copied — the clipboard holds every one of them.`))
  } catch {
    toast(getMessage('toastCopyFailed', undefined, 'Copy failed'), 'error')
  }
}

function popupBulkDownload() {
  if (!popupBulk.length) return
  // Same contract as the Lab: a local Blob download, never a transport push.
  const blob = new Blob([popupBulk.map(r => r.value).join('\n') + '\n'], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ucrypt-bulk-${new Date().toISOString().slice(0, 10)}.txt`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
  toast(getMessage('bulkDownloadedToast', undefined, 'Plaintext .txt downloaded — anyone holding the file holds every secret in it.'))
}

function popupBulkClear() {
  popupBulk = []
  popupBulkRender()
}

// --- R74 §5 — Analyze (paste-any-secret, auto-scrubbed) ---------------------

async function runAnalyze() {
  const raw = $('anInput').value || ''
  if (!raw.trim()) {
    toast(getMessage('anEmptyToast', undefined, 'Paste a password or passphrase to analyze first.'), 'error')
    return
  }
  try { await ensureBreachCorpus() } catch { /* analysis continues without breach data */ }
  const a = analyzePassword(raw)
  const panel = $('anResult')
  if (!a) { panel.classList.add('hidden'); return }
  panel.classList.remove('hidden')
  const badge = strengthBadge(a)
  const fill = $('anStrength')
  fill.style.width = badge.score + '%'
  fill.style.background = badge.color
  $('anBits').textContent = `≈ ${Math.round(a.effective)} bits · ${a.len} chars`
  $('anCrack').textContent = `${badge.label} · ${crackTime(a.effective)} offline`
  const notes = []
  if (a.breached) notes.push(getMessage('anBreached', undefined, '⚠ Appears in the local breach corpus — change it everywhere.'))
  if (Array.isArray(a.patterns) && a.patterns.length) notes.push(`${getMessage('anPatterns', undefined, 'Patterns detected')}: ${a.patterns.slice(0, 3).join(', ')}`)
  $('anNotes').textContent = notes.join(' ')
}

function scrubAnalyzeInput() {
  const inp = $('anInput')
  if (inp && inp.value) inp.value = ''
  const res = $('anResult')
  if (res) res.classList.add('hidden')
}

// --- R74 §5 — Mnemonic (same isolation contract as the Lab) -----------------

async function popupMnemonicGenerate() {
  const mp = popupMnemonicPrefsFromUI()
  const words = mp.length || 12
  // High-risk confirm BEFORE display — same gate as the Lab's tool.
  const warned = getMessage('mnWarning', undefined, 'Wallet recovery phrase — anyone holding these words holds the funds. UCrypt never saves, syncs or logs them.')
  if (!confirm(`${warned}\n\n${getMessage('mnConfirmGenerate', undefined, 'Generate a recovery phrase now?')}`)) return
  try {
    // R74 — the popup lazy-loads the BIP-39 corpus exactly like the Lab does
    // (the 2048-word list is never in the initial popup parse).
    await ensureBip39()
    const result = await generateMnemonic({ words })
    lastResult = result
    popupSetMasked(false)
    $('genOutput').textContent = result.value
    $('genBits').textContent = `≈ ${Math.round(result.entropyBits)} bits · ${result.kind}`
    $('genStrength').style.width = '100%'
    $('genStrength').style.background = '#10b981'
    $('genCrack').textContent = getMessage('labMnCrack', undefined, '128+ bits of entropy — offline brute force is not the threat model; handle the words accordingly.')
    $('copyBtn').disabled = false
    if (popupAutoHideTimer) clearTimeout(popupAutoHideTimer)
    let autoHide = 30
    try {
      const { [STORAGE_KEY]: saved } = await chrome.storage.local.get(STORAGE_KEY)
      autoHide = mergeLabPrefs(saved && saved.lab).autoHideSeconds
    } catch { /* default 30 s */ }
    if (autoHide > 0) popupAutoHideTimer = setTimeout(() => { if (lastResult) popupSetMasked(true) }, autoHide * 1000)
  } catch (e) {
    toast(e.message, 'error')
  }
}

async function popupMnemonicCheck() {
  const raw = ($('mnCheckInput').value || '').trim()
  const out = $('mnCheckOut')
  if (!raw || !out) return
  out.classList.remove('hidden')
  try {
    await ensureBip39()
    const r = await validateMnemonic(raw)
    if (r.valid) {
      out.textContent = getMessage('mnCheckOk', [String(r.wordCount), String(r.entropyBits)], `✓ Valid BIP-39 phrase — ${r.wordCount} words, ≈${r.entropyBits} bits. Checksum OK.`)
    } else if (r.reason === 'bad-length') {
      out.textContent = getMessage('mnCheckBadLength', [String(r.wordCount)], `✗ Bad length (${r.wordCount} words).`)
    } else if (r.reason === 'unknown-word') {
      out.textContent = getMessage('mnCheckUnknown', [(r.unknownWords || []).join(', ')], `✗ Unknown word(s): ${(r.unknownWords || []).join(', ')}.`)
    } else {
      out.textContent = getMessage('mnCheckBadChecksum', undefined, '✗ Checksum failed — the phrase is mistyped.')
    }
  } catch {
    out.textContent = getMessage('mnCheckBadChecksum', undefined, '✗ Checksum failed — the phrase is mistyped.')
  } finally {
    // The pasted phrase is a secret — scrub it as soon as validation ran.
    $('mnCheckInput').value = ''
  }
}

// R72 §9 — Use on page: explicit press, worker relay, native-setter fill on
// an eligible password field, NEVER a submit.
async function useOnPage() {
  if (!lastResult) return
  const r = await bgSend('USE_GENERATED_SECRET', { value: lastResult.value })
  if (r && r.ok) toast(getMessage('labUseFilled', undefined, 'Filled on the page — nothing was submitted'))
  else toast((r && r.error) || getMessage('labUseNoField', undefined, 'No eligible password field found on the current page'), 'error')
}

// R72 §9 — Save to UCrypt: the SAME atomic worker save path the vault uses.
// Generated secrets are never saved merely because they were generated.
async function saveGenerated() {
  if (!lastResult) return
  const tab = await currentTab()
  const domain = domainFromTab(tab)
  if (!domain) {
    toast(getMessage('labSaveNoSite', undefined, 'No site detected — open the Generator Lab in the manager to save with a custom name'), 'error')
    return
  }
  // Truthful breach gate: a fresh random secret is never in the corpus, but
  // the check stays honest for every mode and future source.
  try {
    await ensureBreachCorpus()
    const a = analyzePassword(lastResult.value)
    if (a && a.breached && !confirm(getMessage('labSaveBreached', undefined, 'This secret matches a known breached password. Save it anyway?'))) return
  } catch { /* corpus failure must not block an explicit save */ }
  const r = await bgSend('SAVE_ENTRY', { domain, username: '', password: lastResult.value, note: '', uris: [] })
  if (r && r.ok) toast(getMessage('toastEntrySaved', undefined, 'Entry saved'))
  else toast((r && r.error) || getMessage('toastSaveFailed', undefined, 'Save failed — try again; if it repeats, unlock the vault once.'), 'error')
}

// --- Vault tab -------------------------------------------------------------

function mask(s) {
  if (!s) return ''
  s = String(s)
  if (s.length <= 2) return s[0] + '•'.repeat(Math.max(0, s.length - 1))
  return s[0] + '•'.repeat(s.length - 2) + s[s.length - 1]
}

function entryRow(entry, { withFill = true } = {}) {
  const row = document.createElement('div')
  row.className = 'popup-entry-row'

  const info = document.createElement('div')
  info.className = 'popup-entry-info'
  const u = document.createElement('div')
  u.className = 'popup-entry-user'
  u.textContent = entry.username || '(no username)'
  const d = document.createElement('div')
  d.className = 'popup-entry-sub'
  d.textContent = entry.domain + ' · ' + mask(entry.password)
  info.appendChild(u)
  info.appendChild(d)

  const actions = document.createElement('div')
  actions.className = 'popup-entry-actions'
  const mkBtn = (label, title, fn, primary = false) => {
    const b = document.createElement('button')
    b.className = 'popup-btn popup-btn-mini' + (primary ? ' popup-btn-mini-primary' : '')
    b.textContent = label
    b.title = title
    b.addEventListener('click', fn)
    return b
  }
  if (withFill) {
    actions.appendChild(mkBtn('Fill', 'Fill this login on the page', () => fillEntry(entry), true))
  }
  actions.appendChild(mkBtn('Copy user', 'Copy username', () => copyWithToast(entry.username || '', 'Username copied')))
  actions.appendChild(mkBtn('Copy pass', 'Copy password', () => copyWithToast(entry.password || '', 'Password copied — clears in 20s')))
  row.appendChild(info)
  row.appendChild(actions)
  return row
}

function emptyState(text) {
  const p = document.createElement('p')
  p.className = 'popup-empty'
  p.textContent = text
  return p
}

// v2.7.0 — "migrate from your old browser" nudge: an actionable empty state.
// Only shown when the vault is unlocked and completely empty of logins.
function importNudge() {
  const wrap = document.createElement('div')
  wrap.className = 'popup-import-nudge'
  const p = document.createElement('p')
  p.className = 'popup-empty'
  p.textContent = 'Coming from Chrome, Firefox, Edge, Brave or a password manager?'
  const btn = document.createElement('button')
  btn.type = 'button'
  btn.className = 'btn btn-outline btn-sm'
  btn.textContent = '📥 Import passwords, bookmarks & history'
  btn.addEventListener('click', async (e) => {
    e.preventDefault()
    try {
      await chrome.runtime.openOptionsPage()
    } catch {
      window.open(chrome.runtime.getURL('options.html#data'), '_blank')
    }
    window.close()
  })
  wrap.appendChild(p)
  wrap.appendChild(btn)
  return wrap
}

const isLogin = (e) => !!e && (e.type === undefined || e.type === null || e.type === 'login')

async function fillEntry(entry) {
  const tab = await currentTab()
  if (!tab || !tab.id) { toast('No active tab', 'error'); return }
  const r = await bgSend('FILL_ENTRY', { tabId: tab.id, entry })
  if (r && r.ok) {
    window.close()
  } else {
    toast((r && r.error) || 'Could not fill', 'error')
  }
}

async function refreshVaultTab() {
  const tab = await currentTab()
  const domain = domainFromTab(tab)
  $('currentDomain').textContent = domain || '—'
  $('fillBtn').disabled = !domain
  // R95 §2 U-6 — the disabled Fill names its reason (the armed control
  // keeps its clean label without a tooltip).
  if (domain) $('fillBtn').removeAttribute('title')
  else $('fillBtn').title = getMessage('fillDisabledHint', undefined, 'Open a login page first — Fill needs a site to fill on.')

  const siteBox = $('siteEntries')
  siteBox.textContent = ''

  const r = domain ? await bgSend('GET_ENTRIES', { domain }) : { ok: true, entries: [] }
  // v2.7.0 — TOTP tokens and imported other-data never appear in login lists.
  const siteEntries = ((r && r.ok && r.entries) || []).filter(isLogin)
  if (r && r.ok && r.locked) {
    // R95 F-95-06 (filed P4): the locked state names its fix — and now does
    // so in EVERY locale (was hardcoded EN; the 13-year-old law is per-locale).
    siteBox.appendChild(emptyState(getMessage('pListLocked', undefined, 'Vault is locked — unlock to see saved logins.')))
  } else if (siteEntries.length === 0) {
    siteBox.appendChild(emptyState(domain
      ? getMessage('pNoLoginsFor', [domain], `No saved logins for ${domain} yet.`)
      : getMessage('pNoLoginsOpenSite', undefined, 'Open a website to see its logins.')))
  } else {
    siteEntries.forEach(e => siteBox.appendChild(entryRow(e)))
  }

  const all = await bgSend('GET_ALL_ENTRIES')
  // v2.7.0 — vault tab counts and lists LOGINS; tokens live in the 2FA tab,
  // imported other-data in the options' "Other imported data" pane.
  const allRaw = ((all && all.ok && all.entries) || [])
  allEntriesCache = allRaw.filter(isLogin)
  $('allCount').textContent = String(allEntriesCache.length)
  $('entryCount').textContent = String(allEntriesCache.length)
  renderAllEntries()

  // v2.7.0 — first-run migration nudge (unlocked + completely empty vault,
  // regardless of the current site — that is exactly when it matters).
  if (allRaw.length === 0 && all && all.ok && !all.locked) {
    const box2 = $('allEntries')
    if (box2 && !box2.querySelector('.popup-import-nudge')) box2.appendChild(importNudge())
  }
}

function renderAllEntries() {
  const box = $('allEntries')
  box.textContent = ''
  const q = ($('vaultFilter').value || '').trim().toLowerCase()
  const list = q
    ? allEntriesCache.filter(e =>
        (e.domain || '').toLowerCase().includes(q) ||
        (e.username || '').toLowerCase().includes(q))
    : allEntriesCache
  if (list.length === 0) {
    box.appendChild(emptyState(q ? 'No matches.' : 'No entries yet — save one from a login form or the settings.'))
    if (!q) {
      // R111 §4.2 — DOOR 3: the popup's empty-vault state links to the
      // import front door (the options page's Data tab — the standing
      // wizard; no new import path). The handoff flag opens THAT tab.
      const door = document.createElement('button')
      door.className = 'popup-btn popup-btn-ghost'
      door.type = 'button'
      door.textContent = getMessage('popupImportDoor', undefined, 'Import from another browser')
      door.addEventListener('click', async () => {
        try { await chrome.storage.local.set({ 'ucrypt:openTab': 'data' }) } catch { /* the options page still opens */ }
        try { await chrome.runtime.openOptionsPage() } catch { /* the popup closes either way */ }
        try { window.close() } catch { /* toolbar popups close themselves */ }
      })
      box.appendChild(door)
      // R112 §2 — the DIRECT SHARE door (D1: works with no chain and no
      // vault — only UCrypt). R118 §2.2: the door routes to its OWN tab —
      // the Direct Share tab (the 'share' handoff; the two-tab world).
      // The line names what it is; the button is the one click.
      const dsLine = document.createElement('p')
      dsLine.className = 'popup-empty'
      dsLine.style.margin = '8px 0 4px'
      dsLine.textContent = getMessage('dsPopupEmptyLine', undefined, 'Share a file with any UCrypt user — Direct Share, no account needed.')
      box.appendChild(dsLine)
      const dsDoor = document.createElement('button')
      dsDoor.className = 'popup-btn popup-btn-ghost'
      dsDoor.type = 'button'
      dsDoor.textContent = getMessage('dsPopupEmptyBtn', undefined, 'Open Direct Share')
      dsDoor.addEventListener('click', async () => {
        try { await chrome.storage.local.set({ 'ucrypt:openTab': 'share' }) } catch { /* the options page still opens */ }
        try { await chrome.runtime.openOptionsPage() } catch { /* the popup closes either way */ }
        try { window.close() } catch { /* toolbar popups close themselves */ }
      })
      box.appendChild(dsDoor)
    }
    return
  }
  // v2.16.0 — user-selectable sort (Brave-gap): site / name / recently used /
  // recently changed, shared with the options vault manager.
  const sorted = [...list].sort(vaultSortComparator(vaultSortMode))
  sorted.slice(0, 50).forEach(e => box.appendChild(entryRow(e, { withFill: (e.domain || '') === ($('currentDomain').textContent || '') })))
  if (sorted.length > 50) {
    const p = document.createElement('p')
    p.className = 'popup-empty'
    p.textContent = `…and ${sorted.length - 50} more — use the filter or "Manage vault".`
    box.appendChild(p)
  }
}

// --- Sync tab --------------------------------------------------------------

let vaultSortMode = 'site' // v2.16.0 — shared with options (lib/prefs.js helpers)

const TRANSPORT_LABELS = {
  gdrive: 'Google Drive',
  dropbox: 'Dropbox',
  github: 'GitHub Gist',
  webdav: 'WebDAV',
  custom: 'Custom URL',
}

// v2.18.0 — R28-i18n (wave 5): the transport display name resolves through the
// shared twName* catalogs with the label map as the hard fallback.
const transportLabel = (id) =>
  getMessage(`twName${id ? id[0].toUpperCase() + id.slice(1) : ''}`, undefined, TRANSPORT_LABELS[id] || id || '')

async function refreshSyncTab() {
  const r = await bgSend('GET_STATE')
  const sync = (r && r.sync) || {}
  // v2.13.1 — R23-F2: this row is labeled just "Entries" — count what the
  // synced blob really carries (logins + tokens + other-data), not logins alone.
  $('syncEntries').textContent = String(sync.totalCount ?? sync.entryCount ?? 0)
  $('syncLast').textContent = sync.lastModified ? new Date(sync.lastModified).toLocaleString() : '—'
  $('syncTransport').textContent =
    sync.transport ? (transportLabel(sync.transport.id) || sync.transport.id) : getMessage('pSyncNoTransport', undefined, 'None (manual export/import)')

  const kdf = await bgSend('SYNC_KDF_INFO')
  const info = (kdf && kdf.ok && kdf.info) || { hasSyncCode: false }
  const codeEl = $('syncCodeState')
  if (info.hasSyncCode) {
    const k = String(Math.round(info.iterations / 1000))
    codeEl.textContent = info.isCurrent
      ? getMessage('pSyncCodeSet', [k], `Set · 24 words · ${k}k KDF`)
      : getMessage('pSyncCodeLegacy', [k], `Set · legacy ${k}k KDF`)
    codeEl.style.color = info.isCurrent ? 'var(--accent)' : 'var(--amber)'
  } else {
    codeEl.textContent = getMessage('syncNotSetUp', undefined, 'Not set up')
    codeEl.style.color = 'var(--muted)'
  }

  const badge = $('syncBadge')
  if (sync.syncEnabled && sync.lastModified) {
    const when = new Date(sync.lastModified).toLocaleString()
    badge.textContent = getMessage('pSyncBadge', [when], `Vault updated: ${when}`)
    badge.classList.remove('hidden')
  } else {
    badge.classList.add('hidden')
  }

  // v2.15.0 — R24-F1: the built-in chrome.storage.sync first hop, made
  // truthful. This hop silently does nothing on de-Googled Chromium builds
  // (Helium class) or when the profile is signed out — the ledger written by
  // every vault save says which world this profile is in.
  const hopEl = $('syncHopState')
  if (hopEl) {
    const hop = sync.syncHop
    if (!hop || (!hop.at && !hop.error)) {
      hopEl.textContent = sync.syncEnabled ? getMessage('pSyncHopNever', undefined, 'Not attempted yet') : '—'
      hopEl.style.color = 'var(--muted)'
    } else if (hop.ok) {
      const when = new Date(hop.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      hopEl.textContent = hop.chunks
        ? getMessage('pSyncHopChunks', [String(hop.chunks), when], `✓ ${hop.chunks} chunk${hop.chunks === 1 ? '' : 's'} · ${when}`)
        : getMessage('pSyncHopOk', [when], `✓ ${when}`)
      hopEl.style.color = 'var(--accent)'
    } else {
      hopEl.textContent = getMessage('pSyncWarn', [hop.error || getMessage('pUnavailable', undefined, 'unavailable')], `⚠ ${hop.error || 'unavailable'}`)
      hopEl.title = getMessage('pSyncHopTitle', undefined, 'The browser built-in sync did not accept the write (signed-out or de-Googled profile, quota…). Configure a cloud transport below to sync across devices.')
      hopEl.style.color = 'var(--amber)'
    }
  }

  // v2.8.0 — the real cloud story: when the encrypted vault last reached the
  // transport, or why it didn't (ledger written by every push attempt).
  // v2.16.0 — the success row also says HOW BIG the upload was and HOW LONG
  // it took (push telemetry from the vault engine).
  const pushEl = $('syncPushState')
  if (pushEl) {
    const lp = sync.lastPush
    if (!lp || (!lp.at && !lp.error)) {
      pushEl.textContent = '—'
      pushEl.style.color = 'var(--muted)'
    } else if (lp.skipped) {
      // LAW 0.48 (R133) — the joiner's typed skip: a waiting row, never a failure.
      pushEl.textContent = getMessage('pSyncPushWaiting', undefined, '⏳ Push waits — this device receives first')
      pushEl.style.color = 'var(--muted)'
    } else if (lp.ok) {
      const time = lp.at ? new Date(lp.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
      let meta = ''
      if (typeof lp.bytes === 'number' && lp.bytes > 0) {
        meta += ` · ${lp.bytes >= 1024 ? (lp.bytes / 1024).toFixed(1) + ' KB' : lp.bytes + ' B'}`
      }
      if (typeof lp.durationMs === 'number' && lp.durationMs > 0) {
        meta += ` · ${(lp.durationMs / 1000).toFixed(1)} s`
      }
      // LAW 0.49 (R133) — the read-back confirmation rides the row.
      if (lp.confirmed === true) meta += ' · cloud copy confirmed ✓'
      else if (lp.confirmed === false && lp.confirmError) meta += ' · verifying…'
      pushEl.textContent = `✓ ${time}${meta}`
      pushEl.style.color = 'var(--accent)'
    } else {
      pushEl.textContent = getMessage('pSyncWarn', [lp.error || getMessage('pSyncPending', undefined, 'pending')], `⚠ ${lp.error || 'pending'}`)
      pushEl.style.color = 'var(--amber)'
    }
  }

  // UCRYPT-20 — Exponential backoff retry visual feedback in the popup Sync tab
  const retryRow = $('syncRetryRow')
  const retryEl = $('syncRetryState')
  if (retryRow && retryEl) {
    const as = sync.autoSync || null
    const active = !!(as && (as.inFlight || (as.retrying && Number(as.retryNextAt) > 0) || as.exhausted))
    retryRow.classList.toggle('hidden', !active)
    retryRow.hidden = !active
    if (active) {
      const att = Math.max(1, Number(as.retryCount) || 1)
      const maxAtt = Math.max(1, Number(as.maxRetries) || 6)
      const bSec = Number(as.backoffSeconds) || Math.max(15, Math.round((Number(as.backoffMs) || 15000) / 1000))
      const remSec = as.retryNextAt ? Math.max(0, Math.ceil((Number(as.retryNextAt) - Date.now()) / 1000)) : 0
      if (as.inFlight) {
        retryEl.textContent = `🔄 Retrying now (#${att}/${maxAtt})…`
        retryEl.style.color = 'var(--amber)'
      } else if (as.retrying) {
        retryEl.textContent = `⏳ #${att}/${maxAtt} in ${remSec}s (${bSec}s backoff)`
        retryEl.style.color = 'var(--amber)'
      } else {
        retryEl.textContent = `⚠ Paused (${maxAtt}/${maxAtt} attempts)`
        retryEl.style.color = 'var(--danger, #ef4444)'
      }
      retryEl.title = String(as.lastError || 'Temporary network failure — automatic exponential backoff retry')
    }
  }

  // UCRYPT-27 — Update Popup Sync Hero bar and interactive status chips
  const heroState = $('popupSyncHeroState')
  const chipChain = $('popupSyncChipChain')
  const dotChain = $('popupSyncDotChain')
  const txtChain = $('popupSyncChipChainText')
  const chipCloud = $('popupSyncChipCloud')
  const dotCloud = $('popupSyncDotCloud')
  const txtCloud = $('popupSyncChipCloudText')
  const hasChain = !!sync.syncEnabled
  const hasCloud = !!(sync.transport && sync.transport !== 'none')
  if (heroState) {
    if (hasChain && hasCloud) {
      heroState.textContent = 'Sync chain active · Cloud connected'
      heroState.style.color = 'var(--accent)'
    } else if (hasChain) {
      heroState.textContent = 'Sync chain joined · Connect cloud storage'
      heroState.style.color = 'var(--amber)'
    } else {
      heroState.textContent = 'No sync chain yet — start or join below'
      heroState.style.color = 'var(--muted)'
    }
  }
  if (chipChain && dotChain && txtChain) {
    chipChain.dataset.state = hasChain ? 'ok' : 'off'
    dotChain.className = `sync-chip-dot ${hasChain ? 'ok' : ''}`.trim()
    txtChain.textContent = hasChain ? 'Sync chain: joined' : 'Sync chain: not set'
    if (!chipChain.dataset.wired) {
      chipChain.dataset.wired = '1'
      chipChain.addEventListener('click', () => { $('openSyncSetup')?.click() })
    }
  }
  if (chipCloud && dotCloud && txtCloud) {
    chipCloud.dataset.state = hasCloud ? 'ok' : 'off'
    dotCloud.className = `sync-chip-dot ${hasCloud ? 'ok' : ''}`.trim()
    txtCloud.textContent = hasCloud ? `Cloud: ${sync.transport}` : 'Cloud: not connected'
    if (!chipCloud.dataset.wired) {
      chipCloud.dataset.wired = '1'
      chipCloud.addEventListener('click', () => { $('openSyncSetup')?.click() })
    }
  }

  // R89 (Brave Rank 2, CEO-commanded): the chain-wide device roster —
  // READ-ONLY, presence-derived, from the transfer plane's EXISTING status
  // projection (no new envelope, no new sync surface — the one-blob trust
  // model is untouched). Every chain device the worker knows renders with
  // its TRUTHFUL availability state; this device is labeled honestly.
  try {
    const listEl = $('rosterList')
    if (listEl) {
      const st = await bgSend('TRANSFER_STATUS')
      const peers = (st && st.ok && Array.isArray(st.peers)) ? st.peers : []
      listEl.textContent = ''
      if (!peers.length) {
        const li = document.createElement('li')
        li.className = 'popup-nm-row'
        li.textContent = getMessage('rosterEmpty', undefined, 'No chain devices known yet on this device.')
        listEl.appendChild(li)
      } else {
        for (const p of peers) {
          const li = document.createElement('li')
          li.className = 'popup-nm-row'
          const name = document.createElement('span')
          const label = String(p.label || '').trim()
          name.textContent = label || getMessage('rosterUnnamed', [String(p.deviceId || '').slice(0, 8)], 'Device $ID$')
          const val = document.createElement('strong')
          val.className = 'popup-nm-val'
          const mine = !!p.mine
          if (p.online && !p.stale) {
            val.textContent = getMessage('rosterAvailableUntil', [fmtRosterTime(p.availableUntil)], `Available until $TIME$`)
            val.style.color = 'var(--accent)'
          } else if (p.online && p.stale) {
            val.textContent = getMessage('rosterStale', undefined, 'Stale — last seen a while ago')
            val.style.color = 'var(--amber)'
          } else {
            val.textContent = getMessage('rosterOffline', undefined, 'Offline')
            val.style.color = 'var(--muted)'
          }
          if (mine) name.textContent += getMessage('rosterThisDevice', undefined, ' (this device)')
          li.appendChild(name)
          li.appendChild(val)
          listEl.appendChild(li)
        }
      }
    }
  } catch { /* the roster is a read-only affordance — never blocks the tab */ }
}

/** R89 roster helper: a truthful time render (never "Invalid Date"). */
function fmtRosterTime(iso) {
  const t = Date.parse(String(iso || ''))
  return Number.isFinite(t) ? new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'
}

async function handleSync() {
  const btn = $('syncBtn')
  btn.disabled = true
  btn.textContent = getMessage('syncNowBusy', undefined, 'Syncing…')
  try {
    const r = await bgSend('SYNC_NOW')
    if (r && r.ok) {
      const res = r.result || {}
      // v2.16.0 — R25-F10: the toast used to report only the PULL reason; a
      // FAILED push rendered "Already in sync" — a lie. The push outcome now
      // takes priority when it did not succeed (options does this right).
      const push = res.push
      if (push && !push.ok && push.error) {
        toast(getMessage('pToastPushFailed', [push.error], `Push failed — ${push.error}`), 'error')
      } else if (res.synced) {
        toast(getMessage('pToastSyncUpdated', undefined, 'Vault updated from sync ✓'))
      } else {
        toast(res.reason || getMessage('pSyncAlready', undefined, 'Already in sync'))
      }
    } else {
      const err = (r && r.error) || getMessage('statusSyncFailed', undefined, 'Sync failed — press Sync now to try again.')
      toast(err, 'error')
    }
  } finally {
    btn.disabled = false
    // v2.18.0 — R28-i18n: the reset used to clobber the localized button
    // label after applyI18n had run (the R27 state-renderer hazard).
    btn.textContent = getMessage('syncNow', undefined, 'Sync now')
    await refreshSyncTab()
  }
}

// --- R45-C: native password-manager mode (honest boundary card) --------------

/**
 * R77-A (owner screenshot 20261002_132344): render the compact
 * "UCrypt password manager" state card EXACTLY from live truth.
 *  - Rows 1–4 mirror the ACTUAL stored device-local behavior prefs
 *    (re-read from chrome.storage on every render — never a cached intent).
 *  - The browser save-prompt row is the LITERAL post-set get()/
 *    levelOfControl state. A failed/blocked native setting can NEVER render
 *    as "controlled by UCrypt": permission-missing, policy-managed,
 *    other-extension-controlled, unsupported and API-absent states all
 *    render as browser-controlled/unsupported variants.
 *  - Browser auto sign-in & passkeys are ALWAYS labeled browser-managed —
 *    UCrypt never claims them.
 *  - Dense explanatory copy moves behind the Details expander.
 */
async function refreshNativeManagerCard() {
  const btn = $('nmToggle')
  const state = $('nmState')
  const browserState = $('nmBrowserState')
  const browserNote = $('nmBrowserNote')
  if (!btn || !state || !browserState) return

  const on = getMessage('nmStateOnShort', undefined, 'ON')
  const off = getMessage('nmStateOffShort', undefined, 'OFF')
  const setRow = (id, v) => {
    const el = $(id)
    if (!el) return
    el.textContent = v ? on : off
    el.classList.toggle('popup-nm-on', !!v)
    el.classList.toggle('popup-nm-off', !v)
  }
  let b = { offerSave: true, autoFill: true, showIdentifiers: true, profileFill: true, profileCapture: true }
  try { b = await getBehaviorPrefs() } catch { /* defaults stay */ }
  setRow('nmRowSave', b.offerSave)
  setRow('nmRowPicker', b.autoFill)
  setRow('nmRowProfileFill', b.profileFill)
  setRow('nmRowProfileSave', b.profileCapture)

  const r = await bgSend('NATIVE_MANAGER_GET')
  const st = (r && r.ok && r.status) || null
  btn.disabled = false
  btn.dataset.mode = 'enable'
  btn.textContent = getMessage('nmTurnOn', undefined, 'Turn on')
  browserState.className = 'popup-nm-val popup-nm-val-on'
  let noteKey = 'nmNotePermission'
  let noteDefault = 'Granting the optional privacy permission lets UCrypt turn the browser save prompt off and offer its own save.'
  let detailsKey = 'nmStateOffPermission'
  let detailsDefault = 'Off — turning on asks for the optional privacy permission and switches the browser save prompt to UCrypt.'
  let mode = 'enable'

  if (!st) {
    browserState.textContent = getMessage('nmBrowserUnsupported', undefined, 'Unsupported by this browser')
    browserState.className = 'popup-nm-val popup-nm-val-neutral'
    noteKey = 'nmUnavailable'
    noteDefault = 'Native-manager control is not available here.'
    detailsKey = 'nmUnavailable'
    detailsDefault = noteDefault
    btn.disabled = true
    mode = 'none'
  } else if (!st.permission) {
    // R77-A audit fix (D1 gap 2): this branch must run BEFORE the supported
    // check — the worker reports supported = !!(permission && api), so a
    // missing permission used to shadow as "Unsupported". The honest state
    // is: the browser prompt is still ON and UCrypt has no control.
    browserState.textContent = getMessage('nmBrowserOnPermission', undefined, 'ON — permission not granted')
  } else if (!st.supported) {
    browserState.textContent = getMessage('nmBrowserUnsupported', undefined, 'Unsupported by this browser')
    browserState.className = 'popup-nm-val popup-nm-val-neutral'
    noteKey = 'nmStateNoApi'
    noteDefault = 'This browser does not expose the password-saving setting to extensions.'
    detailsKey = 'nmStateNoApi'
    detailsDefault = noteDefault
    btn.disabled = true
    mode = 'none'
  } else if (st.levelOfControl === 'not_controllable') {
    browserState.textContent = getMessage('nmBrowserOnPolicy', undefined, 'ON — browser policy or another extension controls it')
    noteKey = 'nmStateNotControllable'
    noteDefault = 'Your organization or browser policy manages this setting — UCrypt cannot change it.'
    detailsKey = 'nmStateNotControllable'
    detailsDefault = noteDefault
    btn.disabled = true
    btn.textContent = getMessage('nmStateManaged', undefined, 'Managed')
    mode = 'none'
  } else if (st.levelOfControl === 'controlled_by_other_extensions') {
    browserState.textContent = getMessage('nmBrowserOnOtherExt', undefined, 'ON — another extension controls it')
    noteKey = 'nmStateOtherExt'
    noteDefault = 'Another extension controls this setting. Disable it there first if you want UCrypt to take over.'
    detailsKey = 'nmStateOtherExt'
    detailsDefault = noteDefault
    btn.disabled = true
    btn.textContent = getMessage('nmStateManaged', undefined, 'Managed')
    mode = 'none'
  } else if (st.controlling) {
    browserState.textContent = getMessage('nmBrowserOffUCrypt', undefined, 'OFF — controlled by UCrypt')
    browserState.className = 'popup-nm-val popup-nm-val-ucrypt'
    noteKey = 'nmStateOn'
    noteDefault = 'ON — UCrypt suppresses the browser save prompt and offers its own. UCrypt cannot read or delete passwords the browser already saved; Auto sign-in may still need to be turned off in browser settings.'
    detailsKey = 'nmStateOn'
    detailsDefault = noteDefault
    btn.textContent = getMessage('nmTurnOff', undefined, 'Turn off')
    mode = 'disable'
  } else {
    // controllable_by_this_extension, not yet on (or re-taken by the browser).
    browserState.textContent = getMessage('nmBrowserOn', undefined, 'ON — browser default')
    detailsKey = 'nmStateOff'
    detailsDefault = 'Off — the browser keeps its own save-password prompt.'
  }

  browserNote.textContent = getMessage(noteKey, undefined, noteDefault)
  state.textContent = getMessage(detailsKey, undefined, detailsDefault)
  btn.dataset.mode = mode
}

async function nmToggleClick() {
  const btn = $('nmToggle')
  const mode = btn.dataset.mode
  btn.disabled = true
  try {
    if (mode === 'disable') {
      const r = await bgSend('NATIVE_MANAGER_DISABLE')
      if (!r?.ok) toast(r?.error || getMessage('nmFailed', undefined, 'Could not change the setting — reload the page and try again.'), 'error')
      else toast(getMessage('nmDisabledToast', undefined, 'Browser save prompt restored'))
    } else if (mode === 'enable') {
      // The permission REQUEST must run in this page (user gesture) — the
      // worker cannot ask for permissions. Already-granted resolves true.
      let granted = false
      try {
        granted = await chrome.permissions.request({ permissions: ['privacy'] })
      } catch { granted = false }
      if (!granted) {
        toast(getMessage('nmPermissionDenied', undefined, 'Without the privacy permission UCrypt cannot manage the browser save prompt — enable it in your browser settings.'), 'error')
        return
      }
      const r = await bgSend('NATIVE_MANAGER_ENABLE')
      if (!r?.ok) toast(r?.error || getMessage('nmFailed', undefined, 'Could not change the setting — reload the page and try again.'), 'error')
      else toast(getMessage('nmEnabledToast', undefined, 'UCrypt now handles new password saves'))
    }
  } finally {
    await refreshNativeManagerCard()
  }
}

// --- 2FA tab (TOTP authenticator — v2.4.0) ---------------------------------

let totpTokens = []
let totpTicker = null
let openQrLabel = null // which token's QR popover is expanded

const RING_RADIUS = 12
const RING_CIRC = 2 * Math.PI * RING_RADIUS

function groupCode(code) {
  if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3)
  if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4)
  return code
}

async function refreshTotpTab() {
  const r = await bgSend('TOTP_TOKENS')
  if (r && r.locked) {
    totpTokens = []
    renderTotpTokens()
    stopTotpTicker()
    return
  }
  totpTokens = (r && r.ok && r.tokens) || []
  renderTotpTokens()
  if (totpTokens.length > 0) startTotpTicker()
  else stopTotpTicker()
}

function renderTotpTokens() {
  const list = $('totpList')
  list.textContent = ''
  const n = totpTokens.length
  $('totpCount').textContent = String(n)
  $('totpCountPlural').textContent = n === 1 ? '' : 's'
  show($('totpEmptyHint'), n === 0)

  for (const token of totpTokens) {
    list.appendChild(totpCard(token))
  }
}

function totpCard(token) {
  const info = token.totp || {}
  const label = token.username || '(unlabelled)'

  // Column wrapper: card + (collapsible) QR popover.
  const wrap = document.createElement('div')
  wrap.dataset.tokenwrap = label
  wrap.style.display = 'flex'
  wrap.style.flexDirection = 'column'
  wrap.style.gap = '4px'

  const card = document.createElement('div')
  card.className = 'popup-totp-card'

  const text = document.createElement('div')
  text.className = 'popup-totp-info'
  const issuerEl = document.createElement('div')
  issuerEl.className = 'popup-totp-issuer'
  issuerEl.textContent = info.issuer || '2FA token'
  const labelEl = document.createElement('div')
  labelEl.className = 'popup-totp-label'
  labelEl.textContent = label
  labelEl.title = label
  const codeBtn = document.createElement('button')
  codeBtn.className = 'popup-totp-code totp-mono'
  codeBtn.dataset.code = '1'
  codeBtn.textContent = '······'
  codeBtn.title = 'Copy code'
  codeBtn.setAttribute('aria-label', `Copy verification code for ${info.issuer || ''} ${label}`.trim())
  codeBtn.addEventListener('click', () => {
    const cur = codeBtn.textContent.replace(/\s+/g, '')
    if (cur && !cur.includes('·')) copyWithToast(cur, 'Code copied — clears in 20s')
  })
  text.appendChild(issuerEl)
  text.appendChild(labelEl)
  text.appendChild(codeBtn)

  // Countdown ring
  const ring = document.createElement('div')
  ring.className = 'popup-totp-ring'
  ring.innerHTML =
    `<svg width="30" height="30" viewBox="0 0 30 30" aria-hidden="true">` +
    `<circle class="ring-bg" cx="15" cy="15" r="${RING_RADIUS}" fill="none" stroke-width="3"/>` +
    `<circle class="ring-fg" cx="15" cy="15" r="${RING_RADIUS}" fill="none" stroke-width="3" ` +
    `stroke-linecap="round" stroke-dasharray="${RING_CIRC.toFixed(1)}" stroke-dashoffset="0"/></svg>` +
    `<span class="popup-totp-ring-num" aria-hidden="true">—</span>`

  // Actions
  const actions = document.createElement('div')
  actions.className = 'popup-entry-actions'
  const mkBtn = (labelTxt, titleTxt, fn) => {
    const b = document.createElement('button')
    b.className = 'popup-btn popup-btn-mini'
    b.textContent = labelTxt
    b.title = titleTxt
    b.addEventListener('click', fn)
    return b
  }
  const qrBtn = mkBtn('QR', 'Show a QR code to move this token to your phone', () => toggleTokenQr(label))
  const delBtn = mkBtn('Del', 'Remove this token from the vault', () => handleTokenDelete(delBtn, label))
  delBtn.classList.add('popup-btn-mini-danger')
  // R95 §3.1 — "Fill on page": an EXPLICIT user action that fills the CURRENT
  // code into the page's detected OTP field. The label rides to the content
  // script; the content script asks the worker for the code itself (the code
  // never crosses the popup→tab hop), setNativeValue + highlight, and NEVER a
  // submit. No new permissions (tabs.sendMessage on the active tab only);
  // a locked vault refuses at the worker (never on lock). The button is
  // DISABLED with a reason until the page proves an OTP field exists.
  const fillBtn = mkBtn(
    getMessage('totpFillBtn', undefined, 'Fill'),
    getMessage('totpFillBtnTitle', undefined, 'Fill the current code into the 2FA field on this page — never submits'),
    () => fillTokenOnPage(label, fillBtn),
  )
  fillBtn.disabled = true
  probeOtpFieldOnActiveTab().then((present) => {
    if (!present) {
      fillBtn.title = getMessage('totpFillNoField', undefined, 'No 2FA field on this page — Copy still works')
      return
    }
    fillBtn.disabled = false
  }).catch(() => { /* stays disabled with the default title — truthful */ })
  actions.appendChild(qrBtn)
  actions.appendChild(fillBtn)
  actions.appendChild(delBtn)

  card.appendChild(text)
  card.appendChild(ring)
  card.appendChild(actions)

  const qrHolder = document.createElement('div')
  qrHolder.className = 'popup-totp-qrbox hidden'
  qrHolder.dataset.qrfor = label

  wrap.appendChild(card)
  wrap.appendChild(qrHolder)
  return wrap
}

// R95 §3.1 — the active tab's OTP-field probe (no permissions beyond the
// existing `tabs`; a content-script round trip, silent failure is truthful:
// no field → the Fill button stays disabled with its reason).
async function probeOtpFieldOnActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || tab.id == null || !/^https?:/i.test(tab.url || '')) return false
    const r = await chrome.tabs.sendMessage(tab.id, { type: 'UCRYPT_OTP_FIELD_PRESENT' })
    return !!(r && r.ok && r.present)
  } catch { return false }
}

// R95 §3.1 — the explicit fill action. Sends the LABEL only; the content
// script requests the code from the worker (locked → typed refusal — never
// on lock) and fills the field. Never auto-submits. The toast says so.
async function fillTokenOnPage(label, btn) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || tab.id == null) throw new Error('no active tab')
    const r = await chrome.tabs.sendMessage(tab.id, { type: 'UCRYPT_FILL_TOTP', label })
    if (r && r.ok) {
      toast(getMessage('totpFillDone', [String(r.remainingSec ?? '')], 'Code filled — nothing was submitted'))
    } else {
      toast(getMessage('totpFillFail', undefined, 'Could not fill — no 2FA field on this page'), 'error')
    }
  } catch {
    toast(getMessage('totpFillFail', undefined, 'Could not fill — no 2FA field on this page'), 'error')
  } finally {
    if (btn) btn.blur()
  }
}

function toggleTokenQr(label) {
  if (openQrLabel === label) {
    openQrLabel = null
    updateQrPopovers()
    return
  }
  openQrLabel = label
  updateQrPopovers()
}

function updateQrPopovers() {
  document.querySelectorAll('[data-qrfor]').forEach(box => {
    const label = box.dataset.qrfor
    if (label !== openQrLabel) {
      box.classList.add('hidden')
      box.textContent = ''
      return
    }
    const token = totpTokens.find(t => (t.username || '') === label)
    if (!token || !token.totp) return
    try {
      const uri = buildOtpauthUri({
        label,
        issuer: token.totp.issuer || '',
        secret: token.totp.secret,
        digits: token.totp.digits,
        period: token.totp.period,
        algorithm: token.totp.algorithm,
      })
      const dataUrl = globalThis.QR.encode(uri)
      box.textContent = ''
      const img = document.createElement('img')
      img.src = dataUrl
      img.alt = `QR code for the ${token.totp.issuer || ''} ${label} token`.trim()
      const p = document.createElement('p')
      p.textContent = 'Scan with your phone\'s authenticator to move this token. Anyone who scans it can generate your codes — keep it private.'
      // v2.5.0 — printable PNG export (512×512, white background).
      const pngBtn = document.createElement('button')
      pngBtn.className = 'popup-btn popup-btn-mini popup-qr-png-btn'
      pngBtn.textContent = '⬇ Export PNG'
      pngBtn.setAttribute('aria-label', `Export the ${label} token QR as a PNG image`)
      pngBtn.addEventListener('click', async () => {
        pngBtn.disabled = true
        const prev = pngBtn.textContent
        pngBtn.textContent = 'Rendering…'
        try {
          await exportQrPng(dataUrl, sanitizeFileName(`ucrypt-2fa-${label}.png`))
          pngBtn.textContent = 'PNG saved ✓'
          setTimeout(() => { if (pngBtn.isConnected) { pngBtn.textContent = prev; pngBtn.disabled = false } }, 2200)
        } catch (e) {
          pngBtn.textContent = 'Export failed'
          toast(`PNG export failed: ${e.message}`, 'error')
          setTimeout(() => { if (pngBtn.isConnected) { pngBtn.textContent = prev; pngBtn.disabled = false } }, 2200)
        }
      })
      box.appendChild(img)
      box.appendChild(pngBtn)
      box.appendChild(p)
      box.classList.remove('hidden')
    } catch (e) {
      box.textContent = ''
      const p = document.createElement('p')
      p.textContent = `Could not build QR: ${e.message}`
      box.appendChild(p)
      box.classList.remove('hidden')
    }
  })
}

// --- QR PNG export helpers (v2.5.0) -----------------------------------------

/** Restrict a download filename to a safe subset (keep unicode letters). */
function sanitizeFileName(name) {
  const clean = String(name)
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  return (clean || 'ucrypt-qr.png').slice(0, 60).replace(/^[.\s]+/, '') || 'ucrypt-qr.png'
}

/** Render an SVG data URL onto a 512×512 white canvas and download as PNG. */
async function exportQrPng(svgDataUrl, filename) {
  const img = new Image()
  await new Promise((resolve, reject) => {
    img.onload = resolve
    img.onerror = () => reject(new Error('could not render the QR image'))
    img.src = svgDataUrl
  })
  const canvas = document.createElement('canvas')
  canvas.width = 512
  canvas.height = 512
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('canvas unavailable')
  ctx.fillStyle = '#ffffff'
  ctx.fillRect(0, 0, 512, 512)
  ctx.drawImage(img, 0, 0, 512, 512)
  const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'))
  if (!blob) throw new Error('PNG encoding unsupported')
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

async function handleTokenDelete(btn, label) {
  if (btn.dataset.armed !== '1') {
    btn.dataset.armed = '1'
    btn.textContent = 'Sure?'
    setTimeout(() => {
      if (btn.isConnected) { btn.dataset.armed = ''; btn.textContent = 'Del' }
    }, 3000)
    return
  }
  const r = await bgSend('TOTP_DELETE', { label })
  if (r && r.ok) {
    toast(`Token "${label}" deleted`)
    if (openQrLabel === label) openQrLabel = null
    await refreshTotpTab()
  } else {
    toast((r && r.error) || 'Delete failed', 'error')
  }
}

// --- TOTP ticker: recompute codes each second -------------------------------

const totpState = new Map() // label -> { counter, period }

function startTotpTicker() {
  if (totpTicker) clearInterval(totpTicker)
  tickTotpTokens() // immediate paint
  totpTicker = setInterval(tickTotpTokens, 1000)
}

/** v2.5.0 — no tokens (or locked vault) ⇒ no interval work at all. */
function stopTotpTicker() {
  if (totpTicker) clearInterval(totpTicker)
  totpTicker = null
}

async function tickTotpTokens() {
  if (document.hidden) return
  const nowSec = Date.now() / 1000
  for (const token of totpTokens) {
    const info = token.totp || {}
    const label = token.username || ''
    const wrap = document.querySelector(`[data-tokenwrap="${CSS.escape(label)}"]`)
    if (!wrap) continue
    const codeBtn = wrap.querySelector('[data-code]')
    const ring = wrap.querySelector('.popup-totp-ring')
    if (!codeBtn || !ring) continue
    try {
      const t = await computeTotp(info.secret, {
        timeSec: nowSec,
        period: info.period,
        digits: info.digits,
        algorithm: info.algorithm,
      })
      const prev = totpState.get(label)
      if (!prev || prev.counter !== t.counter || prev.period !== t.period) {
        codeBtn.textContent = groupCode(t.code)
        totpState.set(label, { counter: t.counter, period: t.period })
      }
      const frac = Math.max(0, Math.min(1, t.remainingSec / t.period))
      const fg = ring.querySelector('.ring-fg')
      if (fg) fg.style.strokeDashoffset = (RING_CIRC * (1 - frac)).toFixed(1)
      const num = ring.querySelector('.popup-totp-ring-num')
      if (num) num.textContent = String(t.remainingSec)
      // Amber warning in the final 5 seconds of a window
      const critical = t.remainingSec <= 5
      ring.classList.toggle('is-critical', critical)
      wrap.querySelector('.popup-totp-card')?.classList.toggle('is-critical', critical)
    } catch {
      codeBtn.textContent = 'error'
      codeBtn.title = 'This token\'s secret is invalid — delete and re-add it'
    }
  }
}

// --- Add-token form ----------------------------------------------------------

function totpEffectiveParams() {
  // URI paste wins over manual fields when it parses cleanly.
  const uri = $('totpUri').value.trim()
  if (uri) {
    const parsed = parseOtpauthUri(uri)
    if (parsed) return { ...parsed, fromUri: true }
  }
  const secret = normalizeSecret($('totpSecret').value)
  return {
    label: $('totpLabel').value.trim(),
    issuer: $('totpIssuer').value.trim(),
    secret,
    digits: +$('totpDigits').value || 6,
    period: +$('totpPeriod').value || 30,
    algorithm: $('totpAlgo').value || 'SHA-1',
    fromUri: false,
  }
}

async function refreshTotpPreview() {
  const box = $('totpPreview')
  const errEl = $('totpAddError')
  const p = totpEffectiveParams()
  if (!p.secret) {
    show(box, false)
    show(errEl, false)
    return
  }
  if (!isValidBase32Secret(p.secret)) {
    show(box, false)
    errEl.textContent = 'That secret is not valid base32 (A–Z, 2–7). Check for typos or paste the otpauth:// URI instead.'
    show(errEl, true)
    return
  }
  show(errEl, false)
  try {
    const t = await computeTotp(p.secret, { period: p.period, digits: p.digits, algorithm: p.algorithm })
    $('totpPreviewCode').textContent = groupCode(t.code)
    $('totpPreviewMeta').textContent = `${p.digits}d · ${p.period}s · ${p.algorithm}${p.fromUri ? ' · from URI' : ''}`
    show(box, true)
  } catch (e) {
    show(box, false)
    errEl.textContent = e.message
    show(errEl, true)
  }
}

function clearTotpAddForm() {
  for (const id of ['totpUri', 'totpLabel', 'totpIssuer', 'totpSecret']) $(id).value = ''
  $('totpDigits').value = '6'
  $('totpPeriod').value = '30'
  $('totpAlgo').value = 'SHA-1'
  show($('totpPreview'), false)
  show($('totpAddError'), false)
}

function toggleTotpAddBox(force) {
  const box = $('totpAddBox')
  const on = typeof force === 'boolean' ? force : box.classList.contains('hidden')
  show(box, on)
  $('totpAddToggle').setAttribute('aria-expanded', String(on))
  $('totpAddToggle').textContent = on ? '× Close' : '＋ Add'
  if (on) {
    clearTotpAddForm()
    $('totpUri').focus()
  }
}

async function handleTotpSave() {
  const errEl = $('totpAddError')
  const p = totpEffectiveParams()
  const fail = (msg) => {
    errEl.textContent = msg
    show(errEl, true)
  }
  if (!p.label) return fail('Give the token a label (e.g. the account name).')
  if (!isValidBase32Secret(p.secret)) return fail('The secret is missing or not valid base32.')
  $('totpSaveBtn').disabled = true
  try {
    const r = await bgSend('TOTP_SAVE', { token: p })
    if (r && r.ok) {
      toast(`Token "${p.label}" saved to vault ✓`)
      toggleTotpAddBox(false)
      await refreshTotpTab()
    } else {
      fail((r && r.error) || 'Could not save the token')
    }
  } finally {
    $('totpSaveBtn').disabled = false
  }
}

// --- Health tab (vault password health — v2.5.0) -----------------------------

const HEALTH_RING_RADIUS = 26
const HEALTH_RING_CIRC = 2 * Math.PI * HEALTH_RING_RADIUS

// R59-F4/F5 — surface mode (read once from the URL):
//   WINDOW_MODE  = the resizable vault window (popup.html?window=1)
//   HEALTH_SURFACE = the full health report surface (…&surface=health)
//   TAB_FALLBACK = running in a tab because windows.create was refused
const _SURFACE_PARAMS = new URLSearchParams(location.search)
const WINDOW_MODE = _SURFACE_PARAMS.get('window') === '1'
const HEALTH_SURFACE = _SURFACE_PARAMS.get('surface') === 'health'
const TAB_FALLBACK = _SURFACE_PARAMS.get('tab') === '1'

async function refreshHealthTab() {
  // R59-F5 — toolbar popup: SUMMARY ONLY + "Open full Health report". The
  // full report (CSV, Re-run, distribution, reuse groups, worst list) lives
  // in the extension-controlled vault window — capabilities move, none removed.
  const openFull = $('healthOpenFull')
  if (openFull) openFull.classList.toggle('hidden', !!WINDOW_MODE)
  const actions = $('healthActions')
  if (actions) actions.classList.toggle('hidden', !WINDOW_MODE)
  const body = $('healthBody')
  body.textContent = ''
  const r = await bgSend('HEALTH_REPORT')
  if (r && r.locked) {
    // R95 F-95-06 (filed P4): the locked health state names its fix in every
    // locale (was hardcoded EN — the exact string the USER-GUIDE documents).
    body.appendChild(emptyState(getMessage('pHealthLocked', undefined, 'Vault is locked — unlock to run the health report.')))
    lastHealthReport = null
    return
  }
  const rep = r && r.ok && r.report
  if (!rep) {
    body.appendChild(emptyState(getMessage('pHealthFailed', undefined, 'Could not build the health report — reopen the Health tab to try again.')))
    lastHealthReport = null
    return
  }
  lastHealthReport = rep
  if (WINDOW_MODE) renderHealth(body, rep)
  else renderHealthSummary(body, rep)
}

// R59-F5 — "Open full Health report": the extension-controlled resizable
// vault window at the health surface; NEVER an arbitrary website tab. If the
// window API refuses, the truthful fallback is a tab + a toast (the tab
// variant is marked tab=1 so it does not pollute the persisted bounds).
async function openFullHealthReport() {
  const r = await bgSend('OPEN_VAULT_WINDOW', { surface: 'health' })
  if (r && r.ok && r.fallback) {
    toast(getMessage('pHealthFullFallback', undefined, 'Resizable window unavailable — the full report opened in a tab instead'))
  } else if (!r || !r.ok) {
    toast((r && r.error) || getMessage('pHealthFullFailed', undefined, 'Could not open the full health report'), 'error')
  }
}

// --- v2.9.0 — health report CSV export (parity with the Audit Lab) ----------

let lastHealthReport = null

function csvField(value) {
  const s = String(value ?? '')
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}

function exportHealthCsv() {
  const rep = lastHealthReport
  if (!rep || !rep.total) {
    toast(getMessage('pHealthNothingToExport', undefined, 'Run the report first — nothing to export yet'))
    return
  }
  const band = (bits) => bits < 28 ? 'very weak' : bits < 50 ? 'weak' : bits < 70 ? 'fair' : bits < 100 ? 'strong' : 'excellent'
  const rows = [['domain', 'username', 'bits', 'strength', 'breached', 'reused', 'issues']]
  for (const w of (rep.worst || [])) {
    rows.push([
      w.domain || '', w.username || '', Math.round(w.bits || 0),
      band(Math.round(w.bits || 0)),
      w.breached ? 'yes' : 'no',
      (rep.reuseGroups || []).some(g => (g.sites || []).includes(w.domain)) ? 'yes' : 'no',
      (w.reasons || []).join('; '),
    ])
  }
  const csv = rows.map(r => r.map(csvField).join(',')).join('\r\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `ucrypt-health-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
  toast(getMessage('pHealthExported', undefined, 'Health report exported'))
}

function healthEl(tag, className, text) {
  const el = document.createElement(tag)
  if (className) el.className = className
  if (text != null) el.textContent = text
  return el
}

function renderHealth(body, rep) {
  if (!rep.total) {
    body.appendChild(emptyState(getMessage('pHealthEmpty', undefined, 'No logins to analyze yet — save one from a login form or the settings.')))
    return
  }
  renderHealthTop(body, rep)
  renderHealthKpis(body, rep)

  // Strength distribution bar
  const dist = healthEl('div', 'popup-health-dist')
  dist.title = getMessage('pHealthDistTitle', undefined, 'Very Weak / Weak / Fair / Strong / Excellent')
  const segs = [
    ['veryWeak', '#ef4444'], ['weak', '#f97316'], ['fair', '#eab308'],
    ['strong', '#84cc16'], ['excellent', '#10b981'],
  ]
  for (const [key, color] of segs) {
    const n = rep.buckets[key] || 0
    if (!n) continue
    const seg = healthEl('span', 'popup-health-seg')
    seg.style.flex = String(n)
    seg.style.background = color
    seg.textContent = String(n)
    dist.appendChild(seg)
  }
  if (dist.children.length) body.appendChild(dist)

  // Reuse groups
  for (const g of rep.reuseGroups.slice(0, 3)) {
    const row = healthEl('div', 'popup-health-row is-warnrow')
    row.appendChild(healthEl('div', 'popup-health-row-title',
      getMessage('pHealthReuse', [String(g.count)], `♻ Same password on ${g.count} sites`)))
    row.appendChild(healthEl('div', 'popup-health-row-sub', g.sites.join(', ')))
    body.appendChild(row)
  }

  // Worst offenders
  if (rep.worst.length) {
    const head = healthEl('div', 'popup-domain-label popup-health-listhead', getMessage('pHealthFixFirst', undefined, 'Fix first — weakest logins'))
    body.appendChild(head)
    for (const w of rep.worst) {
      const row = healthEl('div', 'popup-health-row' + (w.breached ? ' is-badrow' : ''))
      const info = healthEl('div', 'popup-health-row-info')
      const t = healthEl('div', 'popup-health-row-title')
      t.textContent = `${w.domain} · ${w.username}`
      t.title = w.reasons.length ? w.reasons.join(' · ') : getMessage('pHealthLowEntropy', undefined, 'Low effective entropy')
      info.appendChild(t)
      const sub = healthEl('div', 'popup-health-row-sub', w.breached
        ? getMessage('pHealthBreached', undefined, '⚠ Exposed in breach data')
        : (w.reasons[0] || getMessage('pHealthWeak', undefined, 'Weak')))
      info.appendChild(sub)
      const bits = healthEl('span', 'popup-health-bits', getMessage('pHealthBits', [String(Math.round(w.bits))], `${Math.round(w.bits)} bits`))
      row.appendChild(info)
      row.appendChild(bits)
      body.appendChild(row)
    }
    const hint = healthEl('p', 'popup-help popup-help-subtle',
      getMessage('pHealthTip', undefined, 'Tip: open Generate, make a strong replacement, then update the site.'))
    body.appendChild(hint)
  }
}

// R59-F5 — shared pieces of the report (ring/band + KPI grid) used by BOTH
// the full window report and the compact toolbar summary.
function renderHealthTop(body, rep) {
  const top = healthEl('div', 'popup-health-top')
  const ring = healthEl('div', 'popup-health-ring')
  const stroke = rep.band.color
  ring.innerHTML =
    `<svg width="64" height="64" viewBox="0 0 64 64" aria-hidden="true">` +
    `<circle cx="32" cy="32" r="${HEALTH_RING_RADIUS}" fill="none" stroke="var(--border)" stroke-width="6"/>` +
    `<circle cx="32" cy="32" r="${HEALTH_RING_RADIUS}" fill="none" stroke="${stroke}" stroke-width="6" ` +
    `stroke-linecap="round" stroke-dasharray="${HEALTH_RING_CIRC.toFixed(1)}" ` +
    `stroke-dashoffset="${(HEALTH_RING_CIRC * (1 - rep.score / 100)).toFixed(1)}" ` +
    `transform="rotate(-90 32 32)"/></svg>` +
    `<span class="popup-health-num">${rep.score}</span>`
  ring.title = getMessage('pHealthRingTitle', [rep.band.label, String(rep.score)], `${rep.band.label} — ${rep.score}/100`)
  const topText = healthEl('div', 'popup-health-top-text')
  const bandLine = healthEl('div', 'popup-health-band', rep.band.label)
  bandLine.style.color = stroke
  topText.appendChild(bandLine)
  topText.appendChild(healthEl('div', 'popup-health-sub',
    getMessage('pHealthSub', [String(rep.total), String(rep.avgBits)], `${rep.total} login${rep.total === 1 ? '' : 's'} analyzed · avg ≈ ${rep.avgBits} bits effective`)))
  top.appendChild(ring)
  top.appendChild(topText)
  body.appendChild(top)
}

function renderHealthKpis(body, rep) {
  const kpis = healthEl('div', 'popup-health-kpis')
  const kpi = (num, label, cls) => {
    const c = healthEl('div', 'popup-health-kpi' + (cls ? ' ' + cls : ''))
    c.appendChild(healthEl('strong', null, String(num)))
    c.appendChild(healthEl('span', null, label))
    return c
  }
  kpis.appendChild(kpi(rep.breached, getMessage('pKpiBreached', undefined, 'breached'), rep.breached > 0 ? 'is-bad' : 'is-good'))
  kpis.appendChild(kpi(rep.weak, getMessage('pKpiWeak', undefined, 'weak'), rep.weak > 0 ? 'is-warn' : 'is-good'))
  kpis.appendChild(kpi(rep.reuseGroups.length, getMessage('pKpiReused', undefined, 'reused sets'), rep.reuseGroups.length > 0 ? 'is-warn' : 'is-good'))
  kpis.appendChild(kpi(rep.buckets.excellent, getMessage('pKpiExcellent', undefined, 'excellent')))
  body.appendChild(kpis)
}

// R59-F5 — the toolbar popup Health SUMMARY: score/status, the four counts,
// top 1–3 fix-first items (domain + bits + reason — NO username/password
// reveal), and the "Open full Health report" primary action.
function renderHealthSummary(body, rep) {
  if (!rep.total) {
    body.appendChild(emptyState(getMessage('pHealthEmpty', undefined, 'No logins to analyze yet — save one from a login form or the settings.')))
    return
  }
  renderHealthTop(body, rep)
  renderHealthKpis(body, rep)
  if (rep.worst && rep.worst.length) {
    body.appendChild(healthEl('div', 'popup-domain-label popup-health-listhead', getMessage('pHealthFixFirst', undefined, 'Fix first — weakest logins')))
    for (const w of rep.worst.slice(0, 3)) {
      const row = healthEl('div', 'popup-health-row' + (w.breached ? ' is-badrow' : ''))
      const info = healthEl('div', 'popup-health-row-info')
      const t = healthEl('div', 'popup-health-row-title', w.domain)
      t.title = w.reasons.length ? w.reasons.join(' · ') : getMessage('pHealthLowEntropy', undefined, 'Low effective entropy')
      info.appendChild(t)
      info.appendChild(healthEl('div', 'popup-health-row-sub', w.breached
        ? getMessage('pHealthBreached', undefined, '⚠ Exposed in breach data')
        : (w.reasons[0] || getMessage('pHealthWeak', undefined, 'Weak'))))
      row.appendChild(info)
      row.appendChild(healthEl('span', 'popup-health-bits', getMessage('pHealthBits', [String(Math.round(w.bits))], `${Math.round(w.bits)} bits`)))
      body.appendChild(row)
    }
  }
  body.appendChild(healthEl('p', 'popup-help popup-help-subtle',
    getMessage('pHealthSummaryHint', undefined, 'Summary only — the full report (CSV, re-run, complete lists) opens in the UCrypt window.')))
}

// --- Unlock / setup / lock ---------------------------------------------------

async function handleUnlock() {
  const pass = $('unlockPass').value
  if (!pass) {
    toast('Enter your master passphrase', 'error')
    return
  }
  const r = await bgSend('UNLOCK', { passphrase: pass })
  if (r && r.ok) {
    await refresh()
  } else {
    toast((r && r.error) || 'Unlock failed', 'error')
  }
}

async function handleSetup() {
  const pass = $('setupPass').value
  const pass2 = $('setupPass2').value
  if (pass.length < 8) { toast('Passphrase must be ≥ 8 chars', 'error'); return }
  if (pass !== pass2) { toast('Passphrases do not match', 'error'); return }
  const r = await bgSend('SET_MASTER', { passphrase: pass })
  if (r && r.ok) {
    // R45-E: the vault exists — the user now makes the EXPLICIT initial
    // choice about how UCrypt coexists with the browser's native manager.
    await showFirstRunChoice()
  } else {
    toast((r && r.error) || 'Setup failed', 'error')
  }
}

// --- R45-E: the explicit first-run choice -----------------------------------

const FIRST_RUN_KEY = 'ucrypt:firstRunChoice'

async function showFirstRunChoice() {
  try {
    const { [FIRST_RUN_KEY]: prev } = await chrome.storage.local.get(FIRST_RUN_KEY)
    if (prev && prev.choice) return refresh() // already decided — skip silently
  } catch { /* first run */ }
  setView('firstRun')
}

/**
 * R45-E: "Use UCrypt only" turns ON native-manager mode (permission request
 * happens right here inside this user gesture); "Use alongside" changes
 * NOTHING in the browser; "I'll decide later" defers — all three are
 * recorded so the setup checklist can distinguish completed / skipped.
 */
async function recordFirstRun(choice) {
  try {
    if (choice === 'ucrypt-only') {
      let granted = false
      try {
        granted = await chrome.permissions.request({ permissions: ['privacy'] })
      } catch { granted = false }
      if (granted) {
        const r = await bgSend('NATIVE_MANAGER_ENABLE')
        if (r?.ok) toast(getMessage('nmEnabledToast', undefined, 'UCrypt now handles new password saves'))
        else toast(r?.error || getMessage('nmFailed', undefined, 'Could not change the setting — reload the page and try again.'), 'error')
      } else {
        toast(getMessage('nmPermissionDenied', undefined, 'Without the privacy permission UCrypt cannot manage the browser save prompt — enable it in your browser settings.'), 'error')
      }
    }
    await chrome.storage.local.set({ [FIRST_RUN_KEY]: { choice, at: Date.now() } })
  } finally {
    await refresh()
  }
}

async function handleLock() {
  await bgSend('LOCK')
  await refresh()
}

// --- Refresh state ---------------------------------------------------------

/**
 * v2.16.0 — the auto-lock copy used to hard-code "10 idle minutes" while the
 * interval became user-configurable; both hints now render the REAL value
 * from the vault state (0 = never).
 */
function applyLockCopy(state) {
  const mins = Math.round((state?.lockTimeoutMs ?? 0) / 60000)
  const hintEl = $('lockHint')
  if (hintEl) {
    hintEl.textContent = mins > 0
      ? getMessage('lockHintDyn', [String(mins)], `Auto-locks after ${mins} idle minutes`)
      : getMessage('lockHintNever', undefined, 'Auto-lock is off')
  }
  const helpEl = $('unlockHelpLine')
  if (helpEl) {
    helpEl.textContent = mins > 0
      ? getMessage('unlockHelpDyn', [String(mins)], `600k PBKDF2 iterations + AES-256-GCM. Auto-locks after ${mins} idle minutes.`)
      : getMessage('unlockHelpNever', undefined, '600k PBKDF2 iterations + AES-256-GCM. Auto-lock is off.')
  }
}

async function refresh() {
  const r = await bgSend('GET_STATE')
  if (!r || !r.ok) {
    toast('Background not responding', 'error')
    setView('locked')
    return
  }
  const state = r.state
  const sync = r.sync || {}
  applyLockCopy(state)
  if (!state.hasMaster) {
    setView('setup')
    $('setupPass').focus()
    return
  }
  if (!state.isUnlocked) {
    setView('locked')
    $('unlockPass').focus()
    return
  }
  setView('unlocked')
  $('entryCount').textContent = String(sync.entryCount || 0)
  await refreshVaultTab()
  await refreshSyncTab()
  switchTab(activeTab)
}

// --- Wire up event listeners ----------------------------------------------

/**
 * v2.21.0 — R30-F2: apply (or remove) the compact list density. The class
 * lives on the vault TAB so both the per-site list and the all-entries list
 * compact together; the toggle mirrors its state for assistive tech.
 */
function applyCompactList(compact) {
  const tab = $('tab-vault')
  const btn = $('compactToggle')
  if (!tab) return
  tab.classList.toggle('popup-compact', !!compact)
  if (btn) {
    btn.setAttribute('aria-pressed', String(!!compact))
    btn.classList.toggle('popup-compact-on', !!compact)
  }
}

/** v2.7.0 — runs before or after DOMContentLoaded (slow import chain safe). */
// R95 §2 U-6 — disabled buttons NAME THEIR REASON: while no generated result
// exists, the result actions carry the enabling action in their tooltip; once
// a result exists the original titles are restored (never a bare disabled
// control — the reason is machine-translated ×3).
function genResultHints() {
  const hint = getMessage('genDisabledHint', undefined, 'Generate first — these actions unlock once a passphrase exists.')
  for (const id of ['copyBtn', 'useBtn', 'saveGenEntryBtn']) {
    const b = $(id)
    if (!b) continue
    if (!b.dataset.genTitle) b.dataset.genTitle = b.title || ''
    if (b.disabled) b.title = hint
    else if (b.dataset.genTitle) b.title = b.dataset.genTitle
    else b.removeAttribute('title')
  }
}

// R95 §2.4 — the popup lists support arrow-key navigation: a delegated
// handler moves focus between the list's focusable controls (buttons and
// [tabindex="0"] rows) with ArrowUp/ArrowDown; Home/End jump to the edges.
// Mouse and touch behavior is untouched — the arrows are an ADDITIVE
// affordance over the existing Tab order.
function wireListArrowNav() {
  for (const id of ['allEntries', 'siteEntries', 'totpList']) {
    const box = document.getElementById(id)
    if (!box || box.dataset.arrowNav === '1') continue
    box.dataset.arrowNav = '1'
    box.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return
      const rows = Array.from(box.querySelectorAll('button, [tabindex="0"]')).filter((el) => !(el instanceof HTMLButtonElement && el.disabled) && el.offsetParent !== null)
      if (rows.length < 2) return
      const i = rows.indexOf(document.activeElement)
      let next = -1
      if (e.key === 'ArrowDown') next = i < 0 ? 0 : Math.min(i + 1, rows.length - 1)
      else if (e.key === 'ArrowUp') next = i <= 0 ? rows.length - 1 : i - 1
      else if (e.key === 'Home') next = 0
      else next = rows.length - 1
      if (next >= 0 && rows[next]) { e.preventDefault(); rows[next].focus() }
    })
  }
}

async function init() {
  // S8.9 completion (R100): this open page hosts the beam's TRANSPORT ONLY
  // (ICE/SDP/data channel) while the sealed machinery stays in the worker.
  registerBeamExecutor('popup')
  // v2.17.0 — R26: honor the shared theme preference. The popup HTML is
  // hardcoded dark while the options page persists 'ucrypt:theme' — a user
  // on the light theme used to get a dark popup every single time.
  try {
    const { 'ucrypt:theme': theme } = await chrome.storage.local.get('ucrypt:theme')
    document.documentElement.setAttribute('data-theme', theme || 'dark')
  } catch { /* keep the HTML default */ }
  // v2.18.0 — R27-F10 (audit): the theme used to be read ONCE at popup init —
  // a theme change made in an already-open options page never reached a
  // concurrently open popup until it was closed and reopened.
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local' || !changes['ucrypt:theme']) return
      document.documentElement.setAttribute('data-theme', changes['ucrypt:theme'].newValue || 'dark')
    })
  } catch { /* storage listener unavailable — init read still applies */ }

  // v2.10.0 — localize the static UI (no-op when chrome.i18n is unavailable;
  // the English HTML content is the source of truth and never wiped).
  applyI18n()

  // R95 §2 — the UX regime: disabled buttons name their reason, and the
  // entry/token lists carry arrow-key navigation.
  genResultHints()
  wireListArrowNav() // R95 §2.4

  // R95 F-95-01 (CEO finding, heuristic audit H1): the version rides the lock
  // row — machine-derived from the manifest on EVERY surface (popup, vault
  // window, health window all run this init), never a hardcoded number
  // (law 0.11: one source, every carrier agrees).
  try {
    const verEl = $('popupVersion')
    if (verEl) {
      verEl.textContent = `v${chrome.runtime.getManifest().version}`
      verEl.setAttribute('title', getMessage('popupVersionTitle', undefined, 'UCrypt version'))
    }
  } catch { /* manifest unavailable — the em-dash placeholder stays truthful */ }

  // v2.21.0 — R30-F2: compact list density (Brave parity). Applied BEFORE the
  // first render so the vault tab never flashes the comfortable layout.
  try {
    const ui = await getPopupUi()
    applyCompactList(ui.compactList)
    $('compactToggle').addEventListener('click', async () => {
      const next = !$('tab-vault').classList.contains('popup-compact')
      applyCompactList(next)
      await savePopupUi({ compactList: next })
    })
  } catch { /* storage unavailable — comfortable density stays */ }

  prefs = await loadPrefs()
  prefsToUI()

  // Enter key submits the unlock/setup form
  $('unlockPass').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock()
  })
  $('setupPass2').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSetup()
  })

  $('unlockBtn').addEventListener('click', handleUnlock)
  $('setupBtn').addEventListener('click', handleSetup)
  // R100 (the CEO's "Take your stuff with you"): the import path is visible
  // at setup — the manager's join wizard takes over (it enforces the
  // local-vault-first ordering itself, law 3.1).
  document.getElementById('setupJoinBtn')?.addEventListener('click', () => {
    try { window.open(chrome.runtime.getURL('options.html#join'), '_blank') } catch { /* the popup may be closing */ }
  })
  // R101 §3 (the CEO's S3 wizard): the first-run MIGRATION entry — the
  // guided browser-import flow in Settings → Data (the vault-first law
  // holds: the wizard saves into an EXISTING vault only).
  document.getElementById('setupMigrateBtn')?.addEventListener('click', () => {
    try { window.open(chrome.runtime.getURL('options.html#data'), '_blank') } catch { /* the popup may be closing */ }
  })
  $('genBtn').addEventListener('click', handleGenerate)
  // R74 — bulk / analyze / mnemonic popup flows
  $('bulkCopyAllBtn').addEventListener('click', popupBulkCopyAll)
  $('bulkDownloadBtn').addEventListener('click', popupBulkDownload)
  $('bulkClearBtn').addEventListener('click', popupBulkClear)
  $('bulkCount').addEventListener('input', () => { $('bulkCountVal').textContent = $('bulkCount').value })
  $('anBtn').addEventListener('click', runAnalyze)
  $('mnCheckBtn').addEventListener('click', popupMnemonicCheck)
  $('mnWords').addEventListener('change', popupMnemonicPrefsFromUI)
  $('copyBtn').addEventListener('click', () => {
    if (!lastResult) return
    // R74 — high-risk confirm before copying a recovery phrase (same gate as
    // the Lab; the popup never saves or fills mnemonics).
    if (lastResult.kind === 'mnemonic' && !confirm(getMessage('mnConfirmCopy', undefined, 'Copy this recovery phrase to the clipboard? Anyone reading it can hold the funds.'))) return
    copyWithToast(lastResult.value)
  })
  $('fillBtn').addEventListener('click', async () => {
    const domain = $('currentDomain').textContent
    const entry = allEntriesCache.find(e => e.domain === domain)
    if (!entry) { toast('No saved logins for this site', 'error'); return }
    await fillEntry(entry)
  })
  $('syncBtn').addEventListener('click', handleSync)
  $('lockBtn').addEventListener('click', handleLock)
  $('lockDot').addEventListener('click', handleLock)
  $('healthRerun').addEventListener('click', refreshHealthTab)
  $('healthExport').addEventListener('click', exportHealthCsv)

  // 2FA (TOTP authenticator) — v2.4.0
  $('totpAddToggle').addEventListener('click', () => toggleTotpAddBox())
  $('totpCancelBtn').addEventListener('click', () => toggleTotpAddBox(false))
  $('totpSaveBtn').addEventListener('click', handleTotpSave)
  $('totpUri').addEventListener('input', async () => {
    // A clean URI parse prefills the manual fields (visible confirmation).
    const uri = $('totpUri').value.trim()
    const parsed = uri ? parseOtpauthUri(uri) : null
    if (parsed) {
      $('totpLabel').value = parsed.label
      $('totpIssuer').value = parsed.issuer
      $('totpSecret').value = parsed.secret
      $('totpDigits').value = String(parsed.digits)
      $('totpPeriod').value = String(parsed.period)
      $('totpAlgo').value = parsed.algorithm
    }
    await refreshTotpPreview()
  })
  for (const id of ['totpSecret', 'totpLabel', 'totpIssuer']) {
    $(id).addEventListener('input', refreshTotpPreview)
  }
  for (const id of ['totpDigits', 'totpPeriod', 'totpAlgo']) {
    $(id).addEventListener('change', refreshTotpPreview)
  }

  // R97 §4 — QR scan-from-image: a pasted image or a picked file decodes to
  // an otpauth:// URI that lands in the totpUri field — the SAME visible
  // path as a paste: the R41 live preview validates it before anything is
  // saved. No silent writes, ever.
  async function scanTotpImage(blob) {
    const r = await globalThis.UCryptQrScan.decodeFromBlob(blob)
    const errEl = $('totpAddError')
    if (!r.ok) {
      const codes = { 'not-image': ['qrErrNotImage', 'That clipboard item is not an image.'], 'too-large': ['qrErrTooLarge', 'That image is too large — the limit is 8 MB.'], 'unreadable': ['qrErrUnreadable', "Couldn't read that image — try a PNG or JPEG."], 'no-qr': ['qrErrNoQr', 'No QR code found in that image. Try a sharper or larger screenshot.'], 'error': ['qrErrUnreadable', "Couldn't read that image — try a PNG or JPEG."] }
      const [key, fb] = codes[r.code] || codes['error']
      errEl.textContent = getMessage(key, undefined, fb)
      show(errEl, true)
      return
    }
    const kind = globalThis.UCryptQrScan.classify(r.text)
    if (kind === 'pairing') {
      errEl.textContent = getMessage('qrErrWrongKindTotp', undefined, 'That QR code holds a sync pairing code — use it on the Sync tab to join a chain.')
      show(errEl, true)
      return
    }
    if (kind !== 'otpauth') {
      errEl.textContent = getMessage('qrErrNotOtpauth', undefined, 'That QR code is not a 2FA code (no otpauth:// payload).')
      show(errEl, true)
      return
    }
    show(errEl, false)
    $('totpUri').value = r.text
    $('totpUri').dispatchEvent(new Event('input')) // prefill + the live preview
    toast(getMessage('qrScanOkTotp', undefined, '2FA code read from the image — check the live preview, then save.'))
  }
  $('totpQrScanBtn').addEventListener('click', () => $('totpQrFile').click())
  $('totpQrFile').addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0]
    e.target.value = '' // allow re-picking the same file
    if (f) await scanTotpImage(f)
  })
  document.addEventListener('paste', async (e) => {
    if ($('totpAddBox').classList.contains('hidden')) return // the add box is closed
    const items = e.clipboardData && e.clipboardData.items
    if (!items) return
    for (const it of items) {
      if (it.kind === 'file' && /^image\//.test(it.type || '')) {
        const blob = it.getAsFile()
        if (blob) { e.preventDefault(); await scanTotpImage(blob); return }
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
  $('openVault').addEventListener('click', (e) => {
    e.preventDefault()
    chrome.runtime.openOptionsPage()
  })
  // R72 — Generator Lab handoff + Use/Save actions (all explicit)
  $('openGenLab').addEventListener('click', (e) => {
    e.preventDefault()
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html#generator') })
    window.close()
  })
  $('useBtn').addEventListener('click', useOnPage)
  $('saveGenEntryBtn').addEventListener('click', saveGenerated)
  $('genOutput').addEventListener('click', () => {
    // Click-to-reveal after auto-hide (masking is display-only, §3.2)
    if (popupMasked && lastResult) popupSetMasked(false)
  })
  // R91 §3.5d (CEO S-F) — settings open as a REAL PAGE. The gear (and every
  // settings entry point) opens the options page as a real browser tab via
  // chrome.runtime.openOptionsPage() — never a floating layer. (The R56
  // window-layer SETTINGS affordance is retired from this entry point by
  // owner order; the vault WINDOW surface itself is untouched.)
  $('settingsWindowBtn')?.addEventListener('click', async () => {
    try {
      await chrome.runtime.openOptionsPage()
      window.close()
    } catch (e) {
      // openOptionsPage can refuse only in exotic embedder contexts — the
      // honest typed fallback names the failure, it never silently no-ops.
      toast(getMessage('settingsOpenFailed', [e.message], `Could not open settings: ${e.message}`), 'error')
    }
  })
  // R79-B (owner screenshot 20261002_200402: "Where is the share file
  // feature?!") — the discoverable entry point for the trusted device
  // transfer. R118 §2.2 (the CEO's S2): the popup doors route to their own
  // TABS — this door opens the Device Transfer tab (the canonical door, law
  // 0.31); the label already carries its audience. The transfer window
  // route (TRANSFER_OPEN_WINDOW) stays wired in the worker — the standalone
  // window remains the programmatic terminal; the tab is the user's door.
  $('shareWindowBtn')?.addEventListener('click', async () => {
    try {
      try { await chrome.storage.local.set({ 'ucrypt:openTab': 'transfer' }) } catch { /* the options page still opens */ }
      await chrome.runtime.openOptionsPage()
      window.close()
    } catch (e) {
      toast(getMessage('shareWindowFailed', [e.message], `Could not open the transfer window: ${e.message}`), 'error')
    }
  })
  // R56-POPUP-WINDOW — running as the resizable VAULT WINDOW
  // (chrome.windows.create, popup.html?window=1): report geometry so the next
  // open restores it (device-local only; lineage R49 §5.3 port).
  // R59-F5 — the TAB fallback (tab=1) never reports bounds: a tab's viewport
  // must not pollute the persisted popup-window size.
  try {
    if (WINDOW_MODE) {
      document.documentElement.classList.add('vault-window')
      if (!TAB_FALLBACK) {
        let boundsTimer = null
        const sendBounds = () => {
          clearTimeout(boundsTimer)
          boundsTimer = setTimeout(() => {
            bgSend('VAULT_WINDOW_BOUNDS', {
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
    }
  } catch { /* not a window surface — nothing to persist */ }
  // R91 §3.5a (CEO S-E) — LABEL-TRUTH: in the vault-window surface the
  // header carries an action-named "Close window" button (a button names its
  // action, not its surface). Toolbar popup never shows it — dismissing the
  // popup IS closing it.
  if (WINDOW_MODE || TAB_FALLBACK) {
    const closeBtn = $('vaultWindowCloseBtn')
    if (closeBtn) {
      closeBtn.classList.remove('hidden')
      closeBtn.addEventListener('click', () => window.close())
    }
  }
  $('openSyncSetup').addEventListener('click', async () => {
    // Deep-link the Sync tab (v2.3.0 options hash routing)
    try { await chrome.storage.local.set({ 'ucrypt:openTab': 'sync' }) } catch { /* the deep-link hint is best-effort — the options page defaults to its own tab (named-swallow law, R169 C1) */ }
    chrome.runtime.openOptionsPage()
    window.close()
  })

  // R61-A §1.3 — first-class Join route: the popup Sync tab and the
  // first-run/onboarding choice both deep-link the guided join wizard
  // (options.html#join). The wizard itself enforces the local-vault-first
  // ordering — no vault, no words entry.
  const openJoinRoute = () => {
    try { window.open(chrome.runtime.getURL('options.html#join'), '_blank') } catch { /* the window open is best-effort — a blocked popup routes the user to Options manually (named-swallow law, R169 C1) */ }
    window.close()
  }
  $('openJoinChain')?.addEventListener('click', openJoinRoute)
  $('frJoinChain')?.addEventListener('click', openJoinRoute)
  // R89 (Brave Rank 2): the roster's Refresh re-reads the presence view.
  $('rosterRefresh')?.addEventListener('click', async () => {
    const b = $('rosterRefresh')
    if (b) b.disabled = true
    try { await refreshSyncTab() } finally { if (b) b.disabled = false }
  })

  // Tabs
  document.querySelectorAll('.popup-tab').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab))
  })

  // Generator modes + options wiring
  document.querySelectorAll('.popup-seg').forEach(seg => {
    seg.addEventListener('click', () => switchMode(seg.dataset.mode))
  })
  wireTablistKeyboard()
  const sliderIds = [
    ['randLength', 'randLengthVal'],
    ['ppWords', 'ppWordsVal'],
    ['pinLength', 'pinLengthVal'],
  ]
  for (const [input, out] of sliderIds) {
    $(input).addEventListener('input', () => { $(out).textContent = $(input).value })
  }
  document.querySelectorAll('#tab-generate input, #tab-generate select').forEach(el => {
    el.addEventListener('change', () => { prefsFromUI(); savePrefs() })
  })
  document.querySelectorAll('.popup-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const preset = PRESETS[chip.dataset.preset]
      if (!preset) return
      prefs.random = { ...prefs.random, ...preset.random }
      savePrefs().then(() => { prefsToUI(); handleGenerate() })
      toast(`${chip.textContent.trim()} preset applied`)
    })
  })

  // Vault filter
  $('vaultFilter').addEventListener('input', renderAllEntries)

  // v2.16.0 — vault sort selector (shared preference with the options
  // vault manager; lib/prefs.js getVaultSort/vaultSortComparator).
  try {
    const sortSel = $('vaultSort')
    if (sortSel) {
      vaultSortMode = await getVaultSort()
      sortSel.value = vaultSortMode
      sortSel.addEventListener('change', async () => {
        vaultSortMode = sortSel.value
        await setVaultSort(vaultSortMode)
        renderAllEntries()
      })
    }
  } catch { /* sorting stays on the default when storage is unavailable */ }

  // Keyboard: G = generate, 1/2/3/4/5 = switch tab (no modifiers, not in inputs).
  // v2.12.0 — the numbers now follow the VISIBLE tab order
  // (1 Generate · 2 Vault · 3 2FA · 4 Health · 5 Sync); the old mapping
  // jumped 3→Sync / 4→2FA / 5→Health and contradicted what the tab bar shows.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.activeElement === $('vaultFilter')) {
      const vf = $('vaultFilter')
      if (vf && vf.value) {
        vf.value = ''
        renderAllEntries()
      } else if (vf) {
        vf.blur()
      }
      return
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return
    if (document.activeElement && ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) return
    if (e.key === '/') {
      e.preventDefault()
      switchTab('vault')
      setTimeout(() => { $('vaultFilter')?.focus() }, 20)
      return
    }
    if (e.key === 'g' || e.key === 'G') handleGenerate()
    if (e.key === '1') switchTab('generate')
    if (e.key === '2') switchTab('vault')
    if (e.key === '3') switchTab('totp')
    if (e.key === '4') switchTab('health')
    if (e.key === '5') switchTab('sync')
  })

  // R45-C/R77-A — native-manager state card: click toggle + live browser-side
  // changes + live device-local behavior-pref changes + settings shortcut.
  const nmBtn = $('nmToggle')
  if (nmBtn) {
    nmBtn.addEventListener('click', nmToggleClick)
    $('nmReviewSettings')?.addEventListener('click', () => {
      try { chrome.tabs.create({ url: 'chrome://settings/passwords' }) } catch { /* chrome:// not openable here */ }
    })
    await refreshNativeManagerCard()
    // The worker broadcasts when the BROWSER (policy / another extension /
    // the user in settings) changes passwordSavingEnabled — the card tells
    // the truth immediately instead of showing a stale state.
    try {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg && msg.type === 'NATIVE_MANAGER_CHANGED' && msg.status) {
          refreshNativeManagerCard()
        }
      })
    } catch { /* listener unavailable — the card refreshes on open */ }
    // R169 G228 — THE ORPHAN-SWEEP CURE (the E-5/E-6 class): the popup rides
    // the same broadcast seat as the options page — UCRYPT_STARTUP_CHECK and
    // UCRYPT_SYNC_RUN refresh the open Sync tab when the background announces
    // the cycle. Best-effort; nothing throws into the message bus.
    try {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg && (msg.type === 'UCRYPT_STARTUP_CHECK' || msg.type === 'UCRYPT_SYNC_RUN')) {
          try { refreshSyncTab() } catch { /* the tab refreshes on open */ }
        }
      })
    } catch { /* listener unavailable — the tab refreshes on open */ }
    // R77-A — the four UCrypt rows must reflect ACTUAL stored state even when
    // the toggles change in the options page while this popup is open.
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes[BEHAVIOR_KEY]) refreshNativeManagerCard()
      })
    } catch { /* best-effort live refresh */ }
  }

  // R77-B (owner screenshots 20261002_131857/132604) — Edge forces the action
  // popup window wider than the fixed body, leaving a large dead right
  // gutter. Pin the body's min-width to the REAL granted window width so the
  // content fills it; in Chrome the window hugs the body and this is a
  // no-op. Re-pins on resize so any browser-forced size change stays filled.
  // R79-B (owner screenshots 20261002_200402/200734) — the content width is
  // now a FIXED pattern: default 400px (+20 owner increase), filled up to a
  // 465px cap so a browser that grants MORE (Edge's occasional 565px+ popup,
  // see the Health screenshot) keeps the same width pattern as every other
  // area instead of stretching. The user-resizable vault window
  // (WINDOW_MODE) always fills at every size — it is a real window, not the
  // action popup.
  const POPUP_DEFAULT_W = 400
  const POPUP_PATTERN_CAP = 465
  const fillPopupWidth = () => {
    try {
      const w = Math.floor(window.innerWidth)
      if (w >= POPUP_DEFAULT_W) {
        document.body.style.minWidth = (WINDOW_MODE ? w : Math.min(w, POPUP_PATTERN_CAP)) + 'px'
      }
    } catch { /* non-DOM context guard */ }
  }
  fillPopupWidth()
  try { window.addEventListener('resize', fillPopupWidth) } catch { /* noop */ }

  // R45-E — the explicit first-run choice buttons.
  $('frUcryptOnly')?.addEventListener('click', () => recordFirstRun('ucrypt-only'))
  $('frAlongside')?.addEventListener('click', () => recordFirstRun('alongside'))
  $('frLater')?.addEventListener('click', () => recordFirstRun('later'))

  // R59-F4 — passphrase show/hide toggles (type swap only; the value is
  // never logged, never stored, autocomplete attributes unchanged).
  for (const [eyeId, inputId] of [['unlockEye', 'unlockPass'], ['setupEye', 'setupPass'], ['setupEye2', 'setupPass2']]) {
    const eye = $(eyeId)
    const input = $(inputId)
    if (!eye || !input) continue
    eye.addEventListener('click', () => {
      const show = input.type === 'password'
      input.type = show ? 'text' : 'password'
      eye.textContent = show ? '🙈' : '👁'
      eye.setAttribute('aria-pressed', String(show))
      const label = show ? getMessage('pEyeHide', undefined, 'Hide passphrase') : getMessage('pEyeShow', undefined, 'Show passphrase')
      eye.setAttribute('aria-label', label)
      eye.setAttribute('title', label)
      input.focus()
    })
  }

  // R59-F5 — "Open full Health report" (toolbar summary → vault window).
  $('healthOpenFull')?.addEventListener('click', openFullHealthReport)

  await refresh()

  // R59-F5 — the health window lands on the FULL report automatically.
  if (WINDOW_MODE && HEALTH_SURFACE) {
    try { switchTab('health') } catch { /* the tab bar still works manually */ }
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => { init().catch(e => console.error('[UCrypt] popup init failed:', e)) })
} else {
  init().catch(e => console.error('[UCrypt] popup init failed:', e))
}
