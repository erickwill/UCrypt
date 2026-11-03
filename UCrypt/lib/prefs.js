/**
 * UCrypt — Popup preferences merge (v2.3.1).
 *
 * BUG this module fixes: popup.js rebuilt `prefs.random` from ONLY the fields
 * the popup UI renders, silently dropping keys the options Generator tab can
 * set (noDuplicates, noSequences, excludeChars, customSymbols…). A user who
 * enabled "no duplicates" in Settings had that security preference reset to
 * the generator default the first time they generated from the popup.
 *
 * The merge is the single source of truth for both entry points and is pure,
 * so it is unit-tested directly (tests/round11-test.mjs).
 */

export const POPUP_PREFS_DEFAULTS = {
  lastMode: 'random',
  random: {
    length: 20,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: true,
    noDuplicates: false,
    noSequences: false,
    excludeChars: '',
    customSymbols: '',
    firstCharLetter: false,
  },
  passphrase: {
    wordCount: 6,
    separator: '-',
    capitalize: true,
    addNumber: true,
    addSymbol: true,
    wordlist: 'large',
    padBetweenWords: false,
    minWordLength: 0,
    maxWordLength: 0,
    excludePattern: '',
  },
  pin: {
    length: 6,
    noRepeats: true,
    noSequences: true,
  },
  pronounceable: {
    syllables: 4,
    capitalize: true,
    addNumber: true,
    addSymbol: true,
  },
}

// ---------------------------------------------------------------------------
// R72 — Generator Lab schema (one validated preference model, §2.1).
// `lastMode` is the POPUP's mode memory; `managerMode` is the FULL MANAGER
// Generator Lab's tab memory. Two surfaces, two mode memories, ONE shared
// option store — the popup and the manager never reset each other's settings,
// and unknown future fields survive every merge (applyPickedPrefs folds the
// stored object back in before overlaying picked fields).
// ---------------------------------------------------------------------------

export const GENERATOR_LAB_DEFAULTS = {
  managerMode: 'random',
  autoHideSeconds: 30, // Off = 0; display-only masking — never closes dialogs
  showComposition: true,
  bulkCount: 10,
  bulkMode: 'random',
  historyEnabled: false, // R72 §8: session-only redacted metadata, default OFF
}

export const LAB_MODES = ['random', 'passphrase', 'pin', 'pronounceable', 'bulk', 'analyze', 'mnemonic']

/** Numeric clamps for the Lab schema (validated, fail-closed to defaults). */
const LAB_CLAMPS = {
  autoHideSeconds: [0, 10, 20, 30, 60],
  bulkCount: [2, 100],
}

/**
 * Merge saved Lab prefs over the defaults. Unknown keys are preserved,
 * numbers are validated against the documented bounds, and only known
 * enumerable values (managerMode, bulkMode, autoHideSeconds) are accepted —
 * anything else falls back to its default.
 */
export function mergeLabPrefs(saved) {
  const s = saved && typeof saved === 'object' ? saved : {}
  const merged = { ...GENERATOR_LAB_DEFAULTS }
  for (const k of ['managerMode']) {
    if (LAB_MODES.includes(s[k])) merged[k] = s[k]
  }
  if (['random', 'passphrase', 'pin', 'pronounceable'].includes(s.bulkMode)) merged.bulkMode = s.bulkMode
  if (typeof s.showComposition === 'boolean') merged.showComposition = s.showComposition
  if (typeof s.historyEnabled === 'boolean') merged.historyEnabled = s.historyEnabled
  const ah = Number(s.autoHideSeconds)
  merged.autoHideSeconds = LAB_CLAMPS.autoHideSeconds.includes(ah) ? ah : GENERATOR_LAB_DEFAULTS.autoHideSeconds
  const bc = Math.floor(Number(s.bulkCount))
  if (Number.isFinite(bc) && bc >= LAB_CLAMPS.bulkCount[0] && bc <= LAB_CLAMPS.bulkCount[1]) {
    merged.bulkCount = bc
  }
  // Unknown future fields survive the merge (never dropped, never validated away).
  for (const [k, v] of Object.entries(s)) {
    if (!(k in merged)) merged[k] = v
  }
  return merged
}

/**
 * Merge saved popup prefs over the defaults (missing keys filled in),
 * preserving per-mode key sets exactly.
 *
 * @param {{lastMode?:string, random?:object, passphrase?:object, pin?:object}} [saved]
 * @returns fully-merged prefs object
 */
export function mergePopupPrefs(saved) {
  const s = saved && typeof saved === 'object' ? saved : {}
  return {
    lastMode: typeof s.lastMode === 'string' ? s.lastMode : POPUP_PREFS_DEFAULTS.lastMode,
    random: { ...POPUP_PREFS_DEFAULTS.random, ...(s.random || {}) },
    passphrase: { ...POPUP_PREFS_DEFAULTS.passphrase, ...(s.passphrase || {}) },
    pin: { ...POPUP_PREFS_DEFAULTS.pin, ...(s.pin || {}) },
  }
}

/**
 * Fold the values picked in the popup UI back into the stored prefs WITHOUT
 * dropping keys the popup does not render. `picked` must be a plain object
 * of the same mode-shape.
 *
 * @param {object} currentPrefs the full merged prefs object
 * @param {'random'|'passphrase'|'pin'} mode
 * @param {object} picked fields from the popup controls
 * @returns a NEW prefs object (input never mutated)
 */
export function applyPickedPrefs(currentPrefs, mode, picked) {
  const base = currentPrefs && typeof currentPrefs === 'object' ? currentPrefs : {}
  const modeDefaults = POPUP_PREFS_DEFAULTS[mode] || {}
  const p = picked && typeof picked === 'object' ? picked : {}
  // Start from DEFAULTS so a mode object always has a complete shape, keep
  // every unknown/extra key from the stored value, then overlay the picked
  // fields. Lengths are re-validated as finite numbers within sane bounds.
  const merged = { ...(modeDefaults || {}), ...(base[mode] || {}), ...p }
  for (const k of ['length', 'wordCount', 'syllables']) {
    if (k in merged) {
      const n = Number(merged[k])
      if (!Number.isFinite(n) || n < 1) merged[k] = modeDefaults[k] ?? 1
      else merged[k] = Math.floor(n)
    }
  }
  // R72 bounds: random length 4–256 (§2.2), PIN length 3–16 (§2.4).
  if (mode === 'random' && typeof merged.length === 'number') {
    merged.length = Math.min(256, Math.max(4, merged.length))
  }
  if (mode === 'pin' && typeof merged.length === 'number') {
    merged.length = Math.min(16, Math.max(3, merged.length))
  }
  if (mode === 'passphrase' && typeof merged.wordCount === 'number') {
    merged.wordCount = Math.min(64, Math.max(1, merged.wordCount))
  }
  if (mode === 'pronounceable' && typeof merged.syllables === 'number') {
    merged.syllables = Math.min(12, Math.max(1, merged.syllables))
  }
  return { ...base, lastMode: mode, [mode]: merged }
}

// ---------------------------------------------------------------------------
// v2.16.0 — Vault list sort preference (shared by popup + options).
// Device-local UX preference, not vault data: it lives in its own
// chrome.storage.local key so both surfaces read/write one source of truth.
// ---------------------------------------------------------------------------

export const VAULT_SORTS = ['site', 'name', 'used', 'changed']

const VAULT_SORT_KEY = 'ucrypt:vaultSort'

/** Read the vault sort mode (defaults to 'site' — the historical order). */
export async function getVaultSort() {
  try {
    const { [VAULT_SORT_KEY]: s } = await chrome.storage.local.get(VAULT_SORT_KEY)
    return VAULT_SORTS.includes(s) ? s : 'site'
  } catch { return 'site' }
}

/** Persist the vault sort mode (silently ignores invalid modes). */
export async function setVaultSort(mode) {
  if (!VAULT_SORTS.includes(mode)) return
  try { await chrome.storage.local.set({ [VAULT_SORT_KEY]: mode }) } catch { /* best-effort */ }
}

/**
 * The comparator for each sort mode. Pure — unit-testable directly.
 *   site    — domain A→Z, then username (the historical fixed order)
 *   name    — username A→Z, then domain
 *   used    — most-recently-USED first (device-local lastUsedAt), then most
 *             recently changed — entries never filled sort by recency too
 *   changed — most-recently-chANGED (updatedAt) first
 */
export function vaultSortComparator(mode) {
  const site = (a, b) =>
    String(a.domain || '').localeCompare(String(b.domain || '')) ||
    String(a.username || '').localeCompare(String(b.username || ''))
  const name = (a, b) =>
    String(a.username || '').localeCompare(String(b.username || '')) ||
    String(a.domain || '').localeCompare(String(b.domain || ''))
  const recency = (key) => (a, b) =>
    (Number(b[key]) || 0) - (Number(a[key]) || 0)
  switch (mode) {
    case 'name': return name
    case 'used': return (a, b) => recency('lastUsedAt')(a, b) || recency('updatedAt')(a, b)
    case 'changed': return recency('updatedAt')
    case 'site':
    default: return site
  }
}

// ---------------------------------------------------------------------------
// v2.21.0 — R30-F2: popup list DENSITY (information-density pass). Brave
// exposes a compact mode for its saved-password list; UCrypt's popup rows
// were fixed two-line rows regardless of how much information the user
// actually wants. Compact mode: single-line rows (the domain·mask sub-line
// hides), tighter padding — roughly double the visible rows on the same
// popup height. Device-local (chrome.storage.local), one storage key.
// ---------------------------------------------------------------------------

export const POPUP_UI_KEY = 'ucrypt:popupUi'

export const POPUP_UI_DEFAULTS = { compactList: false }

/** Read the popup UI prefs (missing keys fall back to the defaults). */
export async function getPopupUi() {
  try {
    const { [POPUP_UI_KEY]: saved } = await chrome.storage.local.get(POPUP_UI_KEY)
    return { ...POPUP_UI_DEFAULTS, ...(saved && typeof saved === 'object' ? saved : {}) }
  } catch { return { ...POPUP_UI_DEFAULTS } }
}

/** Persist a patch of the popup UI prefs (best-effort). */
export async function savePopupUi(patch) {
  try {
    const cur = await getPopupUi()
    await chrome.storage.local.set({ [POPUP_UI_KEY]: { ...cur, ...patch } })
  } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// v2.17.0 — R26-B2: global BEHAVIOR toggles (Brave parity). Brave exposes
// "Offer to save passwords" and "Auto sign-in" as two switches; UCrypt had
// both behaviors hard-wired ON with no way to turn them off. Device-local,
// one storage key; the content script reads it directly (chrome.storage is
// available to content scripts) and the options Security tab edits it.
// ---------------------------------------------------------------------------

export const BEHAVIOR_KEY = 'ucrypt:behavior'

// v2.42.8 — R71-P: two new device-local behavior toggles, same key and same
// merge contract as the R26 pair. `profileFill` gates the FOCUS-TRIGGERED
// protected profile picker (explicit context-menu fill is never gated);
// `profileCapture` gates the POST-SUBMIT "Save these details?" review
// prompt (explicit context-menu capture is never gated either).
export const BEHAVIOR_DEFAULTS = {
  offerSave: true, autoFill: true, showIdentifiers: true,
  profileFill: true, profileCapture: true,
  // R85 (§6 CEO-mandated): 'auto' fills on page load when exactly one login
  // matches and suggests passkeys; 'prompt' NEVER fills without an explicit
  // user selection (the anchored dropdown remains available). Default 'auto'
  // preserves the historical behavior.
  autofillMode: 'auto',
}

/** Read the behavior toggles (defaults ON — the historical behavior).
 *  R59-F1 — `showIdentifiers` (device-local, never synced): full usernames/
 *  emails in the website picker. Default ON per the owner display contract. */
export async function getBehaviorPrefs() {
  try {
    const { [BEHAVIOR_KEY]: b } = await chrome.storage.local.get(BEHAVIOR_KEY)
    return {
      offerSave: !b || typeof b.offerSave !== 'boolean' ? true : b.offerSave,
      autoFill: !b || typeof b.autoFill !== 'boolean' ? true : b.autoFill,
      showIdentifiers: !b || typeof b.showIdentifiers !== 'boolean' ? true : b.showIdentifiers,
      profileFill: !b || typeof b.profileFill !== 'boolean' ? true : b.profileFill,
      profileCapture: !b || typeof b.profileCapture !== 'boolean' ? true : b.profileCapture,
      autofillMode: !b || (b.autofillMode !== 'auto' && b.autofillMode !== 'prompt') ? 'auto' : b.autofillMode,
    }
  } catch { return { ...BEHAVIOR_DEFAULTS } }
}

/** Merge-save the behavior toggles; unknown keys keep their current value. */
export async function saveBehaviorPrefs(patch) {
  const cur = await getBehaviorPrefs()
  const next = {
    offerSave: typeof patch?.offerSave === 'boolean' ? patch.offerSave : cur.offerSave,
    autoFill: typeof patch?.autoFill === 'boolean' ? patch.autoFill : cur.autoFill,
    showIdentifiers: typeof patch?.showIdentifiers === 'boolean' ? patch.showIdentifiers : cur.showIdentifiers,
    profileFill: typeof patch?.profileFill === 'boolean' ? patch.profileFill : cur.profileFill,
    profileCapture: typeof patch?.profileCapture === 'boolean' ? patch.profileCapture : cur.profileCapture,
    autofillMode: (patch?.autofillMode === 'auto' || patch?.autofillMode === 'prompt') ? patch.autofillMode : cur.autofillMode,
  }
  try { await chrome.storage.local.set({ [BEHAVIOR_KEY]: next }) } catch { /* best-effort */ }
  return next
}
