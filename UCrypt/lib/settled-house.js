/**
 * ════════════════════════════════════════════════════════════════════════
 * R170 — THE SETTLED HOUSE — THE SHARED DISCLOSURE COMPONENT (R-170.1).
 *
 * ONE pattern for the whole app: a titled, hinted, keyboard-operable
 * disclosure (`<details class="settled-area" data-settled-area="…">`) whose
 * open/closed choice PERSISTS per area across sessions, whose DEFAULTS
 * follow the settled-house law (the primary path expanded; every
 * alternative, advanced, and danger seat closed), and whose fire exception
 * is mechanical: an area holding an active error, warning, or required
 * action AUTO-REVEALS — no card may hide a fire.
 *
 * A leaf module — zero imports — so options.js and lib/ladder-ui.js can
 * both ride it without a cycle.
 *
 * The shape (the battery pins it):
 *   <details class="settled-area" data-settled-area="your-devices">
 *     <summary>
 *       <h2>…title…</h2>
 *       <span class="settled-hint">…one-line hint…</span>  (optional)
 *     </summary>
 *     …area content…
 *   </details>
 *
 * API:
 *   SettledHouse.apply(areaId, detailsEl, defaultOpen)
 *     — apply the persisted state (or the default), wire the toggle
 *       persistence. Returns 'open' | 'closed'.
 *   SettledHouse.reveal(areaId)
 *     — THE FIRE EXCEPTION: open the area now, persist the choice, and
 *       stamp data-fire-revealed="true" (the battery's machine check).
 *       Returns true when an area was found and revealed.
 *   SettledHouse.applyAll(rootEl, defaultsMap)
 *     — convenience: apply every [data-settled-area] under rootEl.
 *   SettledHouse.DEFAULTS
 *     — the named defaults (the law's row per area; documentation AND the
 *       machine-readable floor the battery asserts against).
 * ════════════════════════════════════════════════════════════════════════
 */

const STORE_KEY = 'ucrypt:settledHouse'

/** The named defaults — the settled-house law, row per area. `true` = the
 * primary path (expanded by default); `false` = an alternative, advanced,
 * or danger seat (collapsed by default). The battery asserts this map. */
export const DEFAULTS = Object.freeze({
  // Cloud Sync tab (E-19): the status card is the primary; the three named
  // areas collapse under it.
  'your-devices': false,
  'cloud-backup': false,
  'conflict-resolver': false,
  'sync-advanced': false,
  // The guided-setup ladder (E-20): Fast is the proven primary (the
  // owner's GREEN stamp) and stays expanded; the alternatives collapse.
  'ladder-guided': false,
  'ladder-selfcheck': false,
  'ladder-manual': false,
  // The manual OAuth configuration (E-21): the alternative path — collapsed
  // whenever the Fast rung is present (the caller passes its default).
  'tw-advanced-config': false,
  // The Security division (E-22 / R-170.3): the passphrase and auto-lock
  // areas are the tab's primary-grade seats; everything else collapses;
  // the danger zone is collapsed AND quarantined.
  'sec-behavior': false,
  'sec-autofill': false,
  'sec-site-never-save': false,
  'sec-site-never-fill': false,
  'sec-adoption': false,
  'sec-totp': false,
  'sec-breach': false,
  'sec-native': false,
  'sec-passkeys': false,
  'sec-verify': false,
  'sec-acc-route': false,
  'sec-danger-zone': false,
  'sec-sync-doctor': false,
  'sec-chain-data': false,
  // Vault tab progressive disclosures: Vault Manager stays expanded at the top;
  // analytical health dashboards and browser autofill deep-links collapse cleanly.
  'vault-health': false,
  'password-health': false,
  'vault-autofill-guide': false,
  // Direct Share tab: Sender and Receiver cards stay expanded; history ledger collapses.
  'ds-ledger': false,
  // Export/Import tab: primary backup & migration cards stay expanded; secondary utilities collapse.
  'data-coherence': false,
  'data-diagnostics': false,
  'data-bookmarks-restore': false,
  'data-xb-import': false,
})

let cache = null
let pending = null

function readStore() {
  if (cache) return Promise.resolve(cache)
  if (pending) return pending
  pending = new Promise((resolve) => {
    try {
      // chrome.storage.local — the same seam the options page already uses
      // for its prefs (PREFS_KEY). In battery/engine contexts without the
      // storage API the law degrades HONESTLY: defaults apply, nothing
      // persists, nothing throws.
      chrome.storage.local.get(STORE_KEY, (r) => {
        cache = (r && r[STORE_KEY] && typeof r[STORE_KEY] === 'object') ? r[STORE_KEY] : {}
        resolve(cache)
      })
    } catch {
      cache = {}
      resolve(cache)
    }
  })
  return pending
}

function writeStore(map) {
  cache = map
  try {
    chrome.storage.local.set({ [STORE_KEY]: map }, () => { void chrome.runtime.lastError })
  } catch { /* the engine context has no storage — the defaults still apply */ }
}

export const SettledHouse = {
  DEFAULTS,

  /** Apply the persisted (or default) open state to one area and wire the
   * toggle persistence. Returns the applied state ('open' | 'closed'). */
  async apply(areaId, detailsEl, defaultOpen = null) {
    if (!detailsEl || typeof detailsEl !== 'object') return 'closed'
    detailsEl.setAttribute('data-settled-area', areaId)
    const map = await readStore()
    const def = defaultOpen !== null ? !!defaultOpen : !!DEFAULTS[areaId]
    const stored = map[areaId]
    const open = (typeof stored === 'boolean') ? stored : def
    try { detailsEl.open = open } catch { /* a detached node still carries the attribute */ }
    if (open) detailsEl.setAttribute('open', '')
    else detailsEl.removeAttribute('open')
    if (!detailsEl.dataset.settledWired) {
      detailsEl.dataset.settledWired = '1'
      detailsEl.addEventListener('toggle', () => {
        // the user's choice persists per area across sessions (R-170.1)
        try {
          readStore().then((m) => {
            m[areaId] = !!detailsEl.open
            writeStore(m)
          })
        } catch { /* the persistence is best-effort; the area still works */ }
      })
    }
    return open ? 'open' : 'closed'
  },

  /** THE FIRE EXCEPTION (R-170.1): reveal an area that holds an active
   * error, warning, or required action. Opens it, persists the choice, and
   * stamps data-fire-revealed="true" so the machine and the user both see
   * the reveal was the fire's work, not a lost toggle. */
  async reveal(areaId) {
    const el = document.querySelector(`details[data-settled-area="${CSS.escape(areaId)}"]`)
    if (!el) return false
    try { el.open = true } catch { return false }
    el.setAttribute('open', '')
    el.setAttribute('data-fire-revealed', 'true')
    try {
      readStore().then((m) => { m[areaId] = true; writeStore(m) })
    } catch { /* the reveal itself never depends on the persistence */ }
    return true
  },

  /** Apply every [data-settled-area] under a root element. Areas already
   * applied (wired) keep their state; defaults come from the DEFAULTS map
   * (or the optional overrides). */
  async applyAll(rootEl, overrides = null) {
    const areas = (rootEl || document).querySelectorAll('details[data-settled-area]')
    const out = {}
    for (const el of areas) {
      const id = el.getAttribute('data-settled-area')
      const def = overrides && Object.prototype.hasOwnProperty.call(overrides, id)
        ? !!overrides[id]
        : null
      out[id] = await SettledHouse.apply(id, el, def)
    }
    return out
  },
}
