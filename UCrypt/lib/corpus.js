/**
 * UCrypt — lazy corpus loader (v2.21.0, R30-F1: SW payload slimming).
 *
 * WHY: breach.js (93 KB) + wordlists.js (118 KB) — ~211 KB of static data —
 * used to be loaded EAGERLY on every surface that needed the analyzer or the
 * generator:
 *   - the MV3 service worker imported them statically at the top level, so
 *     every worker WAKE parsed ~211 KB before answering even a simple
 *     GET_STATE (cold-start cost on the hottest code path there is), and
 *   - popup.html / options.html loaded both as classic <script src> tags, so
 *     every popup OPEN paid the parse too — the popup is the extension's
 *     most-opened surface.
 *
 * The corpora are side-effect modules: breach.js sets globalThis.CRYPTKEY_BREACH
 * (a Set of breached passwords) and wordlists.js sets globalThis.CRYPTKEY_WORDLISTS.
 * They are needed ONLY when a breach check / passphrase generation actually
 * runs — never for unlock, list rendering, fill, or sync.
 *
 * HOW: dynamic import(). The service worker manifest already declares
 * "type": "module", and module workers support dynamic import (the classic
 * worker limitation fixed in R21 does not apply here). The import promise is
 * cached per document/worker lifetime; module evaluation itself is cached by
 * the engine, so the data is parsed exactly once per surface.
 *
 * FAILURE MODE (truthful, not silent): lib/analyzer.js and lib/generator.js
 * degrade quietly when their globalThis corpus is missing (empty Set /
 * empty wordlists). That is the correct defensive posture for the MODULE
 * consumers, but a lazy loader that resolves without the global would turn
 * "corpus not loaded YET" into "breach checks silently pass" — the worst
 * kind of lie. So ensure*() VERIFIES the global after the import resolves
 * and THROWS a clear error if it is missing. Callers surface that error
 * through their normal failure paths (the same shape as any generator or
 * analyzer failure) instead of showing a fake "no breaches" report.
 *
 * Node harnesses that test analyzer/generator behavior import breach.js /
 * wordlists.js statically themselves and are unaffected by this loader.
 *
 * ⚠ PAGE-ONLY (corrected by journey 30 in a real Chromium): this loader must
 * NEVER be imported by the service worker. Chromium disallows dynamic
 * import() on ServiceWorkerGlobalScope — "import() is disallowed on
 * ServiceWorkerGlobalScope by the HTML specification"
 * (w3c/ServiceWorker#1356) — even when the manifest declares "type":
 * "module". The worker therefore keeps breach.js as a STATIC import (and
 * needs no wordlists: it never generates passphrases). Extension PAGES have
 * no such restriction — the popup and options pages proved the loader live.
 */

let breachPromise = null
let wordsPromise = null
let bip39Promise = null

/**
 * Load (once) and verify the breach corpus. Resolves when
 * globalThis.CRYPTKEY_BREACH is a usable Set; rejects with a clear Error
 * when the module could not be loaded or did not install its global.
 * @returns {Promise<void>}
 */
export function ensureBreachCorpus() {
  if (!breachPromise) {
    breachPromise = import('../breach.js').then(() => {
      if (!(globalThis.CRYPTKEY_BREACH instanceof Set) || globalThis.CRYPTKEY_BREACH.size === 0) {
        throw new Error('Breach corpus failed to load (CRYPTKEY_BREACH missing or empty)')
      }
    })
    // A prewarm call that nobody awaits must not surface as an unhandled
    // rejection; real consumers re-await the SAME cached promise below and
    // get the original rejection there.
    breachPromise.catch(() => {})
  }
  return breachPromise
}

/**
 * Load (once) and verify the passphrase wordlists. Resolves when
 * globalThis.CRYPTKEY_WORDLISTS carries at least one non-empty list;
 * rejects with a clear Error otherwise.
 * @returns {Promise<void>}
 */
export function ensureWordlists() {
  if (!wordsPromise) {
    wordsPromise = import('../wordlists.js').then(() => {
      const w = globalThis.CRYPTKEY_WORDLISTS
      const usable = w && typeof w === 'object' &&
        Object.values(w).some((list) => Array.isArray(list) && list.length > 0)
      if (!usable) {
        throw new Error('Passphrase wordlists failed to load (CRYPTKEY_WORDLISTS missing or empty)')
      }
    })
    wordsPromise.catch(() => {})
  }
  return wordsPromise
}

/**
 * R72 — load (once) and verify the BIP-39 corpus for the Generator Lab's
 * mnemonic tool on extension PAGES. The worker already imports lib/bip39.js
 * statically (R45: sync-code generation); this loader is page-only, same
 * contract as ensureWordlists().
 * @returns {Promise<void>}
 */
export function ensureBip39() {
  if (!bip39Promise) {
    bip39Promise = import('./bip39.js').then(() => {
      const list = globalThis.CRYPTKEY_BIP39
      if (!Array.isArray(list) || list.length !== 2048) {
        throw new Error('BIP-39 wordlist failed to load (CRYPTKEY_BIP39 missing or not 2048 words)')
      }
    })
    bip39Promise.catch(() => {})
  }
  return bip39Promise
}

/** Test seam: forget the cached promises (fresh-loader assertions). */
export function resetCorpusCacheForTests() {
  breachPromise = null
  wordsPromise = null
  bip39Promise = null
}
