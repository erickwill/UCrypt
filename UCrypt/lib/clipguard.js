/**
 * UCrypt — clipboard secrecy guard (R97, executes finding F-R96-1).
 *
 * THREAT (R96 §6, the local-device attacker row): a revealed or copied
 * secret stays readable in the OS clipboard until something overwrites it —
 * including after the vault that produced it has locked.
 *
 * THE FIX (the filed plan, CEO-nodded for R97 §1.3): every UCrypt surface
 * that copies a SECRET arms this guard at the moment of the copy. When the
 * vault locks (the VAULT_LOCKED event), a surface holding an armed guard
 * overwrites the OS clipboard with an EMPTY string. The vault window, the
 * popup and the in-page overlay all take part.
 *
 * PERMISSION HYGIENE: the guard never READS the clipboard (that would need
 * the clipboardRead permission — a store-review negative and a privacy
 * regression). It only ever OVERWRITES with an empty string, and only when
 * a UCrypt copy is known to have happened since the last lock.
 *
 * HONEST LIMITATION (documented, not hidden): a surface that has been
 * CLOSED cannot run code — if the user copies a secret and closes every
 * UCrypt surface before the lock fires, the overwrite cannot happen. The
 * 20-second surface-level auto-clears (shipped since R95) remain the first
 * line; this guard is the lock-moment net behind them.
 *
 * Scope (which copies arm the guard — measured, law 0.15): passwords, TOTP
 * codes, recovery words, sync-code words, generated values, token seeds —
 * every vault-secret class. NON-secret copies deliberately do NOT arm the
 * guard (overwriting the user's own clipboard for them would be wrong):
 * the diagnostic summary (worker-built, non-secret by construction),
 * the transfer decision record, the Google-OAuth redirect URI and the
 * direct-transfer manual signal (network-payload class by design).
 */
(function () {
  'use strict'
  let armed = false
  let installed = false

  /** Called by a copy site right after a SECRET lands in the clipboard. */
  function arm() {
    armed = true
  }

  /**
   * Overwrite the clipboard when (and only when) a UCrypt secret copy is
   * armed. Returns 'cleared' | 'not-armed' | 'failed' — the caller decides
   * what the user sees. The guard itself never toasts (it also runs in the
   * page overlay, where the toast vocabulary belongs to the surface).
   */
  async function clearIfArmed() {
    if (!armed) return 'not-armed'
    armed = false
    try {
      await navigator.clipboard.writeText('')
      window.dispatchEvent(new CustomEvent('ucrypt:clipCleared'))
      return 'cleared'
    } catch {
      // Clipboard write refused (unfocused document et al.) — honest no-op;
      // the 20-second timer remains as the backup line.
      return 'failed'
    }
  }

  /** Idempotent install: the lock event is the only trigger. */
  function install() {
    if (installed) return
    installed = true
    const onMessage = (msg) => {
      if (msg && msg.type === 'VAULT_LOCKED') clearIfArmed()
    }
    try {
      if (chrome.runtime && chrome.runtime.onMessage) chrome.runtime.onMessage.addListener(onMessage)
    } catch { /* the overlay context still clears via its own handler */ }
  }

  globalThis.UCryptClipGuard = { arm, install, clearIfArmed }
})()
