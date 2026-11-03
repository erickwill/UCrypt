/**
 * ════════════════════════════════════════════════════════════════════════
 * R175 — THE IMPORT THAT ENDS (R-175.5, the E-33 cure) — the bounded
 * journey. The field proved an import whose preview read the file perfectly
 * (1162 rows parsed, 80 duplicate groups, 552 weak, 70 reused) and then
 * rendered "Importing…" with no end — no success counts, no typed failure,
 * no watchdog, no return of the buttons. The law: every import path
 * terminates in a materialized outcome — success with the committed counts,
 * a typed failure, or the owner's cancel. "Importing…" is a BOUNDED state,
 * never a residence.
 *
 * This leaf is the ONE watchdog every import seat rides (the cross-browser
 * card, the Import Center, the history buttons, the single-entry import):
 *   - a LIVE PROGRESS BEAT (the owner sees the seconds move — the journey
 *     is alive, never a frozen text);
 *   - a bounded wait that materializes a TYPED timeout row and lets the
 *     seat restore the controls (honest words: the wait was ended — the
 *     run may still land; check the vault before retrying).
 *
 * ENGINE-LEAF: zero imports, zero chrome — the battery drives it directly.
 * ════════════════════════════════════════════════════════════════════════
 */

/** The watchdog bound (the ledgered number: the R-175.5 two-minute bound). */
export const IMPORT_WATCHDOG_MS = 120000

/**
 * Run one import journey under the watchdog.
 * @param {() => Promise<any>} run the journey's own await (the bgSend call)
 * @param {{ timeoutMs?: number, onTick?: (elapsedSeconds: number) => void }} [opts]
 * @returns {Promise<{ ok: boolean, watchdog?: boolean, error?: string, [k: string]: unknown }>}
 *   the journey's own result, or the typed timeout row (ok:false, watchdog:true)
 */
export async function boundedImport(run, opts = null) {
  // The floor keeps a misconfigured seat from a zero/negative bound; the
  // battery drives short bounds directly (the G295-a row's 60 ms proof).
  const timeoutMs = Math.max(20, Number(opts && opts.timeoutMs) || IMPORT_WATCHDOG_MS)
  const onTick = opts && typeof opts.onTick === 'function' ? opts.onTick : null
  const t0 = Date.now()
  let beat = null
  let timer = null
  if (onTick) {
    beat = setInterval(() => {
      try { onTick(Math.round((Date.now() - t0) / 1000)) } catch { /* the beat never throws into its caller */ }
    }, 1000)
  }
  try {
    return await Promise.race([
      Promise.resolve().then(run),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve({
          ok: false,
          watchdog: true,
          timeoutMs,
          error: `The import did not finish within ${Math.round(timeoutMs / 1000)} s — the wait was ended and the controls restored. The run may still land (check the vault count before retrying); nothing is ever half-written — the vault saves transactionally.`,
        }), timeoutMs)
      }),
    ])
  } finally {
    if (beat) clearInterval(beat)
    if (timer) clearTimeout(timer)
  }
}

/**
 * The honest landing words for a watchdog row (the seat renders THIS when
 * the bound fired — never a frozen "Importing…", never a silent return).
 */
export function watchdogLandingWords(timeoutMs = IMPORT_WATCHDOG_MS) {
  return `The import did not finish within ${Math.round(timeoutMs / 1000)} s — the wait was ended and the controls restored. The run may still land (check the vault count before retrying); nothing is ever half-written — the vault saves transactionally.`
}
