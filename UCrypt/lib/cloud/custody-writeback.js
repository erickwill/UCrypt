/**
 * ════════════════════════════════════════════════════════════════════════
 * R178 — THE CUSTODY WRITE-BACK HOOK (the leaf seam — no imports, no DOM,
 * no chrome). R-178.2's renewal write-back needs two layers to meet:
 *
 *   - the TRANSPORT layer (lib/transports/gdrive.js) mints/refreshes access
 *     tokens inside ensureAccessToken / _refreshAccessToken — it cannot
 *     import the vault (an import cycle);
 *   - the VAULT layer (lib/vault.js) owns the ONE writer seat of the
 *     transport record (R-177.2) — it cannot be imported downward.
 *
 * This leaf carries the hook between them: gdrive notifies; the vault
 * registers. The hook NEVER throws into its caller (a write-back failure
 * must never break a sync leg — the ledger keeps the typed evidence), and
 * the notify is fire-and-forget from the transport's perspective (awaited
 * by the vault side's own chain, never blocking the mint's answer).
 *
 * LAWS THIS MODULE ENFORCES BY CONSTRUCTION:
 *   - no secret renders, logs, or syncs: the payload rides ONLY between the
 *     two in-process layers (worker memory), and the vault's writer seals it
 *     into the transport envelope before any storage write;
 *   - fail-closed custody: the writer proves the record identity (transport
 *     id + the owning grant) before it writes — a mismatched notification is
 *     dropped, never written;
 *   - additions-only: absent registration (the battery, the page frame) the
 *     notify resolves silently — the mint keeps its answer.
 * ════════════════════════════════════════════════════════════════════════
 */

let _writeBack = null
let _chain = Promise.resolve()

/** The vault registers its ONE writer seat here (at module init). */
export function registerCustodyWriteBack(fn) {
  _writeBack = typeof fn === 'function' ? fn : null
}

/** The transport notifies ONE mint/refresh event (fire-and-forget-safe).
 * Shape: { transportId, token, exp, via, clientId, refreshToken } — the
 * refreshToken rides ONLY as the grant's IDENTITY PROOF (the writer verifies
 * the record still owns this grant before writing); it is never stored by
 * the hook itself. Returns the settled promise (awaited only in tests). */
export function notifyCustodyWriteBack(event) {
  const run = _chain.then(async () => {
    if (!_writeBack || !event || typeof event !== 'object') return
    try { await _writeBack(event) } catch { /* the write-back never breaks the mint */ }
  })
  _chain = run.catch(() => { /* the chain never breaks */ })
  return run
}

/** The battery seam. */
export function _resetCustodyWriteBackForTest() { _writeBack = null; _chain = Promise.resolve() }
