/**
 * ════════════════════════════════════════════════════════════════════════
 * R165 ARC G (the R163 carry, re-commanded and DUE) — THE GAP-SURVEY
 * RECEIPTS: the build's KNOWN GAPS, typed and dated, as a copyable receipt.
 *
 * Honesty doctrine: a gap that is known is NAMED — never hidden, never
 * padded with non-gaps. Each row: id, area, title, state, since, next.
 * The table below is the R165 truth (the battery asserts the shape and the
 * determinism: the same build produces the SAME receipt, byte for byte).
 * ════════════════════════════════════════════════════════════════════════
 */

/** The typed gap table (R165 truth — additions/cures only, never a rewrite). */
export const KNOWN_GAPS = Object.freeze([
  {
    id: 'GAP-S127',
    area: 'owner-stamp',
    title: 'S127 — the Console Item-ID verify (the fek/fak letter question) is formally closed by the owner',
    state: 'pending-owner',
    since: 'R164',
    next: 'Console → Clients → "UCrypt Drive Sync" → Item ID letter-exact vs chrome://extensions (fek expected; Edit in place if wrong — never recreate).',
  },
  {
    id: 'GAP-S130',
    area: 'owner-stamp',
    title: 'S130 — the LIVE fast-rung connect stamp on v3.19.0 (the button completes or fails with a NAMED verdict)',
    state: 'pending-owner',
    since: 'R165',
    next: 'After the seal: press the FAST connect once — the button speaks or completes; attach the ladder receipt to the round report.',
  },
  {
    id: 'GAP-S131',
    area: 'owner-stamp',
    title: 'S131 — the S127 closure folds into the ladder\u2019s identity/binding rungs (the owner\u2019s 2-minute walk)',
    state: 'pending-owner',
    since: 'R165',
    next: 'Console → Clients → the Item ID letter check; the ladder rung 1/2 must agree.',
  },
  {
    id: 'GAP-S132',
    area: 'owner-stamp',
    title: 'S132 — the reset-connection walk (revoke → Reset → reconnect → Allowed) is stamped by the owner',
    state: 'pending-owner',
    since: 'R165',
    next: 'myaccount.google.com/permissions → remove UCrypt → Reset connection (Sync Doctor) → connect → Allow.',
  },
  {
    id: 'GAP-VERIFY-CASA',
    area: 'product-plan',
    title: 'the 100-user ceiling while unverified — Google verification (privacy policy + homepage + demo video) and the drive.appdata security assessment (CASA) await a funded, CEO-consented round',
    state: 'planned',
    since: 'R165',
    next: 'typed for the product plan; NOT this round\u2019s work. The own-key guided path remains the unlimited fallback (the surface says so).',
  },
  {
    id: 'GAP-B1-B7',
    area: 'law-book',
    title: 'the law book rows #44–#82 (B1/B7) wait on the owner\u2019s volume re-delivery (the two-domain split persists)',
    state: 'waiting-owner-volume',
    since: 'R155',
    next: 're-requested every round (the sixth+ request); the book seals from the owner\u2019s forward when they land.',
  },
])

/**
 * Build the gap-survey receipt. Deterministic: the same gaps + the same
 * at/version render the same text (the battery asserts it byte-for-byte).
 * @param {{at?: string, version?: string, gaps?: Array}} [opts]
 */
export function buildGapSurveyReceipt(opts = {}) {
  const gaps = Array.isArray(opts.gaps) ? opts.gaps : KNOWN_GAPS
  const at = String(opts.at || new Date().toISOString())
  const version = String(opts.version || '')
  const L = []
  L.push('UCrypt gap survey — the known gaps of this build, typed and dated (honesty doctrine: named, never hidden)')
  L.push(`at: ${at}${version ? ` · build v${version}` : ''}`)
  L.push(`gaps: ${gaps.length}`)
  for (const g of gaps) {
    L.push(`  [${g.id}] (${g.state}, since ${g.since}) ${g.title}`)
    L.push(`      next: ${g.next}`)
  }
  L.push('end of survey')
  return L.join('\n')
}
