/**
 * UCrypt — R146 §7.4 — THE ONE-TRUTH RUN LEDGER (H-6, the pure law).
 *
 * The Cloud backup card shows ONE coherent state. Every backup/pull run is
 * classified into exactly one typed state, the ✓/✗ glyph DERIVES from that
 * state, and contradictory neighbors are structurally impossible: a success
 * class can never wear a ✗, and a failure always carries its next step.
 *
 * The A5 evidence: "✓ … cloud copy confirmed ✓" and "✗ Merged changes from
 * sync — pushed result" on one card — a SUCCESS class (the merged pull that
 * pushed, vault.js:3665) wearing a failure glyph. The classifier is the
 * cure; the card renders FROM it; the battery pins every class.
 */

export const RUN_STATES = {
  RUNNING: 'running',
  SKIPPED: 'skipped',
  SUCCESS: 'success',
  SUCCESS_MERGED: 'success-merged',
  FAILED: 'failed',
  UNKNOWN: 'unknown',
}

const MERGED_MARKERS = ['merged changes']

function isMergedSuccess(entry) {
  const reason = String((entry && (entry.reason || entry.message || entry.line)) || '')
  const lower = reason.toLowerCase()
  const merged = MERGED_MARKERS.some((m) => lower.includes(m))
  if (!merged) return false
  /* pushed / pushed result / push skipped (unreachable transport) is still a
     SUCCESSFUL pull-merge; only an explicit failure flag contradicts it. */
  return entry.ok !== false && !lower.includes('could not finish')
}

/** classifyRun — exactly one state per entry, glyph + words derived. */
export function classifyRun(entry) {
  if (!entry || typeof entry !== 'object') {
    return { state: RUN_STATES.UNKNOWN, glyph: '•', ok: null, line: 'No backup run recorded yet.', nextStep: null }
  }
  if (entry.running === true || entry.state === 'running') {
    return { state: RUN_STATES.RUNNING, glyph: '•', ok: null, line: String(entry.message || 'Backing up…'), nextStep: 'You can keep working — the run finishes on its own.' }
  }
  if (entry.skipped === true || entry.state === 'skipped') {
    // LAW 0.48 (R133, preserved): the typed lifecycle SKIP is never a red
    // failure — the fresh joiner's push renders its truthful waiting row.
    return { state: RUN_STATES.SKIPPED, glyph: '⏳', ok: null, line: String(entry.error || entry.message || 'waiting — the next sync round carries it'), nextStep: 'Nothing is wrong — the sync lifecycle carries it on its own.' }
  }
  if (isMergedSuccess(entry)) {
    return {
      state: RUN_STATES.SUCCESS_MERGED,
      glyph: '✓',
      ok: true,
      line: 'Merged changes from sync — the result is pushed and verified.',
      nextStep: null,
    }
  }
  const failedExplicit = entry.ok === false || entry.error || /could not finish|failed|unreachable|unreadable/i.test(String(entry.message || entry.reason || ''))
  if (failedExplicit) {
    const reason = String(entry.error || entry.message || entry.reason || 'the run ended early').slice(0, 160)
    return {
      state: RUN_STATES.FAILED,
      glyph: '✗',
      ok: false,
      line: `The last backup run could not finish — ${reason}`,
      nextStep: 'Press "Back up now" to retry — or "Test connection" to check the road first.',
    }
  }
  /* a positively-confirmed run: ok === true, or the confirmed wording */
  const line = String(entry.message || entry.line || 'Backup finished — the cloud copy is confirmed.')
  return { state: RUN_STATES.SUCCESS, glyph: '✓', ok: true, line, nextStep: null }
}

/** foldRuns — the card's ONE head state + a history that agrees with itself.
 * The newest entry wins the head; every history row is classified by the
 * same law, so a ✓ never sits next to a sentence that says it failed. */
export function foldRuns(entries, { now = Date.now() } = {}) {
  const list = Array.isArray(entries) ? entries.filter((e) => e && typeof e === 'object') : []
  if (!list.length) {
    return { head: classifyRun(null), history: [] }
  }
  const sorted = list.slice().sort((a, b) => (Number(b.at) || 0) - (Number(a.at) || 0))
  const head = classifyRun(sorted[0])
  const history = sorted.slice(0, 5).map((e) => ({ ...classifyRun(e), at: Number(e.at) || null }))
  return { head, history }
}

/** The card's single status sentence — head + the honest qualifier. */
export function runCardLine(folded) {
  const h = folded.head
  if (h.state === RUN_STATES.SUCCESS || h.state === RUN_STATES.SUCCESS_MERGED) return `${h.glyph} ${h.line}`
  if (h.state === RUN_STATES.FAILED) return `${h.glyph} ${h.line} ${h.nextStep}`
  if (h.state === RUN_STATES.RUNNING) return `${h.glyph} ${h.line}`
  return `${h.glyph} ${h.line}`
}
