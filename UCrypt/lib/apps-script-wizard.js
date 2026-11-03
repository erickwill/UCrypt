/**
 * UCrypt — R139 §6 — THE APPS SCRIPT WIZARD + THE TYPED FAILURE TAXONOMY.
 *
 * §6.1 THE WIZARD (the CEO's command): a step-by-step wizard inside UCrypt
 * for the Drive bridge. Each deployment screen is NAMED in the wizard's
 * copy; the 'Who has access: Anyone' step carries the explicit warning —
 * it is the classic silent killer that produces exactly the intermittent
 * 'sometimes it will not connect' the CEO has reported across rounds (a
 * deployment that works for its author and for no one else, including the
 * user's own second browser profile).
 *
 * §6.2 THE TYPED FAILURE TAXONOMY: every Drive failure (and every
 * provider's by the same pattern) maps to a typed cause with its fix —
 * no truncated paths (D3), no generic errors, typed end-to-end from
 * transport to surface copy. The R138 fixture set is extended with the
 * deployment-private and URL-swap-after-re-deploy fixtures (the two
 * highest-probability real-world causes).
 *
 * §6.4 THE SHARED DOCTOR CONTRACT: the wizard's final step runs the
 * test-connection round-trip (write → read → delete a real test chunk) and
 * 'ready' is claimed ONLY after a proven round-trip — never asserted.
 *
 * PURE — no DOM, no chrome.*, no network at import time. Battery-pinned
 * (G87 F1; the G86 hardening lineage).
 */

/** The wizard steps (§6.1's exact walk — each names its deployment screen). */
export const WIZARD_STEPS = [
  {
    id: 'create',
    key: 'wizardStepCreate',
    fallback: 'Step 1 — Create the script: open the Apps Script editor and paste the script UCrypt copies for you (one button, the exact script).',
    copyButton: true,
  },
  {
    id: 'deploy',
    key: 'wizardStepDeploy',
    fallback: 'Step 2 — Deploy: New deployment → Web app → Execute as: Me → Who has access: Anyone.',
    warning: 'WIZARD_ACCESS_WARNING',
    warningFallback: '⚠ "Who has access: Anyone" is the classic silent killer: a deployment set to anything else works for its author and for NO ONE else — including your own second browser profile. This is exactly the intermittent "sometimes it will not connect". Check it twice.',
  },
  {
    id: 'paste',
    key: 'wizardStepPaste',
    fallback: 'Step 3 — Paste the Web App URL here (it ends in /exec).',
    input: 'url',
  },
  {
    id: 'test',
    key: 'wizardStepTest',
    fallback: 'Step 4 — Run Test connection: UCrypt writes, reads, and deletes a real test chunk and shows the result per step.',
    action: 'test-connection',
  },
  {
    id: 'done',
    key: 'wizardStepDone',
    fallback: 'Done — the connection is proven. The completion bar stays until you press Close.',
    completionBar: true,
  },
]

/** The completion bar's contract (D2): a sticky bar with the live test
 * result and a Close button; it closes ONLY by the user's hand (the iron
 * law: nothing auto-closes) and remains visible until then. */
export function completionBar(result) {
  return {
    sticky: true,
    autoCloses: false, // the iron law, typed
    liveResult: result || null,
    closeAffordance: true,
    key: 'wizardCompletionBar',
    fallback: result && result.ok
      ? 'Connection proven — the test chunk was written, read, and deleted. You can close this wizard when ready.'
      : 'The connection test has not passed yet — the bar stays with the failing step named.',
  }
}

/**
 * THE TYPED FAILURE TAXONOMY (§6.2). Every Drive failure maps to a typed
 * cause with its fix affordance; the fix names the EXACT wizard step (never
 * a truncated path — D3).
 */
export const DRIVE_FAILURES = {
  URL_MISSING: 'url-missing',
  URL_WRONG: 'url-wrong',
  DEPLOYMENT_PRIVATE: 'deployment-private',
  URL_SWAPPED: 'url-swapped',
  AUTH_REVOKED: 'auth-revoked',
  QUOTA_NEAR: 'quota-near',
  NETWORK: 'network',
}

/** The typed fix per cause — every fix lands on the exact surface (D3's
 * no-truncation rule: the path is complete or the fix opens the wizard). */
export function driveFailureTaxonomy(failure) {
  switch (failure) {
    case DRIVE_FAILURES.URL_MISSING:
      return { cause: DRIVE_FAILURES.URL_MISSING, key: 'driveFixUrlMissing', fix: 'open-wizard:paste', words: 'The Apps Script Web App URL is missing — the wizard opens at the paste step.' }
    case DRIVE_FAILURES.URL_WRONG:
      return { cause: DRIVE_FAILURES.URL_WRONG, key: 'driveFixUrlWrong', fix: 'open-wizard:paste', words: 'The Web App URL does not answer — re-check it ends in /exec and the deployment exists.' }
    case DRIVE_FAILURES.DEPLOYMENT_PRIVATE:
      return { cause: DRIVE_FAILURES.DEPLOYMENT_PRIVATE, key: 'driveFixDeploymentPrivate', fix: 'open-wizard:deploy', words: 'The deployment is private — it works for its author and no one else. Re-deploy with Who has access: Anyone.' }
    case DRIVE_FAILURES.URL_SWAPPED:
      return { cause: DRIVE_FAILURES.URL_SWAPPED, key: 'driveFixUrlSwapped', fix: 'open-wizard:paste', words: 'The Web App URL changed after a re-deploy — paste the fresh /exec URL.' }
    case DRIVE_FAILURES.AUTH_REVOKED:
      return { cause: DRIVE_FAILURES.AUTH_REVOKED, key: 'driveFixAuthRevoked', fix: 're-authenticate', words: 'The sign-in was revoked — re-authenticate in place; the queue is preserved.' }
    case DRIVE_FAILURES.QUOTA_NEAR:
      return { cause: DRIVE_FAILURES.QUOTA_NEAR, key: 'driveFixQuotaNear', fix: 'quota-advice', words: 'The cloud storage is near its quota — free space or choose another transport; nothing was lost.' }
    case DRIVE_FAILURES.NETWORK:
      return { cause: DRIVE_FAILURES.NETWORK, key: 'driveFixNetwork', fix: 'retry-ladder', words: 'The network did not answer — the retry ladder is running; the queue keeps every write.' }
    default:
      return { cause: 'unknown', key: 'driveFixUnknown', fix: 'open-doctor', words: 'The connection answered with something unexpected — run the connection doctor for the live hop trace.' }
  }
}

/**
 * THE REPRO FIXTURE MATRIX (§6.3 — the intermittent-glitch repro hunt). Each
 * fixture maps a real-world fault shape to its typed taxonomy row; the
 * doctor and the surface must type each one identically.
 */
export function classifyDriveFixture(fixture) {
  switch (fixture) {
    case 'deployment-private':
      // the deployment works for the author and nobody else — the HTTP shape
      // is a 200 HTML page (the Apps Script login wall) or a 30x to /accounts
      return DRIVE_FAILURES.DEPLOYMENT_PRIVATE
    case 'url-swap-after-redeploy':
      // the /exec URL changed; the old URL 404s or serves the "not found" page
      return DRIVE_FAILURES.URL_SWAPPED
    case 'token-expiry-mid-session':
      return DRIVE_FAILURES.AUTH_REVOKED
    case 'quota-edge':
      return DRIVE_FAILURES.QUOTA_NEAR
    case 'network-flap-during-push':
      return DRIVE_FAILURES.NETWORK
    case 'url-missing':
      return DRIVE_FAILURES.URL_MISSING
    case 'url-wrong':
      return DRIVE_FAILURES.URL_WRONG
    default:
      return 'unknown'
  }
}

/**
 * THE TEST-CONNECTION ROUND-TRIP (§6.1/§6.4): the wizard writes, reads, and
 * deletes a real test chunk; 'ready' is claimed ONLY after a proven
 * round-trip. The transport is injected (the R96 SW boundary law) — this
 * module sequences the three steps and types each failure through the
 * taxonomy. PURE orchestration.
 */
export async function runTestConnection(transport, { chunkId = 'ucrypt-wizard-test-chunk' } = {}) {
  const steps = []
  const write = await transport.write(chunkId, 'ucrypt-test').catch((e) => ({ error: e }))
  steps.push({ step: 'write', ok: !write.error, error: write.error ? String(write.error.message || write.error) : '' })
  if (write.error) return { ok: false, steps, failure: driveFailureTaxonomy(classifyTransportError(write.error)) }
  const read = await transport.read(chunkId).catch((e) => ({ error: e }))
  const readOk = !read.error && (read.text === 'ucrypt-test' || read === 'ucrypt-test')
  steps.push({ step: 'read', ok: readOk, error: read.error ? String(read.error.message || read.error) : (readOk ? '' : 'the read-back did not match the write') })
  if (!readOk) {
    await transport.remove(chunkId).catch(() => { /* the cleanup is best-effort even on failure */ })
    return { ok: false, steps, failure: driveFailureTaxonomy(DRIVE_FAILURES.URL_WRONG) }
  }
  const remove = await transport.remove(chunkId).catch((e) => ({ error: e }))
  const removeOk = !remove.error
  steps.push({ step: 'cleanup', ok: removeOk, error: remove.error ? String(remove.error.message || remove.error) : '' })
  if (!removeOk) return { ok: false, steps, failure: driveFailureTaxonomy(DRIVE_FAILURES.NETWORK) }
  return { ok: true, steps, failure: null }
}

/** The transport error → taxonomy classifier (the typed end-to-end law). */
export function classifyTransportError(err) {
  const s = String((err && (err.transferCode || err.code)) || (err && err.message) || err || '').toLowerCase()
  if (s.includes('404') || s.includes('not found')) return DRIVE_FAILURES.URL_WRONG
  if (s.includes('401') || s.includes('403') || s.includes('unauthorized') || s.includes('forbidden') || s.includes('login') || s.includes('accounts')) return DRIVE_FAILURES.DEPLOYMENT_PRIVATE
  if (s.includes('429') || s.includes('quota') || s.includes('storage')) return DRIVE_FAILURES.QUOTA_NEAR
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch')) return DRIVE_FAILURES.NETWORK
  return 'unknown'
}
