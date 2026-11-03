/**
 * UCrypt — R140 §7 — THE CHAIN STATE (the cold-start cure, F1).
 *
 * THE STALE-LATCH CLASS IS THE DISEASE: on service-worker cold start the
 * encrypted-backup read probe executed before token refresh and Drive
 * readiness completed; its transient failure was PERSISTED as the chain
 * verdict; and later successful reads never re-derived it. The banner
 * outlived its own cause and contradicted its sibling pill — teaching the
 * user that UCrypt's words cannot be trusted.
 *
 * THE CURE IS ARCHITECTURAL (the contract's exact shape):
 *   1. ONE reactive writer — the verdict is a PURE FUNCTION of its inputs
 *      (cloud auth state, the wake cycle's probe, the last pull, the
 *      timestamps), recomputed on EVERY transition of any input. A persisted
 *      verdict is a CACHE with mandatory re-derivation on wake — never a
 *      writer.
 *   2. PENDING BEFORE ERROR — before the first successful probe of a wake
 *      cycle the verdict is `pending` (calm, informative, self-updating),
 *      never an error.
 *   3. THE RETRY LADDER — an error is declared only after 1s/2s/4s/8s/16s
 *      (five attempts) are exhausted, and only with classified evidence:
 *      probe name, HTTP status, timestamp, next retry. "Answered
 *      unexpectedly" (BRIDGE) is reserved for an ACTUALLY MALFORMED response
 *      class — never for a timeout, an auth race, or a cold network.
 *   4. AUTO-CLEAR — the moment any probe or pull succeeds, the verdict
 *      recomputes to ok with zero user action (the explainer's own promise,
 *      kept by construction).
 *   5. ONE FACT FOR EVERY READER — the banner, the pill, the transfer
 *      plane's cloud gate (F3d), and the readiness inputs all read THIS
 *      derivation; a contradiction between any two of them is structurally
 *      unrepresentable (the R139 single-writer law, carried to Cloud Sync).
 *
 * PURE — no chrome.*, no fetch, no timers at import time. Battery-pinned
 * (tests/r140-round.test.mjs — G89 COLD-START LATCH: five consecutive
 * simulated restarts, the banner never contradicts the pill).
 */

/** The retry ladder (the contract's exact numbers — five attempts). */
export const CHAIN_RETRY_LADDER_MS = [1000, 2000, 4000, 8000, 16000]

/** R145 §6.1 — THE PENDING CAP (the G-3 watchdog, the ledgered number):
 * "Cloud check in progress" may live at most 120 seconds per wake cycle.
 * Past that the derivation returns a TYPED, retryable attention state with
 * ONE plain-words next step — an eternal progress line is a battery-red
 * class from now on (the row "progress must terminate" proves it). */
export const CHAIN_PENDING_CAP_MS = 120000

/** R150 D-3 (§6.2, capture B1 — THE HANGING CHECK) — THE CHECK BUDGET:
 * the CLOUD CHECK (the in-flight probe the pending line speaks for) must
 * resolve TYPED within 10 seconds. The probe itself is bounded ≤10 s
 * worker-side (background.js races the pull), so an in-flight pending state
 * that outlives 10 s IS the machine's defect — the derivation renders it
 * unrepresentable: past budget the verdict becomes the typed
 * CHECK_TIMED_OUT:<hop> attention with ONE next step (the Sync now button).
 * The 120 s wake-ladder cap above stays for the ladder-WAITING leg (the
 * calm between-retries state is not "in progress" — it is scheduled and
 * self-updating; the R145 rows keep pinning it). */
export const CHAIN_CHECK_CAP_MS = 10000

/** The plain-words next step the stalled state always carries. */
export const CHAIN_STALLED_NEXT_STEP = 'We could not finish checking your backup — press Sync now to retry.'

/** R150 D-3 — the one-button next step the CHECK_TIMED_OUT verdict carries
 * (the Sync now button is the working path — the re-check runs on demand). */
export const CHAIN_CHECK_TIMED_OUT_NEXT_STEP = 'The cloud check ran out of time — press Sync now to retry.'

/** The typed verdicts (the ONLY words the strip may render). */
export const CHAIN_VERDICTS = {
  OK: 'ok',
  PENDING: 'pending',
  ATTENTION: 'attention',
  NO_CLOUD: 'no-cloud',
}

/** The typed probe classes (the evidence's vocabulary). */
export const PROBE_CLASSES = {
  AUTH_RACE: 'auth-race',         // 401/403 during a refresh — the ladder owns it
  UNREACHABLE: 'unreachable',     // network/timeout/5xx/429 — the ladder owns it
  MALFORMED: 'malformed',         // the response shape is wrong — the BRIDGE class, evidence-only
  UNREADABLE: 'unreadable',       // fetched but cannot be read with this chain key
  TRANSIENT: 'transient',         // cold-start race with no more specific class
}

/**
 * The wake-cycle record (per service-worker lifetime, persisted as a CACHE):
 * { wakeId, startedAt, firstProbeCompletedAt, attempts, lastProbe }.
 * A NEW wake id DEMOTES the persisted verdict to a cache — re-derivation
 * is mandatory (the latch is unrepresentable).
 */
export function newWakeCycle(wakeId, now = Date.now()) {
  return { wakeId: String(wakeId || ''), startedAt: Number(now) || Date.now(), firstProbeCompletedAt: 0, attempts: 0, lastProbe: null }
}

/** The next retry delay for attempt N (0-based), or null when the ladder is exhausted. */
export function nextRetryMs(attemptIndex) {
  const i = Number(attemptIndex) || 0
  return i >= 0 && i < CHAIN_RETRY_LADDER_MS.length ? CHAIN_RETRY_LADDER_MS[i] : null
}

/** The absolute time of the next retry, or null when the ladder is exhausted. */
export function nextRetryAt(attemptIndex, fromTs = Date.now()) {
  const ms = nextRetryMs(attemptIndex)
  return ms == null ? null : Number(fromTs) + ms
}

/**
 * CLASSIFY ONE PROBE FAILURE (the evidence classifier, F1+F3d shared):
 * the class decides whether the ladder owns the failure (retry, never
 * latch) or the failure is a REAL malformed-response class (BRIDGE, only
 * ever with evidence).
 *
 * @param {{kind?:string, status?:number|null, malformed?:boolean, garbage?:number,
 *          transportState?:string, error?:string, at?:number}} probe
 * @returns {{cls:string, ladderOwned:boolean, evidence:Object}}
 */
export function classifyProbeFailure(probe = {}) {
  const kind = typeof probe.kind === 'string' ? probe.kind : ''
  const status = Number.isFinite(Number(probe.status)) ? Number(probe.status) : null
  const malformed = probe.malformed === true
  const garbage = Number.isFinite(Number(probe.garbage)) ? Number(probe.garbage) : 0
  const state = typeof probe.transportState === 'string' ? probe.transportState : ''
  const evidence = {
    probeName: String(probe.probeName || 'pull-probe'),
    status,
    at: Number(probe.at) || Date.now(),
    kind: kind || null,
    malformed,
    garbage,
  }
  if (state === 'unreadable' || (!state && garbage > 0 && !status)) {
    return { cls: PROBE_CLASSES.UNREADABLE, ladderOwned: false, evidence }
  }
  if (malformed || kind === 'protocol' || kind === 'config') {
    // THE BRIDGE RESERVATION: only an actually malformed response class —
    // a shape UCrypt could not parse — may ever become "answered
    // unexpectedly". A cold-start race that returned a parseable auth or
    // network error is NOT this class (the ladder owns it). The class is
    // REAL evidence — the ladder cannot cure it, so it is NOT ladder-owned.
    return { cls: PROBE_CLASSES.MALFORMED, ladderOwned: false, evidence }
  }
  if (kind === 'auth' || status === 401 || status === 403) {
    return { cls: PROBE_CLASSES.AUTH_RACE, ladderOwned: true, evidence }
  }
  // timeout / network / server / rate-limit — the ladder owns them all
  return { cls: PROBE_CLASSES.UNREACHABLE, ladderOwned: true, evidence }
}

/**
 * THE REACTIVE DERIVATION (the single writer — §7.2). Every reader of the
 * chain verdict calls THIS with the same inputs; no reader persists its own
 * verdict anymore.
 *
 * @param {{
 *   cloudConnected?: boolean,
 *   cloudLabel?: string,
 *   wake?: {wakeId:string, startedAt:number, firstProbeCompletedAt:number, attempts:number, lastProbe:Object|null},
 *   lastPull?: {ok?:boolean, attempted?:boolean, at?:number} | null,
 *   probeInFlight?: boolean,
 *   now?: number,
 * }} input
 * @returns {{
 *   verdict:'ok'|'pending'|'attention'|'no-cloud',
 *   cause:string|null, evidence:Object|null,
 *   pendingWords:string|null, secondsPending:number,
 *   nextRetryAt:number|null, attempts:number,
 * }}
 */
export function deriveChainState(input = {}) {
  const now = Number(input.now) || Date.now()
  const cloudConnected = !!input.cloudConnected
  const wake = input.wake || newWakeCycle('', now)
  const lastPull = input.lastPull || null
  const attempts = Math.max(0, Number(wake.attempts) || 0)
  const lastProbe = wake.lastProbe || null

  // ── no cloud connected: the transfer gate and the strip both read this
  // SAME fact — the gate may say "no cloud is connected" (the honest,
  // proactive manual-route offer) and the strip shows its no-chain states ──
  if (!cloudConnected) {
    return { verdict: CHAIN_VERDICTS.NO_CLOUD, cause: null, evidence: null, pendingWords: null, secondsPending: 0, nextRetryAt: null, attempts, nextStepWords: null }
  }

  // ── AUTO-CLEAR (§7.4): ANY success this wake cycle — probe or pull —
  // derives ok. Zero user action; the promise is kept by construction. ──
  const pullOk = !!(lastPull && lastPull.ok)
  const probeOk = !!(lastProbe && lastProbe.ok)
  if (probeOk || pullOk) {
    return { verdict: CHAIN_VERDICTS.OK, cause: null, evidence: null, pendingWords: null, secondsPending: 0, nextRetryAt: null, attempts, nextStepWords: null }
  }

  // ── PENDING BEFORE ERROR (§7.3): before the first successful probe of a
  // wake cycle the surface shows pending — while the probe runs, while the
  // ladder climbs, always calm. An error CANNOT render in this window. ──
  const firstProbeDone = Number(wake.firstProbeCompletedAt) > 0
  const probeInFlight = input.probeInFlight === true
  const ladderOpen = attempts < CHAIN_RETRY_LADDER_MS.length
  if (!firstProbeDone || probeInFlight || ladderOpen) {
    // ── R145 §6.1 — THE WATCHDOG (the G-3 cure): pending is a CALM state,
    // never an eternal one. Past the cap the SAME derivation returns the
    // typed retryable attention state — the strip's eternal "started Ns
    // ago" line is structurally unrepresentable. The comparison is RAW MS
    // (exact: the cap means "at most 120 seconds", to the millisecond).
    // Auto-clear still wins: the first success anywhere in the cycle
    // returns ok BEFORE this branch (§7.4 held — the stalled state is only
    // ever derived from failure).
    const pendingMs = Math.max(0, now - (Number(wake.startedAt) || now))
    const secondsPending = Math.floor(pendingMs / 1000)
    // ── R150 D-3 — THE CHECK BUDGET (capture B1): while the check itself is
    // genuinely IN FLIGHT, the pending line must resolve within 10 s. The
    // worker bounds every probe ≤10 s, so a pending state that is still
    // in-flight past the budget is the machine's defect — the SAME
    // derivation returns the typed CHECK_TIMED_OUT:<hop> attention with the
    // one-button next step. Auto-clear still wins (the ok branch above);
    // this branch only ever fires from a genuinely hung check. ──
    if (probeInFlight && pendingMs > CHAIN_CHECK_CAP_MS) {
      const hop = String((lastProbe && lastProbe.probeName) || 'pull-probe').slice(0, 40)
      return {
        verdict: CHAIN_VERDICTS.ATTENTION,
        cause: `CHECK_TIMED_OUT:${hop}`,
        evidence: { startedAt: Number(wake.startedAt) || now, now, capMs: CHAIN_CHECK_CAP_MS, secondsPending, attempts, hop },
        pendingWords: null,
        secondsPending,
        nextRetryAt: null,
        attempts,
        nextStepWords: CHAIN_CHECK_TIMED_OUT_NEXT_STEP,
      }
    }
    if (pendingMs > CHAIN_PENDING_CAP_MS) {
      return {
        verdict: CHAIN_VERDICTS.ATTENTION,
        cause: 'check-stalled',
        evidence: { startedAt: Number(wake.startedAt) || now, now, capMs: CHAIN_PENDING_CAP_MS, secondsPending, attempts },
        pendingWords: null,
        secondsPending,
        nextRetryAt: null,
        attempts,
        nextStepWords: CHAIN_STALLED_NEXT_STEP,
      }
    }
    return {
      verdict: CHAIN_VERDICTS.PENDING,
      cause: null,
      evidence: null,
      pendingWords: `Cloud check in progress — verifying your encrypted backup (started ${secondsPending}s ago)`,
      secondsPending,
      nextRetryAt: firstProbeDone && ladderOpen ? nextRetryAt(attempts, wake.lastProbe ? wake.lastProbe.at || now : now) : nextRetryAt(0, wake.startedAt),
      attempts,
      nextStepWords: null,
    }
  }

  // ── the ladder is exhausted and NOTHING succeeded this cycle: the verdict
  // derives from the WORST classified evidence of the cycle (never from a
  // stale persisted row — the wake's own attempts are the evidence) ──
  const classified = lastProbe ? classifyProbeFailure(lastProbe) : classifyProbeFailure({ probeName: 'wake-probe', at: wake.startedAt })
  const cause = classified.cls === PROBE_CLASSES.MALFORMED
    ? 'bridge'
    : classified.cls === PROBE_CLASSES.UNREADABLE
      ? 'unreadable'
      : classified.cls === PROBE_CLASSES.AUTH_RACE
        ? 'auth'
        : 'unreachable'
  return {
    verdict: CHAIN_VERDICTS.ATTENTION,
    cause,
    evidence: { ...classified.evidence, attempts, nextRetryAt: null },
    pendingWords: null,
    secondsPending: 0,
    nextRetryAt: null,
    attempts,
    nextStepWords: CHAIN_STALLED_NEXT_STEP,
  }
}

/**
 * THE WAKE-CACHE DEMOTION LAW: a persisted verdict row may only RENDER
 * after this re-derivation; the wake id comparison makes a stale row
 * unrenderable. (The persisted shape stays a CACHE — never a writer.)
 */
export function isVerdictCacheFresh(cache, wake) {
  if (!cache || !wake) return false
  return String(cache.wakeId || '') === String(wake.wakeId || '')
}

/**
 * THE CLOUD GATE COUPLING (F3d, the structural impossibility): the
 * transfer plane's gate may declare the cloud CLOSED only when this
 * function says so from the SAME derivation the pill renders. A gate
 * verdict that contradicts a green pill is unrepresentable — both read
 * one fact.
 *
 * @returns {{closed:boolean, reason:string|null, evidence:Object|null}}
 *   closed=true ONLY for: no cloud connected (proactive manual route), or
 *   an evidence-backed exhausted-ladder verdict. A pending state NEVER
 *   closes the gate (the ladder is still climbing — a cold-start race is
 *   not a dead cloud).
 */
export function cloudGateFromChainState(derived) {
  const d = derived || {}
  if (d.verdict === CHAIN_VERDICTS.NO_CLOUD) {
    return { closed: true, reason: 'no-cloud-connected', evidence: null }
  }
  if (d.verdict === CHAIN_VERDICTS.PENDING) {
    return { closed: false, reason: null, evidence: null } // the ladder owns it — the road stays open
  }
  if (d.verdict === CHAIN_VERDICTS.ATTENTION) {
    return { closed: true, reason: String(d.cause || 'unreachable'), evidence: d.evidence || null }
  }
  return { closed: false, reason: null, evidence: null } // ok — the road is open
}
