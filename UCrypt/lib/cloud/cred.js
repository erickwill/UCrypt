/**
 * UCrypt — R147 §4 — THE CREDENTIAL LIFECYCLE MACHINE (lib/cloud/cred.js).
 *
 * THE J-5 CURE (capture A1 — "very often is necessary to login again and
 * again with Google Drive"): the state machine beneath the Cloud Sync card.
 * The card's copy machinery (the typed banner, Nothing-was-lost, the four
 * steps) is field-proven GOOD (C4) and STAYS; what dies is the credential
 * handling beneath it — the MALFORMED dead-end (lib/chain-state.js:117-124
 * renders a Google sign-in page as "answered unexpectedly" with no retry,
 * no refresh, no one-click reconnect).
 *
 * THE STATES: FRESH → EXPIRING → REFRESHING → DEAD → REVIVED.
 *   at 80% of the credential's measured lifetime → EXPIRING → refresh UNDER
 *   THE HOOD (never wait for the failure); on any 401 / login-redirect /
 *   non-JSON answer → REFRESHING (a silent refresh BEFORE any user-visible
 *   state); only a failed silent refresh moves to DEAD (the banner arms);
 *   a successful probe at ANY point → REVIVED → FRESH (the banner clears
 *   itself; uploads resume).
 *
 * THE TYPED VERDICT CLASSES (§4.3) — "answered unexpectedly" is no longer
 * allowed to be a final diagnosis. THE SELF-HEAL LOOP (§4.5): backoff
 * 1/2/4/8/15 min (cap 15); uploads pause only after 3 consecutive failed
 * cycles; the banner carries the LIVE retry clock. ONE TRUTH (§4.4): the
 * chip and the banner read THIS machine's last probe verdict.
 *
 * PURE — the probe, the persistence, the clock and the toast are injected.
 * Battery: tests/cloud/r147-cred.test.mjs (the §4.8 fixture rows).
 */

/** The typed verdict classes (the ONLY diagnoses this machine may render). */
export const CRED_VERDICT_CLASSES = Object.freeze({
  UNEXPECTED_LOGIN_REDIRECT: {
    key: 'UNEXPECTED_LOGIN_REDIRECT',
    words: 'Your Google sign-in expired — press Reconnect.',
    nextStep: 'reconnect',
  },
  UNEXPECTED_401: {
    key: 'UNEXPECTED_401',
    words: 'The saved key was refused — press Reconnect.',
    nextStep: 'reconnect',
  },
  UNEXPECTED_HTML: {
    key: 'UNEXPECTED_HTML',
    words: 'The Web App URL is answering with a login or error page — press Reconnect, then re-test.',
    nextStep: 'reconnect',
  },
  UNEXPECTED_NETWORK: {
    key: 'UNEXPECTED_NETWORK',
    words: 'The network path to Google failed — we will retry automatically.',
    nextStep: 'wait',
  },
  UNEXPECTED_CORS: {
    key: 'UNEXPECTED_CORS',
    words: 'The answer was blocked — the Web App deployment needs "Anyone" access re-granted.',
    nextStep: 'redeploy',
  },
  UNEXPECTED_QUOTA: {
    key: 'UNEXPECTED_QUOTA',
    words: 'Google asked us to slow down; we will retry automatically.',
    nextStep: 'wait',
  },
  UNEXPECTED_SHAPE: {
    key: 'UNEXPECTED_SHAPE',
    words: 'The stored Web App may be an older deployment — re-select it once.',
    nextStep: 'reselect',
  },
  // R149 C-1a (capture A1/A2 — THE LOCKED TRUTH): a locked vault is a
  // FIRST-CLASS verdict, never a lying shape/network class. Every browser
  // restart wakes LOCKED (R45-A); the honest sentence names the unlock as
  // the one-step cure — the chain revives on its own afterwards (LAW #79).
  CRED_LOCKED: {
    key: 'CRED_LOCKED',
    words: 'The vault is locked on this device — unlock once and the chain revives on its own.',
    nextStep: 'unlock',
  },
  // R149 §6.6 — THE TWO-TRUTHS SWEEP: the bridge's own ad-hoc sentences
  // (gdrive.js NO_URL_USER_MSG and the shape-class reselect words) may never
  // coexist as contradictory truths. ONE class machine writes every cloud
  // sentence: the bridge causes map onto THESE typed classes and the
  // transport reuses the class words verbatim (contract §6.6).
  BRIDGE_URL_MISSING: {
    key: 'BRIDGE_URL_MISSING',
    words: 'Add your Apps Script Web App URL first — Edit setup and paste the /exec URL.',
    nextStep: 'edit-setup',
  },
  // R171 — THE TRANSPORT-TRUTH CLASS (the E-23 cure): the OAuth transport's
  // own setup-missing verdict. An OAuth-connected user must NEVER be told
  // to add an Apps Script URL — the bridge classes speak for the BRIDGE
  // transport only; this class speaks for the OAuth/fast rungs.
  OAUTH_SETUP_MISSING: {
    key: 'OAUTH_SETUP_MISSING',
    words: 'Connect Google Drive again — press Connect (you ride the OAuth transport; no script setup is involved).',
    nextStep: 'reconnect',
  },
  BRIDGE_AUTH_STALE: {
    key: 'BRIDGE_AUTH_STALE',
    words: 'Reconnect to re-authorize the bridge.',
    nextStep: 'reconnect',
  },
  BRIDGE_DEPLOY_OLD: {
    key: 'BRIDGE_DEPLOY_OLD',
    words: 'The stored Web App is an older deployment — re-select it once.',
    nextStep: 'reselect',
  },
})

/** The states. */
export const CRED_STATES = Object.freeze({
  FRESH: 'fresh',
  EXPIRING: 'expiring',
  REFRESHING: 'refreshing',
  DEAD: 'dead',
  REVIVED: 'revived',
})

/** The §4.5 backoff (the ledgered numbers: 1/2/4/8/15 min, cap 15). */
export const HEAL_BACKOFF_MS = [60_000, 120_000, 240_000, 480_000, 900_000]
export const HEAL_BACKOFF_CAP_MS = 900_000
export const UPLOAD_PAUSE_AFTER_CYCLES = 3

/** The refresh trigger (§4.1: at 80% of the measured lifetime). */
export const REFRESH_AT_LIFETIME_FRACTION = 0.8
/** The journal ring (§4.1: the last 20 with timestamps). */
export const JOURNAL_RING_SIZE = 20

export function credError(code, message) {
  const e = new Error(message)
  e.code = `CRED_${code}`
  return e
}

/**
 * §4.3 — CLASSIFY ONE UNEXPECTED ANSWER. The transport hands over the raw
 * evidence; the machine names the class. `classifyBridgeAnswer`-shaped
 * hints ({cause:'not-public'}) map onto the classes (the transport's four
 * classic causes keep their precision).
 * @param {{kind?:string, status?:number|null, contentType?:string,
 *          bodyStart?:string, htmlHint?:{cause?:string}}} ans
 */
export function classifyCredentialAnswer(ans = {}) {
  const status = Number.isFinite(Number(ans.status)) ? Number(ans.status) : null
  const kind = String(ans.kind || '')
  const body = String(ans.bodyStart || '')
  const cause = ans.htmlHint && ans.htmlHint.cause
  if (kind === 'locked' || ans.locked === true) return CRED_VERDICT_CLASSES.CRED_LOCKED
  if (kind === 'network' || kind === 'timeout') return CRED_VERDICT_CLASSES.UNEXPECTED_NETWORK
  if (kind === 'cors') return CRED_VERDICT_CLASSES.UNEXPECTED_CORS
  if (kind === 'config' && !status && !body && !cause) {
    // §6.6 — an evidence-free CONFIG throw is the client-side setup refusal.
    // R171 — THE TRANSPORT-TRUTH BRANCH: the class follows the ACTIVE
    // transport. A config answer that carries OAuth evidence (the transport
    // mode or an OAuth client/grant) names the OAUTH class — the bridge
    // URL demand is structurally unreachable for it (the E-23 defect's
    // exact class). The bridge shape (no OAuth evidence) keeps its class.
    if (ans.transportMode === 'oauth' || ans.transportMode === 'fast' || ans.oauthEvidence === true) {
      return CRED_VERDICT_CLASSES.OAUTH_SETUP_MISSING
    }
    return CRED_VERDICT_CLASSES.BRIDGE_URL_MISSING
  }
  if (cause === 'editor-url' || cause === 'deploy-errored' || cause === 'html-unknown') {
    // §6.6 — the bridge answered with an HTML page that names a stale or
    // mis-deployed Web App — the deploy-old class (the shape lie dies here).
    return CRED_VERDICT_CLASSES.BRIDGE_DEPLOY_OLD
  }
  if (status === 401 || status === 403) return CRED_VERDICT_CLASSES.UNEXPECTED_401
  if (status === 429) return CRED_VERDICT_CLASSES.UNEXPECTED_QUOTA
  if (cause === 'not-public' || /accounts\.google\.com|sign in|sign-in/i.test(body)) return CRED_VERDICT_CLASSES.UNEXPECTED_LOGIN_REDIRECT
  if (kind === 'html' || /<html[\s>]|<!doctype html/i.test(body)) return CRED_VERDICT_CLASSES.UNEXPECTED_HTML
  if (kind === 'shape') return CRED_VERDICT_CLASSES.UNEXPECTED_SHAPE
  return CRED_VERDICT_CLASSES.UNEXPECTED_SHAPE
}

/** The next backoff for cycle N (0-based), capped (§4.5). */
export function nextHealMs(cycleIndex) {
  const i = Math.max(0, Number(cycleIndex) || 0)
  return i < HEAL_BACKOFF_MS.length ? HEAL_BACKOFF_MS[i] : HEAL_BACKOFF_CAP_MS
}

/** Should uploads pause? (§4.5 — only after 3 consecutive failed cycles.) */
export function uploadsPaused(failedCycles) {
  return (Number(failedCycles) || 0) >= UPLOAD_PAUSE_AFTER_CYCLES
}

/**
 * Create the machine.
 * @param {object} args
 *   probe       — async () => { ok:true, at } | { ok:false, ...evidence } —
 *                 the transport's credential check (a cheap authenticated read)
 *   refresh     — async () => { ok:boolean } — the silent refresh (re-probe
 *                 under the hood; the browser refreshes the session itself)
 *   storage     — { get, set } (chrome.storage.local — §4.2 persistence)
 *   toast       — (words) => void — the mortal toast (the revive announcement)
 *   now         — the clock
 *   storageKey  — the persisted state key (default ucrypt:cred-machine)
 */
export function createCredMachine({ probe, refresh = null, storage = null, toast = () => {}, now = () => Date.now(), storageKey = 'ucrypt:cred-machine' } = {}) {
  if (typeof probe !== 'function') throw credError('SHAPE', 'the machine needs the probe door')
  let state = CRED_STATES.FRESH
  let lastVerdict = { ok: true, at: now(), cls: null }
  let failedCycles = 0
  let nextRetryAt = null
  let journal = []
  let lifetime = { startedAt: now(), measuredMs: 0 } // measured from the last FRESH entry
  let hydrating = null

  const persist = async () => {
    if (!storage || !storage.set) return
    try {
      await storage.set({ [storageKey]: { state, lastVerdict, failedCycles, nextRetryAt, journal, lifetime } })
    } catch { /* a dead store never kills the machine */ }
  }

  const hydrate = async () => {
    if (!storage || !storage.get) return
    try {
      const got = await storage.get(storageKey)
      const saved = got && got[storageKey]
      if (saved && saved.state && saved.lastVerdict) {
        // §4.2 — persistence across restarts; a DEAD state revives to
        // REFRESHING on boot (the machine never trusts a stale death)
        state = saved.state === CRED_STATES.DEAD ? CRED_STATES.REFRESHING : saved.state
        lastVerdict = saved.lastVerdict
        failedCycles = Number(saved.failedCycles) || 0
        nextRetryAt = saved.nextRetryAt || null
        journal = Array.isArray(saved.journal) ? saved.journal.slice(-JOURNAL_RING_SIZE) : []
        lifetime = saved.lifetime || lifetime
      }
    } catch { /* the defaults stand */ }
  }
  hydrating = hydrate()

  const record = (event, detail = {}) => {
    journal.push({ at: now(), event, ...detail })
    if (journal.length > JOURNAL_RING_SIZE) journal = journal.slice(-JOURNAL_RING_SIZE)
  }

  const to = (next, why = '') => {
    if (!Object.values(CRED_STATES).includes(next)) throw credError('STATE', `unknown state ${String(next)}`)
    if (state === CRED_STATES.DEAD && next === CRED_STATES.FRESH) next = CRED_STATES.REVIVED
    record('state', { from: state, to: next, why })
    state = next === CRED_STATES.REVIVED ? CRED_STATES.FRESH : next
    if (next === CRED_STATES.REVIVED || next === CRED_STATES.FRESH) {
      const t = now()
      if (lifetime.startedAt) lifetime.measuredMs = t - lifetime.startedAt
      lifetime.startedAt = t
    }
    persist()
    return state
  }

  return {
    get state() { return state },
    get failedCycles() { return failedCycles },
    get nextRetryAt() { return nextRetryAt },
    get lastVerdict() { return lastVerdict },
    ready() { return hydrating },

    /** The probe — the ONE truth's source (§4.4). Never throws. */
    async check() {
      await hydrating
      let ans
      try { ans = await probe() } catch (e) {
        ans = { ok: false, kind: 'network', error: String((e && e.message) || e).slice(0, 160) }
      }
      if (ans && ans.ok) {
        failedCycles = 0
        nextRetryAt = null
        const wasDead = state === CRED_STATES.DEAD
        to(CRED_STATES.FRESH, 'the probe succeeded')
        lastVerdict = { ok: true, at: now(), cls: null }
        record('probe-ok', {})
        if (wasDead) {
          toast('Cloud reconnected — uploads resumed.')
          record('revived', {})
        }
        await persist()
        return { ok: true, state, verdict: lastVerdict }
      }
      const cls = classifyCredentialAnswer(ans || {})
      record('probe-failed', { cls: cls.key, status: (ans && ans.status) ?? null })
      lastVerdict = { ok: false, at: now(), cls: cls.key, words: cls.words, nextStep: cls.nextStep, evidence: { status: (ans && ans.status) ?? null, kind: String((ans && ans.kind) || ''), bodyStart: String((ans && ans.bodyStart) || '').slice(0, 200) } }
      /* THE SILENT REFRESH (§4.1): before ANY user-visible death */
      to(CRED_STATES.REFRESHING, `the answer classified ${cls.key}`)
      let refreshed = false
      if (refresh) {
        try { refreshed = !!(await refresh()) } catch { refreshed = false }
      }
      if (!refreshed) {
        try { const re = await probe(); refreshed = !!(re && re.ok) } catch { refreshed = false }
      }
      if (refreshed) {
        const wasDead2 = failedCycles > 0
        failedCycles = 0
        nextRetryAt = null
        to(CRED_STATES.FRESH, 'the silent refresh succeeded')
        lastVerdict = { ok: true, at: now(), cls: null }
        record('silent-refresh-ok', {})
        if (wasDead2) toast('Cloud reconnected — uploads resumed.')
        await persist()
        return { ok: true, state, verdict: lastVerdict, silentRefresh: true }
      }
      /* the refresh failed — the ladder of cycles decides the surface */
      failedCycles += 1
      const ms = nextHealMs(failedCycles - 1)
      nextRetryAt = now() + ms
      record('silent-refresh-failed', { cycle: failedCycles, nextRetryAt })
      to(CRED_STATES.DEAD, `cycle ${failedCycles} failed`)
      await persist()
      return { ok: false, state, verdict: lastVerdict, failedCycles, nextRetryAt, uploadsPaused: uploadsPaused(failedCycles) }
    },

    /** The self-heal tick (the alarm/interval calls this) — §4.5. */
    async healTick() {
      await hydrating
      if (state !== CRED_STATES.DEAD && state !== CRED_STATES.EXPIRING) return { ok: state === CRED_STATES.FRESH, skipped: true }
      return this.check()
    },

    /** The proactive refresh (§4.1 — at 80% of the measured lifetime). */
    maybeProactiveRefresh() {
      if (state !== CRED_STATES.FRESH) return false
      const measured = Number(lifetime.measuredMs) || 0
      if (!measured) return false
      const age = now() - Number(lifetime.startedAt)
      if (age >= measured * REFRESH_AT_LIFETIME_FRACTION) {
        to(CRED_STATES.EXPIRING, '80% of the measured lifetime elapsed')
        record('proactive-refresh', { age, measured })
        this.check().catch(() => {})
        return true
      }
      return false
    },

    /** §4.4 — THE ONE TRUTH: the words the chip renders (with its age). */
    chipTruth() {
      const ageMin = Math.max(0, Math.round((now() - Number(lastVerdict.at)) / 60_000))
      if (lastVerdict.ok) return { connected: true, line: `Cloud: connected · checked ${ageMin === 0 ? 'just now' : ageMin + ' min ago'}` }
      return { connected: false, line: `Cloud: needs you · checked ${ageMin === 0 ? 'just now' : ageMin + ' min ago'}` }
    },

    /** §4.5 — the banner's words (the LIVE retry clock when degraded). */
    bannerTruth() {
      if (state === CRED_STATES.DEAD || state === CRED_STATES.REFRESHING) {
        const attempt = Math.min(failedCycles, UPLOAD_PAUSE_AFTER_CYCLES)
        const min = Math.max(1, Math.round((Number(nextRetryAt) - now()) / 60_000))
        return {
          degraded: true,
          uploadsPaused: uploadsPaused(failedCycles),
          words: lastVerdict.words || 'The cloud needs you.',
          clock: failedCycles < UPLOAD_PAUSE_AFTER_CYCLES
            ? `will retry in ${min} min — attempt ${Math.min(failedCycles + 1, UPLOAD_PAUSE_AFTER_CYCLES)} of ${UPLOAD_PAUSE_AFTER_CYCLES}`
            : `uploads paused — will retry in ${min} min (attempt ${attempt} kept)`,
          cls: lastVerdict.cls,
          evidence: lastVerdict.evidence,
        }
      }
      return { degraded: false, uploadsPaused: false, words: '', clock: '' }
    },

    /** §4.7 — the honest auto-sync clock: the next RETRY when degraded. */
    nextSyncClock() {
      if (state === CRED_STATES.DEAD || state === CRED_STATES.REFRESHING) {
        const min = Math.max(1, Math.round((Number(nextRetryAt) - now()) / 60_000))
        return { degraded: true, words: `Next retry in ${min} min — uploads resume on their own when the road returns.` }
      }
      return { degraded: false, words: '' }
    },

    /** §4.6 — one-click reconnect: re-probe preserving EVERY setting. The
     * settings live in their own stores — the machine only re-arms and
     * re-probes (the R145 G-8 class: the owner never re-enters the URL). */
    async reconnect() {
      await hydrating
      record('reconnect', {})
      failedCycles = 0
      nextRetryAt = null
      to(CRED_STATES.REFRESHING, 'the human pressed Reconnect')
      return this.check()
    },

    /** §4.1 — the journaled ring for "Show the technical detail". */
    technicalDetail() {
      return {
        state,
        cls: lastVerdict.cls,
        status: lastVerdict.evidence ? lastVerdict.evidence.status : null,
        bodyStart: lastVerdict.evidence ? lastVerdict.evidence.bodyStart : '',
        journal: [...journal],
      }
    },
  }
}

// ═════════ R150 CURE 3 (§6.3, capture B5) — THE ONE-TRUTH CLOUD CARD ═════════
//
// THE FIELD EVIDENCE: the Cloud backup card held THREE truths at once — the
// ⚠ "connected, but the last backup run could not finish" headline, the
// ✗ "Add your Apps Script Web App URL first" class words, and the ✗
// "Unknown transport: null" line with its recovery card. Three sentence
// writers, one card, zero truth.
//
// THE CURE IS THE STATE MACHINE: the card renders EXACTLY ONE typed state
// per render — ONE headline class with ONE next step and the ONE action row
// (test · edit · back up · disconnect — it already exists). The three-truths
// state is structurally unrepresentable: this function returns ONE state, and
// the renderer writes ONLY that state's lines (the R149 §6.6 two-truths
// sweep's unvisited sibling). PURE — the battery pins every input → state row.
export const CLOUD_CARD_STATES = Object.freeze({
  NOT_CONNECTED: 'not-connected',
  BRIDGE_SETUP: 'bridge-setup',
  CONNECTED_OK: 'connected-ok',
  CONNECTED_DEGRADED: 'connected-degraded',
})

/** The typed BRIDGE_SETUP class (the unresolvable-record state's ONE line;
 * the same words live in lib/vault.js TRANSPORT_BRIDGE_SETUP_WORDS — one
 * sentence, two homes, byte-identical by the battery's pin). */
export const CLOUD_CARD_BRIDGE_SETUP = Object.freeze({
  key: 'BRIDGE_SETUP',
  words: 'Your saved cloud setup names a storage this build cannot resolve — choose a transport and press Connect.',
  nextStep: 'connect',
})

/**
 * THE CARD'S VERDICT (the ONE writer's input machine).
 * @param {{
 *   recordPresent?: boolean,        // a raw 'ucrypt:transport' record exists
 *   usableId?: string|null,         // the LEGACY-ALIAS READER's resolution
 *   hasConfig?: boolean,            // the record carries config content
 *   degradedErr?: string,           // the deduped push/pull error line
 * }} input
 * @returns {{state:string, cls:Object|null}} — EXACTLY ONE state.
 */
export function deriveCloudCardState(input = {}) {
  if (!input.recordPresent) return { state: CLOUD_CARD_STATES.NOT_CONNECTED, cls: null }
  if (!input.usableId) {
    // R150 D-2 — a stored record whose id resolves to nothing: with config
    // content the state is BRIDGE_SETUP (ONE line + the Connect button —
    // the record is never destroyed, but it claims connected nowhere);
    // with no content at all the honest state is simply not-connected.
    return { state: input.hasConfig ? CLOUD_CARD_STATES.BRIDGE_SETUP : CLOUD_CARD_STATES.NOT_CONNECTED, cls: input.hasConfig ? CLOUD_CARD_BRIDGE_SETUP : null }
  }
  if (input.degradedErr) return { state: CLOUD_CARD_STATES.CONNECTED_DEGRADED, cls: null }
  return { state: CLOUD_CARD_STATES.CONNECTED_OK, cls: null }
}
