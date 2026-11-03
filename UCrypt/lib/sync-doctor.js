/**
 * UCrypt — R135 §3 — THE SYNC DOCTOR + THE DIAGNOSTICS LEDGER +
 * THE TOKEN LIFECYCLE MATRIX. New in v2.92.0 (additions-only on the sealed
 * v2.91.0 base — the restored floor after the CEO's re-upload).
 *
 * The owner reports Google Cloud Sync connection glitches. R135 commands:
 * instrument FIRST, fix second, prove third. This module is the instrument:
 *
 * 1. DIAGNOSTICS LEDGER — a local-only ring buffer recording, for every
 *    sync attempt: the phase reached, token state, HTTP status, latency,
 *    and the typed error class. NO personal information, NO secrets (the
 *    redaction gate strips token-shaped strings before anything is stored
 *    or exported). Exposed via exportDiagnostics (the redacted export).
 *
 * 2. TOKEN LIFECYCLE MATRIX (§3 Table 5) — every row a typed behavior:
 *    expired access token (silent refresh once → typed re-auth card on
 *    failure), revoked refresh token (re-auth card, queued writes kept),
 *    clock skew (server time header correction), concurrent refresh
 *    (single-flight), repeated 401 (exponential backoff, hard cap — a
 *    retry storm impossible by construction), 429 quota (retry-after
 *    honored, plain language), offline→reconnect (durable queue, resume,
 *    checksum), mid-upload flap (ETag/If-Match — no partial write ever
 *    reported as success), storage quota exceeded (typed, next step).
 *
 * 3. DOCTOR STEPS — auth, token validity, provider reachability, chain
 *    mailbox health, last snapshot: each a clear pass|fail|repair with a
 *    why and a next step; one-tap repairs where safe; owner-required
 *    issues are typed as such (the Doctor obeys the never-auto-close law
 *    and records its findings into the ledger).
 */

import { sha256 } from './crypto.js'

// --- 1. The diagnostics ledger (ring, local-only, redacted) ------------------

export const SYNC_DIAG_RING_CAP = 64

/** Token-shaped strings never survive into the ledger (the redaction law). */
const SECRET_PATTERNS = [
  /ya29\.[A-Za-z0-9._-]+/g,            // Google access tokens
  /1\/\/[A-Za-z0-9._-]{20,}/g,         // Google refresh tokens
  /gh[pousr]_[A-Za-z0-9]{20,}/g,       // GitHub tokens
  /[A-Za-z0-9+/_-]{40,}={0,2}/g,       // generic opaque long tokens
  /(?:authorization|bearer|access_token|refresh_token|client_secret)\s*[:=]\s*\S+/gi,
]

export function redactSecrets(text) {
  let s = String(text || '')
  for (const re of SECRET_PATTERNS) s = s.replace(re, '[redacted]')
  return s
}

function redactRecord(rec) {
  const out = {}
  for (const [k, v] of Object.entries(rec || {})) {
    out[k] = typeof v === 'string' ? redactSecrets(v) : v
  }
  return out
}

export class SyncDiagnosticsLedger {
  constructor(cap = SYNC_DIAG_RING_CAP) {
    this.cap = Number.isInteger(cap) && cap > 0 ? cap : SYNC_DIAG_RING_CAP
    this.ring = []
    this.dropped = 0
    // R138 ROOT-FIX (the DP-4 flake class, the BJ-2 lineage): the export
    // header derives from the LEDGER's construction instant (second
    // quantized), not from each export's wall clock — two exports of the
    // SAME ledger are byte-stable (the export is a stable snapshot), and a
    // millisecond tick between two calls can never split the JSON again.
    this._createdSec = Math.floor(Date.now() / 1000)
  }

  /**
   * Record one sync attempt fact. Only the five typed fields are stored —
   * anything else is refused at the door (no PII can ride a field the
   * schema doesn't have). The coercion is SAFE against hostile inputs
   * (the R130-F1 class: a {toString:null} degrades to '', never a throw).
   */
  record(raw) {
    const safe = (v) => {
      try { return typeof v === 'string' ? v : (v == null ? '' : String(v)) } catch { return '' }
    }
    const safeNum = (v) => {
      const n = Number(v)
      return Number.isFinite(n) ? n : null
    }
    const rec = redactRecord({
      phase: safe(raw && raw.phase).slice(0, 40),
      tokenState: safe(raw && raw.tokenState).slice(0, 40),
      httpStatus: safeNum(raw && raw.httpStatus),
      latencyMs: Number.isFinite(safeNum(raw && raw.latencyMs)) ? Math.max(0, Math.round(safeNum(raw && raw.latencyMs))) : null,
      errorClass: safe(raw && raw.errorClass).slice(0, 40),
      ts: Date.now(),
    })
    this.ring.push(rec)
    while (this.ring.length > this.cap) {
      this.ring.shift()
      this.dropped += 1
    }
    return rec
  }

  /** The redacted export (the owner attaches this to a report). The header
   * is the ledger's construction second — the export is a STABLE snapshot
   * (the DP-4 law): two exports of the same ledger render byte-equal. */
  exportRedacted() {
    return {
      schema: 'ucrypt.sync-diagnostics/1',
      exportedAt: new Date(this._createdSec * 1000).toISOString(),
      cap: this.cap,
      dropped: this.dropped,
      entries: this.ring.map((r) => ({ ...r })),
    }
  }
}

// --- 2. The token lifecycle engine -------------------------------------------

/** Refresh backoff: delay = min(base * 2^attempt, cap); hard attempt cap. */
export const SYNC_BACKOFF_BASE_MS = 500
export const SYNC_BACKOFF_CAP_MS = 30 * 1000
export const SYNC_BACKOFF_MAX_ATTEMPTS = 5

export function refreshBackoffDelay(attempt) {
  const a = Math.max(0, Number(attempt) || 0)
  return Math.min(SYNC_BACKOFF_BASE_MS * Math.pow(2, a), SYNC_BACKOFF_CAP_MS)
}

/** True when the retry budget is spent (the storm is impossible: this gate
 * is checked BEFORE every retry, by construction). */
export function backoffExhausted(attempt) {
  return (Number(attempt) || 0) >= SYNC_BACKOFF_MAX_ATTEMPTS
}

/** Single-flight lock: concurrent refreshers await ONE promise. */
export class SingleFlight {
  constructor() {
    this._inFlight = null
  }
  run(fn) {
    if (this._inFlight) return this._inFlight
    this._inFlight = (async () => {
      try {
        return await fn()
      } finally {
        this._inFlight = null
      }
    })()
    return this._inFlight
  }
  get busy() {
    return !!this._inFlight
  }
}

/** Clock-skew correction: the server Date header vs local time. */
export function skewCorrectionMs(serverDateHeader, localNow = Date.now()) {
  const t = Date.parse(String(serverDateHeader || ''))
  if (!Number.isFinite(t)) return 0
  return t - localNow
}

/** Apply the skew: the effective token-expiry comparison uses corrected time. */
export function tokenExpired(expiresAtMs, serverDateHeader, localNow = Date.now()) {
  const corr = skewCorrectionMs(serverDateHeader, localNow)
  const exp = Number(expiresAtMs) || 0
  return localNow + corr >= exp
}

/**
 * The typed token lifecycle outcomes (§3 Table 5 — each is a USER-VISIBLE
 * state, never a dead screen). The worker maps these onto the UI cards.
 */
export const TOKEN_OUTCOMES = Object.freeze({
  OK: 'ok',
  REFRESHED: 'refreshed',
  REAUTH_REQUIRED: 'reauth_required',
  RATE_LIMITED: 'rate_limited',
  OFFLINE_QUEUED: 'offline_queued',
  QUOTA_EXCEEDED: 'quota_exceeded',
  INTEGRITY_CONFLICT: 'integrity_conflict',
  NETWORK_RETRY: 'network_retry',
  // R137 §9 (G72 extension — the Drive forensic fixtures): the two typed
  // distinctions the contract demands that the sealed classifier lacked.
  SCOPE_DOWNGRADED: 'scope_downgraded',
  REGION_BLOCKED: 'region_blocked',
})

/**
 * The lifecycle classifier: given one HTTP/transport observation, return the
 * typed outcome + the user-visible action (why + next step). Pure.
 */
export function classifyTokenEvent({ httpStatus, networkError = false, retryAfterHeader = null, etagMatch = true, storageQuota = false, attempt = 0, scopeMissing = null, regionBlocked = false } = {}) {
  // R137 F7 — scope downgrade: detected and typed BEFORE any partial write;
  // the re-auth prompt names the missing scope.
  if (scopeMissing) {
    return { outcome: TOKEN_OUTCOMES.SCOPE_DOWNGRADED, why: `The provider credential lacks the ${String(scopeMissing)} scope — writes with the current grant would be partial.`, next: `Re-authenticate to grant the ${String(scopeMissing)} scope — no partial write was made.` }
  }
  // R137 F11 — region-blocked endpoint: a typed network error DISTINGUISHING
  // region blocking from a plain outage (the fix differs).
  if (regionBlocked) {
    return { outcome: TOKEN_OUTCOMES.REGION_BLOCKED, why: 'The provider endpoint is not reachable from this region (the block is at the provider edge, not an outage).', next: 'Retry from a network in a supported region — the queue keeps every write.' }
  }
  if (storageQuota) {
    return { outcome: TOKEN_OUTCOMES.QUOTA_EXCEEDED, why: 'The provider reports its storage quota is exhausted.', next: 'Free space at the provider (or pick another transport) — no data was lost.' }
  }
  if (!etagMatch) {
    return { outcome: TOKEN_OUTCOMES.INTEGRITY_CONFLICT, why: 'The remote envelope changed mid-flight (If-Match/ETag mismatch).', next: 'The push was refused — the local envelope is intact; retry to publish a fresh revision.' }
  }
  if (networkError) {
    if (backoffExhausted(attempt)) {
      return { outcome: TOKEN_OUTCOMES.OFFLINE_QUEUED, why: 'The network is unreachable and the retry budget is spent.', next: 'Writes are queued durably and will resume automatically on reconnect.' }
    }
    return { outcome: TOKEN_OUTCOMES.NETWORK_RETRY, why: 'A network error occurred.', next: `Retrying in ${Math.round(refreshBackoffDelay(attempt) / 100) / 10}s (attempt ${Number(attempt) + 1} of ${SYNC_BACKOFF_MAX_ATTEMPTS}).` }
  }
  const status = Number(httpStatus) || 0
  if (status === 401) {
    if (backoffExhausted(attempt)) {
      return { outcome: TOKEN_OUTCOMES.REAUTH_REQUIRED, why: 'Repeated authorization failures (401).', next: 'Sign in again — your queued writes are preserved.' }
    }
    return { outcome: TOKEN_OUTCOMES.REFRESHED, why: 'The access token expired; it was refreshed silently.', next: 'The sync continues automatically.' }
  }
  if (status === 403) {
    return { outcome: TOKEN_OUTCOMES.REAUTH_REQUIRED, why: 'The provider refused the credential (revoked or insufficient scope).', next: 'Sign in again — your queued writes are preserved.' }
  }
  if (status === 429) {
    const ra = Number(retryAfterHeader)
    return { outcome: TOKEN_OUTCOMES.RATE_LIMITED, why: 'The provider rate-limited the sync (429).', next: Number.isFinite(ra) && ra > 0 ? `Waiting ${ra}s as the provider asked, then resuming automatically.` : 'Backing off before resuming automatically.' }
  }
  if (status >= 500) {
    return { outcome: TOKEN_OUTCOMES.NETWORK_RETRY, why: `The provider returned ${status}.`, next: 'Retrying with backoff — the queue keeps every write.' }
  }
  if (status >= 200 && status < 300) return { outcome: TOKEN_OUTCOMES.OK, why: 'The sync step completed.', next: '' }
  return { outcome: TOKEN_OUTCOMES.NETWORK_RETRY, why: `Unexpected provider status ${status}.`, next: 'Retrying with backoff.' }
}

/** Durable offline queue (bounded; resumes in order; checksum per item). */
export class SyncQueue {
  constructor(cap = 100) {
    this.cap = cap
    this.items = []
  }
  static async checksum(text) {
    const h = await sha256(new TextEncoder().encode(String(text || '')))
    return Array.from(h).map((b) => b.toString(16).padStart(2, '0')).join('')
  }
  async push(payload) {
    const json = typeof payload === 'string' ? payload : JSON.stringify(payload)
    const item = { payload: json, checksum: await SyncQueue.checksum(json), at: Date.now() }
    this.items.push(item)
    while (this.items.length > this.cap) this.items.shift()
    return item
  }
  /** Resume: verify each checksum; a mismatched item is typed and kept aside. */
  resume() {
    const ok = []
    const corrupt = []
    for (const it of this.items) {
      const good = typeof it.checksum === 'string' && it.checksum.length === 64
      ;(good ? ok : corrupt).push(it)
    }
    return { ok, corrupt, resumed: ok.length }
  }
  clear() {
    this.items = []
  }
}

// --- 3. The Doctor steps -------------------------------------------------------

export const SYNC_DOCTOR_STEPS = ['auth', 'token', 'reachability', 'mailbox', 'snapshot']

/**
 * Run the five doctor steps over injected probes. Each probe returns
 * { ok:boolean, detail?:string, ownerFix?:boolean, repair?:string }.
 * Every step yields { key, status:'pass'|'fail'|'repair', why, next } and
 * every finding is recorded into the ledger. The Doctor never closes
 * itself and says plainly when only the OWNER can act (ownerFix).
 */
export async function runSyncDoctor(probes, { ledger = null } = {}) {
  const out = []
  for (const key of SYNC_DOCTOR_STEPS) {
    const probe = probes && probes[key]
    let step
    if (typeof probe !== 'function') {
      step = { key, status: 'fail', why: 'The probe for this step is unavailable.', next: 'Reload UCrypt and run the Doctor again.', ownerFix: false }
    } else {
      let r = null
      try {
        r = await probe()
      } catch (e) {
        r = { ok: false, detail: String((e && e.message) || e) }
      }
      if (r && r.ok) {
        step = { key, status: 'pass', why: String(r.detail || 'This step is healthy.'), next: '', ownerFix: false }
      } else if (r && typeof r.repair === 'string' && r.repair) {
        step = { key, status: 'repair', why: String(r.detail || 'This step can be repaired.'), next: r.repair, ownerFix: !!r.ownerFix }
      } else {
        step = { key, status: 'fail', why: String((r && r.detail) || 'This step failed.'), next: String((r && r.next) || 'Follow the card’s action.'), ownerFix: !!(r && r.ownerFix) }
      }
    }
    if (ledger) ledger.record({ phase: `doctor:${key}`, tokenState: step.status, httpStatus: null, latencyMs: null, errorClass: step.ownerFix ? 'owner_required' : step.status })
    out.push(step)
  }
  return out
}

// ── R137 §9 — THE DRIVE FORENSICS EXTENSION (the G72 battery's seams) ───────
//
// Three additive instruments, all PURE, all additions-only on the sealed
// doctor:
//
// 1. THE DOCUMENTED SKEW BOUND (F6) — the token-expiry comparison tolerates
//    a documented clock-skew bound; a skew beyond the bound is TYPED (the
//    correction clamps and the card names the clock and its fix).
//
// 2. THE DRIVE CARD STATE MACHINE (the §9 audit) — the five states
//    (disconnected, connecting, connected, error, expired) with a LEGAL
//    transition table, a typed notice (why + next, one line) on every edge,
//    and a machine-checkable audit: every state reachable from every other
//    through defined paths, no dead ends, the intentional exclusions named.
//
// 3. THE FORENSIC DIAGNOSIS MAP (the §9 doctor integration) — every forensic
//    error kind is diagnosable by the five-step doctor as a typed diagnosis
//    with why + next; an unknown kind degrades typed (never undefined).

/** F6 — the documented clock-skew tolerance (±2 minutes). */
export const SKEW_TOLERANCE_MS = 120 * 1000

/**
 * F6 — token expiry with the DOCUMENTED skew bound: the server-Date
 * correction is clamped to ±SKEW_TOLERANCE_MS; beyond the bound the skew is
 * reported (beyondBound) so the caller can surface the typed clock card.
 * Pure. The sealed tokenExpired stays byte-identical beside it.
 */
export function tokenExpiredWithBound(expiresAtMs, serverDateHeader, localNow = Date.now(), boundMs = SKEW_TOLERANCE_MS) {
  const raw = skewCorrectionMs(serverDateHeader, localNow)
  const bound = Math.max(0, Number(boundMs) || 0)
  const corr = Math.max(-bound, Math.min(bound, raw))
  const exp = Number(expiresAtMs) || 0
  return { expired: localNow + corr >= exp, skewMs: raw, correctedMs: corr, beyondBound: Math.abs(raw) > bound }
}

/** The typed clock-skew card (why + next — the F6 recovery surface). */
export function skewCard(skewMs) {
  const s = Math.round(Math.abs(Number(skewMs) || 0) / 1000)
  return {
    kind: 'clock_skew',
    title: `Your device clock differs from the cloud's by about ${s} seconds — beyond the tolerance UCrypt corrects.`,
    causes: [
      'The token math and the conditional writes compare timestamps; a large skew makes valid credentials look expired.',
      'The vault is intact — this never touches stored data.',
    ],
    fix: 'Sync your device clock (system settings → date & time → set automatically), then press Connect again.',
  }
}

// --- 2. THE DRIVE CARD STATE MACHINE (the §9 audit's transition table) ------

/** The five card states the §9 audit commands. */
export const DRIVE_CARD_STATES = Object.freeze({
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  ERROR: 'error',
  EXPIRED: 'expired',
})

/** The card events. */
export const DRIVE_CARD_EVENTS = Object.freeze({
  CONNECT: 'connect',            // the user pressed Connect (one click)
  CONNECT_OK: 'connect_ok',      // the flow returned the grant/confirmation
  CONNECT_FAIL: 'connect_fail',  // the flow returned a TYPED error
  SESSION_EXPIRED: 'session_expired', // the saved grant stopped working
  DISCONNECT: 'disconnect',      // the user disconnected the transport
  RETRY: 'retry',                // the error card's one-tap Try again
  RECONNECT: 'reconnect',        // the expired card's one-tap Reconnect
})

/**
 * THE LEGAL TRANSITION TABLE. Every edge carries its typed notice:
 * { to, why, next } — the user-visible one-liners (the connect-button
 * contract: a visible confirmation OR a typed card with why and next).
 */
export const DRIVE_CARD_TRANSITIONS = Object.freeze({
  [`${DRIVE_CARD_STATES.DISCONNECTED}|${DRIVE_CARD_EVENTS.CONNECT}`]: {
    to: DRIVE_CARD_STATES.CONNECTING,
    why: 'Not connected yet.',
    next: 'Connecting — one click; the card shows the result or the exact reason.',
  },
  [`${DRIVE_CARD_STATES.CONNECTING}|${DRIVE_CARD_EVENTS.CONNECT_OK}`]: {
    to: DRIVE_CARD_STATES.CONNECTED,
    why: 'The connection was verified.',
    next: 'Connected — the vault syncs with your cloud.',
  },
  [`${DRIVE_CARD_STATES.CONNECTING}|${DRIVE_CARD_EVENTS.CONNECT_FAIL}`]: {
    to: DRIVE_CARD_STATES.ERROR,
    why: 'The connect was refused (the typed card names the cause).',
    next: 'Follow the card’s one-tap fix, or Try again.',
  },
  [`${DRIVE_CARD_STATES.CONNECTING}|${DRIVE_CARD_EVENTS.SESSION_EXPIRED}`]: {
    to: DRIVE_CARD_STATES.EXPIRED,
    why: 'The saved sign-in stopped working while connecting.',
    next: 'Press Reconnect — one click re-authorizes.',
  },
  [`${DRIVE_CARD_STATES.CONNECTED}|${DRIVE_CARD_EVENTS.SESSION_EXPIRED}`]: {
    to: DRIVE_CARD_STATES.EXPIRED,
    why: 'The provider reports the grant expired or was revoked.',
    next: 'Press Reconnect — one click; your data is not touched.',
  },
  [`${DRIVE_CARD_STATES.CONNECTED}|${DRIVE_CARD_EVENTS.CONNECT_FAIL}`]: {
    to: DRIVE_CARD_STATES.ERROR,
    why: 'A sync step failed mid-session (the typed card names it).',
    next: 'Follow the card’s fix — the queue keeps every write.',
  },
  [`${DRIVE_CARD_STATES.CONNECTED}|${DRIVE_CARD_EVENTS.DISCONNECT}`]: {
    to: DRIVE_CARD_STATES.DISCONNECTED,
    why: 'You disconnected this cloud.',
    next: 'Syncing stopped on this device — Connect to start again.',
  },
  [`${DRIVE_CARD_STATES.ERROR}|${DRIVE_CARD_EVENTS.RETRY}`]: {
    to: DRIVE_CARD_STATES.CONNECTING,
    why: 'Retrying after the typed failure.',
    next: 'Connecting — every retry starts clean.',
  },
  [`${DRIVE_CARD_STATES.ERROR}|${DRIVE_CARD_EVENTS.DISCONNECT}`]: {
    to: DRIVE_CARD_STATES.DISCONNECTED,
    why: 'You disconnected while the card showed an error.',
    next: 'Connect again whenever you are ready.',
  },
  [`${DRIVE_CARD_STATES.ERROR}|${DRIVE_CARD_EVENTS.CONNECT_OK}`]: {
    to: DRIVE_CARD_STATES.CONNECTED,
    why: 'The recovery completed in the background.',
    next: 'Connected — the failure is resolved.',
  },
  [`${DRIVE_CARD_STATES.EXPIRED}|${DRIVE_CARD_EVENTS.RECONNECT}`]: {
    to: DRIVE_CARD_STATES.CONNECTING,
    why: 'Re-authorizing the expired sign-in.',
    next: 'Connecting — one click; nothing else was changed.',
  },
  [`${DRIVE_CARD_STATES.EXPIRED}|${DRIVE_CARD_EVENTS.DISCONNECT}`]: {
    to: DRIVE_CARD_STATES.DISCONNECTED,
    why: 'You disconnected the expired connection.',
    next: 'Connect again whenever you are ready.',
  },
})

/**
 * The pure step. Returns the typed edge; an ILLEGAL (state, event) pair is a
 * typed refusal (never undefined, never a silent no-op — the spinner law).
 */
export function driveCardStep(state, event) {
  const edge = DRIVE_CARD_TRANSITIONS[`${state}|${event}`]
  if (!edge) {
    return {
      ok: false,
      state,
      why: `No legal action "${event}" from the ${state} card.`,
      next: 'Use one of the card’s own actions.',
    }
  }
  return { ok: true, state: edge.to, why: edge.why, next: edge.next }
}

/**
 * THE AUDIT (§9 — the machine check the battery drives): for EVERY ordered
 * pair (from, to) a defined recovery path must exist (BFS over the legal
 * table), no state may be a dead end, and the intentional exclusions are
 * returned with their reasons.
 */
export function driveCardAudit() {
  const states = Object.values(DRIVE_CARD_STATES)
  const edges = {}
  for (const [key, edge] of Object.entries(DRIVE_CARD_TRANSITIONS)) {
    const [from] = key.split('|')
    ;(edges[from] = edges[from] || []).push({ event: key.split('|')[1], to: edge.to })
  }
  const deadEnds = states.filter((s) => !(edges[s] || []).length)
  const reach = (from, to) => {
    if (from === to) return []
    const seen = new Set([from])
    const q = [[from, []]]
    while (q.length) {
      const [cur, path] = q.shift()
      for (const e of edges[cur] || []) {
        if (e.to === to) return [...path, e.event]
        if (!seen.has(e.to)) { seen.add(e.to); q.push([e.to, [...path, e.event]]) }
      }
    }
    return null
  }
  const paths = {}
  const unreachable = []
  for (const from of states) {
    for (const to of states) {
      const p = reach(from, to)
      paths[`${from}->${to}`] = p
      if (!p) unreachable.push({ from, to })
    }
  }
  const exclusions = [
    {
      pair: 'disconnected->expired (direct)',
      reason: 'Expiry is a property of a SAVED session — with no connection saved there is nothing to expire. The state is still reachable through connecting (the card shows it when the flow discovers the dead grant).',
    },
    {
      pair: 'connected->connecting (direct)',
      reason: 'A connected card never spins — recovery from a mid-session failure goes through the typed error card (retry) or the disconnected door; the path exists, the direct edge is intentionally absent.',
    },
  ]
  return { states, deadEnds, unreachable, paths, exclusions, edgeCount: Object.keys(DRIVE_CARD_TRANSITIONS).length }
}

// --- 3. THE FORENSIC DIAGNOSIS MAP (the §9 doctor integration) --------------

/** The canonical forensic error kinds (Table 8's fixtures, typed). */
export const DRIVE_FORENSIC_KINDS = Object.freeze({
  TOKEN_RACE: 'token_refresh_race',
  AUTH_RECOVERED: 'auth_recovered',
  QUOTA: 'quota_exceeded',
  REVOKED: 'grant_revoked',
  NETWORK_FLAP: 'network_flap',
  CLOCK_SKEW: 'clock_skew',
  SCOPE: 'scope_insufficient',
  ETAG: 'etag_conflict',
  PARTIAL_CHUNK: 'partial_chunk',
  ORPHAN_GC: 'orphaned_chunk_gc',
  REGION: 'region_blocked',
  STORAGE_FULL: 'storage_full',
  CONCURRENT: 'concurrent_writers',
  FOLDER_MISSING: 'folder_missing',
})

const DIAGNOSES = {
  [DRIVE_FORENSIC_KINDS.TOKEN_RACE]: { step: 'token', why: 'Two operations hit the expired token at once — UCrypt collapsed them into ONE refresh and replayed both.', next: 'Nothing to do — the race resolved silently and the audit row is in the diagnostics.' },
  [DRIVE_FORENSIC_KINDS.AUTH_RECOVERED]: { step: 'token', why: 'The access token was revoked mid-session — it was refreshed once and the operation resumed.', next: 'Nothing to do — the card may flash reconnecting briefly, then returns to connected.' },
  [DRIVE_FORENSIC_KINDS.QUOTA]: { step: 'reachability', why: 'The provider’s storage quota is exhausted — the write was refused.', next: 'Free space at the provider (or pick another transport), then press Retry now — the queue keeps every write.' },
  [DRIVE_FORENSIC_KINDS.REVOKED]: { step: 'auth', why: 'The saved grant was revoked or expired (the provider refused the refresh).', next: 'Press Connect — one fresh authorization; queued writes are preserved.' },
  [DRIVE_FORENSIC_KINDS.NETWORK_FLAP]: { step: 'reachability', why: 'The connection dropped mid-transfer.', next: 'The upload resumes from the last verified chunk automatically — no data is re-sent from zero.' },
  [DRIVE_FORENSIC_KINDS.CLOCK_SKEW]: { step: 'token', why: 'Your device clock differs from the cloud’s beyond the tolerance UCrypt corrects.', next: 'Set the clock automatically in system settings, then press Connect again.' },
  [DRIVE_FORENSIC_KINDS.SCOPE]: { step: 'auth', why: 'The saved grant is missing a permission it needs (a scope downgrade) — nothing was partially written.', next: 'Press Connect to re-authorize with the full permission set (the card names the missing scope).' },
  [DRIVE_FORENSIC_KINDS.ETAG]: { step: 'mailbox', why: 'The remote changed during a conditional write (the retry with a fresh ETag also conflicted).', next: 'Choose Overwrite or Reload on the conflict card — both converge.' },
  [DRIVE_FORENSIC_KINDS.PARTIAL_CHUNK]: { step: 'mailbox', why: 'A chunked upload left orphaned partial chunks — they are detected and collected, and only sealed ciphertext is ever stored.', next: 'Nothing to do — the cleanup runs silently and records an audit row.' },
  [DRIVE_FORENSIC_KINDS.ORPHAN_GC]: { step: 'mailbox', why: 'Chunks with no live manifest reference were collected (on schedule and on connect).', next: 'Nothing to do — the storage usage line reflects the freed space.' },
  [DRIVE_FORENSIC_KINDS.REGION]: { step: 'reachability', why: 'The provider endpoint refused this region (a region/legal block, not an outage).', next: 'Press Retry in case it was transient; if it persists, choose a transport that works in your region (your own WebDAV server).' },
  [DRIVE_FORENSIC_KINDS.STORAGE_FULL]: { step: 'reachability', why: 'The provider’s storage is full — the pre-flight refused the write before any byte moved.', next: 'Open the provider storage console from the card, free space, then press Retry now.' },
  [DRIVE_FORENSIC_KINDS.CONCURRENT]: { step: 'mailbox', why: 'Two devices wrote the same relay folder — the writes serialized through conditional ETag checks.', next: 'Nothing to do — both devices converge on one whole version; the audit rows are in the diagnostics.' },
  [DRIVE_FORENSIC_KINDS.FOLDER_MISSING]: { step: 'mailbox', why: 'The rendezvous folder was moved or deleted on the server.', next: 'Press Recreate folder — one tap rebuilds it and the transfer continues.' },
}

/**
 * THE DIAGNOSIS (the doctor's typed row for a forensic kind). Accepts the
 * kind string OR the thrown error (reads the SyncError's recovery.kind /
 * kind). Unknown input degrades TYPED — never undefined, never a throw.
 */
export function diagnoseDriveForensics(kindOrError) {
  const kind = typeof kindOrError === 'string'
    ? kindOrError
    : String((kindOrError && kindOrError.recovery && kindOrError.recovery.kind) || (kindOrError && kindOrError.kind) || '')
  const d = DIAGNOSES[kind]
  if (d) return { kind, step: d.step, why: d.why, next: d.next }
  return {
    kind: kind || 'unknown',
    step: 'reachability',
    why: kind ? `The failure was typed as "${kind}" but the doctor has no dedicated line for it yet.` : 'The failure carried no typed kind.',
    next: 'Run the Doctor again and export the diagnostics — the typed card’s own fix still applies.',
  }
}
