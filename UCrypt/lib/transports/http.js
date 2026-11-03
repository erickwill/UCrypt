/**
 * UCrypt Transport HTTP hardening (v2.3.0).
 *
 * Closes the biggest open gap from the v2.2.0 audit follow-up: every network
 * request a transport makes now has (a) a hard deadline, (b) bounded retry
 * with exponential backoff for TRANSIENT failures only, and (c) a classified,
 * user-actionable error type instead of raw fetch strings.
 *
 * Exports:
 *   SyncError               — Error subclass with .kind + .status + .userMessage
 *   fetchWithTimeout        — AbortController deadline around fetch
 *   fetchWithRetry          — deadline + exponential backoff (jittered)
 *   classifySyncError       — map any thrown value to a SyncError
 *   looksLikeVaultEnvelope  — cheap structural pre-check for downloaded blobs
 *
 * Design notes:
 *   - Retries fire ONLY on network errors, timeouts, and status 408/429/5xx.
 *     Auth failures (401/403), 404s, and 4xx config errors are terminal —
 *     retrying them would just hammer the server.
 *   - Backoff is exponential with EQUAL jitter (v2.20.0 R29-F2): the delay
 *     is drawn from [cap/2, cap) — a guaranteed floor, spread preserved.
 *   - Every transport opts in per call: uploads usually want 2 retries,
 *     downloads 1 (the vault pull already collects multiple candidates).
 */

import { recordRing } from '../egrings.js'

export const DEFAULT_TIMEOUT_MS = 15000
export const DEFAULT_RETRIES = 2
export const BASE_BACKOFF_MS = 500
export const MAX_BACKOFF_MS = 4000

const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504])

/** Error kinds — a small, stable taxonomy the UI can localise. */
export const SYNC_ERROR_KINDS = {
  NETWORK: 'network',     // DNS, refused, offline, CORS-ish failures
  TIMEOUT: 'timeout',     // our own deadline fired
  AUTH: 'auth',           // 401/403 — bad token or credentials
  NOT_FOUND: 'not_found', // 404/409-as-missing — usually "no vault yet"
  SERVER: 'server',       // 5xx — the remote is having a bad day
  RATE_LIMIT: 'rate_limit', // 429
  CONFIG: 'config',       // missing/malformed user configuration
  PROTOCOL: 'protocol',   // response is not what the transport expects
  // R137 §9 (the G72 extension — the Drive forensic battery): provider
  // storage exhaustion is its OWN kind — a 403 whose body names the quota
  // must never render as "wrong credentials" (the card names the quota and
  // links the provider's storage management instead).
  QUOTA: 'quota',         // the provider's storage is full (pre-flight or 403 body)
}

export class SyncError extends Error {
  /**
   * @param {string} kind   one of SYNC_ERROR_KINDS
   * @param {string} message  technical detail (goes to the console)
   * @param {{status?:number, cause?:unknown, userMessage?:string}} [meta]
   */
  constructor(kind, message, meta = {}) {
    super(message)
    this.name = 'SyncError'
    this.kind = kind
    this.status = meta.status
    this.cause = meta.cause
    this.userMessage = meta.userMessage || defaultUserMessage(kind, meta.status)
    // R115 (the audit's finding — a P1 wire defect): the typed recovery card
    // rode into the constructor's meta and was DROPPED — the worker handler
    // reads e.recovery, so every card (redirect_uri_mismatch, invalid_grant,
    // client_secret_missing, …) arrived at the UI as null and the surfaces
    // rendered only the one-line title. The card rides again: the R87 §2.1c
    // law (Google's failures become an actionable card) is live on the wire.
    this.recovery = meta.recovery || null
  }
}

function defaultUserMessage(kind, status) {
  switch (kind) {
    case SYNC_ERROR_KINDS.NETWORK:
      return 'Could not reach the server — check your connection and the URL.'
    case SYNC_ERROR_KINDS.TIMEOUT:
      return 'The server took too long to answer (15s limit).'
    case SYNC_ERROR_KINDS.AUTH:
      return `Authentication failed (${status || '401/403'}) — the token or password is wrong or expired.`
    case SYNC_ERROR_KINDS.NOT_FOUND:
      return 'Nothing stored there yet (this is normal for a first device).'
    case SYNC_ERROR_KINDS.SERVER:
      return `The server reported an outage (${status || '5xx'}) — try again later.`
    case SYNC_ERROR_KINDS.RATE_LIMIT:
      return 'The server is rate-limiting requests — wait a minute and retry.'
    case SYNC_ERROR_KINDS.CONFIG:
      return 'This transport is not configured correctly — open the sync settings.'
    case SYNC_ERROR_KINDS.PROTOCOL:
      return 'The server answered with something UCrypt did not expect.'
    default:
      return 'Sync failed for an unknown reason.'
  }
}

/**
 * Map an HTTP status to an error kind.
 * v2.17.0 — R26-F5: the same status means different things per operation.
 * A 409 on DOWNLOAD is the standard "missing blob" answer (Dropbox's
 * path/not_not_found…) — nothing stored yet, normal for a first device. The
 * same 409 on UPLOAD means the remote EXISTS and disagrees with us — telling
 * the user "this is normal for a first device" would be a lie. Callers pass
 * { op: 'upload' | 'download' } so the message is always truthful.
 */
export function kindForStatus(status, { op = '' } = {}) {
  if (status === 401 || status === 403) return SYNC_ERROR_KINDS.AUTH
  if (status === 404) return SYNC_ERROR_KINDS.NOT_FOUND
  if (status === 409) return op === 'upload' ? SYNC_ERROR_KINDS.PROTOCOL : SYNC_ERROR_KINDS.NOT_FOUND
  if (status === 410) return SYNC_ERROR_KINDS.NOT_FOUND
  if (status === 429) return SYNC_ERROR_KINDS.RATE_LIMIT
  // R137 §9 (G72 extension — F11): HTTP 451 is a REGION/LEGAL block — a
  // network-availability refusal, NOT a user-configuration error. Mapping it
  // to CONFIG used to tell a region-blocked user to "open the sync
  // settings" — a dead end. The typed card (set in statusToSyncError)
  // distinguishes the region block from an outage.
  if (status === 451) return SYNC_ERROR_KINDS.NETWORK
  if (status >= 500) return SYNC_ERROR_KINDS.SERVER
  if (status >= 400) return SYNC_ERROR_KINDS.CONFIG
  return SYNC_ERROR_KINDS.PROTOCOL
}

/**
 * v2.19.0 — R28-F10: join the buffered stream chunks into one Uint8Array
 * for the bounded error-body prefix read.
 */
function concatChunks(chunks, total) {
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

/**
 * v2.17.0 — R26-F5: build a SyncError from a non-ok Response, with the
 * operation context, a capped body snippet (R25 kept the service's error
 * text only on the terminal branch — the final retry lost it) and GitHub
 * style rate-limit detection (403 + X-RateLimit-Remaining: 0 is NOT an auth
 * failure — it is a quota, and X-RateLimit-Reset says when it lifts).
 */
async function statusToSyncError(res, context, op, bodyOverride = null) {
  let kind = kindForStatus(res.status, { op })
  let userMessage = defaultUserMessage(kind, res.status)
  let recovery = null
  if (res.status === 403) {
    const remaining = res.headers?.get?.('x-ratelimit-remaining')
    const reset = Number(res.headers?.get?.('x-ratelimit-reset'))
    if (remaining === '0') {
      kind = SYNC_ERROR_KINDS.RATE_LIMIT
      const when = reset > 0 ? new Date(reset * 1000).toLocaleTimeString() : ''
      userMessage = 'The service rate-limited this token' +
        (when ? ` — the quota resets at ${when}.` : ' — wait a while before retrying.')
    }
  }
  // R137 §9 (G72 extension — F11): the REGION-BLOCK typed card. HTTP 451
  // means the endpoint refused for region/legal reasons — a DIFFERENT
  // failure than an outage (5xx). The card names the region block and
  // offers the retry; the outage family keeps its own wording, so the two
  // never render as the same failure.
  if (res.status === 451) {
    kind = SYNC_ERROR_KINDS.NETWORK
    userMessage = 'The endpoint refused this request for your region (a legal/region block, not an outage) — retry in case it was transient; if it persists, the provider restricts this region.'
    recovery = {
      kind: 'region_blocked',
      title: 'The cloud endpoint is blocked in your region (HTTP 451).',
      causes: [
        'The provider refuses requests from this region by policy (HTTP 451 — Unavailable For Legal Reasons).',
        'An interim network path (proxy/VPN/DNS filter) answered with the block.',
      ],
      fix: 'Press Retry in case the block was transient. If it persists, the provider restricts this region — choose a different cloud transport (WebDAV on your own server always works).',
      retryLabel: 'Retry',
    }
  }
  let snippet = ''
  try {
    // v2.19.0 — R28-F10 (audit): res.text() buffered the WHOLE error body
    // (a misbehaving endpoint can stream megabytes) only to slice 200
    // chars. Read at most a 4 KB prefix when the stream is available.
    let body = ''
    if (bodyOverride != null) {
      // R137 §9: a caller that already read a bounded prefix (to type the
      // failure precisely) passes it through — the body is never consumed
      // twice and the generic wording keeps its snippet.
      body = String(bodyOverride)
    } else if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader()
      try {
        const chunks = []
        let received = 0
        while (received < 4096) {
          const { done, value } = await reader.read()
          if (done) break
          chunks.push(value)
          received += value.length
        }
        body = new TextDecoder().decode(concatChunks(chunks, received))
        if (received >= 4096) try { await reader.cancel() } catch { /* stream already done */ }
      } catch { /* stream failed — fall back to text() */ }
    }
    if (!body) body = (await res.text()) || ''
    snippet = body.slice(0, 200).replace(/[\u0000-\u001f]+/g, ' ').trim()
  } catch { /* body unreadable — status only */ }
  return new SyncError(kind, `${context} failed: ${res.status}${snippet ? ` — ${snippet}` : ''}`, {
    status: res.status,
    userMessage: userMessage + (snippet ? ` (server said: ${snippet})` : ''),
    recovery,
  })
}

/**
 * R137 §9 (the G72 extension): the terminal-error builder, EXPORTED —
 * transports that intercept a response to type it more precisely (the Drive
 * legs type quota/scope from the body's own reason words) reuse the SAME
 * builder for the generic fall-through, so the wording never drifts and the
 * 451/403-snippet behavior stays identical everywhere.
 */
export function responseToSyncError(res, context, op = '', bodyOverride = null) {
  return statusToSyncError(res, context, op, bodyOverride)
}

/**
 * Wrap any thrown value into a SyncError (idempotent).
 * Detects AbortError from our deadline and re-maps to TIMEOUT.
 */
export function classifySyncError(err, { context = '' } = {}) {
  if (err instanceof SyncError) return err
  const msg = String((err && err.message) || err)
  const isAbort =
    (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) ||
    /aborted/i.test(msg)
  const prefix = context ? `${context}: ` : ''
  if (isAbort) {
    return new SyncError(SYNC_ERROR_KINDS.TIMEOUT, `${prefix}request aborted by the ${DEFAULT_TIMEOUT_MS / 1000}s deadline`, { cause: err })
  }
  // v2.16.0 — the old code had two IDENTICAL returns here (a TypeError
  // branch and a fall-through), both producing the same NETWORK error; both
  // network-shaped failures classify identically (pre-connection, there is
  // nothing else to distinguish).
  return new SyncError(SYNC_ERROR_KINDS.NETWORK, `${prefix}${msg}`, { cause: err })
}

/**
 * fetch + AbortController deadline. Resolves as usual, rejects with a
 * SyncError(kind=TIMEOUT) when the deadline fires.
 */
export async function fetchWithTimeout(url, opts = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(new DOMException('deadline', 'TimeoutError')), timeoutMs)
  // v2.17.0 — R26-F10: a caller-supplied signal used to be OVERWRITTEN (the
  // deadline controller won), so a mid-flight abort by the caller never
  // cancelled the request. Merge both signals so EITHER can cancel.
  let signal = ctrl.signal
  if (opts.signal) {
    signal = typeof AbortSignal.any === 'function'
      ? AbortSignal.any([ctrl.signal, opts.signal])
      : ctrl.signal
  }
  const merged = { ...opts, signal }
  try {
    const fetchFn = typeof globalThis.__ucryptFetchOverride === 'function'
      ? globalThis.__ucryptFetchOverride
      : fetch
    return await fetchFn(url, merged)
  } catch (err) {
    // Distinguish "our deadline" from "caller passed their own signal"
    if (opts.signal?.aborted) throw err // caller aborted — theirs, not ours
    throw classifySyncError(err, { context: opts.method || 'GET' })
  } finally {
    clearTimeout(timer)
  }
}

/**
 * v2.18.0 — R27-F4 (audit): a caller abort must also cut the BACKOFF sleep
 * short — waiting out up to 4s after the caller gave up is a leaked timer at
 * best. Rejects with the caller's own AbortError so no retry ever fires.
 * (Replaced the plain, un-abortable sleep.)
 */
const abortableSleep = (ms, signal) => new Promise((resolve, reject) => {
  if (!signal) return setTimeout(resolve, ms)
  if (signal.aborted) return reject(signal.reason || new DOMException('The caller aborted this request', 'AbortError'))
  const timer = setTimeout(resolve, ms)
  signal.addEventListener('abort', () => {
    clearTimeout(timer)
    reject(signal.reason || new DOMException('The caller aborted this request', 'AbortError'))
  }, { once: true })
})

/**
 * fetch with a hard deadline + bounded exponential-backoff retries.
 *
 * @param {string} url
 * @param {RequestInit} opts
 * @param {{timeoutMs?:number, retries?:number, context?:string}} [cfg]
 * @returns Promise<Response> — the FINAL response (caller still checks .ok)
 */
export async function fetchWithRetry(url, opts = {}, cfg = {}) {
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const retries = cfg.retries ?? DEFAULT_RETRIES
  const context = cfg.context || opts.method || 'GET'
  const op = cfg.op || '' // v2.17.0 — R26-F5: 'upload' | 'download' for truthful 409 semantics
  // R85 (F-R84-XFER-1): caller-declared OK statuses. A response whose status
  // is in this set is returned RESPONSE-SHAPED even though res.ok is false —
  // scoped strictly to callers that know the status is a valid terminal
  // outcome of THEIR method (rendezvous MKCOL: 201 created / 204 ok / 405
  // exists). This is the same discipline the 412 CAS signal already had via
  // the rendezvous adapter's response-shaping; with the set in place the
  // adapter's tolerance branches execute as designed instead of being dead
  // code behind a terminal throw.
  const okStatuses = Array.isArray(cfg.okStatuses) && cfg.okStatuses.length
    ? new Set(cfg.okStatuses)
    : null

  // R115 (law 0.28) — THE EVIDENCE RING: every attempt records one typed
  // ring entry (endpoint class, outcome, HTTP kind, status, elapsed, retry
  // tier, the typed error). `cfg.ring` = { flow, transport, stage } lets the
  // connect flows label their HTTP legs; absent, the flow falls back to
  // 'http' and the endpoint class IS the context string (sanitized by the
  // ring module — credential-bearing query values never survive).
  const ring = cfg.ring && typeof cfg.ring === 'object' ? cfg.ring : null
  const ringTransport = String((ring && ring.transport) || context).slice(0, 24)
  const recordAttempt = async (attempt, { ok, status, errKind, errMsg, startedAt }) => {
    try {
      await recordRing({
        flow: (ring && ring.flow) || 'http',
        transport: ringTransport,
        stage: (ring && ring.stage) || 'request',
        outcome: ok ? 'ok' : 'fail',
        httpKind: String(opts.method || 'GET'),
        status: Number.isFinite(status) ? status : null,
        elapsedMs: startedAt ? Date.now() - startedAt : null,
        retryTier: attempt,
        error: errKind || '',
        message: errMsg || '',
      })
    } catch { /* the ring never perturbs the flight it observes */ }
  }

  let lastErr = null
  let nextDelayMs = null // v2.16.0 — Retry-After override for the next sleep
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) {
      // v2.18.0 — R27-F4: a caller abort kills the backoff immediately and
      // propagates THEIR abort — it is never classified as a retryable
      // timeout and never burns another attempt.
      if (opts.signal?.aborted) throw opts.signal.reason || new DOMException('The caller aborted this request', 'AbortError')
      const cap = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** (attempt - 1))
      // v2.20.0 — R29-F2 (audit): FULL jitter (random(0, cap)) could pick a
      // delay of 0 ms — the "retry" hit the just-failed endpoint instantly and
      // the exponential character of the backoff vanished entirely (and a
      // timing-sensitive harness occasionally observed a sub-bound wait).
      // EQUAL jitter guarantees a real floor: delay ∈ [cap/2, cap). The
      // thundering-herd protection stays (attempts still spread across a
      // 2× window); a retry can never again fire before half the step.
      const delay = nextDelayMs ?? (Math.floor(cap / 2) + Math.floor(Math.random() * Math.ceil(cap / 2)))
      nextDelayMs = null
      await abortableSleep(delay, opts.signal)
    }
    let res
    const attemptStarted = Date.now()
    try {
      res = await fetchWithTimeout(url, opts, timeoutMs)
    } catch (err) {
      // v2.18.0 — R27-F4: a caller-supplied abort is theirs, not ours —
      // rethrow verbatim (never classified, never retried).
      if (opts.signal?.aborted) throw err
      lastErr = classifySyncError(err, { context })
      await recordAttempt(attempt, { ok: false, errKind: lastErr.kind, errMsg: lastErr.message, startedAt: attemptStarted })
      // Only network/timeout errors retry here — a SyncError of any other
      // kind cannot exist pre-response, but be defensive anyway.
      if (lastErr.kind !== SYNC_ERROR_KINDS.NETWORK && lastErr.kind !== SYNC_ERROR_KINDS.TIMEOUT) throw lastErr
      continue
    }
    // R85 (F-R84-XFER-1): caller-declared OK statuses return the response
    // itself (never thrown) — the caller owns the semantic interpretation.
    if (res.ok || (okStatuses && okStatuses.has(res.status))) {
      // R115 — the ring records the HTTP truth: a caller-declared okStatus
      // (e.g. a token endpoint's 400 whose JSON body the caller must read for
      // the typed card) is RESPONSE-SHAPED for the caller, but the ring still
      // records outcome:'fail' with the status — the evidence ring shows what
      // the wire did, never what the caller did with it.
      await recordAttempt(attempt, { ok: res.ok, status: res.status, startedAt: attemptStarted })
      return res
    }
    if (!RETRYABLE_STATUS.has(res.status)) {
      // v2.17.0 — R26-F5/F11: one builder for every terminal failure — op
      // context (truthful 409 on upload) + 403 rate-limit detection + the
      // service's own error text, now read on EVERY throw (the final retry
      // used to lose the body snippet).
      const terminal = await statusToSyncError(res, context, op)
      await recordAttempt(attempt, { ok: false, status: res.status, errKind: terminal.kind, errMsg: terminal.message, startedAt: attemptStarted })
      throw terminal
    }
    lastErr = await statusToSyncError(res, context, op)
    await recordAttempt(attempt, { ok: false, status: res.status, errKind: lastErr.kind, errMsg: lastErr.message, startedAt: attemptStarted })
    // v2.16.0 — R25: honor Retry-After (seconds or HTTP-date) on 429/503 so a
    // rate-limited endpoint is not re-hit within seconds of being told to wait.
    if (res.status === 429 || res.status === 503) {
      const ra = res.headers?.get?.('retry-after')
      if (ra) {
        const secs = Number(ra)
        const ms = Number.isFinite(secs) && String(secs).trim() === ra.trim()
          ? secs * 1000
          : (Date.parse(ra) ? Date.parse(ra) - Date.now() : NaN)
        if (Number.isFinite(ms) && ms > 0) nextDelayMs = Math.min(MAX_BACKOFF_MS, ms)
      }
    }
    // 429/5xx → loop and retry
  }
  throw lastErr || new SyncError(SYNC_ERROR_KINDS.NETWORK, `${context} failed after ${retries + 1} attempts`)
}

// --- Envelope pre-check -----------------------------------------------------

/** base64 (standard or URL-safe) character set, optionally chunked with '='. */
const BASE64ISH = /^[A-Za-z0-9+/=_-]+$/

export const ENVELOPE_MIN_CHARS = 48    // even an empty vault encrypts to ~120 chars
export const ENVELOPE_MAX_CHARS = 8 * 1024 * 1024 // 8 MB of base64 is plenty

/**
 * Cheap structural check on a DOWNLOADED blob before we spend a PBKDF2 +
 * AES-GCM decryption on it. The vault blob is base64(iv ‖ ciphertext) —
 * anything that isn't a plausible base64 string of sane length is garbage
 * (an HTML error page, a JSON error body, an empty file…).
 *
 * NOTE: this is a pre-filter, NOT an integrity check — authenticity is
 * enforced by the GCM tag during decryption.
 */
export function looksLikeVaultEnvelope(blob) {
  if (typeof blob !== 'string') return false
  const trimmed = blob.trim()
  if (trimmed.length < ENVELOPE_MIN_CHARS) return false
  if (trimmed.length > ENVELOPE_MAX_CHARS) return false
  if (!BASE64ISH.test(trimmed)) return false
  // Standard base64 length must be a multiple of 4; tolerate URL-safe and
  // whitespace-stripped variants that are not.
  if (/[+/]/.test(trimmed) && trimmed.length % 4 !== 0) return false
  return true
}
