/**
 * ════════════════════════════════════════════════════════════════════════
 * R165 ARC A — THE HONEST PENDING (the cure for H-16, the SILENT PENDING).
 *
 * The field caught it (E-11): a button that promises and never speaks —
 * "Connecting…" forever, because SOME failure lands in an await that never
 * settles. The law this module enforces (R-165.2):
 *
 *   An honest interface is never silent. Every await in a user-facing flow
 *   has a BOUNDED outcome — complete, or fail with a NAMED verdict.
 *   "Connecting…" without a verdict is a lie by omission.
 *
 * Three instruments, pure by construction (the battery drives them without
 * a browser — the clock and the chrome seam are injected):
 *
 *   1. withHonestPending(label, fn, opts) — wraps ANY user-facing promise:
 *        • before  tickMs (5 s)  the UI hears onTick(elapsed, label) — a
 *          visible state change, never silence;
 *        • after  timeoutMs (60 s) the pending is ABANDONED with the typed
 *          PENDING_TIMEOUT verdict — the button speaks or completes, never
 *          spins;
 *        • the wrapped promise's OWN settle always wins the race (a fast
 *          success or a typed failure is never preempted);
 *        • cleanup: every timer is cleared on settle (no stale timers — 0.33).
 *
 *   2. boundedIdentityCall(chromeLike, method, requestInfo, opts) — the
 *      chrome.identity.* callback wrapper that CANNOT hang: the callback
 *      is raced against a timeout, so the deepest S-1 shape (a callback
 *      that never fires) still produces a named verdict
 *      ('identity-callback-timeout') with chrome.runtime.lastError carried
 *      VERBATIM when it exists (the raw service text is the fingerprint
 *      that names the domain — never swallowed, never prettified).
 *
 *   3. PENDING_VERDICTS — the typed verdict table (kind → the honest
 *      sentence + the domain). Domains: CODEBASE (our bug), CONSOLE (the
 *      Google-side binding), CONSENT (the user's own action), TIMEOUT (the
 *      bounded pending fired — the flow was abandoned, nothing was written).
 * ════════════════════════════════════════════════════════════════════════
 */

/** The typed verdict kinds (H-16's alphabet — every shape a NAME).
 * R166 — the alphabet grows ADDITIVELY for the second machinery (the
 * web-auth fallback): the fallback window's cancel and its own bound. */
export const PENDING_VERDICTS = Object.freeze({
  OK: 'ok',
  PENDING_TIMEOUT: 'pending-timeout',           // the 60 s verdict (Arc A)
  IDENTITY_CALLBACK_TIMEOUT: 'identity-callback-timeout', // the never-calling callback (S-1's deepest form)
  LAST_ERROR: 'last-error',                     // the service spoke — its words ride verbatim
  NO_TOKEN: 'no-token',                         // the callback fired with an empty token
  THROWN: 'thrown',                             // the flow threw its own typed error
  WEB_AUTH_CANCELED: 'web-auth-canceled',       // the fallback window closed / consent refused (R166)
  WEB_AUTH_TIMEOUT: 'web-auth-timeout',         // the fallback window outlived its bound (R166)
})

const DEFAULT_TICK_MS = 5000
const DEFAULT_TIMEOUT_MS = 60000

/**
 * The honest-pending wrapper (Arc A's spine).
 *
 * @param {string} label  the honest step name ("Connecting", "Signing in"…)
 * @param {() => Promise<T>} fn  the flow — its own settle ALWAYS wins
 * @param {{tickMs?: number, timeoutMs?: number, onTick?: (elapsedMs: number, label: string) => void,
 *          now?: () => number, setTimer?: (fn: () => void, ms: number) => any, clearTimer?: (t: any) => void}} [opts]
 * @returns {Promise<{ok: true, value: T} | {ok: false, verdict: string, kind: string, raw: string, elapsedMs: number}>}
 *   NEVER throws for the bounded shapes — the caller renders the verdict.
 *   fn's own throw rides out typed (verdict THROWN, raw = its message).
 */
export async function withHonestPending(label, fn, opts = {}) {
  const tickMs = Math.max(0, Number(opts.tickMs ?? DEFAULT_TICK_MS))
  const timeoutMs = Math.max(1, Number(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS))
  const now = opts.now || (() => Date.now())
  const setTimer = opts.setTimer || ((f, ms) => setTimeout(f, ms))
  const clearTimer = opts.clearTimer || ((t) => { try { clearTimeout(t) } catch { /* the clock never throws */ } })
  const t0 = now()
  let pending = true
  const timers = []
  const tick = opts.onTick || null
  if (tick && tickMs > 0) {
    let fired = 0
    const step = () => {
      if (!pending) return
      fired += 1
      try { tick(tickMs * fired, label) } catch { /* the tick never throws into the flow */ }
      // re-arm ABSOLUTE: the next tick lands on the uniform tickMs*(fired+1)
      // boundary of the clock (never drifting by the handler's own latency)
      timers.push(setTimer(step, Math.max(1, tickMs * (fired + 1) - now())))
    }
    timers.push(setTimer(step, tickMs))
  }
  let timeoutHandle = null
  const timeoutPromise = new Promise((resolve) => {
    timeoutHandle = setTimer(() => {
      if (!pending) return
      resolve({
        ok: false,
        verdict: PENDING_VERDICTS.PENDING_TIMEOUT,
        kind: 'pending-timeout',
        raw: '',
        elapsedMs: now() - t0,
      })
    }, timeoutMs)
  })
  const work = (async () => {
    const value = await fn()
    return { ok: true, value, elapsedMs: now() - t0 }
  })()
  const guard = work.then(
    (r) => ({ ok: true, verdict: PENDING_VERDICTS.OK, value: r.value, elapsedMs: r.elapsedMs }),
    (e) => ({
      ok: false,
      verdict: PENDING_VERDICTS.THROWN,
      kind: String((e && e.kind) || (e && e.probeKind) || 'flow-error'),
      raw: String((e && ((e.userMessage && e.message) ? e.message : (e.message || e)))) || '',
      userMessage: String((e && e.userMessage) || ''),
      elapsedMs: now() - t0,
    }),
  )
  const result = await Promise.race([guard, timeoutPromise])
  pending = false
  clearTimer(timeoutHandle)
  for (const t of timers) clearTimer(t)
  return result
}

/**
 * The bounded chrome.identity.* call — the callback wrapper that CANNOT
 * hang (S-1's deepest form: a callback that never fires still settles with
 * a named verdict). chrome.runtime.lastError is surfaced VERBATIM (raw).
 *
 * @param {object|null} chromeLike  the chrome seam (the battery injects fakes)
 * @param {'getAuthToken'|'clearAllCachedAuthTokens'} method
 * @param {object} [requestInfo]  { interactive: true|false } (getAuthToken)
 * @param {{timeoutMs?: number, now?: () => number, setTimer?: Function, clearTimer?: Function}} [opts]
 * @returns {Promise<{ok: true, token: string} | {ok: true, cleared: true} |
 *                    {ok: false, verdict: string, kind: string, raw: string}>}
 */
export function boundedIdentityCall(chromeLike, method, requestInfo = {}, opts = {}) {
  const timeoutMs = Math.max(1, Number(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS))
  const setTimer = opts.setTimer || ((f, ms) => setTimeout(f, ms))
  const clearTimer = opts.clearTimer || ((t) => { try { clearTimeout(t) } catch { /* the clock never throws */ } })
  return new Promise((resolve) => {
    if (!chromeLike || !chromeLike.identity || typeof chromeLike.identity[method] !== 'function') {
      resolve({ ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'identity-unavailable', raw: `chrome.identity.${method} is not available on this browser` })
      return
    }
    let settled = false
    const finish = (r) => {
      if (settled) return
      settled = true
      clearTimer(timer)
      resolve(r)
    }
    const timer = setTimer(() => {
      finish({ ok: false, verdict: PENDING_VERDICTS.IDENTITY_CALLBACK_TIMEOUT, kind: 'identity-callback-timeout', raw: `chrome.identity.${method} never called back within ${timeoutMs} ms — the sign-in was abandoned with no state written` })
    }, timeoutMs)
    try {
      const cb = (token) => {
        let err = null
        try { err = chromeLike.runtime && chromeLike.runtime.lastError } catch { err = null }
        if (method === 'clearAllCachedAuthTokens') {
          finish(err
            ? { ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'clear-failed', raw: String((err && err.message) || err) }
            : { ok: true, cleared: true })
          return
        }
        if (err) {
          finish({ ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'last-error', raw: String((err && err.message) || err) })
        } else if (!token) {
          finish({ ok: false, verdict: PENDING_VERDICTS.NO_TOKEN, kind: 'empty-token', raw: 'the sign-in callback arrived with no token and no error text' })
        } else {
          finish({ ok: true, token: String(token) })
        }
      }
      if (method === 'clearAllCachedAuthTokens') chromeLike.identity[method](cb)
      else chromeLike.identity[method](requestInfo || {}, cb)
    } catch (e) {
      finish({ ok: false, verdict: PENDING_VERDICTS.LAST_ERROR, kind: 'identity-threw', raw: String((e && e.message) || e) })
    }
  })
}

/**
 * R167 — THE EMBEDDED-ERROR DECODER (the E-13 field cure, part 1).
 *
 * The field spoke (the owner's live verdict, E-13): Google's error page rode
 * the authorization window and the raw carried the error name BASE64-ENCODED
 * (the page's protobuf request-details blob —
 * "ChVyZWRpcmVjdF91cmlfbWlzbWF0Y2gg..." decodes to "redirect_uri_mismatch").
 * The classifier only saw the ciphertext and fell to the CODEBASE fallback —
 * a CONSOLE-class shape was sold as UCrypt's own bug. THE CURE: every
 * base64/base64url token (≥16 chars) in the raw is decoded and its
 * printable-ASCII run rides the match corpus, so a named error classifies
 * by ITS NAME in ANY encoding. Pure, exported for the battery.
 * @param {string} raw  the verbatim failure text (may carry base64 blobs)
 * @returns {string} the raw + every decoded blob's printable text (LF-joined)
 */
export function decodeEmbeddedErrorText(raw) {
  const source = String(raw || '')
  const out = [source]
  const tokens = source.match(/[A-Za-z0-9+/=_-]{16,}/g) || []
  for (const tok of tokens) {
    // R168 — THE '=' POISON CURE (the field spoke a SECOND time): a URL
    // query glues its key to the blob (authError=<blob>) and '=' rides the
    // token class, so the naive atob(token) dies on the mid-string '=' and
    // the error name never decodes — the R168 field event carried the FULL
    // error URL (not the bare E-13 blob) and the CODEBASE fallback returned.
    // THE CURE: the candidates now include every '='-delimited segment of
    // the token, so the blob after the key still decodes. Segment
    // candidates ride only when the printable text is ERROR-NAMED
    // (snake_case) — random gibberish can never impersonate a plain word
    // and flip the domain. The bare-blob path is byte-identical to R167.
    const candidates = [tok]
    if (tok.includes('=')) {
      for (const seg of tok.split('=')) {
        if (seg.length >= 16) candidates.push(seg)
      }
    }
    for (const cand of candidates) {
      // base64url → base64 (the URL-safe alphabet never throws in atob)
      const b64 = cand.replace(/-/g, '+').replace(/_/g, '/')
      const padded = b64 + (b64.length % 4 ? '===='.slice(b64.length % 4) : '')
      try {
        const bin = atob(padded)
        let text = ''
        for (const ch of bin) {
          const c = ch.charCodeAt(0)
          text += (c >= 32 && c < 127) ? ch : ' '
        }
        const isSegment = cand !== tok
        const named = isSegment
          ? /[a-z]{3,}(?:_[a-z0-9]+)+/.test(text) // an error NAME (snake_case) — never a bare word
          : /[A-Za-z_]{6,}/.test(text) // a decoded blob rides when it names something
        if (named) {
          out.push(text)
          break
        }
      } catch { /* not base64 — the next candidate speaks */ }
    }
  }
  return out.join('\n')
}

/**
 * The domain mapper (the verdict ladder's honesty): a raw failure text maps
 * to exactly ONE domain — CODEBASE (our bug, with the row name), CONSOLE
 * (the Google-side binding/scope/API, with the exact fix pointer), CONSENT
 * (the user's own action, with the how-to). Pure, exported for the battery.
 * R167: the raw is PRE-DECODED (decodeEmbeddedErrorText) so Google's
 * base64-encoded error names classify by their name (the E-13 cure).
 * @param {{verdict: string, kind: string, raw: string}} failure
 * @returns {{domain: 'CODEBASE'|'CONSOLE'|'CONSENT'|'TIMEOUT', fix: string}}
 */
export function failureDomain(failure) {
  const raw = decodeEmbeddedErrorText((failure && failure.raw) || '')
  const kind = String((failure && failure.kind) || '')
  const verdict = String((failure && failure.verdict) || '')
  if (verdict === PENDING_VERDICTS.PENDING_TIMEOUT || verdict === PENDING_VERDICTS.IDENTITY_CALLBACK_TIMEOUT || verdict === PENDING_VERDICTS.WEB_AUTH_TIMEOUT || kind === 'web-auth-timeout') {
    return { domain: 'TIMEOUT', fix: 'The flow was abandoned by the bounded pending — nothing was written. R168 — the honest still-open note: if Google\u2019s window is still open, close it after reading (nothing was exchanged), then press the button once to retry; if it repeats, copy the connection receipt for support.' }
  }
  if (verdict === PENDING_VERDICTS.WEB_AUTH_CANCELED || kind === 'window-closed') {
    return { domain: 'CONSENT', fix: 'The sign-in window closed before it finished (nothing was exchanged). Press the button once and finish the consent at Google\u2019s window; your own key below always works too.' }
  }
  // R171 — THE SETTLED-UNMATCHED LANE (the owner's R171 field verdict): the
  // window OPENED and closed without completing — Chrome's own words ("The
  // user did not approve access.") used to fall through every lane into
  // CODEBASE ("UCrypt's own bug") — A LIE. The shape routes CONSOLE (the
  // field-proven red page: the Item-ID cure) with the honest self-closed
  // caveat — never CODEBASE, never "failed to open".
  if (kind === 'auth-window-unmatched' || /auth_window_settled_unmatched/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The sign-in window OPENED but the sign-in did not complete before it closed \u2014 nothing was exchanged. The field-proven shape: the window showed Google\u2019s red "Access blocked \u2014 Error 400: redirect_uri_mismatch" page \u2014 the OAuth client\u2019s Item ID must equal this extension\u2019s own ID LETTER-EXACT (the ID prints on this row): Google Cloud Console \u2192 APIs & Services \u2192 Credentials \u2192 the Chrome-Extension client \u2192 Save \u2192 press Connect again. If you closed the window yourself, just press Connect again.' }
  }
  if (kind === 'state-mismatch') {
    return { domain: 'CODEBASE', fix: 'The sign-in redirect did not carry the nonce UCrypt sent — the flow was refused BEFORE anything was minted (the safety worked). This is UCrypt\u2019s own bug class — press Copy connection receipt and send it to support.' }
  }
  // R167 — the redirect lane rides ABOVE the client lane: a captured Google
  // error-page URL carries client_id= as a query param, and a URL param must
  // never decide the verdict — only a NAMED error may. The E-13 field shape
  // (redirect_uri_mismatch, base64-encoded) lands HERE, CONSOLE, with the
  // letter-exact Item-ID fix — never again the CODEBASE fallback.
  if (/redirect_uri_mismatch/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The redirect does not match — the OAuth client\u2019s Item ID must equal this extension\u2019s own ID LETTER-EXACT (the ID prints on this row). Fix in Google Cloud Console → APIs & Services → Credentials → the OAuth client (type Chrome Extension) → correct the Item ID in place if one letter is off (never recreate) → Save (a few minutes to apply) → press Connect again. The redirect itself is DERIVED by chrome.identity (https://<extension-id>.chromiumapp.org/) — it is never hand-typed. R168 — the email chip on Google\u2019s error page is that browser profile\u2019s DEFAULT sign-in, never a choice UCrypt made: the request was refused before Google ever showed the account chooser. UCrypt always asks with prompt=select_account, so once the Item ID is letter-exact the SAME window opens with Google\u2019s account chooser — blank, pick or type any account you want to test with.' }
  }
  if (/invalid_client|unauthorized_client|OAuth client/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The OAuth client does not answer for this extension. Check Cloud Console → APIs & Services → Credentials: the client type is Chrome Extension and the Item ID equals chrome://extensions → UCrypt (letter-exact). Edit in place if one letter is off — never recreate.' }
  }
  if (/admin_policy_enforced|org[_ ]?policy|disallowed/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'A Google organization policy blocked the sign-in. The Workspace administrator allow-lists the client under Security → API controls → App access control — or use a personal Google account.' }
  }
  if (/invalid_grant/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The Google grant is no longer valid (revoked, expired on a Testing-mode client, or a drifted clock). Press Connect to authorize fresh — and publish the consent screen to production so grants stop expiring.' }
  }
  if (/access_denied/i.test(raw)) {
    return { domain: 'CONSENT', fix: 'The consent was refused (or an old denial is cached). Press Reset connection, then reconnect and choose Allow at Google\u2019s window. You can also revoke first: myaccount.google.com/permissions → remove UCrypt.' }
  }
  if (/dailyLimit|api.?not.?enabled|accessNotConfigured|disabled/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The Drive API is off for the project (or the daily limit is spent). Cloud Console → APIs & Services → Library → Google Drive API → Enable.' }
  }
  if (/origin_mismatch/i.test(raw)) {
    return { domain: 'CONSOLE', fix: 'The request origin is not allowed for this client — the OAuth client\u2019s type or origins list does not fit this flow. Cloud Console → Credentials → the client: the type is Chrome Extension with the Item ID letter-exact.' }
  }
  if (/closed|cancel|dismiss/i.test(raw)) {
    return { domain: 'CONSENT', fix: 'The window was closed before the sign-in finished. Press the button again when ready — nothing was exchanged.' }
  }
  return { domain: 'CODEBASE', fix: 'This shape is UCrypt\u2019s own bug class — press Copy connection receipt and send it to support (the receipt names the exact row).' }
}
