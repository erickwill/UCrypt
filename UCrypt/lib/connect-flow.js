/**
 * UCrypt — THE CONNECT-FLOW ORCHESTRATOR (R115 — the glitch hunt's spine).
 *
 * Two laws live here:
 *
 * 1. THE CONNECT SINGLE-FLIGHT (the audit's suspect (a)/(g) fix): Chrome
 *    allows ONE pending launchWebAuthFlow at a time — a second concurrent
 *    connect fails with a raw "another flow is pending" error, and a
 *    double-click or a retry-while-pending used to produce exactly that.
 *    runConnectFlow() deduplicates per transport id: a call while one is in
 *    flight returns the SAME in-flight promise (the window is shared, never
 *    duplicated). The flight is cleared on settle — the next connect starts
 *    CLEAN (the state-reset law: no stale window reference, no half-written
 *    grant, no wedged single-flight).
 *
 * 2. THE EVIDENCE-RING STAGE LADDER (law 0.28): every connect records its
 *    typed stage ladder — auth-window → code → exchange → probe → seal —
 *    with the stage reached, the HTTP kind or the typed failure, the elapsed
 *    ms, the retry tier, and the error's own words (sanitized). When the
 *    glitch strikes, the owner's one diagnostics paste names the stage.
 */

import { recordRing, typedRingError } from './egrings.js'
import { SyncError, SYNC_ERROR_KINDS } from './transports/http.js'

/** transport id → in-flight connect promise. */
const _inFlight = new Map()

// R165 Arc A — THE FLIGHT-AGE LAW (the wedged-flight cure, the map's row 1.1):
// a connect flight that never settled (a dropped identity callback, a killed
// page) must not poison every future connect. A flight older than this TTL
// is DEAD — the next connect abandons it and starts clean. The single-flight
// semantics stay intact for LIVE flights (a double-click still shares the
// window); only the corpse is refused.
export const CONNECT_FLIGHT_TTL_MS = 120000

/**
 * Run a transport's connect flow under the single-flight + ring contract.
 *
 * @param {string} transportId  'gdrive' | 'github' | 'dropbox'
 * @param {(ring: (stage: string, extra?: object) => void) => Promise<object>} flowFn
 *   The transport's own flow. It calls ring(stage, extra) at each stage
 *   boundary; runConnectFlow supplies flow/transport and timing, and records
 *   the final 'seal' stage (ok) or the typed failure ring automatically.
 * @returns {Promise<object>} the flow's own return value (the grant).
 */
export async function runConnectFlow(transportId, flowFn) {
  const existing = _inFlight.get(transportId)
  if (existing) {
    // R165 Arc A — THE FLIGHT-AGE GUARD: a flight past its TTL is a corpse
    // (it never settled — nothing about it can complete); the new connect
    // abandons it and starts CLEAN instead of awaiting forever. A LIVE
    // flight (younger than the TTL) is still shared, byte-true.
    if (existing.startedAt && (Date.now() - existing.startedAt) > CONNECT_FLIGHT_TTL_MS) {
      _inFlight.delete(transportId)
      await recordRing({
        flow: 'connect', transport: transportId, stage: 'single-flight',
        outcome: 'fail', httpKind: 'oauth-window', error: 'stale_flight_abandoned',
        message: `A previous connect never finished (older than ${Math.round(CONNECT_FLIGHT_TTL_MS / 1000)} s) — it was abandoned and this connect starts clean. Nothing was written by the abandoned flight.`,
      })
    } else {
      // THE SINGLE-FLIGHT: reuse the pending window — a second Connect press
      // never fires a second launchWebAuthFlow (Chrome refuses the second; the
      // refusal was a raw wedge). The caller awaits the SAME flight.
      await recordRing({
        flow: 'connect', transport: transportId, stage: 'single-flight',
        outcome: 'ok', httpKind: 'oauth-window', error: 'connect_in_progress_reused',
        message: 'A connect was already in progress — the open window is shared, not duplicated.',
      })
      return existing
    }
  }
  const flight = (async () => {
    const t0 = Date.now()
    const ring = (stage, extra = {}) => recordRing({
      flow: 'connect', transport: transportId, stage,
      httpKind: extra.httpKind || 'oauth-window',
      at: Date.now(),
      elapsedMs: extra.elapsedMs != null ? extra.elapsedMs : Date.now() - t0,
      retryTier: 0,
      ...extra,
    })
    try {
      const result = await flowFn(ring)
      await ring('seal', { outcome: 'ok', error: '', message: 'Grant returned to the page — press Save to seal it device-only.' })
      return result
    } catch (e) {
      const kind = typedRingError(e)
      await ring('seal', {
        outcome: 'fail', error: kind,
        // the error's OWN words — the technical message carries the
        // provider's code word ('(invalid_grant)', '(400 …)') which is
        // exactly what the owner's paste needs; the sanitizer strips any
        // credential shapes before the row lands.
        message: String((e && e.message) || e),
      })
      throw e
    } finally {
      // THE STATE-RESET LAW (0.26 applied to connect): the flight map clears
      // on settle — success or failure — so the next Connect starts clean.
      // There is no stale window reference and no wedged single-flight.
      _inFlight.delete(transportId)
    }
  })()
  flight.startedAt = Date.now() // R165 Arc A — the TTL's clock (the age guard reads it)
  _inFlight.set(transportId, flight)
  return flight
}

/** Test seam — a wedged map must never survive across battery cases. */
export function _resetConnectFlightsForTest() {
  _inFlight.clear()
}

/** R165 battery seam — age the LIVE flight stored in the map past the TTL
 * (the corpse drill: the flight the MAP stores is the inner promise, not the
 * async wrapper a caller sees). Returns true when a flight was aged. */
export function _ageFlightForTest(transportId, ageMs = CONNECT_FLIGHT_TTL_MS + 1000) {
  const f = _inFlight.get(transportId)
  if (!f) return false
  f.startedAt = Date.now() - Math.max(1, Number(ageMs) || (CONNECT_FLIGHT_TTL_MS + 1000))
  return true
}

/**
 * THE TYPED AUTH-WINDOW MAPPER (the audit's suspect (a) fix — the gdrive
 * path's launchWebAuthFlow ran UNCAUGHT: a window loss surfaced as Google's
 * raw engine string with no typed card and no ring). Wraps the flow call and
 * maps every failure to a typed SyncError with the one-click retry wording:
 * the retry is always lawful because the state resets by construction
 * (nothing is written before the grant returns).
 *
 * S4 (the CEO's brief — R126): EVERY window cause gets its OWN typed card,
 * each with a one-click recovery:
 *   - auth_window_blocked  the popup was blocked → [Try again] + the
 *                          browser's popup-settings deep link;
 *   - auth_window_closed   the user closed/cancelled the window → [Try again];
 *   - auth_window_timeout  the flow timed out (the engine's timeout shapes)
 *                          → [Try again] (every retry starts clean);
 *   - auth_window_failed   the window failed to open (every other shape)
 *                          → [Try again] + the popup-settings deep link.
 * The granular kind rides the SyncError's recovery card (the wire already
 * carries recovery — the R115 law), so the page renders the RIGHT card
 * without re-parsing raw strings.
 *
 * @param {() => Promise<string>} callFn the launchWebAuthFlow call
 * @param {{transport: string, label: string}} t
 */
export async function launchWindowTyped(callFn, { transport, label }) {
  const t0 = Date.now()
  let finalUrl
  try {
    finalUrl = await callFn()
  } catch (e) {
    const raw = String((e && e.message) || e)
    // S4 — the four-cause classification (the order the checks matter:
    // the cancel shapes come first — a user's cancel can carry the word
    // "closed" without any popup language; the blocked shapes name the
    // popup explicitly; the timeout shapes name the time).
    // R171 — Chrome's "The user did not approve access." (the window OPENED
    // and was closed before completing — most often after Google's own red
    // "Error 400: redirect_uri_mismatch" page) joins the cancel shapes:
    // the honest "closed before it finished" card + the gdrive consoleNote
    // — never "failed to open", never CODEBASE.
    const kind = /cancel|dismiss|denied|did not approve|closed by the user/i.test(raw)
      ? 'auth_window_closed'
      : (/timeout|timed out/i.test(raw)
        ? 'auth_window_timeout'
        : (/could not be loaded|popup|blocked/i.test(raw)
          ? 'auth_window_blocked'
          : (/window/i.test(raw) ? 'auth_window_blocked' : 'auth_window_failed')))
    await recordRing({
      flow: 'connect', transport, stage: 'auth-window', outcome: 'fail',
      httpKind: 'oauth-window', error: kind,
      message: raw, elapsedMs: Date.now() - t0,
    })
    const label2 = label
    const CARDS = {
      auth_window_blocked: {
        kind,
        title: `The ${label2} sign-in window could not open — the browser blocked it.`,
        causes: [
          `Chrome blocks popups it did not plan for. UCrypt asks the browser for the ${label2} sign-in window and the browser refused to open it.`,
          'This is a browser setting, not an account problem — nothing was exchanged and nothing was written.',
        ],
        fix: "Press Try again. If it happens again, allow popups for this extension (the button opens the browser's popup settings), then press Try again.",
        deepLink: 'chrome://settings/content/popups',
        deepLinkLabel: 'Open popup settings',
        retryLabel: 'Try again',
      },
      auth_window_closed: {
        kind,
        title: `The ${label2} sign-in window was closed before it finished.`,
        causes: [
          'The window was closed (by you or by the browser) before the sign-in completed.',
          'Nothing was exchanged and nothing was written — the retry starts clean.',
        ],
        fix: 'Press Try again when you are ready, and complete the sign-in inside the window.',
        retryLabel: 'Try again',
      },
      auth_window_timeout: {
        kind,
        title: `The ${label2} sign-in took too long and timed out.`,
        causes: [
          'The authorization flow did not finish within the time the browser allows.',
          'Nothing was exchanged and nothing was written — the retry starts clean.',
        ],
        fix: 'Press Try again, and complete the consent within a minute of the window opening.',
        retryLabel: 'Try again',
      },
      auth_window_failed: {
        kind,
        title: `The ${label2} sign-in window failed to open.`,
        causes: [
          `The browser could not open the ${label2} sign-in window (${raw.slice(0, 100)}).`,
          'Nothing was exchanged and nothing was written.',
        ],
        fix: "Press Try again. If it happens again, allow popups for this extension (the button opens the browser's popup settings).",
        deepLink: 'chrome://settings/content/popups',
        deepLinkLabel: 'Open popup settings',
        retryLabel: 'Try again',
      },
    }
    const card = CARDS[kind]
    // R127 §3.2/§3.3 (the CEO's S4 — the disabled-client sighting made a
    // surface): the WINDOW stage is opaque to UCrypt (launchWebAuthFlow
    // cannot read the page it opens), but the shapes Google shows when the
    // OAuth client is disabled are KNOWN — "Access blocked: Authorization
    // Error · Error 401: disabled_client". On every gdrive window death the
    // card carries the console checklist (the two sentences, ×3 locales —
    // the R116 card's wording) with the console deep link as the PRIMARY
    // recovery (the owner's binding order: the primary "Open Google Cloud
    // Console" button). The note names the possibility honestly — it never
    // claims the page was read.
    if (transport === 'gdrive') {
      const rid = (typeof chrome !== 'undefined' && chrome && chrome.runtime && chrome.runtime.id) || '<your extension ID>'
      card.consoleNote = [
        'If the window showed "Access blocked: Authorization Error" with "Error 401: disabled_client", the OAuth client itself is paused or disabled in Google Cloud Console.',
        'Open the console once: check the client exists under APIs & Services → Credentials and that the OAuth consent screen publishing status is "In production" (Testing expires) — then press Try again.',
        // R171 — the field-proven red page gets its own sentence (the
        // guided lane's window is equally opaque to UCrypt): the Item-ID
        // cure with the runtime ID inline for the letter-compare.
        `If the window showed "Access blocked" with "Error 400: redirect_uri_mismatch", the OAuth client's Item ID must equal this extension's own ID letter-exact (${rid}) — fix it in Console → APIs & Services → Credentials → the Chrome-Extension client, then press Try again.`,
      ]
      card.consoleLink = 'https://console.cloud.google.com/apis/credentials'
      card.consoleLabel = 'Open Google Cloud Console'
    }
    throw new SyncError(SYNC_ERROR_KINDS.AUTH, `${label} transport: ${kind} (${raw.slice(0, 120)})`, {
      userMessage: card.title,
      recovery: card,
    })
  }
  await recordRing({
    flow: 'connect', transport, stage: 'auth-window', outcome: 'ok',
    httpKind: 'oauth-window', elapsedMs: Date.now() - t0,
  })
  return finalUrl
}
