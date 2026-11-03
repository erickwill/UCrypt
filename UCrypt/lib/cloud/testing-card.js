/**
 * UCrypt — R160 ARC A′ — THE PROACTIVE TESTING-EXPIRY CARD (G162).
 *
 * THE PROMISED SHIP (R158 §8 D.1, scheduled by R158's own transcript line
 * L158 as "the first scheduled payload row of R159"; carried by R160 §4
 * ARC A′ to land): when the TESTING-class signature of the Google OAuth
 * token is detected, the Cloud Sync area renders a PROACTIVE card —
 * "Your Google token will expire — publish to Production" — naming the
 * EXACT remediation step (Google Cloud Console → APIs & Services →
 * OAuth consent screen → Publishing status: In production — the tutorial's
 * Step 1.5) BEFORE the day-7 silent death.
 *
 * THE CEO'S STANDING REPORT ("Cloud Sync (Google option) sometimes presents
 * glitches that don't allow connection") — the diagnosed prime suspect
 * since R151 (H-13) is the Google TESTING-mode consent screen: Google
 * expires every grant ~7 days after sign-in, and the death is SILENT until
 * now. This card turns the silent death into a guided cure.
 *
 * LAYER-1 DETECTION ONLY: the classifier reads the OAuth state machine's
 * OWN answers — the error words Google already gave us (invalid_grant +
 * "expired or revoked" is the day-7 signature; access_denied + the
 * unverified/Testing consent shape is the risk class) and the stage the
 * answer crossed (a refresh death is the schedule class). NO frozen-byte
 * contact (LAW #101 — lib/cloud/cred.js stays byte-exact; this module READS
 * the machine's world, never edits it), no new permissions, zero network.
 *
 * THE HONEST CONSEQUENCE LINE: "After it expires, Cloud Sync cannot connect
 * until you publish or reconnect." The card NEVER blocks manual sync while
 * the token lives. POPUP SOVEREIGNTY: it never closes itself — the user
 * dismisses it; a dismissed reminder returns after 24 h OR on a NEW
 * evidence event (each reconnect cycle re-arms it); a DEAD card ignores
 * dismissal (the honest-error discipline: the state names the truth).
 *
 * PURE — the battery pins every evidence → card row
 * (tests/r160-testing-card.test.mjs).
 */

/** chrome.storage keys (the evidence hook writes #1; the renderer reads both). */
export const TESTING_EVIDENCE_KEY = 'ucrypt:testing-evidence'
export const TESTING_DISMISSAL_KEY = 'ucrypt:testing-card-dismissal'

/** The Testing-mode schedule: Google expires grants ~7 idle days after mint. */
export const TESTING_LIFETIME_HINT_MS = 7 * 24 * 60 * 60 * 1000
/** A dismissed reminder returns after 24 h (a nudge, never nagware). */
export const REMINDER_RETURN_MS = 24 * 60 * 60 * 1000

/** The typed classes (ONE level each; the renderer writes ONLY that level's lines). */
export const TESTING_CLASSES = Object.freeze({
  TESTING_DEAD: Object.freeze({
    key: 'TESTING_DEAD',
    level: 'dead',
    sig: 'invalid_grant + "expired or revoked" — the day-7 Testing death',
  }),
  TESTING_RISK: Object.freeze({
    key: 'TESTING_RISK',
    level: 'reminder',
    sig: 'invalid_grant at refresh / the unverified-consent shape — the schedule class',
  }),
})

/** Production/console classes that must NEVER render this card (each has
 * its own typed card in lib/transports/gdrive-oauth-help.js). */
export const NON_TESTING_CLASSES = Object.freeze([
  'client_disabled', 'invalid_client', 'unauthorized_client',
  'admin_policy_enforced', 'redirect_uri_mismatch', 'origin_mismatch',
  'client_secret_missing', 'google_error_untyped',
])

/** Google's day-7 signature words (the description the token endpoint gives). */
const DEAD_SIG_RE = /expired\s+or\s+revoked/i
const GRANT_RE = /invalid[_ ]grant/i
const UNVERIFIED_RE = /unverified|testing|not\s+verified/i

/**
 * CLASSIFY ONE OAUTH ANSWER (Layer-1). Never throws — hostile, partial,
 * wrong-typed and oversized evidence classifies to null or a class, never
 * to an exception (the evidence hook rides the recovery path and must not
 * perturb it).
 * @param {{error?:string, errorDescription?:string, status?:number|null,
 *           stage?:string}} ev
 * @returns {{cls:string, level:'dead'|'reminder'}|null}
 */
export function classifyTestingEvidence(ev = {}) {
  try {
    const error = String(ev && ev.error ? ev.error : '').slice(0, 2048)
    const desc = String(ev && ev.errorDescription ? ev.errorDescription : '').slice(0, 2048)
    const stage = String(ev && ev.stage ? ev.stage : '')
    const both = error + ' ' + desc
    if (!both.trim()) return null
    // The schedule class: a grant Google refuses at REFRESH time. Production
    // grants do not die on a schedule; a Testing grant does (day 7).
    if (GRANT_RE.test(both)) {
      if (DEAD_SIG_RE.test(desc) || DEAD_SIG_RE.test(error)) {
        return { cls: TESTING_CLASSES.TESTING_DEAD.key, level: TESTING_CLASSES.TESTING_DEAD.level }
      }
      return { cls: TESTING_CLASSES.TESTING_RISK.key, level: TESTING_CLASSES.TESTING_RISK.level }
    }
    // The consent shape: Google refused the authorization naming the
    // unverified/Testing state (the project has not gone to Production).
    if (/access_denied/.test(both) && UNVERIFIED_RE.test(desc)) {
      return { cls: TESTING_CLASSES.TESTING_RISK.key, level: TESTING_CLASSES.TESTING_RISK.level }
    }
    return null
  } catch {
    return null
  }
}

/**
 * SHOULD THE CARD SHOW AGAIN? The dismissal law: a 'dead' card ignores
 * dismissal; a reminder returns on a NEW evidence event (evidenceAt newer
 * than the dismissal) or after REMINDER_RETURN_MS.
 * @param {{at?:number, level?:string}|null} dismissal
 * @param {number} now
 * @param {number} evidenceAt
 * @param {'dead'|'reminder'} level
 */
export function shouldShowAgain(dismissal, now, evidenceAt, level) {
  if (level === 'dead') return true
  if (!dismissal || typeof dismissal !== 'object') return true
  const at = Number(dismissal.at)
  if (!Number.isFinite(at)) return true
  if (Number.isFinite(evidenceAt) && evidenceAt > at) return true
  return now - at >= REMINDER_RETURN_MS
}

/**
 * DERIVE THE CARD (ONE state per render — the renderer writes only it).
 * @param {{evidence?:object|null, dismissal?:object|null, now?:number}} args
 * @returns {{show:boolean, level?:'dead'|'reminder', cls?:string,
 *            evidenceAt?:number, tutorialStep:string}}
 */
export function deriveTestingCard({ evidence = null, dismissal = null, now = Date.now() } = {}) {
  const cls = classifyTestingEvidence(evidence)
  if (!cls) return { show: false, tutorialStep: 'Step 1.5' }
  const evidenceAt = Number(evidence && evidence.at)
  const show = shouldShowAgain(dismissal, Number(now) || Date.now(), evidenceAt, cls.level)
  return {
    show,
    level: cls.level,
    cls: cls.cls,
    evidenceAt: Number.isFinite(evidenceAt) ? evidenceAt : null,
    tutorialStep: 'Step 1.5',
  }
}

/** The renderer's i18n key names (the copy lives in _locales ×3). */
export const TESTING_CARD_KEYS = Object.freeze({
  reminderTitle: 'testingCardTitle',
  reminderBody: 'testingCardBody',
  step: 'testingCardStep',
  deadTitle: 'testingCardDeadTitle',
  deadBody: 'testingCardDeadBody',
  reconnectBtn: 'testingCardReconnectBtn',
  dismissBtn: 'testingCardDismissBtn',
})
