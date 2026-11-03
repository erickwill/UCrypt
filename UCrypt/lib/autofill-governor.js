/**
 * UCrypt — lib/autofill-governor.js (R133, §6 — AUTOFILL, PASSKEYS, AND
 * NATIVE-MANAGER SUPPRESSION, law 0.52's consent surface)
 *
 * THE CEO'S EXACT SPEC, made pure and battery-pinned (AUTOFILL-1..8):
 *   - TWO MODES (verbatim): "Fill website password and sign in automatically,
 *     or suggest available passkeys" (auto) VS "Prompt for the device sign-in
 *     options before viewing or filling website password" (prompt).
 *   - DEFAULT: prompt (the safe default).
 *   - ORIGIN-TRUTH (shared with law 0.39 — capture and fill must never
 *     disagree): host + scheme equality; NEVER cross-origin. The same
 *     normalizeOrigin() rule the capture pipeline uses for save.
 *   - THE DECISION: auto mode fills on field-focus/submit; prompt mode shows
 *     a consent bar that NEVER auto-closes (law 0.52 — the only exits are
 *     the user's own choices).
 *
 * PURE MODULE — no browser-API anywhere; battery-pinned in r133-round.
 */

export const AUTOFILL_MODES = { AUTO: 'auto', PROMPT: 'prompt' }
export const AUTOFILL_MODE_DEFAULT = AUTOFILL_MODES.PROMPT

/** The persisted shape (chrome.storage.local 'ucrypt:autofill'). */
export function normalizeAutofillSettings(raw) {
  const s = raw && typeof raw === 'object' ? raw : {}
  const mode = s.mode === AUTOFILL_MODES.AUTO ? AUTOFILL_MODES.AUTO : AUTOFILL_MODES.PROMPT
  return {
    mode,
    // passkey suggestions ride the same consent model (the honest gate)
    suggestPasskeys: s.suggestPasskeys !== false,
  }
}

/** ORIGIN-TRUTH (the 0.39 share): host + scheme equality, www-normalized.
 * One function, imported by the capture pipeline's own comparison — capture
 * and fill can never disagree about "the same site". */
export function normalizeOrigin(raw) {
  let s = String(raw || '').trim()
  if (!s) return ''
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s
  try {
    const u = new URL(s)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    const host = u.hostname.toLowerCase().replace(/^www\./i, '')
    if (!host) return ''
    const scheme = u.protocol === 'http:' ? 'http' : 'https'
    const port = u.port ? `:${u.port}` : ''
    return `${scheme}://${host}${port}`
  } catch {
    return ''
  }
}

export function sameOrigin(a, b) {
  const x = normalizeOrigin(a)
  const y = normalizeOrigin(b)
  return !!x && !!y && x === y
}

/** THE DECISION (the mode is the law):
 *  - no saved credential for this origin → nothing happens (no prompt)
 *  - origin mismatch (cross-origin) → NEVER fills — the typed refusal
 *  - auto mode  → { action: 'fill', reason: 'auto-mode' } (fills on
 *                 field-focus/submit; passkeys suggested where exposed)
 *  - prompt mode → { action: 'consent-bar', reason: 'prompt-mode' } — the
 *                 bar asks once, carries the filled choice, and NEVER
 *                 auto-closes (law 0.52). */
export function fillDecision({ mode, pageUrl, entryOrigin, hasSavedCredential, passkeysAvailable = false }) {
  if (!hasSavedCredential) return { action: 'none', reason: 'no-saved-credential', suggestPasskeys: false }
  if (!sameOrigin(pageUrl, entryOrigin)) return { action: 'refuse', reason: 'origin-mismatch', suggestPasskeys: false }
  const m = normalizeAutofillSettings({ mode }).mode
  // R138 §7 (D5 — the CEO's verbatim string as BEHAVIOR): passkey suggestions
  // surface ALONGSIDE the password fill where the site offers them — the
  // suggestion rides the fill decision, it never replaces the password path.
  if (m === AUTOFILL_MODES.AUTO) return { action: 'fill', reason: 'auto-mode', suggestPasskeys: passkeysAvailable === true }
  // R138 §7 (D4): the prompt mode's consent bar IS the device sign-in options
  // prompt — it precedes any fill; the passkey suggestion rides the same bar.
  return { action: 'consent-bar', reason: 'prompt-mode', needsPrompt: true, suggestPasskeys: passkeysAvailable === true }
}

/** NATIVE-MANAGER SUPPRESSION (§6 + law 0.52): the honest duty matrix.
 *  - apiAvailable: chrome.privacy.services.passwordSavingEnabled answered
 *  - controlling: UCrypt turned the browser's save prompt OFF
 *  - otherwise the GUIDED CARD renders the two-step with the detected
 *    browser family's deep link — UCrypt is honest about every duty it
 *    takes over (it never claims a suppression that did not happen). */
export function suppressionPlan({ apiAvailable, levelOfControl, controlling, browserFamily }) {
  // R138 §7 (D3 — the typed never-modify law): EVERY plan kind carries the
  // boolean the ladder card renders — UCrypt never silently changes browser
  // settings; the deep links open the browser's OWN controls for the user.
  if (apiAvailable && controlling) {
    return { kind: 'controlled', modifiesBrowserSettings: false, rows: ['The browser\u2019s save-password prompt is off — UCrypt\u2019s own Save/Update prompt takes over.'] }
  }
  if (apiAvailable && levelOfControl === 'controlled_by_other_extensions') {
    return { kind: 'other-extension', modifiesBrowserSettings: false, rows: ['Another extension controls this setting — UCrypt cannot suppress the browser\u2019s save prompt until that changes.'] }
  }
  const fam = String(browserFamily || 'chrome')
  const deep = {
    chrome: 'chrome://settings/passwords',
    brave: 'brave://settings/passwords',
    edge: 'edge://settings/passwords',
    opera: 'opera://settings/passwords',
    vivaldi: 'vivaldi://settings/passwords',
  }[fam] || 'chrome://settings/passwords'
  return {
    kind: 'guided',
    modifiesBrowserSettings: false,
    deepLink: deep,
    rows: [
      `Step 1 — open ${deep} and turn OFF "Offer to save passwords" (and "Auto sign-in" if you want the prompt gone entirely).`,
      'Step 2 — UCrypt verifies the state on the next visit and shows the live status row here.',
      'UCrypt is honest about every duty it takes over: it fills and saves only what you approve.',
    ],
  }
}
