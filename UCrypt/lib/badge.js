/**
 * UCrypt — Toolbar badge (v2.48.0, R90 §2.1 — canonical completion of the
 * original R42 surface; the CEO-directed "never-shipped surfaces" round).
 *
 * Law (verbatim from the canonical spec):
 *   - matching-login count for the ACTIVE http(s) tab, capped at "9+"
 *   - locked state is "•" with the title "UCrypt is locked" — never a fake
 *     count, never shown when locked
 *   - computed from the URL in the WORKER, not the page
 *   - incognito: off
 *
 * This module is the single source of truth for the DECISION (pure, unit
 * tested); background.js does the chrome.action writes. No other module may
 * set the badge.
 */

/** Cap: counts above 9 render as "9+" (never a truncated fake count). */
export const BADGE_CAP = 9

/** The locked marker — deliberately NOT a digit (never fakes a count). */
export const BADGE_LOCKED = '\u2022' // •

/**
 * Pure decision: what should the badge show for this context?
 * @param {{ unlocked: boolean, incognito: boolean, protocol: string, count: number }} ctx
 * @returns {{ text: string, title: string, color: string }}
 */
export function badgeFor({ unlocked, incognito, protocol, count }) {
  const LOCKED_COLOR = '#6b7280' // neutral grey — a state, not a result
  const OK_COLOR = '#2e7d32'
  const incognitoOff = { text: '', title: 'UCrypt', color: OK_COLOR }
  // Incognito: the badge is OFF entirely — no counts leak into a private
  // window's toolbar.
  if (incognito) return incognitoOff
  // Only http(s) pages carry counts — chrome://, edge://, file://, ftp://
  // and every other scheme render nothing (an extension page is not a
  // login target).
  if (protocol !== 'http:' && protocol !== 'https:') return incognitoOff
  if (!unlocked) {
    return { text: BADGE_LOCKED, title: 'UCrypt is locked', color: LOCKED_COLOR }
  }
  const n = Math.max(0, Math.floor(Number(count) || 0))
  if (n === 0) return { text: '', title: 'UCrypt', color: OK_COLOR }
  const text = n > BADGE_CAP ? `${BADGE_CAP}+` : String(n)
  return {
    text,
    title: n === 1 ? '1 saved login for this site' : `${n} saved logins for this site`,
    color: OK_COLOR,
  }
}
