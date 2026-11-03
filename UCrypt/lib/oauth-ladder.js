/**
 * ════════════════════════════════════════════════════════════════════════
 * R165 ARC B — THE OAUTH VERDICT LADDER (the extrapolated tool, product-grade).
 * ARC C — THE RESET-CONNECTION ROW.  ARC E — THE SMOKE AS RUNG 4.
 * ARC F — THE CONNECTION RECEIPT (privacy-shaped, copyable).
 *
 * One walk, four rungs, each printing PASS/FAIL + its DOMAIN:
 *
 *   Rung 1  IDENTITY    — chrome.runtime.id == the ID the pinned manifest key
 *                         derives (the R164 Arc-D doctor, reused). Fail →
 *                         "install drift — restore the pinned key" (CODEBASE).
 *   Rung 2  BINDING     — the fast path's client_id == the manifest oauth2
 *                         client_id (kills S-2); the scope string == drive.appdata
 *                         EXACTLY (kills S-4); the redirect is DERIVED by
 *                         chrome.identity, never hand-built. Fail → CODEBASE
 *                         (our wiring) or CONSOLE (the Google-side binding,
 *                         with the exact fix pointer).
 *   Rung 3  TOKEN       — the WEB-AUTH machinery (R174b-corrected: the code
 *                         lane — response_type=code, PKCE S256, offline — is
 *                         primary; the canonical implicit lane answers the
 *                         client-rule refusals ONCE). The native interactive
 *                         getAuthToken leg is RETIRED (the portability law).
 *                         The outcome is NAMED — which machinery answered,
 *                         the raw verbatim, the domain per shape.
 *   Rung 4  ROUND-TRIP  — the R164 smoke (write → read back byte-exact →
 *                         delete) with every HTTP status printed. Fail → the
 *                         status names the domain.
 *
 * Every failing rung prints its domain: CODEBASE (our bug, with the row name),
 * CONSOLE (binding/scope/API — with the exact fix pointer), or CONSENT (the
 * user's own action — with the how-to). The last rung IS the smoke.
 *
 * ENGINE-ONLY: no DOM, no chrome.i18n. The chrome seam, the smoke, and the
 * identity timeout are injectable — the battery drives every failure shape.
 * ════════════════════════════════════════════════════════════════════════
 */

import { boundedIdentityCall, failureDomain } from './pending.js'
import { sharedClientId, manifestOauth2, IDENTITY_CALLBACK_TIMEOUT_MS, LANE_U_CLIENT_ID, LANE_C_CLIENT_ID, mintGdriveLaneCToken, LANE_C_SILENT_TIMEOUT_MS } from './ladder.js'
import { webAuthFastToken, webAuthCodeMint, EXCHANGE_FALLBACK_KINDS } from './webauth-fallback.js'
import { idDriftPreflight } from './cloud/id-doctor.js'

/** The scope pin (the manifest's ONLY lawful fast-rung scope). */
export const FAST_SCOPE_PIN = 'https://www.googleapis.com/auth/drive.appdata'

/** The ladder's rung keys (the receipt's stable row names). */
export const LADDER_RUNGS = ['identity', 'binding', 'token', 'roundtrip']

/**
 * Rung 2 — the BINDING verdict (pure; the battery drives it directly).
 * R169 — THE TWO-LANE BINDING (named correction of the S-2 single-client
 * row): the machine now carries TWO lawful clients, each with its own
 * covenant row —
 *   lane-u-client     the fast path's client_id == the LANE U constant
 *                     (the Web-application client — the ONLY client the
 *                     window lane may ride)
 *   lane-c-manifest   the manifest oauth2.client_id == the LANE C constant
 *                     (the Chrome-Extension client — the ONLY client
 *                     getAuthToken may ride; its Console Item ID must equal
 *                     this extension's own ID — the Self-check letter-compare)
 *   scope-pin         the scope string == drive.appdata EXACTLY (kills S-4)
 *   redirect-derived  the redirect is DERIVED by chrome.identity, never
 *                     hand-built
 * Every row's failure domain is CODEBASE (our wiring) — the CONSOLE rows
 * (the Item ID, the redirect registration) are named by the Self-check and
 * the window's own verdict, not here.
 * @param {{fastClientId: string, manifestClientId: string, scope: string|string[], redirect: string, derivedRedirect: string, laneUClientId?: string, laneCClientId?: string}} facts
 */
export function bindingVerdict(facts) {
  const fast = String((facts && facts.fastClientId) || '').trim()
  const man = String((facts && facts.manifestClientId) || '').trim()
  const laneU = String((facts && facts.laneUClientId) || LANE_U_CLIENT_ID).trim()
  const laneC = String((facts && facts.laneCClientId) || LANE_C_CLIENT_ID).trim()
  const scopes = Array.isArray(facts && facts.scope) ? (facts.scope || []) : [String((facts && facts.scope) || '')]
  const redirect = String((facts && facts.redirect) || '')
  const derived = String((facts && facts.derivedRedirect) || '')
  const rows = []
  let ok = true
  if (!fast) {
    ok = false
    rows.push({ check: 'lane-u-client', ok: false, detail: 'the fast path\u2019s client_id is absent — the window lane has nothing to ride' })
  } else if (fast !== laneU) {
    ok = false
    rows.push({ check: 'lane-u-client', ok: false, detail: `the fast path's client_id (${fast}) != the Lane U Web-application client (${laneU}) — the two-lane law (each lane rides its own client)` })
  } else {
    rows.push({ check: 'lane-u-client', ok: true, detail: laneU })
  }
  if (!man) {
    ok = false
    rows.push({ check: 'lane-c-manifest', ok: false, detail: 'the manifest oauth2 client_id is absent — the Chrome silent lane has no lawful client to ride' })
  } else if (man !== laneC) {
    ok = false
    rows.push({ check: 'lane-c-manifest', ok: false, detail: `the manifest's client_id (${man}) != the Lane C Chrome-Extension client (${laneC}) — the two-lane law (the manifest is getAuthToken's only lawful client source)` })
  } else {
    rows.push({ check: 'lane-c-manifest', ok: true, detail: man })
  }
  const scopeOk = scopes.length === 1 && scopes[0] === FAST_SCOPE_PIN
  rows.push({ check: 'scope-pin', ok: scopeOk, detail: scopeOk ? FAST_SCOPE_PIN : `requested [${scopes.join(', ')}] != exactly [${FAST_SCOPE_PIN}] — S-4 class` })
  if (!scopeOk) ok = false
  const redirectOk = !!derived && redirect === derived
  rows.push({ check: 'redirect-derived', ok: redirectOk, detail: redirectOk ? derived : `the redirect must be DERIVED by chrome.identity (${derived || 'unavailable'}), never hand-built (got: ${redirect || 'empty'})` })
  if (!redirectOk) ok = false
  return { ok, rows, domain: ok ? '' : 'CODEBASE', fix: ok ? '' : 'The two-lane wiring drifted — the Lane U client rides the named constant, the Lane C client rides the manifest, the scope stays drive.appdata, and the redirect stays derived. This is a CODEBASE fix (one seal, byte-audited).' }
}

/**
 * THE LADDER WALK. Env seams: { chromeLike, smoke, identityTimeoutMs,
 * setTimer, clearTimer, now } — the battery injects every failure shape.
 * @returns {Promise<{rungs: Array<{key: string, ok: boolean, detail: string, domain: string, fix: string, rows?: Array}>, allOk: boolean, at: string}>}
 */
export async function runConnectionCheck(env = null) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  const smoke = (env && env.smoke) || null
  const rungs = []
  const at = new Date().toISOString()

  // ── Rung 1 — IDENTITY (the R164 doctor, reused) ──────────────────────────
  try {
    // R165 battery seam (additive): env.identityResult overrides the live
    // preflight (the battery runs without chrome.runtime to derive the key).
    const v = (env && env.identityResult) ? env.identityResult : await idDriftPreflight()
    rungs.push({
      key: 'identity',
      ok: !!v.ok,
      detail: v.ok
        ? `this install IS the pinned build (chrome.runtime.id == the key's derived ID)`
        : (v.sentence || 'the pinned identity could not be verified on this browser — restore the pinned key'),
      domain: v.ok ? '' : 'CODEBASE',
      fix: v.ok ? '' : 'install drift — restore the pinned key (the manifest key derives the extension ID; the sealed build carries it)',
    })
  } catch (e) {
    rungs.push({ key: 'identity', ok: false, detail: `the identity check itself failed: ${String((e && e.message) || e).slice(0, 160)}`, domain: 'CODEBASE', fix: 'the doctor row failed to run — this is UCrypt\u2019s own bug class; send the receipt' })
  }

  // ── Rung 2 — BINDING (the byte-compares; kills S-2 and S-4) ──────────────
  try {
    // R165 battery seam (additive): env.manifest overrides the captured
    // manifest read (the battery runs without chrome.runtime.getManifest).
    const man = (env && env.manifest !== undefined) ? env.manifest
      : (manifestOauth2() || ((chromeLike && chromeLike.runtime && chromeLike.runtime.getManifest) ? (chromeLike.runtime.getManifest().oauth2 || null) : null))
    const fast = (env && env.fastClientId != null) ? String(env.fastClientId) : sharedClientId('gdrive')
    let derivedRedirect = ''
    let redirect = ''
    try {
      derivedRedirect = (chromeLike && chromeLike.identity && typeof chromeLike.identity.getRedirectURL === 'function') ? chromeLike.identity.getRedirectURL() : ''
      redirect = derivedRedirect // the fast rung NEVER hand-builds a redirect — the derived value is the only value
    } catch { redirect = '' }
    const bv = bindingVerdict({
      fastClientId: fast,
      manifestClientId: man && man.client_id,
      scope: (man && man.scopes) || [],
      redirect,
      derivedRedirect,
    })
    rungs.push({
      key: 'binding',
      ok: bv.ok,
      detail: bv.ok ? 'client_id match, scope exactly drive.appdata, redirect derived' : bv.rows.filter((r) => !r.ok).map((r) => `${r.check}: ${r.detail}`).join(' · '),
      domain: bv.domain,
      fix: bv.fix,
      rows: bv.rows,
    })
  } catch (e) {
    rungs.push({ key: 'binding', ok: false, detail: `the binding check itself failed: ${String((e && e.message) || e).slice(0, 160)}`, domain: 'CODEBASE', fix: 'the binding row failed to run — this is UCrypt\u2019s own bug class; send the receipt' })
  }

  // ── Rung 3 — TOKEN (R169 — THE TWO-LANE RUNG) ───────────────────────────
  // LEG 0 the Chrome silent lane (getAuthToken {interactive:false}, bounded
  // at the 8 s silent bound, zero windows — the R169 amendment retained it
  // for Chrome; the detail NAMES it when it serves). LEG 1 the code lane
  // (response_type=code, PKCE S256, offline) — the SAME machinery the
  // one-click connect uses. LEG 2 the canonical implicit lane answers the
  // client-rule refusals ONCE. The rung's detail names WHICH lane answered
  // — the receipt carries the truth.
  let tokenOk = false
  try {
    let mint = null
    if (!env?.laneCDisabled) {
      const laneC = env && typeof env.laneCImpl === 'function'
        ? await env.laneCImpl({ chromeLike, timeoutMs: env && env.laneCTimeoutMs })
        : await mintGdriveLaneCToken({ chromeLike, timeoutMs: (env && env.laneCTimeoutMs) || LANE_C_SILENT_TIMEOUT_MS, force: true, setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now })
      if (laneC && laneC.ok) {
        mint = { ok: true, token: laneC.token, expiresIn: 3600, via: 'chrome-lane-c' }
      }
    }
    if (!mint) {
      if (env && typeof env.webAuth === 'function') {
        mint = await env.webAuth({ timeoutMs: env && env.webAuthTimeoutMs, setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now })
      } else {
        mint = await webAuthCodeMint({
          chromeLike,
          clientId: sharedClientId('gdrive'),
          scope: FAST_SCOPE_PIN,
          timeoutMs: env && env.webAuthTimeoutMs,
          setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
        })
      // R174b — the canonical implicit lane answers the client-rule refusals
      // ONCE (the anti-storm law): Google's confidential-client rule, a
      // deleted/unknown client, a wrong-type client. A cancellation, a
      // timeout, or a redirect mismatch keeps its typed row — never a
      // second window for a shape the window itself named.
      if (!mint.ok && EXCHANGE_FALLBACK_KINDS.includes(String(mint.kind || ''))) {
        const web = await webAuthFastToken({
          chromeLike,
          clientId: sharedClientId('gdrive'),
          scope: FAST_SCOPE_PIN,
          timeoutMs: env && env.webAuthTimeoutMs,
          setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now,
        })
        if (web.ok) {
          mint = { ...web, via: 'web-auth-flow' }
        } else {
          const raw2 = String(web.raw || '')
          const dom2 = failureDomain({ verdict: web.verdict, kind: web.kind, raw: raw2 })
          rungs.push({
            key: 'token', ok: false,
            detail: `the code lane: ${String(mint.kind || 'refused')}${mint.raw ? ` — ${String(mint.raw).slice(0, 160)}` : ''} · the implicit lane: ${String(web.kind || web.verdict || 'refused')}${raw2 ? ` — ${raw2.slice(0, 160)}` : ''}`,
            domain: dom2.domain, fix: dom2.fix,
          })
          mint = null
        }
      }
      }
    }
    if (mint && mint.ok) {
      tokenOk = true
      const laneName = mint.via === 'chrome-lane-c'
        ? 'LANE C — Chrome\u2019s own silent connection (zero windows)'
        : mint.via === 'web-auth-code'
          ? 'LANE U — the code lane (the PKCE exchange answered)'
          : 'LANE U — the implicit lane (the canonical second machinery)'
      rungs.push({
        key: 'token', ok: true,
        detail: `the sign-in token arrived (${laneName}; Google's window or Chrome's own cache, the derived redirect${mint.refreshToken ? '; the refresh token arrived (the offline custody rides the sealed envelope)' : '; the token rides the sealed envelope, never the receipt'})`,
      })
    } else if (mint) {
      const raw = String(mint.raw || '')
      const dom = failureDomain({ verdict: mint.verdict, kind: mint.kind, raw })
      rungs.push({ key: 'token', ok: false, detail: `${String(mint.kind || mint.verdict || 'refused')}${raw ? ` — ${raw.slice(0, 200)}` : ''}`, domain: dom.domain, fix: dom.fix })
    }
  } catch (e) {
    rungs.push({ key: 'token', ok: false, detail: `the token rung itself threw: ${String((e && e.message) || e).slice(0, 160)}`, domain: 'CODEBASE', fix: 'the token row failed to run — this is UCrypt\u2019s own bug class; send the receipt' })
  }

  // ── Rung 4 — ROUND-TRIP (the smoke; every HTTP status printed) ───────────
  // Skipped HONESTLY when the token rung failed: the smoke would only
  // re-mint; the ladder says so instead of pretending to check.
  if (!tokenOk) {
    rungs.push({ key: 'roundtrip', ok: false, detail: 'skipped — the token rung did not pass, so the round-trip has no bearer to ride (fix the rungs above first)', domain: '', fix: '' })
  } else if (typeof smoke !== 'function') {
    rungs.push({ key: 'roundtrip', ok: false, detail: 'the smoke leg is unavailable on this build', domain: 'CODEBASE', fix: 'the smoke module did not load — this is UCrypt\u2019s own bug class; send the receipt' })
  } else {
    try {
      const receipt = await smoke()
      const st = (receipt && receipt.statuses) || {}
      const parts = [
        `write ${receipt && receipt.wrote ? 'ok' : 'FAILED'} (HTTP ${st.write ?? '?'})`,
        `read-back ${receipt && receipt.match ? 'byte-exact' : 'DIFFERENT'} (HTTP ${st.read ?? '?'})`,
        `delete ${receipt && receipt.deleted ? 'ok' : 'FAILED'} (HTTP ${st.delete ?? '?'})`,
      ]
      rungs.push({
        key: 'roundtrip',
        ok: !!(receipt && receipt.wrote && receipt.match && receipt.deleted),
        detail: parts.join(' · '),
        domain: (receipt && receipt.wrote && receipt.match && receipt.deleted) ? '' : (Number(st.write) === 403 || Number(st.write) === 401 ? 'CONSOLE' : 'CODEBASE'),
        fix: (receipt && receipt.wrote && receipt.match && receipt.deleted) ? '' : (Number(st.write) === 403 ? 'the write was refused by Google — check the Drive API is enabled for the project and the scope stayed drive.appdata (Console)' : 'the private-folder round-trip failed — send the receipt (the statuses name the leg)'),
      })
    } catch (e) {
      const raw = String((e && e.message) || e)
      const dom = failureDomain({ verdict: 'last-error', kind: 'smoke-threw', raw })
      rungs.push({ key: 'roundtrip', ok: false, detail: `the round-trip failed: ${raw.slice(0, 200)}`, domain: dom.domain, fix: dom.fix })
    }
  }

  const allOk = rungs.every((r) => r.ok)
  return { rungs, allOk, at }
}

/**
 * ARC C — THE RESET CONNECTION: clear the cached auth tokens (bounded) and
 * hand back the plain revoke instructions. Google caches denials: a user who
 * once clicked "cancel" can stay denied even after clicking Allow later —
 * the reset + one revoke clears the cached refusal class.
 * @returns {Promise<{ok: boolean, cleared: boolean, detail: string, steps: string[]}>}
 */
export async function resetConnection(env = null) {
  const chromeLike = (env && env.chromeLike) || (typeof chrome !== 'undefined' ? chrome : null)
  const r = await boundedIdentityCall(chromeLike, 'clearAllCachedAuthTokens', {}, { timeoutMs: Number((env && env.identityTimeoutMs) || IDENTITY_CALLBACK_TIMEOUT_MS), setTimer: env && env.setTimer, clearTimer: env && env.clearTimer, now: env && env.now })
  const cleared = !!r.ok
  return {
    ok: cleared,
    cleared,
    detail: cleared
      ? 'the cached sign-in tokens were cleared — the next connect asks Google fresh'
      : `the clear did not confirm (${String(r.raw || r.kind || 'unknown').slice(0, 120)}) — do the revoke below anyway; it clears the cached denial on Google\u2019s side`,
    steps: [
      'Open myaccount.google.com/permissions and remove UCrypt (this revokes the cached denial on Google\u2019s side).',
      'Come back and press the connect button once.',
      'At Google\u2019s window choose Allow (first time: Advanced → "Go to UCrypt").',
    ],
  }
}

/**
 * ARC F — THE CONNECTION RECEIPT (privacy-shaped, copyable text for support):
 * rung results, the raw service texts, the HTTP statuses, the timestamps,
 * the extension ID, the client_id, the redirect presented, the lane that
 * served — and NO token, NO personal data, NO vault material, NO secret.
 * The token-shaped strings are stripped defensively even if a raw service
 * text ever carried one (the sweep asserts the shape — G194), and R169's
 * E-SEC-1 law adds the GOCSPX- prefix shape and the client_secret/private_key
 * member shapes to the strip (objects, arrays, JSON members — any encoding
 * of the member name is caught; the VALUES never ride, only the marker).
 * @param {{rungs: Array, allOk: boolean, at: string}} walk
 * @param {{extensionId?: string, clientId?: string, redirect?: string, lane?: string}} [facts]
 */
export function connectionReceipt(walk, facts = {}) {
  const extId = String(facts.extensionId || '').trim()
  const clientId = String(facts.clientId || '').trim()
  const redirect = String(facts.redirect || '').trim()
  const lane = String(facts.lane || '').trim()
  const L = []
  L.push('UCrypt connection receipt (no token, no personal data, no vault material, no secret)')
  L.push(`at: ${String(walk && walk.at) || new Date().toISOString()}`)
  if (extId) L.push(`extension ID: ${extId}`)
  if (clientId) L.push(`client_id: ${clientId}`)
  if (redirect) L.push(`redirect presented: ${redirect}`)
  if (lane) L.push(`lane served: ${lane}`)
  L.push(`verdict: ${walk && walk.allOk ? 'ALL RUNGS PASS' : 'A RUNG FAILED (see below)'}`)
  for (const r of ((walk && walk.rungs) || [])) {
    L.push(`rung ${r.key}: ${r.ok ? 'PASS' : 'FAIL'}${r.domain ? ` — domain ${r.domain}` : ''}`)
    if (r.detail) L.push(`  ${String(r.detail).replace(/\s+/g, ' ').slice(0, 300)}`)
    if (r.fix && !r.ok) L.push(`  fix: ${String(r.fix).slice(0, 300)}`)
  }
  L.push('end of receipt')
  // G194 + R169 E-SEC-1 — the defensive strip: no token-shaped,
  // bearer-shaped, email-shaped, client_secret-shaped, private_key-shaped,
  // or GOCSPX--prefixed string may ride the receipt even by accident.
  return L.join('\n')
    .replace(/Bearer\s+[A-Za-z0-9._\-]+/g, 'Bearer [stripped]')
    .replace(/ya29\.[A-Za-z0-9._\-]+/g, '[token stripped]')
    .replace(/GOCSPX-[A-Za-z0-9_\-]+/g, '[secret stripped]')
    .replace(/client_secret["']?\s*[:=]\s*["']?[A-Za-z0-9._\-]*/gi, 'client_secret [stripped]')
    .replace(/private_key["']?\s*[:=]\s*["']?[A-Za-z0-9._\-]*/gi, 'private_key [stripped]')
    .replace(/client_secret[^&\s"']*/gi, 'client_secret [stripped]')
    .replace(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, '[email stripped]')
    .replace(/[A-Za-z0-9._\-]{80,}/g, (m) => (m.includes('googleusercontent') || m.includes('.apps.')) ? m : '[long string stripped]')
}

/** The receipt PRIVACY ASSERTION (G194's battery seam): a receipt must not
 * contain the token, the personal email, or vault material it was handed.
 * Pure — the battery drives it with poisoned inputs and asserts the strip. */
export function assertReceiptPrivacy(receiptText, forbidden = []) {
  const t = String(receiptText || '')
  const leaks = (Array.isArray(forbidden) ? forbidden : []).filter((s) => s && String(s).length >= 8 && t.includes(String(s)))
  return { ok: leaks.length === 0, leaks }
}
