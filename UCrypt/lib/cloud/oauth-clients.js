/**
 * ════════════════════════════════════════════════════════════════════════
 * R169 — THE TWO-LANE CLIENT REGISTRY (the named config constants, O-1).
 *
 * The CSA/CEO round contract (R169 "THE TWO LANES") types the definitive
 * OAuth architecture as TWO lanes, and THIS module is the one seat that
 * names both clients (a leaf module — zero imports — so every consumer
 * (ladder.js, gdrive.js, oauth-selfcheck.js, oauth-ladder.js) can ride it
 * without a cycle):
 *
 *   LANE U — THE UNIVERSAL LANE (primary, EVERY Chromium browser):
 *     chrome.identity.launchWebAuthFlow + a Google "Web application" client
 *     + the runtime-derived redirect + URLSearchParams-built URLs + a state
 *     nonce verified before any other read + PKCE S256 + response_type=code
 *     with access_type=offline (the code lane) and the canonical implicit
 *     lane as the typed fallback. The client is a PUBLIC identifier; the
 *     secret NEVER rides the package (E-SEC-1: the exposed GOCSPX- string
 *     was rotated owner-side; the no-secret sweep asserts the shape can
 *     never ride — pattern rule only, the literal is never embedded).
 *
 *   LANE C — THE CHROME SILENT LANE (retained by the R169 CSA amendment,
 *     typed openly against the R174b portability ban; the ban's motive is
 *     cross-browser and inside Chrome the motive does not apply):
 *     chrome.identity.getAuthToken with interactive:false + the manifest
 *     oauth2 block — the Chrome-Extension client below, whose Console Item
 *     ID must equal THIS extension's own ID (the letter-compare the
 *     Self-check card prints). Chrome only, zero-window silent sign-in and
 *     silent refresh across browser restarts — the CEO's own requirement
 *     ("keeps connection with cloud service even when reboot the browser").
 *     In Brave/Helium the lane is absent or wedged — the press falls
 *     through to Lane U the moment it is unavailable (never a dead press).
 *
 * HISTORY (the named corrections, in order — anti-trim: additive, each
 * documented): 1047722433028-… was the FIRST client (its Item ID carried a
 * one-letter typo — the R174 field proof) and rode the manifest until the
 * R173 rewiring; 816184664980-d8sooe… was the R173 factory client (the
 * native-family receipt; probe-proven DELETED at R174c, T2);
 * 849241523153-… was the R174 interim Web client (probe-proven DELETED,
 * T4); 816184664980-tvcsbo… is the OWNER'S delivered Web-application client
 * (R174b; Google's own token endpoint named it CONFIDENTIAL = Web
 * application — the R174c probe T1). R169: 1047722433028-… REVIVES as the
 * Lane C client (the amendment), the owner fixes its Item ID Console-side
 * (the fakon-typo check, in place, never recreate).
 *
 * LAW 0.15 holds: both IDs are OWNER-SUPPLIED, owner-attributed, PUBLIC BY
 * DESIGN — identifiers, never credentials. No client_secret exists in this
 * tree in any shape.
 * ════════════════════════════════════════════════════════════════════════
 */

/** LANE U — the universal lane's Web-application client (project ucrypt-513016).
 * Probe-proven alive + confidential (Web-application) at R174c (T1). */
export const LANE_U_CLIENT_ID = '816184664980-tvcsbo2jkni3sqlcp4lpfn0moo4uvapr.apps.googleusercontent.com'

/** LANE C — the Chrome silent lane's Chrome-Extension client (project
 * ucrypt-512820). Rides the manifest oauth2.client_id letter-exact (the
 * manifest is getAuthToken's only lawful client source). Its Console Item ID
 * must equal this extension's own runtime ID — the owner's §5 step 4 check. */
export const LANE_C_CLIENT_ID = '1047722433028-8c3c65c55a3gou9jijjj7dll25mjdkmm.apps.googleusercontent.com'

/** ═══ R171 — THE SPINE CLIENT (the unbroken spine's one client) ═══
 * The Chrome-extension-class client 1047722433028-8c3c65c55a3gou9jijjj7dll25mjdkmm
 * (project ucrypt-512820) — the SAME client the manifest already pins for
 * Lane C. ONE CLIENT, BOTH LANES, NO MANIFEST RE-PIN: the R171 contract
 * names this client the spine's window lane seat — a PUBLIC installed-class
 * client whose secretless code exchange mints the REFRESH TOKEN (the
 * persistent sign-in custody the Web-application client can never mint —
 * Google's confidential-client rule refuses it, machine-proven at R174c).
 * The constant rides HERE (the named-constant law) so a future re-pin is
 * one line. When its Console Item-ID row is armed
 * (Item ID = ccnbcioppelddohenblnmijegofidjpm, the extension's own derived
 * ID), the connect flow opens Google's window ONCE with this client and the
 * connection survives every browser restart afterwards. */
export const SPINE_CLIENT_ID = LANE_C_CLIENT_ID

/** R171 — THE SPARE CLIENT, recorded VERBATIM by the CSA's command (the
 * full ID handed to She at the round open; the evidence doc carries it too).
 * It stays SPARE — never pinned as a second source of truth: exactly ONE
 * spine client constant exists (SPINE_CLIENT_ID above). If the CSA commands
 * the re-pin, this constant's value becomes the spine in one line. */
export const SPARE_SPINE_CLIENT_ID = '816184664980-qr1bomlnsu7qn5pl2029s8oc8c0amigq.apps.googleusercontent.com'

/** The DEAD clients (probe-proven deleted_client at R174c — T2 and T4): the
 * R173 factory client and the R174 interim Web client. They never ride ANY
 * lane again (the guard substitutes the lawful lane client). NOTE: the
 * first client 1047722433028-… is NOT here anymore — it revived as LANE_C
 * (the R169 amendment); lane membership is checked with the helpers below. */
export const DEAD_GDRIVE_CLIENTS = Object.freeze([
  '816184664980-d8sooe4jaic1ciq9b7pc7d3bt38iso31.apps.googleusercontent.com',
  '849241523153-ofatrg14sdo70g84p79n9gad43hojjis.apps.googleusercontent.com',
])

/** Which lane does this client belong to? ('U' | 'C' | 'dead' | 'unknown'). */
export function laneForClientId(clientId) {
  const id = String(clientId || '').trim()
  if (!id) return 'unknown'
  if (id === LANE_U_CLIENT_ID) return 'U'
  if (id === LANE_C_CLIENT_ID) return 'C'
  if (DEAD_GDRIVE_CLIENTS.includes(id)) return 'dead'
  return 'unknown'
}

/** Is this the universal lane's client? */
export function isLaneUClientId(clientId) {
  return laneForClientId(clientId) === 'U'
}

/** Is this the Chrome silent lane's client? */
export function isLaneCClientId(clientId) {
  return laneForClientId(clientId) === 'C'
}

/** Is this client probe-proven dead (deleted in the Console)? */
export function isDeadClientId(clientId) {
  return laneForClientId(clientId) === 'dead'
}

/** Is this the spine's client? (R171 — the one client, both lanes.) */
export function isSpineClientId(clientId) {
  return laneForClientId(clientId) === 'C'
}
