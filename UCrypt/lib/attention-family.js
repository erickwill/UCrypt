/**
 * ════════════════════════════════════════════════════════════════════════
 * R174 — THE ONE-TRUTH FAMILY RESOLVER (R-174.1 / R-174.2 / R-174.5).
 *
 * The field spoke with ONE failure and the house told FOUR stories about it
 * (E-29/E-30): the strip rendered a READ wall for a PRE-READ abort, the
 * diagnosed line fell to "could not name", the checklist read the wrong
 * evidence, and the 4-step checklist spoke another method's words.
 *
 * THE LAW: one failure renders ONE named truth on EVERY surface. The class
 * TRAVELS with the failure — read from the pull ledger row's OWN typed
 * fields, at FIRST paint, synchronously (never behind a second diagnose).
 *
 * This leaf is the ONE resolver every surface rides:
 *   - resolveAttentionFamily(row) → { family, key } — the named family for
 *     the row's class (the sign-in, the storage, the data, the network, the
 *     healthy-read classes) — the strip, the diagnosed line, and the
 *     checklist all render FROM THIS answer;
 *   - readMaySpeakWall(row) → boolean — the ONLY lawful shape of the
 *     "upload blocked until cloud copy can be read" story: a real read ran
 *     and was blocked by a real copy (R-174.2); a pre-read abort can never
 *     reach it;
 *   - checklistConnectionFacts(sync) → the CONNECTION evidence (R-174.1) —
 *     the onboarding checklist's "Connect a cloud drive" step reads the
 *     transport record's connection truth, never a push ledger row.
 *
 * ENGINE-ONLY: zero imports, zero DOM, zero chrome — the battery drives it
 * directly and the pack gate proves the surfaces ride it.
 * ════════════════════════════════════════════════════════════════════════
 */

/** The named families (R-174.5). Each family owns ONE story; the surfaces
 * speak the family's words in the ACTIVE method's voice. */
export const ATTENTION_FAMILIES = {
  SIGNIN: 'signin',     // the sign-in expired / needs the one-click Connect
  STORAGE: 'storage',   // the storage answered unexpectedly (the setup class)
  DATA: 'data',         // the copy was fetched but cannot be read with this key
  NETWORK: 'network',   // the cloud could not be reached
  NOCOPY: 'nocopy',     // connected; the first push has not landed yet
  READ_BLOCKED: 'read-blocked', // a REAL read ran and a REAL copy blocked it
  NONE: 'none',         // nothing failed (no evidence of an attention state)
}

/** The sign-in words a materialized SyncError line carries (the fast lane's
 * reconnect cards + the guided re-auth cards). FAMILY EVIDENCE ONLY — a
 * family may be named by the row's own words when the typed kind was lost
 * (the field's exact disease); a SPECIFIC cause card may never be chosen by
 * words alone (the R-172.1 order stands — this is the LAST resort, and it
 * names a family, never a cure card beyond the family's own). */
const SIGNIN_WORD_RE = /sign-?in|oauth|re-?auth|one-click|reconnect|access_denied|invalid_grant|invalid_client|redirect_uri|admin_policy|unverified|consent|token/i

/**
 * Resolve the attention family from the pull ledger row's OWN typed fields.
 * Order is evidence-first; every branch is a named family (R-174.5) — the
 * unnamed fallback is abolished.
 *
 * @param {{attempted?:boolean, ok?:boolean, remoteObserved?:boolean,
 *          kind?:string|null, status?:number|null, recoveryKind?:string|null,
 *          transportMode?:string|null, transportState?:string|null,
 *          garbage?:number|null, error?:string|null}|null} row the pull
 *          ledger row (getSyncStatus().lastPull's shape)
 * @returns {{family:string, readRan:boolean}} the named family + whether a
 *          real read positively ran (the wall's lawful base, R-174.2)
 */
export function resolveAttentionFamily(row) {
  if (!row || typeof row !== 'object') return { family: ATTENTION_FAMILIES.NONE, readRan: false }
  const attempted = !!row.attempted
  const ok = !!row.ok
  const remoteObserved = !!row.remoteObserved
  const state = typeof row.transportState === 'string' ? row.transportState : ''
  const kind = typeof row.kind === 'string' ? row.kind : ''
  const status = (row.status === null || row.status === undefined) ? null
    : (Number.isFinite(Number(row.status)) ? Number(row.status) : null)
  const mode = typeof row.transportMode === 'string' ? row.transportMode : ''
  const errWords = typeof row.error === 'string' ? row.error : ''
  // A healthy or not-attempted row names no attention family.
  if (!attempted || ok) return { family: ATTENTION_FAMILIES.NONE, readRan: remoteObserved }
  // 1. The copy was FETCHED but cannot be read with this key — a REAL read
  //    ran and a REAL copy blocked it: the ONLY lawful home of the
  //    "upload blocked" story (R-174.2), with its own typed cure card.
  if (state === 'unreadable' || (!state && Number(row.garbage) > 0)) {
    return { family: ATTENTION_FAMILIES.DATA, readRan: false }
  }
  // 2. The typed auth family (401/403 or the OAuth refresh refused).
  if (kind === 'auth' || status === 401 || status === 403) {
    return { family: ATTENTION_FAMILIES.SIGNIN, readRan: remoteObserved }
  }
  // 3. The setup answered wrong — the ACTIVE method's family: an OAuth-active
  //    record's config failure is the SIGNIN family (the one-click Connect
  //    cure); a bridge record's is the STORAGE family (never cross-method).
  if (kind === 'protocol' || kind === 'config') {
    return { family: (mode === 'fast' || mode === 'guided') ? ATTENTION_FAMILIES.SIGNIN : ATTENTION_FAMILIES.STORAGE, readRan: remoteObserved }
  }
  // 4. The cloud could not be reached at all.
  if (kind === 'network' || kind === 'timeout' || kind === 'server' || kind === 'rate_limit' || status === 0) {
    return { family: ATTENTION_FAMILIES.NETWORK, readRan: remoteObserved }
  }
  // 5. THE NAMED FALLBACK (R-174.5) — no typed evidence rode the row (the
  //    kind-lost class the field proved). The row's OWN materialized words
  //    name the FAMILY as the last resort (never a specific cure card): the
  //    sign-in words → the sign-in family; otherwise the active method
  //    speaks — an OAuth record's abort is the sign-in family, a bridge
  //    record's is the storage family, a silent row is the network family.
  if (SIGNIN_WORD_RE.test(errWords)) return { family: ATTENTION_FAMILIES.SIGNIN, readRan: remoteObserved }
  if (mode === 'fast' || mode === 'guided') return { family: ATTENTION_FAMILIES.SIGNIN, readRan: remoteObserved }
  if (mode === 'bridge' || mode === 'manual') return { family: ATTENTION_FAMILIES.STORAGE, readRan: remoteObserved }
  return { family: ATTENTION_FAMILIES.NETWORK, readRan: remoteObserved }
}

/**
 * The ONLY lawful shape of the "upload blocked until cloud copy can be read"
 * story (R-174.2): a real read RAN and was blocked by a REAL copy. A
 * pre-read abort (`remoteObserved:false` with no unreadable state) can never
 * reach it — the strip's wall is structurally unreachable for the field's
 * 5:15 PM failure from this law on.
 *
 * @param {{attempted?:boolean, ok?:boolean, remoteObserved?:boolean,
 *          transportState?:string|null, garbage?:number|null}|null} row
 * @returns {boolean}
 */
export function readMaySpeakWall(row) {
  if (!row || typeof row !== 'object') return false
  if (!row.attempted || row.ok) return false
  // A positively observed remote that still failed the attention state means
  // a real read ran (the fetched-but-unreadable class is its own family and
  // carries its own card — the wall story rides only where the copy itself
  // stood between the device and a completed read).
  if (row.transportState === 'unreadable') return true
  if (row.remoteObserved === true) return true
  return false
}

/**
 * The CONNECTION evidence for the onboarding checklist's "Connect a cloud
 * drive" step (R-174.1): connected/not is ONE value read by the chips, the
 * checklist, the Cloud backup row, and the footer alike — the transport
 * record's connection truth. A push ledger row (ok or failed) is the
 * FIRST-SYNC step's story and can never flip the connection step again (the
 * E-29 incoherence: an unfinished "Connect a cloud drive" beside a connected
 * cloud dies here).
 *
 * @param {{transport?:{hasConfig?:boolean,id?:string}|null}} sync a
 *        getSyncStatus()-shaped object
 * @returns {{connected:boolean, verified:boolean, blocked:boolean}}
 *   connected — the connection evidence (the transport record resolves);
 *   verified  — a push has positively landed (the FIRST-SYNC step's evidence);
 *   blocked   — the CONNECTION itself is broken (no usable record).
 */
export function checklistConnectionFacts(sync) {
  const s = sync && typeof sync === 'object' ? sync : {}
  const t = s.transport && typeof s.transport === 'object' ? s.transport : null
  const connected = !!(t && (t.hasConfig || t.id))
  const verified = !!(s.lastPush && s.lastPush.ok)
  return { connected, verified, blocked: !connected }
}
