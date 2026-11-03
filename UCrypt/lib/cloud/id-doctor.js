/**
 * ════════════════════════════════════════════════════════════════════════
 * R164 ARC D — THE ID-DRIFT DOCTOR (G187).
 *
 * The OAuth client is bound to the RUNNING extension's ID; the pinned
 * manifest key DERIVES that ID (base64 → DER → SHA-256 → first 16 bytes →
 * the a-p alphabet — G184's mathematics, carried live). This module compares
 * chrome.runtime.id against the DERIVED ID at the connect door:
 *
 *   match   → silence (the door opens; the doctor row says "verified").
 *   mismatch → the honest sentence ("OAuth is bound to extension ID <X>;
 *              this install is ID <Y> — sync will fail. Restore the pinned
 *              key.") and the fast connect REFUSES — fail-closed, house
 *              style: disabled + explained, never hidden, never removed.
 *
 * NEVER FIRES FALSELY (G187): the verdict is pure; the battery mutates the
 * key in a test copy and proves the sentence, then restores and proves the
 * silence. The tools/identity-pin.mjs CLI asserts the same math offline;
 * the battery cross-checks both implementations against one another.
 * ════════════════════════════════════════════════════════════════════════
 */

const ID_ALPHABET = 'abcdefghijklmnop'

/** The pure, sync verdict (exported for the battery — G187's rows).
 * @param {string} runtimeId  chrome.runtime.id (the RUNNING install's ID)
 * @param {string} derivedId  the ID the PINNED manifest key derives
 * @returns {{ok: boolean, drifted: boolean, runningId: string, derivedId: string, sentence: string, sentenceKey: string, subs: string[]}}
 */
export function idDriftVerdict(runtimeId, derivedId) {
  const a = String(runtimeId || '').trim()
  const b = String(derivedId || '').trim()
  const ok = !!a && !!b && a === b
  return {
    ok,
    drifted: !!a && !!b && a !== b,
    runningId: a,
    derivedId: b,
    sentenceKey: ok ? 'idDoctorRowOk' : 'idDriftSentence',
    subs: ok ? [] : [b, a],
    sentence: ok
      ? ''
      : `OAuth is bound to extension ID ${b}; this install is ID ${a} — sync will fail. Restore the pinned key.`,
  }
}

/** The live derivation: SHA-256 over the DER bytes (WebCrypto — async).
 * The battery cross-checks this against tools/identity-pin.mjs's node:crypto
 * answer for the same key (one math, two engines, zero drift). */
export async function deriveIdFromKey(b64Key) {
  const raw = atob(String(b64Key || ''))
  const bytes = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  const hex = [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 32)
  return [...hex].map((c) => ID_ALPHABET[parseInt(c, 16)]).join('')
}

/** The connect-door preflight: derive the pinned ID from the RUNNING
 * manifest's own key and compare it to chrome.runtime.id. If either half is
 * unavailable the verdict is fail-closed with the honest "cannot verify"
 * sentence — a door whose identity is unproven never opens quietly. */
export async function idDriftPreflight() {
  const chromeLike = typeof chrome !== 'undefined' ? chrome : null
  const manifest = chromeLike && chromeLike.runtime && chromeLike.runtime.getManifest ? chromeLike.runtime.getManifest() : null
  const runtimeId = chromeLike && chromeLike.runtime && chromeLike.runtime.id ? String(chromeLike.runtime.id) : ''
  if (!manifest || !manifest.key || !runtimeId || typeof crypto === 'undefined' || !crypto.subtle) {
    return { ok: false, drifted: false, runningId: runtimeId, derivedId: '', sentenceKey: 'idDoctorRowOk', subs: [], sentence: 'The pinned identity could not be verified on this browser — sync stays disabled until the manifest key can be checked.' }
  }
  const derivedId = await deriveIdFromKey(manifest.key)
  return idDriftVerdict(runtimeId, derivedId)
}
