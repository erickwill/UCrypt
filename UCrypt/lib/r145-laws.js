/**
 * UCrypt — R145 §4.4 / §6.4 — THE TOAST LIFETIME LAW (G-9) and THE WORDS
 * PARSER (G-5). One module, two laws, both PURE.
 *
 * ══ THE LIFETIME LAW (G-9) ══════════════════════════════════════════════
 * The field showed ONE toast ("Pairing code copied — it carries the
 * words…") riding across three captures and 10+ minutes of use. Law:
 *
 *   • CONSENT SURFACES (anything asking the user to decide — save-login
 *     prompts, confirmations): NEVER auto-close. Only the user closes
 *     them. (The standing popup law — unchanged.)
 *   • STATUS TOASTS (copied / synced / saved / failed): auto-dismiss on a
 *     bounded timer — TOAST_STATUS_MS (6000 ms, ledgered in the close) —
 *     and the manual × always works.
 *   • A toast never survives a page reload as a zombie (the element starts
 *     hidden; no boot path re-opens an old toast).
 *
 * The two lifetimes are TYPED: 'status' (auto) vs 'consent' (never auto).
 *
 * ══ THE WORDS PARSER (G-5) ══════════════════════════════════════════════
 * The backup verification demanded four hand-typed words; the owner asked
 * for the paste-the-whole-list path. parsePastedWords() turns one pasted
 * blob (the 24 words in any whitespace/newline/comma layout) into the
 * positional map the existing check already speaks. Wrong count → a
 * plain-words error with the counted number. Bad characters → named, with
 * the position. The hand-typed path remains for those who prefer it.
 *
 * PURE — no chrome.*, no DOM. Battery-pinned (tests/r145-round.test.mjs:
 * valid, wrong count, extra whitespace, commas/newlines, bad characters,
 * uppercase normalization, 24 vs shorter codes).
 */

/** The bounded status-toast timer (the ledgered number — 6 s). */
export const TOAST_STATUS_MS = 6000

/** The typed toast kinds. 'consent' NEVER auto-closes; everything else is
 * a status toast and MUST auto-dismiss at TOAST_STATUS_MS. */
export const TOAST_KINDS = {
  STATUS: 'status',
  CONSENT: 'consent',
}

/** Map the legacy UI kinds ('info' | 'error' | 'ok') onto the typed law:
 * every legacy kind is a STATUS toast (auto-dismiss). Only an explicit
 * 'consent' kind (or a call-site migration) buys the never-close lifetime. */
export function toastLifetime(kind = 'info') {
  const k = String(kind || 'info')
  if (k === 'consent' || k === 'sticky') return { kind: TOAST_KINDS.CONSENT, autoDismissMs: null }
  return { kind: TOAST_KINDS.STATUS, autoDismissMs: TOAST_STATUS_MS }
}

/** The word-count law: the sync code is a 24-word code. */
export const SYNC_CODE_WORD_COUNT = 24

/**
 * Parse ONE pasted word list into the positional map.
 *
 * @param {string} text  the pasted blob (any whitespace/newline/comma layout)
 * @param {number[]} positions  the asked positions (1-based, e.g. [3,9,10,24])
 * @returns {{ ok: true, words: Record<string,string>, count: number } |
 *           { ok: false, reason: 'count'|'chars'|'empty', count: number, bad?: Array<{pos:number,word:string}> }}
 */
export function parsePastedWords(text, positions) {
  const raw = String(text || '')
  const asked = Array.isArray(positions) ? positions.map(Number).filter(Number.isFinite) : []
  const tokens = raw.split(/[\s,;·]+/).map((t) => t.trim().toLowerCase()).filter(Boolean)
  const count = tokens.length
  if (!count) return { ok: false, reason: 'empty', count: 0 }
  // the character law: the code's words are plain a–z (the wordlist is
  // lowercase English) — anything else is a paste artifact, named with its
  // position in the PASTED list
  const bad = []
  tokens.forEach((t, i) => {
    if (!/^[a-z]+$/.test(t)) bad.push({ pos: i + 1, word: t.slice(0, 24) })
  })
  if (bad.length) return { ok: false, reason: 'chars', count, bad }
  // R145 §6.4 — THE TWO LAWFUL PASTES (the CEO's exact ask: "paste that
  // entire list of words provided at the beginning"):
  //   1. THE WHOLE PHRASE (count === 24): position p takes token p — the
  //      paste IS the code, the asked positions index INTO it.
  //   2. JUST THE ASKED WORDS (count === asked.length): the k-th token
  //      fills the k-th asked position.
  // Anything else is a count error, in plain words, with the number.
  const words = {}
  if (count === SYNC_CODE_WORD_COUNT && asked.length && asked.length <= count) {
    for (const p of asked) words[String(p)] = tokens[p - 1] || ''
    return { ok: true, words, count, mode: 'whole-phrase' }
  }
  if (asked.length && count === asked.length) {
    asked.forEach((p, i) => { words[String(p)] = tokens[i] || '' })
    return { ok: true, words, count, mode: 'asked-words' }
  }
  return { ok: false, reason: 'count', count }
}

/** The plain-words error for a wrong count (the counted number named). */
export function wordCountMessage(count, expected = SYNC_CODE_WORD_COUNT) {
  return `That is ${count} word${count === 1 ? '' : 's'} — the code has ${expected}. Paste the whole list from your written-down copy.`
}
