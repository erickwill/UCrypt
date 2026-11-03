/**
 * ════════════════════════════════════════════════════════════════════════
 * R171 — THE HONEST ERROR LAW (the E-24 cure's leaf machine).
 *
 * The field spoke (E-24): the Cloud backup card printed the literal string
 * "[object Promise]" to the owner — a non-awaited async value had reached a
 * user-facing message. The law now reads: NO Promise, and no non-string
 * object, may EVER reach a user-facing message.
 *
 * This leaf is the ONE materializer every writer and renderer rides:
 *   - a Promise can never resolve meaningfully at render time → it is
 *     named honestly (a typed generic — never its engine shape);
 *   - an Error/objects with a string .message/.userMessage donate that
 *     string (the typed words survive);
 *   - any other object is named by its constructor class, never String(obj)
 *     (whose "[object …]" shape is the defect itself);
 *   - strings ride byte-true (trimmed, bounded).
 *
 * ENGINE-ONLY: zero imports, zero DOM, zero chrome — the battery drives it
 * directly and the sweep tool (tools/r171-honest-error-sweep.mjs) proves no
 * user-facing interpolation seat bypasses it. The twin permanent rule: the
 * string "[object" may never appear in shipped copy (the sweep's literal
 * gate).
 *
 * R176 — THE LIVING CUSTODY (two laws land here):
 *   R-176.3 THE TYPED JOURNEY — carry(): no re-throw may strip a typed
 *     error. Any relay of an error preserves kind, userMessage, and the
 *     fingerprint; constructing a new Error from an old one is lawful only
 *     through carry. ONE materialization, many readers.
 *   R-176.4 THE UNCONDITIONAL RENDER BELT — coverage is proven at the LAST
 *     seat, not claimed at the write seats. The thenable branch (the R174
 *     pin's bare branch — the field's E-35/E-36/E-37 bare row rode it) now
 *     carries its own shape fingerprint: bare HONEST_ERROR_GENERIC becomes
 *     structurally unreachable from the materializer. beltRender() is the
 *     render seats' one door: materialize, then verify a family name rides;
 *     an unnamed arrival is fingerprinted AT PAINT (constructor, code,
 *     keys, bounded sanitized JSON).
 * ════════════════════════════════════════════════════════════════════════
 */

/** The typed generic (i18n seats localize around it; the worker's English
 * words are the canonical fallback). Never contains engine shapes. */
export const HONEST_ERROR_GENERIC = 'The error message could not be read — press Test connection for the live verdict.'

/** The materializer — PURE, total (never throws, never returns undefined).
 * @param {unknown} v the raw value a seat wants to show a human
 * @param {{cap?: number, generic?: string}} [opts]
 * @returns {string} a honest, human-readable, bounded string
 */
export function materializeUserText(v, opts = null) {
  const cap = Math.max(8, Math.min(400, Number(opts && opts.cap) || 200))
  const generic = String((opts && opts.generic) || HONEST_ERROR_GENERIC)
  // 1. Strings ride byte-true (the happy path — the law's zero-cost case).
  if (typeof v === 'string') {
    const s = v.trim()
    if (s) return s.slice(0, cap)
    // R175 — THE NAMED UNKNOWN: an empty string is a failure shape too —
    // it names its emptiness instead of rendering the bare wall.
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  // 2. A Promise (or any thenable) can NEVER render meaningfully — the E-24
  //    defect's exact shape. Name it honestly, never "[object Promise]".
  //    R176 — R-176.4 supersedes the R174 bare pin (the map's Adjudication 3):
  //    the thenable branch was the ONE class that still rendered the bare
  //    generic, and the field hit it twice (the 21:51 ×2 and 22:08 rows). A
  //    thenable rejection now arrives CARRYING its own shape evidence — the
  //    constructor class and the awaited-value's own words when it carries a
  //    reason. Bare generic is structurally unreachable.
  if (v instanceof Promise || (v !== null && typeof v === 'object' && typeof v.then === 'function')) {
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  // 3. Errors and error-shaped objects donate their typed words.
  if (v instanceof Error) {
    const m = String(v.message || '').trim()
    if (m) return m.slice(0, cap)
    // R175 — THE NAMED UNKNOWN: a message-less Error (a DOMException with an
    // empty message, a constructed Error without words) never renders bare —
    // its shape donates the evidence (name, code, cause chain).
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  if (v !== null && typeof v === 'object') {
    const donated = String((v.userMessage && typeof v.userMessage === 'string' ? v.userMessage : '') ||
      (v.message && typeof v.message === 'string' ? v.message : '') ||
      (v.error && typeof v.error === 'string' ? v.error : '') ||
      (v.reason && typeof v.reason === 'string' ? v.reason : '')).trim()
    if (donated) return donated.slice(0, cap)
    // 4. Any other object: the honest generic CARRYING ITS OWN FINGERPRINT
    //    (R-175.2) — never String(obj) (whose "[object …]" shape is the
    //    defect itself), never bare (the field's evidence-free wall).
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  // 5. Numbers/booleans/bigints: their honest string form CARRYING THE
  //    FINGERPRINT (R-175.2's total taxonomy — a bare "42" names nothing;
  //    "the failure was the value 42" names its shape).
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') {
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  if (typeof v === 'undefined' || v === null) {
    // R175 — THE NAMED UNKNOWN: a null/undefined rejection names its emptiness.
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  if (typeof v === 'function' || typeof v === 'symbol') {
    // R175 — THE NAMED UNKNOWN: a function/symbol rejection names its shape
    // (never String(fn)'s engine source, never String(sym)'s throw).
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
  try { return String(v).slice(0, cap) } catch {
    return (generic + ' — ' + fingerprintShape(v)).slice(0, Math.max(cap, 240))
  }
}

/** True when a value would have poisoned a message (the sweep's runtime twin). */
export function isPoisonedUserValue(v) {
  if (v instanceof Promise) return true
  if (v !== null && typeof v === 'object' && typeof v.then === 'function') return true
  return false
}

// ══════════════════════════════════════════════════════════════════════
// R176 — R-176.3 THE TYPED JOURNEY: carry(). The field proved the type can
// be BORN (the expiry card proves the auth family was known) and then LOST
// (the push catch rendered bare) between the birth seat and the reader
// seats. The law: no re-throw may strip a typed error. carry() is the ONE
// lawful relay: it preserves kind, userMessage, and the shape fingerprint
// on the carried error; a wrapper that must construct a new error donates
// the old one as the cause and copies the typed fields — the type travels
// from birth to every eye.
// ══════════════════════════════════════════════════════════════════════

/**
 * Relay ONE error to the next consumer WITHOUT stripping its type (R-176.3).
 * PURE-ish (never throws; returns a value the caller throws onward).
 *   - carry(e) with no wrapper        → e itself (identity — the typed fields
 *                                       ride by reference; the zero-cost case)
 *   - carry(e, { wrap: 'new words' }) → a new Error whose message is the
 *                                       wrapper's words, with kind/userMessage
 *                                       COPIED from e, e riding as .cause, and
 *                                       the carried fingerprint stamped — the
 *                                       type survives the wrap byte-true.
 * @param {unknown} e the caught value
 * @param {{ wrap?: string, from?: string }} [opts]
 * @returns {unknown} the value to throw onward
 */
export function carry(e, opts = null) {
  const from = String((opts && opts.from) || '').slice(0, 60)
  const wrapWords = String((opts && opts.wrap) || '').trim()
  if (!wrapWords) {
    // Identity relay: the typed fields ride by reference. When the relay
    // seat is named, the journey is STAMPED on the error (diagnostics read
    // the hop chain; the type itself is untouched).
    if (from && e && typeof e === 'object' && !e.carriedFrom) {
      try { e.carriedFrom = from } catch { /* the stamp never throws */ }
    }
    return e
  }
  const src = (e && typeof e === 'object') ? e : {}
  const kind = typeof src.kind === 'string' && src.kind ? src.kind : ''
  const userMessage = typeof src.userMessage === 'string' && src.userMessage ? src.userMessage : ''
  const out = new Error(wrapWords)
  if (kind) out.kind = kind
  if (userMessage) out.userMessage = userMessage
  out.cause = e
  out.carriedFrom = from
  out.carriedFingerprint = fingerprintShape(e)
  return out
}

// ══════════════════════════════════════════════════════════════════════
// R176 — R-176.4 THE UNCONDITIONAL RENDER BELT. Coverage is proven at the
// LAST seat — the one before the owner's eyes. Every owner-facing render of
// an error string rides beltRender(): materialize, then PROVE a family name
// rides. An unnamed arrival (a value whose materialization would be the
// bare generic) is fingerprinted AT PAINT — constructor, code, keys, the
// bounded sanitized JSON. Bare HONEST_ERROR_GENERIC becomes structurally
// unreachable at the belt: even a shape every write seat missed still
// arrives carrying evidence.
// ══════════════════════════════════════════════════════════════════════

/**
 * The render belt (R-176.4) — the LAST seat before the owner's eyes.
 * @param {unknown} v the raw value a render seat wants to show a human
 * @param {{ cap?: number, generic?: string }} [opts]
 * @returns {string} a bounded, human-readable string that ALWAYS carries a
 *   family name (never the bare generic)
 */
export function beltRender(v, opts = null) {
  const cap = Math.max(8, Math.min(400, Number(opts && opts.cap) || 200))
  const words = materializeUserText(v, { cap, generic: (opts && opts.generic) || undefined })
  // The belt's proof: a non-empty string whose body is exactly the bare
  // generic (the historical bare shape) is an UNNAMED ARRIVAL — fingerprint
  // it AT PAINT. (After the materializer's R176 cure this branch is
  // belt-and-braces: the proof lives here so a future regression cannot
  // reopen the bare wall.)
  const generic = String((opts && opts.generic) || HONEST_ERROR_GENERIC)
  const trimmed = words.trim()
  if (trimmed === generic.trim()) {
    const fp = fingerprintShape(v)
    const tail = fp ? fp + ' (the render belt fingerprinted this unnamed arrival)' : 'the row was written before the render belt — the next cycle writes a fresh, fingerprinted row'
    return (generic + ' — ' + tail).slice(0, Math.max(cap, 260))
  }
  return words
}

// ════════════════════════════════════════════════════════════════════════
// R175 — THE NAMED UNKNOWN (R-175.2, the E-31/E-32/E-34 cure). The field
// proved the last-resort branch itself bare: "The error message could not be
// read" rendered with ZERO evidence attached — a failure with no type is a
// failure the house cannot see (R-172.7 violated at the last branch). The
// law: the materializer's last resort becomes family UNKNOWN + a SANITIZED
// FINGERPRINT — constructor name, code/status properties, own key NAMES, a
// bounded sanitized JSON slice — so even a shape the house has never seen
// arrives CARRYING evidence. The taxonomy reaches TOTAL coverage: null,
// undefined, empty string, numbers/booleans/bigints, plain objects,
// DOMException, message-less Errors, nested causes (thenables already
// extinct, R174 — their bare-generic pin stays byte-true: a promise's shape
// carries no evidence to fingerprint).
//
// SANITATION LAW: the fingerprint carries FIELD NAMES and bounded built-in
// values only — never credential material, never unbounded payloads. Every
// piece is clamped; the composed fingerprint is bounded by the cap.
// ════════════════════════════════════════════════════════════════════════

const _clamp = (s, n) => String(s).slice(0, Math.max(1, n))

/** The sanitized shape fingerprint (PURE, total, never throws).
 * @param {unknown} v the raw failure shape
 * @returns {string} a bounded, human-readable, secret-free fingerprint
 */
export function fingerprintShape(v) {
  try {
    if (v === null) return 'the failure carried no value (null)'
    if (typeof v === 'undefined') return 'the failure carried no value (undefined)'
    if (typeof v === 'string') return v.trim() ? '' : 'the failure was an empty message'
    if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') return `the failure was the value ${_clamp(String(v), 40)}`
    if (typeof v === 'function') return 'the failure was a function (not an error value)'
    if (typeof v === 'symbol') return 'the failure was a symbol (its engine name is intentionally not printed)'
    // R176 — R-176.4: the thenable class donates its shape evidence too (the
    // R174 bare pin's branch — the field's E-35/E-36/E-37 bare row rode it).
    // The constructor class + the awaited-value's own words (when the
    // thenable carries a readable .message/.userMessage — a hybrid shape)
    // arrive AT PAINT; the promise's value itself is never awaited at render
    // time (the E-24 law holds — a Promise can never resolve meaningfully
    // for the eye) and no token/secret can ride (only the shape speaks).
    if (v instanceof Promise || (v && typeof v === 'object' && typeof v.then === 'function')) {
      const pctor = _clamp((v && v.constructor && v.constructor.name) || 'Promise', 40)
      const donated = String((v && typeof v.message === 'string' && v.message) || '').trim()
      const pk = (() => { try { const ks = Object.keys(v || {}).slice(0, 6); return ks.length ? `keys: ${ks.map((k) => _clamp(k, 24)).join(',')}` : '' } catch { return '' } })()
      const bits = [`a thenable (${pctor}) arrived where words belong — its words could not be awaited`]
      if (donated) bits.push(`note: ${_clamp(donated, 80)}`)
      if (pk) bits.push(pk)
      return bits.join('; ')
    }
    // DOMException / Error shapes: the name + the typed codes donate evidence
    // even when the message is empty (the taxonomy's message-less class).
    const ctor = _clamp((v && v.constructor && v.constructor.name) || (v instanceof Error ? 'Error' : ''), 40)
    const parts = []
    if (ctor) parts.push(ctor)
    const name = typeof v.name === 'string' && v.name && v.name !== ctor ? _clamp(v.name, 40) : ''
    if (name) parts.push(`name ${name}`)
    if (v.code !== undefined && v.code !== null && v.code !== '') parts.push(`code ${_clamp(String(v.code), 20)}`)
    if (v.status !== undefined && v.status !== null && v.status !== '') parts.push(`status ${_clamp(String(v.status), 20)}`)
    // Nested cause (the walked chain — bounded depth, each hop named).
    let causeNote = ''
    let hop = v && (v.cause || v.reason)
    for (let depth = 0; hop != null && depth < 3; depth++) {
      const hopWords = typeof hop === 'string'
        ? _clamp(hop.trim(), 80)
        : String((hop && (hop.message || hop.userMessage)) || '') && _clamp(String(hop.message || hop.userMessage), 80)
      if (hopWords) { causeNote = hopWords; break }
      hop = (hop && (hop.cause || hop.reason)) || null
    }
    // Own enumerable key NAMES (never values) — the shape's own anatomy.
    let keys = ''
    try {
      const ks = Object.keys(v || {}).filter((k) => k !== 'message' && k !== 'userMessage' && k !== 'cause' && k !== 'reason' && k !== 'stack').slice(0, 8)
      if (ks.length) keys = `keys: ${ks.map((k) => _clamp(k, 24)).join(',')}`
    } catch { /* keys are best-effort evidence */ }
    // A bounded sanitized JSON slice for plain objects (field names + safe
    // scalars only — functions/thenables/symbols never survive stringify;
    // the slice bounds any nested payload).
    let slice = ''
    if (ctor === 'Object' || !ctor) {
      try {
        const j = JSON.stringify(v, (k, val) => {
          if (typeof val === 'function' || typeof val === 'symbol') return undefined
          if (typeof val === 'string') return _clamp(val, 48)
          return val
        })
        if (j && j !== '{}' && j.length > 2) slice = _clamp(j, 160)
      } catch { /* a circular or hostile shape keeps the keys row only */ }
    }
    const bits = []
    if (parts.length) bits.push(`shape: ${parts.join(', ')}`)
    if (keys) bits.push(keys)
    if (slice) bits.push(`detail: ${slice}`)
    if (causeNote) bits.push(`cause: ${causeNote}`)
    return bits.length ? `the failure could not be named (${bits.join('; ')})` : 'the failure could not be named (its shape carried no readable evidence)'
  } catch { return 'the failure could not be named (its shape resisted inspection)' }
}

/** True when the value is one of the taxonomy's UNNAMED classes (the exact
 * shapes whose generic rendering was the field's bare wall). */
export function isUnnamedFailureShape(v) {
  if (v === null || typeof v === 'undefined') return true
  if (typeof v === 'string') return v.trim() === ''
  if (typeof v === 'function' || typeof v === 'symbol') return true
  // R176 — R-176.4: the thenable class is an UNNAMED arrival now (its bare
  // rendering was the field's wall; the belt fingerprints it at paint).
  if (v instanceof Promise || (v && typeof v === 'object' && typeof v.then === 'function')) return true
  if (v instanceof Error) return String(v.message || '').trim() === ''
  if (typeof v === 'object') {
    const donated = v && typeof v === 'object' &&
      ((typeof v.userMessage === 'string' && v.userMessage) ||
       (typeof v.message === 'string' && v.message) ||
       (typeof v.error === 'string' && v.error) ||
       (typeof v.reason === 'string' && v.reason))
    return !donated
  }
  return false
}

// ════════════════════════════════════════════════════════════════════════
// R174 — THE STRING-POISON HEAL (R-174.4, the A3 cure). The field proved
// (E-30's 10:41 row) that the ONLY poison class which SURVIVES storage is a
// STRING — a pre-R171 writer baked "[object Promise]" into the row via
// String(thenable), and every later layer (heal, render) passed strings
// byte-true. The heal names the pattern and rewrites it to the typed
// generic; the self-heal (lib/vault.js) rides it at the next worker wake.
// ════════════════════════════════════════════════════════════════════════

/** The poison pattern: the "[object …]" engine shape (String(thenable) is
 * "[object Promise]"; String(plainObject) is "[object Object]"). */
export const POISONED_STRING_RE = /\[object\s+[A-Za-z_$][\w$]*\]/

/**
 * The storage-depth heal for ONE user-facing text field (PURE, total).
 * A poisoned STRING renders the typed generic; a healthy string rides
 * byte-true; a non-string donates through the materializer.
 * @param {unknown} v the stored field value
 * @param {{cap?: number, generic?: string}} [opts]
 * @returns {string} the healed, human-readable, bounded string
 */
export function healPoisonedUserText(v, opts = null) {
  const generic = String((opts && opts.generic) || HONEST_ERROR_GENERIC)
  if (typeof v === 'string') {
    const s = v.trim()
    if (POISONED_STRING_RE.test(s)) return generic.slice(0, Math.max(8, Math.min(400, Number(opts && opts.cap) || 200)))
    return (s ? s : generic).slice(0, Math.max(8, Math.min(400, Number(opts && opts.cap) || 200)))
  }
  return materializeUserText(v, { cap: (opts && opts.cap) || 200, generic })
}
