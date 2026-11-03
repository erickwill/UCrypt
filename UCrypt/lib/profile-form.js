/**
 * UCrypt — Profile form semantics (v2.42.8 — R71-P).
 *
 * CSA/CSE AMENDMENT R71-P: protected profile autofill and EXPLICIT profile
 * capture. This module is the pure, unit-tested heart of the conservative
 * semantic classifier. The content script adapts live DOM nodes into plain
 * descriptors and calls these functions — every decision (is this a profile
 * field? is this form capture-eligible? create/update/duplicate?) is made
 * HERE so it can be tested without a browser.
 *
 * Storage model (R71-P §2 — physical audit): a profile IS one encrypted
 * `type:'address'` vault entry (ADDRESS_KEYS: name/email/phone/org/street/
 * city/state/zip/country [+ ssn, MANUAL-MANAGER-ONLY]). No new type, no
 * schema change, no migration. Semantic field keys exist in memory only,
 * per page, and are never persisted — no template records, no duplicated
 * values, nothing that could drift.
 *
 * Boundaries (R71-P §3/§6 — non-negotiable):
 *   - autocomplete tokens FIRST (the standards answer), bounded heuristics
 *     second, a MANDATORY confidence threshold everywhere;
 *   - passwords, login identifiers, OTP, search, payment, bank, government
 *     ID, security answers and medical hints are on an explicit reject list;
 *   - `ssn` is NEVER a capturable field (manual manager entry only);
 *   - low confidence → no offer, no capture (manual manager routes remain).
 */

// --- Semantic field tables ---------------------------------------------------
//
// Each kind: [key, autocomplete tokens, id/name hint regex, label hint regex]
// The id/name hints run before the label hints (a field named "email_label"
// must not match the "name" kind — same ordering lesson as the R28 picker).

const PROFILE_FIELD_KINDS = [
  ['email', 'email', /(^|[^a-z])(e-?mail|mail)([^a-z]|$)/i, /e-?mail/i],
  ['phone', 'tel', /(^|[^a-z])(phone|mobile|cell|tel\b|telephone)([^a-z]|$)/i, /(phone|mobile|cell|telephone)/i],
  ['org', 'organization', /(^|[^a-z])(org|company|business|employer|firm|institution)([^a-z]|$)/i, /(organization|company|employer|business|institution)/i],
  ['zip', 'postal-code', /(zip|postal|post-?code|pin-?code|postcode)/i, /(zip|postal code|post code|pin code)/i],
  ['country', 'country country-name', /(country|nation|region-?sel)/i, /country/i],
  ['state', 'address-level1', /(state|province|region|county)(?![a-z])/i, /(state|province|region)(?![a-z])/i],
  ['city', 'address-level2', /(city|town|locality|suburb)(?![a-z])/i, /(city|town|locality)(?![a-z])/i],
  ['street', 'street-address address-line1', /(street|address-?line-?1|address-?1|addr-?1|street-?address|address)(?![a-z])/i, /(street|address)(?![a-z])/i],
  ['street2', 'address-line2', /(address-?line-?2|address-?2|addr-?2|apt|apartment|suite|unit)(?![a-z])/i, /(apartment|apt\b|suite|unit|address line 2)/i],
  ['fullName', 'name given-name family-name additional-name honorific-prefix honorific-suffix', /(^|[^a-z])(full-?name|your-?name|first-?last|first-?name|last-?name|given-?name|surname|family-?name)([^a-z]|$)/i, /(full name|your name|first name|last name|given name|family name|surname)/i],
]

/** Semantic keys that map into the vault `address` object on capture. */
const CAPTURE_ADDRESS_KEYS = ['name', 'email', 'phone', 'org', 'street', 'city', 'state', 'zip', 'country']

/** Field kinds offered by the PROFILE FILL picker (street2 folds into street). */
const FILL_FIELD_KINDS = ['fullName', 'givenName', 'familyName', 'email', 'phone', 'org', 'street', 'street2', 'city', 'state', 'zip', 'country']

// --- Reject list (R71-P §3) ---------------------------------------------------
//
// A field matching ANY of these is never a profile field — not for fill,
// not for capture. The form-level scan additionally refuses to CAPTURE when
// any visible field matches a sensitive category (a checkout with a card
// number may still be FILLED field-by-field, but never saved as a profile).

const REJECT_FIELD = [
  // credentials & identifiers
  /pass(word|wort)?/i, /\buser(name|id)?\b/i, /\blogin\b/i, /sign-?in-?email-?only/i,
  /otp\b|one[- ]?time|2fa|authenticator|verification[- ]?code|captcha|recaptcha/i,
  /search|query\b/i,
  // payment
  /cc-?(num|number|csc|cvv|cvc|exp)|card-?(num|number|code|verif)|\bcvv\b|\bcvc\b|cardholder/i,
  /\biban\b|bank(-| )?account|routing[- ]?number|sort[- ]?code|swift\b/i,
  // government / identity documents
  /\bssn\b|social[- ]?sec(urity)?|tax[- ]?(id|number)| VAT\b|\bvat[- ]?num|gover(nment)?[- ]?id|\bpassport\b|identity[- ]?card|driver'?s[- ]?lic|licen[cs]e[- ]?num/i,
  // security questions / secrets
  /security[- ]?(answer|question)|secret[- ]?(answer|question)|mother'?s[- ]?maiden|\bpin\b/i,
  // medical / arbitrary sensitive
  /\bdiagnos|symptom|medic(ation|al)\b|health[- ]?(cond|record)/i,
]

const REJECT_FORM_CATEGORIES = [
  ...REJECT_FIELD,
  /gift[- ]?card/i, /\bcoupon\b/i,
]

/** Autocomplete tokens that mark a login identifier — hard reject. */
const REJECT_AUTOCOMPLETE = new Set([
  'username', 'current-password', 'new-password', 'password', 'one-time-code',
  'cc-number', 'cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-name',
])

// --- Confidence model ----------------------------------------------------------

/** Confidence per evidence source. Threshold is mandatory (R71-P §3). */
const CONFIDENCE = {
  AUTOCOMPLETE: 1.0, // the spec answer
  ID_NAME: 0.7,      // machine-readable name/id heuristics
  LABEL: 0.6,        // human-readable label/aria/placeholder heuristics
}

/** Minimum confidence for a single field to be offered for fill. */
const FILL_MIN_CONFIDENCE = 0.6
/** Minimum MEAN confidence across recognized fields for capture eligibility. */
const CAPTURE_MIN_MEAN_CONFIDENCE = 0.55
/** Minimum recognized (user-typed) fields for a capture prompt. */
const CAPTURE_MIN_FIELDS = 3

const FILLABLE_INPUT_TYPES = new Set(['text', 'email', 'tel', 'number', 'search-false', ''])
// 'search-false' is never a real type — keeps the set honest without empty-string bugs.

/**
 * A plain field descriptor the content script builds from a DOM node.
 * All fields optional; unknown values simply lower the evidence.
 * @typedef {Object} FieldDescriptor
 * @property {string} [tagName]        'INPUT' | 'TEXTAREA' | 'SELECT'
 * @property {string} [type]           input type
 * @property {string} [autocomplete]   raw attribute value
 * @property {string} [name]
 * @property {string} [id]
 * @property {string} [label]          label text (visible text evidence)
 * @property {string} [ariaLabel]
 * @property {string} [placeholder]
 * @property {boolean} [visible]
 * @property {boolean} [disabled]
 * @property {boolean} [readOnly]
 */

/**
 * Classify ONE field descriptor against the profile kind tables.
 * @returns {{key: string, confidence: number, source: 'autocomplete'|'id-name'|'label'} | null}
 */
function classifyProfileField(fd) {
  const d = fd && typeof fd === 'object' ? fd : {}
  const tagName = String(d.tagName || 'INPUT').toUpperCase()
  const type = String(d.type || '').toLowerCase()
  if (d.disabled || d.readOnly) return null
  if (d.visible === false) return null
  if (tagName === 'INPUT' && !FILLABLE_INPUT_TYPES.has(type)) return null
  if (tagName !== 'INPUT' && tagName !== 'TEXTAREA' && tagName !== 'SELECT') return null
  // SELECT elements are country/state pickers on real forms — only those two
  // kinds may come from a <select> (a <select> named "email" is not an email box).
  const selectOk = tagName !== 'SELECT'

  const toks = String(d.autocomplete || '').toLowerCase().split(/\s+/).filter(Boolean)
  for (const t of toks) {
    if (REJECT_AUTOCOMPLETE.has(t)) return null // login/payment autocomplete — hard reject
  }

  // 1. autocomplete — the standards answer wins outright. given-name /
  //    family-name / additional-name refine into their own keys so pages with
  //    split name boxes fill BOTH halves of the stored full name.
  for (const [key, tokens] of PROFILE_FIELD_KINDS.map(k => [k[0], k[1]])) {
    for (const tok of tokens.split(' ')) {
      if (toks.includes(tok)) {
        if (!selectOk && key !== 'country' && key !== 'state') return null
        if (key === 'fullName' && toks.includes('given-name')) {
          return { key: 'givenName', confidence: CONFIDENCE.AUTOCOMPLETE, source: 'autocomplete' }
        }
        if (key === 'fullName' && (toks.includes('family-name') || toks.includes('additional-name'))) {
          return { key: 'familyName', confidence: CONFIDENCE.AUTOCOMPLETE, source: 'autocomplete' }
        }
        return { key, confidence: CONFIDENCE.AUTOCOMPLETE, source: 'autocomplete' }
      }
    }
  }

  const idish = [d.name, d.id].filter(Boolean).join(' ')
  const labelish = [d.label, d.ariaLabel, d.placeholder].filter(Boolean).join(' ')
  const rejectHay = `${idish} ${labelish}`
  for (const re of REJECT_FIELD) {
    if (re.test(rejectHay)) return null
  }

  // 2. machine-readable name/id first, 3. human labels second.
  for (const [key, , idHint, labelHint] of PROFILE_FIELD_KINDS) {
    if (idHint.test(idish)) {
      if (!selectOk && key !== 'country' && key !== 'state') return null
      return { key, confidence: CONFIDENCE.ID_NAME, source: 'id-name' }
    }
  }
  for (const [key, , , labelHint] of PROFILE_FIELD_KINDS) {
    if (labelHint.test(labelish)) {
      if (!selectOk && key !== 'country' && key !== 'state') return null
      return { key, confidence: CONFIDENCE.LABEL, source: 'label' }
    }
  }
  return null
}

/** True when a visible field sits in a rejected sensitive category (form gate). */
function isSensitiveField(fd) {
  const d = fd && typeof fd === 'object' ? fd : {}
  const hay = [d.name, d.id, d.label, d.ariaLabel, d.placeholder, d.autocomplete]
    .filter(Boolean).join(' ')
  if (!hay) return false
  for (const re of REJECT_FORM_CATEGORIES) if (re.test(hay)) return true
  const toks = String(d.autocomplete || '').toLowerCase().split(/\s+/)
  for (const t of toks) if (REJECT_AUTOCOMPLETE.has(t)) return true
  return false
}

/**
 * Classify a whole form (pure). `descriptors` = plain field descriptors.
 * @returns {{ fields: Array<{index:number, key:string, confidence:number, source:string}>,
 *              meanConfidence: number, fillEligible: boolean, captureEligible: boolean,
 *              rejectedSensitive: number, keys: string[] }}
 */
function classifyProfileForm(descriptors) {
  const list = Array.isArray(descriptors) ? descriptors : []
  const fields = []
  let rejectedSensitive = 0
  list.forEach((fd, index) => {
    if (isSensitiveField(fd)) { rejectedSensitive += 1; return }
    const hit = classifyProfileField(fd)
    if (hit) fields.push({ index, key: hit.key, confidence: hit.confidence, source: hit.source })
  })
  // first kind wins per key (a page with two email boxes fills the first)
  const seen = new Set()
  const unique = fields.filter(f => (seen.has(f.key) ? false : (seen.add(f.key), true)))
  const mean = unique.length ? unique.reduce((s, f) => s + f.confidence, 0) / unique.length : 0
  const hasIdentity = unique.some(f => f.key === 'name' || f.key === 'email')
  return {
    fields: unique,
    keys: unique.map(f => f.key),
    meanConfidence: mean,
    fillEligible: unique.length >= 2 && mean >= FILL_MIN_CONFIDENCE - 1e-9,
    // R71-P §5.1/§6: a form containing ANY rejected sensitive category is
    // never a capture candidate — the gate lives HERE so every caller and
    // every test shares one rule.
    captureEligible: unique.length >= CAPTURE_MIN_FIELDS && hasIdentity &&
      mean >= CAPTURE_MIN_MEAN_CONFIDENCE - 1e-9 && rejectedSensitive === 0,
    rejectedSensitive,
  }
}

// --- Capture candidate builder (R71-P §5) -------------------------------------

/** Fold the semantic key set into the vault `address` object shape. */
function buildAddressFromPairs(pairs) {
  const addr = {}
  const byKey = new Map()
  for (const p of Array.isArray(pairs) ? pairs : []) {
    if (!p || typeof p.value !== 'string') continue
    // street2/givenName/familyName are capture-time keys folded into the
    // canonical address shape below (not ADDRESS_KEYS themselves).
    if (!CAPTURE_ADDRESS_KEYS.includes(p.key) && !['street2', 'givenName', 'familyName', 'fullName'].includes(p.key)) continue
    if (typeof p.value !== 'string') continue
    byKey.set(p.key, String(p.value))
  }
  let name = (byKey.get('name') || '').trim()
  if (!name) name = (byKey.get('fullName') || '').trim() // the classifier's combined-name key
  if (!name) {
    const given = (byKey.get('givenName') || '').trim()
    const family = (byKey.get('familyName') || '').trim()
    name = [given, family].filter(Boolean).join(' ')
  }
  if (name) addr.name = name.slice(0, 200)
  for (const k of ['email', 'phone', 'org', 'city', 'state', 'zip', 'country']) {
    const v = (byKey.get(k) || '').trim()
    if (v) addr[k] = v.slice(0, 200)
  }
  const street1 = (byKey.get('street') || '').trim()
  const street2 = (byKey.get('street2') || '').trim()
  const street = [street1, street2].filter(Boolean).join('\n')
  if (street) addr.street = street.slice(0, 200)
  return addr
}

/** Exact-duplicate check on the address payload (whitespace-normalized). */
function isDuplicateAddress(a, b) {
  const norm = (o) => {
    const out = {}
    for (const [k, v] of Object.entries(o && typeof o === 'object' ? o : {})) {
      const s = String(v || '').replace(/\s+/g, ' ').trim()
      if (s) out[k] = s
    }
    return out
  }
  const x = norm(a), y = norm(b)
  const kx = Object.keys(x), ky = Object.keys(y)
  if (kx.length !== ky.length) return false
  for (const k of kx) if (x[k] !== y[k]) return false
  return true
}

/** Changed keys between an existing address and a candidate (truthful update list). */
function changedAddressKeys(existing, candidate) {
  const keys = new Set([...Object.keys(existing || {}), ...Object.keys(candidate || {})])
  const changed = []
  for (const k of keys) {
    const a = String(existing?.[k] ?? '').replace(/\s+/g, ' ').trim()
    const b = String(candidate?.[k] ?? '').replace(/\s+/g, ' ').trim()
    if (a !== b) changed.push(k)
  }
  return changed
}

/**
 * Decide the capture action against the vault's existing address entries.
 * Existing entries: [{ username (title), address }]
 * @returns {{ mode: 'create'|'update'|'duplicate',
 *             target?: { domain: string, username: string },
 *             changedKeys: string[] }}
 */
function decideCapture(existingEntries, candidateAddress, title) {
  const list = Array.isArray(existingEntries) ? existingEntries : []
  for (const e of list) {
    if (isDuplicateAddress(e.address, candidateAddress)) {
      return { mode: 'duplicate', changedKeys: [] }
    }
  }
  const t = String(title || '').trim().toLowerCase()
  if (t) {
    const target = list.find(e => String(e.username || '').trim().toLowerCase() === t)
    if (target) {
      return {
        mode: 'update',
        target: { domain: String(target.domain || ''), username: String(target.username || '') },
        changedKeys: changedAddressKeys(target.address || {}, candidateAddress),
      }
    }
  }
  return { mode: 'create', changedKeys: [] }
}

// --- Fill helpers (R71-P §4.2) --------------------------------------------------

/** Split a stored full name into [given, rest] for given-name/family-name fields. */
function splitFullName(fullName) {
  const s = String(fullName || '').trim().replace(/\s+/g, ' ')
  if (!s) return { given: '', family: '' }
  const idx = s.indexOf(' ')
  if (idx < 0) return { given: s, family: '' }
  return { given: s.slice(0, idx), family: s.slice(idx + 1) }
}

/** Second line of a folded street ("line1\nline2") for address-line2 fields. */
function streetLine2(street) {
  const parts = String(street || '').split('\n')
  return parts.length > 1 ? parts.slice(1).join(' ').trim() : ''
}

/** First line of a folded street. */
function streetLine1(street) {
  return String(street || '').split('\n')[0].trim()
}

/** Bounded country-name normalization (safe select matching). */
const COUNTRY_ALIASES = new Map(Object.entries({
  'usa': 'United States', 'us': 'United States', 'united states of america': 'United States',
  'uk': 'United Kingdom', 'great britain': 'United Kingdom', 'britain': 'United Kingdom',
  'deutschland': 'Germany', 'germania': 'Germany',
  'brasil': 'Brazil', 'schweiz': 'Switzerland', 'oesterreich': 'Austria', 'österreich': 'Austria',
  'suisse': 'Switzerland', 'nederland': 'Netherlands', 'holland': 'Netherlands',
  '中国': 'China', '中国大陆': 'China', '英国': 'United Kingdom', '美国': 'United States',
  '德国': 'Germany', '法国': 'France', '日本': 'Japan',
}))

/**
 * Normalize a stored country/state value for select matching: trims, collapses
 * whitespace, applies the bounded alias table. Pure.
 */
function normalizeSelectValue(value) {
  const s = String(value || '').replace(/\s+/g, ' ').trim()
  if (!s) return ''
  const lower = s.toLowerCase()
  if (COUNTRY_ALIASES.has(lower)) return COUNTRY_ALIASES.get(lower)
  if (COUNTRY_ALIASES.has(s)) return COUNTRY_ALIASES.get(s)
  return s
}

/**
 * Nonsecret picker descriptor for one profile (closed-shadow only):
 * "<title>" is the primary; this builds the secondary — city/country or the
 * email — plus the field-group list ("Name, email, address").
 * @returns {{ descriptor: string, groups: string[] }}
 */
function profileDescriptor(address) {
  const a = address && typeof address === 'object' ? address : {}
  const groups = []
  if (a.name) groups.push('name')
  if (a.email) groups.push('email')
  if (a.phone) groups.push('phone')
  if (a.org) groups.push('org')
  if (a.street || a.city || a.state || a.zip || a.country) groups.push('address')
  const bits = []
  const place = [a.city, a.country].filter(Boolean).join(', ')
  if (place) bits.push(place)
  else if (a.email) bits.push(a.email)
  else if (a.org) bits.push(a.org)
  else if (a.phone) bits.push(a.phone)
  return { descriptor: bits.join(' · '), groups }
}

/** Map a semantic key to its field-group (for "which fields will be filled"). */
function fieldGroup(key) {
  switch (key) {
    case 'fullName': case 'givenName': case 'familyName': return 'name'
    case 'email': return 'email'
    case 'phone': return 'phone'
    case 'org': return 'org'
    case 'street': case 'street2': return 'address'
    case 'city': return 'address'
    case 'state': return 'address'
    case 'zip': return 'address'
    case 'country': return 'address'
    default: return ''
  }
}
// --- globalThis attach (R71-P) ------------------------------------------------
//
// Plain script (NOT an ES module) so it can be listed in manifest.json's
// content_scripts "js" array BEFORE content.js — content scripts cannot
// import ES modules. It attaches the API to globalThis.UCRYPT_PROFILE_FORM.
// Written as valid ESM-without-imports so the test harness can `import()`
// the very same file and assert against the exact code the page runs
// (single source of truth — no content-script inline mirror).
if (typeof globalThis !== 'undefined') {
  globalThis.UCRYPT_PROFILE_FORM = {
    PROFILE_FIELD_KINDS, CAPTURE_ADDRESS_KEYS, FILL_FIELD_KINDS,
    REJECT_FIELD, REJECT_AUTOCOMPLETE, CONFIDENCE,
    FILL_MIN_CONFIDENCE, CAPTURE_MIN_MEAN_CONFIDENCE, CAPTURE_MIN_FIELDS,
    classifyProfileField, isSensitiveField, classifyProfileForm,
    buildAddressFromPairs, isDuplicateAddress, changedAddressKeys, decideCapture,
    splitFullName, streetLine1, streetLine2, normalizeSelectValue,
    profileDescriptor, fieldGroup,
  }
}
