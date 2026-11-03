/**
 * UCrypt — Canonical secret generator (R72 Generator Lab core).
 *
 * Exports:
 *   - generateRandomPassword(opts)
 *   - generatePassphrase(opts)
 *   - generatePin(opts)
 *   - generatePronounceable(opts)
 *   - generateMnemonic(opts) / validateMnemonic(phrase)     [R72]
 *   - generateSecret({ mode, options, source })             [R72 canonical entry]
 *   - extractWordlistFromText(text) / validateWordlistUrl(u)[R72 worker helpers]
 *   - pickSeparator(), PRESETS
 *
 * Each generator returns { value, entropyBits, kind, ... }.
 *
 * All randomness comes from crypto.getRandomValues with rejection sampling
 * (zero modulo bias) via the helpers in crypto.js — the ONE random primitive
 * in UCrypt. No fallback RNG exists anywhere in the product.
 *
 * R72 fixes (audited in docs/generator-lab-r72-feature-map.md):
 *   A. generateRandomPassword no longer shuffles AFTER enforcing adjacency
 *      constraints (the final shuffle could reintroduce prohibited adjacent
 *      sequences — the exact CryptKey bug the R72 order forbids). Required
 *      class chars are placed at random positions first, the body is filled
 *      with live constraint checks against BOTH neighbors, and a final
 *      verification pass re-runs the whole string with bounded retries.
 *   B. generatePassphrase no longer silently reverts to the unfiltered list
 *      when word filters leave too few words — it throws a structured
 *      PassphraseFilterError (code FILTER_TOO_NARROW) so the UI can offer the
 *      explicit relax-or-cancel choice.
 *   C. generatePronounceable reports the EXACT entropy of its construction
 *      (the 2/3-probability coda model is now priced honestly) instead of the
 *      previous over-claim.
 *   D. PIN entropy is computed EXACTLY for the enabled constraints via a
 *      digit-transition DP (count of valid length-n PINs), so the shown bits
 *      are the true alphabet size of the constrained space, with the honest
 *      "PINs are lower entropy" warning carried in metadata.
 *
 * Wordlists are loaded from wordlists.js (globalThis.CRYPTKEY_WORDLISTS) and
 * the BIP-39 corpus from lib/bip39.js (globalThis.CRYPTKEY_BIP39) — the SAME
 * canonical bundles used by sync-code generation; no duplicate corpus exists.
 */

import { secureRandomInt, secureRandomIntRange, securePick, secureShuffle, secureRandomBytes, sha256 } from './crypto.js'

// --- Character pools --------------------------------------------------------

const AMBIGUOUS = new Set('lI1O0oS5B8G6Z2|`\''.split(''))

const POOLS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
}

// Pronounceable syllable building blocks
const ONSETS = [
  'b','c','d','f','g','h','j','k','l','m','n','p','q','r','s','t','v','w','x','y','z',
  'ch','sh','th','ph','wh','br','cr','dr','fr','gr','pr','tr','bl','cl','fl','gl',
  'pl','sl','sc','sk','sm','sn','sp','st','sw','qu','kr','ks','tw'
]
const NUCLEI = [
  'a','e','i','o','u','y','ae','ai','ao','au','ea','ee','ei','eo','eu','ia','ie',
  'io','iu','oa','oe','oi','oo','ou','ua','ue','ui','uo'
]
const CODAS = [
  'b','c','d','f','g','h','k','l','m','n','p','r','s','t','v','w','x','y','z',
  'ch','sh','th','ph','ng','nk','nt','nd','st','sk','sp','ld','lt','lf','lv','rd',
  'rt','rm','rn','rs','rk','rl','mp','mb','ct','ft','pt','ll','nn','rr','tt','gg',
  'dd','ff','pp','bb','mm'
]
// Exact probability the syllable model gives its coda (2 of 3 picks carry one).
const CODA_PROB = 2 / 3

const DEFAULT_SEPARATORS = ['-', '_', '.', ' ', '#', '+', '|', ':', '/', ',', ';']

/** R72 §2.3 — the canonical separator set the Lab UI offers. */
export const PASSPHRASE_SEPARATORS = ['-', '.', '_', ' ', '', '+', '/']

// --- Helpers ----------------------------------------------------------------

function getWordlists() {
  return globalThis.CRYPTKEY_WORDLISTS || { 'short-1': [], 'short-2': [], 'large': [] }
}

function filterAmbiguous(input) {
  return [...input].filter(c => !AMBIGUOUS.has(c)).join('')
}

function applyExcludeChars(str, excludeChars) {
  if (!excludeChars) return str
  const ex = new Set(excludeChars.split(''))
  return [...str].filter(c => !ex.has(c)).join('')
}

function isSequential(prev, next) {
  if (!prev) return false
  const a = prev.charCodeAt(0)
  const b = next.charCodeAt(0)
  return a + 1 === b || a - 1 === b || prev === next
}

/** Binary entropy of a Bernoulli(p) variable. */
function h2(p) {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log2(p) - (1 - p) * Math.log2(1 - p)
}

/** log2 of the falling factorial α·(α−1)·…·(α−n+1) — sampling WITHOUT replacement. */
function log2FallingFactorial(alpha, n) {
  if (n > alpha) return -Infinity
  let bits = 0
  for (let i = 0; i < n; i++) bits += Math.log2(alpha - i)
  return bits
}

/**
 * R72 §2.2 — conservative entropy for a constrained random password.
 * Model: uniform over the final alphabet, with the adjacency/no-duplicate
 * constraints priced via a Markov-style acceptance discount that can only
 * UNDERSTATE the true constrained space (never overstate it).
 */
function constrainedRandomEntropyBits({ alphabetSize, length, noDuplicates, noSequences }) {
  const naive = length * Math.log2(Math.max(2, alphabetSize))
  let bits = naive
  if (noDuplicates) {
    bits = Math.min(bits, log2FallingFactorial(alphabetSize, length))
  }
  if (noSequences && length > 1) {
    // Average forbidden-follower fraction over the alphabet: a following char
    // is forbidden when it equals the previous char or sits ±1 from it. This
    // is computed from the ACTUAL alphabet the caller reports.
    // R73 F-R73-GEN-1 — the previous line did `bits -= discount`, but log2(1−f)
    // is ≤ 0, so subtracting it ADDED entropy: digits-only L13 claimed 49.36
    // bits against a true constrained space of 37.54 (and above the 43.19
    // unconstrained naive — a constraint can only SHRINK the space). The
    // honest adjacency price ADDS log2(1−f) per follow-up character:
    // bits = naive + (L−1)·log2(1−f) ≤ naive. The model stays provably
    // conservative: each character forbids ≤3 followers, so the allowed
    // fraction is ≥ (1−f) and the true constrained space is never smaller
    // than this estimate.
    const f = Math.min(0.9, 3 / Math.max(3, alphabetSize)) // ≤3 followers per char
    bits += (length - 1) * Math.log2(Math.max(0.05, 1 - f))
  }
  return Math.max(1, bits)
}

// --- Random password generator ----------------------------------------------

export function generateRandomPassword(opts = {}) {
  const o = {
    length: 20,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
    customSymbols: '',
    excludeAmbiguous: true,
    noDuplicates: false,
    noSequences: false,
    excludeChars: '',
    firstCharLetter: false,
    ...opts,
  }

  if (o.length < 1 || !Number.isFinite(o.length)) {
    throw new Error('Length must be a positive number')
  }
  o.length = Math.min(256, Math.floor(o.length))

  // Build the ACTUAL final alphabet (ambiguity + explicit exclusions applied
  // per class, exactly once).
  // R73 F-R73-GEN-2 — an ENABLED class whose pool is emptied by the ambiguity
  // filter or explicit exclusions is a satisfiability CONFLICT, not a
  // preference: it now throws an actionable error instead of silently
  // dropping the class (no silent weakening of the requested composition).
  const classPools = []
  const droppedClasses = []
  const addPool = (enabled, raw, label) => {
    if (!enabled) return
    let filtered = o.excludeAmbiguous ? filterAmbiguous(raw) : raw
    filtered = applyExcludeChars(filtered, o.excludeChars)
    if (!filtered) { droppedClasses.push(label); return }
    classPools.push([...filtered])
  }
  addPool(o.lowercase, POOLS.lower, 'lowercase')
  addPool(o.uppercase, POOLS.upper, 'uppercase')
  addPool(o.numbers, POOLS.numbers, 'digits')
  addPool(o.symbols, POOLS.symbols, 'symbols')
  if (o.customSymbols) addPool(true, o.customSymbols, 'custom symbols')
  if (droppedClasses.length) {
    throw new Error(`The enabled character class "${droppedClasses.join('", "')}" has no characters left after the ambiguity/exclusion filters — relax the exclusions or disable the class`)
  }

  const alpha = [...new Set(classPools.flat())].join('')
  if (!alpha) throw new Error('At least one character type must be enabled')

  if (o.noDuplicates && o.length > alpha.length) {
    throw new Error(`Cannot produce a no-duplicate password of length ${o.length} from a ${alpha.length}-character alphabet`)
  }
  if (o.firstCharLetter) {
    const letters = alpha.split('').filter(c => /[a-zA-Z]/.test(c))
    if (!letters.length) throw new Error('firstCharLetter requires a letter class (lowercase or uppercase) to be enabled')
  }

  // One required char per enabled class guarantees representation.
  const required = classPools.map(pool => securePick(pool))
  if (o.length < required.length) {
    throw new Error(`Length ${o.length} cannot represent all ${required.length} enabled character classes`)
  }

  // R72-A — construct the FINAL ORDERING under the constraints directly (no
  // post-hoc shuffle): required chars take random distinct slots, the rest is
  // filled with live adjacency checks against both neighbors, then the whole
  // string is verified. Bounded retries; a clear error when unsatisfiable.
  const violates = (arr, idx, c) => {
    if (o.noSequences) {
      if (idx > 0 && isSequential(arr[idx - 1], c)) return true
      if (idx < arr.length - 1 && arr[idx + 1] && isSequential(c, arr[idx + 1])) return true
    }
    if (o.noDuplicates && arr.includes(c)) return true
    return false
  }

  let value = null
  let lastError = null
  for (let attempt = 0; attempt < 24 && !value; attempt++) {
    const slots = new Array(o.length).fill(null)
    // 1) first-character-letter rule: position 0 takes a letter BEFORE the
    // class representatives are placed (they then fill the remaining slots).
    if (o.firstCharLetter) {
      const letters = alpha.split('').filter(c => /[a-zA-Z]/.test(c))
      slots[0] = securePick(letters)
    }
    // 2) place one char of every enabled class at random distinct positions
    const free = []
    for (let i = (o.firstCharLetter ? 1 : 0); i < o.length; i++) free.push(i)
    const positions = secureShuffle(free).slice(0, required.length)
    for (let i = 0; i < required.length; i++) slots[positions[i]] = required[i]
    // 3) fill remaining slots left-to-right with live checks
    let stuck = false
    for (let idx = 0; idx < o.length; idx++) {
      if (slots[idx] !== null) continue
      let placed = false
      for (let t = 0; t < 64; t++) {
        const c = alpha[secureRandomInt(alpha.length)]
        if (!violates(slots, idx, c)) { slots[idx] = c; placed = true; break }
      }
      if (!placed) { stuck = true; lastError = new Error('Could not satisfy constraints — relax noDuplicates/noSequences/excludeChars'); break }
    }
    if (stuck) continue
    // 4) full verification of the final ordering (defensive — R72-A)
    const candidate = slots.join('')
    let ok = true
    for (let i = 0; i < candidate.length && ok; i++) {
      if (o.noDuplicates && candidate.indexOf(candidate[i]) !== i) ok = false
      if (ok && o.noSequences && i > 0 && isSequential(candidate[i - 1], candidate[i])) ok = false
    }
    if (ok && o.firstCharLetter && !/[a-zA-Z]/.test(candidate[0])) ok = false
    if (ok) value = candidate
    else lastError = new Error('Could not satisfy constraints — relax noDuplicates/noSequences/excludeChars')
  }
  if (!value) throw (lastError || new Error('Could not satisfy constraints'))

  const entropyBits = constrainedRandomEntropyBits({
    alphabetSize: alpha.length,
    length: o.length,
    noDuplicates: !!o.noDuplicates,
    noSequences: !!o.noSequences,
  })

  // Composition metadata (nonsecret; the composition of a displayed secret
  // reveals nothing beyond the display itself).
  const composition = { lower: 0, upper: 0, digit: 0, symbol: 0 }
  for (const c of value) {
    if (c >= 'a' && c <= 'z') composition.lower++
    else if (c >= 'A' && c <= 'Z') composition.upper++
    else if (c >= '0' && c <= '9') composition.digit++
    else composition.symbol++
  }

  return {
    value,
    entropyBits,
    alphabetSize: alpha.length,
    length: o.length,
    kind: 'random',
    metadata: {
      constrained: !!(o.noDuplicates || o.noSequences || o.excludeChars || o.excludeAmbiguous),
      firstCharLetter: !!o.firstCharLetter,
      composition,
      entropyModel: 'conservative-constrained',
    },
  }
}

// --- Diceware passphrase generator ------------------------------------------

/**
 * Structured rejection for over-narrow word filters (R72-B): the UI turns
 * this into the explicit relax-or-cancel choice. Never silently reverted.
 */
export class PassphraseFilterError extends Error {
  constructor(filteredSize, wordCount, poolSize) {
    super(`Word filters leave ${filteredSize} words — need at least ${wordCount}. Relax the filters or cancel.`)
    this.name = 'PassphraseFilterError'
    this.code = 'FILTER_TOO_NARROW'
    this.filteredSize = filteredSize
    this.wordCount = wordCount
    this.poolSize = poolSize
  }
}

export function generatePassphrase(opts = {}) {
  const o = {
    wordCount: 6,
    wordlist: 'large',
    capitalize: true,
    separator: '-',
    addNumber: true,
    addSymbol: true,
    padBetweenWords: false,
    minWordLength: 0,
    maxWordLength: 0,
    excludePattern: '',
    customWords: null,
    ...opts,
  }

  if (o.wordCount < 1 || !Number.isFinite(o.wordCount)) {
    throw new Error('wordCount must be a positive number')
  }
  o.wordCount = Math.min(64, Math.floor(o.wordCount))
  if (!PASSPHRASE_SEPARATORS.includes(o.separator) && !DEFAULT_SEPARATORS.includes(o.separator)) {
    throw new Error(`Unsupported separator — use one of: ${PASSPHRASE_SEPARATORS.map(s => s === '' ? '(none)' : s).join(' ')}`)
  }

  let pool
  if (o.wordlist === 'custom' && Array.isArray(o.customWords)) {
    pool = o.customWords
  } else {
    const lists = getWordlists()
    pool = lists[o.wordlist] || lists['large'] || []
  }

  if (!pool || pool.length === 0) {
    throw new Error(`Wordlist "${o.wordlist}" is empty or missing`)
  }

  const ex = (o.excludePattern || '').trim().toLowerCase()
  let filtered = pool.filter(w =>
    typeof w === 'string' &&
    (!o.minWordLength || w.length >= o.minWordLength) &&
    (!o.maxWordLength || w.length <= o.maxWordLength) &&
    (!ex || !w.toLowerCase().includes(ex))
  )
  // R72-B — NEVER a silent revert: an over-narrow filter is an explicit
  // decision the user must make (relax the filter or cancel).
  if (filtered.length < o.wordCount) {
    throw new PassphraseFilterError(filtered.length, o.wordCount, pool.length)
  }
  if (filtered.length === 0) throw new Error('No words match the filters')

  // Entropy from the ACTUAL filtered pool (R72 §2.3), plus the honest price
  // of the decorations (digit/symbol choice AND their word position; padding
  // digits between words).
  let entropyBits = o.wordCount * Math.log2(filtered.length)
  if (o.addNumber) entropyBits += Math.log2(10) + Math.log2(o.wordCount)
  if (o.addSymbol) entropyBits += Math.log2(POOLS.symbols.length) + Math.log2(o.wordCount)
  if (o.padBetweenWords) entropyBits += (o.wordCount - 1) * Math.log2(10)

  // Use a copy so we don't mutate the global list; sampling WITHOUT
  // replacement (no repeated words) — claiming the with-replacement bound
  // (wordCount·log2(pool)) is therefore conservative.
  const shuffled = secureShuffle([...filtered])
  const words = shuffled.slice(0, o.wordCount).map(w =>
    o.capitalize ? w[0].toUpperCase() + w.slice(1) : w
  )

  if (o.addNumber) {
    const i = secureRandomInt(words.length)
    words[i] += String(secureRandomInt(10))
  }
  if (o.addSymbol) {
    const i = secureRandomInt(words.length)
    words[i] += securePick(POOLS.symbols.split(''))
  }

  let value
  if (o.padBetweenWords) {
    const parts = []
    for (let i = 0; i < words.length; i++) {
      parts.push(words[i])
      if (i < words.length - 1) {
        parts.push(String(secureRandomInt(10)))
      }
    }
    value = parts.join(o.separator)
  } else {
    value = words.join(o.separator)
  }

  return {
    value,
    entropyBits,
    wordlist: o.wordlist,
    wordCount: o.wordCount,
    poolSize: filtered.length,
    kind: 'passphrase',
    metadata: {
      filteredPoolSize: filtered.length,
      separator: o.separator,
      entropyModel: 'filtered-pool-exact',
    },
  }
}

// --- PIN generator -----------------------------------------------------------

/**
 * EXACT count of length-n digit strings satisfying the enabled constraints
 * (no three identical digits in a row; no ascending/descending run of three).
 * Digit DP over the (prev2, prev1) state space — 100 states, n ≤ 64.
 */
function countValidPins(n, noRepeats, noSequences) {
  if (n <= 0) return 0
  // Seed with the 100 possible length-2 strings, then transition for each
  // ADDITIONAL digit (lengths 3..n) — one step per new digit, exactly.
  let state = new Array(100).fill(0)
  for (let a = 0; a < 10; a++)
    for (let b = 0; b < 10; b++) state[a * 10 + b] = 1
  if (n === 1) return 10
  let cur = new Array(100).fill(0)
  for (let len = 3; len <= n; len++) {
    cur = new Array(100).fill(0)
    for (let s = 0; s < 100; s++) {
      const cnt = state[s]
      if (!cnt) continue
      const x = Math.floor(s / 10), y = s % 10
      for (let z = 0; z < 10; z++) {
        if (noRepeats && x === y && y === z) continue
        if (noSequences && x + 1 === y && y + 1 === z) continue
        if (noSequences && x - 1 === y && y - 1 === z) continue
        cur[y * 10 + z] += cnt
      }
    }
    state = cur
  }
  return state.reduce((a, b) => a + b, 0)
}

export function generatePin(opts = {}) {
  const o = {
    length: 6,
    noRepeats: true,
    noSequences: true,
    ...opts,
  }

  if (!Number.isFinite(o.length) || o.length < 3 || o.length > 16) {
    throw new Error('PIN length must be between 3 and 16')
  }
  o.length = Math.floor(o.length)

  const digits = []
  let attempts = 0
  const maxAttempts = o.length * 8 + 32

  while (digits.length < o.length) {
    if (attempts++ > maxAttempts) {
      throw new Error('Could not satisfy PIN constraints — relax noRepeats/noSequences')
    }
    const c = String(secureRandomInt(10))
    if (o.noRepeats && digits.length >= 2 && digits.slice(-2).join('') === c + c) continue
    if (o.noSequences && digits.length >= 2) {
      const x = +digits[digits.length - 2]
      const y = +digits[digits.length - 1]
      const z = +c
      if (x + 1 === y && y + 1 === z) continue
      if (x - 1 === y && y - 1 === z) continue
    }
    digits.push(c)
  }

  // R72-D — honest entropy: the EXACT size of the constrained space.
  const validCount = countValidPins(o.length, !!o.noRepeats, !!o.noSequences)
  const entropyBits = Math.log2(validCount)

  return {
    value: digits.join(''),
    entropyBits,
    length: o.length,
    kind: 'pin',
    metadata: {
      constrained: !!(o.noRepeats || o.noSequences),
      entropyModel: 'exact-constrained-dp',
      pinLowerEntropy: true, // the UI renders the honest lower-entropy warning
    },
  }
}

// --- Pronounceable password generator ---------------------------------------

export function generatePronounceable(opts = {}) {
  const o = {
    syllables: 4,
    capitalize: true,
    addNumber: true,
    addSymbol: true,
    ...opts,
  }

  if (o.syllables < 1 || !Number.isFinite(o.syllables)) {
    throw new Error('syllables must be a positive number')
  }
  o.syllables = Math.min(32, Math.floor(o.syllables))

  const parts = []
  for (let i = 0; i < o.syllables; i++) {
    const onset = securePick(ONSETS)
    const nucleus = securePick(NUCLEI)
    const coda = secureRandomInt(3) > 0 ? securePick(CODAS) : ''
    parts.push(onset + nucleus + coda)
  }
  let value = parts.join('')
  if (o.capitalize) value = value[0].toUpperCase() + value.slice(1)
  if (o.addNumber) {
    const pos = secureRandomInt(value.length + 1)
    value = value.slice(0, pos) + String(secureRandomInt(10)) + value.slice(pos)
  }
  if (o.addSymbol) value += securePick(POOLS.symbols.split(''))

  // R72-C — EXACT entropy of the construction. A coda is present with
  // probability 2/3 and uniform over CODAS otherwise, so its per-syllable
  // entropy is h(2/3) + (2/3)·log2(|CODAS|) — NOT log2(1+|CODAS|).
  const bitsPerSyllable =
    Math.log2(ONSETS.length) +
    Math.log2(NUCLEI.length) +
    h2(CODA_PROB) + CODA_PROB * Math.log2(CODAS.length)

  let entropyBits = o.syllables * bitsPerSyllable
  if (o.addNumber) entropyBits += Math.log2(10) + Math.log2(value.length + 1)
  if (o.addSymbol) entropyBits += Math.log2(POOLS.symbols.length)

  return {
    value,
    entropyBits,
    syllables: o.syllables,
    kind: 'pronounceable',
    metadata: {
      entropyModel: 'construction-exact',
      pronounceable: true, // UI copy: easier to type, MAY be less predictable
    },
  }
}

// --- BIP-39 mnemonic (R72 §6 — heavily isolated wallet-seed tool) -----------
//
// BOUNDARY: this is the WALLET tool. UCrypt sync recovery words are a
// DIFFERENT concept generated by lib/sync.js over the SAME wordlist corpus;
// the two never share storage, labels, flows, or persistence. A wallet
// mnemonic is NEVER written to storage, history, sync, diagnostics, or any
// export by this module — it exists only in the return value.

export const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24]

function getBip39List() {
  const list = globalThis.CRYPTKEY_BIP39
  if (!Array.isArray(list) || list.length !== 2048) {
    throw new Error('BIP-39 wordlist not loaded')
  }
  return list
}

function bytesToBits(bytes) {
  const bits = []
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1)
  }
  return bits
}

function bitsToBytes(bits) {
  const out = new Uint8Array(Math.ceil(bits.length / 8))
  for (let i = 0; i < out.length; i++) {
    let byte = 0
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | (bits[i * 8 + j] || 0)
    }
    out[i] = byte
  }
  return out
}

/** Words (11-bit indices) → entropy bytes + checksum, per BIP-39. */
function mnemonicWordsToEntropy(words, list) {
  const bits = []
  for (const w of words) {
    const idx = list.indexOf(w)
    if (idx < 0) return { error: 'unknown-word', word: w }
    for (let i = 10; i >= 0; i--) bits.push((idx >> i) & 1)
  }
  const entBits = Math.floor(bits.length / 33) * 32
  const csBits = bits.length - entBits
  const ent = bitsToBytes(bits.slice(0, entBits))
  return { ent, csBits, cs: bits.slice(entBits) }
}

export function generateMnemonic(opts = {}) {
  const o = { words: 12, ...opts }
  const list = getBip39List()
  const words = MNEMONIC_LENGTHS.includes(Math.floor(o.words)) ? Math.floor(o.words) : 12
  // BIP-39: wordCount × 11 bits total, checksum = wordCount / 3, so the
  // embedded entropy is wordCount × 11 − wordCount / 3 (128/160/192/224/256).
  const entBits = words * 11 - words / 3
  const csBits = words / 3
  const entropy = secureRandomBytes(entBits / 8)

  return sha256(entropy).then(hash => {
    const all = [...bytesToBits(entropy), ...bytesToBits(hash).slice(0, csBits)]
    const phrase = []
    for (let i = 0; i < words; i++) {
      let idx = 0
      for (let b = 0; b < 11; b++) idx = (idx << 1) | all[i * 11 + b]
      phrase.push(list[idx])
    }
    return {
      value: phrase.join(' '),
      entropyBits: entBits,
      wordCount: words,
      kind: 'mnemonic',
      metadata: {
        highRisk: true,
        checksumBits: csBits,
        wordlist: 'BIP-39 English (2048)',
        namespace: 'wallet-seed', // NEVER the UCrypt sync-recovery namespace
      },
    }
  })
}

/** Local validation: word-list membership + length + BIP-39 checksum. */
export function validateMnemonic(phrase) {
  const list = getBip39List()
  const words = String(phrase || '').trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!MNEMONIC_LENGTHS.includes(words.length)) {
    return { valid: false, wordCount: words.length, reason: 'bad-length', entropyBits: 0, unknownWords: [], checksumOk: false }
  }
  const unknown = words.filter(w => !list.includes(w))
  if (unknown.length) {
    return { valid: false, wordCount: words.length, reason: 'unknown-word', entropyBits: 0, unknownWords: unknown.slice(0, 5), checksumOk: false }
  }
  const dec = mnemonicWordsToEntropy(words, list)
  if (dec.error) {
    return { valid: false, wordCount: words.length, reason: dec.error, entropyBits: 0, unknownWords: [dec.word], checksumOk: false }
  }
  return sha256(dec.ent).then(hash => {
    const expected = bytesToBits(hash).slice(0, dec.csBits)
    const checksumOk = expected.every((b, i) => b === dec.cs[i])
    return {
      valid: checksumOk,
      wordCount: words.length,
      reason: checksumOk ? 'ok' : 'bad-checksum',
      entropyBits: words.length * 11 - words.length / 3,
      unknownWords: [],
      checksumOk,
    }
  })
}

// --- Canonical entry point (R72 §2.1) ---------------------------------------

export const SECRET_MODES = ['random', 'passphrase', 'pin', 'pronounceable', 'mnemonic']

/**
 * The ONE API the Lab UIs call. `source` is nonsecret bookkeeping
 * ('popup' | 'full-manager' | 'page-suggest' | 'bulk') carried in metadata.
 * The returned value lives in the caller's UI/session memory ONLY — this
 * module never persists, logs, or transmits it.
 */
export async function generateSecret({ mode, options = {}, source = 'full-manager' } = {}) {
  if (!SECRET_MODES.includes(mode)) {
    throw new Error(`Unknown generator mode: ${mode}`)
  }
  let result
  switch (mode) {
    case 'random': result = generateRandomPassword(options); break
    case 'passphrase': result = generatePassphrase(options); break
    case 'pin': result = generatePin(options); break
    case 'pronounceable': result = generatePronounceable(options); break
    case 'mnemonic': result = await generateMnemonic(options); break
  }
  result.metadata = { ...(result.metadata || {}), source }
  return result
}

// --- Safe custom-wordlist helpers (R72 §7 — worker-side fetch support) ------

/**
 * HTTPS-only URL validation for the user-triggered wordlist fetch.
 * Returns { ok, url } or { ok:false, reason } — no proxy, no non-HTTPS.
 */
export function validateWordlistUrl(raw) {
  let u
  try { u = new URL(String(raw || '')) } catch { return { ok: false, reason: 'not-a-url' } }
  if (u.protocol !== 'https:') return { ok: false, reason: 'https-only' }
  if (u.username || u.password) return { ok: false, reason: 'no-credentials-in-url' }
  // Nonstandard TLS ports remain valid HTTPS (dev mirrors, self-hosted corpus
  // endpoints) — the security-relevant refusals are scheme + embedded creds.
  return { ok: true, url: u.toString() }
}

/**
 * Deterministic wordlist extraction: strip script/style/tags, lowercase,
 * match [a-z]{3,12}, dedupe + sort, bounded count. Pure — unit-tested.
 */
export function extractWordlistFromText(text, { maxWords = 20000 } = {}) {
  const stripped = String(text || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
  const matches = stripped.toLowerCase().match(/\b[a-z]{3,12}\b/g) || []
  const unique = [...new Set(matches)].sort()
  return unique.slice(0, maxWords)
}

// --- Convenience: pick a separator from the default list ---------------------

export function pickSeparator() {
  return securePick(DEFAULT_SEPARATORS)
}

// --- Convenience: generate using a "preset" (Banking/Email/etc.) -------------

export const PRESETS = {
  banking: {
    random: { length: 32, lowercase: true, uppercase: true, numbers: true, symbols: true, excludeAmbiguous: true, noDuplicates: false, noSequences: true, excludeChars: '' },
  },
  email: {
    random: { length: 20, lowercase: true, uppercase: true, numbers: true, symbols: true, excludeAmbiguous: true, noDuplicates: false, noSequences: false, excludeChars: '' },
  },
  social: {
    random: { length: 16, lowercase: true, uppercase: true, numbers: true, symbols: false, excludeAmbiguous: true, noDuplicates: false, noSequences: false, excludeChars: '' },
  },
  wifi: {
    random: { length: 24, lowercase: true, uppercase: false, numbers: true, symbols: false, excludeAmbiguous: true, noDuplicates: false, noSequences: false, excludeChars: '' },
  },
  maximum: {
    random: { length: 48, lowercase: true, uppercase: true, numbers: true, symbols: true, excludeAmbiguous: false, noDuplicates: false, noSequences: false, excludeChars: '' },
  },
  quick: {
    random: { length: 12, lowercase: true, uppercase: true, numbers: true, symbols: false, excludeAmbiguous: true, noDuplicates: false, noSequences: false, excludeChars: '' },
  },
}
