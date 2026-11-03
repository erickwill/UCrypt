/**
 * UCrypt — Password strength analyzer + breach check (ported from UCrypt).
 *
 * Exports:
 *   analyzePassword(pw) -> { pw, len, naive, effective, breached, patterns, recs, breachDbSize }
 *
 * The breach list is provided by breach.js which sets globalThis.CRYPTKEY_BREACH
 * as a Set of SHA-1 / plain breached passwords (we use plain lowercase form).
 */

// Common passwords to flag even if not in the breach set
const COMMON = new Set([
  'password','123456','123456789','12345678','12345','1234567','admin',
  'letmein','welcome','monkey','dragon','master','qwerty','login','princess',
  'abc123','password1','shadow','sunshine','trustno1','iloveyou','batman',
  'football','charlie','superman','michael','jennifer','jordan','hunter',
  'pass','1234','0000','1111','baseball','soccer','hockey','starwars',
  'access','flower','hello','charlie','donald','123123','654321','666666',
])

// Leet -> letter substitutions (for partial de-leeting)
const LEET = {
  '@':'a','4':'a','0':'o','$':'s','5':'s','7':'t','1':'i','!':'i','|':'i',
  '3':'e','2':'z','6':'g','8':'b','(':'c','{':'c','[':'c','#':'h','^':'a',
}

function lightDeleet(s) {
  let out = ''
  for (const c of s) out += LEET[c] || c
  return out
}

function getBreachSet() {
  return globalThis.CRYPTKEY_BREACH || new Set()
}

export function analyzePassword(pw) {
  if (!pw || typeof pw !== 'string') return null

  const len = pw.length
  const lower = (pw.match(/[a-z]/g) || []).length
  const upper = (pw.match(/[A-Z]/g) || []).length
  const digit = (pw.match(/[0-9]/g) || []).length
  const sym = len - lower - upper - digit

  const alpha =
    (lower > 0 ? 26 : 0) +
    (upper > 0 ? 26 : 0) +
    (digit > 0 ? 10 : 0) +
    (sym > 0 ? 32 : 0)

  const naive = len * Math.log2(alpha || 1)
  let penalty = 0
  const patterns = []

  const lowerPw = pw.toLowerCase()
  const lightD = lightDeleet(lowerPw)
  const stripped = lightD.replace(/[^a-z].*$/, '')

  const BREACH = getBreachSet()

  // --- Breach check ---------------------------------------------------------
  let breached = false
  if (
    BREACH.has(lowerPw) ||
    BREACH.has(lightD) ||
    (stripped.length >= 4 && BREACH.has(stripped))
  ) {
    patterns.push('Based on a common/breached password — cracked instantly')
    penalty = naive
    breached = true
  } else {
    // Check substrings of length 16 down to 4
    outer: for (let l = Math.min(lowerPw.length, 16); l >= 4; l--) {
      for (let i = 0; i + l <= lowerPw.length; i++) {
        const sub = lowerPw.slice(i, i + l)
        if (BREACH.has(sub)) {
          patterns.push(`Contains breached substring: "${sub}"`)
          penalty += Math.min(naive * 0.6, l * Math.log2(94))
          // v2.2.0 fix (audit finding): a long breached substring (≥8 chars,
          // e.g. "password1" inside "password123") IS a breach — the daily
          // check used to miss it because only exact matches set the flag.
          if (l >= 8) breached = true
          break outer
        }
      }
    }
  }

  if (COMMON.has(lowerPw)) {
    patterns.push('Common password')
    penalty = naive
  }

  // --- Sequences ------------------------------------------------------------
  let run = ''
  for (let i = 1; i < len; i++) {
    const a = pw.charCodeAt(i - 1)
    const b = pw.charCodeAt(i)
    if (a + 1 === b || a - 1 === b) {
      run += pw[i]
    } else {
      if (run.length >= 2) {
        patterns.push(`Sequential: "${pw[i - 1 - run.length]}${run}${pw[i - 1]}"`)
        penalty += Math.log2((run.length + 1) ** 2)
      }
      run = ''
    }
  }
  if (run.length >= 2) {
    patterns.push('Sequential chars')
    penalty += Math.log2((run.length + 1) ** 2)
  }

  // --- Repeats --------------------------------------------------------------
  for (let i = 0; i < len;) {
    let j = i + 1
    while (j < len && pw[j] === pw[i]) j++
    if (j - i >= 3) {
      patterns.push(`Repeated: "${pw.slice(i, j)}" (${j - i}x)`)
      penalty += Math.log2(26) * (j - i - 1)
    }
    i = j
  }

  // --- Keyboard walks -------------------------------------------------------
  const rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
  const seenWalks = new Set()
  for (const row of rows) {
    for (let l = 6; l >= 3; l--) {
      for (let i = 0; i + l <= row.length; i++) {
        const s = row.slice(i, i + l)
        const key = s + row
        if (seenWalks.has(key)) continue
        if (lowerPw.includes(s) || lowerPw.includes(s.split('').reverse().join(''))) {
          patterns.push(`Keyboard walk: "${s}"`)
          penalty += Math.log2(l * l)
          seenWalks.add(key)
        }
      }
    }
  }

  // --- Years / dates --------------------------------------------------------
  const dates = pw.match(/\b(19|20)\d{2}\b/g)
  if (dates) {
    for (const d of dates) {
      patterns.push(`Year: "${d}"`)
      penalty += Math.log2(200)
    }
  }

  penalty = Math.min(penalty, naive * 0.85)
  const effective = Math.max(0.5, naive - penalty)

  // --- Recommendations ------------------------------------------------------
  const recs = []
  if (breached) recs.unshift('Exposed in a breach — change it everywhere')
  if (len < 12) recs.push('Use at least 12 characters')
  if (!upper) recs.push('Add uppercase letters')
  if (!digit) recs.push('Add numbers')
  if (!sym) recs.push('Add symbols')
  if (patterns.some(p => p.includes('Sequential'))) recs.push('Avoid sequences')
  if (patterns.some(p => p.includes('Keyboard'))) recs.push('Avoid keyboard patterns')
  if (patterns.some(p => p.includes('Repeated'))) recs.push('Avoid repeats')
  if (patterns.some(p => p.includes('Year'))) recs.push('Avoid years/dates')
  if (!recs.length && effective >= 80) recs.push('Strong — store in a password manager')
  if (!recs.length) recs.push('Use a password manager')

  return {
    pw,
    len,
    naive,
    effective,
    breached,
    patterns,
    recs,
    breachDbSize: BREACH.size || 0,
  }
}

// --- Strength bucket helper (used by UI) -----------------------------------

export function strengthBucket(effectiveBits) {
  if (effectiveBits < 28) return { label: 'Very Weak', score: 10, color: '#ef4444' }
  if (effectiveBits < 40) return { label: 'Weak', score: 28, color: '#f97316' }
  if (effectiveBits < 60) return { label: 'Fair', score: 50, color: '#eab308' }
  if (effectiveBits < 80) return { label: 'Strong', score: 76, color: '#84cc16' }
  // R72 §2.5: standard, defensible entropy language only — the former
  // "Excellent · Quantum-resistant" marketing claim is retired.
  return { label: 'Excellent', score: 92, color: '#10b981' }
}

/**
 * R72 §3.3 — the ONE strength-badge builder for every surface.
 * Contract (owner screenshot 20261001_135912: "Modify to 'VERY WEAK'"):
 *   - label is the FULL text, never truncated ("VERY WEAK", never "VERY");
 *   - BREACHED supersedes the entropy label;
 *   - every badge carries text + color + an ariaLabel (screen readers);
 *   - callers render the full label; the CSS prevents clipping
 *     (white-space:nowrap + a flexible row).
 */
export function strengthBadge(analysis) {
  if (analysis && analysis.breached) {
    return {
      label: 'Breached',
      score: 100,
      color: '#dc2626',
      aria: 'Breached: this password appears in a known breach list. Change it everywhere.',
    }
  }
  const b = strengthBucket(analysis ? analysis.effective : 0)
  const aria = {
    'Very Weak': 'Strength: very weak',
    'Weak': 'Strength: weak',
    'Fair': 'Strength: fair',
    'Strong': 'Strength: strong',
    'Excellent': 'Strength: excellent',
  }[b.label] || `Strength: ${b.label}`
  return { ...b, aria }
}

// --- Crack-time formatter ---------------------------------------------------

export function crackTime(b) {
  if (b <= 0) return 'instant'
  const seconds = Math.pow(2, b - 1) / 1e13
  if (seconds < 1) return 'instant'
  if (seconds < 60) return Math.round(seconds) + ' sec'
  if (seconds < 3600) return (seconds / 60).toFixed(1) + ' min'
  if (seconds < 86400) return (seconds / 3600).toFixed(1) + ' hr'
  if (seconds < 3.156e7) return (seconds / 86400).toFixed(1) + ' days'
  const y = seconds / 3.156e7
  if (y < 1e3) return y.toFixed(1) + ' yr'
  if (y < 1e6) return (y / 1e3).toFixed(1) + 'k yr'
  if (y < 1e9) return (y / 1e6).toFixed(1) + 'M yr'
  if (y < 1e12) return (y / 1e9).toFixed(1) + 'B yr'
  if (y < 1e15) return (y / 1e12).toFixed(1) + 'T yr'
  const e = Math.floor(Math.log10(y))
  return (y / Math.pow(10, e)).toFixed(1) + '×10^' + e + ' yr'
}
