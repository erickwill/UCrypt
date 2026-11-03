/**
 * UCrypt — 2FA/OTP field detector (v2.5.0).
 *
 * Plain script (NOT an ES module) so it can be listed in manifest.json's
 * content_scripts "js" array BEFORE content.js — content scripts cannot
 * import ES modules. It attaches the detector to globalThis.UCRYPT_OTP.
 * Written as valid ESM-without-imports so the test harness can `import()`
 * the very same file and assert against the exact code the page runs
 * (single source of truth — no content-script inline mirror this time).
 *
 * Detection philosophy — CONSERVATIVE:
 *   - autocomplete="one-time-code" is an explicit site declaration → trusted
 *     (after basic type/visibility checks).
 *   - Otherwise the field must hint OTP-ness via its name/id/placeholder/
 *     aria-label AND NOT look like a search/username/email/password field.
 *   - Password, email, search, hidden, disabled and invisible fields never
 *     qualify. Numbers/tel/text inputs only — OTP codes are typed digits.
 *
 * Attached API (globalThis.UCRYPT_OTP):
 *   isOtpInput(el)      -> bool
 *   findOtpField(scope) -> element | null   (scope defaults to document)
 */
;(function (root) {
  'use strict'

  var OTP_HINT = /(otp|one[-_ ]?time|2fa|two[-_ ]?factor|verification\s*code|verify\s*code|authenticator|totp|security\s*code)/i
  var NOT_OTP = /(search|user(name)?|login|pass(word)?|email)/i

  function isVisible(el) {
    if (!el) return false
    if (el.disabled || el.hidden) return false
    var style
    try { style = root.window ? root.window.getComputedStyle(el) : null } catch (e) { style = null }
    if (style && (style.display === 'none' || style.visibility === 'hidden')) return false
    var rect = el.getBoundingClientRect()
    return !(rect.width === 0 && rect.height === 0)
  }

  function isOtpInput(el) {
    if (!el || el.tagName !== 'INPUT') return false
    if (el.disabled || el.readOnly) return false
    var type = String(el.type || 'text').toLowerCase()
    // OTP codes are typed as text/tel/number — never password/email/etc.
    if (!['text', 'tel', 'number', ''].includes(type)) return false
    if (!isVisible(el)) return false

    var autocomplete = String(el.getAttribute('autocomplete') || '').toLowerCase()
    var sig = [
      el.name || '',
      el.id || '',
      el.placeholder || '',
      autocomplete,
      el.getAttribute('aria-label') || '',
    ].join(' ').toLowerCase()

    // Explicit site declaration wins (after the type/visibility guards).
    if (autocomplete === 'one-time-code') return true

    if (!OTP_HINT.test(sig)) return false
    // Anti-false-positive: clearly-identified non-OTP fields.
    if (NOT_OTP.test(sig)) return false
    return true
  }

  function findOtpField(scope) {
    var box = scope && scope.querySelectorAll ? scope : document
    var inputs = box.querySelectorAll('input')
    for (var i = 0; i < inputs.length; i++) {
      if (isOtpInput(inputs[i])) return inputs[i]
    }
    return null
  }

  root.UCRYPT_OTP = { isOtpInput: isOtpInput, findOtpField: findOtpField }
})(typeof globalThis !== 'undefined' ? globalThis : self)
