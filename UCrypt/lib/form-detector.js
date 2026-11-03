/**
 * UCrypt — Login form detector.
 *
 * Exports: detectLoginForm(doc) -> { passwordField, usernameField, form, submitButton } | null
 *
 * Heuristics (in priority order):
 *  1. Find the first visible <input type="password"> that is not disabled or hidden.
 *  2. Walk backwards through DOM siblings to find the nearest preceding
 *     text/email input — that's the username field.
 *  3. Climb up to the enclosing <form> (if any).
 *  4. Find the form's submit button (button[type=submit], input[type=submit],
 *     or the most submit-looking button).
 *  5. If no <form> wraps the password field (passwordless SPA flows), still
 *     return the password field + submit button found nearby.
 */

const TEXT_INPUT_TYPES = new Set(['text', 'email', 'tel', ''])
const SUBMIT_INPUT_TYPES = new Set(['submit', 'image'])
const SUBMIT_BUTTON_SUBTYPES = new Set(['submit', ''])

function isVisible(el) {
  if (!el) return false
  if (el.disabled) return false
  if (el.hidden) return false
  // CSS visibility check (best-effort; getBoundingClientRect is fast)
  const style = (typeof getComputedStyle === 'function')
    ? getComputedStyle(el)
    : (el.style || {})
  if (style.display === 'none' || style.visibility === 'hidden') return false
  const rect = el.getBoundingClientRect()
  if (rect.width === 0 && rect.height === 0) return false
  return true
}

function isPasswordField(el) {
  return el && el.tagName === 'INPUT' && el.type === 'password' && isVisible(el)
}

function isUsernameField(el) {
  if (!el || el.tagName !== 'INPUT') return false
  const type = (el.type || 'text').toLowerCase()
  if (!TEXT_INPUT_TYPES.has(type)) return false
  if (!isVisible(el)) return false
  if (el.readOnly) return false // v2.13.0 — R22-F3: readonly fields are display-only (Chrome parity)
  const name = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' + (el.autocomplete || '')).toLowerCase()
  // Reject fields that look like search, captcha, or one-time codes
  if (/(search|captcha|otp|one-?time|2fa|cf-|recaptcha)/i.test(name)) return false
  if (/(username|user|login|email|account|userid|user_id|userid|uid|nickname|handle|accountname|name)/i.test(name)) return true
  // Generic text field — accept as fallback
  return true
}

function isSubmitButton(el) {
  if (!el) return false
  const tag = el.tagName
  if (tag === 'BUTTON') {
    const type = (el.type || 'submit').toLowerCase()
    return SUBMIT_BUTTON_SUBTYPES.has(type)
  }
  if (tag === 'INPUT') {
    const type = (el.type || '').toLowerCase()
    return SUBMIT_INPUT_TYPES.has(type)
  }
  // Allow role=submit on arbitrary elements
  if (el.getAttribute && el.getAttribute('role') === 'button') {
    const label = ((el.textContent || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('value') || '')).toLowerCase()
    if (/(sign\s*in|log\s*in|submit|continue|next|register|sign\s*up|create|enter|go)/i.test(label)) return true
  }
  return false
}

function enclosingForm(el) {
  let node = el
  while (node) {
    if (node.tagName === 'FORM') return node
    node = node.parentElement
  }
  return null
}

function findNearestUsernameBefore(passwordField, rootDoc) {
  const doc = rootDoc || (passwordField.ownerDocument || document)
  // Walk backwards through preceding siblings and their descendants,
  // then up through parent's previous siblings
  let node = passwordField.previousElementSibling
  let depthBudget = 200
  let bestCandidate = null
  let bestScore = -1

  while (node && depthBudget-- > 0) {
    // Search descendants of `node` for the rightmost text/email input
    const inputs = node.querySelectorAll ? Array.from(node.querySelectorAll('input')) : []
    for (let i = inputs.length - 1; i >= 0; i--) {
      if (isUsernameField(inputs[i])) {
        // Score by how username-like the field is
        const name = ((inputs[i].name || '') + ' ' + (inputs[i].id || '') + ' ' + (inputs[i].placeholder || '') + ' ' + (inputs[i].autocomplete || '')).toLowerCase()
        let score = 1
        if (/username|user|login/.test(name)) score += 10
        if (/email/.test(name)) score += 8
        if (inputs[i].autocomplete === 'username') score += 12
        if (inputs[i].type === 'email') score += 6
        if (score > bestScore) {
          bestScore = score
          bestCandidate = inputs[i]
        }
      }
    }
    // The node itself might be a text input (rare but possible)
    if (isUsernameField(node)) {
      const name = ((node.name || '') + ' ' + (node.id || '') + ' ' + (node.placeholder || '') + ' ' + (node.autocomplete || '')).toLowerCase()
      let score = 1
      if (/username|user|login/.test(name)) score += 10
      if (node.autocomplete === 'username') score += 12
      if (score > bestScore) {
        bestScore = score
        bestCandidate = node
      }
    }
    // Move to the previous sibling
    node = node.previousElementSibling
  }

  // If nothing found in siblings, walk up the tree and look at parent's previous siblings
  if (!bestCandidate) {
    let parent = passwordField.parentElement
    let upBudget = 8
    while (parent && upBudget-- > 0) {
      let sib = parent.previousElementSibling
      while (sib) {
        const inputs = sib.querySelectorAll ? Array.from(sib.querySelectorAll('input')) : []
        for (const inp of inputs) {
          if (isUsernameField(inp)) return inp
        }
        if (isUsernameField(sib)) return sib
        sib = sib.previousElementSibling
      }
      parent = parent.parentElement
    }
  }

  return bestCandidate
}

function findSubmitButton(form, passwordField) {
  if (!form) {
    // No form — look for the nearest submit button after the password field
    let node = passwordField
    let budget = 30
    while (node && budget-- > 0) {
      // Search within node and following siblings
      const buttons = node.parentElement
        ? Array.from(node.parentElement.querySelectorAll('button, input[type=submit], input[type=image], [role=button]'))
        : []
      for (const b of buttons) {
        if (isSubmitButton(b) && isVisible(b)) return b
      }
      node = node.nextElementSibling
    }
    return null
  }

  // Find the form's submit button (prefer the visible, enabled, default one)
  const candidates = Array.from(form.querySelectorAll('button, input[type=submit], input[type=image], [role=button]'))
    .filter(b => isVisible(b) && isSubmitButton(b))

  if (candidates.length === 0) return null
  if (candidates.length === 1) return candidates[0]

  // Prefer type=submit / type=image
  const explicitSubmit = candidates.find(b =>
    (b.tagName === 'BUTTON' && (b.type || 'submit').toLowerCase() === 'submit') ||
    (b.tagName === 'INPUT' && SUBMIT_INPUT_TYPES.has((b.type || '').toLowerCase()))
  )
  if (explicitSubmit) return explicitSubmit

  // Otherwise prefer the one with a submit-ish label
  const byLabel = candidates.find(b => {
    const label = ((b.textContent || '') + ' ' + (b.getAttribute('aria-label') || '') + ' ' + (b.getAttribute('value') || '')).toLowerCase()
    return /(sign\s*in|log\s*in|submit|continue|next|register|sign\s*up|create|enter|go)/i.test(label)
  })
  if (byLabel) return byLabel

  return candidates[0]
}

/**
 * Detect a login form in the given document.
 * @param {Document} doc
 * @returns {{passwordField, usernameField, form, submitButton}|null}
 */
export function detectLoginForm(doc) {
  const root = doc || (typeof document !== 'undefined' ? document : null)
  if (!root) return null

  // Find all password fields; pick the first visible one
  const passwordFields = Array.from(root.querySelectorAll('input[type=password]'))
  const passwordField = passwordFields.find(isPasswordField) || null
  if (!passwordField) return null

  const usernameField = findNearestUsernameBefore(passwordField, root)
  const form = enclosingForm(passwordField)
  const submitButton = findSubmitButton(form, passwordField)

  return {
    passwordField,
    usernameField,
    form,
    submitButton,
  }
}

/**
 * Convenience: detect all login forms (e.g., signup + login on same page).
 * Returns an array of the same shape as detectLoginForm, one per password field.
 */
export function detectAllLoginForms(doc) {
  const root = doc || (typeof document !== 'undefined' ? document : null)
  if (!root) return []
  return Array.from(root.querySelectorAll('input[type=password]'))
    .filter(isPasswordField)
    .map(passwordField => ({
      passwordField,
      usernameField: findNearestUsernameBefore(passwordField, root),
      form: enclosingForm(passwordField),
      submitButton: findSubmitButton(enclosingForm(passwordField), passwordField),
    }))
}
