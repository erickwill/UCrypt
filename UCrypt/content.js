/**
 * UCrypt — Content script.
 *
 * Plain script (content scripts don't support ES modules). Runs at document_idle.
 *
 * Responsibilities:
 *   - Detect login forms on the page.
 *   - Ask the background for any saved entries matching the page's domain.
 *   - If entries found, show an "Auto-fill available" overlay with a Fill button.
 *   - On form submit, detect any new/changed password value and show a
 *     "Save this password?" overlay.
 *   - On receiving { type: 'PERFORM_FILL' } from the background (popup-triggered),
 *     fill the username + password fields with the most recently used entry.
 *   - (v2.5.0) Detect 2FA/OTP fields (lib/otp-field.global.js, loaded before
 *     this script via the manifest) and offer a one-click "fill code" chip
 *     backed by the vault's TOTP tokens. Codes are computed in the background
 *     worker and only on an explicit click — secrets never reach the page.
 *   - (v2.6.0) Brave/Chrome parity: "Suggest strong password" on signup/new-
 *     password fields (autocomplete=new-password, paired password+confirm
 *     fields, or signup-labeled forms). Focusing a candidate shows an anchored
 *     chip; the panel generates via the background (GENERATE_FOR_FILL →
 *     lib/generator.js), fills the field (+ its confirm twin) on Use, and
 *     supports Regenerate/Copy. Context-menu (right-click) and keyboard
 *     shortcuts (Ctrl+Shift+L / Ctrl+Shift+U) route here as SUGGEST_STRONG_PASSWORD
 *     / PERFORM_FILL / SAVE_PAGE_LOGIN messages.
 *
 * Communication with the background uses chrome.runtime.sendMessage.
 */

(function UCryptContent() {
  'use strict'

  const OVERLAY_ID = 'ucrypt-autofill-overlay'
  const SAVE_OVERLAY_ID = 'ucrypt-save-overlay'
  const OTP_OVERLAY_ID = 'ucrypt-otp-overlay'
  // v2.18.0 — R27-F9: the locked prompt gets its OWN surface id. It reused
  // OVERLAY_ID since v2.2.0 (the R26-recorded nit): the two flows never
  // collide in practice, but removal/Esc/geometry then had to reason about
  // "which overlay is this?" — a dedicated id makes every check exact.
  const LOCKED_OVERLAY_ID = 'ucrypt-locked-overlay'
  const SUGGEST_CHIP_ID = 'ucrypt-suggest-chip'
  const SUGGEST_PANEL_ID = 'ucrypt-suggest-panel'
  const TOAST_ID = 'ucrypt-toast'
  const STYLE_ID = 'ucrypt-content-style'

  // v2.18.0 — R28-i18n (wave 6): content overlays localize through the
  // _locales catalogs. This is a CLASSIC script (no ES-module imports), so it
  // carries the 6-line local helper per the i18n spec: chrome.i18n.getMessage
  // works in content scripts; the English literal stays as the hard fallback
  // so QA stubs and exotic embeds keep the exact current strings.
  function msg(key, subs, fallback) {
    try {
      const t = subs !== undefined ? chrome.i18n.getMessage(key, subs) : chrome.i18n.getMessage(key)
      if (t) return t
    } catch { /* stubbed or unavailable — fall through */ }
    return fallback
  }

  // --- Utility: domain extraction ------------------------------------------

  function domainFromLocation() {
    try {
      return window.location.hostname.replace(/^www\./, '')
    } catch {
      return ''
    }
  }

  // v2.11.0 — F7 (iframes): with content scripts now in ALL frames, the
  // passive overlays must stay out of frames where they would be clipped or
  // absurd (0×0 tracking pixels, 200px ad slots). A frame may host passive
  // UI when it is the top page, or when it is big enough to actually show an
  // overlay. EXPLICIT fills (popup / keyboard shortcut) still work in any
  // frame — the gate only quiets the passive UX, never the fill itself.
  function frameIsUsable() {
    try {
      if (window.top === window) return true
      return window.innerWidth >= 300 && window.innerHeight >= 200
    } catch {
      return false
    }
  }

  // --- R59-F2 — vaultStateEpoch: a lock event must win every race ----------
  // Monotonic counter bumped on VAULT_LOCKED / VAULT_UNLOCKED / SPA nav. Every
  // entries request captures the epoch at send time; the response handler
  // discards any reply whose epoch no longer matches — a late GET_ENTRIES
  // answer that races a lock can never resurrect a picker.
  let vaultStateEpoch = 0
  function bumpVaultEpoch() { vaultStateEpoch += 1; return vaultStateEpoch }
  function epochNow() { return vaultStateEpoch }

  // --- R59-F1/F2 — closed-ShadowRoot vault surfaces -------------------------
  // Vault-derived surfaces (autofill picker, OTP chip, card/identity picker)
  // render inside a dedicated host with a CLOSED shadow root: page JS sees
  // only the generic host element — no username text, entry ids, or row
  // content is reachable (Element.shadowRoot is null for closed trees), and
  // nothing identifier-bearing lands in host attributes/dataset/titles.
  const shadowSurfaces = new Map() // surface id -> { host, root }
  function attachShadowSupported() {
    try { return typeof document.createElement('div').attachShadow === 'function' } catch { return false }
  }
  function openShadowSurface(id) {
    closeShadowSurface(id)
    let root = null
    const host = document.createElement('div')
    host.id = id // generic surface name ONLY — never carries user data
    try { root = host.attachShadow({ mode: 'closed' }) } catch { root = null }
    if (!root) return null // no attachShadow → caller uses the masked fallback
    const style = document.createElement('style')
    style.textContent = OVERLAY_CSS
    root.appendChild(style)
    document.documentElement.appendChild(host)
    const rec = { host, root }
    shadowSurfaces.set(id, rec)
    return rec
  }
  function closeShadowSurface(id) {
    const rec = shadowSurfaces.get(id)
    if (!rec) return
    try { rec.host.remove() } catch { /* already gone */ }
    shadowSurfaces.delete(id)
  }
  function closeAllShadowSurfaces() {
    for (const id of Array.from(shadowSurfaces.keys())) closeShadowSurface(id)
  }
  /** Find a surface's inner element — closed shadow first, light DOM second. */
  function surfaceEl(id) {
    const rec = shadowSurfaces.get(id)
    if (rec) { try { return rec.root.getElementById(id) } catch { return null } }
    return document.getElementById(id)
  }
  /** Remove a surface regardless of which mode rendered it. */
  function dismissSurface(id) {
    closeShadowSurface(id)
    removeOverlay(id)
  }

  // --- Utility: send message to background --------------------------------

  function send(type, data = {}) {
    return new Promise((resolve) => {
      try {
        // v2.10.0 — payload spread FIRST so a data `type` field can never clobber
      // the message type on the wire (protocol fix, matches options.js bgSend).
      chrome.runtime.sendMessage({ ...data, type }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message })
            return
          }
          resolve(response || { ok: false, error: 'No response' })
        })
      } catch (e) {
        resolve({ ok: false, error: e.message })
      }
    })
  }

  // --- v2.11.0 — F6: two-step login username memory -------------------------
  // Google/Microsoft/GitHub-style flows type the username on PAGE 1 and the
  // password on PAGE 2. At submit time the username field no longer exists,
  // so the save prompt used to save an EMPTY username. Track the last
  // qualifying text field the user typed:
  //   1. in this page's JS memory (covers SPA two-step on one URL), and
  //   2. mirrored to the background WORKER's memory keyed by tab+domain
  //      (survives the step-1 → step-2 navigation; worker memory only —
  //      never persisted, never synced, TTL-capped; see background.js).
  // The page's sessionStorage is deliberately NOT used: it is readable by
  // the page itself — credentials never go into page-visible storage.
  let lastUsernameCandidate = ''

  function recordUsernameCandidate(el) {
    try {
      if (!el || el.tagName !== 'INPUT') return
      const type = (el.type || 'text').toLowerCase()
      if (!['text', 'email', ''].includes(type)) return
      const sig = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' + (el.autocomplete || '')).toLowerCase()
      if (/(search|captcha|otp|one-?time|2fa|cf-|recaptcha)/i.test(sig)) return
      const val = String(el.value || '').trim()
      if (!val || val.length > 100 || /\s/.test(val)) return
      lastUsernameCandidate = val
      send('REMEMBER_USERNAME', { domain: domainFromLocation(), username: val })
    } catch { /* best-effort */ }
  }

  document.addEventListener('focusout', (e) => recordUsernameCandidate(e.target), true)

  /** The username for a save prompt: typed value → in-page candidate →
   *  the background's per-tab memory (survives step-1 → step-2 navigation). */
  async function resolveUsername(usernameField, domain) {
    const direct = usernameField ? String(usernameField.value || '').trim() : ''
    if (direct) return direct
    if (lastUsernameCandidate) return lastUsernameCandidate
    try {
      const r = await send('GET_LAST_USERNAME', { domain })
      if (r && r.ok && r.username) return String(r.username)
    } catch { /* background unavailable — proceed without */ }
    return ''
  }

  // --- Inline form detector (mirror of lib/form-detector.js) ---------------
  // (Content scripts cannot import ES modules — we inline the same logic.)

  function isVisible(el) {
    if (!el) return false
    if (el.disabled || el.hidden) return false
    const style = window.getComputedStyle(el)
    if (style.display === 'none' || style.visibility === 'hidden') return false
    const rect = el.getBoundingClientRect()
    if (rect.width === 0 && rect.height === 0) return false
    return true
  }

  function isPassword(el) {
    return el && el.tagName === 'INPUT' && el.type === 'password' && isVisible(el)
  }

  function isUsername(el) {
    if (!el || el.tagName !== 'INPUT') return false
    const type = (el.type || 'text').toLowerCase()
    if (!['text', 'email', 'tel', ''].includes(type)) return false
    if (!isVisible(el)) return false
    if (el.readOnly) return false // v2.13.0 — R22-F3: readonly fields are display-only (Chrome parity)
    const sig = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '') + ' ' + (el.autocomplete || '')).toLowerCase()
    if (/(search|captcha|otp|one-?time|2fa|cf-|recaptcha)/i.test(sig)) return false
    return true
  }

  function findSubmitButton(form, passwordField) {
    if (form) {
      const buttons = Array.from(form.querySelectorAll('button, input[type=submit], input[type=image], [role=button]'))
        .filter(b => isVisible(b))
      const explicit = buttons.find(b =>
        (b.tagName === 'BUTTON' && (b.type || 'submit').toLowerCase() === 'submit') ||
        (b.tagName === 'INPUT' && ['submit', 'image'].includes((b.type || '').toLowerCase()))
      )
      if (explicit) return explicit
      const byLabel = buttons.find(b => {
        const label = ((b.textContent || '') + ' ' + (b.getAttribute('aria-label') || '') + ' ' + (b.getAttribute('value') || '')).toLowerCase()
        return /(sign\s*in|log\s*in|submit|continue|next|register|sign\s*up|create|enter|go)/i.test(label)
      })
      return byLabel || buttons[0] || null
    }
    // v2.11.0 — F8: no <form>. The old inline mirror only searched the
    // password field's IMMEDIATE parent; lib/form-detector.js walks forward
    // through the siblings. Align the mirror with the library so SPA
    // passwordless markup (button in a sibling container) finds its submit.
    let node = passwordField
    let budget = 30
    while (node && budget-- > 0) {
      const buttons = node.parentElement
        ? Array.from(node.parentElement.querySelectorAll('button, input[type=submit], input[type=image], [role=button]'))
            .filter(b => isVisible(b))
        : []
      const explicit = buttons.find(b =>
        (b.tagName === 'BUTTON' && (b.type || 'submit').toLowerCase() === 'submit') ||
        (b.tagName === 'INPUT' && ['submit', 'image'].includes((b.type || '').toLowerCase()))
      )
      if (explicit) return explicit
      const byLabel = buttons.find(b => {
        const label = ((b.textContent || '') + ' ' + (b.getAttribute('aria-label') || '') + ' ' + (b.getAttribute('value') || '')).toLowerCase()
        return /(sign\s*in|log\s*in|submit|continue|next|register|sign\s*up|create|enter|go)/i.test(label)
      })
      if (byLabel) return byLabel
      node = node.nextElementSibling
    }
    return null
  }

  function enclosingForm(el) {
    let node = el
    while (node) {
      if (node.tagName === 'FORM') return node
      node = node.parentElement
    }
    return null
  }

  function findUsernameBefore(passwordField) {
    // v2.42.8 — R71 (two-step fidelity): the walk must NOT cross a <form>
    // boundary. On two-step pages the step-2 password form sits BELOW other
    // visible forms (a checkout, a profile editor, the step-1 form of a
    // DIFFERENT flow); the old sibling walk happily adopted an unrelated
    // form's name field as "the username" and saved logins under a wrong
    // identity. Within the password's own form (or the whole page when the
    // password is formless) the heuristic is unchanged; ACROSS forms the
    // truthful answer is "no username field here" — the two-step candidate
    // memory (recordUsernameCandidate/resolveUsername) owns that case.
    const homeForm = enclosingForm(passwordField)
    const insideHome = (el) => !homeForm || homeForm.contains(el)
    let node = passwordField.previousElementSibling
    let budget = 200
    let best = null
    let bestScore = -1
    while (node && budget-- > 0) {
      if (node.tagName === 'FORM' && node !== homeForm) break // never cross into a sibling form
      const inputs = node.querySelectorAll ? Array.from(node.querySelectorAll('input')) : []
      for (let i = inputs.length - 1; i >= 0; i--) {
        if (isUsername(inputs[i])) {
          const sig = ((inputs[i].name || '') + ' ' + (inputs[i].id || '') + ' ' + (inputs[i].placeholder || '') + ' ' + (inputs[i].autocomplete || '')).toLowerCase()
          let score = 1
          if (/username|user|login/.test(sig)) score += 10
          if (/email/.test(sig)) score += 8
          if (inputs[i].autocomplete === 'username') score += 12
          if (inputs[i].type === 'email') score += 6
          if (score > bestScore) { bestScore = score; best = inputs[i] }
        }
      }
      if (isUsername(node)) {
        const sig = ((node.name || '') + ' ' + (node.id || '') + ' ' + (node.placeholder || '') + ' ' + (node.autocomplete || '')).toLowerCase()
        let score = 1
        if (/username|user|login/.test(sig)) score += 10
        if (node.autocomplete === 'username') score += 12
        if (score > bestScore) { bestScore = score; best = node }
      }
      node = node.previousElementSibling
    }
    if (!best) {
      // Walk up to parents' previous siblings — same form-boundary rule.
      let parent = passwordField.parentElement
      let up = 8
      while (parent && up-- > 0) {
        let sib = parent.previousElementSibling
        while (sib) {
          if (sib.tagName === 'FORM' && sib !== homeForm) { sib = sib.previousElementSibling; continue }
          const inputs = sib.querySelectorAll ? Array.from(sib.querySelectorAll('input')) : []
          for (const inp of inputs) if (isUsername(inp) && insideHome(inp)) return inp
          if (isUsername(sib) && insideHome(sib)) return sib
          sib = sib.previousElementSibling
        }
        if (homeForm && parent === homeForm) break // the home form's boundary is the walk's edge
        parent = parent.parentElement
      }
    }
    return best
  }

  function detectLoginForm() {
    const fields = Array.from(document.querySelectorAll('input[type=password]'))
    const password = fields.find(isPassword)
    if (!password) return null
    const username = findUsernameBefore(password)
    const form = enclosingForm(password)
    const submit = findSubmitButton(form, password)
    return { passwordField: password, usernameField: username, form, submitButton: submit }
  }

  // --- Styling -------------------------------------------------------------

  // R59-F1: the stylesheet is shared by the light-DOM surfaces AND injected
  // into every closed shadow root — one source of truth, no user data in it.
  const OVERLAY_CSS = `
.ucrypt-overlay{position:fixed;z-index:2147483647;right:16px;bottom:16px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#0f0f1a;color:#f0f0f5;border:1px solid #2a2a3e;border-radius:10px;
  box-shadow:0 10px 30px -8px rgba(0,0,0,.4);padding:12px 14px;
  display:flex;flex-direction:column;gap:8px;min-width:240px;max-width:320px;
  font-size:13px;line-height:1.4;animation:ck-slide-in .18s ease-out}
.ucrypt-overlay.top{top:16px;bottom:auto}
@keyframes ck-slide-in{from{transform:translateY(8px);opacity:0}
  to{transform:translateY(0);opacity:1}}
.ucrypt-overlay-head{display:flex;align-items:center;gap:8px;font-weight:600}
.ucrypt-overlay-head .ck-badge{background:#10b981;color:#fff;border-radius:6px;
  padding:2px 6px;font-size:10px;font-weight:700;letter-spacing:.04em}
.ucrypt-overlay-sub{font-size:11px;color:#9ca3af}
.ucrypt-overlay-actions{display:flex;gap:6px;flex-wrap:wrap}
.ck-btn{font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;
  border:none;border-radius:6px;padding:6px 10px;transition:opacity .15s,background .15s}
.ck-btn-primary{background:#10b981;color:#fff}
.ck-btn-primary:hover{background:#0e9c71}
.ck-btn-ghost{background:transparent;color:#9ca3af;border:1px solid #2a2a3e}
.ck-btn-ghost:hover{color:#f0f0f5;border-color:#3a3a4e}
.ck-btn-danger{background:transparent;color:#f87171;border:1px solid #f87171}
.ck-btn-danger:hover{background:#f87171;color:#fff}
.ck-close{position:absolute;top:6px;right:8px;width:20px;height:20px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;
  color:#9ca3af;border:none;background:none;font-size:14px}
.ck-close:hover{color:#f0f0f5}
.ucrypt-overlay-wrap{position:relative}
.ucrypt-otp-token{display:flex;align-items:center;justify-content:space-between;gap:8px;
  padding:6px 8px;background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;font-size:11px}
.ucrypt-otp-token:hover{border-color:#10b981}
/* v2.9.0 — domain-ranked tokens: same-site tokens lead with an accent. */
.ucrypt-otp-token.is-site{border-color:#10b981;background:#12201d}
.ucrypt-otp-sitenote{font-size:10px;color:#9ca3af;padding:2px 2px 0}
.ucrypt-otp-token .uc-otp-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#e5e7eb}
.ucrypt-otp-token .uc-otp-issuer{color:#9ca3af;margin-right:4px}
.ucrypt-otp-status{font-size:10.5px;color:#10b981;min-height:14px}
.ck-entries{display:flex;flex-direction:column;gap:4px;max-height:160px;overflow-y:auto}
.ck-entry-row{display:flex;align-items:center;gap:8px;padding:6px 8px;
  background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;font-size:11px}
.ck-entry-row code{font-family:"SF Mono",Menlo,Consolas,monospace;flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#e5e7eb}
@media (prefers-color-scheme: light){
  .ucrypt-overlay{background:#fff;color:#1a1a2e;border-color:#e5e7eb}
  .ucrypt-overlay-sub{color:#6b7280}
  .ck-btn-ghost{color:#6b7280;border-color:#e5e7eb}
  .ck-btn-ghost:hover{color:#1a1a2e;border-color:#9ca3af}
  .ck-close{color:#6b7280}
  .ck-close:hover{color:#1a1a2e}
  .ck-entry-row{background:#f9fafb;border-color:#e5e7eb}
  .ck-entry-row code{color:#1a1a2e}
}
/* --- v2.6.0: suggest strong password chip + panel + toast ---------------- */
.ucrypt-suggest-chip{position:fixed;z-index:2147483647;display:flex;align-items:center;gap:6px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:12px;font-weight:600;
  color:#fff;background:#0f0f1a;border:1px solid #10b981;border-radius:8px;padding:6px 10px;
  cursor:pointer;box-shadow:0 6px 18px -6px rgba(0,0,0,.45);animation:ck-slide-in .15s ease-out}
.ucrypt-suggest-chip:hover{background:#161628}
.ucrypt-suggest-chip .uc-chip-dot{width:7px;height:7px;border-radius:50%;background:#10b981;flex:0 0 auto}
.ucrypt-panel{position:fixed;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#0f0f1a;color:#f0f0f5;border:1px solid #2a2a3e;border-radius:10px;
  box-shadow:0 12px 34px -8px rgba(0,0,0,.5);padding:12px 14px;width:300px;
  display:flex;flex-direction:column;gap:8px;font-size:13px;animation:ck-slide-in .15s ease-out}
.ucrypt-panel .uc-pw-row{display:flex;align-items:center;gap:6px}
.ucrypt-panel .uc-pw{flex:1;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:12.5px;
  background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;padding:7px 9px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;user-select:all;min-height:15px}
.ucrypt-panel .uc-pw-meta{font-size:11px;color:#9ca3af}
.ucrypt-panel .uc-pw-status{font-size:11px;color:#10b981;min-height:14px}
.ucrypt-toast{position:fixed;z-index:2147483647;left:50%;transform:translateX(-50%);bottom:24px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:12.5px;font-weight:600;
  background:#0f0f1a;color:#f0f0f5;border:1px solid #2a2a3e;border-radius:8px;padding:9px 14px;
  box-shadow:0 8px 24px -8px rgba(0,0,0,.5);animation:ck-slide-in .18s ease-out}
@media (prefers-color-scheme: light){
  .ucrypt-suggest-chip{background:#fff;color:#1a1a2e}
  .ucrypt-suggest-chip:hover{background:#f3f4f6}
  .ucrypt-panel{background:#fff;color:#1a1a2e;border-color:#e5e7eb}
  .ucrypt-panel .uc-pw{background:#f9fafb;border-color:#e5e7eb;color:#111827}
  .ucrypt-panel .uc-pw-meta{color:#6b7280}
  .ucrypt-toast{background:#fff;color:#1a1a2e;border-color:#e5e7eb}
/* --- R59-F1: readable account selection (inside the closed shadow) ------ */
.ck-picker-search{width:100%;box-sizing:border-box;font-family:inherit;font-size:12px;
  background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;padding:6px 8px;color:#f0f0f5}
.ck-picker-search:focus{border-color:#10b981;outline:none}
.ck-picker-count{font-size:10.5px;color:#9ca3af;padding:0 2px}
.ck-entry-id{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:#e5e7eb;font-size:12px}
.ck-entry-meta{font-size:10px;color:#9ca3af;flex:0 1 auto;max-width:45%;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.ck-entry-row:focus-visible{border-color:#10b981;outline:none}
.ck-picker-search:focus-visible{outline:2px solid #10b981;outline-offset:1px}
@media (prefers-color-scheme: light){
  .ck-picker-search{background:#f9fafb;border-color:#e5e7eb;color:#1a1a2e}
  .ck-entry-id{color:#1a1a2e}
}
/* --- v2.42.8 — R71-P: profile fill picker / capture review / username picker --- */
.uc-prf-row{cursor:pointer;user-select:none}
.uc-prf-row[aria-selected="true"]{border-color:#10b981;background:#12201d}
.uc-prf-replace-row{display:flex;align-items:center;gap:6px;font-size:11px;color:#9ca3af;cursor:pointer}
.uc-prf-replace-row input{accent-color:#10b981;margin:0}
.ucrypt-profile-save{max-width:340px;min-width:280px;max-height:min(70vh,480px);overflow-y:auto}
.uc-prf-name-row{display:flex;flex-direction:column;gap:3px}
.uc-prf-name-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em}
.uc-prf-name-input{font-family:inherit;font-size:12.5px;background:#1a1a2e;border:1px solid #2a2a3e;
  border-radius:6px;padding:6px 8px;color:#f0f0f5;width:100%;box-sizing:border-box}
.uc-prf-name-input:focus{border-color:#10b981;outline:none}
.uc-prf-fields{display:flex;flex-direction:column;gap:4px;max-height:180px;overflow-y:auto}
.uc-prf-field-row{display:flex;align-items:center;gap:7px;font-size:11.5px;cursor:pointer;
  background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;padding:5px 8px}
.uc-prf-field-row input{accent-color:#10b981;margin:0;flex:0 0 auto}
.uc-prf-field-name{color:#9ca3af;flex:0 0 auto;min-width:72px}
.uc-prf-field-value{color:#e5e7eb;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.uc-user-picker{max-width:320px}
.uc-user-row{cursor:pointer}
.uc-user-row:hover{border-color:#10b981}
.uc-user-avatar{width:26px;height:26px;border-radius:50%;background:#12201d;border:1px solid #10b981;
  color:#10b981;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px;flex:0 0 auto}
.uc-user-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px}
.uc-user-dots{letter-spacing:.18em;font-size:9px}
@media (prefers-color-scheme: light){
  .uc-prf-row[aria-selected="true"]{background:#ecfdf5}
  .uc-prf-name-input,.uc-prf-field-row{background:#f9fafb;border-color:#e5e7eb;color:#1a1a2e}
  .uc-prf-field-name{color:#6b7280}
  .uc-prf-field-value{color:#1a1a2e}
  .uc-user-avatar{background:#ecfdf5}
}
`

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return
    const style = document.createElement('style')
    style.id = STYLE_ID
    style.textContent = OVERLAY_CSS
    document.documentElement.appendChild(style)
  }

  // --- Overlay: Auto-fill available ---------------------------------------

  function removeOverlay(id) {
    const el = document.getElementById(id)
    if (el && el.parentNode) el.parentNode.removeChild(el)
  }

  // v2.17.0 — R26-B2: the global behavior toggles (Brave parity — Brave has
  // "Offer to save passwords" and "Auto sign-in"; UCrypt had both hard-wired
  // ON). Read LIVE on every offer so flipping the switch applies without a
  // reload. chrome.storage is available to content scripts.
  async function behaviorPrefs() {
    try {
      const b = (await chrome.storage.local.get('ucrypt:behavior'))['ucrypt:behavior'] || {}
      return {
        offerSave: typeof b.offerSave === 'boolean' ? b.offerSave : true,
        autoFill: typeof b.autoFill === 'boolean' ? b.autoFill : true,
        // R59-F1 — device-local picker identifier disclosure (default ON per
        // the owner display contract; never synced — this is storage.local).
        showIdentifiers: typeof b.showIdentifiers === 'boolean' ? b.showIdentifiers : true,
        // v2.42.8 — R71-P: the two profile toggles ride the same key. The
        // lib/prefs.js BEHAVIOR contract is mirrored here (classic script).
        profileFill: typeof b.profileFill === 'boolean' ? b.profileFill : true,
        profileCapture: typeof b.profileCapture === 'boolean' ? b.profileCapture : true,
      }
    } catch {
      return { offerSave: true, autoFill: true, showIdentifiers: true, profileFill: true, profileCapture: true }
    }
  }

  // R59-F1 — the primary identity of a picker row. Full username/email by
  // default (owner order: a date cannot select an account); a local ordinal
  // when identifiers are hidden. NEVER a password/TOTP/note/history value.
  function pickerPrimaryLabel(entry, idx, showIdentifiers) {
    if (!showIdentifiers) return msg('ovlPickerOrdinal', [String(idx + 1)], 'Account ' + (idx + 1))
    const u = String(entry.username || '').trim()
    return u || msg('ovlPickerNoUser', undefined, '(no username)')
  }

  // R59-F1 — secondary metadata: the entry's domain ONLY when it differs from
  // the current page (alias disambiguation) + the updated date (helps, never
  // replaces the username).
  function pickerMetaLabel(entry, pageDomain) {
    const bits = []
    const d = String(entry.domain || '').replace(/^www\./, '')
    if (d && d !== pageDomain) bits.push(d)
    const ts = Number(entry.updatedAt || entry.createdAt || 0)
    if (ts) {
      try { bits.push(new Date(ts).toLocaleDateString()) } catch { /* skip date */ }
    }
    return bits.join(' · ')
  }

  function showAutoFillOverlay(entries, anchorField, display = {}) {
    // R59-F2 — closed shadow first; the masked light-DOM picker is the
    // fallback ONLY for browsers without attachShadow (never raw identifiers
    // in page-readable DOM).
    const showIdentifiers = display.showIdentifiers !== false
    if (!attachShadowSupported()) return showAutoFillOverlayLegacy(entries, anchorField)
    const surf = openShadowSurface(OVERLAY_ID)
    if (!surf) return showAutoFillOverlayLegacy(entries, anchorField)
    if (!entries || entries.length === 0) { closeShadowSurface(OVERLAY_ID); return }
    if (!frameIsUsable()) { closeShadowSurface(OVERLAY_ID); return } // v2.11.0 — F7: stay silent in small frames
    // R45: while the OTP chip overlay or the suggest-strong-password chip is
    // showing, the auto-fill overlay stays silent — two anchored helpers
    // fighting over the same fields made the deeper one unclickable.
    if (surfaceEl(OTP_OVERLAY_ID) || document.getElementById(SUGGEST_CHIP_ID)) { closeShadowSurface(OVERLAY_ID); return }

    const root = surf.root
    const pageDomain = domainFromLocation()
    const close = () => dismissSurface(OVERLAY_ID)

    const wrap = document.createElement('div')
    wrap.id = OVERLAY_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlAutofillAria', undefined, 'UCrypt auto-fill'))

    const closeBtn = document.createElement('button')
    closeBtn.className = 'ck-close'
    closeBtn.textContent = '×'
    closeBtn.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    closeBtn.onclick = close

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlAutofillHead', undefined, 'Auto-fill available')

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = entries.length === 1
      ? msg('ovlUseOne', [pickerPrimaryLabel(entries[0], 0, showIdentifiers), entries[0].domain], `Use ${pickerPrimaryLabel(entries[0], 0, showIdentifiers)} for ${entries[0].domain}?`)
      : msg('ovlUseMany', [String(entries.length)], `${entries.length} saved logins for this site`)

    wrap.appendChild(closeBtn)
    wrap.appendChild(head)
    wrap.appendChild(sub)

    if (entries.length > 1) {
      // R59-F1 §2.3 — multi-account usability: count line, in-picker search
      // for >5 rows, visible rows capped with scroll. The filter term lives
      // and dies inside this closed shadow — it never reaches the page world.
      let searchInput = null
      if (entries.length > 5) {
        searchInput = document.createElement('input')
        searchInput.type = 'text'
        searchInput.className = 'ck-picker-search'
        searchInput.placeholder = msg('ovlPickerSearch', undefined, 'Filter matching accounts…')
        searchInput.setAttribute('aria-label', msg('ovlPickerSearchAria', undefined, 'Filter matching accounts'))
        searchInput.autocomplete = 'off'
        searchInput.spellcheck = false
        wrap.appendChild(searchInput)
      }

      const countLine = document.createElement('div')
      countLine.className = 'ck-picker-count'
      countLine.setAttribute('role', 'status')
      wrap.appendChild(countLine)

      const list = document.createElement('div')
      list.className = 'ck-entries'
      list.setAttribute('role', 'listbox')
      list.setAttribute('aria-label', msg('ovlPickerListAria', undefined, 'Matching accounts'))
      wrap.appendChild(list)

      const rows = entries.map((entry, idx) => {
        const row = document.createElement('div')
        row.className = 'ck-entry-row'
        row.setAttribute('role', 'option')
        row.setAttribute('aria-selected', 'false')
        row.tabIndex = -1
        const id = document.createElement('span')
        id.className = 'ck-entry-id'
        id.textContent = pickerPrimaryLabel(entry, idx, showIdentifiers)
        const meta = document.createElement('span')
        meta.className = 'ck-entry-meta'
        meta.textContent = pickerMetaLabel(entry, pageDomain)
        const btn = document.createElement('button')
        btn.className = 'ck-btn ck-btn-primary'
        btn.textContent = msg('ovlBtnFill', undefined, 'Fill')
        // Closure-captured entry reference — no entry id in any attribute,
        // nothing the page can resolve (the tree is closed anyway).
        const fill = (e) => {
          if (e) e.preventDefault()
          performFill(entry)
          close()
        }
        btn.onclick = fill
        row.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') fill(e)
        })
        row.appendChild(id)
        row.appendChild(meta)
        row.appendChild(btn)
        list.appendChild(row)
        return { row, entry, idx }
      })

      const applyFilter = (term) => {
        const t = String(term || '').trim().toLowerCase()
        let shown = 0
        for (const { row, entry, idx } of rows) {
          const hay = showIdentifiers
            ? `${entry.username || ''} ${entry.domain || ''}`.toLowerCase()
            : `account ${idx + 1} ${entry.domain || ''}`.toLowerCase()
          const hit = !t || hay.includes(t)
          row.style.display = hit ? '' : 'none'
          if (hit) shown++
        }
        countLine.textContent = t
          ? msg('ovlPickerCountFiltered', [String(shown), String(entries.length)], `${shown} of ${entries.length} matching accounts`)
          : msg('ovlPickerCount', [String(entries.length)], `${entries.length} matching accounts`)
      }
      applyFilter('')
      if (searchInput) {
        searchInput.addEventListener('input', () => applyFilter(searchInput.value))
      }
    } else {
      const actions = document.createElement('div')
      actions.className = 'ucrypt-overlay-actions'
      const fillBtn = document.createElement('button')
      fillBtn.className = 'ck-btn ck-btn-primary'
      fillBtn.textContent = msg('ovlBtnFillNow', undefined, 'Fill now')
      fillBtn.onclick = (e) => {
        e.preventDefault()
        performFill(entries[0])
        close()
      }
      const skipBtn = document.createElement('button')
      skipBtn.className = 'ck-btn ck-btn-ghost'
      skipBtn.textContent = msg('ovlNotNow', undefined, 'Not now')
      skipBtn.onclick = close
      actions.appendChild(fillBtn)
      actions.appendChild(skipBtn)
      wrap.appendChild(actions)
    }

    // v2.17.0 — R26-B5: an "All logins…" escape hatch. R59-F1 §2.3: it opens
    // the full manager filtered to THIS origin (via a device-local handoff
    // the options page consumes and clears) — raw usernames stay extension-side.
    const allRow = document.createElement('button')
    allRow.className = 'ck-btn ck-btn-ghost'
    allRow.type = 'button'
    allRow.textContent = msg('ovlAllLogins', undefined, 'All logins…')
    allRow.onclick = async (e) => {
      e.preventDefault()
      try {
        if (pageDomain) await chrome.storage.local.set({ 'ucrypt:vaultOriginFilter': pageDomain })
      } catch { /* handoff is best-effort */ }
      await send('OPEN_OPTIONS', { tab: true })
      close()
    }
    wrap.appendChild(allRow)

    root.appendChild(wrap)
    // v2.17.0 — R26-B5: FIELD-ANCHORED placement (corner fallback unchanged).
    if (anchorField && anchorField.isConnected) {
      try {
        const place = () => {
          try {
            if (!wrap.isConnected) { cleanupAnchorTracking(); return }
            if (!anchorField.isConnected) { close(); cleanupAnchorTracking(); return }
            const w = wrap.offsetWidth || 280
            const h = wrap.offsetHeight || 160
            const pos = anchorRectFor(anchorField, w, h)
            wrap.style.right = 'auto'
            wrap.style.bottom = 'auto'
            wrap.style.left = Math.round(pos.left) + 'px'
            wrap.style.top = Math.round(pos.top) + 'px'
          } catch { cleanupAnchorTracking() }
        }
        const reposition = () => { place() }
        window.addEventListener('scroll', reposition, { passive: true, capture: true })
        window.addEventListener('resize', reposition, { passive: true })
        const cleanupAnchorTracking = () => {
          window.removeEventListener('scroll', reposition, { capture: true })
          window.removeEventListener('resize', reposition)
        }
        place()
        const anchorObserver = new MutationObserver(() => { if (!wrap.isConnected) { cleanupAnchorTracking(); anchorObserver.disconnect() } })
        anchorObserver.observe(document.documentElement, { childList: true, subtree: true })
      } catch { /* corner fallback */ }
    }
    // R85 (§7 prompt-persistence law): NO auto-dismiss. This surface carries
    // a pending decision — it closes only by explicit user action.
  }

  // R59-F1 §2.2 — FALLBACK picker for browsers without attachShadow: masked
  // identifiers in page-readable DOM are acceptable here ONLY because the
  // protected surface is unavailable; raw identifiers never render. The
  // "All logins…" handoff to the extension surface stays available.
  function showAutoFillOverlayLegacy(entries, anchorField) {
    ensureStyle()
    removeOverlay(OVERLAY_ID)
    if (!entries || entries.length === 0) return
    if (!frameIsUsable()) return
    if (document.getElementById(OTP_OVERLAY_ID) || document.getElementById(SUGGEST_CHIP_ID)) return

    const wrap = document.createElement('div')
    wrap.id = OVERLAY_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlAutofillAria', undefined, 'UCrypt auto-fill'))

    const close = document.createElement('button')
    close.className = 'ck-close'
    close.textContent = '×'
    close.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    close.onclick = () => removeOverlay(OVERLAY_ID)

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlAutofillHead', undefined, 'Auto-fill available')

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = entries.length === 1
      ? msg('ovlUseOne', [mask(entries[0].username), entries[0].domain], `Use ${mask(entries[0].username)} for ${entries[0].domain}?`)
      : msg('ovlUseMany', [String(entries.length)], `${entries.length} saved logins for this site`)

    wrap.appendChild(close)
    wrap.appendChild(head)
    wrap.appendChild(sub)

    if (entries.length > 1) {
      const list = document.createElement('div')
      list.className = 'ck-entries'
      list.setAttribute('role', 'listbox')
      list.setAttribute('aria-label', msg('ovlPickerListAria', undefined, 'Matching accounts'))
      entries.forEach((entry, idx) => {
        const row = document.createElement('div')
        row.className = 'ck-entry-row'
        row.setAttribute('role', 'option')
        row.setAttribute('aria-selected', 'false')
        const code = document.createElement('code')
        code.textContent = `${mask(entry.username)} · ${new Date(entry.updatedAt || entry.createdAt || Date.now()).toLocaleDateString()}`
        const btn = document.createElement('button')
        btn.className = 'ck-btn ck-btn-primary'
        btn.textContent = msg('ovlBtnFill', undefined, 'Fill')
        btn.onclick = (e) => {
          e.preventDefault()
          performFill(entry)
          removeOverlay(OVERLAY_ID)
        }
        row.appendChild(code)
        row.appendChild(btn)
        list.appendChild(row)
      })
      wrap.appendChild(list)
    } else {
      const actions = document.createElement('div')
      actions.className = 'ucrypt-overlay-actions'
      const fillBtn = document.createElement('button')
      fillBtn.className = 'ck-btn ck-btn-primary'
      fillBtn.textContent = msg('ovlBtnFillNow', undefined, 'Fill now')
      fillBtn.onclick = (e) => {
        e.preventDefault()
        performFill(entries[0])
        removeOverlay(OVERLAY_ID)
      }
      const skipBtn = document.createElement('button')
      skipBtn.className = 'ck-btn ck-btn-ghost'
      skipBtn.textContent = msg('ovlNotNow', undefined, 'Not now')
      skipBtn.onclick = () => removeOverlay(OVERLAY_ID)
      actions.appendChild(fillBtn)
      actions.appendChild(skipBtn)
      wrap.appendChild(actions)
    }

    const allRow = document.createElement('button')
    allRow.className = 'ck-btn ck-btn-ghost'
    allRow.type = 'button'
    allRow.textContent = msg('ovlAllLogins', undefined, 'All logins…')
    allRow.onclick = async (e) => {
      e.preventDefault()
      await send('OPEN_OPTIONS', { tab: true })
      removeOverlay(OVERLAY_ID)
    }
    wrap.appendChild(allRow)

    document.documentElement.appendChild(wrap)
    // R85 (§7 prompt-persistence law): NO auto-dismiss (interactive surface).
  }

  function mask(s) {
    if (!s) return ''
    s = String(s)
    if (s.length <= 2) return s[0] + '•'.repeat(s.length - 1)
    return s[0] + '•'.repeat(s.length - 2) + s[s.length - 1]
  }

  // --- Overlay: 2FA code fill chip (v2.5.0) --------------------------------

  let lastOtpUrl = null // show the chip once per SPA navigation, not on every re-init

  function showOtpChip(tokens, otpField) {
    // R59-F2 — token labels are vault-derived: render inside a closed shadow
    // root; the light-DOM path remains only as the no-attachShadow fallback.
    // v2.42.7 — R70 (F-R70-UI-1): the legacy light-DOM leftover is removed
    // BEFORE the shadow surface opens. The old order opened the surface first
    // and THEN called removeOverlay(OTP_OVERLAY_ID) — which resolves the
    // freshly created light-DOM host by id and destroys it, leaving the chip
    // rendered into a detached closed-shadow root: mounted, error-free, and
    // permanently invisible (the root cause of the R70 E2E overlay holds).
    removeOverlay(OTP_OVERLAY_ID)
    const surf = attachShadowSupported() ? openShadowSurface(OTP_OVERLAY_ID) : null
    if (!surf) ensureStyle()
    const mount = surf ? surf.root : document.documentElement
    const dismiss = () => dismissSurface(OTP_OVERLAY_ID)
    if (!otpField || !tokens || tokens.length === 0) { if (surf) closeShadowSurface(OTP_OVERLAY_ID); return }
    if (!frameIsUsable()) { if (surf) closeShadowSurface(OTP_OVERLAY_ID); return } // v2.11.0 — F7: stay silent in small frames
    lastOtpUrl = window.location.href

    const wrap = document.createElement('div')
    wrap.id = OTP_OVERLAY_ID
    wrap.className = 'ucrypt-overlay' + (document.getElementById(OVERLAY_ID) ? ' top' : '')
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlOtpAria', undefined, 'UCrypt 2FA code fill'))

    const close = document.createElement('button')
    close.className = 'ck-close'
    close.textContent = '×'
    close.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    close.onclick = () => removeOverlay(OTP_OVERLAY_ID)

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlOtpHead', undefined, '2FA code ready')

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = msg('ovlOtpSub', undefined, 'Click a token to fill the verification field:')

    const status = document.createElement('div')
    status.className = 'ucrypt-otp-status'
    status.setAttribute('role', 'status')

    wrap.appendChild(close)
    wrap.appendChild(head)
    wrap.appendChild(sub)

    const list = document.createElement('div')
    list.className = 'ck-entries'
    // v2.9.0 — the background RANKS tokens for this site (exact domain → same
    // eTLD+1 → others) and tags matches; matched tokens lead the chip.
    const hasSiteMatches = tokens.some(t => t.match)
    if (hasSiteMatches) {
      const note = document.createElement('div')
      note.className = 'ucrypt-otp-sitenote'
      note.textContent = msg('ovlOtpSiteNote', undefined, 'Tokens for this site are listed first')
      list.appendChild(note)
    }
    for (const t of tokens) {
      const row = document.createElement('button')
      row.className = 'ucrypt-otp-token' + (t.match ? ' is-site' : '')
      row.type = 'button'
      const name = document.createElement('span')
      name.className = 'uc-otp-name'
      const issuer = document.createElement('span')
      issuer.className = 'uc-otp-issuer'
      issuer.textContent = t.issuer ? t.issuer + ' ·' : ''
      name.appendChild(issuer)
      name.appendChild(document.createTextNode((t.match === 'exact' ? '★ ' : t.match === 'site' ? '◦ ' : '') + (t.label || msg('ovlUnlabelled', undefined, '(unlabelled)'))))
      const fill = document.createElement('span')
      fill.className = 'ck-btn ck-btn-primary'
      fill.textContent = msg('ovlBtnFill', undefined, 'Fill')
      row.appendChild(name)
      row.appendChild(fill)
      row.onclick = async (e) => {
        e.preventDefault()
        row.disabled = true
        status.textContent = ''
        const r = await send('TOTP_AUTOFILL_CODE', { label: t.label })
        row.disabled = false
        if (r && r.ok && r.code) {
          setNativeValue(otpField, r.code)
          otpField.focus()
          otpField.style.transition = 'box-shadow .2s'
          otpField.style.boxShadow = '0 0 0 2px #10b981'
          setTimeout(() => { otpField.style.boxShadow = '' }, 800)
          status.textContent = msg('ovlOtpFilled', [String(r.remainingSec)], `Code filled — valid for ${r.remainingSec}s more`)
        } else {
          status.textContent = msg('ovlOtpErr', [(r && r.error) || msg('icUnknownError', undefined, 'unknown error')], 'Could not compute a code: ' + ((r && r.error) || 'unknown error'))
          status.style.color = '#f87171'
          setTimeout(() => { status.textContent = ''; status.style.color = '#10b981' }, 4000)
        }
      }
      list.appendChild(row)
    }
    wrap.appendChild(list)
    wrap.appendChild(status)

    mount.appendChild(wrap)
    // R85 (§7 prompt-persistence law): NO auto-dismiss (interactive surface —
    // the code chip fills only on an explicit user tap).
  }

  async function maybeOfferOtpFill() {
    // Requires the global detector from lib/otp-field.global.js (manifest).
    const detector = (typeof globalThis !== 'undefined' && globalThis.UCRYPT_OTP) || null
    if (!detector) return
    if (window.location.href === lastOtpUrl) return // already offered on this URL
    const otpField = detector.findOtpField(document)
    if (!otpField) return
    const r = await send('TOTP_AUTOFILL_LIST')
    if (!r || !r.ok || r.locked) return // locked vaults stay silent — no nagging
    if (r.tokens && r.tokens.length > 0) showOtpChip(r.tokens, otpField)
  }

  // --- Overlay: Save / Update this password --------------------------------

  // v2.9.0 — the prompt now MATCHES what will happen (Brave/Chrome parity):
  //   - an existing username signing in with a DIFFERENT password → "Update
  //     password for …?" (was a generic "Save this password?" that actually
  //     overwrote the entry — clinically wrong words over a real overwrite),
  //   - a persistent "Never for this site" exception (device-local),
  //   - a pre-accept strength/breach hint from the offline analyzer.
  function showSaveOverlay(username, password, domain, opts = {}) {
    ensureStyle()
    removeOverlay(SAVE_OVERLAY_ID)

    const isUpdate = !!opts.isUpdate
    if (!frameIsUsable()) {
      // v2.13.0 — R22-F2: a login submitted inside a small embedded frame
      // (ad-slot or widget) used to be silently dropped: the overlay refused
      // to render where it cannot be seen, so the user never got a chance to
      // save. Chrome/Brave anchor the bubble to browser chrome — relay the
      // prompt to the TOP frame, where the overlay has room. The relay rides
      // the same in-memory worker channel every SAVE_ENTRY already uses.
      relaySavePromptToTop(username, password, domain, opts)
      return
    }

    const wrap = document.createElement('div')
    wrap.id = SAVE_OVERLAY_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', isUpdate
      ? msg('ovlSaveAriaUpdate', undefined, 'Update password in UCrypt')
      : msg('ovlSaveAriaSave', undefined, 'Save password to UCrypt'))

    const close = document.createElement('button')
    close.className = 'ck-close'
    close.textContent = '×'
    close.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    close.onclick = () => {
      if (!opts.fromRelay) consumeSaveCandidate() // R125 §2 — dismissed by action
      removeOverlay(SAVE_OVERLAY_ID)
    }

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> '
      + (isUpdate ? msg('ovlSaveHeadUpdate', undefined, 'Update password for this login?') : msg('ovlSaveHeadSave', undefined, 'Save this password?'))

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = isUpdate
      ? msg('ovlSaveSubUpdate', [mask(username), domain], `${mask(username)} @ ${domain} — replace the saved password`)
      : msg('ovlSaveSub', [mask(username), domain], `${mask(username)} @ ${domain}`)

    // v2.9.0 — strength/breach hint (async: arrives after the overlay shows).
    const hint = document.createElement('div')
    hint.className = 'ucrypt-overlay-sub uc-save-hint'
    hint.setAttribute('role', 'status')
    hint.style.display = 'none'
    send('CHECK_PASSWORD_STRENGTH', { password }).then((r) => {
      if (!r || !r.ok || !r.warn) return
      hint.textContent = r.breached
        ? msg('ovlHintBreached', [r.label.toLowerCase(), String(r.bits)], `⚠ This password appears in known breach lists — ${r.label.toLowerCase()} (${r.bits} bits). Consider generating a strong one.`)
        : msg('ovlHintWeak', [r.label, String(r.bits)], `⚠ ${r.label} password (~${r.bits} bits) — the in-page generator can make a strong one.`)
      hint.style.display = 'block'
      hint.style.color = '#fbbf24'
    })

    const actions = document.createElement('div')
    actions.className = 'ucrypt-overlay-actions'

    const saveBtn = document.createElement('button')
    saveBtn.className = 'ck-btn ck-btn-primary'
    saveBtn.textContent = isUpdate ? msg('ovlBtnUpdate', undefined, 'Update') : msg('ovlBtnSave', undefined, 'Save')
    const errLine = document.createElement('div')
    errLine.className = 'ucrypt-overlay-sub ck-save-error'
    errLine.setAttribute('role', 'alert')
    errLine.style.color = '#f87171'
    errLine.style.display = 'none'
    saveBtn.onclick = async (e) => {
      e.preventDefault()
      saveBtn.disabled = true
      saveBtn.textContent = isUpdate ? msg('ovlBtnUpdating', undefined, 'Updating…') : msg('ovlBtnSaving', undefined, 'Saving…')
      errLine.style.display = 'none'
      const r = await send('SAVE_ENTRY', { domain, username, password })
      if (r && r.ok) {
        if (!opts.fromRelay) consumeSaveCandidate() // R125 §2 — the answer is in: never re-ask
        saveBtn.textContent = isUpdate ? msg('ovlBtnUpdated', undefined, 'Updated ✓') : msg('ovlBtnSaved', undefined, 'Saved ✓')
        setTimeout(() => removeOverlay(SAVE_OVERLAY_ID), 800)
      } else {
        saveBtn.disabled = false
        saveBtn.textContent = isUpdate ? msg('ovlBtnUpdate', undefined, 'Update') : msg('ovlBtnSave', undefined, 'Save')
        // v2.3.1: inline error instead of alert() — keeps the user in context.
        errLine.textContent = msg('ovlSaveErr', [(r && r.error) || msg('icUnknownError', undefined, 'unknown error. Is the vault unlocked?')], 'Could not save: ' + ((r && r.error) || 'unknown error. Is the vault unlocked?'))
        errLine.style.display = 'block'
      }
    }

    const neverBtn = document.createElement('button')
    neverBtn.className = 'ck-btn ck-btn-ghost'
    neverBtn.textContent = msg('ovlNotNow', undefined, 'Not now')
    neverBtn.onclick = () => {
      if (!opts.fromRelay) consumeSaveCandidate() // R125 §2 — an explicit no is never re-asked
      removeOverlay(SAVE_OVERLAY_ID)
    }

    // v2.9.0 — persistent per-site exception (Brave parity). Device-local;
    // suppresses only the SAVE prompt, never autofill.
    const siteNeverBtn = document.createElement('button')
    siteNeverBtn.className = 'ck-btn ck-btn-ghost'
    siteNeverBtn.textContent = msg('ovlBtnNever', undefined, 'Never for this site')
    siteNeverBtn.title = msg('ovlNeverTitle', [domain], 'UCrypt will stop asking to save passwords on ' + domain)
    siteNeverBtn.onclick = async (e) => {
      e.preventDefault()
      if (!opts.fromRelay) consumeSaveCandidate() // R125 §2 — the exception is the answer
      const r = await send('NEVER_SAVE_ADD', { domain })
      if (r && r.ok) {
        const note = document.createElement('div')
        note.className = 'ucrypt-overlay-sub'
        note.textContent = msg('ovlNeverDone', [domain], `OK — UCrypt will no longer offer to save on ${domain}.`)
        note.style.color = '#10b981'
        actions.replaceWith(note)
        setTimeout(() => removeOverlay(SAVE_OVERLAY_ID), 1600)
      } else {
        errLine.textContent = msg('ovlNeverErr', [(r && r.error) || msg('icUnknownError', undefined, 'unknown error')], 'Could not add the exception: ' + ((r && r.error) || 'unknown error'))
        errLine.style.display = 'block'
      }
    }

    actions.appendChild(saveBtn)
    actions.appendChild(neverBtn)
    actions.appendChild(siteNeverBtn)

    wrap.appendChild(close)
    wrap.appendChild(head)
    wrap.appendChild(sub)
    wrap.appendChild(hint)
    wrap.appendChild(actions)
    wrap.appendChild(errLine)

    document.documentElement.appendChild(wrap)
    // R85 (§7 prompt-persistence law): the 60 s hard timeout is GONE — the
    // save decision (Save / Update / Not now / Never) is the user's, and the
    // bubble closes only by explicit action.
  }

  // v2.13.0 — R22-F2: ask the worker to re-render the save prompt in the
  // top frame (background forwards to frameId 0). In-memory only.
  function relaySavePromptToTop(username, password, domain, opts = {}) {
    try {
      if (window.top === window) return // nothing above us to host the prompt
      send('SAVE_PROMPT_RELAY', {
        domain,
        username: String(username || ''),
        password: String(password || ''),
        isUpdate: !!opts.isUpdate,
      })
    } catch { /* best-effort */ }
  }

  // --- R125 §2 — F-R125-CAPTURE-1: THE CAPTURE-SUPREMACY SPINE (law 0.39) ---
  //
  // The forensic on the sealed bytes proved the pipeline alive ONLY on the
  // synthetic in-page-submit shape:
  //   SHAPE-B  a classical form that NAVIGATES tears the page down mid
  //            round-trip — the async GET_ENTRIES→prefs→offer chain never
  //            finishes; the bubble never renders; nothing saves.
  //   SHAPE-C  an SPA click login (no <form>) never fires a submit event at
  //            all — only the password-field Enter path was covered.
  // THE ROOT FIX, two halves, both at the trust boundary:
  //   1. THE STAGED CANDIDATE — at submit (and at a login-looking click), the
  //      candidate rides to the worker SYNCHRONOUSLY, before anything async.
  //      The worker holds it in memory (tab-keyed, TTL-capped, one-shot) and
  //      re-prompts on the tab's LANDING page via the SHOW_SAVE_PROMPT relay
  //      the small-frame path already uses — the Chrome-anchored shape.
  //   2. THE CLICK CAPTURE — a capture-phase click listener arms the same
  //      snapshot when a login-looking button is pressed with a filled
  //      password field; if no submit event follows (the SPA shape), the
  //      in-page offer runs after a short settle window.
  // Every in-page offer terminal consumes the staged candidate (Save, Not
  // now, Never, ✕) — a user's explicit answer is never asked twice. The
  // candidate is in-memory on both ends: never persisted, never synced,
  // wiped on lock (the credential-layer law 0.14/0.24).

  let lastSubmitAt = 0 // a real submit event owns the flow (the SPA timer defers to it)

  // The sync username snapshot: typed value → the two-step candidate memory.
  // (resolveUsername is async — a navigating page cannot await it.)
  function resolveUsernameSync(usernameField) {
    const direct = usernameField ? String(usernameField.value || '').trim() : ''
    if (direct) return direct
    return lastUsernameCandidate || ''
  }

  function stageSaveCandidate(username, password, domainOverride) {
    try {
      const domain = domainOverride || domainFromLocation()
      if (!domain || !password) return
      send('SAVE_CANDIDATE_STAGE', {
        domain,
        username: String(username || ''),
        password: String(password),
      })
    } catch { /* best-effort — the in-page path still runs */ }
  }

  function consumeSaveCandidate() {
    try { send('SAVE_CANDIDATE_CONSUME', {}) } catch { /* best-effort */ }
  }

  // The SPA click-capture. A button OUTSIDE any <form> whose label reads like
  // a login action, with a filled visible password field on the page, arms
  // the candidate snapshot at the click itself (navigation-safe) and offers
  // in-page only if no submit event followed the click. Buttons INSIDE a
  // form never arm here — the form's submit event owns them (no double
  // offer; the staged candidate from the submit covers the navigate case).
  let armedSpaClick = null
  document.addEventListener('click', (e) => {
    try {
      const t = e.target
      if (!t || t.nodeType !== 1) return
      const tag = t.tagName
      const buttonish = tag === 'BUTTON'
        || (tag === 'INPUT' && ['submit', 'button'].includes(String(t.type || '').toLowerCase()))
        || (t.getAttribute && t.getAttribute('role') === 'button')
      if (!buttonish) return
      if (t.closest && t.closest('form')) return // the submit event owns form buttons
      const pw = Array.from(document.querySelectorAll('input[type=password]')).find(isVisible)
      const pwVal = pw ? String(pw.value || '') : ''
      if (!pwVal) return
      const label = String((t.textContent || '') + ' ' + (t.getAttribute('aria-label') || '') + ' ' + (t.value || ''))
      if (!/(sign\s*in|log\s*in|log\s*on|submit|continue|next|enter|register|sign\s*up|access|connect|acceder|anmelden|connexion|войти|登录|登入)/i.test(label)) return
      const userEl = document.querySelector('input[type=email], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[name*="login" i]')
      const user = String((userEl && userEl.value) || lastUsernameCandidate || '')
      const domain = domainFromLocation()
      if (!domain) return
      armedSpaClick = { at: Date.now(), user, pass: pwVal, domain }
      stageSaveCandidate(user, pwVal, domain) // navigation-safe from the click itself
      const arm = armedSpaClick
      setTimeout(() => { maybeOfferSpaCapture(arm) }, 1400)
    } catch { /* best-effort */ }
  }, true)

  async function maybeOfferSpaCapture(arm) {
    try {
      if (!arm || armedSpaClick !== arm) return // superseded or consumed by a newer click
      if (Date.now() - lastSubmitAt < 3000) return // a real submit owned the flow
      if (document.getElementById(SAVE_OVERLAY_ID)) return // an offer is already up
      if (!frameIsUsable()) return
      const r = await send('GET_ENTRIES', { domain: arm.domain })
      if (!r || !r.ok || !r.entries) return
      if (r.neverSave) return // v2.9.0 — per-site exception
      const b = await behaviorPrefs()
      if (!b.offerSave) return // v2.17.0 — R26-B2 global gate
      const exact = r.entries.some((en) => en.username === arm.user && en.password === arm.pass)
      if (exact) return // already saved — Chrome parity silence
      const isUpdate = r.entries.some((en) => en.username === arm.user && en.password !== arm.pass)
      showSaveOverlay(arm.user, arm.pass, arm.domain, { isUpdate })
    } catch { /* best-effort */ }
  }

  // --- Fill fields ---------------------------------------------------------

  // v2.13.0 — R22-F1: change-password forms. The submit watcher used to read
  // the FIRST visible password field — the CURRENT-password box. On
  // "old + new + confirm" forms that meant the vault compared (and offered to
  // save) the OLD secret while the NEW one was ignored — the exact opposite
  // of what Chrome/Brave do (they capture the NEW password). When the form
  // declares autocomplete=new-password fields and the user typed into one,
  // that typed value is the submission's password.
  function captureSubmitPassword(form, passwordField) {
    if (form) {
      const fresh = Array.from(form.querySelectorAll('input[type=password]'))
        .filter(isVisible)
        .filter(f => (f.autocomplete || '').toLowerCase() === 'new-password')
        .find(f => (f.value || '').length > 0)
      if (fresh) return fresh.value
    }
    return passwordField ? (passwordField.value || '') : ''
  }

  function setNativeValue(el, value) {
    if (!el) return
    // Use the native setter to trigger React/Vue change listeners
    try {
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
        : el.tagName === 'SELECT' ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype
      const setter = Object.getOwnPropertyDescriptor(proto, 'value').set
      setter.call(el, value)
    } catch {
      el.value = value
    }
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  }

  function performFill(entry) {
    const login = detectLoginForm()
    if (!login || !login.passwordField) {
      console.warn('[UCrypt] No password field to fill on this page')
      return
    }
    setNativeValue(login.passwordField, entry.password || '')
    if (login.usernameField && entry.username) {
      setNativeValue(login.usernameField, entry.username)
    }
    login.passwordField.focus()
    // Brief visual cue
    login.passwordField.style.transition = 'box-shadow .2s'
    login.passwordField.style.boxShadow = '0 0 0 2px #10b981'
    setTimeout(() => { login.passwordField.style.boxShadow = '' }, 800)
    // v2.16.0 — last-used tracking (device-local): every real fill touches
    // the entry so the "Recently used" sort reflects THIS device's actual
    // usage. Fire-and-forget; never surfaces errors and never blocks.
    try {
      send('TOUCH_ENTRY', { domain: entry.domain, username: entry.username }).catch(() => {})
    } catch { /* best-effort */ }
  }

  // --- v2.19.0 — R28-B1: CARD / IDENTITY FORM-FILL (Brave parity III) ------
  // The last feasible gap in the round-25 24-feature Brave matrix: imported
  // cards and identities could be VIEWED and EDITED but never filled into a
  // web form. Chrome/Brave fill addresses and payment methods from the
  // browser; UCrypt now does the same from the vault via two context-menu
  // entry points ("Fill card" / "Fill identity"). Explicit user action →
  // deliberately NOT gated by the Offer-to-save / Auto sign-in toggles,
  // exactly like the context-menu login save. Detection follows the HTML
  // autofill spec first (autocomplete tokens), then field-name heuristics.

  const DATA_PICKER_ID = 'ucrypt-data-picker'

  // [kind, name/id/placeholder hint regex, autocomplete tokens (space-list)]
  const CARD_FIELD_KINDS = [
    ['cardNumber', /(cc-?number|card-?number|cardnum|cc-?num|card-?num)/i, 'cc-number'],
    ['cardExpMonth', /(cc-?exp-?month|card-?exp-?month|exp-?month)/i, 'cc-exp-month'],
    ['cardExpYear', /(cc-?exp-?year|card-?exp-?year|exp-?year)/i, 'cc-exp-year'],
    ['cardExp', /(cc-?exp\b|card-?exp\b|expir|valid\s*thru|valid\s*until|valid\s*thru)/i, 'cc-exp'],
    ['cardCode', /(cc-?csc|cc-?cvv|\bcvv\b|\bcvc\b|card-?code|security-?code|card-?verif)/i, 'cc-csc'],
    ['cardHolder', /(cc-?name|card-?holder|card-?name|name-?on-?card)/i, 'cc-name'],
  ]
  const ADDR_FIELD_KINDS = [
    ['addrEmail', /(^|-|_)(e-?mail)/i, 'email'],
    ['addrPhone', /(^|-|_)(phone|mobile|tel\b|cell)/i, 'tel'],
    ['addrOrg', /(^|-|_)(org|company|business|employer|firm)/i, 'organization'],
    ['addrStreet', /(street|address-?line-?1|address-?1|addr-?1|street-?address)/i, 'street-address address-line1'],
    ['addrCity', /(city|town|locality)/i, 'address-level2'],
    ['addrState', /(state|province|region)/i, 'address-level1'],
    ['addrZip', /(zip|postal|post-?code|pin-?code)/i, 'postal-code'],
    ['addrCountry', /country/i, 'country country-name'],
    ['addrName', /(^|-|_)(name|full-?name|your-?name|first-?last)/i, 'name'],
  ]

  function autocompleteTokens(el) {
    return String(el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/).filter(Boolean)
  }

  function labelForField(el) {
    try {
      if (el.labels && el.labels.length) return (el.labels[0].textContent || '').trim()
      if (el.id) {
        const lab = document.querySelector('label[for="' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id) + '"]')
        if (lab) return (lab.textContent || '').trim()
      }
      const wrap = el.closest('label')
      if (wrap) return (wrap.textContent || '').trim()
    } catch { /* labels unavailable — name heuristics still apply */ }
    return ''
  }

  /** Classify one visible input against the kind tables for a fill type. */
  function classifyDataField(el, kinds) {
    const toks = autocompleteTokens(el)
    const haystack = [el.name, el.id, el.getAttribute('placeholder'), labelForField(el)]
      .filter(Boolean).join(' ')
    // 1. autocomplete token — the spec answer, wins outright.
    for (const [kind, , tokens] of kinds) {
      for (const tok of tokens.split(' ')) {
        if (toks.includes(tok)) return { kind, strong: true }
      }
    }
    // 2. heuristics on the machine-readable names FIRST (id/name), then the
    //    human labels — a field named "email_label" must not match "name".
    const idish = [el.name, el.id].filter(Boolean).join(' ')
    for (const [kind, hint] of kinds) {
      if (hint.test(idish)) return { kind, strong: false }
    }
    for (const [kind, hint] of kinds) {
      if (hint.test(haystack)) return { kind, strong: false }
    }
    return null
  }

  /** Map of kind → element for the requested fill type (first match wins). */
  function detectDataFields(type) {
    const kinds = type === 'card' ? CARD_FIELD_KINDS : ADDR_FIELD_KINDS
    const found = {}
    const inputs = document.querySelectorAll('input, select')
    for (const el of inputs) {
      if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button' || el.type === 'checkbox' || el.type === 'radio' || el.type === 'file') continue
      if (!isVisible(el)) continue
      const hit = classifyDataField(el, kinds)
      if (!hit) continue
      if (found[hit.kind] && hit.strong !== true) continue // first match stays; a later autocomplete match may override
      found[hit.kind] = el
    }
    return found
  }

  function setSelectValue(sel, value) {
    if (!sel || sel.tagName !== 'SELECT' || !value) return false
    const want = String(value).trim().toLowerCase()
    for (const opt of sel.options || []) {
      if ((opt.value || '').trim().toLowerCase() === want || (opt.textContent || '').trim().toLowerCase() === want) {
        setNativeValue(sel, opt.value)
        return true
      }
    }
    // Partial match — "United States" stored vs "United States of America".
    for (const opt of sel.options || []) {
      const text = (opt.textContent || '').trim().toLowerCase()
      if (want.length >= 4 && (text.includes(want) || want.includes(text))) {
        setNativeValue(sel, opt.value)
        return true
      }
    }
    return false
  }

  /** Fill the detected card/identity fields from a vault entry. */
  function fillDataEntry(entry, type) {
    const detected = detectDataFields(type)
    const payload = type === 'card' ? (entry.card || {}) : (entry.address || {})
    let filled = 0
    const cue = (el) => {
      if (!el) return
      el.style.transition = 'box-shadow .2s'
      el.style.boxShadow = '0 0 0 2px #10b981'
      setTimeout(() => { el.style.boxShadow = '' }, 800)
    }
    const put = (kind, value) => {
      if (!value || !detected[kind]) return
      const el = detected[kind]
      if (el.tagName === 'SELECT') {
        if (setSelectValue(el, value)) filled++
        return
      }
      setNativeValue(el, String(value))
      cue(el)
      filled++
    }

    if (type === 'card') {
      put('cardHolder', payload.holder)
      put('cardNumber', payload.number)
      put('cardExpMonth', payload.expMonth)
      put('cardExpYear', payload.expYear)
      put('cardCode', payload.code)
      // Combined single expiry field (MM/YY) when the page has no split ones.
      if (payload.expMonth && payload.expYear && !detected.cardExpMonth && !detected.cardExpYear && detected.cardExp) {
        const mm = String(payload.expMonth).trim().padStart(2, '0')
        const rawYear = String(payload.expYear).trim()
        const yy = rawYear.length > 2 ? rawYear.slice(-2) : rawYear.padStart(2, '0')
        put('cardExp', `${mm}/${yy}`)
      }
    } else {
      put('addrName', payload.name)
      put('addrEmail', payload.email)
      put('addrPhone', payload.phone)
      put('addrOrg', payload.org)
      put('addrStreet', payload.street)
      put('addrCity', payload.city)
      put('addrState', payload.state)
      put('addrZip', payload.zip)
      put('addrCountry', payload.country)
    }

    if (filled > 0) {
      showPageToast(type === 'card'
        ? msg('ovlCardFilled', [String(filled)], `Card filled — ${filled} field${filled === 1 ? '' : 's'} from your vault`)
        : msg('ovlAddrFilled', [String(filled)], `Identity filled — ${filled} field${filled === 1 ? '' : 's'} from your vault`))
      // last-used tracking — same ledger the login fill touches.
      try { send('TOUCH_ENTRY', { domain: entry.domain, username: entry.username }).catch(() => {}) } catch { /* best-effort */ }
    } else {
      showPageToast(msg('ovlDataNoFields', undefined, 'No matching card fields found on this page'))
    }
    return filled
  }

  /** More than one card/identity saved — let the user pick one. */
  function showDataPicker(entries, type) {
    // R59-F2 — card/identity labels are vault-derived: closed shadow root,
    // light DOM only as the no-attachShadow fallback.
    // v2.42.7 — R70 (F-R70-UI-1): same order repair as showOtpChip — the
    // legacy leftover is removed BEFORE the shadow surface opens, never the
    // freshly mounted closed-shadow host after it.
    removeOverlay(DATA_PICKER_ID)
    const surf = attachShadowSupported() ? openShadowSurface(DATA_PICKER_ID) : null
    if (!surf) ensureStyle()
    const mount = surf ? surf.root : document.documentElement
    const dismiss = () => dismissSurface(DATA_PICKER_ID)
    const wrap = document.createElement('div')
    wrap.id = DATA_PICKER_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlDataPickTitle', undefined, 'Choose what to fill'))

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlDataPickTitle', undefined, 'Choose what to fill')
    wrap.appendChild(head)

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = type === 'card' ? msg('ovlDataPickCards', [String(entries.length)], `${entries.length} cards in the vault`) : msg('ovlDataPickAddrs', [String(entries.length)], `${entries.length} identities in the vault`)
    wrap.appendChild(sub)

    for (const entry of entries.slice(0, 8)) {
      // R85 (F-R84-DOC-1): picker labels are MASKED in every rendering path —
      // the no-attachShadow light-DOM fallback used to render the raw
      // username + card last-4, contradicting SECURITY_DECISIONS.md ("the
      // fallback keeps masked labels only"). mask() is applied unconditionally
      // now, so the shadow path and the fallback path carry identical
      // (non-identifying) labels.
      const label = type === 'card'
        ? [mask(entry.username), (entry.card?.number || '').slice(-4)].filter(Boolean).join(' ·· ')
        : [mask(entry.username), mask(entry.address?.email || entry.address?.city || '')].filter(Boolean).join(' ·· ')
      const row = mkBtn(
        label,
        'ck-btn',
        async () => {
          dismiss()
          fillDataEntry(entry, type)
        },
      )
      wrap.appendChild(row)
    }

    // v2.20.0 — R29-F4 (audit): the 8-row cap used to be SILENT — a vault
    // with 12 cards offered 4 entries that could never be picked from the
    // page. The overflow is now declared honestly.
    if (entries.length > 8) {
      const more = document.createElement('div')
      more.className = 'ucrypt-overlay-sub'
      more.textContent = msg('ovlDataPickMore', [String(entries.length - 8)], `…and ${entries.length - 8} more — open the UCrypt popup to pick from the full list`)
      wrap.appendChild(more)
    }

    wrap.appendChild(mkBtn(msg('ovlNotNow', undefined, 'Not now'), 'ck-btn-ghost', dismiss))
    mount.appendChild(wrap)
    // R85 (§7 prompt-persistence law): an interactive decision surface NEVER
    // auto-dismisses. The old 25 s timer hid a pending choice — the picker now
    // closes only by explicit user action (row click, Esc, "Not now",
    // documented click-outside).
  }

  // --- v2.6.0: Suggest strong password (Brave/Chrome parity) ---------------

  const SIGNUP_LABEL = /(sign\s*-?\s*up|register|create\s+(an?\s+)?account|new\s+password|choose\s+(a\s+)?password|set\s+(a\s+)?password|reset\s+password)/i

  function isSuggestCandidate(field) {
    if (!isPassword(field)) return false
    if ((field.autocomplete || '').toLowerCase() === 'new-password') return true
    const form = enclosingForm(field)
    if (form) {
      const pwFields = Array.from(form.querySelectorAll('input[type=password]')).filter(isVisible)
      if (pwFields.length >= 2) return true // password + confirm / change-password
      const submit = findSubmitButton(form, field)
      const label = submit
        ? ((submit.textContent || '') + ' ' + (submit.getAttribute('value') || '') + ' ' + (submit.getAttribute('aria-label') || ''))
        : ''
      if (SIGNUP_LABEL.test(label)) return true
    }
    return false
  }

  /** Confirm twin: the next visible password field in the same form. */
  function findConfirmField(field) {
    const scope = enclosingForm(field) || field.closest('div') || document.body
    if (!scope) return null
    const fields = Array.from(scope.querySelectorAll('input[type=password]')).filter(isVisible)
    const idx = fields.indexOf(field)
    if (idx === -1) return null
    return fields[idx + 1] || null
  }

  function visiblePasswordFields() {
    return Array.from(document.querySelectorAll('input[type=password]')).filter(isPassword)
  }

  function bestSuggestTarget() {
    const active = document.activeElement
    if (active && isPassword(active)) return active
    const candidates = visiblePasswordFields().filter(isSuggestCandidate)
    if (candidates.length > 0) return candidates[0]
    return visiblePasswordFields()[0] || null // last resort, same as Chrome
  }

  function showPageToast(message, ms = 3500) {
    ensureStyle()
    removeOverlay(TOAST_ID)
    const el = document.createElement('div')
    el.id = TOAST_ID
    el.className = 'ucrypt-toast'
    el.setAttribute('role', 'status')
    el.textContent = message
    document.documentElement.appendChild(el)
    setTimeout(() => removeOverlay(TOAST_ID), ms)
  }

  // R97 (F-R96-1): the overlay's clipboard guard — armed when a SECRET copy
  // lands here (the save-prompt password copy), overwritten with an empty
  // string on VAULT_LOCKED (the handler below). Never reads the clipboard.
  let overlayClipArmed = false

  function copyToClipboard(text) {
    return new Promise((resolve) => {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => { overlayClipArmed = true; resolve(true) }).catch(() => resolve(fallbackCopy(text)))
      } else {
        resolve(fallbackCopy(text))
      }
    }).then((ok) => { if (ok) overlayClipArmed = true; return ok })
  }

  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(ta)
      return ok
    } catch {
      return false
    }
  }

  function removeSuggestUi() {
    removeOverlay(SUGGEST_CHIP_ID)
    removeOverlay(SUGGEST_PANEL_ID)
  }

  function anchorRectFor(field, elWidth, elHeight) {
    const rect = field.getBoundingClientRect()
    let left = rect.right - elWidth
    if (left < 8) left = Math.max(8, rect.left)
    let top = rect.bottom + 6
    if (top + elHeight > window.innerHeight - 8) top = Math.max(8, rect.top - elHeight - 6)
    return { left, top }
  }

  function showSuggestChip(field) {
    ensureStyle()
    removeSuggestUi()
    const chip = document.createElement('button')
    chip.id = SUGGEST_CHIP_ID
    chip.type = 'button'
    chip.className = 'ucrypt-suggest-chip'
    chip.innerHTML = '<span class="uc-chip-dot" aria-hidden="true"></span> ' + msg('ovlChipLabel', undefined, 'UCrypt · strong password')

    const probe = chip.cloneNode(true)
    probe.style.visibility = 'hidden'
    document.documentElement.appendChild(probe)
    const size = { w: probe.offsetWidth || 190, h: probe.offsetHeight || 32 }
    probe.remove()

    const pos = anchorRectFor(field, size.w, size.h)
    chip.style.left = pos.left + 'px'
    chip.style.top = pos.top + 'px'
    chip.onclick = (e) => {
      e.preventDefault()
      openSuggestPanel(field)
    }
    document.documentElement.appendChild(chip)
    // Transient by design — never nag longer than 15s.
    setTimeout(() => removeOverlay(SUGGEST_CHIP_ID), 15000)
  }

  async function openSuggestPanel(field) {
    ensureStyle()
    removeOverlay(SUGGEST_CHIP_ID)
    removeOverlay(SUGGEST_PANEL_ID)

    const wrap = document.createElement('div')
    wrap.id = SUGGEST_PANEL_ID
    wrap.className = 'ucrypt-panel'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlSuggestAria', undefined, 'UCrypt suggested password'))

    const close = document.createElement('button')
    close.className = 'ck-close'
    close.textContent = '×'
    close.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    close.onclick = () => removeSuggestUi()

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlSuggestHead', undefined, 'Suggested strong password')

    const pwRow = document.createElement('div')
    pwRow.className = 'uc-pw-row'
    const pwEl = document.createElement('div')
    pwEl.className = 'uc-pw'
    pwEl.textContent = '…'
    pwRow.appendChild(pwEl)

    const meta = document.createElement('div')
    meta.className = 'uc-pw-meta'
    meta.textContent = msg('ovlGenerating', undefined, 'Generating locally…')

    const status = document.createElement('div')
    status.className = 'uc-pw-status'
    status.setAttribute('role', 'status')

    const actions = document.createElement('div')
    actions.className = 'ucrypt-overlay-actions'

    let currentPassword = ''

    const useBtn = mkBtn(msg('ovlBtnUse', undefined, 'Use'), 'ck-btn-primary', async (e) => {
      e.preventDefault()
      if (!currentPassword) return
      const confirm = findConfirmField(field)
      setNativeValue(field, currentPassword)
      if (confirm) setNativeValue(confirm, currentPassword)
      field.style.transition = 'box-shadow .2s'
      field.style.boxShadow = '0 0 0 2px #10b981'
      setTimeout(() => { field.style.boxShadow = '' }, 800)
      removeSuggestUi()
    })
    const reBtn = mkBtn(msg('ovlBtnRegen', undefined, 'Regenerate'), 'ck-btn-ghost', async (e) => {
      e.preventDefault()
      status.textContent = ''
      await generate()
    })
    const copyBtn = mkBtn(msg('historyCopy', undefined, 'Copy'), 'ck-btn-ghost', async (e) => {
      e.preventDefault()
      if (!currentPassword) return
      const ok = await copyToClipboard(currentPassword)
      status.textContent = ok ? msg('ovlCopied', undefined, 'Copied to clipboard ✓') : msg('ovlCopyFail', undefined, 'Copy failed — select the password and copy manually')
      if (!ok) status.style.color = '#f87171'
      setTimeout(() => { status.textContent = ''; status.style.color = '#10b981' }, 2500)
    })

    actions.appendChild(useBtn)
    actions.appendChild(reBtn)
    actions.appendChild(copyBtn)

    wrap.appendChild(close)
    wrap.appendChild(head)
    wrap.appendChild(pwRow)
    wrap.appendChild(meta)
    wrap.appendChild(actions)
    wrap.appendChild(status)

    const probe = wrap.cloneNode(true)
    probe.style.visibility = 'hidden'
    document.documentElement.appendChild(probe)
    const size = { w: probe.offsetWidth || 300, h: probe.offsetHeight || 190 }
    probe.remove()

    const pos = anchorRectFor(field, size.w, size.h)
    wrap.style.left = pos.left + 'px'
    wrap.style.top = pos.top + 'px'
    document.documentElement.appendChild(wrap)

    async function generate() {
      pwEl.textContent = '…'
      meta.textContent = msg('ovlGenerating', undefined, 'Generating locally…')
      useBtn.disabled = true
      reBtn.disabled = true
      copyBtn.disabled = true
      const r = await send('GENERATE_FOR_FILL', { length: 20 })
      useBtn.disabled = false
      reBtn.disabled = false
      copyBtn.disabled = false
      if (r && r.ok && r.password) {
        currentPassword = r.password
        pwEl.textContent = r.password
        const base = msg('ovlMeta', [String(r.entropyBits || '?'), String(r.length)], `~${r.entropyBits || '?'} bits · ${r.length} chars · generated offline`)
        meta.textContent = base + (findConfirmField(field) ? msg('ovlMetaBoth', undefined, ' · will fill both password fields') : '')
      } else {
        currentPassword = ''
        pwEl.textContent = ''
        meta.textContent = ''
        status.textContent = msg('ovlGenFailed', [(r && r.error) || msg('icUnknownError', undefined, 'unknown error')], 'Generation failed: ' + ((r && r.error) || 'unknown error'))
        status.style.color = '#f87171'
      }
    }

    await generate()
    // R85 (§7 prompt-persistence law): NO auto-dismiss (Use/Copy decision).
  }

  function mkBtn(label, cls, onclick) {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'ck-btn ' + cls
    b.textContent = label
    b.onclick = onclick
    return b
  }

  function onEscapeKey(e) {
    if (e.key !== 'Escape') return
    // v2.17.0 — R26: Escape closes EVERY UCrypt surface (the suggest UI used
    // to be the only one — the autofill, save and 2FA overlays ignored it).
    // R59-F1/F2: the vault-derived surfaces may live in closed shadows —
    // dismissSurface() covers both modes.
    removeSuggestUi()
    dismissSurface(OVERLAY_ID)
    dismissSurface(OTP_OVERLAY_ID)
    removeOverlay(SAVE_OVERLAY_ID)
    removeOverlay(LOCKED_OVERLAY_ID)
    dismissSurface(DATA_PICKER_ID)
    // v2.42.8 — R71-P: Escape cancels the profile surfaces too (an Escape on
    // the capture review counts as "Not now" — the candidate is scrubbed).
    dismissSurface(PROFILE_PICKER_ID)
    dismissSurface(USERNAME_PICKER_ID)
    scrubProfileState() // covers PROFILE_SAVE_ID + capture candidate
  }
  document.addEventListener('keydown', onEscapeKey, true)

  // v2.17.0 — R26-B5: keyboard navigation inside the auto-fill dropdown —
  // ArrowDown/ArrowUp cycle the buttons (Brave's field dropdown behaves the
  // same); Enter activates the focused button natively.
  function onOverlayArrowKeys(e) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    // R59-F1/F2: the picker may live inside a closed shadow root —
    // surfaceEl() finds the inner wrap in both modes.
    const wrap = surfaceEl(OVERLAY_ID)
    if (!wrap) return
    const btns = Array.from(wrap.querySelectorAll('button'))
    if (!btns.length) return
    e.preventDefault()
    const idx = btns.indexOf(document.activeElement)
    // v2.19.0 — R28-F7 (audit): ArrowUp from nothing used to land on the
    // second-to-last button ((-2) mod n) — it must wrap to the LAST one.
    const next = e.key === 'ArrowDown'
      ? btns[(idx + 1) % btns.length] // idx -1 (nothing focused) lands on 0
      : btns[idx <= 0 ? btns.length - 1 : idx - 1]
    next.focus()
  }
  document.addEventListener('keydown', onOverlayArrowKeys, true)

  // Focus a signup/new-password field → offer the chip (conservative: only
  // for candidates, never on plain login fields).
  let lastChipField = null
  document.addEventListener('focusin', (e) => {
    const t = e.target
    if (!t || t.tagName !== 'INPUT' || t.type !== 'password') return
    if (!isSuggestCandidate(t)) return
    if (t === lastChipField && document.getElementById(SUGGEST_CHIP_ID)) return
    lastChipField = t
    showSuggestChip(t)
  }, true)

  // --- Submit listener (save prompt) --------------------------------------

  function watchFormSubmit(form, passwordField, usernameField) {
    if (!form) return
    if (form.dataset.ucryptWatched) return
    form.dataset.ucryptWatched = '1'

    form.addEventListener('submit', (e) => {
      // Don't block the actual submit
      try {
        // v2.13.0 — R22-F1: capture the NEW password on change-password forms.
        const pw = captureSubmitPassword(form, passwordField)
        if (!pw) return
        lastSubmitAt = Date.now()
        // R125 §2 (law 0.39): stage the candidate BEFORE anything async — a
        // form that NAVIGATES tears this page down mid-round-trip and the
        // in-page offer dies with it. The worker holds the candidate and
        // re-prompts on the landing page (the SHOW_SAVE_PROMPT relay).
        stageSaveCandidate(resolveUsernameSync(usernameField), pw)
        // Ask background if we already have this exact entry
        const domain = domainFromLocation()
        // v2.11.0 — F6: two-step flows leave the username on the previous
        // page; fall back to the remembered candidate instead of saving "".
        resolveUsername(usernameField, domain).then((user) => {
          send('GET_ENTRIES', { domain }).then((r) => {
            if (!r || !r.ok || !r.entries) return
            // v2.9.0 — per-site exception suppresses the SAVE prompt entirely
            // (autofill still works — Chrome-compatible behavior).
            if (r.neverSave) return
            // v2.17.0 — R26-B2: the global "Offer to save passwords" toggle
            // gates the AUTOMATIC prompt (an explicit context-menu save still
            // works — only the proactive offer is suppressed).
            behaviorPrefs().then((b) => {
              if (!b.offerSave) return
              const exact = r.entries.some(en => en.username === user && en.password === pw)
              if (exact) return
              // v2.9.0 — same username + different password = UPDATE, say so.
              const isUpdate = r.entries.some(en => en.username === user && en.password !== pw)
              showSaveOverlay(user, pw, domain, { isUpdate })
            })
          })
        })
      } catch (err) {
        console.warn('[UCrypt] Submit listener error:', err)
      }
    }, { capture: false, passive: true })
  }

  // --- Init (v2.11.0 — re-runs for dynamically injected forms, F4) ---------
  // The old init ran ONCE, 300 ms after document_idle, and only re-ran when
  // the SPA URL poll noticed a navigation. Login forms that APPEAR later —
  // React/Vue modals, client-rendered checkout, lazy-loaded widgets — were
  // never watched: no autofill overlay, no submit watcher, no save prompt.
  // A debounced MutationObserver now re-scans whenever nodes containing
  // password inputs are added.

  let offeredForUrl = null // URL the autofill/locked UI already ran for
  let domScanTimer = null

  function offerAutofillOnce(anchorField) {
    const domain = domainFromLocation()
    if (!domain) return
    const url = window.location.href
    if (offeredForUrl === url) return
    offeredForUrl = url
    // R59-F2 — capture the epoch BEFORE asking: if a lock lands while the
    // reply is in flight, the epoch no longer matches and the reply is
    // discarded (a lock event wins the race; no stale picker renders).
    const epoch = epochNow()
    // Ask the background for entries (also handles "locked" state)
    send('GET_ENTRIES', { domain }).then(async (r) => {
      if (epoch !== epochNow()) return // lock/unlock/nav happened — stale reply
      if (!r || !r.ok) return
      if (r.locked) {
        // v2.19.0 — R28-F8 (audit 28a-9): the locked prompt was the ONLY
        // overlay without the small-frame gate — it could pop inside a tiny
        // ad iframe. Every other overlay returns early via frameIsUsable().
        if (!frameIsUsable()) return
        // Vault locked — show a truthful "click to unlock" mini-prompt
        showLockedPrompt()
        return
      }
      if (r.entries && r.entries.length > 0) {
        // v2.17.0 — R26-B2: the "Auto sign-in" toggle gates the passive
        // auto-fill offer (an explicit popup fill still works).
        const b = await behaviorPrefs()
        if (epoch !== epochNow()) return // lock landed during the prefs read
        if (!b.autoFill) return
        // R85 (§6): PROMPT mode never fills on page load — the anchored
        // dropdown (username picker) stays available on user interaction.
        if (b.autofillMode === 'prompt') return
        // R85 (§6): per-site never-fill exception — a listed site never gets
        // an automatic fill; the user fills it by explicit choice.
        if (r.neverFill) return
        showAutoFillOverlay(r.entries, anchorField, { showIdentifiers: b.showIdentifiers !== false })
      }
    })
  }

  function ensureSubmitWatching(login) {
    if (!login || !login.passwordField) return
    if (login.form) {
      watchFormSubmit(login.form, login.passwordField, login.usernameField)
      return
    }
    // Passwordless (no <form>) — watch the password field's enter key.
    // dataset guard: re-scans must not stack duplicate key listeners.
    if (login.passwordField.dataset.ucryptEnterWatched) return
    login.passwordField.dataset.ucryptEnterWatched = '1'
    login.passwordField.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return
      const pw = login.passwordField.value || ''
      if (!pw) return
      lastSubmitAt = Date.now()
      stageSaveCandidate(resolveUsernameSync(login.usernameField), pw) // R125 §2 (law 0.39)
      const d = domainFromLocation()
      // v2.11.0 — F6: remembered username across two-step flows.
      resolveUsername(login.usernameField, d).then((user) => {
        send('GET_ENTRIES', { domain: d }).then((r) => {
          if (!r || !r.ok || !r.entries) return
          if (r.neverSave) return // v2.9.0 — per-site exception
          // v2.17.0 — R26-B2: global "Offer to save passwords" gate.
          behaviorPrefs().then((b) => {
            if (!b.offerSave) return
            const exact = r.entries.some(en => en.username === user && en.password === pw)
            if (exact) return
            const isUpdate = r.entries.some(en => en.username === user && en.password !== pw)
            showSaveOverlay(user, pw, d, { isUpdate })
          })
        })
      })
    })
  }

  function scanForLoginUx() {
    const login = detectLoginForm()
    if (!login) {
      // v2.5.0 — no login form? This may still be a 2FA-only page.
      maybeOfferOtpFill()
      return
    }
    offerAutofillOnce(login.usernameField || login.passwordField || null)
    ensureSubmitWatching(login)
    // v2.5.0 — offer one-click 2FA code fill when an OTP field exists
    maybeOfferOtpFill()
  }

  function scheduleScan() {
    if (domScanTimer) clearTimeout(domScanTimer)
    domScanTimer = setTimeout(scanForLoginUx, 250)
  }

  function init() {
    scanForLoginUx()

    // v2.11.0 — F4: watch for late-arriving password fields (SPA modals,
    // client-rendered login cards). Debounced so DOM storms cost one scan.
    try {
      const mo = new MutationObserver((muts) => {
        for (const m of muts) {
          const added = m.addedNodes || []
          for (const n of added) {
            if (n.nodeType !== 1) continue
            if ((n.tagName === 'INPUT' && n.type === 'password') ||
                (n.querySelector && n.querySelector('input[type=password]'))) {
              scheduleScan()
              return
            }
          }
        }
      })
      mo.observe(document.documentElement, { childList: true, subtree: true })
    } catch { /* MutationObserver unavailable — the SPA URL poll still covers */
    }
  }

  function showLockedPrompt() {
    ensureStyle()
    removeOverlay(LOCKED_OVERLAY_ID)
    const wrap = document.createElement('div')
    wrap.id = LOCKED_OVERLAY_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')

    const close = document.createElement('button')
    close.className = 'ck-close'
    close.textContent = '×'
    close.onclick = () => removeOverlay(LOCKED_OVERLAY_ID)

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlLockedHead', undefined, 'Vault locked')

    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = msg('ovlLockedSub', undefined, 'UCrypt is locked — unlock it to auto-fill your saved logins.')

    const actions = document.createElement('div')
    actions.className = 'ucrypt-overlay-actions'
    const btn = document.createElement('button')
    btn.className = 'ck-btn ck-btn-primary'
    btn.textContent = msg('ovlLockedBtn', undefined, 'Open UCrypt settings')
    btn.onclick = async () => {
      // v2.2.0 fix: chrome.action.openPopup() is not callable from content
      // scripts — the button silently no-op'd. Opening the options page in a
      // new tab via the background worker actually works.
      const r = await send('OPEN_OPTIONS', { tab: true })
      if (!r || !r.ok) removeOverlay(LOCKED_OVERLAY_ID)
    }
    actions.appendChild(btn)

    wrap.appendChild(close)
    wrap.appendChild(head)
    wrap.appendChild(sub)
    wrap.appendChild(actions)
    document.documentElement.appendChild(wrap)
    // R85 (§7 prompt-persistence law): the unlock prompt NEVER vanishes — it
    // stays until the user acts (unlock / dismiss).
  }

  // --- R59-F2 — the lock event must win all races --------------------------
  // Broadcast by the worker on EVERY lock path. The page must end up with NO
  // vault-derived surface and NO vault-derived data in memory/DOM — only the
  // truthful locked prompt (which claims nothing about stored logins).
  function handleVaultLocked() {
    bumpVaultEpoch() // invalidates every in-flight entries/fill response
    offeredForUrl = null // the next scan may offer again (after unlock)
    lastOtpUrl = null
    closeShadowSurface(OVERLAY_ID)
    closeShadowSurface(OTP_OVERLAY_ID)
    closeShadowSurface(DATA_PICKER_ID)
    removeOverlay(OVERLAY_ID)
    removeOverlay(OTP_OVERLAY_ID)
    removeOverlay(SAVE_OVERLAY_ID)
    removeOverlay(DATA_PICKER_ID)
    // v2.42.8 — R71-P: lock clears the profile picker, the selected profile,
    // field maps, the pending capture review, its raw candidate and the
    // filled-value caches — nothing vault-derived may survive a lock.
    scrubProfileState()
    // Truthful locked prompt where a login form exists and there is room —
    // mirroring the scan-driven behavior; it contains NO entry claim.
    try {
      if (frameIsUsable() && detectLoginForm()) showLockedPrompt()
    } catch { /* prompt is best-effort */ }
  }

  function handleVaultUnlocked() {
    bumpVaultEpoch() // any reply racing the unlock is discarded; fresh fetch follows
    offeredForUrl = null
    lastOtpUrl = null
    removeOverlay(LOCKED_OVERLAY_ID) // a stale "vault locked" bubble must not survive an unlock
    try { scanForLoginUx() } catch { /* the next scan re-offers */ }
  }

  // ===========================================================================
  // v2.42.8 — R71 / R71-P: PROTECTED PROFILE FILL + EXPLICIT PROFILE CAPTURE
  // and the R71 protected USERNAME-STEP ACCOUNT PICKER (Brave parity).
  //
  // Contract (owner amendment R71-P, mirrored in
  // docs/feature-change-approvals/R71-profile-autofill.md):
  //   - No automatic fill, no automatic save, no automatic submit. The picker
  //     requires an explicit Fill; the capture prompt requires an explicit
  //     Save/Update; nothing is ever stored that the review did not show.
  //   - All vault-derived content (profile values, labels, account names)
  //     renders inside a CLOSED shadow root or not at all. Without
  //     attachShadow the picker degrades to a MASKED surface and the capture
  //     review does not open at all — raw identity/address values never land
  //     in page-readable DOM.
  //   - A profile IS one encrypted type:'address' vault entry (R71-P §2
  //     physical audit). Semantic field keys live in memory per page and are
  //     never persisted; no template records are created.
  //   - Lock wins every race: lock scrubs surfaces, the selected profile,
  //     field maps, pending promises, capture candidates and filled-value
  //     caches (handleVaultLocked below calls scrubProfileState).
  // ===========================================================================

  const PROFILE_PICKER_ID = 'ucrypt-profile-picker'
  const PROFILE_SAVE_ID = 'ucrypt-profile-save'
  const USERNAME_PICKER_ID = 'ucrypt-username-picker'

  // Device-local per-site capture suppression ("Never ask on this site").
  // Capture-only: it never disables explicit manual save nor profile fill.
  const PROFILE_NEVER_KEY = 'ucrypt:profileNeverAsk'

  async function getProfileNeverList() {
    try {
      const { [PROFILE_NEVER_KEY]: l } = await chrome.storage.local.get(PROFILE_NEVER_KEY)
      return Array.isArray(l) ? l.map(String) : []
    } catch { return [] }
  }

  async function addProfileNever(domain) {
    const d = String(domain || '').trim()
    if (!d) return false
    const list = await getProfileNeverList()
    if (!list.includes(d)) {
      const next = [...list, d].slice(-200) // bounded ledger, device-local only
      try { await chrome.storage.local.set({ [PROFILE_NEVER_KEY]: next }) } catch { return false }
    }
    return true
  }

  // Fields the USER actually typed into (trusted input events only). A WeakSet
  // leaves zero DOM footprint — the page cannot observe, enumerate or spoof it,
  // and UCrypt's own synthetic fills (isTrusted === false) never pollute it.
  const userTypedFields = new WeakSet()
  function markUserTyped(e) {
    try {
      if (!e || !e.isTrusted || !e.target) return
      const t = e.target
      if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT') {
        userTypedFields.add(t)
      }
    } catch { /* best-effort */ }
  }
  document.addEventListener('input', markUserTyped, true)

  /** Build the plain descriptor the pure classifier consumes. */
  function profileFieldDescriptor(el) {
    return {
      tagName: el.tagName,
      type: el.tagName === 'INPUT' ? (el.type || '') : '',
      autocomplete: el.getAttribute('autocomplete') || '',
      name: el.name || '',
      id: el.id || '',
      label: labelForField(el),
      ariaLabel: el.getAttribute('aria-label') || '',
      placeholder: el.getAttribute('placeholder') || '',
      visible: isVisible(el),
      disabled: !!el.disabled,
      readOnly: !!el.readOnly,
    }
  }

  /**
   * Recognized profile fields within a scope. First kind wins (a page with
   * two email boxes fills the first), EXCEPT the split-name kinds which are
   * distinct fields by definition.
   * @returns {Map<string, element>} semantic key → element
   */
  function detectProfileFields(scopeEl) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!A) return new Map()
    const scope = scopeEl || document
    const found = new Map()
    let els = []
    try { els = Array.from(scope.querySelectorAll('input, textarea, select')) } catch { return new Map() }
    for (const el of els) {
      const hit = A.classifyProfileField(profileFieldDescriptor(el))
      if (!hit) continue
      const distinct = hit.key === 'givenName' || hit.key === 'familyName' || hit.key === 'street2'
      if (found.has(hit.key) && !distinct) continue
      found.set(hit.key, el)
    }
    return found
  }

  /** Nonsecret group label keys for a semantic key set (i18n-resolved later). */
  function profileGroupKeys(keys) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    const groups = []
    for (const k of keys || []) {
      const g = A ? A.fieldGroup(k) : ''
      if (g && !groups.includes(g)) groups.push(g)
    }
    return groups
  }

  function profileGroupLabel(group) {
    switch (group) {
      case 'name': return msg('prfGroupName', undefined, 'Name')
      case 'email': return msg('prfGroupEmail', undefined, 'Email')
      case 'phone': return msg('prfGroupPhone', undefined, 'Phone')
      case 'org': return msg('prfGroupOrg', undefined, 'Organization')
      case 'address': return msg('prfGroupAddress', undefined, 'Address')
      default: return ''
    }
  }

  function profileFieldLabel(key) {
    switch (key) {
      case 'name': case 'fullName': return msg('prfGroupName', undefined, 'Name')
      case 'givenName': return msg('prfGroupGiven', undefined, 'First name')
      case 'familyName': return msg('prfGroupFamily', undefined, 'Last name')
      case 'email': return msg('prfGroupEmail', undefined, 'Email')
      case 'phone': return msg('prfGroupPhone', undefined, 'Phone')
      case 'org': return msg('prfGroupOrg', undefined, 'Organization')
      case 'street': return msg('prfGroupStreet', undefined, 'Street address')
      case 'street2': return msg('prfGroupStreet2', undefined, 'Apartment, suite, etc.')
      case 'city': return msg('prfGroupCity', undefined, 'City')
      case 'state': return msg('prfGroupState', undefined, 'State / region')
      case 'zip': return msg('prfGroupZip', undefined, 'Postal code')
      case 'country': return msg('prfGroupCountry', undefined, 'Country')
      default: return key
    }
  }

  /** Set a <select> from a stored value with safe normalization (R71-P §4.2). */
  function setProfileSelectValue(sel, rawValue) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!sel || sel.tagName !== 'SELECT' || !rawValue) return false
    const candidates = []
    const norm = A ? A.normalizeSelectValue(rawValue) : String(rawValue).trim()
    if (norm) candidates.push(norm)
    const raw = String(rawValue).trim()
    if (raw && !candidates.includes(raw)) candidates.push(raw)
    for (const want of candidates) {
      const w = want.toLowerCase()
      for (const opt of sel.options || []) {
        if ((opt.value || '').trim().toLowerCase() === w || (opt.textContent || '').trim().toLowerCase() === w) {
          setNativeValue(sel, opt.value)
          return true
        }
      }
    }
    // Bounded partial match, unchanged from the R28 card/identity fill.
    for (const want of candidates) {
      const w = want.toLowerCase()
      for (const opt of sel.options || []) {
        const text = (opt.textContent || '').trim().toLowerCase()
        if (w.length >= 4 && (text.includes(w) || w.includes(text))) {
          setNativeValue(sel, opt.value)
          return true
        }
      }
    }
    return false
  }

  /**
   * Fill the recognized profile fields of a scope from an address entry.
   * Default: non-empty fields KEEP the user's values; overwriting requires
   * opts.replace === true (an explicit picker toggle). Unknown/ambiguous
   * fields are never touched. Never submits anything.
   * @returns {{ filled: number, kept: number }}
   */
  function fillProfileFields(entry, scopeEl, opts = {}) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    const detected = detectProfileFields(scopeEl)
    const a = entry && entry.address ? entry.address : {}
    let filled = 0
    let kept = 0
    const cue = (el) => {
      el.style.transition = 'box-shadow .2s'
      el.style.boxShadow = '0 0 0 2px #10b981'
      setTimeout(() => { el.style.boxShadow = '' }, 800)
    }
    const put = (key, value, el) => {
      if (!value || !el) return false
      if (String(el.value || '').trim() && !opts.replace) { kept++; return false }
      if (el.tagName === 'SELECT') {
        if (setProfileSelectValue(el, value)) { cue(el); filled++; return true }
        return false
      }
      setNativeValue(el, String(value))
      cue(el)
      filled++
      return true
    }
    for (const [key, el] of detected) {
      if (key === 'fullName') { put(key, a.name, el); continue }
      if (key === 'givenName') { put(key, A ? A.splitFullName(a.name).given : '', el); continue }
      if (key === 'familyName') { put(key, A ? A.splitFullName(a.name).family : '', el); continue }
      if (key === 'email') { put(key, a.email, el); continue }
      if (key === 'phone') { put(key, a.phone, el); continue }
      if (key === 'org') { put(key, a.org, el); continue }
      if (key === 'city') { put(key, a.city, el); continue }
      if (key === 'state') { put(key, a.state, el); continue }
      if (key === 'zip') { put(key, a.zip, el); continue }
      if (key === 'country') { put(key, a.country, el); continue }
      if (key === 'street') {
        // With a dedicated line-2 field: split the folded street. Without one:
        // the whole stored street (folded to single spaces) goes in line 1.
        const hasLine2 = detected.has('street2')
        put(key, hasLine2 ? (A ? A.streetLine1(a.street) : a.street) : String(a.street || '').replace(/\n/g, ' '), el)
        continue
      }
      if (key === 'street2') { put(key, A ? A.streetLine2(a.street) : '', el); continue }
    }
    if (filled > 0) {
      try { send('TOUCH_ENTRY', { domain: entry.domain, username: entry.username }).catch(() => {}) } catch { /* best-effort */ }
    }
    return { filled, kept }
  }

  // --- Profile capture state (scrubbed on resolve/lock/navigation) ----------

  let profileCapture = null // { pairs, domain, form, source } — raw values, page memory only

  function scrubProfileState() {
    profileCapture = null
    try { closeShadowSurface(PROFILE_PICKER_ID) } catch { /* already gone */ }
    try { closeShadowSurface(PROFILE_SAVE_ID) } catch { /* already gone */ }
    try { closeShadowSurface(USERNAME_PICKER_ID) } catch { /* already gone */ }
    removeOverlay(PROFILE_PICKER_ID)
    removeOverlay(PROFILE_SAVE_ID)
    removeOverlay(USERNAME_PICKER_ID)
  }

  /**
   * Collect typed pairs from a form's recognized fields at submit time.
   * Only user-typed (trusted input) values from allowlisted semantic fields.
   */
  function collectTypedProfilePairs(formEl) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!A) return []
    const scope = formEl || document
    const found = detectProfileFields(scope)
    const pairs = []
    for (const [key, el] of found) {
      if (!userTypedFields.has(el)) continue
      const value = String(el.value || '').trim()
      if (!value) continue
      pairs.push({ key, value: value.slice(0, 200), include: true })
    }
    return pairs
  }

  // One document-level CAPTURE-phase submit listener covers every form —
  // including ones injected later by SPA renders — and never blocks or
  // cancels the actual submission (the listener only schedules the review).
  document.addEventListener('submit', (e) => {
    try {
      const f = e.target
      if (f && f.tagName === 'FORM') maybeCaptureProfile(f, 'submit')
    } catch { /* best-effort */ }
  }, true)
  // A navigation ends the review window: no prompt may survive it.
  window.addEventListener('pagehide', () => {
    if (profileCapture) scrubProfileState()
  }, { capture: true, once: false })

  async function maybeCaptureProfile(form, source) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!A || profileCapture) return // one review at a time; never stack
    const domain = domainFromLocation()
    if (!domain) return
    if (!attachShadowSupported()) return // no raw values in page DOM — hard rule
    if (!frameIsUsable()) return
    // Device-local per-site suppression (capture offer only).
    const neverList = await getProfileNeverList()
    if (neverList.includes(domain)) return
    // Behavior toggle gates the AUTOMATIC offer only (manual capture paths
    // pass source !== 'submit').
    if (source === 'submit') {
      const b = await behaviorPrefs()
      if (!b.profileCapture) return
    }
    // Trust boundary: a form is classified as a whole. Any visible sensitive
    // category inside it makes the whole form capture-ineligible (§6).
    let descriptors = []
    try {
      descriptors = Array.from(form.querySelectorAll('input, textarea, select')).map(profileFieldDescriptor)
    } catch { return }
    const verdict = A.classifyProfileForm(descriptors)
    if (verdict.rejectedSensitive > 0) return
    if (!verdict.captureEligible) return
    const pairs = collectTypedProfilePairs(form)
    if (pairs.length < 2) return // a lone typed email is not a profile event
    profileCapture = { pairs, domain, form, source }
    // The review supersedes the focus-offered fill/account pickers — two
    // anchored vault surfaces fighting for the same fields would bury the
    // review (and the review is the moment that matters now).
    dismissSurface(PROFILE_PICKER_ID)
    dismissSurface(USERNAME_PICKER_ID)
    showProfileSaveOverlay()
  }

  // --- Profile review dialog (capture — R71-P §5) ----------------------------
  //
  // Closed shadow only. Persists until the user resolves it (no dismiss timer
  // timer) unless lock or navigation cancels it safely. The candidate and the
  // raw typed values die with the surface (scrub on every exit path).

  function showProfileSaveOverlay() {
    const cap = profileCapture
    if (!cap) return
    if (!attachShadowSupported()) { scrubProfileState(); return }
    removeOverlay(PROFILE_SAVE_ID)
    const surf = openShadowSurface(PROFILE_SAVE_ID)
    if (!surf) { scrubProfileState(); return } // closed shadow mandatory here
    const root = surf.root
    const epoch = epochNow()

    const wrap = document.createElement('div')
    wrap.id = PROFILE_SAVE_ID
    wrap.className = 'ucrypt-overlay ucrypt-profile-save'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('prfSaveAria', undefined, 'Save profile to UCrypt'))

    const closeBtn = document.createElement('button')
    closeBtn.className = 'ck-close'
    closeBtn.textContent = '×'
    closeBtn.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    closeBtn.onclick = () => scrubProfileState()

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfSaveHead', undefined, 'Save these details as a UCrypt profile?')

    const site = document.createElement('div')
    site.className = 'ucrypt-overlay-sub'
    site.textContent = msg('prfSiteLabel', [cap.domain], 'From ' + cap.domain)

    // Profile name (editable — the vault entry title).
    const nameRow = document.createElement('div')
    nameRow.className = 'uc-prf-name-row'
    const nameLabel = document.createElement('label')
    nameLabel.className = 'uc-prf-name-label'
    nameLabel.textContent = msg('prfNameLabel', undefined, 'Profile name')
    const nameInput = document.createElement('input')
    nameInput.type = 'text'
    nameInput.className = 'uc-prf-name-input'
    nameInput.maxLength = 100
    nameInput.autocomplete = 'off'
    nameInput.spellcheck = false
    const defaultName = (() => {
      const namePair = cap.pairs.find(p => p.key === 'fullName' || p.key === 'givenName' || p.key === 'name')
      return namePair ? namePair.value : cap.domain
    })()
    nameInput.value = defaultName.slice(0, 100)
    nameLabel.setAttribute('for', 'uc-prf-name')
    nameInput.id = 'uc-prf-name'
    nameRow.appendChild(nameLabel)
    nameRow.appendChild(nameInput)

    // Per-field include/exclude (only fields the user typed are listed).
    const fieldsBox = document.createElement('div')
    fieldsBox.className = 'uc-prf-fields'
    const boxes = cap.pairs.map((p) => {
      const row = document.createElement('label')
      row.className = 'uc-prf-field-row'
      const cb = document.createElement('input')
      cb.type = 'checkbox'
      cb.checked = true
      const label = document.createElement('span')
      label.className = 'uc-prf-field-name'
      label.textContent = profileFieldLabel(p.key)
      const val = document.createElement('span')
      val.className = 'uc-prf-field-value'
      val.textContent = p.value
      row.appendChild(cb)
      row.appendChild(label)
      row.appendChild(val)
      fieldsBox.appendChild(row)
      return { p, cb }
    })

    const status = document.createElement('div')
    status.className = 'ucrypt-overlay-sub ck-save-error'
    status.setAttribute('role', 'alert')
    status.style.display = 'none'

    const actions = document.createElement('div')
    actions.className = 'ucrypt-overlay-actions'

    const saveBtn = document.createElement('button')
    saveBtn.className = 'ck-btn ck-btn-primary'
    saveBtn.textContent = msg('prfBtnSave', undefined, 'Save profile')
    const notNowBtn = document.createElement('button')
    notNowBtn.className = 'ck-btn ck-btn-ghost'
    notNowBtn.textContent = msg('ovlNotNow', undefined, 'Not now')
    notNowBtn.onclick = () => scrubProfileState()
    const neverBtn = document.createElement('button')
    neverBtn.className = 'ck-btn ck-btn-ghost'
    neverBtn.textContent = msg('prfBtnNever', undefined, 'Never ask on this site')
    neverBtn.onclick = async (e) => {
      e.preventDefault()
      const ok = await addProfileNever(cap.domain)
      if (ok) {
        const note = document.createElement('div')
        note.className = 'ucrypt-overlay-sub'
        note.textContent = msg('prfNeverDone', [cap.domain], 'OK — UCrypt will no longer offer to save profiles on ' + cap.domain + '.')
        note.style.color = '#10b981'
        actions.replaceWith(note)
        setTimeout(() => scrubProfileState(), 1600)
      } else {
        status.textContent = msg('prfNeverErr', undefined, 'Could not add the exception')
        status.style.color = '#f87171'
        status.style.display = 'block'
      }
    }
    actions.appendChild(saveBtn)
    actions.appendChild(notNowBtn)
    actions.appendChild(neverBtn)

    const dupNote = document.createElement('div')
    dupNote.className = 'ucrypt-overlay-sub'
    dupNote.style.display = 'none'

    const doSave = async (e) => {
      e.preventDefault()
      saveBtn.disabled = true
      saveBtn.textContent = msg('prfBtnSaving', undefined, 'Saving…')
      status.style.display = 'none'
      const included = boxes.filter(b => b.cb.checked).map(b => ({ key: b.p.key, value: b.p.value }))
      if (!included.length) {
        saveBtn.disabled = false
        saveBtn.textContent = msg('prfBtnSave', undefined, 'Save profile')
        return
      }
      const A = globalThis.UCRYPT_PROFILE_FORM
      const address = A ? A.buildAddressFromPairs(included) : {}
      const title = String(nameInput.value || '').trim() || cap.domain
      // Fresh decision at save time: the vault may have changed while the
      // dialog was open (duplicate / update target).
      const r = await send('SAVE_PROFILE_ENTRY', {
        title,
        address,
        capturedFrom: cap.domain,
        source: cap.source || 'manual',
      })
      if (r && r.ok && r.duplicate) {
        head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfDupHead', undefined, 'Already saved')
        dupNote.textContent = msg('prfDupSub', undefined, 'An identical profile is already in your vault — nothing was changed.')
        dupNote.style.display = 'block'
        actions.replaceWith(dupNote)
        return // no mutation, no push — truthful no-op
      }
      if (r && r.ok) {
        saveBtn.textContent = r.mode === 'update' ? msg('prfBtnUpdated', undefined, 'Updated ✓') : msg('prfBtnSaved', undefined, 'Saved ✓')
        setTimeout(() => scrubProfileState(), 900)
      } else {
        saveBtn.disabled = false
        saveBtn.textContent = msg('prfBtnSave', undefined, 'Save profile')
        status.textContent = msg('prfSaveErr', [(r && r.error) || msg('icUnknownError', undefined, 'unknown error')], 'Could not save: ' + ((r && r.error) || 'unknown error'))
        status.style.color = '#f87171'
        status.style.display = 'block'
      }
    }
    saveBtn.onclick = doSave

    wrap.appendChild(closeBtn)
    wrap.appendChild(head)
    wrap.appendChild(site)
    wrap.appendChild(nameRow)
    wrap.appendChild(fieldsBox)
    wrap.appendChild(actions)
    wrap.appendChild(status)
    root.appendChild(wrap)

    // §5.1 — the dialog must SAY what will happen: an existing profile with
    // the same title labels the action "Update profile" (head + button);
    // an exact duplicate shows the truthful "Already saved" no-op state
    // immediately. Fresh decision, best-effort — the save path re-decides.
    ;(async () => {
      const A2 = globalThis.UCRYPT_PROFILE_FORM
      if (!A2) return
      const r = await send('GET_OTHER_ENTRIES', {})
      if (epoch !== epochNow()) return // lock/unlock/nav — stale
      if (!r || !r.ok) return
      const existing = (r.entries || []).filter(e => e.type === 'address')
      const included0 = boxes.filter(b => b.cb.checked).map(b => ({ key: b.p.key, value: b.p.value }))
      const addr0 = A2.buildAddressFromPairs(included0)
      const decision = A2.decideCapture(existing, addr0, String(nameInput.value || '').trim())
      if (decision.mode === 'duplicate' && status.style.display !== 'block') {
        head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfDupHead', undefined, 'Already saved')
        dupNote.textContent = msg('prfDupSub', undefined, 'An identical profile is already in your vault — nothing was changed.')
        dupNote.style.display = 'block'
        actions.replaceWith(dupNote)
        return
      }
      if (decision.mode === 'update') {
        head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfUpdateHead', undefined, 'Update your UCrypt profile?')
        saveBtn.textContent = msg('prfBtnUpdate', undefined, 'Update profile')
      }
    })().catch(() => { /* the save path re-decides */ })

    // If a lock or navigation lands while the review is open, the epoch no
    // longer matters — handleVaultLocked / scrubProfileState destroy the
    // surface directly. Never dismissed by a timer: the prompt persists until the
    // user resolves it (R71-P §8), lock/navigation being the safe cancels.
  }

  // --- Profile fill picker (R71-P §4) -----------------------------------------

  function profilePickerSurfaceOpen() {
    return !!(surfaceEl(PROFILE_PICKER_ID) || surfaceEl(PROFILE_SAVE_ID) ||
      surfaceEl(USERNAME_PICKER_ID) || surfaceEl(OVERLAY_ID) || surfaceEl(OTP_OVERLAY_ID) ||
      document.getElementById(SUGGEST_CHIP_ID) || document.getElementById(SUGGEST_PANEL_ID))
  }

  let lastProfileOfferField = null

  async function maybeOfferProfileFill(field) {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!A || !field || profilePickerSurfaceOpen()) return
    if (field === lastProfileOfferField && surfaceEl(PROFILE_PICKER_ID)) return
    if (!frameIsUsable()) return
    const formEl = enclosingForm(field)
    const scope = formEl || document
    // Eligible FORM gate (§4.1): the focused field must sit in a form with
    // ≥2 recognized fields at/above the confidence threshold.
    let descriptors = []
    try { descriptors = Array.from(scope.querySelectorAll('input, textarea, select')).map(profileFieldDescriptor) } catch { return }
    const verdict = A.classifyProfileForm(descriptors)
    if (!verdict.fillEligible || !verdict.keys.length) return
    const own = A.classifyProfileField(profileFieldDescriptor(field))
    if (!own || own.confidence < A.FILL_MIN_CONFIDENCE) return
    if (verdict.rejectedSensitive > 0 && verdict.keys.length < 2) return
    const b = await behaviorPrefs()
    if (!b.profileFill) return
    const epoch = epochNow()
    const r = await send('GET_OTHER_ENTRIES', {})
    if (epoch !== epochNow()) return // lock/unlock/nav — stale reply
    if (!r || !r.ok || !r.entries) return
    const profiles = r.entries.filter(e => e.type === 'address')
    if (!profiles.length) return
    lastProfileOfferField = field
    showProfilePicker(profiles, field, scope)
  }

  function showProfilePicker(profiles, anchorField, scopeEl) {
    removeOverlay(PROFILE_PICKER_ID)
    const A = globalThis.UCRYPT_PROFILE_FORM
    const surf = attachShadowSupported() ? openShadowSurface(PROFILE_PICKER_ID) : null
    if (!surf) { showProfilePickerFallback(profiles, anchorField, scopeEl); return }
    const root = surf.root
    const epoch = epochNow()
    let selected = profiles.length === 1 ? profiles[0] : null
    let replace = false

    const wrap = document.createElement('div')
    wrap.id = PROFILE_PICKER_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('prfPickAria', undefined, 'UCrypt profile fill'))

    const closeBtn = document.createElement('button')
    closeBtn.className = 'ck-close'
    closeBtn.textContent = '×'
    closeBtn.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    closeBtn.onclick = () => dismissSurface(PROFILE_PICKER_ID)

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfPickHead', undefined, 'Fill profile')

    // What will be filled — group names only, never values (§4.1).
    const scopeKeys = []
    for (const [key] of detectProfileFields(scopeEl)) scopeKeys.push(key)
    const groups = profileGroupKeys(scopeKeys.length ? scopeKeys : ['name', 'email', 'street'])
    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = profiles.length === 1
      ? msg('prfPickWhat', [groups.map(profileGroupLabel).join(', ') || '—'], 'Will fill: ' + (groups.map(profileGroupLabel).join(', ') || '—'))
      : msg('prfPickMany', [String(profiles.length)], profiles.length + ' saved profiles')

    wrap.appendChild(closeBtn)
    wrap.appendChild(head)
    wrap.appendChild(sub)

    let searchInput = null
    if (profiles.length > 5) {
      searchInput = document.createElement('input')
      searchInput.type = 'text'
      searchInput.className = 'ck-picker-search'
      searchInput.placeholder = msg('prfPickSearch', undefined, 'Filter profiles…')
      searchInput.setAttribute('aria-label', msg('prfPickSearchAria', undefined, 'Filter profiles'))
      searchInput.autocomplete = 'off'
      searchInput.spellcheck = false
      wrap.appendChild(searchInput)
    }

    const countLine = document.createElement('div')
    countLine.className = 'ck-picker-count'
    countLine.setAttribute('role', 'status')
    wrap.appendChild(countLine)

    const list = document.createElement('div')
    list.className = 'ck-entries'
    list.setAttribute('role', 'listbox')
    list.setAttribute('aria-label', msg('prfPickListAria', undefined, 'Saved profiles'))
    wrap.appendChild(list)

    const fillBtn = document.createElement('button')
    fillBtn.className = 'ck-btn ck-btn-primary'
    fillBtn.textContent = msg('ovlBtnFill', undefined, 'Fill')
    fillBtn.disabled = !selected

    const replaceRow = document.createElement('label')
    replaceRow.className = 'uc-prf-replace-row'
    const replaceCb = document.createElement('input')
    replaceCb.type = 'checkbox'
    replaceCb.checked = false
    const replaceLabel = document.createElement('span')
    replaceLabel.textContent = msg('prfPickReplace', undefined, 'Replace existing values')
    replaceRow.appendChild(replaceCb)
    replaceRow.appendChild(replaceLabel)
    replaceRow.title = msg('prfPickReplaceTitle', undefined, 'Off (default): fields you already filled are kept. On: UCrypt overwrites non-empty fields with the selected profile.')
    replaceCb.addEventListener('change', () => { replace = replaceCb.checked })

    const status = document.createElement('div')
    status.className = 'ucrypt-overlay-sub'
    status.setAttribute('role', 'status')

    const rows = profiles.map((entry, idx) => {
      const d = A ? A.profileDescriptor(entry.address) : { descriptor: '', groups: [] }
      const row = document.createElement('div')
      row.className = 'ck-entry-row uc-prf-row'
      row.setAttribute('role', 'option')
      row.setAttribute('aria-selected', selected === entry ? 'true' : 'false')
      row.tabIndex = -1
      const id = document.createElement('span')
      id.className = 'ck-entry-id'
      id.textContent = String(entry.username || '').trim() || msg('prfPickUnnamed', undefined, '(unnamed profile)')
      const meta = document.createElement('span')
      meta.className = 'ck-entry-meta'
      meta.textContent = [d.descriptor, d.groups.map(profileGroupLabel).join(', ')].filter(Boolean).join(' · ')
      row.appendChild(id)
      row.appendChild(meta)
      const select = () => {
        selected = entry
        for (const r of list.children) r.setAttribute('aria-selected', 'false')
        row.setAttribute('aria-selected', 'true')
        fillBtn.disabled = false
        fillBtn.focus()
      }
      row.addEventListener('click', select)
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); select() } })
      list.appendChild(row)
      return { row, entry, idx }
    })

    const applyFilter = (term) => {
      const t = String(term || '').trim().toLowerCase()
      let shown = 0
      for (const { row, entry } of rows) {
        const d = A ? A.profileDescriptor(entry.address) : { descriptor: '' }
        const hay = `${entry.username || ''} ${d.descriptor}`.toLowerCase()
        const hit = !t || hay.includes(t)
        row.style.display = hit ? '' : 'none'
        if (hit) shown++
      }
      countLine.textContent = t
        ? msg('ovlPickerCountFiltered', [String(shown), String(profiles.length)], shown + ' of ' + profiles.length + ' matching profiles')
        : msg('prfPickCount', [String(profiles.length)], profiles.length + ' saved profiles')
    }
    applyFilter('')
    if (searchInput) searchInput.addEventListener('input', () => applyFilter(searchInput.value))

    const doFill = () => {
      if (!selected) return
      // The scope may have re-rendered since the offer — re-detect at fill time.
      const res = fillProfileFields(selected, scopeEl || document, { replace })
      dismissSurface(PROFILE_PICKER_ID)
      if (res.filled > 0) {
        // 4 substitution slots ($1 count, $2 kept, $3/$4 plural suffixes) —
        // chrome.i18n drops the WHOLE message on a count mismatch.
        const fs = res.filled === 1 ? '' : 's'
        const ks = res.kept === 1 ? '' : 's'
        showPageToast(msg('prfPickFilled', [String(res.filled), String(res.kept), fs, ks],
          'Profile filled — ' + res.filled + ' field' + fs + (res.kept ? ' · kept ' + res.kept + ' existing value' + ks : '')))
      } else {
        showPageToast(msg('prfPickNothing', undefined, 'Nothing filled — the matching fields already have values (tick Replace to overwrite)'))
      }
    }
    fillBtn.onclick = (e) => { e.preventDefault(); doFill() }

    const notNow = document.createElement('button')
    notNow.className = 'ck-btn ck-btn-ghost'
    notNow.textContent = msg('ovlNotNow', undefined, 'Not now')
    notNow.onclick = () => dismissSurface(PROFILE_PICKER_ID)

    const actions = document.createElement('div')
    actions.className = 'ucrypt-overlay-actions'
    actions.appendChild(fillBtn)
    actions.appendChild(notNow)

    wrap.appendChild(replaceRow)
    wrap.appendChild(actions)
    root.appendChild(wrap)

    // Anchor placement — same corner math as the login picker.
    if (anchorField && anchorField.isConnected) {
      try {
        const place = () => {
          if (!wrap.isConnected) { cleanupAnchorTracking(); return }
          if (!anchorField.isConnected) { dismissSurface(PROFILE_PICKER_ID); cleanupAnchorTracking(); return }
          const w = wrap.offsetWidth || 300
          const h = wrap.offsetHeight || 200
          const pos = anchorRectFor(anchorField, w, h)
          wrap.style.right = 'auto'
          wrap.style.bottom = 'auto'
          wrap.style.left = Math.round(pos.left) + 'px'
          wrap.style.top = Math.round(pos.top) + 'px'
        }
        window.addEventListener('scroll', place, { passive: true, capture: true })
        window.addEventListener('resize', place, { passive: true })
        const cleanupAnchorTracking = () => {
          window.removeEventListener('scroll', place, { capture: true })
          window.removeEventListener('resize', place)
        }
        place()
      } catch { /* corner fallback */ }
    }
    // R85 (§7 prompt-persistence law): NO auto-dismiss (interactive surface).
  }

  /** No attachShadow → MASKED rows only: never raw identity values in page DOM. */
  function showProfilePickerFallback(profiles, anchorField, scopeEl) {
    ensureStyle()
    removeOverlay(PROFILE_PICKER_ID)
    if (!frameIsUsable()) return
    const wrap = document.createElement('div')
    wrap.id = PROFILE_PICKER_ID
    wrap.className = 'ucrypt-overlay'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('prfPickAria', undefined, 'UCrypt profile fill'))
    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('prfPickHead', undefined, 'Fill profile')
    const sub = document.createElement('div')
    sub.className = 'ucrypt-overlay-sub'
    sub.textContent = msg('prfPickMaskedNote', undefined, 'Protected display unavailable — values are masked here. Fill still works.')
    wrap.appendChild(head)
    wrap.appendChild(sub)
    profiles.forEach((entry, idx) => {
      const A = globalThis.UCRYPT_PROFILE_FORM
      const d = A ? A.profileDescriptor(entry.address) : { groups: [] }
      const row = document.createElement('div')
      row.className = 'ck-entry-row'
      const code = document.createElement('code')
      code.textContent = mask(String(entry.username || '') || ('Profile ' + (idx + 1))) + ' · ' + d.groups.map(profileGroupLabel).join(', ')
      const btn = document.createElement('button')
      btn.className = 'ck-btn ck-btn-primary'
      btn.textContent = msg('ovlBtnFill', undefined, 'Fill')
      btn.onclick = (e) => {
        e.preventDefault()
        fillProfileFields(entry, scopeEl || document, { replace: false })
        removeOverlay(PROFILE_PICKER_ID)
      }
      row.appendChild(code)
      row.appendChild(btn)
      wrap.appendChild(row)
    })
    const notNow = document.createElement('button')
    notNow.className = 'ck-btn ck-btn-ghost'
    notNow.textContent = msg('ovlNotNow', undefined, 'Not now')
    notNow.onclick = () => removeOverlay(PROFILE_PICKER_ID)
    wrap.appendChild(notNow)
    if (anchorField && anchorField.isConnected) {
      const pos = anchorRectFor(anchorField, 300, 200)
      wrap.style.left = Math.round(pos.left) + 'px'
      wrap.style.top = Math.round(pos.top) + 'px'
    }
    document.documentElement.appendChild(wrap)
    // R85 (§7 prompt-persistence law): NO auto-dismiss (interactive surface).
  }

  // --- R71: username-step account picker (Brave parity) -----------------------
  //
  // Two-step logins (accounts.google.com & friends) type the username on a
  // page with NO password field — the login picker never fired there. On
  // focus of a username-like field, offer the saved accounts for this domain
  // in a closed-shadow dropdown: avatar initial + username + masked dots.
  // A click fills the username (native setters) and records the candidate so
  // the page-2 save prompt keeps working (existing two-step memory).

  let lastUsernamePickerField = null

  async function maybeOfferUsernamePicker(field) {
    if (!field || profilePickerSurfaceOpen()) return
    if (!isUsername(field)) return
    if (!attachShadowSupported() || !frameIsUsable()) return
    // Only on the USERNAME STEP: any visible password field → the login
    // picker owns the page (R59 machinery stays authoritative).
    if (visiblePasswordFields().length > 0) return
    if (field === lastUsernamePickerField && surfaceEl(USERNAME_PICKER_ID)) return
    const domain = domainFromLocation()
    if (!domain) return
    const b = await behaviorPrefs()
    if (!b.autoFill) return
    const epoch = epochNow()
    const r = await send('GET_ENTRIES', { domain })
    if (epoch !== epochNow()) return
    if (!r || !r.ok || r.locked) return
    // R85 (§6): per-site never-fill — no suggestions on listed sites.
    if (r.neverFill) return
    const entries = r.entries || []
    if (!entries.length) return
    lastUsernamePickerField = field
    // R77-A — await the open so the identifier-visibility decision reads LIVE
    // storage (the same real-time truth the login picker uses); the old dead
    // module-level cache never refreshed, so the toggle was cosmetic here.
    await showUsernamePicker(entries, field, domain)
  }

  async function showUsernamePicker(entries, anchorField, pageDomain) {
    removeOverlay(USERNAME_PICKER_ID)
    const surf = openShadowSurface(USERNAME_PICKER_ID)
    if (!surf) return
    const root = surf.root
    const epoch = epochNow()
    // R77-A (owner screenshot file:199, order §1): showIdentifiers must be a
    // REAL end-to-end control — read the stored device-local pref at open
    // time (never a cached snapshot), defaulting ON.
    let showIdentifiers = true
    try {
      const b = (await chrome.storage.local.get('ucrypt:behavior'))['ucrypt:behavior'] || {}
      showIdentifiers = b.showIdentifiers !== false
    } catch { showIdentifiers = true }

    const wrap = document.createElement('div')
    wrap.id = USERNAME_PICKER_ID
    wrap.className = 'ucrypt-overlay ucrypt-user-picker'
    wrap.setAttribute('role', 'dialog')
    wrap.setAttribute('aria-label', msg('ovlAutofillAria', undefined, 'UCrypt auto-fill'))

    const closeBtn = document.createElement('button')
    closeBtn.className = 'ck-close'
    closeBtn.textContent = '×'
    closeBtn.setAttribute('aria-label', msg('ovlDismissAria', undefined, 'Dismiss'))
    closeBtn.onclick = () => dismissSurface(USERNAME_PICKER_ID)

    const head = document.createElement('div')
    head.className = 'ucrypt-overlay-head'
    head.innerHTML = '<span class="ck-badge">UCrypt</span> ' + msg('ovlUserHead', undefined, 'Saved accounts')

    wrap.appendChild(closeBtn)
    wrap.appendChild(head)

    const list = document.createElement('div')
    list.className = 'ck-entries'
    list.setAttribute('role', 'listbox')
    list.setAttribute('aria-label', msg('ovlPickerListAria', undefined, 'Matching accounts'))
    wrap.appendChild(list)

    const rows = entries.map((entry, idx) => {
      const row = document.createElement('div')
      row.className = 'ck-entry-row uc-user-row'
      row.setAttribute('role', 'option')
      row.setAttribute('aria-selected', 'false')
      row.tabIndex = -1
      const avatar = document.createElement('span')
      avatar.className = 'uc-user-avatar'
      avatar.setAttribute('aria-hidden', 'true')
      avatar.textContent = (showIdentifiers ? (String(entry.username || '').trim()[0] || '•') : String(idx + 1))
      const textCol = document.createElement('span')
      textCol.className = 'uc-user-text'
      const id = document.createElement('span')
      id.className = 'ck-entry-id'
      id.textContent = showIdentifiers ? pickerPrimaryLabel(entry, idx, true) : msg('ovlPickerOrdinal', [String(idx + 1)], 'Account ' + (idx + 1))
      const dots = document.createElement('span')
      dots.className = 'ck-entry-meta uc-user-dots'
      dots.textContent = '••••••••'
      textCol.appendChild(id)
      textCol.appendChild(dots)
      const btn = document.createElement('button')
      btn.className = 'ck-btn ck-btn-primary'
      btn.textContent = msg('ovlBtnFill', undefined, 'Fill')
      const fill = (e) => {
        if (e) e.preventDefault()
        setNativeValue(anchorField, String(entry.username || ''))
        recordUsernameCandidate(anchorField)
        anchorField.focus()
        dismissSurface(USERNAME_PICKER_ID)
      }
      btn.onclick = fill
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') fill(e) })
      row.appendChild(avatar)
      row.appendChild(textCol)
      row.appendChild(btn)
      list.appendChild(row)
      return { row, entry, idx }
    })

    // Multi-account search — same closed-shadow filter as the login picker.
    let searchInput = null
    if (entries.length > 5) {
      searchInput = document.createElement('input')
      searchInput.type = 'text'
      searchInput.className = 'ck-picker-search'
      searchInput.placeholder = msg('ovlPickerSearch', undefined, 'Filter matching accounts…')
      searchInput.setAttribute('aria-label', msg('ovlPickerSearchAria', undefined, 'Filter matching accounts'))
      searchInput.autocomplete = 'off'
      searchInput.spellcheck = false
      wrap.appendChild(searchInput)
      const countLine = document.createElement('div')
      countLine.className = 'ck-picker-count'
      countLine.setAttribute('role', 'status')
      wrap.appendChild(countLine)
      const applyFilter = (term) => {
        const t = String(term || '').trim().toLowerCase()
        let shown = 0
        for (const { row, entry, idx } of rows) {
          const hay = showIdentifiers
            ? `${entry.username || ''} ${entry.domain || ''}`.toLowerCase()
            : `account ${idx + 1}`.toLowerCase()
          const hit = !t || hay.includes(t)
          row.style.display = hit ? '' : 'none'
          if (hit) shown++
        }
        countLine.textContent = msg('ovlPickerCountFiltered', [String(shown), String(entries.length)], shown + ' of ' + entries.length + ' matching accounts')
      }
      applyFilter('')
      searchInput.addEventListener('input', () => applyFilter(searchInput.value))
    }

    // "All logins…" escape hatch (same device-local handoff as the login picker).
    const allRow = document.createElement('button')
    allRow.className = 'ck-btn ck-btn-ghost'
    allRow.type = 'button'
    allRow.textContent = msg('ovlAllLogins', undefined, 'All logins…')
    allRow.onclick = async (e) => {
      e.preventDefault()
      try { if (pageDomain) await chrome.storage.local.set({ 'ucrypt:vaultOriginFilter': pageDomain }) } catch { /* best-effort */ }
      await send('OPEN_OPTIONS', { tab: true })
      dismissSurface(USERNAME_PICKER_ID)
    }
    wrap.appendChild(allRow)

    root.appendChild(wrap)

    if (anchorField && anchorField.isConnected) {
      try {
        const place = () => {
          if (!wrap.isConnected) return
          if (!anchorField.isConnected) { dismissSurface(USERNAME_PICKER_ID); return }
          const w = wrap.offsetWidth || 300
          const h = wrap.offsetHeight || 160
          const pos = anchorRectFor(anchorField, w, h)
          wrap.style.right = 'auto'
          wrap.style.bottom = 'auto'
          wrap.style.left = Math.round(pos.left) + 'px'
          wrap.style.top = Math.round(pos.top) + 'px'
        }
        window.addEventListener('scroll', place, { passive: true, capture: true })
        window.addEventListener('resize', place, { passive: true })
        place()
      } catch { /* corner fallback */ }
    }
    // R85 (§7 prompt-persistence law): NO auto-dismiss (interactive surface).
  }

  // behaviorPrefs — R77-A: the username picker now reads 'ucrypt:behavior'
  // LIVE at open time (see showUsernamePicker); the login/profile pickers
  // already read live. No module-level cache exists — a stale snapshot here
  // would make a behavior toggle cosmetic, which the behavior contract
  // forbids.

  // Focus router: one capture-phase listener dispatches the three focus
  // behaviors (password chip → login machinery; profile field → profile
  // picker; username step → account picker). Never cancels default focus.
  document.addEventListener('focusin', (e) => {
    const t = e.target
    if (!t || !t.tagName) return
    try {
      // v2.42.8 — R71: a REVEALED (not injected) step-2 password field never
      // crossed the MutationObserver's added-node filter — two-step flows
      // that toggle a hidden form got no watcher and no picker. Focusing a
      // password field is the earliest possible user signal: re-scan.
      if (t.tagName === 'INPUT' && t.type === 'password') scheduleScan()
      if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA') {
        const A = globalThis.UCRYPT_PROFILE_FORM
        if (A) {
          const hit = A.classifyProfileField(profileFieldDescriptor(t))
          if (hit && hit.confidence >= A.FILL_MIN_CONFIDENCE) {
            maybeOfferProfileFill(t)
            return
          }
        }
      }
      if (t.tagName === 'INPUT') maybeOfferUsernamePicker(t)
    } catch { /* focus routing is best-effort */ }
  }, true)

  // Manual context-menu paths (always available — never gated by toggles).
  async function openProfilePickerManual() {
    const epoch = epochNow()
    const r = await send('GET_OTHER_ENTRIES', {})
    if (epoch !== epochNow()) return
    if (r && r.locked) { if (frameIsUsable()) showLockedPrompt(); return }
    if (!r || !r.ok) return
    const profiles = (r.entries || []).filter(e => e.type === 'address')
    if (!profiles.length) {
      showPageToast(msg('ovlDataNoAddrs', undefined, 'No identities saved — add or import one in the UCrypt vault'))
      return
    }
    const active = document.activeElement
    const scope = (active && enclosingForm(active)) || document
    // Manual fill works wherever ANY profile field is recognized; on pages
    // with none, say so honestly instead of pretending.
    if (!detectProfileFields(scope).size) {
      showPageToast(msg('prfNoFieldsManual', undefined, 'UCrypt: no recognized profile fields on this page'))
      return
    }
    showProfilePicker(profiles, active && active.tagName === 'INPUT' ? active : null, scope)
  }

  async function openProfileSaveManual() {
    const A = globalThis.UCRYPT_PROFILE_FORM
    if (!A) return
    if (!attachShadowSupported()) {
      showPageToast(msg('prfManualNoShadow', undefined, 'UCrypt: this page cannot host the protected review dialog — manage profiles in the UCrypt vault instead'))
      return
    }
    if (profileCapture) return
    const active = document.activeElement
    const form = (active && enclosingForm(active)) || null
    const domain = domainFromLocation()
    // High-confidence gate for the manual route too (§5.3): the classifier
    // must recognize the form, or the honest answer is "cannot infer".
    let descriptors = []
    try { descriptors = Array.from((form || document).querySelectorAll('input, textarea, select')).map(profileFieldDescriptor) } catch { /* none */ }
    const verdict = A.classifyProfileForm(descriptors)
    if (!verdict.captureEligible || verdict.rejectedSensitive > 0) {
      showPageToast(msg('prfManualCannot', undefined, 'UCrypt: could not safely recognize a profile form here — add or edit it in the UCrypt vault'))
      return
    }
    // Manual route may include ANY current field values (explicit action),
    // still restricted to recognized allowlisted fields; sensitive categories
    // already rejected by the form gate above.
    const found = detectProfileFields(form || document)
    const pairs = []
    for (const [key, el] of found) {
      const value = String(el.value || '').trim()
      if (!value) continue
      pairs.push({ key, value: value.slice(0, 200), include: true })
    }
    if (pairs.length < 2) {
      showPageToast(msg('prfManualEmpty', undefined, 'UCrypt: nothing to save — the recognized fields are empty'))
      return
    }
    profileCapture = { pairs, domain, form, source: 'manual' }
    showProfileSaveOverlay()
  }

  // --- Listen for fill commands from background ----------------------------

  // R28-i18n note: the listener's payload parameter is `m` — the name `msg`
  // now belongs to the i18n helper above and a shadowing parameter would turn
  // every msg('key', …) call inside this listener into a property lookup.
  chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
    if (m && m.type === 'PERFORM_FILL') {
      const domain = domainFromLocation()
      send('GET_ENTRIES', { domain }).then((r) => {
        if (!r || !r.ok || !r.entries || r.entries.length === 0) {
          // Let the caller know via console; popup will already show the user
          console.warn('[UCrypt] No entries to fill')
          sendResponse({ ok: false, error: 'No saved entries' })
          return
        }
        performFill(r.entries[0])
        sendResponse({ ok: true })
      })
      return true // async
    }
    // v2.3.0 — fill a SPECIFIC entry picked in the popup's Vault tab
    if (m && m.type === 'PERFORM_FILL_ENTRY') {
      if (!m.entry || typeof m.entry !== 'object') {
        sendResponse({ ok: false, error: 'Missing entry' })
        return
      }
      performFill(m.entry)
      sendResponse({ ok: true })
      return
    }
    // R72 §9 — "Use on page": fill the JUST-GENERATED secret into an eligible
    // password field. Explicit user press (Generator Lab "Use on page")
    // routed through the worker; native setters + events, a brief nonsecret
    // highlight, a toast — and NEVER a submit.
    if (m && m.type === 'UCRYPT_USE_GENERATED_SECRET') {
      const value = typeof m.value === 'string' ? m.value : ''
      const field = bestSuggestTarget()
      if (!value || !field) {
        showPageToast(msg('ovlToastNoField', undefined, 'UCrypt: no password field on this page'))
        sendResponse({ ok: false, error: 'No password field' })
        return
      }
      setNativeValue(field, value)
      field.focus({ preventScroll: false })
      field.style.transition = 'box-shadow .2s'
      field.style.boxShadow = '0 0 0 2px #10b981'
      setTimeout(() => { field.style.boxShadow = '' }, 800)
      showPageToast(msg('labUseToast', undefined, 'UCrypt: generated secret filled — nothing was submitted'))
      sendResponse({ ok: true })
      return
    }
    // R95 §3.1 — the popup's "Fill on page" affordance. The probe answers
    // with the detector's verdict (lib/otp-field.global.js — conservative,
    // single-source); the fill action carries the token LABEL only, asks the
    // worker for the CURRENT code itself (locked → typed refusal — never on
    // lock), fills via setNativeValue, highlights briefly, and NEVER submits.
    // Explicit user action only (the popup button press) — the overlay laws
    // are untouched: no keystroke capture, no auto-fill without the press.
    if (m && m.type === 'UCRYPT_OTP_FIELD_PRESENT') {
      const detector = (typeof globalThis !== 'undefined' && globalThis.UCRYPT_OTP) || null
      const field = detector ? detector.findOtpField(document) : null
      sendResponse({ ok: true, present: !!field })
      return
    }
    if (m && m.type === 'UCRYPT_FILL_TOTP') {
      const label = typeof m.label === 'string' ? m.label : ''
      const detector = (typeof globalThis !== 'undefined' && globalThis.UCRYPT_OTP) || null
      const field = detector ? detector.findOtpField(document) : null
      if (!field) {
        sendResponse({ ok: false, error: 'no-otp-field' })
        return
      }
      send('TOTP_AUTOFILL_CODE', { label }).then((r) => {
        if (!(r && r.ok && r.code)) {
          sendResponse({ ok: false, error: (r && r.error) || 'code-unavailable' })
          return
        }
        setNativeValue(field, r.code)
        field.focus({ preventScroll: false })
        field.style.transition = 'box-shadow .2s'
        field.style.boxShadow = '0 0 0 2px #10b981'
        setTimeout(() => { field.style.boxShadow = '' }, 800)
        showPageToast(msg('ovlOtpFilled', [String(r.remainingSec)], `Code filled — valid for ${r.remainingSec}s more`))
        sendResponse({ ok: true, remainingSec: r.remainingSec })
      }).catch((e) => sendResponse({ ok: false, error: String((e && e.message) || e) }))
      return true // async
    }
    // v2.6.0 — context menu / Ctrl+Shift+U: suggest a strong password
    if (m && m.type === 'SUGGEST_STRONG_PASSWORD') {
      const field = bestSuggestTarget()
      if (!field) {
        showPageToast(msg('ovlToastNoField', undefined, 'UCrypt: no password field on this page'))
        sendResponse({ ok: false, error: 'No password field' })
        return
      }
      field.focus({ preventScroll: false })
      openSuggestPanel(field)
      sendResponse({ ok: true })
      return
    }
    // v2.6.0 — context menu: save whatever is typed into the page's login form
    if (m && m.type === 'SAVE_PAGE_LOGIN') {
      const login = detectLoginForm()
      const domain = domainFromLocation()
      // v2.13.0 — R22-F1: same new-password capture as the submit watcher.
      const pw = login && login.passwordField
        ? captureSubmitPassword(login.form, login.passwordField)
        : ''
      if (!login || !pw) {
        showPageToast(msg('ovlToastNothing', undefined, 'UCrypt: nothing to save — type the login first'))
        sendResponse({ ok: false, error: 'Nothing to save' })
        return
      }
      // v2.11.0 — F6: fall back to the remembered username (two-step flows).
      // v2.16.0 — R25: the context-menu save now honors the per-site
      // never-save exception exactly like the passive submit watchers —
      // the two capture paths suppressed the prompt on exception sites,
      // this one did not (Chrome's menu respects the exception too).
      resolveUsername(login.usernameField, domain).then((user) => {
        send('GET_ENTRIES', { domain }).then((r) => {
          if (r && r.ok && r.neverSave) {
            showPageToast(msg('ovlToastNeverSite', undefined, 'UCrypt: saving is turned off for this site'))
            sendResponse({ ok: false, error: 'Never-save exception' })
            return
          }
          showSaveOverlay(user, pw, domain)
          sendResponse({ ok: true })
        }).catch(() => {
          // The entries check must never block a legitimate manual save.
          showSaveOverlay(user, pw, domain)
          sendResponse({ ok: true })
        })
      })
      return true // async
    }
    // v2.19.0 — R28-B1: context-menu "Fill card / Fill identity". Fetches the
    // structured entries, fills directly when there is exactly ONE, and shows
    // a picker overlay when the vault holds several. Locked → the standard
    // click-to-unlock prompt; explicit action → NOT gated by behavior prefs.
    if (m && m.type === 'FILL_DATA_PROMPT') {
      const fillType = m.fillType === 'address' ? 'address' : 'card'
      send('GET_OTHER_ENTRIES', {}).then((r) => {
        if (r && r.locked) {
          // GET_OTHER_ENTRIES answers locked with ok:false + locked:true —
          // the locked check MUST precede the generic !ok branch.
          if (frameIsUsable()) showLockedPrompt()
          sendResponse({ ok: false, locked: true })
          return
        }
        if (!r || !r.ok) {
          sendResponse({ ok: false, error: (r && r.error) || 'Vault unavailable' })
          return
        }
        const entries = (r.entries || []).filter(e => e.type === fillType)
        if (!entries.length) {
          showPageToast(fillType === 'card'
            ? msg('ovlDataNoCards', undefined, 'No cards saved — add or import one in the UCrypt vault')
            : msg('ovlDataNoAddrs', undefined, 'No identities saved — add or import one in the UCrypt vault'))
          sendResponse({ ok: false, empty: true })
          return
        }
        if (entries.length === 1) fillDataEntry(entries[0], fillType)
        else showDataPicker(entries, fillType)
        sendResponse({ ok: true, count: entries.length })
      }).catch((e) => {
        sendResponse({ ok: false, error: String(e && e.message || e) })
      })
      return true // async
    }
    if (m && m.type === 'SHOW_SAVE_PROMPT') {
      // v2.13.0 — R22-F2: the save prompt relayed from a too-small frame lands
      // here (frameId 0 = the top document), where there is room to show it.
      // R125 §2 — the same relay now also carries the worker-held staged
      // candidate to the LANDING page after a navigating submit (law 0.39);
      // fromRelay marks it so its terminals never consume a newer candidate.
      showSaveOverlay(
        String(m.username || ''),
        String(m.password || ''),
        String(m.domain || domainFromLocation()),
        { isUpdate: !!m.isUpdate, fromRelay: true },
      )
      sendResponse({ ok: true })
      return
    }
    if (m && m.type === 'VAULT_LOCKED') {
      // R59-F2 — the worker broadcasts this on EVERY lock path (explicit
      // LOCK, auto-lock alarm, keepalive transition check). A lock event
      // wins all races: surfaces destroyed, epoch bumped, caches cleared.
      // R97 (F-R96-1): an armed overlay copy is overwritten with an empty
      // string — the lock-moment clipboard net (lib/clipguard.js docs).
      try {
        if (overlayClipArmed) {
          overlayClipArmed = false
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText('').catch(() => {})
        }
      } catch { /* clipboard refused — honest no-op */ }
      handleVaultLocked()
      sendResponse({ ok: true })
      return
    }
    if (m && m.type === 'VAULT_UNLOCKED') {
      handleVaultUnlocked()
      sendResponse({ ok: true })
      return
    }
    // v2.42.8 — R71-P: context-menu "Fill profile from vault" — explicit
    // user action, NOT gated by the behavior toggles (same rule as the
    // card/identity context fill since R28).
    if (m && m.type === 'FILL_PROFILE_PROMPT') {
      openProfilePickerManual().then(() => sendResponse({ ok: true })).catch((e) => {
        sendResponse({ ok: false, error: String(e && e.message || e) })
      })
      return true // async
    }
    // v2.42.8 — R71-P: context-menu "Save current form as a profile" — the
    // review dialog opens only when the classifier confidence is high;
    // otherwise an honest explanation is shown instead.
    if (m && m.type === 'SAVE_FORM_PROFILE') {
      openProfileSaveManual().then(() => sendResponse({ ok: true })).catch((e) => {
        sendResponse({ ok: false, error: String(e && e.message || e) })
      })
      return true // async
    }
    if (m && m.type === 'PING') {
      sendResponse({ ok: true, domain: domainFromLocation() })
      return
    }
  })

  // Run after DOM is ready (document_idle should ensure it is)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 300))
  } else {
    setTimeout(init, 300)
  }

  // Re-check on SPA navigations (best-effort)
  let lastUrl = window.location.href
  setInterval(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href
      // R59-F2 — a navigation invalidates every in-flight reply: no stale
      // message or late response may resurrect a picker after it.
      bumpVaultEpoch()
      // v2.42.8 — R71-P: SPA replacement clears the profile surfaces, the
      // capture candidate and every pending profile promise.
      scrubProfileState()
      setTimeout(init, 500)
    }
  }, 2000)
})()
