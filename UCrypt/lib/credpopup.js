/**
 * UCrypt — the credential popup layer (R109 §3.1, law 0.24).
 *
 * ONE reusable modal for every vault-passphrase confirm and transport-secret
 * entry on the configuration surfaces — never a fixed inline credential
 * field on a page (the CEO's S2/S3). The popup obeys the standing laws:
 *
 *   0.8  prompt persistence — the popup NEVER auto-dismisses. No timeout, no
 *        backdrop-click dismissal, no focus-blur dismissal. It closes only on
 *        the user's explicit action: Confirm success, Cancel, or Esc.
 *   0.24 typed title naming the action, masked input with a show-toggle,
 *        verify-against-vault (passphrase mode) or validate-format (secret
 *        mode), truthful typed errors rendered INSIDE the popup, focus moves
 *        in on open and restores to the opener on close.
 *   0.13 no dead ends — the help line names the fix; errors name the fix.
 *
 * Theme-safe by construction: the dialog reuses the surfaces' own
 * .dialog-overlay / .dialog classes and the CSS custom properties, so both
 * themes render correctly with zero new palette constants.
 *
 * API (global — the extension pages are classic scripts):
 *   const r = await UCryptCredPopup.open({
 *     title,            // typed title naming the action (required)
 *     help,             // one-sentence why (optional)
 *     mode,             // 'passphrase' | 'secret'  (default 'passphrase')
 *     placeholder,      // input placeholder (optional)
 *     confirmLabel,     // confirm button label (default 'Confirm')
 *     revealValue,      // passphrase mode + set: after a verified confirm the
 *                       // popup turns into a read-only reveal view showing
 *                       // this value with a Copy action (the S2 ask: visualize
 *                       // the stored code after the UCrypt password check).
 *     revealNote,       // caption under the revealed value (optional)
 *     verify,           // async (value) => { ok:true } | { ok:false, error }
 *                       // passphrase mode: the caller's own worker verify —
 *                       // a false result renders the typed error INSIDE the
 *                       // popup and keeps it open (0.8).
 *   })
 *   r.ok === true  → { ok:true, value }         (the confirmed/entered value;
 *                                                never logged, never stored
 *                                                outside the caller's own
 *                                                sealed path)
 *   r.ok === false → { ok:false, cancelled:true } — the user's explicit cancel
 */
;(function () {
  'use strict'

  let _active = null
  let _restoreFocusTo = null

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
  }

  function build(opts) {
    const overlay = document.createElement('div')
    overlay.className = 'dialog-overlay ucrypt-credpopup'
    overlay.setAttribute('role', 'dialog')
    overlay.setAttribute('aria-modal', 'true')
    overlay.setAttribute('aria-label', opts.title || 'Confirm')
    const isPass = (opts.mode || 'passphrase') === 'passphrase'
    overlay.innerHTML = `
      <div class="dialog" style="max-width:430px">
        <h2 id="ucp-title">${esc(opts.title || 'Confirm')}</h2>
        ${opts.help ? `<p class="card-help" style="margin:0 0 10px">${esc(opts.help)}</p>` : ''}
        <div class="ucp-entry">
          <div style="display:flex;gap:6px;align-items:stretch">
            <input id="ucp-input" type="password" autocomplete="off" spellcheck="false"
              placeholder="${esc(opts.placeholder || (isPass ? 'Master passphrase' : 'Paste the value'))}"
              style="flex:1;min-width:0" aria-describedby="ucp-error" />
            <button id="ucp-eye" class="btn btn-ghost btn-sm" type="button"
              aria-label="Show the value" aria-pressed="false" title="Show / hide"
              style="min-width:38px">👁</button>
          </div>
          <p id="ucp-error" class="sync-test-result" role="alert" style="margin:8px 0 0" hidden></p>
        </div>
        <div class="ucp-reveal" hidden>
          <div style="display:flex;gap:6px;align-items:stretch">
            <input id="ucp-revealed" type="text" readonly
              style="flex:1;min-width:0;font-family:var(--mono,monospace);user-select:all" />
            <button id="ucp-copy" class="btn btn-outline btn-sm" type="button" style="min-width:38px"
              aria-label="Copy the value" title="Copy">⧉</button>
          </div>
          ${opts.revealNote ? `<p class="card-help pwm-note" style="margin:8px 0 0">${esc(opts.revealNote)}</p>` : ''}
        </div>
        <div class="dialog-actions">
          <button id="ucp-cancel" class="btn btn-ghost" type="button">Cancel</button>
          <button id="ucp-confirm" class="btn btn-primary" type="button">${esc(opts.confirmLabel || 'Confirm')}</button>
        </div>
      </div>`
    return overlay
  }

  function showError(overlay, msg) {
    const el = overlay.querySelector('#ucp-error')
    if (!el) return
    el.textContent = msg ? '✗ ' + msg : ''
    el.className = 'sync-test-result' + (msg ? ' err' : '')
    el.hidden = !msg
  }

  function close(resolution) {
    if (!_active) return
    const { overlay, resolve } = _active
    _active = null
    try { overlay.remove() } catch { /* already gone */ }
    document.removeEventListener('keydown', _activeKeyHandler, true)
    if (_restoreFocusTo && typeof _restoreFocusTo.focus === 'function') {
      try { _restoreFocusTo.focus() } catch { /* the opener may be gone */ }
    }
    _restoreFocusTo = null
    resolve(resolution)
  }

  function _activeKeyHandler(e) {
    if (!_active) return
    if (e.key === 'Escape') {
      e.preventDefault()
      e.stopPropagation()
      close({ ok: false, cancelled: true })
      return
    }
    // The focus-trap: Tab cycles inside the dialog (0.24 focus management).
    if (e.key === 'Tab') {
      const focusables = _active.overlay.querySelectorAll('button, input, [tabindex]:not([tabindex="-1"])')
      if (!focusables.length) return
      const list = [...focusables].filter((el) => el.offsetParent !== null)
      if (!list.length) return
      const first = list[0]
      const last = list[list.length - 1]
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
    }
  }

  async function open(opts) {
    opts = opts || {}
    if (_active) close({ ok: false, cancelled: true }) // one popup at a time
    const isPass = (opts.mode || 'passphrase') === 'passphrase'
    _restoreFocusTo = document.activeElement
    const overlay = build(opts)
    document.body.appendChild(overlay)

    const input = overlay.querySelector('#ucp-input')
    const eye = overlay.querySelector('#ucp-eye')
    const confirmBtn = overlay.querySelector('#ucp-confirm')
    const cancelBtn = overlay.querySelector('#ucp-cancel')
    const entryBox = overlay.querySelector('.ucp-entry')
    const revealBox = overlay.querySelector('.ucp-reveal')

    const show = () => { input.type = 'text'; eye.setAttribute('aria-pressed', 'true') }
    const hide = () => { input.type = 'password'; eye.setAttribute('aria-pressed', 'false') }
    eye.addEventListener('click', () => { (input.type === 'password' ? show : hide)() })

    const finish = (resolution) => close(resolution)

    confirmBtn.addEventListener('click', async () => {
      const value = String(input.value || '')
      if (!value) {
        showError(overlay, isPass
          ? 'Enter your master passphrase to continue.'
          : 'Paste the value first — the field is empty.')
        input.focus()
        return
      }
      if (typeof opts.verify === 'function') {
        confirmBtn.disabled = true
        showError(overlay, '')
        let verdict = null
        try { verdict = await opts.verify(value) } catch (e) { verdict = { ok: false, error: String((e && e.message) || e) } }
        confirmBtn.disabled = false
        if (!verdict || verdict.ok !== true) {
          showError(overlay, (verdict && verdict.error) || 'That did not verify — check the value and try again.')
          input.focus()
          input.select && input.select()
          return // NEVER auto-dismiss (0.8): the popup stays, the error is typed
        }
      }
      // The S2 reveal view: after a verified confirm, show the value instead
      // of closing straight away — the user reads/copies, then closes by hand.
      if (opts.revealValue != null && isPass) {
        entryBox.hidden = true
        revealBox.hidden = false
        const revealed = overlay.querySelector('#ucp-revealed')
        revealed.value = String(opts.revealValue)
        confirmBtn.hidden = true
        cancelBtn.textContent = 'Close'
        overlay.querySelector('#ucp-copy').addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(String(opts.revealValue))
            const c = overlay.querySelector('#ucp-copy')
            c.textContent = '✓'
            setTimeout(() => { try { c.textContent = '⧉' } catch { /* the icon reset is best-effort — a gone overlay owes nothing (named-swallow law, R169 C1) */ } }, 1200)
          } catch { /* the input is select-all — the manual copy stays */ }
        })
        revealed.focus()
        revealed.select && revealed.select()
        return // the user's explicit Close finishes the popup
      }
      finish({ ok: true, value })
    })

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); confirmBtn.click() }
    })
    cancelBtn.addEventListener('click', () => finish({ ok: false, cancelled: true }))
    // 0.8: a backdrop click is NOT a dismissal — clicks on the overlay itself
    // are ignored. Only the explicit controls and Esc close the popup.
    overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) e.preventDefault() })

    document.addEventListener('keydown', _activeKeyHandler, true)
    setTimeout(() => { try { input.focus() } catch { /* the focus is best-effort — the overlay may already be gone (named-swallow law, R169 C1) */ } }, 30)

    return new Promise((resolve) => { _active = { overlay, resolve } })
  }

  globalThis.UCryptCredPopup = { open }
})()
