/**
 * UCrypt — R116 §2.3 — THE INLINE-FIX CONNECT OVERLAY (law 0.29; the CEO's
 * S6 order, the round's headline visual).
 *
 * The Discovery checklist's "✗ Cloud rendezvous — [Connect your cloud]" used
 * to deep-link to the options page (ANOTHER area — the exact defect the CEO
 * named: "The configuration for this must to be opened inside 'File
 * transfer' area... we could use more pop up layers"). Now the connect flow
 * opens as an overlay RIGHT HERE, and the demoted fallback (Open settings)
 * renders after the primary path, visually demoted.
 *
 * Two overlays live here:
 *   openConnectOverlay() — the transport chooser (Google Drive first, then
 *     WebDAV / GitHub Gist / Dropbox / Custom URL), a minimal form rendered
 *     from the REAL transport field definitions (single source of truth —
 *     no schema drift), the OAuth Connect button per OAuth transport, Test
 *     connection (the typed recovery card renders INLINE — the disabled
 *     client's checklist + the Cloud Console deep link), then Save.
 *   openJoinOverlay()    — paste the 24-word sync code → the chain joins
 *     in place (SYNC_CODE_SET, source 'adopt'); the full setup stays one
 *     demoted click away.
 *
 * The pure parts (the form model, the join-words pre-check) are exported
 * for the battery (law 0.4: the census rows and the battery rows carry the
 * same symbols). The DOM parts need `document` — the transfer page only.
 */

// --- The pure model (battery-pinned) ---------------------------------------

/** The OAuth transports' worker message + grant field (the wire contract). */
export const CONNECT_MSG_TYPES = {
  gdrive: { msgType: 'TRANSPORT_GDRIVE_CONNECT', grantField: 'refreshToken' },
  github: { msgType: 'TRANSPORT_GITHUB_CONNECT', grantField: 'oauthAccessToken' },
  dropbox: { msgType: 'TRANSPORT_DROPBOX_CONNECT', grantField: 'refreshToken' },
}

/** The chooser order — Google Drive first (the CEO's own setup), the
 * no-account transports after, Custom URL last (the power-user lane). */
export const CONNECT_CHOOSER_ORDER = ['gdrive', 'webdav', 'github', 'dropbox', 'custom']

/** The taglines — one line each, 13-year-old level (law 0.13). */
export const CONNECT_CHOOSER_TAGLINES = {
  gdrive: 'Your Google account via PKCE — recommended.',
  webdav: 'Nextcloud, Synology, or any WebDAV server.',
  github: 'A private GitHub Gist — code + PKCE.',
  dropbox: 'Your Dropbox account via PKCE.',
  custom: 'Any URL that accepts PUT + GET.',
}

/**
 * The minimal form model for one transport, derived from the REAL transport
 * definition (the same `fields` the options wizard renders — additions-only
 * filtering, never a divergent copy): advanced/bridge fields stay out of
 * the overlay (they remain in the full wizard), the OAuth fields and the
 * core url/user/pass fields stay in, in definition order.
 *
 * @param {string} transportId
 * @param {(id: string) => {name: string, fields: Array<object>}|null} getTransportImpl
 * @returns {{id: string, name: string, tagline: string, oauth: boolean, msgType?: string, grantField?: string, fields: Array<object>}}
 */
export function connectFormModel(transportId, getTransportImpl) {
  const t = getTransportImpl(transportId)
  if (!t) return null
  const wire = CONNECT_MSG_TYPES[transportId] || null
  const fields = (t.fields || []).filter(
    (f) => !f.advancedField && !f.bridgeField
  )
  return {
    id: transportId,
    name: t.name,
    tagline: CONNECT_CHOOSER_TAGLINES[transportId] || '',
    oauth: !!wire,
    msgType: wire ? wire.msgType : undefined,
    grantField: wire ? wire.grantField : undefined,
    fields,
  }
}

/** The chooser model — every transport in CONNECT_CHOOSER_ORDER order. */
export function connectChooserModel(getTransportImpl) {
  const out = []
  for (const id of CONNECT_CHOOSER_ORDER) {
    const m = connectFormModel(id, getTransportImpl)
    if (m) out.push(m)
  }
  return out
}

/**
 * R117 §3 (law 0.30; the CEO's S2) — the chooser card's STATE line, pure:
 * the currently-selected card's state (configured, last outcome) renders on
 * the card itself, and the SAME summary rides the form layer's header. The
 * input is the page's status provider result (or null — never invented).
 * @param {{configured?: boolean, lastPush?: {ok?: boolean, at?: number, error?: string}|null, lastTest?: {ok?: boolean, at?: number}|null}|null} st
 * @returns {{cls: 'ok'|'err'|'dim', text: string}}
 */
export function chooserStatusLine(st) {
  if (!st || !st.configured) return { cls: 'dim', text: '' }
  const lp = st.lastPush
  if (lp && lp.ok) return { cls: 'ok', text: '✓ Last push OK' }
  if (lp && !lp.ok) return { cls: 'err', text: '⚠ Last push failed' }
  return { cls: 'ok', text: '✓ Configured' }
}

/**
 * The join-words pre-check (pure): the 24 words, whitespace/dash separated.
 * The worker validates against the BIP39 list + checksum — this is the
 * fast, kind pre-check that refuses obvious mistakes before the wire.
 */
export function validateJoinWords(text) {
  const words = String(text || '').trim().split(/[\s-]+/).filter(Boolean)
  if (words.length === 0) return { ok: false, error: 'Paste the 24 words first — the field is empty.' }
  if (words.length !== 24) {
    return { ok: false, words, error: `The sync code is 24 words — this paste carries ${words.length}.` }
  }
  if (!words.every((w) => /^[a-zA-Zà-öø-ÿÀ-ÖØ-ß][a-zA-Zà-öø-ÿÀ-ÖØ-ß-]*$/.test(w))) {
    return { ok: false, words, error: 'The words should be letters only — numbers or symbols do not belong in a sync code.' }
  }
  return { ok: true, words, error: '' }
}

// --- The overlays (DOM — the transfer page only) ----------------------------

/**
 * R117 §2 (the CEO's S3; law 0.26) — the overlay header's VISIBLE close
 * button: a popup layer that cannot be dismissed by an explicit click is a
 * dead end (Esc alone is not an answer). Both overlays build the same
 * header row: the title + the ✕ (aria-labeled, focusable, closes the
 * dialog). On close, focus RETURNS to the triggering checklist row (law
 * 0.13's keyboard path — the trigger is passed in deps.trigger).
 */
function buildOverlayHeader(dlg, root, titleId, titleText, msg, closeLabel) {
  const headRow = document.createElement('div')
  headRow.className = 'transfer-overlay-head'
  const head = document.createElement('h3')
  head.id = titleId
  head.textContent = titleText
  headRow.appendChild(head)
  const closeBtn = document.createElement('button')
  closeBtn.type = 'button'
  closeBtn.className = 'transfer-overlay-close'
  closeBtn.setAttribute('aria-label', msg('tcoCloseBtn', undefined, closeLabel))
  closeBtn.title = msg('tcoCloseBtn', undefined, closeLabel)
  closeBtn.textContent = '✕'
  closeBtn.addEventListener('click', () => { try { dlg.close() } catch { /* the close handler stands */ } })
  headRow.appendChild(closeBtn)
  root.appendChild(headRow)
  return head
}

/**
 * Build and open the connect overlay. Everything the user needs lives in
 * the overlay (law 0.29): the chooser, the form, Test (with the typed
 * recovery card INLINE), Save — and the demoted "Open full setup" ghost
 * row at the very bottom (the fallback path, visually demoted).
 *
 * R117 §3 (law 0.30; the CEO's S2): choosing a transport card NOW opens
 * its configuration in one click — the form layer scrolls into view inside
 * the dialog and carries the card's status summary (Last push · configured)
 * in its header; the same state line renders on the card itself.
 *
 * @param {object} deps injected by the page:
 *   worker(msg) — the worker postMessage helper
 *   getTransport(id) — the real transport registry getter
 *   getStatus(id) — async (id) => {configured, lastPush, lastTest}|null (the ledger truth)
 *   msg(key, subs, fallback) — the i18n helper
 *   onSaved() / onClose() — page callbacks (refresh the checklist)
 *   openFullSetup() — the DEMOTED fallback (the old deep link)
 *   trigger — the element focus returns to on close (law 0.13)
 */
export function openConnectOverlay(deps) {
  const { worker, getTransport, getStatus, msg, onSaved, onClose, openFullSetup, trigger } = deps
  if (typeof document === 'undefined') return null
  const chooser = connectChooserModel(getTransport)
  const statusOf = typeof getStatus === 'function' ? getStatus : async () => null
  const statusCache = new Map()

  const dlg = document.createElement('dialog')
  dlg.id = 'transferConnectOverlay'
  dlg.className = 'transfer-overlay-dialog'
  dlg.setAttribute('aria-labelledby', 'tcoTitle')

  const root = document.createElement('div')
  root.className = 'transfer-connect'

  const head = buildOverlayHeader(dlg, root, 'tcoTitle', msg('tcoTitle', undefined, 'Connect your cloud'), msg, 'Close')
  const sub = document.createElement('p')
  sub.className = 'transfer-overlay-sub'
  sub.textContent = msg('tcoSub', undefined, 'Pick a cloud storage, connect it, and the checklist row above turns green. Your vault is encrypted before anything is uploaded.')
  root.appendChild(sub)

  // -- step 1: the chooser --------------------------------------------------
  const chooserBox = document.createElement('div')
  chooserBox.className = 'transfer-chooser'
  chooserBox.setAttribute('role', 'radiogroup')
  chooserBox.setAttribute('aria-label', msg('tcoChooserLabel', undefined, 'Choose a cloud storage'))
  root.appendChild(chooserBox)

  // -- step 2: the form (hidden until a transport is picked) -----------------
  const formBox = document.createElement('div')
  formBox.className = 'transfer-connect-form hidden'
  formBox.hidden = true
  root.appendChild(formBox)

  const resultLine = document.createElement('p')
  resultLine.className = 'transfer-overlay-result'
  resultLine.setAttribute('role', 'status')
  root.appendChild(resultLine)

  // -- the demoted fallback row (ALWAYS last, visually demoted) --------------
  const fallbackRow = document.createElement('div')
  fallbackRow.className = 'transfer-overlay-fallback'
  const fallbackBtn = document.createElement('button')
  fallbackBtn.type = 'button'
  fallbackBtn.className = 'btn btn-ghost btn-sm'
  fallbackBtn.textContent = msg('tcoOpenFullSetup', undefined, 'Open the full cloud setup instead')
  fallbackBtn.title = msg('tcoOpenFullSetupTitle', undefined, 'The long form lives in Cloud Sync — this overlay covers the common case.')
  fallbackBtn.addEventListener('click', () => {
    try { dlg.close() } catch { /* the page callback stands */ }
    if (typeof openFullSetup === 'function') openFullSetup()
  })
  fallbackRow.appendChild(fallbackBtn)
  root.appendChild(fallbackRow)

  dlg.appendChild(root)
  document.body.appendChild(dlg)

  let picked = null
  let pickedModel = null

  const renderChooser = () => {
    chooserBox.textContent = ''
    for (const m of chooser) {
      const opt = document.createElement('button')
      opt.type = 'button'
      opt.className = 'transfer-chooser-option' + (picked === m.id ? ' picked' : '')
      opt.setAttribute('role', 'radio')
      opt.setAttribute('aria-checked', picked === m.id ? 'true' : 'false')
      const nm = document.createElement('strong')
      nm.textContent = m.name
      const tg = document.createElement('span')
      tg.className = 'transfer-chooser-tag'
      tg.textContent = m.tagline
      opt.appendChild(nm)
      opt.appendChild(tg)
      // R117 §3 (law 0.30; the CEO's S2): the card's own state line — the
      // configured card's last outcome renders ON the card (never a dead
      // selection: choosing it carries the same summary to the form header).
      const stLine = chooserStatusLine(statusCache.get(m.id))
      if (stLine.text) {
        const st = document.createElement('span')
        st.className = 'transfer-chooser-state transfer-chooser-state-' + stLine.cls
        st.textContent = stLine.text
        opt.appendChild(st)
      }
      opt.addEventListener('click', () => {
        picked = m.id
        pickedModel = m
        renderChooser()
        renderForm(m)
      })
      chooserBox.appendChild(opt)
    }
  }

  const setLine = (text, kind = '') => {
    resultLine.textContent = text || ''
    resultLine.className = 'transfer-overlay-result' + (kind ? ' ' + kind : '')
  }

  const collectForm = () => {
    const cfg = {}
    for (const inp of formBox.querySelectorAll('input[data-field-key], select[data-field-key]')) {
      const k = inp.getAttribute('data-field-key')
      if (k) cfg[k] = String(inp.value || '').trim()
    }
    return cfg
  }

  // THE TYPED RECOVERY CARD AT THE WORDS (law 0.29; the CEO's S2 law made
  // overlay law too): a failed test/connect renders the card INLINE here —
  // title, causes, the fix, the Cloud Console deep link as the primary.
  const renderRecoveryCard = (recovery) => {
    if (!recovery || typeof recovery !== 'object') return
    const card = document.createElement('div')
    card.className = 'transfer-overlay-recovery'
    const title = document.createElement('strong')
    title.textContent = recovery.title || ''
    card.appendChild(title)
    if (Array.isArray(recovery.causes) && recovery.causes.length) {
      const ul = document.createElement('ul')
      for (const c of recovery.causes) {
        const li = document.createElement('li')
        li.textContent = String(c)
        ul.appendChild(li)
      }
      card.appendChild(ul)
    }
    if (recovery.fix) {
      const fix = document.createElement('p')
      fix.className = 'card-help'
      fix.style.whiteSpace = 'pre-line'
      fix.textContent = String(recovery.fix)
      card.appendChild(fix)
    }
    if (recovery.consoleUrl) {
      const row = document.createElement('div')
      row.className = 'btn-row'
      const b = document.createElement('button')
      b.type = 'button'
      b.className = 'btn btn-primary btn-sm'
      b.textContent = msg('attnActionConsole', undefined, 'Open Google Cloud Console')
      b.addEventListener('click', () => { try { chrome.tabs.create({ url: recovery.consoleUrl }) } catch { /* the card stays */ } })
      row.appendChild(b)
      card.appendChild(row)
    }
    resultLine.appendChild(card)
  }

  const renderForm = (m) => {
    formBox.textContent = ''
    formBox.classList.remove('hidden')
    formBox.hidden = false
    // R117 §3 (law 0.30; the CEO's S2): the form layer's HEADER carries the
    // card's status summary — the selection is the beginning of the
    // configuration, never a search for where the form lives.
    const formHead = document.createElement('div')
    formHead.className = 'transfer-form-head'
    const formName = document.createElement('strong')
    formName.textContent = m.name
    formHead.appendChild(formName)
    const headSt = chooserStatusLine(statusCache.get(m.id))
    if (headSt.text) {
      const headStatus = document.createElement('span')
      headStatus.className = 'transfer-form-status transfer-form-status-' + headSt.cls
      headStatus.textContent = headSt.text
      formHead.appendChild(headStatus)
    }
    formBox.appendChild(formHead)
    const back = document.createElement('button')
    back.type = 'button'
    back.className = 'btn btn-ghost btn-sm'
    back.textContent = msg('tcoBack', undefined, '← Choose a different storage')
    back.addEventListener('click', () => {
      picked = null
      pickedModel = null
      setLine('')
      formBox.classList.add('hidden')
      formBox.hidden = true
      renderChooser()
    })
    formBox.appendChild(back)
    for (const f of m.fields) {
      const wrap = document.createElement('div')
      wrap.className = 'form-group'
      const lab = document.createElement('label')
      lab.setAttribute('for', `tco-field-${f.key}`)
      lab.textContent = f.label || f.key
      wrap.appendChild(lab)
      let inp
      if (f.type === 'select' && Array.isArray(f.options)) {
        inp = document.createElement('select')
        for (const o of f.options) {
          const oi = document.createElement('option')
          oi.value = o
          oi.textContent = o
          if (f.default && o === f.default) oi.selected = true
          inp.appendChild(oi)
        }
      } else {
        inp = document.createElement('input')
        inp.type = f.type === 'password' ? 'password' : (f.type === 'url' ? 'url' : 'text')
        if (f.placeholder) inp.placeholder = f.placeholder
      }
      inp.id = `tco-field-${f.key}`
      inp.setAttribute('data-field-key', f.key)
      inp.autocomplete = 'off'
      wrap.appendChild(inp)
      if (f.help) {
        const h = document.createElement('p')
        h.className = 'card-help'
        h.style.margin = '4px 0 0'
        h.textContent = f.help
        wrap.appendChild(h)
      }
      formBox.appendChild(wrap)
    }
    // The OAuth Connect button rides ABOVE Test/Save for oauth transports.
    if (m.oauth) {
      const connectBtn = document.createElement('button')
      connectBtn.type = 'button'
      connectBtn.className = 'btn btn-primary'
      connectBtn.textContent = msg('tcoConnectBtn', [m.name], `Connect ${m.name} (OAuth)`)
      connectBtn.addEventListener('click', async () => {
        setLine(msg('tcoConnecting', undefined, 'Opening the authorization window…'))
        try {
          const res = await worker({ type: m.msgType, config: collectForm() })
          if (res && res.ok && (res.refreshToken || res.accessToken)) {
            const grant = res.refreshToken || res.accessToken
            const rt = formBox.querySelector(`input[data-field-key="${m.grantField}"]`)
            if (rt) rt.value = grant
            setLine('✓ ' + msg('tcoConnected', undefined, 'Grant received — press Save to seal it device-only.'), 'ok')
          } else {
            setLine('✗ ' + ((res && res.error) || msg('tcoFail', undefined, 'The authorization did not finish.')), 'err')
            renderRecoveryCard(res && res.recovery)
          }
        } catch (e) {
          setLine('✗ ' + String((e && e.message) || e), 'err')
        }
      })
      formBox.appendChild(connectBtn)
    }
    const testBtn = document.createElement('button')
    testBtn.type = 'button'
    testBtn.className = 'btn btn-outline'
    testBtn.textContent = msg('tcoTestBtn', undefined, 'Test connection')
    testBtn.addEventListener('click', async () => {
      setLine(msg('twTesting', undefined, 'Testing…'))
      try {
        const res = await worker({ type: 'TRANSPORT_TEST', transportId: m.id, config: collectForm() })
        if (res && res.ok) {
          setLine('✓ ' + (res.message || msg('twTestOk', undefined, 'Server reachable')), 'ok')
        } else if (res && res.locked) {
          setLine('✗ ' + String(res.error || 'Unlock the vault first.'), 'err')
        } else {
          setLine('✗ ' + ((res && res.error) || msg('twTestFail', undefined, 'Connection failed — check the details, then press Test again.')), 'err')
          renderRecoveryCard(res && res.recovery)
        }
      } catch (e) {
        setLine('✗ ' + String((e && e.message) || e), 'err')
      }
    })
    formBox.appendChild(testBtn)
    const saveBtn = document.createElement('button')
    saveBtn.type = 'button'
    saveBtn.className = 'btn btn-primary'
    saveBtn.textContent = msg('tcoSaveBtn', undefined, 'Save transport')
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true
      try {
        const res = await worker({ type: 'TRANSPORT_SAVE', transportId: m.id, config: collectForm() })
        if (res && res.ok) {
          setLine('✓ ' + msg('tcoSaved', undefined, 'Saved — your cloud is connected. The checklist row above turns green.'), 'ok')
          if (typeof onSaved === 'function') onSaved()
          // LAW 0.52 (R133, the CEO's verbatim command — POPUP CONSENT): a
          // layer that asked for input NEVER closes itself. The success line
          // stays; the ONLY exit is the user's own Close button (the visible
          // ✕ in the header). The old 1.2 s timer close is deleted.
        } else {
          setLine('✗ ' + ((res && res.error) || msg('tcoSaveFail', undefined, 'Could not save the transport')), 'err')
          renderRecoveryCard(res && res.recovery)
        }
      } catch (e) {
        setLine('✗ ' + String((e && e.message) || e), 'err')
      } finally {
        saveBtn.disabled = false
      }
    })
    formBox.appendChild(saveBtn)
    // R117 §3 (law 0.30): the revealed configuration is IN VIEW — the form
    // scrolls to the dialog's top the moment the card is clicked (the CEO's
    // S2 anchor law: choose → configure, never a search for the form).
    try { formBox.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* static reveal stands */ }
  }

  // Prime the status cache (the ledger truth), then render. The cards'
  // state lines and the form header share one fetch per transport.
  ;(async () => {
    try {
      await Promise.all(chooser.map(async (m) => {
        const st = await statusOf(m.id)
        if (st) statusCache.set(m.id, st)
      }))
    } catch { /* the cards render without state lines — never a lie */ }
    renderChooser()
  })()
  renderChooser()
  if (typeof dlg.showModal === 'function') dlg.showModal()
  else dlg.setAttribute('open', '')
  dlg.addEventListener('close', () => {
    try { dlg.remove() } catch { /* already gone */ }
    if (trigger && typeof trigger.focus === 'function') { try { trigger.focus() } catch { /* gone */ } }
    if (typeof onClose === 'function') onClose()
  })
  dlg.addEventListener('cancel', (e) => { e.preventDefault(); try { dlg.close() } catch { /* stays */ } })
  return dlg
}

/**
 * Build and open the join overlay: paste the 24 words → the chain joins in
 * place (the checklist's chain row turns green). The full setup (generate a
 * NEW code / QR pairing) stays one demoted click away — the fallback path.
 */
export function openJoinOverlay(deps) {
  const { worker, msg, onJoined, onClose, openFullSetup, trigger } = deps
  if (typeof document === 'undefined') return null

  const dlg = document.createElement('dialog')
  dlg.id = 'transferJoinOverlay'
  dlg.className = 'transfer-overlay-dialog'
  dlg.setAttribute('aria-labelledby', 'tjoTitle')
  const root = document.createElement('div')
  root.className = 'transfer-connect'

  // R117 §2 (the CEO's S3): the join overlay carries the SAME visible close
  // button as the connect overlay — every popup layer is dismissible by
  // click (law 0.26: a truthful dead end is a defect).
  const head = buildOverlayHeader(dlg, root, 'tjoTitle', msg('tjoTitle', undefined, 'Join a sync chain'), msg, 'Close')
  void head
  const sub = document.createElement('p')
  sub.className = 'transfer-overlay-sub'
  sub.textContent = msg('tjoSub', undefined, 'Paste the 24-word sync code from your other device. The words are this chain’s key — they never leave this device.')
  root.appendChild(sub)

  const lab = document.createElement('label')
  lab.setAttribute('for', 'tjoWords')
  lab.textContent = msg('tjoWordsLabel', undefined, 'The 24 words')
  root.appendChild(lab)
  const words = document.createElement('textarea')
  words.id = 'tjoWords'
  words.className = 'transfer-overlay-words'
  words.rows = 3
  words.autocomplete = 'off'
  words.spellcheck = false
  words.placeholder = 'word one word two … (24 words)'
  root.appendChild(words)

  const resultLine = document.createElement('p')
  resultLine.className = 'transfer-overlay-result'
  resultLine.setAttribute('role', 'status')
  root.appendChild(resultLine)

  const joinBtn = document.createElement('button')
  joinBtn.type = 'button'
  joinBtn.className = 'btn btn-primary'
  joinBtn.textContent = msg('tjoJoinBtn', undefined, 'Join the chain')
  joinBtn.addEventListener('click', async () => {
    const pre = validateJoinWords(words.value)
    if (!pre.ok) {
      setLine('✗ ' + pre.error, 'err')
      return
    }
    joinBtn.disabled = true
    setLine(msg('tjoJoining', undefined, 'Joining…'))
    try {
      const res = await worker({ type: 'SYNC_CODE_SET', mnemonic: pre.words.join(' '), source: 'adopt' })
      if (res && res.ok) {
        setLine('✓ ' + msg('tjoJoined', undefined, 'Joined — this device is on your sync chain. The checklist row above turns green.'), 'ok')
        if (typeof onJoined === 'function') onJoined()
        // LAW 0.52 (R133, POPUP CONSENT): the join dialog asked for input —
        // it never closes itself. The ✓ line stays; the user's own Close
        // button is the only exit. The old 1.2 s timer close is deleted.
      } else {
        setLine('✗ ' + ((res && res.error) || msg('tjoFail', undefined, 'The words did not join a chain — check the paste and try again.')), 'err')
      }
    } catch (e) {
      setLine('✗ ' + String((e && e.message) || e), 'err')
    } finally {
      joinBtn.disabled = false
    }
  })
  root.appendChild(joinBtn)

  const fallbackRow = document.createElement('div')
  fallbackRow.className = 'transfer-overlay-fallback'
  const fallbackBtn = document.createElement('button')
  fallbackBtn.type = 'button'
  fallbackBtn.className = 'btn btn-ghost btn-sm'
  fallbackBtn.textContent = msg('tjoOpenFullSetup', undefined, 'Open the full chain setup instead')
  fallbackBtn.title = msg('tjoOpenFullSetupTitle', undefined, 'Generate a NEW code, scan a QR, or manage devices — the long form lives in Cloud Sync.')
  fallbackBtn.addEventListener('click', () => {
    try { dlg.close() } catch { /* the page callback stands */ }
    if (typeof openFullSetup === 'function') openFullSetup()
  })
  fallbackRow.appendChild(fallbackBtn)
  root.appendChild(fallbackRow)

  function setLine(text, kind = '') {
    resultLine.textContent = text || ''
    resultLine.className = 'transfer-overlay-result' + (kind ? ' ' + kind : '')
  }

  dlg.appendChild(root)
  document.body.appendChild(dlg)
  if (typeof dlg.showModal === 'function') dlg.showModal()
  else dlg.setAttribute('open', '')
  words.focus()
  dlg.addEventListener('close', () => {
    try { dlg.remove() } catch { /* already gone */ }
    if (trigger && typeof trigger.focus === 'function') { try { trigger.focus() } catch { /* gone */ } }
    if (typeof onClose === 'function') onClose()
  })
  dlg.addEventListener('cancel', (e) => { e.preventDefault(); try { dlg.close() } catch { /* stays */ } })
  return dlg
}
