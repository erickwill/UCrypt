/**
 * UCrypt — R136 §6 + R138 §3/§4 — THE BEAM 3 PAGE SUPERVISOR.
 *
 * R138 THE HANDSHAKE — the single-writer law at the screen: EVERY rendered
 * element of the transfer surface derives from ONE projection
 * (projectHandshake, via the engine's status payload) — the readiness rows,
 * the glyphs, the prose, the buttons, the step rail, the fallback decision,
 * the diagnostics drawer. Independent polling writers are RETIRED: there is
 * nothing left to contradict, because there is only one writer (F2).
 *
 *   1. INTENT: Send a file / Receive — either click ARMS AVAILABILITY
 *      automatically (R136-F4) with the visible confirmation + instant Stop.
 *   2. READINESS: the tri-state rows (F5 — done ✓ / active ▶ / pending ·)
 *      with every red row's one-tap fix; a pending CHOICE never carries a
 *      check; glyph and text derive from the same fact (F2).
 *   3. EVIDENCE: the step rail is a DEEP-LINK rail (F6) — every row navigates
 *      to its action area (scroll + focus + highlight) and the flow auto-
 *      advances BY COMPLETION, never by timers; picking the file and pressing
 *      Send is the LAST step of the flow.
 *   4. PAIRING: the six-step two-way manual protocol (§4.2) — the answer
 *      exists THE INSTANT the inbound signal opens, its return path is
 *      stated in plain copy, 'Codes match — connect' lands CONNECTED
 *      deterministically, and NO step ever needs repeating (the no-redo law).
 *   5. TRUTH: 'Searching… Xs' while the machine is SEARCHING (F3 — the wait
 *      is never silent); a 30-second stall is a TYPED notice with its fix;
 *      every FAILED carries its typed reason and its fix in the same breath.
 *   6. FALLBACK: auto-collapses when a better plane connects (F7) — a
 *      REVERSIBLE layout state with a persistent 'Show manual fallback'
 *      affordance, never a disappearing surface.
 *   7. DIAGNOSTICS: the drawer (F8) hosts the per-hop telemetry (F4) + the
 *      Beam identity + 'Open settings'; it opens ITSELF only on anomaly.
 *   8. IRON LAW (§4.5): nothing closes without consent — terminals stay
 *      until the user dismisses them; collapse ≠ dismissal.
 *
 * The legacy handlers stay wired beside the new renders (law 0.4 — nothing
 * removed); the worker is the engine; this file renders its truth.
 */

const $ = (id) => document.getElementById(id)

function send(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (res) => {
        void chrome.runtime.lastError
        resolve(res || null)
      })
    } catch {
      resolve(null)
    }
  })
}

let getMessage = (key, subs, fallback) => {
  try {
    const m = chrome.i18n.getMessage(key, subs)
    return m || fallback || key
  } catch {
    return fallback || key
  }
}

const STEP_FALLBACKS = {
  INTENT: 'Choose Send a file or Receive — UCrypt arms availability for you',
  READINESS: 'Check the readiness strip — every row must be green or have its fix pressed',
  PAIR: 'Pair the devices — copy your signal, paste theirs',
  CONFIRM: 'Confirm the code — compare the 4×4 code on both screens',
  TRANSFER: 'Transfer — pick the file (or await the offer) and watch the progress',
  VERIFY: 'Verify — the digest is checked before anything is saved',
  DONE: 'Done — the receipt stays until you dismiss it',
}

let lastSessionId = ''
let lastSignal = null
let pollTimer = null
let lastProjection = null
let userExpandedFallback = false // the user's explicit reopen wins over the collapse (F7)

function fmtBytes(n) {
  const v = Number(n) || 0
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)} MB`
  if (v >= 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${v} B`
}

/* ═══ R138 F6 — THE DEEP-LINK NAVIGATION: every rail row and every fix
 * navigates to its action area with scroll, focus, and a visible highlight,
 * and returns the user's eye to the checklist by the completion evidence
 * (the flow auto-advances BY COMPLETION). Never inert text. ═══ */
const RAIL_TARGETS = {
  intent: 'transferRoleSend',
  readiness: 'beam3ReadinessRows',
  pair: 'beam3PairCard',
  confirm: 'beam3PairState',
  transfer: 'transferRoleSend',
  verify: 'beam3Workflow',
  done: 'beam3Workflow',
}

function deepLink(targetId) {
  const el = targetId === 'transferRoleSend' ? $('transferRoleSend') : $(targetId)
  if (!el) return
  try {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.focus({ preventScroll: true })
    el.classList.remove('beam3-deeplink-flash')
    void el.offsetWidth // restart the highlight animation
    el.classList.add('beam3-deeplink-flash')
  } catch { /* the highlight is enhancement; the navigation already happened */ }
}

/** The step rail — ONE active, done collapsed, future dimmed; every row a deep link (F6). */
function renderSteps(steps) {
  const host = $('beam3Steps')
  if (!host || !Array.isArray(steps)) return
  host.textContent = ''
  for (const s of steps) {
    const li = document.createElement('li')
    li.className = `beam3-step beam3-step-${s.state}`
    li.dataset.step = s.id
    const chip = document.createElement('span')
    chip.className = 'beam3-step-state'
    chip.textContent = s.glyph || s.state
    const label = document.createElement('button')
    label.type = 'button'
    label.className = 'beam3-step-label beam3-deeplink'
    label.dataset.target = s.target || s.id
    label.textContent = getMessage(s.key, undefined, s.label || STEP_FALLBACKS[s.id] || s.id)
    label.addEventListener('click', () => deepLink(s.target === 'transfer' ? 'transferRoleSend' : (RAIL_TARGETS[s.target] || s.target)))
    li.appendChild(chip)
    li.appendChild(label)
    host.appendChild(li)
  }
}

/** The readiness rows — the tri-state glyphs, the inline fix (F5/F2). */
function renderReadiness(rows) {
  const host = $('beam3ReadinessRows')
  if (!host || !Array.isArray(rows)) return
  host.textContent = ''
  for (const r of rows) {
    const li = document.createElement('li')
    li.className = `beam3-ready-row ${r.state === 'done' ? 'ok' : r.state === 'fail' ? 'bad' : 'pend'}`
    li.dataset.readyRow = r.id
    const mark = document.createElement('span')
    mark.className = 'beam3-ready-mark'
    mark.textContent = r.glyph
    const text = document.createElement('span')
    text.textContent = getMessage(r.key, undefined, r.fallback)
    li.appendChild(mark)
    li.appendChild(text)
    if (r.state !== 'done' && r.fix) {
      const fix = document.createElement('button')
      fix.className = 'btn btn-outline btn-sm beam3-ready-fix'
      fix.type = 'button'
      fix.textContent = getMessage(r.fix.key, undefined, r.fix.fallback || 'Fix')
      fix.addEventListener('click', async () => {
        await runFix(r.fix.action)
      })
      li.appendChild(fix)
    }
    host.appendChild(li)
  }
}

/** The ONE fix dispatcher (F6): every fix navigates to its action area. */
async function runFix(action) {
  if (action === 'open-cloud-sync') {
    // the ONE code path (R136-F3): the fixed Open settings destination —
    // options.html#sync, the Cloud Sync context the button names
    const btn = $('transferOpenSettings') || $('beam3DrawerSettings')
    if (btn) btn.click()
    return
  }
  if (action === 'show-intent') {
    deepLink('transferRoleSend')
    return
  }
  if (action === 'show-pairing') {
    userExpandedFallback = true // an explicit fix is an explicit user intent (F7)
    const zone = $('transferManualZone')
    if (zone) zone.open = true
    deepLink('beam3PairCard')
    if (!lastSignal) {
      // the pairing card needs a signal — declare the intent if none exists
      const res = await send({ type: 'TRANSFER_BEAM3_INTENT', role: 'receive' })
      if (res && res.ok) {
        lastSessionId = res.sessionId
        lastSignal = res.signal || null
        renderFromProjection(res.handshake)
        renderPairing({ signalText: res.signalText, signalWords: res.signalWords })
      }
    }
    return
  }
  if (action === 'open-diagnostics') {
    openDrawer(true)
    return
  }
  if (action === 'reload-surface') {
    try { location.reload() } catch { /* the user can reload manually */ }
    return
  }
  if (action === 'regenerate') {
    regenerate()
    return
  }
  if (action === 'resume' || action === 'retry') {
    pollOnce()
  }
}

/** The prose lines: the live search counter, the slow path, the stall, the typed failure. */
function renderProse(prose) {
  const search = $('beam3Searching')
  if (search) {
    if (prose && prose.search) {
      search.hidden = false
      const secs = String((prose.search.fallback.match(/…\s*(\d+)s/) || [])[1] || '0')
      search.textContent = getMessage('hsProseSearching', [secs], prose.search.fallback)
    } else {
      search.hidden = true
      search.textContent = ''
    }
  }
  const stall = $('beam3Stall')
  if (stall) {
    if (prose && prose.stall) {
      stall.hidden = false
      stall.textContent = getMessage('hsProseStall', undefined, prose.stall.fallback)
    } else if (prose && prose.latency) {
      stall.hidden = false
      stall.textContent = getMessage('hsProseSlow', undefined, prose.latency.fallback)
    } else if (prose && prose.failed) {
      stall.hidden = false
      const reason = String((prose.failed.fallback.match(/Stopped: ([^—]+) —/) || [])[1] || (lastProjection && lastProjection.reason) || 'failed')
      stall.textContent = getMessage('hsProseFailed', [reason.trim()], prose.failed.fallback)
    } else {
      stall.hidden = true
      stall.textContent = ''
    }
  }
}

/** The diagnostics drawer (F8): the hops + identity + Open settings; opens ITSELF only on anomaly. */
function openDrawer(force) {
  const d = $('beam3Drawer')
  if (!d) return
  if (force) d.open = true
}

function renderDrawer(drawer) {
  const d = $('beam3Drawer')
  if (!d || !drawer) return
  const host = $('beam3DrawerHops')
  if (host) {
    host.textContent = ''
    for (const h of drawer.hops || []) {
      const li = document.createElement('li')
      li.className = `beam3-hop beam3-hop-${h.state}`
      li.dataset.hop = h.name
      const mark = document.createElement('span')
      mark.className = 'beam3-ready-mark'
      mark.textContent = h.glyph
      const text = document.createElement('span')
      text.textContent = `${h.name}${h.detail ? ` — ${h.detail}` : ''}`
      li.appendChild(mark)
      li.appendChild(text)
      if (h.state === 'fail' && h.fix) {
        const fix = document.createElement('button')
        fix.className = 'btn btn-outline btn-sm beam3-ready-fix'
        fix.type = 'button'
        fix.textContent = getMessage(h.fix.key, undefined, h.fix.fallback || 'Fix')
        fix.addEventListener('click', () => runFix(h.fix.action))
        li.appendChild(fix)
      }
      host.appendChild(li)
    }
  }
  const identity = $('beam3DrawerIdentity')
  if (identity && drawer.identity) identity.textContent = drawer.identity
  if (drawer.openOnLoad) d.open = true // the anomaly promotion — the ONLY self-open (F8)
}

/** THE SINGLE-WRITER RENDER: everything from one projection (F2). */
function renderFromProjection(v) {
  if (!v) return
  lastProjection = v
  renderReadiness(v.rows)
  renderSteps(v.steps)
  renderProse(v.prose)
  renderDrawer(v.drawer)
  const connect = $('beam3CodesConnect')
  if (connect) connect.hidden = !v.buttons.codesMatchConnect
  // the fallback decision (F7): auto-collapse when a better plane connects —
  // a REVERSIBLE layout state; the user's explicit reopen wins
  const zone = $('transferManualZone')
  if (zone && v.fallback) {
    if (v.fallback.collapsedByDefault && !userExpandedFallback) {
      zone.open = false
      const note = $('beam3FallbackNote')
      if (note) {
        note.hidden = false
        note.textContent = getMessage('beam3FallbackCollapsed', undefined, `Manual fallback collapsed — ${v.fallback.reason}.`)
      }
    }
  }
  const reopen = $('beam3FallbackReopen')
  if (reopen) reopen.hidden = !(v.fallback && v.fallback.collapsedByDefault)
}

/** The pairing card — the signal in full + validity + regenerate + THE ANSWER (§4.2). */
function renderPairing(res) {
  const card = $('beam3PairCard')
  if (!card) return
  if (!res || (!res.signalText && !res.paired && !res.mySignalText)) {
    card.hidden = true
    return
  }
  card.hidden = false
  if (res.signalText) {
    const mine = $('beam3SignalMine')
    if (mine) mine.value = res.signalText
    const words = $('beam3SignalWords')
    if (words) words.textContent = res.signalWords || getMessage('beam3SignalValidity', undefined, 'valid until used, or 24 hours')
  }
  // the ANSWER box (the two-way protocol): exists the instant the open lands
  if (res.answerText) {
    const ans = $('beam3AnswerMine')
    if (ans) ans.value = res.answerText
    const aw = $('beam3AnswerWords')
    if (aw) aw.textContent = res.answerWords || 'Now copy this answer back to the first device.'
    const ansRow = $('beam3AnswerRow')
    if (ansRow) ansRow.hidden = false
  } else if (res.mySignalText) {
    const ansRow = $('beam3AnswerRow')
    if (ansRow) ansRow.hidden = true
  }
  if (res.paired) {
    const peerEl = $('beam3PeerName')
    if (peerEl) peerEl.textContent = (res.peer && (res.peer.label || res.peer.id)) || '—'
    const state = $('beam3PairState')
    if (state) state.textContent = getMessage('beam3PairPaired', undefined, 'Paired — compare the 4×4 code on both screens, then press Codes match — connect.')
  }
}

/** The typed refusals (the expiry terminal + regenerate, R136-F1). */
function renderRefusal(res) {
  const el = $('beam3Refusal')
  if (!el) return
  if (!res || res.ok) {
    el.hidden = true
    return
  }
  el.hidden = false
  el.textContent = res.words || 'The signal could not be opened.'
  el.dataset.terminal = res.terminal || 'invalid'
}

async function copySignal() {
  const box = $('beam3SignalMine')
  if (!box || !box.value) return
  try {
    await navigator.clipboard.writeText(box.value)
    const st = $('beam3CopyState')
    if (st) st.textContent = getMessage('beam3SignalCopied', undefined, 'Copied — carry it to the other device; it stays valid until used, or 24 hours.')
    const j = await send({ type: 'TRANSFER_BEAM3_STATUS' })
    if (j && j.ok && j.handshake) renderFromProjection(j.handshake)
  } catch {
    box.select()
    try { document.execCommand('copy') } catch { /* the box is selectable — the user can still copy */ }
  }
}

/** THE ANSWER's copy (§4.2 step 2→3): the return path stated in plain copy. */
async function copyAnswer() {
  const box = $('beam3AnswerMine')
  if (!box || !box.value) return
  try {
    await navigator.clipboard.writeText(box.value)
    const st = $('beam3AnswerState')
    if (st) st.textContent = getMessage('beam3AnswerCopied', undefined, 'Answer copied — carry it back to the first device and paste it there; the transfer code appears on both screens.')
  } catch {
    box.select()
    try { document.execCommand('copy') } catch { /* the box is selectable */ }
  }
}

/**
 * OPEN (the ONE paste door — the engine classifies): a peer's signal →
 * PAIRED + the answer exists; the peer's answer → CONNECTED deterministically
 * (the no-redo law — 'Answer applied' always continues, §4.2).
 */
async function openPasted() {
  const box = $('beam3SignalPaste')
  if (!box) return
  const text = String(box.value || '').trim()
  const res = await send({ type: 'TRANSFER_BEAM3_OPEN_SIGNAL', text })
  renderRefusal(res)
  if (res && res.ok) {
    lastSessionId = res.sessionId || lastSessionId
    renderFromProjection(res.handshake)
    renderPairing(res)
    if (res.idempotent) {
      const st = $('beam3PairState')
      if (st) st.textContent = getMessage('beam3PairAlready', undefined, 'Already paired with this signal — nothing was repeated; the journey continues below.')
    }
    if (res.connected) {
      const st = $('beam3PairState')
      if (st) st.textContent = getMessage('beam3PairConnected', undefined, 'Connected — pick the file and press Send (sending is the last step), or await their offer below.')
    }
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
    schedule(1500)
  }
}

/** CODES MATCH — CONNECT (§4.2 step 4): the deterministic button. */
async function codesMatchConnect() {
  const res = await send({ type: 'TRANSFER_BEAM3_CODES_MATCH' })
  if (res && res.ok) {
    renderFromProjection(res.handshake)
    const st = $('beam3PairState')
    if (st) st.textContent = getMessage('beam3PairConnected', undefined, 'Connected — pick the file and press Send (sending is the last step), or await their offer below.')
    schedule(1500)
  }
}

async function regenerate() {
  const res = await send({ type: 'TRANSFER_BEAM3_REGENERATE', previous: lastSignal || null })
  if (res && res.ok) {
    lastSignal = res.signal
    const mine = $('beam3SignalMine')
    if (mine) mine.value = res.signalText
    const words = $('beam3SignalWords')
    if (words) words.textContent = res.signalWords || ''
    const st = $('beam3CopyState')
    if (st) st.textContent = getMessage('beam3SignalRegenerated', undefined, 'Fresh signal created — the old one simply rests; nothing in flight was touched.')
  }
}

/** INTENT (R136-F4): Send or Receive arms availability automatically. */
async function declareIntent(role) {
  const res = await send({ type: 'TRANSFER_BEAM3_INTENT', role })
  const confirmEl = $('beam3ArmConfirm')
  if (confirmEl) {
    confirmEl.hidden = false
    confirmEl.textContent = res && res.armed
      ? getMessage('beam3ArmDone', undefined, 'Availability armed automatically — devices on your chain can see this device for 10 minutes.')
      : getMessage('beam3ArmFailed', undefined, 'Availability could not arm (unlock the vault first) — you can arm it manually in Receive.')
  }
  if (res && res.ok) {
    lastSessionId = res.sessionId
    lastSignal = res.signal || null
    // the SINGLE-WRITER render: the projection carries everything
    renderFromProjection(res.handshake)
    renderPairing({ signalText: res.signalText, signalWords: res.signalWords })
    const cont = $('beam3PairedCard')
    if (cont) cont.hidden = true
  }
}

/** The arm strip's instant Stop (R136-F4's "instant Stop"). */
async function stopAvailability() {
  await send({ type: 'TRANSFER_DISABLE_AVAILABILITY' })
  const confirmEl = $('beam3ArmConfirm')
  if (confirmEl) confirmEl.textContent = getMessage('beam3ArmStopped', undefined, 'Availability stopped — this device is hidden now.')
}

/** THE FALLBACK REOPEN (F7): the persistent affordance — collapse is never dismissal. */
function reopenFallback() {
  userExpandedFallback = true
  const zone = $('transferManualZone')
  if (zone) zone.open = true
  const note = $('beam3FallbackNote')
  if (note) note.hidden = true
  deepLink('transferManualZone')
}

async function pollOnce() {
  const res = await send({ type: 'TRANSFER_BEAM3_STATUS' })
  if (res && res.ok) {
    // the SINGLE-WRITER render from the poll's projection (F2)
    renderFromProjection(res.handshake)
    if (res.mySignalText) {
      const mine = $('beam3SignalMine')
      if (mine && !mine.value) mine.value = res.mySignalText
    }
    if (res.answerText) {
      const ans = $('beam3AnswerMine')
      if (ans && !ans.value) ans.value = res.answerText
      const ansRow = $('beam3AnswerRow')
      if (ansRow) ansRow.hidden = false
    }
    const card = $('beam3PairCard')
    if (card && res.mySignalText) card.hidden = false
    const live = (res.sessions || []).some((s) => !s.terminal) || (res.handshake && ['ARMED', 'SEARCHING', 'PAIRED'].includes(res.handshake.state))
    schedule(live ? 2000 : 15000)
    return
  }
  schedule(15000)
}

function schedule(ms) {
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = setTimeout(() => { pollOnce().catch(() => schedule(15000)) }, ms)
}

function wire() {
  // intent — BESIDE the legacy role handlers (additions-only)
  $('transferRoleSend')?.addEventListener('click', () => { declareIntent('send') })
  $('transferRoleReceive')?.addEventListener('click', () => { declareIntent('receive') })
  $('beam3SignalCopy')?.addEventListener('click', copySignal)
  $('beam3AnswerCopy')?.addEventListener('click', copyAnswer)
  $('beam3SignalOpen')?.addEventListener('click', openPasted)
  $('beam3CodesConnect')?.addEventListener('click', codesMatchConnect)
  $('beam3SignalRegen')?.addEventListener('click', regenerate)
  $('beam3ArmStop')?.addEventListener('click', stopAvailability)
  $('beam3FallbackReopen')?.addEventListener('click', reopenFallback)
  // the drawer's own Open settings rides the ONE existing handler (F8 relocation)
  $('beam3DrawerSettings')?.addEventListener('click', () => { $('transferOpenSettings')?.click() })
  renderBuildTag()
}

/** Build attribution (R137 §3, the G80 standing order): the Device Transfer
 * surface is SELF-IDENTIFYING — every future capture carries its own
 * version, so the next mirror has honest pixels. ONE element, i18n-free
 * plain render (the version is build metadata, not prose — law 0.11 keeps
 * it equal to BUILD.json and Help→About), appended inside the guided
 * workflow section. No layout redesign (the canonical-UI protection). */
function renderBuildTag() {
  const host = $('beam3Workflow')
  if (!host || $('beam3BuildTag')) return
  let v = ''
  try { v = String(chrome.runtime.getManifest().version || '') } catch { /* non-extension context */ }
  if (!v) return
  const tag = document.createElement('p')
  tag.id = 'beam3BuildTag'
  tag.className = 'card-help beam3-build-tag'
  tag.textContent = `UCrypt Device Transfer — v${v}`
  host.appendChild(tag)
}

try {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
    wire()
    schedule(15000)
  }
} catch { /* never take the legacy page down */ }
