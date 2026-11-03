/**
 * UCrypt — R139 §5 — THE BOND PAGE SUPERVISOR (the ONE writer of the
 * transfer journey).
 *
 * §5.1's law made real at the screen: EVERY rendered journey element —
 * the readiness rows, the glyphs, the prose, the buttons, the step rail,
 * the availability card, the fallback visibility, the diagnostics drawer —
 * derives from ONE projection (projectBond, via the engine's status
 * payload `bond`). The independent journey writers are retired from the
 * surface (the consent basis is the R139 contract §5): the legacy truth
 * strip, the duplicate manual paste zone, and the duplicate availability
 * cluster no longer have canvases on this page; the Beam chrome renders
 * ONLY inside the diagnostics drawer (D6).
 *
 * What this module OWNS (the journey — §5.7's fixed order):
 *   readiness strip → intent actions ('Send a file' | 'Receive') → guide
 *   (collapsible, current step highlighted, every row a deep link) →
 *   manual fallback (ONE paste box, ONE classifier door, replay-idempotent)
 *   → diagnostics drawer (the shared doctor's inline mount, the hops, the
 *   Beam identity, Open settings — the doctor's last resort, never its body).
 *
 * The transport executors (the legacy send/receive cards, the receive
 * modal, the progress cards) stay owned by their sealed supervisors BELOW
 * the journey: the Bond advances from their truth through the worker's
 * transport mirror (one journey machine, whatever the plane).
 *
 * The honest clocks (§5.5): 'Searching… Xs' ticks live (local 1 s
 * interpolation over the machine's measured start); the slow notice fires
 * at budget/2 and the typed terminal at budget×2 — machine law, not copy.
 * Nothing closes without consent: terminals and receipts stay until the
 * user dismisses them.
 */

// R142-A1 CURE (published in r142-claims-audit.json): this import said
// './sync-doctor.js' — from lib/beam3/ that resolves to lib/beam3/sync-doctor.js,
// which does not exist (the file lives at lib/sync-doctor.js). The exact
// R139 supervisor-killer class, alive in the sealed v2.98.0: one wrong
// relative import killed the whole Bond page module graph. Fixed 2026-10-19.
import { runSyncDoctor, SyncDiagnosticsLedger, classifyTokenEvent, TOKEN_OUTCOMES } from '../sync-doctor.js'

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

let lastBondView = null
let lastFetchAt = 0
let pollTimer = null
let tickTimer = null
let userExpandedFallback = false
let userCollapsedGuide = false
const doctorLedger = new SyncDiagnosticsLedger()

/* ═══ THE DEEP-LINK RAIL (§5.7 — every row navigates, never inert text) ═══ */
const RAIL_TARGETS = {
  intent: 'bondIntentRow',
  pair: 'bondPairCard',
  confirm: 'bondConnectReason',
  transfer: 'transferRoleSend',
  verify: 'bondGuideCard',
  done: 'bondGuideCard',
}

function deepLink(targetId) {
  const el = $(targetId)
  if (!el) return
  try {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el.focus({ preventScroll: true })
    el.classList.remove('bond-flash')
    void el.offsetWidth
    el.classList.add('bond-flash')
  } catch { /* the highlight is enhancement; the navigation already happened */ }
}

/* ═══ THE SHARED CONNECTION DOCTOR (§6.4 — the same doctor Cloud Sync uses,
 * mounted INLINE in the drawer: hops test live with pass/fail and per-hop
 * fixes; settings links are the last resort, never the whole body — D5) ═══ */
async function runDoctorInline() {
  const host = $('bondDoctorOut')
  if (host) host.textContent = getMessage('bondDoctorWorking', undefined, 'Running the connection doctor…') + ' ' + getMessage('bondDoctorHint', undefined, 'The doctor tests auth, token, reachability, and the relay read — each with its fix.')
  const storage = chrome.storage && chrome.storage.local
  const keys = await storage.get(['ucrypt:sync:cloud'])
  const cloud = keys['ucrypt:sync:cloud'] || null
  const probes = {
    auth: async () => {
      if (!cloud || !cloud.connected) return { ok: false, detail: 'No cloud storage is connected yet.', next: 'Press Connect your cloud and sign in.' }
      return { ok: true, detail: `A cloud transport is connected (${String(cloud.provider || 'provider').slice(0, 24)}).` }
    },
    token: async () => {
      if (!cloud || !cloud.connected) return { ok: false, detail: 'Without a connected transport there is no token to check.', next: 'Connect the cloud storage first.' }
      const outcome = classifyTokenEvent({ httpStatus: cloud.lastStatus || 200 })
      if (outcome.outcome === TOKEN_OUTCOMES.REAUTH_REQUIRED) return { ok: false, detail: outcome.why, next: outcome.next, repair: 'Sign in again from the cloud card in Sync & devices.', ownerFix: true }
      return { ok: true, detail: `The last sync step ended as “${outcome.outcome}”.` }
    },
    reachability: async () => {
      const base = String((cloud && cloud.vaultUrl) || '').replace(/\/[^/]*$/, '/')
      if (!base) return { ok: false, detail: 'No provider base URL is known yet.', next: 'Connect the cloud storage first.' }
      const t0 = Date.now()
      try {
        await fetch(base, { method: 'HEAD', mode: 'cors' })
        doctorLedger.record({ phase: 'doctor:reachability', tokenState: 'pass', httpStatus: 200, latencyMs: Date.now() - t0, errorClass: 'pass' })
        return { ok: true, detail: `The provider answered in ${Date.now() - t0} ms.` }
      } catch {
        doctorLedger.record({ phase: 'doctor:reachability', tokenState: 'fail', httpStatus: null, latencyMs: Date.now() - t0, errorClass: 'network' })
        return { ok: false, detail: 'The provider did not answer the HEAD probe (offline, blocked, or a captive portal).', next: 'Check the network; the sync queue keeps every write meanwhile.' }
      }
    },
    mailbox: async () => {
      // the transfer-context probe: the availability poll IS the relay read
      const res = await send({ type: 'TRANSFER_BEAM3_STATUS' })
      const hopRow = res && res.ok && res.bond && Array.isArray(res.bond.drawer.hops)
        ? res.bond.drawer.hops.find((h) => h.name === 'relayRead')
        : null
      if (hopRow && hopRow.state === 'fail') return { ok: false, detail: `The relay read failed: ${hopRow.detail || 'unavailable'}.`, next: 'Check your cloud connection, or pair by code below.' }
      if (hopRow && hopRow.state === 'done') return { ok: true, detail: 'The relay read answered — your cloud can carry the sealed chunks.' }
      return { ok: false, detail: 'The relay read has not run yet.', next: 'Arm availability (or press Send a file) and the doctor re-tests it.' }
    },
  }
  const steps = await runSyncDoctor(probes, { ledger: doctorLedger })
  if (host) {
    host.textContent = ''
    for (const s of steps) {
      const li = document.createElement('li')
      li.className = `bond-hop bond-hop-${s.status === 'pass' ? 'done' : 'fail'}`
      const mark = document.createElement('span')
      mark.className = 'bond-ready-mark'
      mark.textContent = s.status === 'pass' ? '✓' : '✗'
      const text = document.createElement('span')
      text.textContent = `${s.key} — ${s.why || s.detail || ''}${s.next ? ` → ${s.next}` : ''}`
      li.appendChild(mark)
      li.appendChild(text)
      host.appendChild(li)
    }
  }
  // the failing hop's fix affordance opens the drawer for you (the anomaly law)
  const d = $('bondDrawer')
  if (d && steps.some((s) => s.status === 'fail')) d.open = true
  return steps
}

/* ═══ THE RENDERERS — everything from the ONE projection ═══ */

/** R140 F2 — THE HEADER STATUS (Table S, the single writer): the CEO's
 * command — the live connection status where the motto recited. Derived in
 * projectBond so it can never contradict the glyph, the guide, or the drawer. */
function renderHeaderStatus(h) {
  const el = $('bondHeaderStatus')
  if (!el || !h) return
  el.textContent = getMessage(h.key, h.subs, h.fallback)
  el.dataset.tone = h.tone || ''
}

function renderRows(rows) {
  const host = $('bondReadinessRows')
  if (!host || !Array.isArray(rows)) return
  host.textContent = ''
  for (const r of rows) {
    const li = document.createElement('li')
    li.className = `bond-ready-row ${r.state === 'done' ? 'ok' : r.state === 'fail' ? 'bad' : 'pend'}`
    li.dataset.readyRow = r.id
    const mark = document.createElement('span')
    mark.className = 'bond-ready-mark'
    mark.textContent = r.glyph // glyph and text: the SAME fact rendered together
    const text = document.createElement('span')
    text.textContent = getMessage(r.key, r.subs, r.fallback)
    li.appendChild(mark)
    li.appendChild(text)
    if (r.state !== 'done' && r.fix) {
      const fix = document.createElement('button')
      fix.className = 'btn btn-outline btn-sm bond-ready-fix'
      fix.type = 'button'
      fix.textContent = getMessage(r.fix.key, undefined, r.fix.fallback || 'Fix')
      fix.addEventListener('click', () => runFix(r.fix.action))
      li.appendChild(fix)
    }
    host.appendChild(li)
  }
}

function renderAvailability(a) {
  const card = $('bondAvailCard')
  if (!card || !a) return
  const countdown = $('bondAvailCountdown')
  if (countdown) {
    countdown.hidden = !a.armed
    countdown.textContent = a.armed ? `${a.minutesRemaining} ${getMessage('bondAvailCountdownWord', undefined, 'minutes left')}` : ''
  }
  const stateEl = $('bondAvailState')
  if (stateEl) {
    stateEl.textContent = getMessage(a.key, a.subs, a.fallback)
    stateEl.classList.toggle('bond-avail-on', !!a.armed)
    stateEl.classList.toggle('bond-avail-off', !a.armed)
  }
  const word = $('bondAvailWord')
  if (word) {
    word.textContent = a.armed ? getMessage('bondAvailTrue', undefined, 'True') : getMessage('bondAvailWordOff', undefined, 'Off')
    word.classList.toggle('bond-avail-true', !!a.armed)
  }
  const stop = $('bondAvailStop')
  if (stop) stop.hidden = !a.canStop
  const arm = $('bondAvailArm')
  if (arm) arm.hidden = !a.canArm
}

function renderSteps(steps) {
  const host = $('bondSteps')
  if (!host || !Array.isArray(steps)) return
  host.textContent = ''
  for (const s of steps) {
    const li = document.createElement('li')
    li.className = `bond-step bond-step-${s.state}`
    li.dataset.step = s.id
    const chip = document.createElement('span')
    chip.className = 'bond-step-state'
    chip.textContent = s.glyph
    const label = document.createElement('button')
    label.type = 'button'
    label.className = 'bond-step-label bond-deeplink'
    label.dataset.target = s.target
    label.textContent = getMessage(s.key, undefined, s.label)
    label.addEventListener('click', () => deepLink(RAIL_TARGETS[s.target] || s.target))
    li.appendChild(chip)
    li.appendChild(label)
    host.appendChild(li)
  }
}

/** ONE typed notice line: the slow clock, the typed terminal, the friendly
 * noop, the declined/cancelled/integrity rows — each with its fix.
 * R140 §6.4: the sender's HONEST MAILBOX CLAIM rides the same line — the
 * receipt (written/fetched/pending-proof) replaces the generic waiting
 * words; the undeliverable truth shows when no receipt exists. */
function renderProse(prose, clock, mailbox) {
  const search = $('bondSearchLine')
  if (search) {
    if (prose && prose.search && clock) {
      search.hidden = false
      // the live counter: local interpolation over the machine's measured start
      const drift = Math.max(0, Math.floor((Date.now() - lastFetchAt) / 1000))
      const secs = (clock.waitSeconds || 0) + drift
      search.textContent = getMessage('bondProseSearching', [String(secs)], `Searching for the other device… ${secs}s`)
    } else {
      search.hidden = true
      search.textContent = ''
    }
  }
  const notice = $('bondNotice')
  if (!notice) return
  const mailboxLine = mailbox && mailbox.claim ? mailbox : null
  const line = (prose && (prose.terminal || prose.slow || prose.noop || prose.declined || prose.cancelled || prose.integrity))
    || mailboxLine
    || (prose && (prose.waiting || prose.transferring || prose.verified || prose.offerIn))
  if (!line) {
    notice.hidden = true
    notice.textContent = ''
    notice.dataset.kind = ''
    return
  }
  notice.hidden = false
  notice.dataset.kind = prose && prose.terminal ? 'terminal' : 'notice'
  notice.className = `bond-notice ${prose && prose.terminal ? 'bond-notice-terminal' : 'bond-notice-soft'}`
  notice.textContent = getMessage(line.key, line.subs, line.fallback)
  if (prose && prose.terminal && prose.terminal.pending) {
    notice.textContent += ' ' + getMessage('bondTerminalPendingHint', undefined, 'Still trying in the background — we will tell you when it lands.')
  }
  notice.dataset.fix = (prose && prose.terminal && prose.terminal.fix) || ''
}

/** THE GATED CONNECT (§5.4): visible in the journey's pairing half; DISABLED
 * with a live reason whenever prerequisites are unmet; enabled → every click
 * lands CONNECTED or a typed failure. A dead click is unrepresentable. */
function renderConnect(buttons) {
  const wrap = $('bondConnectRow')
  if (!wrap || !buttons || !buttons.connect) return
  const c = buttons.connect
  wrap.hidden = !c.visible
  const btn = $('bondConnect')
  if (btn) {
    btn.disabled = !c.enabled
    btn.textContent = getMessage('beam3CodesConnect', undefined, 'Codes match — connect')
  }
  const reason = $('bondConnectReason')
  if (reason) {
    const showReason = c.visible
    reason.hidden = !showReason
    if (showReason) reason.textContent = c.enabled
      ? getMessage('bondConnectEnabledHint', undefined, 'The codes match — press connect to seal the bond.')
      : getMessage(c.reasonKey, undefined, c.reason)
  }
}

function renderFallback(fallback) {
  const zone = $('bondFallbackZone')
  if (!zone || !fallback) return
  if (fallback.collapsedByDefault && !userExpandedFallback) {
    zone.open = false
    const note = $('bondFallbackNote')
    if (note) {
      note.hidden = false
      note.textContent = getMessage('beam3FallbackCollapsed', undefined, `Manual fallback collapsed — ${fallback.reason}.`)
    }
  }
  const reopen = $('bondFallbackReopen')
  if (reopen) reopen.hidden = !(fallback.collapsedByDefault && !userExpandedFallback)
}

function renderDrawer(drawer) {
  const d = $('bondDrawer')
  if (!d || !drawer) return
  const host = $('bondDrawerHops')
  if (host) {
    host.textContent = ''
    for (const h of drawer.hops || []) {
      const li = document.createElement('li')
      li.className = `bond-hop bond-hop-${h.state}`
      li.dataset.hop = h.name
      const mark = document.createElement('span')
      mark.className = 'bond-ready-mark'
      mark.textContent = h.glyph
      const text = document.createElement('span')
      text.textContent = `${h.name}${h.detail ? ` — ${h.detail}` : ''}`
      li.appendChild(mark)
      li.appendChild(text)
      if (h.state === 'fail' && h.fix) {
        const fix = document.createElement('button')
        fix.className = 'btn btn-outline btn-sm bond-ready-fix'
        fix.type = 'button'
        fix.textContent = getMessage(h.fix.key, undefined, h.fix.fallback || 'Fix')
        fix.addEventListener('click', () => runFix(h.fix.action))
        li.appendChild(fix)
      }
      host.appendChild(li)
    }
  }
  const identity = $('bondDrawerIdentity')
  if (identity) {
    identity.hidden = !drawer.identity
    identity.textContent = drawer.identity || ''
  }
  if (drawer.openOnLoad) d.open = true // the anomaly promotion — the ONLY self-open
}

/** THE SINGLE-WRITER RENDER (§5.1): everything from one projection. */
function renderBond(v) {
  if (!v) return
  lastBondView = v
  lastFetchAt = Date.now()
  renderHeaderStatus(v.headerStatus) // R140 F2 — the header speaks the connection truth
  renderRows(v.rows)
  renderAvailability(v.availability)
  renderSteps(v.steps)
  renderProse(v.prose, v.clock, v.mailbox)
  renderConnect(v.buttons)
  renderFallback(v.fallback)
  renderDrawer(v.drawer)
  const guide = $('bondGuideCard')
  if (guide) guide.hidden = userCollapsedGuide
  const stopTop = $('bondAvailStop')
  if (stopTop) stopTop.hidden = !(v.availability && v.availability.canStop)
}

/* ═══ THE ACTIONS (the ONE door per act) ═══ */

async function runFix(action) {
  if (action === 'open-cloud-sync') {
    const btn = $('transferOpenSettings')
    if (btn) btn.click()
    return
  }
  if (action === 'show-intent') { deepLink('bondIntentRow'); return }
  if (action === 'show-pairing' || action === 'show-fallback') {
    userExpandedFallback = true
    const zone = $('bondFallbackZone')
    if (zone) zone.open = true
    deepLink('bondPairCard')
    return
  }
  if (action === 'open-diagnostics') {
    const d = $('bondDrawer')
    if (d) d.open = true
    return
  }
  if (action === 'open-doctor') {
    const d = $('bondDrawer')
    if (d) d.open = true
    await runDoctorInline()
    return
  }
  if (action === 'regenerate') { await regenerate(); return }
  if (action === 'resume' || action === 'retry') { await pollOnce(); return }
  if (action === 'reload-surface') { try { location.reload() } catch { /* manual */ } }
}

async function declareIntent(role) {
  const res = await send({ type: 'TRANSFER_BEAM3_INTENT', role })
  const confirmEl = $('bondArmConfirm')
  if (confirmEl) {
    confirmEl.hidden = false
    confirmEl.textContent = res && res.armed
      ? getMessage('bondArmDone', undefined, 'Availability armed automatically — this device is visible to your chain for 10 minutes.')
      : getMessage('bondArmFailed', undefined, 'Availability could not arm (unlock the vault first) — you can arm it on the availability card.')
  }
  if (res && res.ok && res.bond) renderBond(res.bond)
  schedule(2000)
}

async function openPasted() {
  const box = $('bondSignalPaste')
  if (!box) return
  const text = String(box.value || '').trim()
  if (!text) return
  const res = await send({ type: 'TRANSFER_BEAM3_OPEN_SIGNAL', text })
  if (res && res.ok && res.bond) {
    renderBond(res.bond)
    if (res.answerText) {
      const ans = $('bondAnswerMine')
      if (ans) ans.value = res.answerText
      const ansRow = $('bondAnswerRow')
      if (ansRow) ansRow.hidden = false
    }
    if (res.replayNoop) {
      const st = $('bondPairState')
      if (st) st.textContent = getMessage('bondProseReplayNoop', undefined, 'This signal is already active — here is where you are.') + ' ' + getMessage('bondNoopHint', undefined, 'Nothing was repeated — the journey continues below.')
    } else if (res.paired) {
      const st = $('bondPairState')
      if (st) st.textContent = getMessage('bondPairPaired', undefined, 'Paired — copy the answer back to the other device; the 4×4 code shows on both screens.')
    }
    schedule(2000)
  } else {
    // the typed refusal — genuinely foreign/stale/tampered records only (D7)
    const notice = $('bondNotice')
    if (notice) {
      notice.hidden = false
      notice.className = 'bond-notice bond-notice-terminal'
      notice.dataset.kind = 'terminal'
      notice.textContent = (res && res.words) || getMessage('beam3RefusalInvalid', undefined, 'This is not a UCrypt signal — ask the other device to copy its signal again.')
      notice.dataset.fix = res && res.regenerate ? 'regenerate' : ''
    }
  }
}

async function copySignal() {
  const box = $('bondSignalMine')
  if (!box || !box.value) return
  try {
    await navigator.clipboard.writeText(box.value)
    const st = $('bondCopyState')
    if (st) st.textContent = getMessage('beam3SignalCopied', undefined, 'Copied — carry it to the other device; it stays valid until used, or 24 hours.')
  } catch {
    box.select()
    try { document.execCommand('copy') } catch { /* selectable */ }
  }
}

async function copyAnswer() {
  const box = $('bondAnswerMine')
  if (!box || !box.value) return
  try {
    await navigator.clipboard.writeText(box.value)
    const st = $('bondAnswerState')
    if (st) st.textContent = getMessage('beam3AnswerCopied', undefined, 'Answer copied — carry it back to the first device and paste it there.')
  } catch {
    box.select()
    try { document.execCommand('copy') } catch { /* selectable */ }
  }
}

async function codesMatchConnect() {
  const res = await send({ type: 'TRANSFER_BEAM3_CODES_MATCH' })
  if (res && res.ok && res.bond) {
    renderBond(res.bond)
    const st = $('bondPairState')
    if (st && res.connected) st.textContent = getMessage('beam3PairConnected', undefined, 'Connected — pick the file and press Send (sending is the last step), or await their offer below.')
    schedule(2000)
  }
}

async function regenerate() {
  const res = await send({ type: 'TRANSFER_BEAM3_REGENERATE', previous: null })
  if (res && res.ok) {
    const mine = $('bondSignalMine')
    if (mine) mine.value = res.signalText || ''
    const st = $('bondCopyState')
    if (st) st.textContent = getMessage('beam3SignalRegenerated', undefined, 'Fresh signal created — the old one simply rests; nothing in flight was touched.')
  }
}

async function armAvailability() {
  await send({ type: 'TRANSFER_ENABLE_AVAILABILITY', minutes: 10, label: '' })
  await pollOnce()
}

async function stopAvailability() {
  await send({ type: 'TRANSFER_DISABLE_AVAILABILITY' })
  const confirmEl = $('bondArmConfirm')
  if (confirmEl) {
    confirmEl.hidden = false
    confirmEl.textContent = getMessage('beam3ArmStopped', undefined, 'Availability stopped — this device is hidden now.')
  }
  await pollOnce()
}

async function dismissTerminal() {
  await send({ type: 'TRANSFER_BEAM3_HS_RESET' })
  await pollOnce()
}

function reopenFallback() {
  userExpandedFallback = true
  const zone = $('bondFallbackZone')
  if (zone) zone.open = true
  const note = $('bondFallbackNote')
  if (note) note.hidden = true
  deepLink('bondFallbackZone')
}

/* ═══ THE POLL (the adaptive cadence + the 1 s live tick) ═══ */

async function pollOnce() {
  const res = await send({ type: 'TRANSFER_BEAM3_STATUS' })
  if (res && res.ok && res.bond) {
    renderBond(res.bond)
    if (res.mySignalText) {
      const mine = $('bondSignalMine')
      if (mine && !mine.value) mine.value = res.mySignalText
    }
    const live = ['ARMED', 'WAITING_FOR_PEER', 'SIGNAL_EXCHANGED', 'CODE_SHOWN', 'TRANSFERRING'].includes(res.bond.state)
    schedule(live ? 2000 : 15000)
    return
  }
  schedule(15000)
}

function schedule(ms) {
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = setTimeout(() => { pollOnce().catch(() => schedule(15000)) }, ms)
}

/** the 1 s tick: the live counter only re-renders the clock line (never a
 * second writer — the same projection, the same fact, interpolated). */
function startTick() {
  if (tickTimer) clearInterval(tickTimer)
  tickTimer = setInterval(() => {
    if (!lastBondView || !lastBondView.prose || !lastBondView.prose.search) return
    const search = $('bondSearchLine')
    if (!search || search.hidden) return
    const drift = Math.max(0, Math.floor((Date.now() - lastFetchAt) / 1000))
    const secs = (lastBondView.clock.waitSeconds || 0) + drift
    search.textContent = getMessage('bondProseSearching', [String(secs)], `Searching for the other device… ${secs}s`)
  }, 1000)
}

function wire() {
  $('transferRoleSend')?.addEventListener('click', () => { declareIntent('send') })
  $('transferRoleReceive')?.addEventListener('click', () => { declareIntent('receive') })
  $('bondSignalCopy')?.addEventListener('click', copySignal)
  $('bondAnswerCopy')?.addEventListener('click', copyAnswer)
  $('bondSignalOpen')?.addEventListener('click', openPasted)
  $('bondConnect')?.addEventListener('click', codesMatchConnect)
  $('bondSignalRegen')?.addEventListener('click', regenerate)
  $('bondAvailArm')?.addEventListener('click', armAvailability)
  $('bondAvailStop')?.addEventListener('click', stopAvailability)
  $('bondFallbackReopen')?.addEventListener('click', reopenFallback)
  $('bondDoctorRun')?.addEventListener('click', () => { runDoctorInline().catch(() => {}) })
  $('bondDismiss')?.addEventListener('click', dismissTerminal)
  const dismissBtn = $('bondDismiss')
  if (dismissBtn) dismissBtn.title = getMessage('bondResetHint', undefined, 'The receipt stays until you dismiss it — nothing closes by itself.')
  $('bondGuideToggle')?.addEventListener('click', () => {
    userCollapsedGuide = !userCollapsedGuide
    const guide = $('bondGuideCard')
    if (guide) guide.hidden = userCollapsedGuide
  })
}

try {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
    wire()
    startTick()
    schedule(15000)
    pollOnce().catch(() => {})
    // R140 §6.3 — the focus law: a focus event polls AGAIN immediately
    try { window.addEventListener('focus', () => { pollOnce().catch(() => {}) }) } catch { /* enhancement */ }
  }
} catch { /* never take the page down */ }
