/**
 * UCrypt — R76 Part E "Secure Direct Device Transfer" — TRANSFER WINDOW PAGE
 * (lib/transfer/page.js). New in v2.42.14.
 *
 * Controller for transfer.html. The WORKER (lib/transfer/worker.js) owns ALL
 * transfer key material — this page exchanges runtime messages with it and
 * handles only non-secret artifacts: device lists, offers, fingerprints,
 * SDP/ICE transport metadata, progress and the one-time file export.
 *
 * Honesty gates implemented here (owner order):
 *   - B5: an incoming-offer decision card is NEVER auto-dismissed. No timer
 *     removes it while it awaits a decision; the 5 s poll MERGES by offerId
 *     and only updates non-decision fields. A vault lock cancels pending
 *     cards with a truthful "Cancelled — vault locked." state.
 *   - The receiver ALWAYS explicitly accepts (no auto-accept, no auto-open,
 *     no auto-execute, no auto-resume).
 *   - NO relay: RTCPeerConnection is created with { iceServers: [] } — no
 *     STUN/TURN server is configured, so ICE collects host candidates only
 *     (direct/LAN reachability) and NOTHING is ever sent to a third party.
 *   - The MV3 keepalive note: the 5 s poll interval ALSO serves as a worker
 *     keepalive — every poll wakes the transfer router while the window is
 *     open, so the availability window behaves predictably.
 *   - File export is ONE-SHOT (worker enforces it) and the Blob reference is
 *     wiped right after the a[download] click.
 *
 * Signaling transport: this release defaults to the cloud rendezvous (the
 * user's own WebDAV storage, separate 'ucrypt-rendezvous-v1' namespace). The
 * worker's TRANSFER_STATUS carries no transport field in v2.42.14, so cloud
 * is attempted first and ANY publish failure falls back to the manual
 * copy/paste surface below — which is ALWAYS available. The fallback is
 * honest: the exact sealed record (the same bytes the cloud path would have
 * written) is staged for copying, nothing more.
 */

import { applyI18n, getMessage } from '../i18n.js'
import { registerBeamExecutor } from '../beam-executor-page.js'
import { bytesToBase64 } from '../crypto.js'
// R145 §5.2 (the G-1 cure, WALL 2) — the embed guard (static import: the
// R142-A3 law prefers static graphs; this is a page, but the discipline holds).
import { embedMode } from '../embed-guard.js'
import { toastLifetime } from '../r145-laws.js' // R145 §4.4 — the G-9 typed lifetimes
// R132 (law 0.47 — THE PASTE-GUIDANCE LAW; the CEO's S2): every pasted
// signal is classified ON PASTE with its typed identity and next action —
// a wrong-order paste is a guided correction, never a silent dead end.
import { classifyPastedSignal, refineForManualBox, PASTE_CLASSES } from '../paste-classify.js'
import {
  SEND_STAGES,
  SEND_TERMINAL_OUTCOMES,
  TRANSFER_STATES,
  evaluateStageWatchdog,
  classifyRoute,
  cleanupPlan,
  terminalResultFor,
} from './lifecycle.js'
import {
  discoveryModel,
  shouldAutoArm,
  armCountdown,
  isSelfPresence,
  manualGuidance,
  manualZonePromotion,
} from './discovery.js'
import {
  openConnectOverlay,
  openJoinOverlay,
} from './connect-overlay.js'
import { getTransport } from '../transports/index.js'

// --- Tiny DOM helpers ---------------------------------------------------------

function $(id) { return document.getElementById(id) }

/** LAW 0.50 (R133, the CEO's modal spec) — THE FILE CODE: a display code
 * derived from the offer's own sha256 (data BOTH sides hold at offer time).
 * First 16 hex chars, grouped 4×4, uppercased — "DA0D 5DEE D9BC 597A". The
 * sender shows it the moment the offer is created; the receiver's decision
 * modal shows the same code — human comparison, zero copying. Pure and
 * exported for the battery (ONETOUCH). */
export function offerDisplayCode(sha256Hex) {
  const hex = String(sha256Hex || '').replace(/[^0-9a-fA-F]/g, '').slice(0, 16).padEnd(16, '0').toUpperCase()
  return hex.replace(/(.{4})(.{4})(.{4})(.{4})/, '$1 $2 $3 $4')
}

function msg(key, subs, fallback) {
  return getMessage(key, subs, fallback)
}

function show(el, on = true) {
  if (!el) return
  el.classList.toggle('hidden', !on)
  if (on) el.removeAttribute('hidden')
  else el.setAttribute('hidden', '')
}

function toast(text, kind = 'info') {
  const el = $('transferToast')
  if (!el) return
  // LAW 0.52 (R133) — the text rides its own span; the ✕ close is always
  // present (an expiring toast still carries the user's own exit).
  const textEl = $('transferToastText')
  if (textEl) textEl.textContent = text
  else el.textContent = text
  el.className = 'transfer-toast' + (kind === 'error' ? ' transfer-toast-error' : '')
  show(el, true)
  clearTimeout(toast._t)
  // R145 §4.4 (the G-9 cure) — THE TYPED LIFETIMES (the whole-area law:
  // the transfer surface obeys the same law options.js obeys): status
  // toasts auto-dismiss at the bounded TOAST_STATUS_MS (6 s, ledgered —
  // the "Pairing code copied" toast that rode three captures and 10+
  // minutes is the exact disease); a consent toast NEVER auto-closes.
  // The ✕ always works in both lifetimes; no timer survives a reload.
  const life = toastLifetime(kind)
  if (life.autoDismissMs != null) {
    toast._t = setTimeout(() => show(el, false), life.autoDismissMs)
  } else {
    toast._t = null // consent: the user owns the close
  }
}

/** Locale time "HH:MM" for an ISO stamp (honest unknown → '—'). */
function fmtTime(iso) {
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return '—'
  try {
    return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch { return '—' }
}

function humanSize(n) {
  const v = Number(n) || 0
  if (v >= 1024 * 1024 * 1024) return (v / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
  if (v >= 1024 * 1024) return (v / (1024 * 1024)).toFixed(1) + ' MB'
  if (v >= 1024) return Math.round(v / 1024) + ' KB'
  return v + ' B'
}

/** Non-secret short form of a deviceId for display. */
function shortId(id) {
  const s = String(id || '')
  return s ? s.slice(0, 12) + '…' : '—'
}

/**
 * R132 (law 0.46 — THE PRESENCE-HONESTY LAW; the CEO's S1): does THIS
 * transport carry a live rendezvous? Read from the worker's status
 * projection (status.rendezvous.available — the R127 capability answer).
 * When the status has not arrived yet the answer is conservative-false:
 * the roster renders the honest UNKNOWN (never a fabricated offline) until
 * the capability truth lands — an undetectable device is never called
 * offline.
 */
function rendezvousAvailableHere() {
  const st = state.status
  return !!(st && st.rendezvous && st.rendezvous.available)
}

function shortSha(hex) {
  const s = String(hex || '')
  return s ? s.slice(0, 16) + '…' : '—'
}

// --- Worker messaging ------------------------------------------------------------

/**
 * Every worker call resolves (never rejects). Errors carry the worker's
 * stable code + userMessageKey so the UI can show truthful localized copy.
 * Payloads are NEVER logged — no keys, no file bytes, no plaintext chunks.
 */
function worker(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (res) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: 'no_worker', userMessageKey: 'transferErrInternal' })
          return
        }
        resolve(res || { ok: false, error: 'no_response', userMessageKey: 'transferErrInternal' })
      })
    } catch (e) {
      console.warn('[UCrypt] Transfer page: message failed:', (e && e.message) || e)
      resolve({ ok: false, error: 'no_worker', userMessageKey: 'transferErrInternal' })
    }
  })
}

/** Turn a failed worker response into an Error carrying the locale key. */
function keyed(res) {
  const e = new Error(String((res && res.error) || 'internal'))
  e.userMessageKey = (res && res.userMessageKey) || 'transferErrInternal'
  e.workerCode = (res && res.error) || 'internal'
  return e
}

/** Localized truthful text for a failure (locale key first, code fallback). */
function errorText(e) {
  if (e && e.userMessageKey) return msg(e.userMessageKey, undefined, errorText.fallbackFor(e))
  return msg('transferErrInternal', undefined, 'Direct transfer hit an unexpected error. Nothing was sent or saved.')
}
errorText.fallbackFor = function (e) {
  const map = {
    locked: 'Vault locked — unlock to use direct transfer.',
    no_sync_code: 'Direct transfer needs a sync chain — set one up first.',
    rendezvous_unavailable: 'The rendezvous storage is unreachable — check the cloud transport, or use manual copy/paste below.',
    over_limit: 'This file is over the 20 MB default limit of this release.',
    hard_cap: 'Files over 100 MB are refused.',
    empty: 'That file has no content.',
    no_session: 'No matching transfer is active on this device.',
  }
  return map[(e && e.workerCode) || 'internal'] || 'Direct transfer hit an unexpected error. Nothing was sent or saved.'
}

// --- Page state -----------------------------------------------------------------

const state = {
  status: null,            // last TRANSFER_STATUS response
  role: null,              // 'send' | 'receive'
  selectedPeerId: null,    // sender: chosen target deviceId
  file: null,              // sender: chosen File object (never logged)
  fileSha: '',             // sender: sha256hex of the chosen file
  pendingOffers: new Map(),// offerId → { offer, el, state }  (B5: never auto-removed while pending)
  activeSend: null,        // { transferId, pc, channel, file, size, totalChunks, stage, terminal, ... }
  activeRecv: null,        // { transferId, offerId, pc, saved }
  manualSignal: '',        // last staged sealed record (base64) for the manual surface
  exporting: false,        // one-shot export guard
  availabilityOwnedHere: false, // R81-F1: availability enabled FROM this window
}

const POLL_MS = 5000
const STATUS_REFRESH_MS = 30000
const CHUNK_BYTES = 16384  // must match the worker's CHUNK_SIZE (transfer plane)
const CHANNEL_LOW_WATER = 128 * 1024 // backpressure: ≤8 frames buffered on the SCTP layer
const GATHER_CAP_MS = 3000  // host candidates gather fast; never hang the flow

/** R128 §3 (the CEO's S5 — the code-congruency mid-transfer): the FAST
 * ANSWER POLL. The 5 s freshness poll is too slow for the one moment the
 * two screens must agree: the receiver shows the code the instant it
 * accepts, while the sender's copy travels by mailbox — at 5 s cadence the
 * sender stared at dashes for up to 5 s (and longer on a quiet rendezvous),
 * reading as broken. While `activeSendAwaitingAnswer` holds, this loop
 * polls every ~1.5 s — the code fields agree within moments of the accept.
 * The loop dies with the flow (handleAnswer + finishSend both stop it). */
const ANSWER_POLL_MS = 1500
let fastAnswerTimer = null
async function fastAnswerLoop() {
  if (!state.activeSendAwaitingAnswer) return
  try {
    await pollTick()
  } catch { /* the next tick retries — never fatal into the flow */ }
  if (state.activeSendAwaitingAnswer) {
    fastAnswerTimer = setTimeout(() => { fastAnswerLoop() }, ANSWER_POLL_MS)
  } else {
    fastAnswerTimer = null
  }
}
function startFastAnswerPoll() {
  if (fastAnswerTimer) clearTimeout(fastAnswerTimer)
  fastAnswerTimer = setTimeout(() => { fastAnswerLoop() }, ANSWER_POLL_MS)
}

/** R81-F3: the sender watchdog ticks every second and enforces the bounded
 * per-stage deadlines from lifecycle.js — a breach becomes a TYPED terminal
 * state with a localized recovery action, never a silent hang. */
let sendWatchdogTimer = null
function startSendWatchdog() {
  stopSendWatchdog()
  sendWatchdogTimer = setInterval(() => { try { checkSendWatchdog() } catch { /* never fatal */ } }, 1000)
}
function stopSendWatchdog() {
  if (sendWatchdogTimer) { clearInterval(sendWatchdogTimer); sendWatchdogTimer = null }
}

// --- Status + state line -------------------------------------------------------------

function locked() {
  return !(state.status && state.status.unlocked)
}

function renderStatus() {
  const st = state.status
  const line = $('transferStateLine')
  if (!line) return
  // LAW 0.50 (R133, the CEO's F4) — the role buttons VANISH while a transfer
  // is in flight: the mid-process role click is structurally impossible (the
  // view is already where the live session is). They return when idle.
  try {
    const rolesRow = $('transferRoles')
    if (rolesRow) {
      const busy = !!state.activeSend || !!state.activeRecv
      rolesRow.classList.toggle('hidden', busy)
      rolesRow.hidden = busy
    }
  } catch { /* the row hide never breaks the render */ }
  if (!st) {
    line.textContent = msg('transferStateLoading', undefined, 'Checking vault state…')
    return
  }
  if (!st.unlocked) {
    line.textContent = msg('transferStateLocked', undefined, 'Vault locked — unlock to use direct transfer.')
    // R90 §5 — the inline unlock is VISIBLE exactly while locked; the
    // password field lives in the dialog itself (no settings navigation).
    showInlineUnlock()
    renderDiscoveryPanel()
    return
  }
  hideInlineUnlock()
  // R79 (F-R78-3): readiness-mapped state line — the worker reports the REAL
  // readiness; the UI renders it truthfully and can NEVER say "Vault locked"
  // while the vault is unlocked.
  const readiness = String(st.readiness || '')
  const rendezvousOk = !st.rendezvous || st.rendezvous.available !== false
  // R85 (T7): the typed "interrupted — resend" affordance — an in-flight
  // transfer cut down by a worker recycle is surfaced here, never silent.
  renderInterruptedNote(Array.isArray(st.interrupted) ? st.interrupted : [])
  if (readiness === 'no_sync_code') {
    line.textContent = msg('transferStateNoChain', undefined, 'No sync chain on this device — create or join a sync chain first.')
    renderDiscoveryPanel()
    return
  }
  if (readiness === 'enable_availability') {
    line.textContent = msg('transferStateEnableAvail', undefined, 'Ready — enable availability (Receive tab or Settings) to receive; you can always send.')
    renderDiscoveryPanel()
    return
  }
  if (!rendezvousOk) {
    // R89 (F-R89-MANUAL-1): a missing cloud rendezvous does NOT make the
    // feature unavailable — the manual copy/paste fallback (T1/T2) is fully
    // usable. R140 §6.2: the verdict is EVIDENCE-BASED — the sentence names
    // the probe that failed and the road that works; the unexplained
    // cloud-verdict class is retired (G87+ fingerprint).
    line.textContent = msg('transferStateManualOnly', undefined,
      'The transfer rendezvous on your cloud is not answering right now (the rendezvous check just failed) — the manual route below is the road: one copy, one paste. UCrypt keeps retrying the cloud road automatically.')
    renderDiscoveryPanel()
    promoteManualZone()
    return
  }
  const dev = st.deviceId ? ' ' + msg('transferStateDevice', [shortId(st.deviceId)], 'Device $ID$') : ''
  if (st.availability && st.availability.enabled) {
    line.textContent = msg('transferStateAvail', [fmtTime(st.availability.expiresAt), dev.trim()],
      'Available until $TIME$$DEV$ — offers arrive while the window is open.')
  } else {
    line.textContent = msg('transferStateAvailOff', [dev.trim()],
      'Availability is off$DEV$ — you can send; enable availability (Receive or Settings) to receive.')
  }
  // Receiver availability card — truthful mirror.
  const availLine = $('transferAvailState')
  if (availLine) {
    availLine.textContent = (st.availability && st.availability.enabled)
      ? msg('transferAvailStateOn', [fmtTime(st.availability.expiresAt)], 'Available until $TIME$')
      : msg('transferAvailStateOff', undefined, 'Off — enable it in Settings → Sync & devices → Direct transfer.')
  }
  // R107: the truth panel renders on EVERY healthy-path status render too.
  renderDiscoveryPanel()
}

/**
 * R85 (T7) + R101 (F-R100-1): the typed "interrupted — resend" note — the
 * ledger's LATEST entry renders once; an empty ledger clears the note.
 * Entries carry the transferId (the law) and the worker's projection already
 * filtered any LIVE session out, so the note can only ever name sessions
 * truly gone.
 */
function renderInterruptedNote(list) {
  const interruptedNote = $('transferInterruptedNote')
  if (!interruptedNote) return
  const last = Array.isArray(list) && list.length ? list[list.length - 1] : null
  interruptedNote.textContent = last
    ? msg('transferInterruptedNotice',
        [last.role === 'sender' ? msg('transferRoleSend', undefined, 'Sent') : msg('transferRoleReceive', undefined, 'Received'), String(last.name || '')],
        'An in-flight transfer ($ROLE$: $NAME$) was interrupted by a browser worker restart — nothing was harmed; resend the file.')
    : ''
}

/**
 * R101 (F-R100-2, the CEO's binding defect report): the STALE SENDER CLEAR.
 * A worker recycle mid-flow can leave this page holding a sender state the
 * worker no longer has (the session was WebRTC-bound — unresumable, really
 * interrupted). Without this reconciliation the one-active-send gate refuses
 * every later send until a manual reload — the CEO's exact finding. The law:
 * when the WORKER CONFIRMS no in-flight sender transfer matching the page's
 * id, the page clears its stale state (typed note, no reload) and the next
 * send just works. A worker answer is the only authority — an unreachable
 * worker or a genuinely live session NEVER clears on a guess.
 */
async function clearStaleSenderIfWorkerIdle() {
  const stale = state.activeSend
  if (!stale) return false
  const res = await worker({ type: 'TRANSFER_ACTIVE_SESSION' }).catch(() => null)
  if (!res || !res.ok) return false // unconfirmed — the refusal stands
  const live = res.activeSession
  if (live && live.role === 'sender' && live.transferId === stale.transferId) return false // genuinely live
  // Confirmed stale: run the same terminal-shaped cleanup finishSend uses,
  // WITHOUT the worker TRANSFER_CANCEL (the worker already confirmed the
  // session is gone; terminalCleanup is idempotent anyway) and with the
  // truthful interrupted note — the T7 ledger (F-R100-1) carries the entry
  // the wake wrote for exactly this recycle.
  stopSendWatchdog()
  try { if (stale.pc) stale.pc.close() } catch { /* already closed */ }
  try { if (stale.channel) stale.channel.close() } catch { /* already closed */ }
  stale.file = null // drop the File reference
  state.activeSend = null
  show($('transferSendProgressCard'), false)
  const btn = $('transferSendBtn')
  if (btn) btn.disabled = !state.file
  renderInterruptedNote(Array.isArray(res.interrupted) ? res.interrupted : [])
  return true
}

async function refreshStatus() {
  const res = await worker({ type: 'TRANSFER_STATUS' })
  if (res.ok) {
    state.status = res
    renderStatus()
    noteStagedPresence(res)
    if (!res.unlocked) handleVaultLockedLocally()
  } else if (res.error === 'locked') {
    state.status = { ok: true, unlocked: false, availability: null, peers: [] }
    renderStatus()
    handleVaultLockedLocally()
  }
}

/**
 * R89 (F-R89-MANUAL-1): when a presence publish fails (no transport /
 * unreachable rendezvous), the worker hands the page the EXACT sealed record
 * so the manual Copy button can carry first contact by hand. The manual
 * result line says so truthfully — the cloud copy is still retried by the
 * availability cadence, and a successful publish clears the staged record.
 */
function noteStagedPresence(res) {
  const b64 = res && res.stagedManualPresenceB64
  if (!b64) return
  if (state.manualSignal === b64) return // already rendered
  // A staged offer/answer/completion the user has not copied yet must never
  // be clobbered by a presence refresh: presence staging fills an EMPTY
  // manual surface (first contact) or replaces an earlier staged presence
  // only while no transfer flow is live.
  if (state.manualSignal && (state.activeSend || state.activeRecv)) return
  state.manualSignal = String(b64)
  renderManualMineBox()
  const out = $('transferManualResult')
  if (out) out.textContent = msg('transferManualStagedPresence', undefined,
    'No cloud route for your availability signal — copy it below and paste it on the other device once to be discoverable manually.')
}

/** R128 §6 (the CEO's S6 — the zero-learning-curve manual path): the signal
 * LIVES IN A BOX on step 1 — the copy button adjacent. Every site that sets
 * or clears state.manualSignal mirrors it here; the user always sees the
 * exact bytes they are handing over (one box, one button, one action). */
function renderManualMineBox() {
  const mine = $('transferManualMine')
  if (!mine) return
  mine.value = String(state.manualSignal || '')
}

/**
 * R107 §2.2 — THE DISCOVERY TRUTH PANEL (the S9 law, made concrete).
 * The page renders its OWN precondition chain live — chain · cloud ·
 * availability · devices — and every ✗ row carries its one-click next
 * action. Updated IN PLACE on every status render; never prose alone
 * (the amended 0.13: an unexplained empty list is a defect).
 */
function renderDiscoveryPanel() {
  const host = $('transferTruthRows')
  if (!host) return
  const model = discoveryModel(state.status)
  const labelOf = {
    chain: 'transferTruthRowChain',
    cloud: 'transferTruthRowCloud',
    availability: 'transferTruthRowAvail',
    devices: 'transferTruthRowDevices',
  }
  const actionOf = {
    // R116 §2.3 (law 0.29; the CEO's S6): the ✗ rows' fixes open AS OVERLAYS
    // right here in File transfer — the cloud row opens the connect overlay
    // (the transport chooser + the OAuth connect + Test + Save in one sheet),
    // the chain row opens the join overlay (paste the 24 words in place).
    // The old deep-link to the options page survives ONLY as the overlays'
    // demoted "Open the full setup instead" fallback row (visually demoted,
    // rendered last) — never the first answer.
    setup: ['transferTruthActSetup', (ev) => openJoinOverlayInPage(ev)],
    connect: ['transferTruthActConnect', (ev) => openConnectOverlayInPage(ev)],
    manual: ['transferTruthActManual', () => promoteManualZone(true)],
    arm: ['transferTruthActArm', () => enableAvailabilityHere()],
    stop: ['transferTruthActStop', () => disableAvailabilityHere()],
    pair: ['transferTruthActPair', () => promoteManualZone(true)],
  }
  host.textContent = ''
  // R127 §4 (the CEO's S6 — the checklist is a PRECONDITION surface, not a
  // step): when every precondition is green, the four rows collapse into
  // ONE ready line — the flow reads like Direct Share's clean sheet. The
  // details stay reachable (one click re-renders the full list — honesty
  // never hides state, it de-clutters the ready path).
  const allOk = model.rows.every((r) => r.ok)
  if (allOk && !discoveryModel._detailsWanted) {
    const li = document.createElement('li')
    li.className = 'transfer-truth-row ok transfer-truth-ready'
    li.dataset.truthRow = 'ready'
    const mark = document.createElement('span')
    mark.className = 'transfer-truth-mark'
    mark.setAttribute('aria-hidden', 'true')
    mark.textContent = '✓'
    const label = document.createElement('span')
    label.className = 'transfer-truth-label'
    label.textContent = msg('transferTruthAllOk', undefined, 'Ready — your chain can send and receive.')
    li.appendChild(mark)
    li.appendChild(label)
    const toggle = document.createElement('button')
    toggle.type = 'button'
    toggle.className = 'btn btn-ghost btn-sm transfer-truth-action'
    toggle.textContent = msg('transferTruthShowRows', undefined, 'Show the preconditions')
    toggle.addEventListener('click', () => { discoveryModel._detailsWanted = true; renderDiscoveryPanel() })
    li.appendChild(toggle)
    host.appendChild(li)
    renderArmStrip()
    return
  }
  if (allOk && discoveryModel._detailsWanted) {
    // The user asked for the details — the collapse toggle flips back.
    const li = document.createElement('li')
    li.className = 'transfer-truth-row ok'
    const mark = document.createElement('span')
    mark.className = 'transfer-truth-mark'
    mark.setAttribute('aria-hidden', 'true')
    mark.textContent = '✓'
    const label = document.createElement('span')
    label.className = 'transfer-truth-label'
    label.textContent = msg('transferTruthAllOk', undefined, 'Ready — your chain can send and receive.')
    li.appendChild(mark)
    li.appendChild(label)
    const toggle = document.createElement('button')
    toggle.type = 'button'
    toggle.className = 'btn btn-ghost btn-sm transfer-truth-action'
    toggle.textContent = msg('transferTruthHideRows', undefined, 'Hide the preconditions')
    toggle.addEventListener('click', () => { discoveryModel._detailsWanted = false; renderDiscoveryPanel() })
    li.appendChild(toggle)
    host.appendChild(li)
  }
  for (const row of model.rows) {
    const li = document.createElement('li')
    li.className = 'transfer-truth-row' + (row.ok ? ' ok' : ' bad')
    li.dataset.truthRow = row.id
    const mark = document.createElement('span')
    mark.className = 'transfer-truth-mark'
    mark.setAttribute('aria-hidden', 'true')
    mark.textContent = row.ok ? '✓' : '✗'
    const label = document.createElement('span')
    label.className = 'transfer-truth-label'
    label.textContent = msg(labelOf[row.id], undefined, row.id)
    li.appendChild(mark)
    li.appendChild(label)
    if (!row.ok) {
      for (const actionId of row.actions) {
        const def = actionOf[actionId]
        if (!def) continue
        const btn = document.createElement('button')
        btn.type = 'button'
        // R116 §2.3 — the DEMOTED FALLBACK LAW: the manual copy/paste path is
        // the fallback, never the headline — it renders LAST (the actions
        // arrays already order it so) and visually demoted (the ghost class).
        const demoted = actionId === 'manual' || actionId === 'pair'
        btn.className = 'btn btn-outline btn-sm transfer-truth-action' + (demoted ? ' transfer-truth-action--demoted' : '')
        btn.dataset.truthAction = actionId
        btn.textContent = msg(def[0], undefined, actionId)
        if (demoted) {
          btn.title = msg('transferTruthDemotedTitle', undefined, 'Works without any cloud — both devices open, hand-carried signals.')
        }
        btn.addEventListener('click', def[1])
        li.appendChild(btn)
      }
    } else if (row.id === 'devices' && model.peers.length) {
      const n = model.peers.length
      const count = document.createElement('span')
      count.className = 'transfer-truth-detail'
      count.textContent = msg('transferTruthPeersSome', [String(n)], '$1$ device(s) visible')
      li.appendChild(count)
    }
    host.appendChild(li)
  }
  renderArmStrip()
}

/**
 * R107 §2.3 — THE AUTO-ARM STRIP: the visible countdown + one-click Stop.
 * A 1-second ticker (only while armed) keeps the countdown honest; the copy
 * states the privacy truth — the window's opening is the opt-in.
 */
let armTicker = null
function renderArmStrip() {
  const strip = $('transferArmStrip')
  if (!strip) return
  const st = state.status
  const armed = !!(st && st.availability && st.availability.enabled && st.unlocked)
  show(strip, armed)
  if (armTicker) { clearInterval(armTicker); armTicker = null }
  if (!armed) return
  const chip = $('transferArmCountdown')
  const render = () => {
    const cd = armCountdown(st.availability.expiresAt, Date.now())
    if (chip) {
      // R137 G80 FP-P7 (Table 3): the countdown-to-death copy is RETIRED —
      // the chip states the availability truth and names the instant Stop;
      // the ticker's remaining job is the honest flip to the ended state.
      chip.textContent = cd.expired
        ? msg('transferArmEnded', undefined, 'Availability window ended — devices no longer see this device.')
        : msg('transferArmCountdown', undefined, 'Visible to your chain\'s devices while availability is on — press Stop to end it now; the window also ends on its own.')
    }
    if (cd.expired && armTicker) { clearInterval(armTicker); armTicker = null }
  }
  render()
  armTicker = setInterval(render, 1000)
}

/**
 * R107 §2.4 — THE ADVANCED ZONE PROMOTION: collapsed by default; opened +
 * promoted with truthful copy exactly when the chain has no cloud rendezvous
 * (the zero-transport law's UI face). One-click actions can force it open.
 */
// R125 §3.1 (the CEO's S1) — the sync transport's honest display name for
// the promotion copy (the ID is the only thing that crosses — 0.14).
function syncTransportLabel(id) {
  const labels = {
    gdrive: 'Google Drive',
    dropbox: 'Dropbox',
    github: 'GitHub',
    custom: 'Custom URL',
    http: 'Custom URL',
    webdav: 'WebDAV',
  }
  return labels[String(id || '')] || String(id || 'the cloud')
}

function promoteManualZone(force = false) {
  const zone = $('transferManualZone')
  if (!zone) return
  const promo = manualZonePromotion(state.status)
  const promoEl = $('transferManualPromo')
  if (promo.promote) {
    zone.open = true
    if (promoEl) {
      // R108 §5.1 (the CEO's S3) — the promotion NAMES THE CURE: connect the
      // cloud to make transfers one-click; the manual dance below works
      // without it (the zero-transport law — never removed, never a lie).
      // R136-F2 (the CEO's evidence): the WebDAV-capable-folder sentence is
      // RETIRED — the connected cloud IS the relay (Beam 3 Plane B), so the
      // sync-transport branch is unreachable; the only promotion left names
      // manual pairing as the first-class path it now is.
      promoEl.textContent = promo.syncTransport
        ? msg(promo.copyKey, [syncTransportLabel(promo.syncTransport)],
            `Your sync cloud (${syncTransportLabel(promo.syncTransport)}) is connected — transfers ride it as sealed chunks. Manual pairing below stays available any time.`)
        : msg(promo.copyKey, undefined,
            'Your chain has no cloud connected — manual pairing is a first-class path: copy the signal, paste theirs, and the transfer completes device-to-device when a path exists.')
      show(promoEl, true)
    }
  } else if (force) {
    zone.open = true
    if (promoEl) {
      promoEl.textContent = msg('transferManualHealthyRoute', undefined,
        'Cloud route healthy — devices on your chain discover each other automatically; manual pairing is only needed when the cloud route is down.')
      show(promoEl, true)
    }
  } else if (promoEl) {
    show(promoEl, false)
  }
  if (zone.open) {
    const box = $('transferManualIn')
    if (box) box.focus({ preventScroll: true })
    // R117 §2 (the CEO's S3; laws 0.29 + 0.30): opening the zone is not
    // enough — the zone lives BELOW THE FOLD, so the click read as dead.
    // The zone now ANCHORS into view (smooth) with a brief highlight ring,
    // and only then focuses the paste box (the focus stays preventScroll so
    // the ring, not the caret jump, carries the eye).
    try {
      zone.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } catch { zone.scrollIntoView() }
    zone.classList.remove('transfer-zone-flash')
    // restart the animation on every promotion (the reflow is the trigger)
    void zone.offsetWidth
    zone.classList.add('transfer-zone-flash')
    setTimeout(() => zone.classList.remove('transfer-zone-flash'), 1600)
  }
}

// --- Vault lock (order B5/E7 — the lock cancels EVERYTHING) -----------------------------

function handleVaultLockedLocally() {
  // Close live connections first — no auto-resume ever, in any direction.
  // R81-F2: the lock is a TERMINAL event — the watchdog stops, the sender
  // session dies locally (the WORKER runs the same terminal cleanup on the
  // lock path, so no TRANSFER_CANCEL round-trip is needed here).
  stopSendWatchdog()
  try { if (state.activeSend && state.activeSend.pc) state.activeSend.pc.close() } catch { /* already closed */ }
  try { if (state.activeRecv && state.activeRecv.pc) state.activeRecv.pc.close() } catch { /* already closed */ }
  state.activeSend = null
  state.activeRecv = null

  // B5: pending decision cards are cancelled TRUTHFULLY, never silently dropped.
  for (const rec of state.pendingOffers.values()) {
    if (rec.state === 'pending') {
      rec.state = 'cancelled'
      setCardState(rec, msg('transferCancelLocked', undefined, 'Cancelled — vault locked.'))
    }
  }
  if ($('transferDialogOverlay') && !$('transferDialogOverlay').classList.contains('hidden')) {
    closeDecisionDialog()
  }

  // Reset the sender + receiver flows so nothing pretends to continue.
  resetSendUi()
  resetRecvUi()
  renderStatus()
}

// Vault-lock broadcast: same subscription pattern as the popup's
// NATIVE_MANAGER_CHANGED listener (chrome.runtime.onMessage, type check).
try {
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'VAULT_LOCKED') handleVaultLockedLocally()
    // R90 §5 — an unlock from ANY surface (inline field, popup, settings)
    // refreshes this dialog's state in place — the locked view never lingers.
    if (msg && msg.type === 'VAULT_UNLOCKED') {
      hideInlineUnlock()
      refreshStatus()
    }
  })
} catch { /* listener unavailable — the 5 s poll backstop still catches locks */ }

// --- Poll (data + MV3 keepalive — every poll wakes the worker) ---------------------------

let pollBusy = false
// R140 §6.3 — the inbox's self-report: the page's own poll IS a check; the
// line renders the truth of its activity (never silent about why)
let _inboxLastPollAt = 0
let _inboxPollTimer = null
const INBOX_FAST_MS = 2000 // the §6.3 cadence while the Receive view is open + armed
function renderInboxLine() {
  const el = document.getElementById('transferInboxStatus')
  if (!el) return
  const recvVisible = (() => { try { const v = document.getElementById('viewReceive'); return !!v && !v.classList.contains('hidden') } catch { return false } })()
  const armed = !!(state.status && state.status.availability && state.status.availability.enabled)
  if (!recvVisible || !armed) {
    el.textContent = msg('spineInboxIdle', undefined, 'The inbox checks when you open Receive with availability armed.')
    return
  }
  const ago = _inboxLastPollAt ? Math.max(0, Math.round((Date.now() - _inboxLastPollAt) / 1000)) : null
  el.textContent = msg('spineInboxActive', ['2', String(ago == null ? '…' : ago)], ago == null ? 'Checking for offers every 2 s…' : `Checking for offers every 2 s · last checked ${ago}s ago`)
}
/** The adaptive cadence (§6.3): 2 s while Receive is open + armed, 5 s
 * otherwise — receiving is passive, and the page-open case MUST receive. */
function scheduleInboxPoll() {
  if (_inboxPollTimer) clearTimeout(_inboxPollTimer)
  _inboxPollTimer = setTimeout(async () => {
    await pollTick().catch(() => {})
    renderInboxLine()
    scheduleInboxPoll()
  }, (() => {
    try {
      const v = document.getElementById('viewReceive')
      const recvVisible = !!v && !v.classList.contains('hidden')
      const armed = !!(state.status && state.status.availability && state.status.availability.enabled)
      return recvVisible && armed ? INBOX_FAST_MS : POLL_MS
    } catch { return POLL_MS }
  })())
}
// R105 §2.3 — the losing surface's persistent hint flag (cleared when a NEW
// offer arrives on THIS surface — a real decision supersedes the notice).
let hintConsumedElsewhere = false
async function pollTick() {
  if (pollBusy) return
  pollBusy = true
  try {
    const res = await worker({ type: 'TRANSFER_POLL' })
    if (!res.ok) {
      if (res.error === 'locked') {
        state.status = { ok: true, unlocked: false, availability: null, peers: [] }
        renderStatus()
        handleVaultLockedLocally()
      } else if (res.error === 'no_worker' || res.error === 'no_response') {
        // R86 (live-matrix finding, T7 honesty): a dead/unreachable worker
        // must never leave the page claiming "Waiting for receiver approval".
        // Surface the typed interruption truth — the next successful status
        // render re-syncs this note from the worker's own truthful state.
        stopSendWatchdog()
        const note86 = $('transferInterruptedNote')
        if (note86 && !note86.textContent) {
          note86.textContent = msg('transferInterruptedWorker', undefined,
            'The extension worker restarted mid-transfer — this window lost the live connection. The transfer was interrupted; nothing was saved. Resend the file when both devices are available.')
        }
      }
      return // rendezvous errors surface via explicit actions, not poll spam
    }
    // Offers — MERGE by offerId (B5): existing pending cards are left untouched.
    for (const offer of res.offers || []) addPendingOffer(offer)
    // Answers (sender role).
    for (const answer of res.answers || []) handleAnswer(answer)
    // Remote ICE candidates for any live connection.
    for (const ice of res.ices || []) handleRemoteIce(ice)
    // Peer cancels (true sender-initiated cancels only — R85 separates the
    // receiver's DECLINE into its own typed terminal below).
    for (const transferId of res.cancels || []) handlePeerCancel(transferId)
    // R85 (F-R84-XFER-3): the receiver's refusal — the ordered DECLINE copy.
    for (const d of res.declines || []) handlePeerDecline(d && typeof d === 'object' ? d.transferId : d)
    // Receiver-verified completions (sender role).
    for (const transferId of res.completes || []) handleComplete(transferId)
    // R86 (T5): the sender's OWN offer expiring is a truthful terminal — the
    // poll surfaces swept expired ids so the UI never sits past the deadline.
    for (const transferId of res.expired || []) handleOwnOfferExpired(transferId)
    // R85 (F-R84-XFER-2): truthful notice when an offer is still refused
    // unknown_sender AFTER the poll's auto-learn retry.
    // R105 §2.3 — THE MULTI-WINDOW OFFER HINT: another UCrypt surface opened
    // an offer THIS surface had been shown. The typed one-line notice
    // persists (law 0.8 — no auto-dismiss) until a NEW offer arrives here;
    // the unknown-sender copy wins when both fire (it names the live gate).
    for (const c of (res.consumedElsewhere || [])) { if (c && c.offerId) hintConsumedElsewhere = true }
    const notice = $('transferReceiveNotice')
    if (notice) {
      const unknown = Number(res.unknownSenders) || 0
      notice.textContent = unknown > 0
        ? msg('transferRecvUnknownSender', undefined, 'Sender unknown — they must enable availability (and be on your sync chain) before you can receive their offers.')
        : (hintConsumedElsewhere
          ? msg('transferOfferOpenedElsewhere', undefined, 'A transfer offer was opened in another UCrypt window.')
          : '')
    }
  } finally {
    pollBusy = false
    _inboxLastPollAt = Date.now()
  }
}

// R86 (T5): the sender's own offer expired while waiting — render the typed
// EXPIRED terminal with its truthful next-step copy (never a silent reset).
function handleOwnOfferExpired(transferId) {
  if (!transferId) return
  const activeSend = state.activeSend
  if (activeSend && activeSend.transferId === transferId && !activeSend.terminal) {
    finishSend(TRANSFER_STATES.EXPIRED, 'transferTermExpired', undefined,
      'The offer expired — the receiver did not respond in time. Nothing was sent. Pick the file again to try another device.')
    toast(msg('transferTermExpired', undefined, 'The offer expired — the receiver did not respond in time. Nothing was sent.'))
  }
}

// --- Incoming offers (receiver) — decision cards NEVER auto-dismiss (B5) ---------------

function addPendingOffer(offer) {
  if (!offer || !offer.offerId) return
  if (!state.pendingOffers.has(offer.offerId)) {
    // R105 §2.3 — a NEW offer on this surface supersedes the consumed-
    // elsewhere notice: the decision the user actually faces comes first.
    hintConsumedElsewhere = false
    const notice = $('transferReceiveNotice')
    if (notice) notice.textContent = ''
  }
  const existing = state.pendingOffers.get(offer.offerId)
  if (existing) {
    // Merge: only non-decision fields may be refreshed (B5).
    if (existing.state === 'pending' && existing.offer.expiresAt !== offer.expiresAt) {
      existing.offer.expiresAt = offer.expiresAt
      const meta = existing.el && existing.el.querySelector('.transfer-incoming-meta')
      if (meta) meta.textContent = offerMetaText(existing.offer)
    }
    return
  }
  const el = buildOfferCard(offer)
  state.pendingOffers.set(offer.offerId, { offer, el, state: 'pending' })
  const list = $('transferIncomingList')
  if (list) list.appendChild(el)
  // Prominent decision surface: the modal opens for the NEW offer only.
  openDecisionDialog(offer)
}

function offerMetaText(offer) {
  const from = (offer.fromLabel || offer.senderLabel || msg('transferDeviceUnknown', undefined, 'Device'))
  return msg('transferOfferMeta', [humanSize(offer.size), fmtTime(offer.expiresAt), from, shortId(offer.from)],
    '$SIZE$ · offer expires $TIME$ · from $FROM$ ($ID$)')
}

function buildOfferCard(offer) {
  const card = document.createElement('div')
  card.className = 'transfer-incoming'
  card.setAttribute('role', 'listitem')

  const title = document.createElement('p')
  title.className = 'transfer-incoming-title'
  title.textContent = offer.name || msg('transferDeviceUnknown', undefined, 'Device')
  card.appendChild(title)

  const meta = document.createElement('p')
  meta.className = 'transfer-incoming-meta'
  meta.textContent = offerMetaText(offer)
  card.appendChild(meta)

  if (offer.warning) {
    const warn = document.createElement('p')
    warn.className = 'transfer-warning'
    warn.setAttribute('role', 'alert')
    warn.textContent = msg('transferDialogWarning', undefined,
      '⚠ This file looks like a program or archive. Do not run or open it unless you trust the sender completely.')
    card.appendChild(warn)
  }

  // SHA-256: short inline, full on expand (details — non-secret, never a key).
  const details = document.createElement('details')
  const summary = document.createElement('summary')
  summary.className = 'transfer-incoming-meta'
  summary.textContent = msg('transferShaShort', [shortSha(offer.sha256)], 'SHA-256: $SHA$')
  details.appendChild(summary)
  const full = document.createElement('p')
  full.className = 'transfer-incoming-meta'
  full.style.wordBreak = 'break-all'
  full.textContent = String(offer.sha256 || '')
  details.appendChild(full)
  card.appendChild(details)

  const row = document.createElement('div')
  row.className = 'btn-row'
  const accept = document.createElement('button')
  accept.type = 'button'
  accept.className = 'btn btn-primary btn-sm'
  accept.textContent = msg('transferDialogAccept', undefined, 'Accept')
  accept.addEventListener('click', () => acceptOffer(offer.offerId))
  const decline = document.createElement('button')
  decline.type = 'button'
  decline.className = 'btn btn-ghost btn-sm'
  decline.textContent = msg('transferDialogDecline', undefined, 'Decline')
  decline.addEventListener('click', () => declineOffer(offer.offerId))
  row.appendChild(accept)
  row.appendChild(decline)
  card.appendChild(row)

  // Reopen the decision dialog for THIS offer (never a timer — the user decides).
  card.addEventListener('click', (e) => {
    if (e.target === accept || e.target === decline) return
    if (state.pendingOffers.get(offer.offerId)?.state === 'pending') openDecisionDialog(offer)
  })

  // Nice-to-have (order B5 wording): ESC while the card is focused declines.
  card.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && state.pendingOffers.get(offer.offerId)?.state === 'pending') {
      declineOffer(offer.offerId)
    }
  })

  return card
}

/** Replace the decision buttons with a terminal, truthful status line. */
function setCardState(rec, text) {
  if (!rec || !rec.el) return
  const row = rec.el.querySelector('.btn-row')
  if (row) {
    const status = document.createElement('p')
    status.className = 'transfer-incoming-meta'
    status.setAttribute('role', 'status')
    status.textContent = text
    row.replaceWith(status)
  }
}

// --- Decision dialog (prominent surface; the inline card stays pending) ---------------

let dialogOfferId = null
// R79 (F-R78-10): the focus-restore target lives in ITS OWN ephemeral slot —
// it was previously assigned as a property on the offerId STRING primitive,
// which threw a TypeError on every dialog open and killed the focus contract.
let dialogFocusRestore = null

function openDecisionDialog(offer) {
  const overlay = $('transferDialogOverlay')
  if (!overlay || !offer) return
  $('transferDialogFrom').textContent = offer.fromLabel || offer.senderLabel || msg('transferDeviceUnknown', undefined, 'Device')
  $('transferDialogDeviceId').textContent = shortId(offer.from)
  $('transferDialogName').textContent = offer.name || '—'
  $('transferDialogSize').textContent = humanSize(offer.size)
  // LAW 0.50 (R133, the CEO's modal spec): "Incoming file from DELL —
  // <name> <size> — code DA0D 5DEE D9BC 597A" — the FILE CODE rides the
  // modal; the same code auto-displays on the sender's screen from offer
  // creation (human comparison, zero copying).
  const codeEl = $('transferDialogCode')
  if (codeEl) {
    codeEl.textContent = offerDisplayCode(offer.sha256)
    codeEl.classList.add('set')
    codeEl.classList.remove('waiting')
  }
  $('transferDialogSha').textContent = String(offer.sha256 || '—')
  $('transferDialogExpiry').textContent = fmtTime(offer.expiresAt)
  show($('transferDialogWarning'), !!offer.warning)
  // LAW 0.50 — THE ROLE NEVER NEEDS A MID-PROCESS CLICK: an incoming offer
  // opens the receive view by itself (the user was on Send — the offer still
  // reaches them: the view switches, the modal pops, nothing is clicked).
  if (state.role !== 'receive') selectRole('receive')
  // LAW 0.50 (F6, the CEO's exact command) — availability AUTO-ARMS when a
  // signal arrives: the receive intent is proven by the offer itself.
  const st = state.status
  if (st && !(st.availability && st.availability.enabled)) {
    enableAvailabilityHere({ auto: true }).catch(() => { /* the checklist names it */ })
  }
  overlay.classList.remove('hidden')
  dialogOfferId = offer.offerId
  // Element REFERENCE in ephemeral page state (never a property on a string).
  dialogFocusRestore = document.activeElement instanceof Element ? document.activeElement : null
  $('transferDialogAccept').focus()
}

function closeDecisionDialog() {
  const overlay = $('transferDialogOverlay')
  if (!overlay) return
  overlay.classList.add('hidden')
  const prev = dialogFocusRestore
  dialogFocusRestore = null
  dialogOfferId = null
  // Restore ONLY when the target is still connected and focusable.
  if (prev && prev.isConnected && typeof prev.focus === 'function') {
    try { prev.focus() } catch { /* the element refused focus — nothing to restore */ }
  }
}

// --- Accept (receiver): answer + SDP inside the sealed payload -------------------------

async function acceptOffer(offerId) {
  const rec = state.pendingOffers.get(offerId)
  if (!rec || rec.state !== 'pending') return
  const offer = rec.offer

  // Decide FIRST — a second accept/decline can never race (B5 discipline).
  rec.state = 'accepted'
  setCardState(rec, msg('transferCardAccepted', undefined, 'Accepted — connecting directly to the sender…'))

  let pc = null
  try {
    if (locked()) throw keyed({ ok: false, error: 'locked', userMessageKey: 'transferErrLocked' })

    // NO relay (owner order): iceServers: [] means host candidates only —
    // the connection is possible only on a direct path and no STUN/TURN
    // third party is ever contacted.
    pc = new RTCPeerConnection({ iceServers: [] })
    state.activeRecv = { transferId: offer.transferId, offerId, pc, saved: false }
    wireReceiverConnection(pc)

    await pc.setRemoteDescription({ type: 'offer', sdp: String(offer.sdp || '') })
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await waitIceGathering(pc, GATHER_CAP_MS)

    const res = await worker({ type: 'TRANSFER_ACCEPT_OFFER', offerId, sdp: pc.localDescription.sdp })
    if (!res.ok) throw keyed(res)

    // Publish the sealed answer record to the sender's mailbox (cloud) — on
    // failure the SAME record is staged for the manual copy/paste surface.
    // R89 (F-R89-MANUAL-1): the staged answer CONTINUES the accept (manual is
    // a first-class fallback) — the receiver's connection stays armed so the
    // direct channel can open once the answer crosses by hand.
    // F-R99-1 (R99): the answer's hand-carry bytes mirror into an EMPTY paste
    // box the instant the answer exists (no "publish failed" claim — the
    // cloud attempt is still ahead); a successful publish clears the mirror.
    state.manualSignal = String(res.answerRecordB64 || '')
    renderManualMineBox()
    const inBoxPre = $('transferManualIn')
    if (inBoxPre && state.manualSignal && !inBoxPre.value.trim()) inBoxPre.value = state.manualSignal
    const pubAnswer = await publishSignal(res.answerRecord, offer.from, res.answerRecordB64, { manualContinue: true })
    if (pubAnswer && pubAnswer.ok) { state.manualSignal = ''; renderManualMineBox() }
    await publishIceCandidates(pc, offer.transferId, offer.from)

    // Prominent fingerprint — both devices must show the same code.
    // R128 §3: the receiver's field is the SET state from this instant —
    // large, bright, the ✓ congruency chip beside it (the sender's copy
    // crosses within moments on the fast answer poll).
    show($('transferFingerprintRecvBox'), true)
    const recvFp = $('transferFingerprintRecv')
    recvFp.textContent = String(res.fingerprint || '')
    recvFp.classList.remove('waiting')
    recvFp.classList.add('set')
    show($('transferRecvProgressCard'), true)
    setRecvProgress(0, offer.size)
    setRecvText(msg('transferRecvWaiting', undefined, 'Connecting — the file arrives only after you accepted.'))
    toast(msg('transferCardAccepted', undefined, 'Accepted — connecting directly to the sender…'))
  } catch (e) {
    try { if (pc) pc.close() } catch { /* already closed */ }
    if (state.activeRecv && state.activeRecv.offerId === offerId) state.activeRecv = null
    if (e && e.workerCode === 'locked') {
      rec.state = 'cancelled'
      setCardState(rec, msg('transferCancelLocked', undefined, 'Cancelled — vault locked.'))
      handleVaultLockedLocally()
      return
    }
    // Honest recovery: the decision is pending again — nothing happened.
    rec.state = 'pending'
    setCardState(rec, '')
    rebuildCardButtons(rec)
    toast(errorText(e), 'error')
  }
}

async function declineOffer(offerId) {
  const rec = state.pendingOffers.get(offerId)
  if (!rec || rec.state !== 'pending') return
  const offer = rec.offer
  rec.state = 'declined'
  setCardState(rec, msg('transferCardDeclining', undefined, 'Declining…'))
  try {
    // Tell the sender (best-effort with BOUNDED RETRY): a sealed 'decline'
    // record — R85 (F-R84-XFER-3) gives the refusal its own T5 wire kind, so
    // the sender renders "Receiver declined — …" instead of the cancel family.
    // R86 (live-matrix finding): a worker recycle mid-offer used to swallow
    // the failure while the card CLAIMED "the sender was notified" — a lie.
    // Retry the delivery a few times (the message wake + lazy chain-key
    // re-derivation usually lands within seconds), then tell the TRUTH.
    let delivered = false
    for (let attempt = 0; attempt < 3 && !delivered; attempt++) {
      if (attempt > 0) await sleep(2500)
      try {
        const sealed = await worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'decline', to: offer.from, transferId: offer.transferId, payload: { reason: 'declined' } })
        if (sealed.ok) {
          await publishSignal(sealed.record, offer.from, sealed.recordB64)
          delivered = true
        }
      } catch { /* retry */ }
    }
    if (delivered) {
      setCardState(rec, msg('transferCardDeclined', undefined, 'Declined — the sender was notified.'))
    } else {
      setCardState(rec, msg('transferCardDeclinedLocal', undefined, 'Declined — but the sender could not be notified (the extension worker restarted). The sender will see the offer expire.'))
    }
    await worker({ type: 'TRANSFER_CANCEL', transferId: offer.transferId })
  } catch { /* the decline stands locally regardless — never fatal */ }
}

// --- Receiver data path -------------------------------------------------------------

function wireReceiverConnection(pc) {
  pc.onicecandidate = (e) => {
    if (e.candidate) collectCandidate(pc, e.candidate)
  }
  pc.onconnectionstatechange = () => {
    if (!state.activeRecv || state.activeRecv.pc !== pc) return
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      if (!state.activeRecv.saved) {
        setRecvText(msg('transferRecvConnClosed', undefined, 'Direct connection closed before the transfer finished. Nothing was saved — no auto-resume.'))
      }
    }
  }
  pc.ondatachannel = (e) => {
    const channel = e.channel
    if (!channel || channel.label !== 'ucrypt-xfer') return // only the UCrypt channel is used
    channel.binaryType = 'arraybuffer'
    channel.onmessage = (ev) => { ingestFrame(ev.data).catch(() => { /* handled inside */ }) }
    channel.onclose = () => { /* terminal states are driven by ingest/finalize results */ }
  }
}

async function ingestFrame(data) {
  const active = state.activeRecv
  if (!active) return
  let frame = null
  try {
    frame = typeof data === 'string' ? JSON.parse(data) : null
  } catch { frame = null }
  if (!frame || typeof frame !== 'object') {
    failRecv(msg('transferErrBadRecord', undefined, 'That signal is not a valid sealed record.'))
    return
  }
  const res = await worker({ type: 'TRANSFER_INGEST_FRAME', transferId: active.transferId, frame })
  if (!res.ok) {
    if (res.error === 'locked') { handleVaultLockedLocally(); return }
    failRecv(errorText(keyed(res)))
    return
  }
  setRecvProgress(res.received, res.total)
  if (res.received >= res.total && res.total > 0) await finalizeRecv()
}

async function finalizeRecv() {
  const active = state.activeRecv
  if (!active) return
  const res = await worker({ type: 'TRANSFER_FINALIZE', transferId: active.transferId })
  if (!res.ok) {
    if (res.error === 'locked') { handleVaultLockedLocally(); return }
    failRecv(errorText(keyed(res)))
    return
  }
  // R83 ladder: verified ⇒ SAVE PENDING. The sender's 'complete' notice is
  // published ONLY after the user actually saves (saveRecvFile) — the ladder
  // the owner ordered is Verifying → Verified/Save pending → Completed, and
  // "Delivered" must mean the file is in the receiver's hands.
  setRecvProgress(null, null, 100)
  setRecvText(msg('transferRecvVerified', [shortSha(res.sha256)], 'Verified — SHA-256 matches the offer ($SHA$). Save the file when ready.'))
  $('transferSaveBtn').disabled = false
  active.saved = 'ready'
}

async function saveRecvFile() {
  const active = state.activeRecv
  if (!active || active.saved !== 'ready' || state.exporting) return
  // R98 (S8.6) — the BEAM envelope: the received "file" is the sealed vault
  // envelope (the exact cloud bytes). The joiner adopts it as the vault
  // (digest re-verified → pull-first adopt → live) instead of saving a file.
  const offerMeta = (state.pendingOffers.get(active.offerId) || { offer: {} }).offer
  if (offerMeta && offerMeta.name === 'ucrypt-vault.enc') return adoptRecvBeam(offerMeta)
  state.exporting = true
  $('transferSaveBtn').disabled = true
  try {
    // ONE-SHOT export: the worker wipes its plaintext buffer after this read.
    const res = await worker({ type: 'TRANSFER_EXPORT_INBOX', transferId: active.transferId })
    if (!res.ok) {
      if (res.error === 'locked') { handleVaultLockedLocally(); return }
      toast(errorText(keyed(res)), 'error')
      return
    }
    const bytes = base64ToBytesLocal(res.bytesB64)
    const blob = new Blob([bytes], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = String(res.name || 'received-file') // worker returns the SANITIZED name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => { URL.revokeObjectURL(url) }, 10000)
    // Wipe the local blob reference — one download, nothing retained.
    bytes.fill(0)
    active.saved = true
    $('transferRecvDone').textContent = msg('transferRecvSaved', undefined, 'Received and verified. Nothing was opened automatically.')
    setRecvText(msg('transferRecvSaved', undefined, 'Received and verified. Nothing was opened automatically.'))
    toast(msg('transferRecvSaved', undefined, 'Received and verified. Nothing was opened automatically.'))
    // R83 ladder final rung: the file is SAVED — only now does the sender
    // learn the transfer is complete (post-save, never before), and the
    // receiver session gets its one terminal cleanup (TRANSFER_FINISH).
    try {
      const from = (state.pendingOffers.get(active.offerId) || { offer: {} }).offer.from
      if (from) {
        const sealed = await worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'complete', to: from, transferId: active.transferId, payload: {} })
        if (sealed.ok) {
          // R89 (F-R89-MANUAL-1): an unreachable cloud STAGES the completion
          // record for the manual surface — the sender can still learn
          // DELIVERED by hand (T5: DELIVERED is a terminal BOTH sides reach).
          const pub = await worker({ type: 'TRANSFER_PUBLISH_RECORD', record: sealed.record, to: from })
          if (!pub.ok) stageManualSignal(sealed.recordB64 || '', pub.error, pub.userMessageKey)
        }
      }
    } catch { /* completion notice is best-effort; the save already happened */ }
    await worker({ type: 'TRANSFER_FINISH', transferId: active.transferId }).catch(() => { /* idempotent */ })
  } finally {
    state.exporting = false
  }
}

function failRecv(text) {
  const active = state.activeRecv
  try { if (active && active.pc) active.pc.close() } catch { /* already closed */ }
  state.activeRecv = null
  setRecvProgress(0, 1, 0)
  setRecvText(text)
  $('transferSaveBtn').disabled = true
  toast(text, 'error')
}

/**
 * R98 (S8.6/S8.7) — the BEAM landing on the transfer surface: the verified
 * envelope is ADOPTED as the vault (digest re-verified, pull-first adopt)
 * instead of being saved as a file. The backup step (S8.7) is named from the
 * offer's sealed cloud hint (provider + stripped URL — never credentials).
 */
async function adoptRecvBeam(offerMeta) {
  const active = state.activeRecv
  if (!active || active.saved !== 'ready') return
  state.exporting = true
  $('transferSaveBtn').disabled = true
  try {
    // ONE-SHOT export: the worker wipes its plaintext buffer after this read.
    const res = await worker({ type: 'TRANSFER_EXPORT_INBOX', transferId: active.transferId })
    if (!res.ok) {
      if (res.error === 'locked') { handleVaultLockedLocally(); return }
      toast(errorText(keyed(res)), 'error')
      return
    }
    const adopt = await worker({ type: 'TRANSFER_BEAM_ADOPT', bytesB64: res.bytesB64, sha256hex: offerMeta.sha256hex || '', peerDeviceId: offerMeta.from || '' })
    if (adopt && adopt.ok) {
      active.saved = true
      const landed = msg('beamTransferLanded', [String(adopt.entryCount || 0)],
        `The beam landed — ${adopt.entryCount || 0} entries are live on this device.`)
      $('transferRecvDone').textContent = landed
      setRecvText(landed)
      toast(landed)
      // S8.7 — the backup step is named (the offer's cloud hint).
      const hint = offerMeta.beamCloudHint || null
      if (hint && hint.provider) {
        const note = msg('beamTransferBackup', [hint.provider + (hint.url ? ` (${hint.url})` : '')],
          `One step left: connect the same cloud storage the other device uses — $1.`)
        const done = $('transferRecvDone')
        if (done) done.textContent += ' ' + note
      }
    } else {
      const why = (adopt && (adopt.reason || adopt.error)) || msg('beamTransferAdoptFail', undefined, 'The received envelope could not be adopted — nothing was changed.')
      setRecvText('✗ ' + why)
      toast('✗ ' + why, 'error')
    }
    // R83 ladder final rung: the vault is live — the origin learns COMPLETED.
    try {
      const from = offerMeta.from
      if (from) {
        const sealed = await worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'complete', to: from, transferId: active.transferId, payload: {} })
        if (sealed.ok) {
          const pub = await worker({ type: 'TRANSFER_PUBLISH_RECORD', record: sealed.record, to: from })
          if (!pub.ok) stageManualSignal(sealed.recordB64 || '', pub.error, pub.userMessageKey)
        }
      }
    } catch { /* completion notice is best-effort */ }
    await worker({ type: 'TRANSFER_FINISH', transferId: active.transferId }).catch(() => { /* idempotent */ })
  } finally {
    state.exporting = false
  }
}

function resetRecvUi() {
  show($('transferRecvProgressCard'), false)
  show($('transferFingerprintRecvBox'), false)
  setRecvProgress(0, 1, 0)
  setRecvText('—')
  $('transferRecvDone').textContent = ''
  $('transferSaveBtn').disabled = true
}

function setRecvProgress(received, total, pctOverride) {
  const pct = typeof pctOverride === 'number'
    ? Math.max(0, Math.min(100, Math.round(pctOverride)))
    : (total > 0 ? Math.min(100, Math.round(((received || 0) / total) * 100)) : 0)
  const bar = $('transferRecvProgress')
  const fill = $('transferRecvProgressFill')
  if (fill) fill.style.width = pct + '%'
  if (bar) bar.setAttribute('aria-valuenow', String(pct))
}

function setRecvText(text) {
  const el = $('transferRecvProgressText')
  if (el) el.textContent = text
}

// --- Sender: device list ----------------------------------------------------------

async function refreshPeers() {
  const res = await worker({ type: 'TRANSFER_LIST_PEERS' })
  if (!res.ok) {
    if (res.error === 'locked') { renderStatus(); handleVaultLockedLocally(); return }
    toast(errorText(keyed(res)), 'error')
    return
  }
  if (res.unlocked === false) { state.status = res; renderStatus(); handleVaultLockedLocally(); return }
  state.status = res
  renderStatus()
  const peers = (res.peers || []).filter((p) => !p.mine)
  // R92 §2.1 — the 13-year-old test's action reductions, without security
  // loss: (a) the LAST device used is pre-selected (remembered device-local
  // — never synced, a convenience only); (b) when EXACTLY ONE peer is
  // available (online, not stale) and nothing is selected yet, that peer is
  // pre-selected — the send becomes: choose file → Send. Every
  // pre-selection stays a REAL selection the user can change with one click
  // (the picker still renders the Chosen state and the other buttons).
  if (!state.selectedPeerId && peers.length) {
    const available = peers.filter((p) => p.online && !p.stale)
    if (lastPeerId && peers.some((p) => p.deviceId === lastPeerId)) {
      state.selectedPeerId = lastPeerId
    } else if (available.length === 1) {
      state.selectedPeerId = available[0].deviceId
    }
    if (state.selectedPeerId) rememberPeer(state.selectedPeerId)
  }
  renderDeviceList(peers)
  renderDeviceList.peers = peers
  updateSendButtonLabel()
}

// R92 §2.1 — remember-last-device storage (device-local convenience).
let lastPeerId = null
function rememberPeer(deviceId) {
  if (!deviceId) return
  lastPeerId = deviceId
  try { chrome.storage.local.set({ 'ucrypt:transferLastPeer': deviceId }) } catch { /* convenience only */ }
}
function loadLastPeer() {
  try {
    chrome.storage.local.get('ucrypt:transferLastPeer', (r) => {
      lastPeerId = (r && r['ucrypt:transferLastPeer']) || null
    })
  } catch { /* convenience only */ }
}

/**
 * R79 (F-R78-3): the EXACT owner-ordered readiness copy for an empty device
 * list — mapped from the worker's real state, never defaulted to "locked".
 *   Vault locked            → Unlock to transfer
 *   No recovery chain       → Create or join a sync chain first
 *   No capable transport    → Direct transfer unavailable for current storage
 *   No available devices    → No paired device is currently available
 *   Ready                   → Select a device
 */
function emptyListHint() {
  const st = state.status
  if (!st || !st.unlocked) {
    return msg('transferStateLocked', undefined, 'Vault locked — unlock to use direct transfer.')
  }
  const readiness = String(st.readiness || '')
  if (readiness === 'no_sync_code') {
    return msg('transferStateNoChain', undefined, 'No sync chain on this device — create or join a sync chain first.')
  }
  if (st.rendezvous && st.rendezvous.available === false) {
    // R89 (F-R89-MANUAL-1): manual-ready copy — the empty list is not a dead
    // end when the manual surface can bootstrap first contact by hand.
    // R140 §6.2: the verdict is EVIDENCE-BASED — the rendezvous probe is the
    // evidence; the sentence names it and the road that works right now.
    return msg('transferStateManualOnly', undefined,
      'The transfer rendezvous on your cloud is not answering right now (the rendezvous check just failed) — the manual route below is the road: one copy, one paste. UCrypt keeps retrying the cloud road automatically.')
  }
  if (readiness === 'enable_availability') {
    return msg('transferStateEnableAvail', undefined, 'Ready — enable availability (Receive tab or Settings) to receive; you can always send.')
  }
  // R107: the empty list names the precondition and points at the checklist.
  return msg('transferStateNoDevices', undefined, 'No paired device is currently available — the Discovery checklist above names the missing step.')
}

// R123 §2.4 (the CEO's S4) — THE DYNAMIC SEND LABEL: the button NAMES its
// target ("Send to helium") — the outcome is predictable from the label
// (the confidence audit's checklist (b)). No selection → the plain "Send".
function updateSendButtonLabel() {
  const btn = $('transferSendBtn')
  if (!btn) return
  const peers = renderDeviceList.peers || []
  const sel = peers.find((p) => p.deviceId === state.selectedPeerId)
  btn.textContent = sel
    ? msg('transferSendBtnTo', [sel.label || msg('transferDeviceUnknown', undefined, 'Device')], 'Send to $1')
    : msg('transferSendBtn', undefined, 'Send')
}

/** R128 §5 (law 0.30 — selection-configuration): choosing a device with no
 * file yet glows the file card ONCE — the eye is guided to the flow's next
 * (and last) action without a single word of protocol. */
function highlightFileCard() {
  const card = $('transferFileCard')
  if (!card) return
  card.classList.remove('file-glow')
  // restart the animation even on a rapid re-pick
  void card.offsetWidth
  card.classList.add('file-glow')
  setTimeout(() => card.classList.remove('file-glow'), 1500)
}

function renderDeviceList(peers) {
  const list = $('transferDeviceList')
  if (!list) return
  list.textContent = ''
  if (!peers.length) {
    const hint = document.createElement('p')
    hint.className = 'card-help'
    hint.textContent = emptyListHint()
    list.appendChild(hint)
    return
  }
  for (const peer of peers) {
    const card = document.createElement('div')
    card.className = 'transfer-device'
    // R128 §5 — the chosen device card is HIGHLIGHTED (accent border + tint).
    if (state.selectedPeerId === peer.deviceId) card.classList.add('chosen')

    const main = document.createElement('div')
    main.className = 'transfer-device-main'
    const name = document.createElement('span')
    name.className = 'transfer-device-name'
    // R127 §4 (the CEO's S6 — every device card names itself completely):
    // the self-declared device type rides the projection (R113) — the card
    // shows the type icon beside the name, the Direct-Share card's
    // completeness on the chain's own tab.
    const typeIcon = peer.deviceType === 'phone' ? '📱' : peer.deviceType === 'tablet' ? '📲' : peer.deviceType === 'computer' ? '💻' : ''
    name.textContent = (typeIcon ? typeIcon + ' ' : '') + (peer.label || msg('transferDeviceUnknown', undefined, 'Device'))
    const pick = document.createElement('button')
    pick.type = 'button'
    pick.className = 'btn btn-outline btn-sm transfer-device-pick'
    pick.dataset.peerId = peer.deviceId
    pick.textContent = state.selectedPeerId === peer.deviceId
      ? msg('transferChosen', undefined, 'Chosen')
      : msg('transferPickDevice', undefined, 'Choose')
    pick.setAttribute('aria-pressed', String(state.selectedPeerId === peer.deviceId))
    pick.addEventListener('click', () => {
      state.selectedPeerId = peer.deviceId
      rememberPeer(peer.deviceId)
      renderDeviceList(renderDeviceList.peers || peers)
      // R128 §5 (the CEO's S4 — the inverted flow, law 0.30): the device
      // choice ADVANCES the flow — with no file yet chosen, the file card
      // glows once, guiding the eye to the next (and last) action.
      if (!state.file) highlightFileCard()
    })
    main.appendChild(name)
    main.appendChild(pick)
    card.appendChild(main)

    const stLine = document.createElement('p')
    stLine.className = 'transfer-device-state'
    // R81-F1: THREE truthful presence states — a fresh advertisement is
    // "Available", an aging one is "Presence may be stale" (device locked or
    // unreachable — never a live claim), and anything else is "Offline".
    // R127 (law 0.41 — presence ENRICHES, never gates): an offline chain
    // member that self-declared a cloud sync reads the honest annotation —
    // the rendezvous's absence never erases the member from the family.
    // R132 (law 0.46 — THE PRESENCE-HONESTY LAW; the CEO's S1): when this
    // transport carries NO rendezvous, "Offline — last synced via cloud" is
    // a LIE about a live device — the honest annotation is "Online status
    // unknown — this chain's cloud doesn't support live presence — last
    // synced N ago". The 'offline' wording now renders ONLY when the
    // rendezvous capability exists and says so.
    if (peer.online && peer.availableUntil && !peer.stale) {
      stLine.textContent = msg('transferDeviceAvail', [fmtTime(peer.availableUntil)], 'Available until $TIME$')
    } else if (peer.online && peer.stale) {
      stLine.textContent = msg('transferDeviceStale', undefined, 'Presence may be stale — device locked or unavailable')
    } else if (rendezvousAvailableHere()) {
      // The rendezvous exists and says offline — the truthful offline line.
      stLine.textContent = peer.syncAt
        ? msg('transferDeviceOfflineCloud', [fmtTime(peer.syncAt)], 'Offline — last synced via cloud ($TIME$)')
        : msg('transferDeviceOffline', undefined, 'Offline')
    } else if (peer.syncAt) {
      stLine.textContent = msg('transferDevicePresenceUnknown', [fmtTime(peer.syncAt)], 'Online status unknown — this chain\u2019s cloud doesn\u2019t support live presence — last synced $TIME$')
    } else {
      stLine.textContent = msg('transferDevicePresenceUnknownBare', undefined, 'Online status unknown — this chain\u2019s cloud doesn\u2019t support live presence')
    }
    card.appendChild(stLine)

    const idLine = document.createElement('p')
    idLine.className = 'transfer-device-id'
    idLine.textContent = shortId(peer.deviceId)
    card.appendChild(idLine)

    list.appendChild(card)
  }
  // R123 §2.4 — the Send button's label follows the selection.
  updateSendButtonLabel()
}

// --- Sender: file choice + limits (worker is the authoritative gate) ----------------

async function onFileChosen() {
  const input = $('transferFile')
  const confirmBox = $('transferSendConfirm')
  state.file = null
  state.fileSha = ''
  $('transferSendBtn').disabled = true
  confirmBox.textContent = ''
  show(confirmBox, false)
  // R108 §5.2 — a fresh file choice clears a stale "Send another" button.
  document.getElementById('transferSendAnotherBtn')?.remove()
  const f = input && input.files && input.files[0]
  if (!f) return

  const limits = (state.status && state.status.limits) || {}
  const defaultLimit = Number(limits.defaultLimit) || 20 * 1024 * 1024
  const hardCap = Number(limits.hardCap) || 100 * 1024 * 1024
  // Instant truthful pre-check with the WORKER's own limit numbers; the
  // authoritative gate runs again inside TRANSFER_CREATE_OFFER.
  if (f.size > hardCap) {
    showConfirmError(msg('transferErrHardCap', undefined, 'Files over 100 MB are refused — pick a smaller file.'))
    return
  }
  if (f.size > defaultLimit) {
    showConfirmError(msg('transferErrOverLimit', undefined, 'This file is over the 20 MB default limit of this release.'))
    return
  }
  if (f.size === 0) {
    showConfirmError(msg('transferErrEmpty', undefined, 'That file has no content.'))
    return
  }

  try {
    // SHA-256 of the exact bytes on offer — computed HERE, sent to the worker
    // inside the sealed offer; the receiver re-derives and compares it.
    const buf = await f.arrayBuffer()
    const digest = await crypto.subtle.digest('SHA-256', buf)
    state.fileSha = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
    state.file = f
  } catch {
    state.file = null
    showConfirmError(msg('transferFileReadFailed', undefined, 'The file could not be read. Choose it again.'))
    return
  }

  confirmBox.textContent = ''
  const head = document.createElement('p')
  head.textContent = msg('transferConfirmReady', undefined, 'Ready to offer:')
  confirmBox.appendChild(head)
  const rows = document.createElement('p')
  rows.className = 'mono'
  rows.textContent = `${state.file.name} · ${humanSize(state.file.size)}`
  confirmBox.appendChild(rows)
  const shaLine = document.createElement('p')
  shaLine.className = 'mono'
  shaLine.textContent = msg('transferShaShort', [shortSha(state.fileSha)], 'SHA-256: $SHA$') + ' ' + state.fileSha
  confirmBox.appendChild(shaLine)
  show(confirmBox, true)
  $('transferSendBtn').disabled = false
}

function showConfirmError(text) {
  const confirmBox = $('transferSendConfirm')
  confirmBox.textContent = text
  show(confirmBox, true)
}

// --- Sender: offer + RTC + chunk pump -------------------------------------------------

// --- R81-F2/F3: ONE terminal cleanup + ONE stage ladder for the sender ------------

/**
 * Render the user-visible ladder stage (owner order R81-F3). The text comes
 * from real worker/session/data-channel events — never from guessed timers.
 * The transferring stage shows live byte progress in the same line.
 */
function setSendStage(stage, detailText) {
  const active = state.activeSend
  if (active) {
    active.stage = stage
    active.stageEnteredAt = Date.now()
  }
  const lines = {
    // R95 F-95-05 (filed P4): every waiting/connecting state names what
    // happens next and the typical duration (the EN fallbacks stay byte-stable
    // with the locale catalogs — the drift gates pin both).
    [SEND_STAGES.PREPARING]: () => msg('transferStagePreparing', undefined, 'Preparing secure transfer'),
    [SEND_STAGES.REQUEST_PUBLISHED]: () => msg('transferStageRequestPublished', undefined, 'Sending encrypted request — a moment, then the receiver decides'),
    [SEND_STAGES.WAITING_ANSWER]: () => msg('transferStageWaitingAnswer', undefined, 'Waiting for receiver approval — the other device shows a dialog; this usually resolves within seconds and expires safely if the receiver is not open'),
    [SEND_STAGES.CONNECTING]: () => msg('transferStageNegotiating', undefined, 'Receiver accepted — negotiating connection (usually under 10 seconds)'),
    [SEND_STAGES.CONNECTED]: () => detailText || msg('transferStageConnectedUnknown', undefined, 'Connected securely — route type unavailable'),
    [SEND_STAGES.TRANSFERRING]: () => detailText || '',
    [SEND_STAGES.VERIFYING]: () => msg('transferStageVerifying', undefined, 'Verifying received file'),
  }
  const render = lines[stage]
  if (render) setSendText(render())
}

// --- R123 §2.4 (law 0.37) — THE WAITING COUNTDOWN + THE WEDGE TRUTH ------
// The waiting-for-answer state renders a live countdown from the offer's
// own expiresAt (the worker's sealed record — the SAME TTL the mailbox
// enforces, so the number never lies), with the target's NAME in the line
// and the offline truth when the target's presence is gone:
//   reachable:  "Waiting for helium to answer — 9:41 left"
//   offline:    "Waiting for helium to answer — 9:41 left · helium isn't
//                reachable right now; delivery is confirmed here the moment
//                helium reads the offer."
// Every second says what the flow is waiting for and what happens if it
// never comes — no silent stall (the wedge states get their typed
// terminals with the one-click recovery below).
let waitTicker = null
function fmtWaitLeft(expiresAt, now = Date.now()) {
  const end = Date.parse(String(expiresAt || ''))
  if (!Number.isFinite(end)) return { text: '', expired: true }
  const leftMs = Math.max(0, end - now)
  const mm = Math.floor(leftMs / 60000)
  const ss = String(Math.floor((leftMs % 60000) / 1000)).padStart(2, '0')
  return { text: `${mm}:${ss}`, expired: leftMs <= 0 }
}
function renderWaitCountdown() {
  const active = state.activeSend
  if (!active || active.terminal || active.stage !== SEND_STAGES.WAITING_ANSWER) return
  const cd = fmtWaitLeft(active.offerExpiresAt)
  if (cd.expired) return // the watchdog's EXPIRED terminal owns the next word
  const who = active.peerLabel || msg('transferDeviceUnknown', undefined, 'the other device')
  const line = active.peerReachable === false
    ? msg('transferWaitOffline', [who, cd.text],
        `Waiting for $1 to answer — $2 left · $1 isn't reachable right now; delivery is confirmed here the moment their device reads the offer.`)
    : msg('transferWaitCountdown', [who, cd.text], `Waiting for $1 to answer — $2 left`)
  setSendText(line)
}
function startWaitCountdown() {
  stopWaitCountdown()
  waitTicker = setInterval(() => { try { renderWaitCountdown() } catch { /* never fatal */ } }, 1000)
}
function stopWaitCountdown() {
  if (waitTicker) { clearInterval(waitTicker); waitTicker = null }
}

/**
 * R81-F2 — THE one idempotent sender terminal cleanup. EVERY terminal path
 * goes through here (completion, decline, cancel local/peer, connection
 * failure, channel error, pump error, expiry, lock, pagehide). The cleanup
 * plan is pure (lifecycle.js); running it twice is a no-op. After cleanup the
 * UI is READY again: controls re-enabled, a typed localized next action
 * shown, no orphan resources, and the next send creates a FRESH transfer id,
 * capability nonce, ephemeral keys and offer (worker enforces the fresh
 * session — this page only ever starts new ones).
 */
function finishSend(outcome, textKey, subs, fallbackText, { silentToast = false } = {}) {
  const active = state.activeSend
  if (!active) return // idempotent: nothing active — nothing to clean
  const plan = cleanupPlan(String(outcome || TRANSFER_STATES.FAILED))
  active.terminal = true
  active.outcome = plan.reason
  stopSendWatchdog()
  stopWaitCountdown() // R123 §2.4 — the countdown never outlives its flow
  // R128 §3 — the fast answer poll never outlives its flow either.
  state.activeSendAwaitingAnswer = false
  if (fastAnswerTimer) { clearTimeout(fastAnswerTimer); fastAnswerTimer = null }
  try { if (active.channel) active.channel.close() } catch { /* already closed */ }
  try { if (active.pc) active.pc.close() } catch { /* already closed */ }
  active.file = null // drop the File reference; buffers die with the objects
  state.activeSend = null
  // Worker-side terminal cleanup too (never a bare wipe — the worker runs
  // terminalCleanup so its one-active-send gate opens and the ledger records).
  worker({ type: 'TRANSFER_CANCEL', transferId: active.transferId }).catch(() => { /* worker may be gone */ })
  // Restore ready controls + truthful typed message (non-secret, localized).
  // R83: the copy comes from THE typed terminal-copy map (lifecycle.js) —
  // every terminal outcome carries its recovery action; a caller-supplied
  // textKey/fallback still wins for special cases (locked, peer cancel).
  show($('transferSendProgressCard'), true)
  // R123 §2.4b: the code's afterlife. A FILLED field stays on every terminal
  // (it is the record of the channel this transfer used — Delivered, failed
  // mid-stream, cancelled: the evidence persists, law 0.25). A field that
  // never filled (expired / declined / dead before any answer) retires with
  // the flow — no empty promise lingers under a terminal that explains why.
  const fpAfter = String($('transferFingerprintSender')?.textContent || '').trim()
  if (!/^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$/.test(fpAfter)) {
    show($('transferFingerprintSenderBox'), false)
  }
  show($('transferFingerprintSenderNote'), false)
  const typed = terminalResultFor(outcome)
  const text = textKey
    ? msg(textKey, subs, fallbackText || '')
    : msg(typed.key, undefined, typed.fallback)
  setSendText(text)
  const btn = $('transferSendBtn')
  if (btn) btn.disabled = !state.file
  if (!silentToast && text) toast(text, outcome === TRANSFER_STATES.COMPLETED ? 'ok' : 'info')
  // R108 §5.2 (the CEO's S3 — the tightened default path): after a verified
  // delivery the ONE next action is one press away — "Send another" resets
  // to the file step (the last-device memory keeps the target picked). The
  // sender was already READY (R81-F2); this makes the ready state a door,
  // not a dead end. A user-action button — nothing auto-dismisses (0.8).
  if (outcome === TRANSFER_STATES.COMPLETED) {
    const row = $('transferCancelSender')?.parentElement
    if (row && !row.querySelector('#transferSendAnotherBtn')) {
      const again = document.createElement('button')
      again.id = 'transferSendAnotherBtn'
      again.className = 'btn btn-outline btn-sm'
      again.type = 'button'
      again.textContent = msg('transferSendAnother', undefined, 'Send another file')
      again.addEventListener('click', () => {
        const inp = $('transferFile')
        if (inp) inp.value = ''
        state.file = null
        state.fileSha = ''
        const cb = $('transferSendConfirm')
        if (cb) { cb.textContent = ''; show(cb, false) }
        const b = $('transferSendBtn')
        if (b) b.disabled = true
        show($('transferSendProgressCard'), false)
        const view = $('viewSend')
        if (view) view.scrollIntoView({ behavior: 'smooth', block: 'start' })
        again.remove()
      })
      row.appendChild(again)
    }
  }
  // R123 §2.4 (law 0.37) — THE WEDGE'S ONE-CLICK RECOVERY: an offer that
  // expired (the receiver never answered within the TTL) leaves a "Send
  // again" button — the file and the target are still staged; one press
  // re-sends (a FRESH offer, a fresh TTL). The typed terminal names the
  // fix; the button IS the fix.
  if (outcome === TRANSFER_STATES.EXPIRED) {
    const row = $('transferCancelSender')?.parentElement
    if (row && !row.querySelector('#transferSendAnotherBtn')) {
      const retry = document.createElement('button')
      retry.id = 'transferSendAnotherBtn'
      retry.className = 'btn btn-primary btn-sm'
      retry.type = 'button'
      retry.textContent = msg('transferSendAgain', undefined, 'Send again')
      retry.addEventListener('click', () => {
        retry.remove()
        createAndSendOffer().catch(() => {})
      })
      row.appendChild(retry)
    }
  }
}

/**
 * R81-F3 — watchdog tick: convert any breached stage deadline into a typed
 * terminal state through the SAME finishSend cleanup. Waiting-for-answer
 * breaches are an EXPIRED outcome; every other breach is a FAILED outcome.
 */
function checkSendWatchdog() {
  const active = state.activeSend
  if (!active || active.terminal) return
  const verdict = evaluateStageWatchdog({
    stage: active.stage,
    enteredAt: active.stageEnteredAt,
    lastProgressAt: active.lastProgressAt || 0,
  })
  if (!verdict.breached) return
  if (verdict.terminalOutcome === SEND_TERMINAL_OUTCOMES.EXPIRED) {
    finishSend(TRANSFER_STATES.EXPIRED, 'transferTermExpired', undefined,
      'Request expired — the other device did not respond in time. Request the transfer again.')
  } else {
    finishSend(TRANSFER_STATES.FAILED, 'transferFailNoRoute', undefined,
      'Could not establish a direct route — the transfer stopped safely. Try again.')
  }
}

/**
 * R81-F3 — route truth from WebRTC stats. 'direct' ONLY when the selected
 * pair provably uses host↔host candidates; 'relay' for a relay pair; and
 * when the stats cannot prove the route, the UI says exactly that.
 */
async function routeClassification(pc) {
  try {
    const report = await pc.getStats()
    const pairs = []
    const candidates = new Map()
    report.forEach((e) => {
      if (!e || typeof e !== 'object') return
      if (e.type === 'candidate-pair') pairs.push(e)
      else if (e.type === 'local-candidate' || e.type === 'remote-candidate') {
        candidates.set(e.id, { candidateType: e.candidateType })
      }
    })
    return classifyRoute(pairs, candidates)
  } catch {
    return 'unavailable'
  }
}

function connectedStageText(route) {
  if (route === 'direct') return msg('transferStageConnectedDirect', undefined, 'Connected directly')
  if (route === 'relay') return msg('transferStageConnectedRelay', undefined, 'Connected through your configured relay')
  return msg('transferStageConnectedUnknown', undefined, 'Connected securely — route type unavailable')
}

async function createAndSendOffer() {
  if (state.activeSend) {
    // R101 (F-R100-2): the busy gate asks the worker FIRST — when it confirms
    // no in-flight sender transfer, the page's stale sender state clears (the
    // typed interrupted note renders) and the send proceeds WITHOUT a reload.
    const cleared = await clearStaleSenderIfWorkerIdle()
    if (!cleared) { toast(msg('transferSendBusy', undefined, 'A transfer is already in progress on this device.'), 'error'); return }
  }
  if (!state.file || !state.selectedPeerId) {
    toast(msg('transferSendMissing', undefined, 'Choose the other device and a file first.'), 'error')
    return
  }
  let pc = null
  let channel = null
  try {
    if (locked()) throw keyed({ ok: false, error: 'locked', userMessageKey: 'transferErrLocked' })

    setSendStage(SEND_STAGES.PREPARING)
    show($('transferSendProgressCard'), true)
    // R123 §2.4b (the CEO's S4b — Screenshot_20261014_195259): the code field
    // is on screen from the FIRST motion of the flow — the offer's creation.
    // LAW 0.50 (R133) — the code is NO LONGER a placeholder that waits: the
    // FILE CODE (derived from the offer's sha256, the data both sides hold at
    // offer time) fills the field the instant the file is picked — the SAME
    // code the receiver's decision modal shows (zero copying, zero waiting).
    // The transcript-derived fingerprint still takes the field when the
    // answer lands (the congruency chip flips — R128 §3).
    show($('transferFingerprintSenderBox'), true)
    const fpPlaceholder = $('transferFingerprintSender')
    if (fpPlaceholder && state.fileSha) {
      fpPlaceholder.textContent = offerDisplayCode(state.fileSha)
      fpPlaceholder.classList.remove('waiting')
      fpPlaceholder.classList.add('set')
    }
    const fpWaitChip = $('transferFpWaitChip')
    if (fpWaitChip) fpWaitChip.classList.add('hidden')
    const fpOkChip = $('transferFpOkChip')
    if (fpOkChip) fpOkChip.classList.add('hidden')
    show($('transferFingerprintSenderNote'), true)
    {
      const note = $('transferFingerprintSenderNote')
      if (note) note.textContent = msg('transferFingerprintFileCodeNote', undefined,
        'This file code also shows in the accept dialog on their device — compare the two when the transfer starts.')
    }
    state.activeSendAwaitingAnswer = true
    startFastAnswerPoll() // R128 §3 — the code crosses within moments of the accept

    // NO relay (owner order): host candidates only, no STUN/TURN third party.
    pc = new RTCPeerConnection({ iceServers: [] })
    // ordered + reliable (the defaults) — a gap would fail the strict
    // expectedSeq ingest on the receiver, so the channel MUST be reliable.
    channel = pc.createDataChannel('ucrypt-xfer', { ordered: true })
    channel.binaryType = 'arraybuffer'

    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    await waitIceGathering(pc, GATHER_CAP_MS)

    const res = await worker({
      type: 'TRANSFER_CREATE_OFFER',
      to: state.selectedPeerId,
      file: { name: state.file.name, size: state.file.size, sha256hex: state.fileSha },
      sdp: pc.localDescription.sdp,
    })
    if (!res.ok) throw keyed(res)

    state.activeSend = {
      transferId: res.transferId,
      pc,
      channel,
      file: state.file,
      size: state.file.size,
      totalChunks: Math.ceil(state.file.size / CHUNK_BYTES), // matches the worker's offer schema
      // R79 (F-R78-8): the REAL recipient — cancelSend needs it to publish a
      // signed cancel record the receiver can actually act on.
      peerId: state.selectedPeerId,
      cancelled: false,
      done: false,
      terminal: false,
      // R81-F3 ladder bookkeeping (deadlines enforced by the watchdog).
      stage: SEND_STAGES.PREPARING,
      stageEnteredAt: Date.now(),
      lastProgressAt: 0,
    }
    wireSenderConnection(pc, channel)
    startSendWatchdog()

    // R123 §2.4 (law 0.37 — THE FLOW-COMPLETION LAW; the CEO's S4) — the
    // waiting state says what it's waiting for and shows the offer's own
    // TTL as a live countdown: "Waiting for helium to answer — 9:41 left".
    // The offline truth rides the same line: an OFFLINE/stale target names
    // WHY nothing may come (delivery confirms the moment their device reads
    // the offer — the honest mailbox law's receipt rides the notice line).
    // The wedge never stalls silently.
    state.activeSend.offerExpiresAt = (res.record && res.record.expiresAt) || new Date(Date.now() + 10 * 60 * 1000).toISOString()
    const selPeer = (renderDeviceList.peers || []).find((p) => p.deviceId === state.selectedPeerId)
    state.activeSend.peerLabel = (selPeer && (selPeer.label || '')) || ''
    state.activeSend.peerReachable = !!(selPeer && selPeer.online && !selPeer.stale)
    startWaitCountdown()

    setSendProgress(0, state.activeSend.size)
    setSendStage(SEND_STAGES.REQUEST_PUBLISHED)

    // Publish the sealed offer to the peer's mailbox (cloud) — failure stages
    // the SAME record for the manual copy/paste surface (always available).
    // R89 (F-R89-MANUAL-1): the staged offer CONTINUES the send (manual is a
    // first-class fallback) — the send genuinely waits for the answer wherever
    // it comes from, so a publish failure must not kill the session.
    await publishSignal(res.record, state.selectedPeerId, res.recordB64, { manualContinue: true })
    // R123 §2.4 — the waiting line RENDERS (with the countdown + the target's
    // name + the offline truth) — the offer is out; the state says exactly
    // what it's waiting for and for how long.
    renderWaitCountdown()
    setSendStage(SEND_STAGES.WAITING_ANSWER)
  } catch (e) {
    try { if (pc) pc.close() } catch { /* already closed */ }
    try { if (channel) channel.close() } catch { /* already closed */ }
    // R81-F2: ANY failure on this path — including a failed cloud publish —
    // must leave the sender READY, never permanently busy. The terminal
    // cleanup restores controls and shows the typed recovery action.
    if (e && e.workerCode === 'locked') {
      state.activeSend = null
      stopSendWatchdog()
      handleVaultLockedLocally()
      return
    }
    if (state.activeSend) {
      finishSend(TRANSFER_STATES.FAILED, null, undefined, errorText(e))
    } else {
      stopSendWatchdog()
      show($('transferSendProgressCard'), false)
      toast(errorText(e), 'error')
    }
  }
}

function wireSenderConnection(pc, channel) {
  pc.onicecandidate = (e) => { if (e.candidate) collectCandidate(pc, e.candidate) }
  pc.onconnectionstatechange = () => {
    if (!state.activeSend || state.activeSend.pc !== pc) return
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      // R81-F2: a failed negotiation is TERMINAL — cleanup + recovery action,
      // never a stuck "connecting" line.
      if (!state.activeSend.terminal && !state.activeSend.done) {
        finishSend(TRANSFER_STATES.FAILED, 'transferFailNoRoute', undefined,
          'Could not establish a direct route — the transfer stopped safely. Try again.')
      }
    } else if (pc.connectionState === 'connected') {
      // R81-F3: the route label comes from getStats() proof, never a guess.
      routeClassification(pc).then((route) => {
        if (state.activeSend && state.activeSend.pc === pc && !state.activeSend.terminal) {
          state.activeSend.route = route
          if (state.activeSend.stage === SEND_STAGES.CONNECTING) setSendStage(SEND_STAGES.CONNECTED, connectedStageText(route))
        }
      }).catch(() => { /* route stays 'unavailable' — truthful copy */ })
    }
  }
  channel.onopen = () => {
    const active = state.activeSend
    if (!active || active.terminal) return
    // Route re-check once the channel is live (stats settle after connect).
    routeClassification(pc).then((route) => {
      if (state.activeSend && state.activeSend.pc === pc && !state.activeSend.terminal) {
        state.activeSend.route = route
        if (active.stage === SEND_STAGES.CONNECTING || active.stage === SEND_STAGES.CONNECTED) {
          setSendStage(SEND_STAGES.CONNECTED, connectedStageText(route))
        }
      }
    }).catch(() => { /* truthful 'unavailable' copy stays */ })
    pumpFile().catch(() => { /* handled inside */ })
  }
  channel.onerror = () => {
    const active = state.activeSend
    if (active && !active.terminal && !active.done) {
      finishSend(TRANSFER_STATES.FAILED, 'transferFailNoRoute', undefined,
        'Could not establish a direct route — the transfer stopped safely. Try again.')
    }
  }
}

/**
 * Read the File slice-by-slice (16 KiB), have the worker seal each chunk
 * (AES-256-GCM, canonical AAD), and push the JSON frame over the data channel.
 *
 * R79 (F-R78-2, P1): ONE strictly sequential pump. The 16-lane parallel pump
 * raced chunk sealing against channel.send, so frames could LEAVE in
 * promise-resolution order while the receiver enforces strictly increasing
 * seq — any reordering was a fatal gap. The v1 protocol chooses safety and
 * simplicity: seal chunk i, send chunk i (after the channel drains below the
 * low-water mark), THEN seal chunk i+1. The channel is ordered+reliable;
 * backpressure is honored via bufferedAmountLowThreshold, memory stays flat,
 * and progress reports bytes actually handed to a drained channel.
 */
async function pumpFile() {
  const active = state.activeSend
  if (!active || !active.channel || active.channel.readyState !== 'open') return
  const { file, size, totalChunks, channel, transferId } = active
  channel.bufferedAmountLowThreshold = CHANNEL_LOW_WATER
  const waitDrain = () => new Promise((resolve) => {
    // Poll backstop guarantees liveness even if the bufferedamountlow event
    // is missed (or the channel closes mid-wait — send() below then throws
    // and the terminal state surfaces truthfully).
    const t = setTimeout(resolve, 25)
    try {
      channel.addEventListener('bufferedamountlow', () => { clearTimeout(t); resolve() }, { once: true })
    } catch { clearTimeout(t); resolve() }
  })
  try {
    for (let seq = 0; seq < totalChunks; seq++) {
      if (active.cancelled || active.terminal) return
      const start = seq * CHUNK_BYTES
      const buf = await file.slice(start, start + CHUNK_BYTES).arrayBuffer()
      const res = await worker({
        type: 'TRANSFER_SEAL_CHUNK',
        transferId,
        seq,
        totalChunks,
        totalBytes: size,
        bytesB64: bytesToBase64(new Uint8Array(buf)),
      })
      if (!res.ok) throw keyed(res)
      if (active.cancelled || active.terminal) return
      // Backpressure (owner order §1.3): never push while the SCTP buffer is
      // above the low-water mark — bounded memory, honest progress.
      while (!active.cancelled && !active.terminal && channel.readyState === 'open' && channel.bufferedAmount > CHANNEL_LOW_WATER) {
        await waitDrain()
      }
      if (active.cancelled || active.terminal) return
      channel.send(JSON.stringify(res.frame))
      // R81-F3: live progress IS the ladder's transferring stage, and it also
      // resets the inactivity deadline (progress = liveness proof).
      active.lastProgressAt = Date.now()
      setSendStage(SEND_STAGES.TRANSFERRING)
      setSendProgress(Math.min(size, (seq + 1) * CHUNK_BYTES), size)
    }
    if (active.cancelled || active.terminal) return
    active.done = true
    // All frames handed over — the RECEIVER verifies the digest now (bounded
    // VERIFYING deadline; the 'complete' record ends the transfer).
    setSendStage(SEND_STAGES.VERIFYING)
    // R83-F3: report the REAL verifying rung into the canonical session.
    worker({ type: 'TRANSFER_REPORT_STAGE', transferId: active.transferId, stage: TRANSFER_STATES.VERIFYING })
      .catch(() => { /* report is best-effort */ })
  } catch (e) {
    if (active.cancelled || active.terminal) return
    if (e && e.workerCode === 'locked') {
      finishSend(TRANSFER_STATES.CANCELLED, 'transferFailLocked', undefined,
        'Vault locked — transfer stopped. Nothing was saved on the other device.', { silentToast: true })
      handleVaultLockedLocally()
      return
    }
    // R81-F2: a pump error is TERMINAL — cleanup, ready controls, truthful
    // typed message. The sender can never get stuck here again.
    finishSend(TRANSFER_STATES.FAILED, null, undefined, errorText(e))
  }
}

async function handleAnswer(answer) {
  const active = state.activeSend
  if (!active || active.terminal || !answer || answer.transferId !== active.transferId) {
    return
  }
  if (answer.declined) {
    // R81-F2: a decline is TERMINAL — cleanup + "choose another device"
    // recovery action. NO cancel record is published (the receiver decided;
    // there is nothing to tell it).
    finishSend(TRANSFER_STATES.RECEIVER_DECLINED, 'transferTermDeclinedNext', undefined,
      'Receiver declined — choose another device or send a different file.')
    return
  }
  // R83: a restored session (page reload) has no RTCPeerConnection — the old
  // one died with the previous window and a WebRTC answer cannot be applied
  // to nothing. Truthful terminal cleanup instead of a silent limbo.
  if (!active.pc) {
    finishSend(TRANSFER_STATES.FAILED, 'transferRestoreConnLost', undefined,
      'The transfer window was reloaded — the direct connection ended. Nothing was harmed; start the transfer again.')
    return
  }
  // Prominent fingerprint on BOTH devices before/while the channel is used.
  // R123 §2.4b: the answer fills the field that has been waiting since the
  // offer — the waiting note retires (its promise kept), the code stays.
  // R128 §3 (the CEO's S5): the SET state is the prominent one — the pulse
  // stops, the code GROWS, the wait chip swaps for the ✓ congruency chip.
  show($('transferFingerprintSenderBox'), true)
  const senderFp = $('transferFingerprintSender')
  senderFp.textContent = String(answer.fingerprint || '')
  senderFp.classList.remove('waiting')
  senderFp.classList.add('set')
  const waitChip128 = $('transferFpWaitChip')
  if (waitChip128) waitChip128.classList.add('hidden')
  const okChip128 = $('transferFpOkChip')
  if (okChip128) okChip128.classList.remove('hidden')
  show($('transferFingerprintSenderNote'), false)
  state.activeSendAwaitingAnswer = false
  try {
    await active.pc.setRemoteDescription({ type: 'answer', sdp: String(answer.sdp || '') })
    drainRemoteCandidates(active.pc)
    // R81-F3: the ladder advances on the REAL answer event — deadline armed.
    setSendStage(SEND_STAGES.CONNECTING)
    // R83-F3: report the REAL connection rung into the canonical worker
    // session (event-derived state API — the page forwards events only).
    worker({ type: 'TRANSFER_REPORT_STAGE', transferId: active.transferId, stage: TRANSFER_STATES.CONNECTING })
      .catch(() => { /* report is best-effort; the ladder still renders */ })
  } catch { /* terminal states surface via connectionstatechange */ }
}

function handleComplete(transferId) {
  const active = state.activeSend
  if (!active || transferId !== active.transferId) return
  // R81-F2: verified delivery is TERMINAL — the sender is READY again for the
  // next transfer immediately (no reload, no stuck-busy session).
  finishSend(TRANSFER_STATES.COMPLETED, 'transferSendDoneConfirm', undefined,
    'Delivered — the other device verified the file.')
}

// --- Sender cancel ----------------------------------------------------------------------

/**
 * R81-F2: local/peer cancel → THE one terminal cleanup (finishSend), then a
 * best-effort signed cancel record so the peer's UI never waits on a dead
 * transfer. The LOCAL state is always destroyed first; the message stays
 * truthful about whether the peer was actually reached.
 */
async function cancelSend(byPeer = false, forcedText = '') {
  const active = state.activeSend
  if (!active) return
  const transferId = active.transferId
  const peerId = active.peerId
  const alreadyTerminal = !!active.terminal
  // Local terminal cleanup FIRST (idempotent; closes channel/pc, drops keys,
  // stops the watchdog, restores ready controls).
  finishSend(TRANSFER_STATES.CANCELLED, null, undefined,
    byPeer ? (forcedText || msg('transferSendCancelledByPeer', undefined, 'The sender cancelled the transfer.'))
           : msg('transferSendCancelled', undefined, 'Transfer cancelled.'),
    { silentToast: true })
  if (alreadyTerminal) return
  let peerNotified = false
  try {
    // R79 (F-R78-8): tell the peer (best-effort) so its UI never waits on a
    // dead transfer. The REAL recipient recorded at offer time is used.
    if (peerId) {
      const sealed = await worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'cancel', to: peerId, transferId, payload: {} })
      if (sealed.ok) {
        const pub = await worker({ type: 'TRANSFER_PUBLISH_RECORD', record: sealed.record, to: peerId })
        peerNotified = !!pub.ok
      }
    }
  } catch { /* local cancel stands regardless */ }
  if (byPeer) {
    const text = forcedText || msg('transferSendCancelledByPeer', undefined, 'The sender cancelled the transfer.')
    setSendText(text)
    toast(text)
  } else {
    // R79 (F-R78-8): the local state is ALWAYS destroyed; the message stays
    // truthful about whether the peer was actually reached.
    toast(peerNotified
      ? msg('transferSendCancelled', undefined, 'Transfer cancelled.')
      : msg('transferCancelNotNotified', undefined, 'Transfer cancelled on this device — the other device may not have been notified.'))
  }
}

// --- Receiver-side peer cancel -----------------------------------------------------------

function handlePeerCancel(transferId) {
  // Pending offer cards: truthful terminal state (B5 — decided by the PEER now).
  for (const rec of state.pendingOffers.values()) {
    if (rec.state === 'pending' && rec.offer.transferId === transferId) {
      rec.state = 'cancelled'
      setCardState(rec, msg('transferCardCancelledBySender', undefined, 'Cancelled by the sender.'))
    }
  }
  // Live receive: the worker already wiped the session — mirror it locally.
  if (state.activeRecv && state.activeRecv.transferId === transferId) {
    try { state.activeRecv.pc.close() } catch { /* already closed */ }
    state.activeRecv = null
    setRecvText(msg('transferRecvCancelledBySender', undefined, 'The sender cancelled the transfer. Nothing was saved.'))
    $('transferSaveBtn').disabled = true
  }
  const activeSend = state.activeSend
  if (activeSend && activeSend.transferId === transferId) {
    cancelSend(true, msg('transferSendCancelledByPeer', undefined, 'The sender cancelled the transfer.'))
  }
}

/**
 * R85 (F-R84-XFER-3): the receiver's DECLINE reaches the sender as its own
 * typed terminal — the R83-ordered copy ("Receiver declined — …"), never the
 * cancel family. Legacy wire form (cancel + reason:'declined') is mapped to
 * this terminal worker-side, so the UI only ever sees the truth.
 */
function handlePeerDecline(transferId) {
  if (!transferId) return
  // Pending offer cards: the decision was made by the receiver elsewhere —
  // for a sender-side card this transfer never had one; only the live send
  // path below carries the terminal copy.
  for (const rec of state.pendingOffers.values()) {
    if (rec.state === 'pending' && rec.offer.transferId === transferId) {
      rec.state = 'declined'
      setCardState(rec, msg('transferCardDeclined', undefined, 'Declined — the sender was notified. Nothing was saved.'))
    }
  }
  const activeSend = state.activeSend
  if (activeSend && activeSend.transferId === transferId && !activeSend.terminal) {
    finishSend(TRANSFER_STATES.RECEIVER_DECLINED, 'transferTermDeclinedNext', undefined,
      'Receiver declined — choose another device or send a different file.')
    toast(msg('transferTermDeclinedNext', undefined, 'Receiver declined — choose another device or send a different file.'))
  }
}

// --- ICE plumbing (non-secret transport metadata; SDP carries host candidates) ---------

const candidateBuffers = new WeakMap() // pc → RTCIceCandidateInit[] awaiting publish

function collectCandidate(pc, candidate) {
  const buf = candidateBuffers.get(pc)
  if (buf) buf.push(candidate.toJSON ? candidate.toJSON() : candidate)
}

/**
 * Publish gathered ICE candidates as sealed 'ice' records (cloud path). In the
 * common case the SDP already carries every host candidate, so this is a
 * robustness net (publish failures here are non-fatal — the SDP path works).
 */
async function publishIceCandidates(pc, transferId, to) {
  const buf = candidateBuffers.get(pc) || []
  candidateBuffers.delete(pc)
  for (const candidate of buf) {
    try {
      const res = await worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'ice', to, transferId, payload: { candidate: JSON.stringify(candidate) } })
      if (!res.ok) continue
      await worker({ type: 'TRANSFER_PUBLISH_RECORD', record: res.record, to })
    } catch { /* best-effort — see comment above */ }
  }
}

const pendingRemoteCandidates = new WeakMap() // pc → candidates that arrived early

function handleRemoteIce(ice) {
  if (!ice || !ice.candidate) return
  const pc = (state.activeRecv && state.activeRecv.transferId === ice.transferId && state.activeRecv.pc) ||
             (state.activeSend && state.activeSend.transferId === ice.transferId && state.activeSend.pc)
  if (!pc) return
  let init = null
  try { init = typeof ice.candidate === 'string' ? JSON.parse(ice.candidate) : ice.candidate } catch { return }
  if (pc.remoteDescription) {
    try { pc.addIceCandidate(init).catch(() => { /* unusable candidate — others may still connect */ }) } catch { /* same */ }
  } else {
    const list = pendingRemoteCandidates.get(pc) || []
    list.push(init)
    pendingRemoteCandidates.set(pc, list)
  }
}

function drainRemoteCandidates(pc) {
  const list = pendingRemoteCandidates.get(pc) || []
  pendingRemoteCandidates.delete(pc)
  for (const init of list) {
    try { pc.addIceCandidate(init).catch(() => { /* ignore */ }) } catch { /* ignore */ }
  }
}

function waitIceGathering(pc, capMs) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve()
    let done = false
    const finish = () => {
      if (done) return
      done = true
      pc.removeEventListener('icegatheringstatechange', onChange)
      clearTimeout(timer)
      resolve()
    }
    const onChange = () => { if (pc.iceGatheringState === 'complete') finish() }
    pc.addEventListener('icegatheringstatechange', onChange)
    // Honest cap: host-candidate gathering is local and fast; a hung gatherer
    // must never block the flow (the SDP still carries what was collected).
    const timer = setTimeout(finish, capMs)
  })
}

// --- Signaling publish + manual fallback -------------------------------------------------

/**
 * Cloud rendezvous first; ANY failure stages the exact sealed record for the
 * manual copy/paste surface (never a degraded or re-encoded variant).
 */
async function publishSignal(record, to, recordB64, opts = {}) {
  const res = await worker({ type: 'TRANSFER_PUBLISH_RECORD', record, to })
  if (res.ok) return { ok: true }
  // R79 (F-R78-7): the reason is localized through the response's OWN
  // userMessageKey — the old code string-built 'transferErr' + code, which
  // produced keys that exist in no locale and rendered raw error codes.
  stageManualSignal(recordB64 || '', res.error, res.userMessageKey)
  // R89 (F-R89-MANUAL-1): callers that opt into manualContinue treat the
  // staged record as a CONTINUING state (T1/T2: the manual copy/paste surface
  // is the transport-free fallback — the exact sealed record is copyable and
  // the flow stays alive). Callers without the opt keep the throw (the
  // pre-R89 contract) so best-effort notifies never mask failures.
  if (opts.manualContinue) return { ok: false, staged: true }
  throw keyed(res)
}

function stageManualSignal(b64, reasonCode, reasonKey) {
  state.manualSignal = String(b64 || '')
  renderManualMineBox()
  const out = $('transferManualResult')
  if (out && state.manualSignal) {
    const reason = reasonKey
      ? msg(reasonKey, undefined, reasonCode || 'error')
      : (reasonCode || 'error')
    out.textContent = msg('transferManualStaged', [reason],
      'Publishing failed — copy this signal below and paste it on the other device.')
  }
  // R98 (S8.8): the staged signal is ALSO mirrored into the paste box — the
  // user sees the exact bytes to hand-carry (and can copy them straight from
  // the box); the box's placeholder behavior is unchanged when nothing is staged.
  const inBox = $('transferManualIn')
  if (inBox && state.manualSignal && !inBox.value.trim()) {
    inBox.value = state.manualSignal
  }
}

async function copyManualSignal() {
  if (!state.manualSignal) {
    // R107: truthful guidance when the copy is empty — a HEALTHY cloud route
    // needs no hand-carry; an armed-but-unstaged window re-arms to stage.
    const st = state.status
    if (st && st.availability && st.availability.enabled && st.rendezvous && st.rendezvous.available !== false) {
      toast(msg('transferManualHealthyNoCarry', undefined,
        'Your cloud route is healthy — devices discover each other automatically. Manual copy is only needed when the route is down.'), 'info')
    } else {
      toast(msg('transferManualNothing', undefined, 'Nothing to copy yet — create an offer or accept one first.'), 'error')
    }
    return
  }
  try {
    await navigator.clipboard.writeText(state.manualSignal)
    // R107: the copy USED ends the pulse + confirms the leg truthfully.
    const btn = $('transferManualCopy')
    if (btn) btn.classList.remove('transfer-pulse')
    toast(msg('transferManualCopied', undefined, 'Signal copied — paste it on the other device.'))
  } catch {
    toast(msg('transferManualCopyFailed', undefined, 'The clipboard refused — select and copy the text manually.'), 'error')
  }
}

async function openManualSignal() {
  const input = $('transferManualIn')
  if (!input) return
  const signal = String(input.value || '').trim()
  if (!signal) {
    setManualResult(msg('transferManualEmpty', undefined, 'Paste a signal from the other device first.'))
    return
  }
  // R132 (law 0.47 — THE PASTE-GUIDANCE LAW): the typed identity renders
  // BEFORE the open attempt — the user always knows WHAT they pasted and
  // WHAT it will do. The wrong-order corrections refine with the page's
  // live state (awaiting a reply / awaiting an offer).
  const classification = refineForManualBox(
    classifyPastedSignal(signal, { selfId: (state.status && state.status.deviceId) || '' }),
    { awaitingReply: !!(state.activeSend && !state.activeSend.done), awaitingOffer: !state.activeSend },
  )
  if (classification.cls === PASTE_CLASSES.OWN_SIGNAL) {
    setManualResult(msg(classification.guidanceKey, undefined, classification.guidanceFallback))
    highlightManualCopy()
    return
  }
  if (classification.cls === PASTE_CLASSES.NOT_A_RECORD) {
    setManualResult(msg(classification.guidanceKey, undefined, classification.guidanceFallback))
    return
  }
  const res = await worker({ type: 'TRANSFER_OPEN_MANUAL', signal })
  if (!res.ok) {
    if (res.error === 'locked') { handleVaultLockedLocally(); return }
    setManualResult(errorText(keyed(res)))
    return
  }
  switch (res.kind) {
    case 'presence': {
      // R107 (F-R107-SELF-1): the worker types a self-signal truthfully —
      // the signal just pasted is THIS device's own carrier; it belongs on
      // the OTHER device's window. Never the old false "it now appears…".
      if (res.self || isSelfPresence(res.peer && res.peer.deviceId, state.status && state.status.deviceId)) {
        const guide = manualGuidance('self-signal')
        setManualResult(msg(guide.copyKey, undefined,
          'That is this device\'s OWN signal — the OTHER device needs it, not this one. Press Copy my signal and paste it there.'))
        highlightManualCopy()
        await refreshPeers()
        break
      }
      // R107 (F-R107-DISC-1): leg 1 landed — the reverse leg is NOW the
      // missing precondition, and the page says so with the one-click
      // affordance (the guided dance the CEO's hands proved nobody teaches).
      const guide = manualGuidance('peer-learned')
      const who = (res.peer && res.peer.label) || msg('transferDeviceUnknown', undefined, 'Device')
      setManualResult(msg(guide.copyKey, [who],
        'Device learned: $1$. Now let THEM see you — press Copy my signal and paste it on that device.'))
      highlightManualCopy()
      await refreshPeers()
      break
    }
    case 'offer':
      if (state.activeSend) {
        // R132 (law 0.47): invitation-when-expecting-reply — the typed
        // correction. This device SENT an offer and awaits THEIR reply; a
        // second invitation cannot advance anything. Never a silent dead end.
        setManualResult(msg('transferManualInviteExpectingReply', undefined,
          'This looks like an invitation — but this device is the SENDER here: you need THEIR reply, not another invitation.'))
        break
      }
      setManualResult(msg('transferManualOffer', undefined, 'Offer opened — decide below.'))
      addPendingOffer(res.offer)
      break
    case 'answer':
      if (state.activeSend && res.answer && res.answer.transferId === state.activeSend.transferId) {
        handleAnswer(res.answer)
        setManualResult(msg('transferManualAnswer', undefined, 'Answer applied — the transfer continues below.'))
      } else if (!state.activeSend) {
        // R132 (law 0.47): reply-without-offer — the typed correction the
        // CEO's S2 named. The reply is real, but the offer it answers was
        // never created HERE — the guided correction names Step 1.
        setManualResult(msg('transferManualReplyNoOffer', undefined,
          'This is a reply code, but you haven\u2019t created an offer yet — complete Step 1 first: press \u201CCopy my signal\u201D and send it to the other device.'))
        highlightManualCopy()
      } else {
        setManualResult(msg('transferManualNoMatch', undefined, 'No matching transfer on this device for this signal.'))
      }
      break
    case 'ice':
      handleRemoteIce(res.ice)
      setManualResult(msg('transferManualIce', undefined, 'Connection detail applied.'))
      break
    case 'cancel':
      handlePeerCancel(res.transferId)
      setManualResult(msg('transferManualCancel', undefined, 'The transfer was cancelled by the other device.'))
      break
    case 'decline':
      // R85 (F-R84-XFER-3): the manual path renders the same typed DECLINE
      // terminal as the poll path — one truth, both transports.
      handlePeerDecline(res.transferId)
      setManualResult(msg('transferManualDecline', undefined, 'The receiver declined the transfer.'))
      break
    case 'complete':
      // R89 (F-R89-MANUAL-1): the manual path delivers the sender's DELIVERED
      // terminal too — one truth, both transports (T5: DELIVERED = digest
      // match, learned here from the receiver's sealed completion record).
      handleComplete(res.transferId)
      setManualResult(msg('transferManualComplete', undefined, 'Completion applied — the transfer is marked Delivered.'))
      break
    default:
      setManualResult(msg('transferManualNoMatch', undefined, 'No matching transfer on this device for this signal.'))
  }
}

function setManualResult(text) {
  const el = $('transferManualResult')
  if (el) el.textContent = text
}

/** R107: the reverse-leg affordance — Copy my signal pulses until used. */
function highlightManualCopy() {
  const btn = $('transferManualCopy')
  if (!btn) return
  btn.classList.add('transfer-pulse')
  const zone = $('transferManualZone')
  if (zone) zone.open = true
  try {
    btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  } catch { /* scrolling is best-effort */ }
}

// --- R90 §5: INLINE UNLOCK (the locked dialog unlocks in place) ------------
// Law 0.8: no interactive UCrypt surface auto-dismisses — the unlock error
// is shown PERSISTENTLY (no auto-hide timer); success refreshes the dialog
// state in place and the send/receive surfaces return without navigation.

function showInlineUnlock() {
  const box = $('transferInlineUnlock')
  if (box) box.classList.remove('hidden')
}

function hideInlineUnlock() {
  const box = $('transferInlineUnlock')
  if (box) box.classList.add('hidden')
}

function resetInlineUnlockUi() {
  const input = $('transferUnlockPass')
  const err = $('transferUnlockErr')
  if (input) input.value = ''
  if (err) { err.classList.add('hidden'); err.textContent = '' }
}

async function inlineUnlock() {
  const input = $('transferUnlockPass')
  const err = $('transferUnlockErr')
  const pass = input ? input.value : ''
  if (err) { err.classList.add('hidden'); err.textContent = '' }
  if (!pass) {
    if (err) {
      err.textContent = msg('transferUnlockEmpty', undefined, 'Enter your master passphrase to unlock.')
      err.classList.remove('hidden')
    }
    return
  }
  const btn = $('transferUnlockBtn')
  if (btn) btn.disabled = true
  try {
    const res = await worker({ type: 'UNLOCK', passphrase: pass })
    if (res && res.ok) {
      // Success: reset the field, refresh the dialog state IN PLACE. The
      // worker broadcasts VAULT_UNLOCKED (which also triggers refreshStatus);
      // the explicit calls make the in-place refresh deterministic even if
      // the broadcast raced this response.
      resetInlineUnlockUi()
      hideInlineUnlock()
      await refreshStatus()
    } else {
      // Failure: the TYPED error, shown for as long as the user looks at it
      // (never auto-dismissed — law 0.8).
      if (err) {
        const raw = (res && (res.userMessage || res.error)) || 'The passphrase did not unlock the vault.'
        err.textContent = '✗ ' + String(raw).slice(0, 200)
        err.classList.remove('hidden')
      }
    }
  } catch (e) {
    if (err) {
      err.textContent = '✗ ' + String((e && e.message) || e).slice(0, 200)
      err.classList.remove('hidden')
    }
  } finally {
    if (btn) btn.disabled = false
  }
}

// --- Sender UI helpers ----------------------------------------------------------------------

function resetSendUi() {
  show($('transferSendProgressCard'), false)
  show($('transferFingerprintSenderBox'), false)
  setSendProgress(0, 1)
  setSendText('—')
  const btn = $('transferSendBtn')
  if (btn) btn.disabled = !state.file
  const input = $('transferFile')
  if (input && !state.file) input.value = ''
}

function setSendProgress(bytes, total) {
  const pct = total > 0 ? Math.min(100, Math.round((bytes / total) * 100)) : 0
  const fill = $('transferSendProgressFill')
  const bar = $('transferSendProgress')
  if (fill) fill.style.width = pct + '%'
  if (bar) bar.setAttribute('aria-valuenow', String(pct))
  // R92 §2.4 — PROGRESS TRUTH: the transferring line carries live SPEED
  // (bytes/second over a 5-second sliding window of real pump samples).
  // "Delivered" still appears ONLY on the receiver's digest verification —
  // a full bar is a full pipe, never a claim of delivery.
  const active = state.activeSend
  let speedText = ''
  if (active && total > 0) {
    if (!active.speedSamples) active.speedSamples = []
    active.speedSamples.push({ t: Date.now(), b: bytes })
    const cutoff = Date.now() - 5000
    while (active.speedSamples.length > 2 && active.speedSamples[0].t < cutoff) active.speedSamples.shift()
    const first = active.speedSamples[0]
    const dtMs = Date.now() - first.t
    if (dtMs > 900 && bytes >= first.b) {
      const bps = ((bytes - first.b) / dtMs) * 1000
      if (bps > 1) speedText = ' — ' + msg('transferSendSpeed', [humanSize(bps) + '/s'], '$SPEED$')
    }
  }
  setSendText(msg('transferSendProgressText',
    [humanSize(bytes), humanSize(total), String(pct)],
    '$SENT$ of $TOTAL$ ($PCT$%)') + speedText)
}

function setSendText(text) {
  const el = $('transferSendProgressText')
  if (el) el.textContent = text
}

// --- Base64 (local, no import cycle risk in the page) ----------------------------------------

function base64ToBytesLocal(b64) {
  const bin = atob(String(b64 || ''))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// --- Role selection -------------------------------------------------------------------------

function selectRole(role) {
  if (locked()) {
    toast(msg('transferErrLocked', undefined, 'Vault locked — unlock to use direct transfer.'), 'error')
    return
  }
  state.role = role
  show($('viewSend'), role === 'send')
  show($('viewReceive'), role === 'receive')
  // R85 (F-R84-XFER-2): BOTH views learn. The Receive view previously never
  // touched the peer map — a receiver whose map lacked the sender refused
  // every offer forever. refreshPeers() runs TRANSFER_LIST_PEERS, whose
  // presence pass learns the sender (replay-exempt, TOFU-disciplined).
  refreshPeers()
  refreshStatus()
}

// --- Options-page escape hatch -----------------------------------------------------------------

/**
 * R117 §3 (law 0.30) — THE OVERLAY STATUS PROVIDER: the ledger truth for
 * one transport, read from the SAME keys the options page's summary uses
 * (ucrypt:transport / ucrypt:lastPush / ucrypt:lastTest) — one source of
 * truth, never a divergent copy. The chooser cards' state lines and the
 * form headers render from this.
 */
async function transportStatusFor(id) {
  try {
    const store = await chrome.storage.local.get(['ucrypt:transport', 'ucrypt:lastPush', 'ucrypt:lastTest'])
    const saved = store['ucrypt:transport']
    if (!saved || saved.id !== id) return { configured: false }
    const lp = store['ucrypt:lastPush']
    const lt = store['ucrypt:lastTest']
    return {
      configured: true,
      lastPush: lp && lp.transportId === id ? lp : null,
      lastTest: lt && lt.transportId === id ? lt : null,
    }
  } catch { return { configured: false } }
}

/** ── R116 §2.3 (law 0.29; the CEO's S6) — THE IN-PLACE OVERLAY WRAPPERS ──
 *  The Discovery checklist's fix buttons open the flows AS OVERLAYS here —
 *  the configuration lives INSIDE File transfer (the CEO's exact words),
 *  with the old options deep-link surviving only as the overlays' demoted
 *  fallback row. The overlays refresh the checklist on save/join so the ✗
 *  row turns green in front of the user's eyes. R117 §2 (the CEO's S3):
 *  the TRIGGER row is passed so focus returns to the words that named the
 *  fix when the layer closes (law 0.13's keyboard path).
 */
function openConnectOverlayInPage(ev) {
  const trigger = ev && ev.currentTarget ? ev.currentTarget : null
  openConnectOverlay({
    worker,
    getTransport,
    getStatus: transportStatusFor,
    msg,
    trigger,
    onSaved: () => { refreshStatus().catch(() => {}) },
    onClose: () => { refreshStatus().catch(() => {}) },
    openFullSetup: () => { openOptions('sync') },
  })
}

function openJoinOverlayInPage(ev) {
  const trigger = ev && ev.currentTarget ? ev.currentTarget : null
  openJoinOverlay({
    worker,
    msg,
    trigger,
    onJoined: () => { refreshStatus().catch(() => {}) },
    onClose: () => { refreshStatus().catch(() => {}) },
    openFullSetup: () => { openOptions('sync') },
  })
}

/**
 * R107: the truth-panel deep links land on the RIGHT tab — 'sync' opens the
 * options page and switches to the Sync tab (the chain + cloud precondition
 * steps live there). The options tab is addressed DIRECTLY (tabs.sendMessage
 * with a bounded retry — the page binds its tabs a beat after load); the
 * options page owns the UCRYPT_OPTIONS_FOCUS_TAB listener. The plain form
 * keeps its old behavior.
 */
async function openOptions(targetTab) {
  try {
    await chrome.runtime.openOptionsPage()
  } catch {
    try { await chrome.tabs.create({ url: 'options.html' }) } catch { /* nothing else to try */ }
  }
  if (!targetTab) return
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 400))
    let tabs = []
    try { tabs = await chrome.tabs.query({ url: 'chrome-extension://*/options.html' }) } catch { /* query unavailable */ }
    const tab = tabs && tabs[0]
    if (!tab) continue
    try {
      await chrome.tabs.sendMessage(tab.id, { type: 'UCRYPT_OPTIONS_FOCUS_TAB', tab: targetTab })
      return
    } catch { /* the page has not bound its listener yet — retry */ }
  }
}

/**
 * R107 §2.5 — the joiner's completion checklist gains "Open direct transfer"
 * AND the origin's sheet after Accept — the message relay the deep links use:
 * the options page listens for UCRYPT_OPTIONS_FOCUS_TAB (additions-only).
 * The transfer window itself is opened through the worker's canonical
 * TRANSFER_OPEN_WINDOW (popup → tab fallback, the sealed law).
 */
async function openDirectTransferWindow() {
  const res = await worker({ type: 'TRANSFER_OPEN_WINDOW' })
  if (!res.ok) toast(errorText(keyed(res)), 'error')
}

// --- Availability ownership (R81-F1) ------------------------------------------------------

/**
 * R81-F1: the transfer page can OWN availability. When it does, closing the
 * window (pagehide) withdraws availability immediately — the worker (which
 * survives the page) performs the signed tombstone + best-effort delete and
 * stops the refresh cadence. The note element reports the TRUTHFUL result:
 * if the tombstone never reached the cloud, the copy says the presence may
 * remain visible until it expires — never a claimed withdrawal.
 * R107 §2.3: the SAME path arms the window's DEFAULT availability — the
 * auto-arm passes {auto:true} so the toast states the privacy truth (the
 * window's opening is the opt-in; Stop hides you instantly).
 */
async function enableAvailabilityHere({ auto = false } = {}) {
  if (locked()) { toast(msg('transferErrLocked', undefined, 'Vault locked — unlock to use direct transfer.'), 'error'); return }
  const res = await worker({ type: 'TRANSFER_ENABLE_AVAILABILITY', minutes: 10, label: '' })
  if (!res.ok) { toast(errorText(keyed(res)), 'error'); return }
  state.availabilityOwnedHere = true
  state.status = res
  renderStatus()
  noteStagedPresence(res)
  toast(auto
    ? msg('transferArmAuto', [fmtTime(res.availability && res.availability.expiresAt)],
        'This device is visible to your chain for 10 minutes (until $1$). Press Stop to hide it now — closing this window also hides it.')
    : msg('transferAvailEnabledHere', undefined, 'This device is available for 10 minutes.'), auto ? 'info' : 'ok')
  // R107 §2.4: with the arm in place, the manual zone renders its promotion
  // state (opened + truthful copy when no cloud route exists).
  promoteManualZone()
}

async function disableAvailabilityHere() {
  const res = await worker({ type: 'TRANSFER_DISABLE_AVAILABILITY' })
  state.availabilityOwnedHere = false
  if (res.ok) {
    state.status = res
    renderStatus()
    const wd = res.withdrawal || {}
    const note = $('transferAvailWithdrawNote')
    if (note) {
      note.textContent = wd.tombstoneOk
        ? msg('transferAvailWithdrawn', undefined, 'Availability withdrawn — other devices will no longer see this device as available.')
        : msg('transferAvailWithdrawFailed', undefined, 'Availability is off on this device, but the cloud update failed — other devices may still see this device until the record expires.')
    }
  }
}

// R81-F1 pagehide: the transfer window closing is an availability stop path
// (when the page owns it) AND a sender terminal event (the worker session
// must not linger and block the next send — the worker runs terminalCleanup).
// R133: the listener is WINDOW-GUARDED so the page's pure helpers (the
// battery's offerDisplayCode) import cleanly outside a browser too — in a
// browser this is exactly the same registration as before.
if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
window.addEventListener('pagehide', () => {
  try {
    if (state.activeSend) {
      // Fire-and-forget: the page may be dying; the worker cleans its side.
      chrome.runtime.sendMessage({ type: 'TRANSFER_CANCEL', transferId: state.activeSend.transferId }, () => { void chrome.runtime.lastError })
    }
    if (state.availabilityOwnedHere) {
      chrome.runtime.sendMessage({ type: 'TRANSFER_DISABLE_AVAILABILITY' }, () => { void chrome.runtime.lastError })
    }
  } catch { /* page is going away — nothing else to try */ }
})
}

// --- Wiring (no inline handlers anywhere — addEventListener only) ------------------------------

function wire() {
  $('transferRoleSend')?.addEventListener('click', () => selectRole('send'))
  $('transferRoleReceive')?.addEventListener('click', () => selectRole('receive'))
  // R136-F3 (class-b, fixed at the root): the button NAMED Cloud Sync
  // settings but landed on the options page's default tab — read by the
  // CEO as "does nothing". The hash-routable options page (options.html#sync,
  // the v2.3.0 law) takes the target explicitly; the focus message then
  // re-asserts the tab once the page is alive (openOptions' own retry).
  $('transferOpenSettings')?.addEventListener('click', () => { openOptions('sync') })
  // R138 §6 — the cross-reference LANDS on the surface it names: the Direct
  // Share deep link opens the options window exactly on the share tab.
  $('transferGoDirectShare')?.addEventListener('click', () => { openOptions('share') })
  // R90 §5 — the inline unlock: button click AND Enter in the field.
  $('transferUnlockBtn')?.addEventListener('click', inlineUnlock)
  $('transferUnlockPass')?.addEventListener('keydown', (ev) => {
    if (ev && ev.key === 'Enter') { ev.preventDefault(); inlineUnlock() }
  })
  $('transferRefreshPeers')?.addEventListener('click', refreshPeers)
  $('transferAvailEnable')?.addEventListener('click', enableAvailabilityHere)
  $('transferAvailDisable')?.addEventListener('click', disableAvailabilityHere)
  $('transferFile')?.addEventListener('change', onFileChosen)
  $('transferSendBtn')?.addEventListener('click', createAndSendOffer)
  $('transferCancelSender')?.addEventListener('click', () => cancelSend(false))
  // R85 (F-R84-XFER-2): the Receive view's refresh affordance now LEARNS too —
  // one press refreshes presence + the peer map (LIST_PEERS) and polls.
  $('transferPollNow')?.addEventListener('click', () => { refreshPeers(); pollTick(); refreshStatus() })
  $('transferSaveBtn')?.addEventListener('click', saveRecvFile)
  $('transferCancelReceiver')?.addEventListener('click', () => {
    const active = state.activeRecv
    if (active) {
      try { active.pc.close() } catch { /* already closed */ }
      state.activeRecv = null
      try {
        const from = (state.pendingOffers.get(active.offerId) || { offer: {} }).offer.from
        const sealed = worker({ type: 'TRANSFER_SEAL_RECORD', kind: 'cancel', to: from, transferId: active.transferId, payload: {} })
        sealed.then(async (res) => {
          if (res && res.ok && from) await worker({ type: 'TRANSFER_PUBLISH_RECORD', record: res.record, to: from })
        }).catch(() => { /* best-effort notice */ })
      } catch { /* best-effort notice */ }
      worker({ type: 'TRANSFER_CANCEL', transferId: active.transferId })
    }
    resetRecvUi()
    toast(msg('transferSendCancelled', undefined, 'Transfer cancelled.'))
  })

  // Decision dialog (modal is the PROMINENT surface; inline cards stay pending).
  $('transferDialogAccept')?.addEventListener('click', () => {
    const id = dialogOfferId
    closeDecisionDialog()
    acceptOffer(id)
  })
  $('transferDialogDecline')?.addEventListener('click', () => {
    const id = dialogOfferId
    closeDecisionDialog()
    declineOffer(id)
  })
  $('transferDialogOverlay')?.addEventListener('click', (e) => {
    if (e.target === $('transferDialogOverlay')) closeDecisionDialog()
  })
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('transferDialogOverlay').classList.contains('hidden')) {
      // Non-destructive: ESC closes the dialog; the decision card REMAINS
      // pending in the list (B5 — no dismissal without a decision).
      closeDecisionDialog()
    }
  })

  // Manual signaling fallback (both roles).
  $('transferManualOpen')?.addEventListener('click', openManualSignal)
  $('transferManualCopy')?.addEventListener('click', copyManualSignal)
  // R132 (law 0.47 — THE PASTE-GUIDANCE LAW; the CEO's S2): the paste is
  // CLASSIFIED AS IT LANDS — the typed identity + next action render while
  // the user is still looking at the box. A wrong-order paste is a guided
  // correction, never a silent wait for an Open that will fail.
  $('transferManualIn')?.addEventListener('input', () => {
    const box = $('transferManualIn')
    if (!box) return
    const t = String(box.value || '').trim()
    if (!t) { setManualResult(''); return }
    const classification = refineForManualBox(
      classifyPastedSignal(t, { selfId: (state.status && state.status.deviceId) || '' }),
      { awaitingReply: !!(state.activeSend && !state.activeSend.done), awaitingOffer: !state.activeSend },
    )
    if (classification.cls === PASTE_CLASSES.EMPTY) return
    setManualResult(msg(classification.guidanceKey, undefined, classification.guidanceFallback))
    if (classification.cls === PASTE_CLASSES.OWN_SIGNAL) highlightManualCopy()
    // LAW 0.50 (R133, the CEO's F6/F4 — the paste AUTO-ENABLES everything):
    // a valid OTHER-device signal pasted here is the receive intent itself —
    // availability arms (bounded, Stop one click away), the receive view
    // opens, the countdown shows. The user never hunts the Receive button
    // or the availability switch after a paste — the surface performs.
    const receiveIntent = ![PASTE_CLASSES.EMPTY, PASTE_CLASSES.OWN_SIGNAL, PASTE_CLASSES.NOT_A_RECORD].includes(classification.cls)
    if (receiveIntent) {
      if (state.role !== 'receive') selectRole('receive')
      const st = state.status
      if (st && !(st.availability && st.availability.enabled)) {
        enableAvailabilityHere({ auto: true }).catch(() => { /* the log row names it */ })
      }
    }
  })
  // R107 §2.3 — the auto-arm strip's one-click Stop (truthful withdrawal;
  // the same disable path the Receive tab has always owned).
  $('transferArmStop')?.addEventListener('click', () => { disableAvailabilityHere() })
  // LAW 0.52 (R133) — the toast's explicit close (the user's own exit).
  $('transferToastClose')?.addEventListener('click', () => {
    const el = $('transferToast')
    if (el) { clearTimeout(toast._t); show(el, false) }
  })
  // R107 §2.4 — the Advanced zone's summary is a real toggle; keep the
  // promotion copy from fighting the user's manual choice after first open.
  $('transferManualZone')?.addEventListener('toggle', () => {
    if ($('transferManualZone')?.open) {
      const promo = $('transferManualPromo')
      if (promo && !promo.textContent) {
        promo.textContent = msg('transferManualHealthyRoute', undefined,
          'Cloud route healthy — devices on your chain discover each other automatically; manual pairing is only needed when the cloud route is down.')
        show(promo, true)
      }
    }
  })
}

/**
 * R83 — canonical restore on page (re)load. The worker owns the transfer
 * state machine; this page NEVER invents a fresh idle UI over a live
 * session. Restored sessions render truthfully:
 *   sender waiting for the answer → stage line + working Cancel button
 *     (the stale request can be cancelled; the cloud answer path keeps
 *     working through the poll loop);
 *   sender past the answer (connecting/verifying/…) → the RTC channel died
 *     with the old page — truthful terminal cleanup, no auto-resume;
 *   receiver still holding verified plaintext → the export stays available
 *     (the worker holds the buffer) — restore the save surface;
 *   receiver save-pending tombstone → the export was already consumed —
 *     finish the session truthfully (if the download was lost, ask for a
 *     resend; one-time-read cannot be repeated).
 */
async function restoreActiveSession() {
  const res = await worker({ type: 'TRANSFER_ACTIVE_SESSION' })
  if (!res.ok || !res.activeSession) return // truthful idle — nothing to restore
  const s = res.activeSession
  if (s.role === 'sender') {
    if (s.state === TRANSFER_STATES.OFFER_SENT) {
      // A live offer waiting for its answer — restore the wait + cancel.
      state.activeSend = {
        transferId: s.transferId,
        pc: null,
        channel: null,
        file: null,
        size: s.offerSize || 0,
        totalChunks: 0,
        peerId: s.peerDeviceId || null,
        cancelled: false,
        done: false,
        terminal: false,
        stage: SEND_STAGES.WAITING_ANSWER,
        stageEnteredAt: Date.now(),
        lastProgressAt: 0,
      }
      startSendWatchdog()
      show($('transferSendProgressCard'), true)
      setSendStage(SEND_STAGES.WAITING_ANSWER)
      setSendProgress(0, s.offerSize || 1)
      toast(msg('transferRestoreWaiting', undefined, 'Previous transfer restored — still waiting for the other device to accept.'))
      return
    }
    // Past the answer the RTC channel belonged to the dead page: honest
    // terminal state (FAILED — connection lost), never a fake continuation.
    await worker({ type: 'TRANSFER_CANCEL', transferId: s.transferId }).catch(() => { /* idempotent */ })
    show($('transferSendProgressCard'), true)
    setSendText(msg('transferRestoreConnLost', undefined,
      'The transfer window was reloaded — the direct connection ended. Nothing was harmed; start the transfer again.'))
    return
  }
  // Receiver role.
  if (s.state === TRANSFER_STATES.VERIFYING) {
    // Verified plaintext still held by the worker — restore the save surface.
    state.activeRecv = {
      transferId: s.transferId,
      offerId: null,
      pc: null,
      saved: 'ready',
    }
    show($('transferRecvProgressCard'), true)
    setRecvProgress(null, null, 100)
    setRecvText(msg('transferRecvVerified', [shortSha(s.fingerprint || '')], 'Verified — SHA-256 matches the offer ($SHA$). Save the file when ready.'))
    $('transferSaveBtn').disabled = false
    toast(msg('transferRestoreSaveReady', undefined, 'Previous transfer restored — the verified file is ready to save.'))
    return
  }
  // Any other receiver state (pending/accepted/receiving/save-pending): the
  // connection or the one-time buffer did not survive the reload — truthful
  // terminal cleanup. A save-pending tombstone is closed with TRANSFER_FINISH.
  if (s.state === TRANSFER_STATES.RECEIVER_SAVE_PENDING) {
    await worker({ type: 'TRANSFER_FINISH', transferId: s.transferId }).catch(() => { /* idempotent */ })
    show($('transferRecvProgressCard'), true)
    setRecvText(msg('transferRestoreExported', undefined,
      'The earlier file was verified, but its one-time download did not complete in this window — ask the sender to resend.'))
    return
  }
  await worker({ type: 'TRANSFER_CANCEL', transferId: s.transferId }).catch(() => { /* idempotent */ })
  show($('transferRecvProgressCard'), true)
  setRecvText(msg('transferRestoreRecvLost', undefined,
    'The transfer window was reloaded — the direct connection ended. Nothing was saved; ask the sender to resend.'))
}

// --- Boot --------------------------------------------------------------------------------------

/**
 * R118 §2.1 — THE MODE PARAMETER (the CEO's S2; the two-tab world): the
 * transfer page carries ?mode=devices|share. The DEVICES mode (the default —
 * the standalone window and the existing embeds stay byte-behavioral) renders
 * the chain experience. The SHARE mode renders ONLY its own mode's surface —
 * a truthful shell that names its audience and carries the ONE-CLICK action
 * to the canonical door (the options page's Direct Share tab; law 0.26 — a
 * state never dead-ends, law 0.31 — one canonical door per capability, NO
 * cross-rendering: no devices section shows in share mode, and the devices
 * mode never renders share words).
 */
function transferPageMode() {
  try {
    const m = String(new URLSearchParams(location.search).get('mode') || '').toLowerCase()
    return m === 'share' ? 'share' : 'devices'
  } catch { return 'devices' }
}

function renderShareModeShell() {
  const main = $('transferMain')
  if (!main) return
  // The devices-mode sections NEVER render in share mode (no cross-rendering).
  for (const sel of ['.transfer-roles', '.transfer-truth', '#transferStatusCard',
    '#viewSend', '#viewReceive', '#transferManualZone', '.transfer-footer']) {
    for (const el of main.querySelectorAll(sel)) el.classList.add('hidden')
  }
  const hdr = $('transferWindowHeader')
  if (hdr) hdr.classList.add('hidden')
  // The share-mode shell: the audience-first words + the one-click door.
  const shell = document.createElement('section')
  shell.className = 'transfer-card transfer-share-shell'
  shell.id = 'transferShareShell'
  shell.setAttribute('aria-labelledby', 'transferShareShellHead')
  const h1 = document.createElement('h1')
  h1.id = 'transferShareShellHead'
  h1.textContent = msg('dsTabH1', undefined, 'File Transfer between UCrypt Users')
  const aud = document.createElement('p')
  aud.className = 'card-help'
  aud.style.margin = '6px 0 10px'
  aud.textContent = '🤝 ' + msg('dsDoorHelp', undefined,
    'No chain, no cloud, no account needed: they just need UCrypt. The code travels through any messenger; the security stays in the cryptography.')
  const row = document.createElement('div')
  row.className = 'btn-row'
  const openBtn = document.createElement('button')
  openBtn.type = 'button'
  openBtn.className = 'btn btn-primary'
  openBtn.id = 'transferShareShellOpen'
  openBtn.textContent = msg('tshOpenShareTab', undefined, 'Open Direct Share')
  openBtn.addEventListener('click', () => { openOptions('share') })
  const hint = document.createElement('p')
  hint.className = 'card-help'
  hint.style.margin = '8px 0 0'
  hint.textContent = msg('tshWhereLine', undefined,
    'Direct Share lives on its own tab in the main UCrypt window — this button opens it there.')
  row.appendChild(openBtn)
  shell.appendChild(h1)
  shell.appendChild(aud)
  shell.appendChild(row)
  shell.appendChild(hint)
  main.prepend(shell)
}

async function init() {
  // R108 §4.1 — THE EMBED MODE: the File-transfer tab hosts THIS experience
  // inside the options page (transfer.html?embed=1, same-origin iframe).
  // One experience, zero duplicated state (the worker owns it all); the body
  // class tightens the shell padding — every behavior is identical.
  try {
    // R145 §5.2 (the G-1 cure, WALL 2) — FRAMING FORCES EMBED MODE: the query
    // param is only the SECONDARY signal now. window.self !== window.top is
    // the structural proof of embedding — a Helium-class fork may strip or
    // rewrite the query, but it cannot un-frame a framed document. A framed
    // transfer page ALWAYS renders the bare surface (header hidden, embed
    // padding), no matter what the URL says.
    const em = embedMode(window, location.search)
    if (em.embed) {
      document.body.classList.add('transfer-embed')
      const hdr = $('transferWindowHeader')
      if (hdr) hdr.classList.add('hidden')
    }
  } catch { /* standalone window behavior is the default */ }
  // R118 §2.1 — the mode param: ?mode=share renders the share-mode shell
  // ONLY (the devices sections never mount); the devices mode (the default)
  // boots exactly as before.
  try {
    if (transferPageMode() === 'share') {
      renderShareModeShell()
      applyI18n()
      return // the share mode owns the page — no transfer wiring, no polls
    }
  } catch { /* devices mode is the default */ }
  // S8.9 completion (R100): the transfer page — the live-proven RTC rail —
  // is also a beam executor while open.
  registerBeamExecutor('transfer')
  // R96 §2.2 — the shared theme preference (the theme consistency fix).
  // transfer.html shipped with NO data-theme attribute, so it always rendered
  // the :root (light) values while every other surface defaults dark and
  // honors 'ucrypt:theme' — a user on the dark theme saw a light transfer
  // window (the R95 audit's H4 consistency "1"). Same ONE mechanism as
  // popup.js:2146-2160: the stored preference overrides the HTML default,
  // and storage.onChanged applies a concurrent options-page change live.
  // No new mechanism, no per-surface fork — one switch, CSS variables only.
  try {
    document.documentElement.setAttribute('data-theme', 'dark') // match popup/options HTML defaults
  } catch { /* the HTML attribute is already present in that case */ }
  try {
    const { 'ucrypt:theme': theme } = await chrome.storage.local.get('ucrypt:theme')
    document.documentElement.setAttribute('data-theme', theme || 'dark')
  } catch { /* keep the HTML default */ }
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local' || !changes['ucrypt:theme']) return
      document.documentElement.setAttribute('data-theme', changes['ucrypt:theme'].newValue || 'dark')
    })
  } catch { /* storage listener unavailable — the init read still applies */ }
  applyI18n()
  wire()
  loadLastPeer()
  await refreshStatus()
  await restoreActiveSession()
  // R107 §2.3 — THE AUTO-ARM LAW: the window's opening is the opt-in. A
  // ready chain arms availability BY DEFAULT (bounded 10 minutes, live
  // countdown, one-click Stop, withdrawn on close/lock by the existing
  // pagehide ownership). A locked vault or a chainless device NEVER arms;
  // an already-armed window is left exactly as the user set it.
  if (shouldAutoArm(state.status)) {
    try { await enableAvailabilityHere({ auto: true }) } catch { /* never blocks boot */ }
  }
  // 5 s poll: data freshness AND the MV3 worker keepalive — every poll wakes
  // the worker while this window is open (see the header comment).
  // R140 §6.3: the cadence is ADAPTIVE — 2 s while the Receive view is open
  // and availability is armed (a receiver who waits MUST receive), 5 s
  // otherwise; a window focus polls AGAIN immediately.
  scheduleInboxPoll()
  try { window.addEventListener('focus', () => { pollTick().catch(() => {}); renderInboxLine() }) } catch { /* the focus poll is enhancement */ }
  setInterval(() => { renderInboxLine() }, 1000)
  // 30 s passive status refresh — never closes or dismisses anything.
  setInterval(() => { refreshStatus() }, STATUS_REFRESH_MS)
}

// R133: the init is DOCUMENT-GUARDED — in a browser this is exactly the
// same boot as before; outside one (the battery's pure-helper import) it
// is a clean no-op, never a ReferenceError.
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { init().catch((e) => console.error('[UCrypt] transfer page init failed:', e)) })
  } else {
    init().catch((e) => console.error('[UCrypt] transfer page init failed:', e))
  }
}
