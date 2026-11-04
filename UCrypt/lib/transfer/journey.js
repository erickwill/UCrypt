/**
 * UCrypt — R149 §5.1 — THE ONE-BOX JOURNEY (the page controller, R149 re-land).
 *
 * THE R146 four-beat journey is RETAINED (field-proven converging — C1/C2)
 * and remains THE ROAD's only customer (§5): lib/road/page.js owns the
 * logic, this controller owns the DOM — ONE writer per surface.
 *
 *   LAW #69 (THE ONE-SPOT LAW) — a beat's PAYLOAD renders AT the beat:
 *     the compact offer's QR + THE ONE WORDS BOX + "Copy words" + the reply
 *     box live INSIDE the send card, under the beat line. The 6-digit code
 *     panel RELOCATES to the active session's surface (the sender's card,
 *     or the incoming card on the receiver).
 *   R149 C-6 (§5.1 — THE ONE-BOX JOURNEY, the round's ONE CONSENTED TRIM):
 *     ONE words box for THIS device's words (mbQrWords — the id is kept).
 *     The label + helper ADAPT to the role the door assigned (sender →
 *     "Show these…"; receiver → "Send these back…"). The R148 separate
 *     receiver box (jrAnswerDoor/jrAnswerWords/jrAnswerCopy) is DEAD — the
 *     trim comment at the removal site carries the CEO's verbatim consent.
 *     The answer QR + the state line render at the beat INSIDE the door.
 *   R149 C-5 (§5.1 — THE BIRTH AT THE BEAT, LAW #69 extended): the receive
 *     spawn shows the explicit waiting state FIRST ("Building your reply
 *     words…" under THE box, the box EMPTY), then the real answer words
 *     render in the same flow-turn; any failure renders the TYPED verdict —
 *     never silence, never "???????" (the K-8 scope extension: the waiting
 *     state joined the unrepresentable class).
 *   §6.2 (ROLE ORCHESTRATION) — the active session's role-side shows; the
 *     other role collapses to the one-line affordance (J-10 dies). The
 *     pairing beat keeps both surfaces visible (THE box lives in the send
 *     card — the receiver's words render there).
 *   §5.5 (LAW #70) — the road badge names only ESTABLISHED roads.
 *   §6.4 — units on ALL intervals ("every 60 s", never "every 60").
 *
 * SECURITY, HIGH AND INVISIBLE: end-to-end sealed with the chain group key
 * (unchanged engine); the 6-digit safety-code compare rides the human gate;
 * nothing secret ever displayed; no consent ever auto-closes.
 * NO BONDING HERE: "Your devices are your chain. To add one, use Cloud
 * Sync." — the join flow lives there, and this page never re-learns it.
 */

import { bootTheme } from '../theme.js'
import { createJourney, assertNoDeadEnds } from './beats.js'
import { projectChainRoster, rosterVerdict, verdictNextStep, optionLabel } from './chain-roster.js'
import { installPageTrap } from '../page-trap.js'
import { recordRoadAttempt } from '../bridge/road-record.js'
import { createRoadBadge } from '../road/badge.js'
import {
  roadSend, roadAnswerOffer, confirmCode, submitReplyBundle, importQrImage,
  cancelSession, startFromIncomingBundle, activateReceive, receiveEnvelopeText,
  answerIncoming, reRequestIncoming,
} from '../road/page.js'
import {
  landingVerdict, verdictCodeFor, createLandingWatchdog, createPageSaver,
  arrivalRow, arrivalRowLine, arrivalCardLine, recordArrival, readArrivals,
} from '../road/landing.js'

const $ = (id) => document.getElementById(id)

function msg(key, subs = undefined, fallback = '') {
  try {
    const s = chrome.i18n.getMessage(key, subs)
    return s || fallback
  } catch { return fallback }
}

function door(type, extra = {}) {
  try {
    if (typeof chrome === 'undefined' || !chrome || !chrome.runtime || typeof chrome.runtime.sendMessage !== 'function') {
      return Promise.resolve({ ok: false, code: 'DOOR_OFFLINE' })
    }
    return chrome.runtime.sendMessage({ type, ...extra }).then(
      (r) => r || { ok: false, code: 'DOOR_EMPTY' },
      (e) => ({ ok: false, code: 'DOOR_ERROR', userMessage: String((e && e.message) || e).slice(0, 160) }),
    )
  } catch (e) {
    return Promise.resolve({ ok: false, code: 'DOOR_ERROR', userMessage: String((e && e.message) || e).slice(0, 160) })
  }
}

/* ── the road-line translate map (the i18n law at the render seam) ─────────
 * The road modules speak canonical English (they are pure — no chrome.*);
 * the journey translates at render: every known road line renders through
 * its key ×3 (en/zh_CN/de), unknown lines render verbatim. */
const ROAD_LINE_KEYS = [
  ['Choosing the road…', 'jrRoadChoosing', []],
  ['Trying the direct connection…', 'jrRoadTrying', []],
  ['Direct — this network ✓', 'jrRoadDirectVerified', []],
  ['Cloud relay ✓ — end-to-end encrypted', 'jrRoadRelayVerified', []],
  ['The direct road did not open — trying your cloud…', 'jrRoadDirectFailed', []],
  ['The direct road did not complete its check — trying your cloud…', 'jrRoadDirectFailed', []],
  ['The cloud would not carry the handshake — the words handshake still works at the beat.', 'jrRoadNoRelay', []],
  ['The cloud would not carry the handshake — the QR handshake still works below.', 'jrRoadNoRelay', []],
  ['Compare the 6-digit code on both screens — the file moves when they confirm.', 'jrRoadCompare', []],
  ['Waiting for the code confirmation on the other device…', 'jrRoadWaitingConfirm', []],
  ['The codes match — the bytes may move.', 'jrRoadMatched', []],
  ['Road unavailable — check that both devices are online, then send again.', 'jrRoadUnavailable', []],
  ['Direct unavailable — sending through your cloud, still end-to-end encrypted.', 'roadDirectUnavailable', []],
  ['Relay — through the chain\'s mailbox, still end-to-end encrypted.', 'roadRelayEngaged', []],
  ['The reply is in — the connection completes on the sender\'s screen.', 'transferReplyIn', []],
  ['The answer is on its way — the connection completes on their screen.', 'transferAnswerWay', []],
  ['These words came from an older UCrypt. Update both devices to the same version and paste again — nothing was lost.', 'jrRoadLegacyVerdict', []],
  ['The answer is on its way — the connection completes on their screen.', 'jrRoadAnswerWay', []],
  /* §5.2 — the LEGACY verdict rides the render seam too (R149) */
  ['These words came from an older UCrypt. Update both devices to the same version and paste again — nothing was lost.', 'jrRoadLegacyVerdict', []],
  /* R150 §5.1 — the landing's verdicts + the arrival ride the render seam too
   * (Cure A-e/B — the B2 disease's typed cure; every line ×3 or verbatim). */
  ['Waiting for your Accept — nothing is saved until you accept.', 'jrVerdictAwaitingAccept', []],
  ['The byte stream stalled — the last chunk was not confirmed.', 'jrVerdictAwaitingFinalAck', []],
  ['The copy arrived damaged (hash mismatch) — nothing was saved.', 'jrVerdictHashMismatch', []],
  ['The file verified but the save failed', 'jrVerdictSaveFailed', []],
  ['The resume window closed — the sender can send again; nothing partial is kept silently.', 'jrVerdictExpired', []],
  ['The transfer stalled — the sender can send again; the watermark holds for 10 minutes.', 'jrVerdictReceiveTimeout', []],
  ['Received ✓ — hash verified · ', 'jrArrivedVerified', []],
  ['Accepted — the file moves into your consented basket.', 'jrAcceptedNow', []],
  ['Declined — nothing was saved; the sender was told.', 'jrDeclineSent', []],
  ['The interrupted transfer resumes from zero — the partial bytes were not kept silently.', 'jrResumeRestart', []],
  ['The last chunk was re-requested — the sender re-sends what is missing.', 'jrReRequestSent', []],
]
function translateRoadLine(t) {
  const s = String(t || '')
  for (const [lit, key] of ROAD_LINE_KEYS) {
    if (s === lit || s.startsWith(lit)) {
      const rest = s.slice(lit.length)
      return msg(key, undefined, lit) + rest
    }
  }
  // the calling line: "Calling {peer} directly…"
  const call = s.match(/^Calling (.+) directly… \(they may need to confirm on their screen\)$/)
  if (call) return msg('jrRoadCalling', [call[1]], s)
  return s
}
function renderRoadLine(line) { renderJourneyLine(translateRoadLine(line)) }

const machine = createJourney()
const roadBadge = createRoadBadge()

/* the battery-facing pure helpers (the row families pin these, not the DOM) */
export { fmtSize }
export const shortHash = (h) => String(h || '').slice(0, 12)
let selectedFiles = []
let selectedFile = null
let cloudConnected = false
const seenOfferIds = new Set()
let pollTimer = null

/* ── R150 §5 — THE LANDING (Cure A): the saver lives where the bytes live ──
 * The receiver's pump assembles the bytes IN THIS PAGE, so THIS PAGE saves
 * them: chrome.downloads (the permission exists since the R150 manifest) with
 * the observable "name (2).ext" collision policy. The SW door
 * (BRIDGE_DELIVER_FILE) stays as the TYPED FALLBACK (2-a's contract:
 * {ok:true} | {ok:false, reason}) — honored, never assumed. */
const pageSaver = createPageSaver({
  downloads: (typeof chrome !== 'undefined' && chrome && chrome.downloads) || null,
  makeBlob: (bytes) => new Blob([bytes], { type: 'application/octet-stream' }),
  createURL: (blob) => URL.createObjectURL(blob),
  revokeURL: (u) => { try { URL.revokeObjectURL(u) } catch { /* gone */ } },
  lastError: () => ((typeof chrome !== 'undefined' && chrome && chrome.runtime && chrome.runtime.lastError && chrome.runtime.lastError.message) || null),
})

let lastSave = null // { fileName: <saved>, downloadId } — the landing's observed truth
let lastLandingArgs = null // { fileName, bytesB64 } — the Retry-save button's bytes
let lastAcceptMeta = null // { fileName, size, from } — the Accept gate's shown truth
let lastReceiveSessionId = null // the incoming card the outcome renders into
let landingWatch = null // Cure B — the 15 s budget
let watchdogTimer = null

/* THE LANDING DOOR (Cure A-b): page save FIRST (the bytes' home), the SW
 * door as the typed fallback. The door NEVER lies: it returns the saver's
 * typed verdict, and the pump's verifyAndLand maps it to LAND_FAILED. */
async function landingDoor({ fileName, bytesB64 }) {
  lastLandingArgs = { fileName, bytesB64 }
  const r = await pageSaver.save({ fileName, bytesB64 })
  if (r && r.ok) {
    lastSave = { fileName: r.fileName, downloadId: r.downloadId }
    return { ok: true, fileName: r.fileName, downloadId: r.downloadId }
  }
  const sw = await door('BRIDGE_DELIVER_FILE', { fileName, bytesB64 })
  if (sw && sw.ok) {
    lastSave = { fileName: sw.fileName || fileName, downloadId: null }
    return { ok: true, fileName: lastSave.fileName, downloadId: null }
  }
  return {
    ok: false,
    code: (sw && sw.code) || (r && r.code) || 'SAVE_FAILED',
    userMessage: (sw && sw.userMessage) || (r && r.reason) || 'the file could not be saved',
  }
}

function stopWatchdog() {
  if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null }
}

function startWatchdog() {
  stopWatchdog()
  watchdogTimer = setInterval(() => {
    const v = landingWatch && landingWatch.expired()
    if (v) {
      stopWatchdog()
      renderLandingVerdict({ ok: false, code: v.code })
    }
  }, 1000)
}

/* THE ARRIVAL CARD (Cure A-d) — the bar's replacement: "Received — saved as
 * <name> (<size>, verified)" + [Show in folder] / [Open] (guarded honestly by
 * the downloads API's REAL availability) + the ledger row. The badge is
 * untouched — it keeps naming only the ESTABLISHED road (LAW #70). */
function renderArrivalCard(v) {
  renderProgressBar(null) // the bar resolves — never a 100%-hang
  renderProgressLine('')
  if (landingWatch && !landingWatch.resolved) landingWatch.resolve({ ok: true })
  stopWatchdog()
  const out = $('jrReceiveOutcome')
  if (!out) return
  const inc = lastReceiveSessionId ? activeIncoming.get(lastReceiveSessionId) : null
  if (inc && inc.card && out.parentElement !== inc.card) inc.card.appendChild(out) // the receiver's beat (LAW #69)
  out.hidden = false
  const line = $('jrVerdictLine')
  const acts = $('jrVerdictActions')
  if (line) { line.hidden = true; line.textContent = '' }
  if (acts) { acts.hidden = true; acts.textContent = '' }
  const savedName = (lastSave && lastSave.fileName) || v.fileName || 'received-file'
  const arrival = $('jrArrivalLine')
  if (arrival) arrival.textContent = msg('jrArrivalSavedAs', [savedName, fmtSize(v.size || 0)], arrivalCardLine(savedName, v.size || 0))
  const row = $('jrArrivalActions')
  if (row) {
    row.textContent = ''
    const dl = (typeof chrome !== 'undefined' && chrome && chrome.downloads) || null
    const id = Number(lastSave && lastSave.downloadId)
    const mk = (label, fn) => {
      const b = document.createElement('button')
      b.className = 'btn btn-outline btn-sm'
      b.type = 'button'
      b.textContent = label
      b.addEventListener('click', () => { try { fn() } catch { /* the API refused — the note below names the policy */ } })
      return b
    }
    if (dl && Number.isFinite(id) && typeof dl.show === 'function') row.append(mk(msg('jrArrivalShowBtn', undefined, 'Show in folder'), () => dl.show(id)))
    if (dl && Number.isFinite(id) && typeof dl.open === 'function') row.append(mk(msg('jrArrivalOpenBtn', undefined, 'Open'), () => dl.open(id)))
  }
  // THE LEDGER ROW — the transfers ledger's received side (fed to the list +
  // the history): "received · <name> · verified · just now"
  const ledger = arrivalRow({ name: savedName, size: v.size || 0, sha12: shortHash(v.sha256 || ''), road: '', at: Date.now() })
  const rowEl = $('jrArrivalLedgerRow')
  if (rowEl) rowEl.textContent = arrivalRowLine(ledger, Date.now())
  if (typeof chrome !== 'undefined' && chrome && chrome.storage && chrome.storage.local) {
    recordArrival(chrome.storage.local, ledger).then(() => renderArrivalsList()).catch(() => { /* the row still renders above */ })
  }
}

/* THE TYPED VERDICT CARD (Cure A-e + B) — the anti-arrival: every failed
 * landing resolves HERE (the pump's code, the SW door's typed refusal, or
 * the watchdog's fired verdict), each with its ONE-button path. */
function renderLandingVerdict(v) {
  if (!v) return
  if (landingWatch && !landingWatch.resolved) landingWatch.resolve(v)
  stopWatchdog()
  renderProgressBar(null) // the bar resolves — the 100%-hang is unrepresentable
  renderProgressLine('')
  const code = verdictCodeFor(v.code || 'UNKNOWN')
  const detail = code === 'SAVE_FAILED' ? String(v.userMessage || v.nextStep || '') : ''
  const verdict = landingVerdict(code, detail)
  const out = $('jrReceiveOutcome')
  if (!out) { renderJourneyLine(translateRoadLine(verdict.line)); return }
  const inc = lastReceiveSessionId ? activeIncoming.get(lastReceiveSessionId) : null
  if (inc && inc.card && out.parentElement !== inc.card) inc.card.appendChild(out)
  out.hidden = false
  const arrival = $('jrArrivalLine')
  const rowA = $('jrArrivalActions')
  const ledgerEl = $('jrArrivalLedgerRow')
  if (arrival) arrival.textContent = ''
  if (rowA) { rowA.textContent = '' }
  if (ledgerEl) ledgerEl.textContent = ''
  const line = $('jrVerdictLine')
  const acts = $('jrVerdictActions')
  if (line) { line.hidden = false; line.textContent = translateRoadLine(verdict.line) }
  renderJourneyLine(translateRoadLine(verdict.line))
  if (acts) {
    acts.hidden = false
    acts.textContent = ''
    const b = document.createElement('button')
    b.className = 'btn btn-outline btn-sm'
    b.type = 'button'
    /* the ONE-button path's label — the typed key map (the i18n law: valid
       key names only, each declared in tools/r150-i18n-keys-transfer.json) */
    const actionKeys = { accept: 'jrVerdictAcceptNow', 're-request': 'jrVerdictReRequest', 'retry-save': 'jrVerdictRetrySave', 'try-again': 'jrVerdictTryAgain' }
    b.textContent = msg(actionKeys[verdict.actionKey] || 'jrVerdictTryAgain', undefined, verdict.actionLine)
    b.addEventListener('click', () => runLandingAction(verdict.actionKey))
    acts.append(b)
  }
}

/* THE ONE-BUTTON PATHS (Cure B): each verdict's single next step. */
async function runLandingAction(actionKey) {
  if (actionKey === 'accept') {
    const b = $('jrAcceptYes')
    if (b) b.click()
    return
  }
  if (actionKey === 'retry-save') {
    const args = lastLandingArgs
    if (!args) {
      renderLandingVerdict({ ok: false, code: 'SAVE_FAILED', userMessage: 'nothing held to retry — ask the sender to send again' })
      return
    }
    const r = await landingDoor(args)
    if (r.ok) renderArrivalCard({ code: 'ARRIVED', fileName: args.fileName, size: (lastAcceptMeta && lastAcceptMeta.size) || 0, sha256: '' })
    else renderLandingVerdict({ ok: false, code: 'LAND_FAILED', userMessage: r.userMessage || 'the save failed again' })
    return
  }
  if (actionKey === 're-request') {
    await reRequestIncoming().catch(() => ({ ok: false }))
    renderJourneyLine(translateRoadLine(msg('jrReRequestSent', undefined, 'The last chunk was re-requested — the sender re-sends what is missing.')))
    if (landingWatch) landingWatch.arm(landingWatch.phaseName() || 'progress') // the budget re-arms
    startWatchdog()
    return
  }
  await cancelSend() // 'try-again'
}

/* THE ACCEPT GATE (Cure C) — the consent note's mechanics: name + size +
 * source BEFORE the first byte; [Accept] / [Decline]. */
function renderAcceptGate(meta) {
  lastAcceptMeta = meta || null
  landingWatch.arm('accept') // the prompt's budget (Cure B)
  startWatchdog()
  const gate = $('jrAcceptGate')
  if (!gate) return
  const inc = lastReceiveSessionId ? activeIncoming.get(lastReceiveSessionId) : null
  if (inc && inc.card && gate.parentElement !== inc.card) inc.card.appendChild(gate) // follows the code panel (LAW #69)
  gate.hidden = false
  const from = (meta && meta.from) || ''
  const name = (meta && meta.fileName) || 'a file'
  const size = (meta && meta.size) || 0
  const lineEl = $('jrAcceptGateLine')
  if (lineEl) lineEl.textContent = msg('jrArrivalsConsent', [from || 'the sender', name, fmtSize(size)], `${from || 'A device'} wants to send you ${name} (${fmtSize(size)}) — Accept to save it.`)
  machine.dispatch('ARRIVE', { offer: { from, name } })
}

function hideAcceptGate() {
  const gate = $('jrAcceptGate')
  if (gate) gate.hidden = true
}

/* THE ARRIVALS LIST (Cure E — the section's true job): every landing's
 * verified name, size, time — built from the ceremony's ledger rows. */
async function renderArrivalsList() {
  const list = $('jrArrivalsList')
  if (!list) return
  list.textContent = ''
  let rows = []
  try { rows = await readArrivals(chrome.storage.local) } catch { rows = [] }
  if (!rows.length) {
    const p = document.createElement('p')
    p.className = 'card-help'
    p.textContent = msg('jrArrivalsEmpty', undefined, 'Nothing has landed yet — verified arrivals appear here.')
    list.append(p)
    return
  }
  for (const row of rows.slice().reverse()) {
    const p = document.createElement('p')
    p.className = 'card-help'
    p.textContent = arrivalRowLine(row, Date.now())
    list.append(p)
  }
}

/* ── the ONE writer per surface ──────────────────────────────────────────── */

function renderJourneyLine(line) { const el = $('mbSendJourney'); if (el) el.textContent = line || '' }
function renderProgressLine(line) { const el = $('mbDirectProgress') || $('jrProgressLine'); if (el) el.textContent = line || '' }
function renderProgressBar(percent) {
  const track = $('jrProgressTrack') || $('jrProgressWrap')
  const fill = $('jrProgressFill') || $('jrProgressBar')
  if (!track || !fill) return
  if (percent == null) { track.hidden = true; fill.style.width = '0%'; return }
  track.hidden = false
  fill.style.width = `${Math.max(0, Math.min(100, Math.round(percent)))}%`
}

function fmtSize(n) {
  const b = Number(n) || 0
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

/* ── the road badge (LAW #70 — one writer, the machine owns the truth) ───── */

function renderRoadBadge() {
  const el = $('mbRoadBadge')
  if (!el) return
  /* R148 §4.6 (the K-8 cure) — the BADGE STATE MACHINE at the writer: the
     visible badge NEVER renders an empty line. line()==='' (the HIDDEN
     words) hides the element; a live beat with an unmapped state throws —
     a blank badge is impossible by construction. */
  const line = String(roadBadge.line() || '')
  if (!line || !roadBadge.visible()) { el.hidden = true; el.textContent = ''; return }
  el.hidden = false
  el.textContent = line
  el.className = roadBadge.cssClass()
}

/* ── THE ONE WRITER FOR THIS DEVICE'S WORDS (R149 C-6 + C-5) ───────────────
 * THE ??????? CLASS IS UNREPRESENTABLE (the K-8 scope extension — the
 * waiting state joined the class): the box's value may ONLY ever be set to
 * a real token. In the single writer (writeWordsBox), a falsy value or one
 * matching /^[?·\s]+$/ (question marks, middots, whitespace — the A5
 * disease's shape) is treated as EMPTY and NEVER rendered; the waiting
 * words live in the state line instead (LAW #69 extended: the birth at the
 * beat happens in words, never in punctuation). */
export function safeWordsValue(value) {
  if (!value) return '' // falsy (null / undefined / '' / 0 / false) — EMPTY, never rendered
  const v = String(value)
  if (!v) return ''
  if (/^[?·\s]+$/.test(v)) return '' // the ??????? class — never rendered
  return v
}

function writeWordsBox(box, value) {
  if (!box) return
  box.value = safeWordsValue(value)
}

/* the role THE DOOR assigned to THE box (drives the label + helper swap) */
let wordsRole = 'sender'

/* C-6 — the label + helper ADAPT to the role: sender → "Show these…";
 * receiver → "Send these back…". The data-i18n attribute is swapped too, so
 * a re-apply of the page i18n never clobbers the role-adapted words. */
function setWordsRole(role) {
  wordsRole = role === 'receiver' ? 'receiver' : 'sender'
  const sender = wordsRole === 'sender'
  const labelKey = sender ? 'mbWordsSenderLabel' : 'mbWordsReceiverLabel'
  const helpKey = sender ? 'mbWordsSenderHelp' : 'mbWordsReceiverHelp'
  const labelText = sender
    ? msg('mbWordsSenderLabel', undefined, 'Show these to the other device — or scan their words below.')
    : msg('mbWordsReceiverLabel', undefined, 'Send these back to the sender — the pair completes when they paste them.')
  const helpText = sender
    ? msg('mbWordsSenderHelp', undefined, 'The words or the QR — either one carries the same sealed handshake.')
    : msg('mbWordsReceiverHelp', undefined, 'Copy the words or show the answer QR — either one finishes the pair.')
  const label = $('mbWordsRoleLabel')
  if (label) { label.textContent = labelText; label.setAttribute('data-i18n', labelKey) }
  const help = $('mbWordsRoleHelp')
  if (help) { help.textContent = helpText; help.setAttribute('data-i18n', helpKey) }
}

function setAnswerState(line, { hidden = false } = {}) {
  const state = $('jrAnswerState')
  if (!state) return
  state.hidden = hidden
  state.textContent = line || ''
}

function setAnswerBeat(hidden) {
  const beat = $('jrAnswerBeat')
  if (beat) beat.hidden = hidden
}

/* ── C-5 — THE BIRTH AT THE BEAT (LAW #69 extended) ────────────────────────
 * The door routed an OFFER and spawned the receive flow: the machine shows
 * the explicit waiting state FIRST — the state line under THE box reads
 * "Building your reply words…" and THE box stays EMPTY (never placeholder
 * punctuation). roadAnswerOffer's resolution renders the real words in the
 * same flow-turn (showAnswerWords); any failure renders the typed verdict
 * (the driveUniversalDoor spawn branch). Never silence, never "???????". */
function setWordsWaiting() {
  const doorEl = $('mbQrDoor')
  if (doorEl) doorEl.hidden = false // the beat is OPEN — the birth happens here
  setWordsRole('receiver') // the pasted OFFER made THIS device the receiver
  writeWordsBox($('mbQrWords'), '') // the box waits EMPTY — never punctuation
  setAnswerBeat(true)
  setAnswerState(msg('jrWordsBuilding', undefined, 'Building your reply words…'))
}

/* ── THE ANSWER-WORDS SURFACE (R148 §4.2 → R149 C-6 — THE ONE BOX) ─────────
 * The receiver's beat payload renders INTO THE ONE BOX (mbQrWords): the
 * answer token, the role-adapted label, the answer QR right under THE box,
 * and the plain send-back line in the state line. The owner's question
 * answered by construction: YES — a code (the answer words) is generated
 * and shown, in the SAME box the sender uses (the C-6 merge). */
function showAnswerWords({ answerWords, answerCompact } = {}) {
  const doorEl = $('mbQrDoor')
  if (!doorEl) return
  doorEl.hidden = false
  setWordsRole('receiver')
  const words = safeWordsValue(answerWords)
  writeWordsBox($('mbQrWords'), words) // THE ONE BOX (the C-6 consented trim)
  if (words) {
    setAnswerState(msg('jrAnswerSendBack', undefined, 'Send these back to the SENDER — they paste them in their reply box. The codes match on both screens, then the file moves.'))
  } else {
    // the honest empty edge: the words did not arrive — the verdict above names it
    setAnswerState(msg('jrWordsMissing', undefined, 'The reply words did not arrive — the verdict above names the next step.'))
  }
  setAnswerBeat(false)
  const holder = $('jrAnswerQr')
  if (holder) {
    holder.textContent = ''
    try {
      const url = (typeof QR !== 'undefined' && answerCompact) ? QR.encode(String(answerCompact)) : ''
      if (url) {
        const im = document.createElement('img')
        im.src = url
        im.alt = msg('jrAnswerQrAlt', undefined, 'Your answer QR — the sender can read it from their screen')
        im.width = 132
        im.height = 132
        holder.append(im)
      } else {
        holder.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — the words carry the same handshake)')
      }
    } catch {
      holder.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — the words carry the same handshake)')
    }
  }
}

function hideAnswerWords() {
  setAnswerBeat(true)
  setAnswerState('', { hidden: true })
  setWordsRole('sender')
}

/* C-5 — the receive spawn's VERDICT LINE (pure; the battery pins it): a
 * successful spawn renders the door banner; a failed spawn renders the
 * spawn's TYPED verdict (nextStep / userMessage / code) — the waiting line
 * is REPLACED, never silence, never a placeholder. */
export function spawnVerdictLine(r) {
  if (!r) return ''
  if (r.route === 'receive-spawned') {
    if (r.receive && r.receive.ok) return r.line || ''
    if (r.receive) return translateRoadLine(r.receive.nextStep || r.receive.userMessage || r.receive.code || '')
  }
  return r.line || r.nextStep || ''
}

/* THE UNIVERSAL DOOR BINDING (R148 §4.1 — LAW #72; R149 C-5 — the birth at
 * the beat): every words input feeds ONE router. The route result renders
 * INLINE at the surface that received the paste — never a silent nothing,
 * never a toast-only death. The waiting-writer rides INTO the spawn path:
 * the waiting state fires BEFORE the receive flow builds its answer. */
async function driveUniversalDoor(text, stateEl, { fallbackKey = 'jrReplyFailed', fallback = 'The reply could not be built — check the words and try again.' } = {}) {
  const write = (line) => { if (stateEl) stateEl.textContent = line || ''; renderJourneyLine(line || '') }
  try {
    const r = await receiveEnvelopeText(text, {
      onLine: (t) => write(translateRoadLine(t || '')),
      onWait: () => setWordsWaiting(), // C-5: the waiting state BEFORE the spawn
      codePanel: codePanelAdapter(),
      badge: roadBadge,
    })
    if (r && r.route === 'receive-spawned') {
      if (r.receive && r.receive.ok) {
        /* the pairing beat lives in the send card (THE box) — both surfaces
           stay visible so the answer words + the code are ON SCREEN (LAW #69). */
        if (r.receive.sessionId) lastReceiveSessionId = r.receive.sessionId // the outcome renders at THIS receive's beat
        setRoleFocus(null)
        showAnswerWords(r.receive)
        renderRoadBadge()
        write(spawnVerdictLine(r))
        return r
      }
      /* C-5 — the typed verdict REPLACES the waiting line (never silence,
         never "???????"): the spawn's failure names its next step under THE
         box AND on the journey line (the §5.2 legacy verdict renders here). */
      const verdict = spawnVerdictLine(r) || msg(fallbackKey, undefined, fallback)
      setAnswerState(verdict)
      write(verdict)
      return r
    }
    if (r && r.route === 'receive' && r.ok) {
      renderRoadBadge()
    }
    if (r && r.route === 'handshake-complete') {
      if (r.complete && r.complete.ok === false) {
        // §5.2 — a LEGACY_ANSWER through the door: the typed verdict answers,
        // never a dead code gate, never a false success.
        const v = translateRoadLine(r.complete.userMessage || r.complete.why || '')
        write(v || msg(fallbackKey, undefined, fallback))
        return r
      }
      write(r.line || msg('jrReplySent', undefined, 'The reply is in — the connection completes on the sender\u2019s screen.'))
      return r
    }
    if (r && r.route === 'handoff-join') {
      write(r.line)
      openCloudSync()
      return r
    }
    write((r && (r.line || r.nextStep)) || msg(fallbackKey, undefined, fallback))
    return r
  } catch (e) {
    write(String((e && e.message) || e).slice(0, 200))
    return { ok: false }
  }
}

/* ── the beat adapters (the road calls these; the DOM answers) ───────────── */

function qrDoorAdapter() {
  return {
    show({ qrText, words }) {
      const box = $('mbQrDoor')
      if (!box) return
      box.hidden = false
      /* C-6 — the door assigned the SENDER role: the label + helper adapt,
         and any receiver leftovers (the answer QR, the state line) yield. */
      setWordsRole('sender')
      setAnswerBeat(true)
      setAnswerState('', { hidden: true })
      const holder = $('mbQrFrames')
      holder.textContent = ''
      try {
        const url = (typeof QR !== 'undefined') ? QR.encode(String(qrText || '')) : ''
        if (url) {
          const im = document.createElement('img')
          im.src = url
          im.alt = msg('mbQrAlt', undefined, 'The transfer handshake QR — one frame')
          im.width = 148
          im.height = 148
          holder.append(im)
        } else {
          holder.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — the words below carry the same handshake)')
        }
      } catch {
        holder.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — the words below carry the same handshake)')
      }
      /* THE ONE WRITER — the box's value may only ever be a real token (the
         ??????? class is unrepresentable; an empty token arms nothing). */
      writeWordsBox($('mbQrWords'), words)
    },
    hide() {
      const box = $('mbQrDoor')
      if (box) box.hidden = true
    },
  }
}

function codePanelAdapter() {
  return {
    show(code, { role } = {}) {
      const panel = $('mbCodePanel')
      if (!panel) return
      panel.hidden = false
      const codeEl = $('mbCodeShown') || $('mbSafetyCode')
      if (codeEl) codeEl.textContent = formatSafetyCodeLocal(code)
      const roleEl = $('mbCodeRole')
      if (roleEl) {
        roleEl.textContent = role === 'receiver'
          ? msg('mbCodeRecvRole', undefined, 'Compare this code with the sender\u2019s screen. The file moves only after you confirm.')
          : msg('mbCodeSendRole', undefined, 'Show this code to the other device. The file moves only when they confirm the match.')
      }
    },
    hide() {
      const panel = $('mbCodePanel')
      if (panel) panel.hidden = true
    },
  }
}

function formatSafetyCodeLocal(code) {
  const digits = String(code || '').replace(/\D/g, '')
  return digits.length === 6 ? `${digits.slice(0, 3)} ${digits.slice(3)}` : String(code || '··· ···')
}

/* ── ROLE ORCHESTRATION (§6.2 — the one active role, the collapsed other) ── */

function setRoleFocus(role) {
  const sendCard = $('jrSendCard')
  const arrivals = $('jrArrivalsCard')
  const toggle = $('jrReceiveToggle')
  if (!sendCard || !arrivals || !toggle) return
  if (role === 'sender') {
    // the send session is active — the receiver machinery collapses to one line
    sendCard.hidden = false
    arrivals.hidden = true
    toggle.hidden = false
    toggle.setAttribute('aria-expanded', 'false')
    toggle.textContent = msg('jrReceiveToggleCollapsed', undefined, 'Receive a file instead ▾')
  } else if (role === 'receiver') {
    // an incoming session is active — the composer collapses to one line
    sendCard.hidden = true
    arrivals.hidden = false
    toggle.hidden = false
    toggle.setAttribute('aria-expanded', 'true')
    toggle.textContent = msg('jrSendToggleCollapsed', undefined, 'Send a file instead ▸')
  } else {
    sendCard.hidden = false
    arrivals.hidden = false
    toggle.hidden = true
  }
}

/* ── BEAT 1 — PICK (the canonical roster, the ONE device truth) ─────────── */

async function renderRoster() {
  const sel = $('jrRecipient')
  if (!sel) return []
  const r = await door('TRANSFER_LIST_PEERS')
  const verdict = rosterVerdict({ ok: !!r.ok, unlocked: r.unlocked, chainReady: r.chainReady, readiness: r.readiness || '', peers: r.peers })
  const step = verdictNextStep(verdict)
  sel.textContent = ''
  const emptyRow = $('jrEmptyChainRow') || $('jrNoChainBox')
  const sendRow = $('jrSendRow')
  if (emptyRow) emptyRow.hidden = verdict === 'ready'
  if (sendRow) sendRow.hidden = verdict !== 'ready'
  if (verdict !== 'ready') {
    renderJourneyLine(step ? msg(step.lineKey, undefined, step.line) : '')
    return []
  }
  const rows = projectChainRoster(r.peers || [], { selfId: r.deviceId })
  for (const p of rows) {
    const opt = document.createElement('option')
    opt.value = p.deviceId
    opt.textContent = optionLabel(p)
    sel.append(opt)
  }
  const self = document.createElement('option')
  self.disabled = true
  self.textContent = msg('jrSelfOption', undefined, '(this device)')
  sel.append(self)
  const send = $('jrSend')
  if (send) send.disabled = !sel.value || !selectedFiles.length
  renderJourneyLine(rows.length ? '' : msg('jrEmptyChain', undefined, 'Your devices are your chain. To add one, use Cloud Sync.'))
  return rows
}

/* ── BEAT 2/3 — SEND (the road under the hood, the hash proof on delivery) ─ */

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function sendOneFile(file, toMemberId, peerName) {
  selectedFile = file
  machine.dispatch('START_SEND')
  const send = $('jrSend')
  if (send) send.disabled = true
  setRoleFocus('sender')
  renderRoadBadge()
  const r = await roadSend({
    file,
    peerMemberId: toMemberId,
    peerName,
    cloudConnected,
    onLine: (t) => renderRoadLine(t || ''),
    onProgress: (p) => {
      if (p && typeof p.percent === 'number') {
        machine.dispatch('PROGRESS', { pct: Math.round(p.percent), name: file.name })
        const road = p.phase === 'receiving' ? msg('jrRoadReceiving', undefined, 'Receiving') : msg('jrRoadSending', undefined, 'Sending')
        renderProgressLine(msg('jrSendingProgress2', [file.name, String(Math.round(p.percent)), p.speedLine || '', p.etaLine || ''], `${road} ${file.name}… ${Math.round(p.percent)}%${p.speedLine ? ' · ' + p.speedLine : ''}${p.etaLine ? ' · ' + p.etaLine : ''}`))
        renderProgressBar(p.percent)
      } else if (p && p.line) {
        renderProgressLine(p.line)
      }
    },
    qrDoor: qrDoorAdapter(),
    codePanel: codePanelAdapter(),
    badge: roadBadge,
  })
  renderRoadBadge()
  renderProgressBar(null)
  if (r.ok) {
    machine.dispatch('DELIVERED', { sha12: String(r.receipt && r.receipt.sha256 || '').slice(0, 12), road: r.road, name: file.name })
    const roadWords = r.road === 'direct' ? msg('jrRoadDirect', undefined, 'direct') : msg('jrRoadRelay', undefined, 'your cloud')
    renderJourneyLine(msg('jrDelivered', [file.name, roadWords, String(r.receipt.sha256).slice(0, 12)], `Delivered — verified · ${file.name} · ${roadWords} · hash ${String(r.receipt.sha256).slice(0, 12)}…`))
    renderProgressLine('')
    return true
  }
  machine.dispatch('SEND_FAILED', { reason: r.nextStep || r.code || '' })
  recordRoadAttempt(chrome.storage, { iceState: r.code || 'failed', pairsTried: 0, turnAgreed: false, lastError: r.nextStep || '', at: Date.now() }).catch(() => {})
  renderJourneyLine(msg('jrSendFailedTyped', [r.nextStep || 'the transfer did not move'], `The file did not move — ${r.nextStep || 'the road answered with a failure'}.`))
  return false
}

async function sendFiles() {
  const toMemberId = $('jrRecipient').value
  if (!toMemberId || !selectedFiles.length) return
  const peerName = (($('jrRecipient').selectedOptions[0] && $('jrRecipient').selectedOptions[0].textContent.replace(/ — .*$/, '')) || '')
  const send = $('jrSend')
  if (send) send.disabled = true
  let okCount = 0
  for (const f of selectedFiles) {
    const ok = await sendOneFile(f, toMemberId, peerName)
    if (ok) okCount++
    if (machine.get().state === 'proof.cancelled') break
  }
  selectedFiles = []
  selectedFile = null
  const nameLine = $('jrFileName')
  if (nameLine) nameLine.textContent = ''
  if (send) send.disabled = !($('jrRecipient').value)
  if (okCount > 1) {
    renderProgressLine(msg('jrBatchDone', [String(okCount)], `${okCount} files delivered — each verified by hash.`))
  }
  setRoleFocus(null)
}

async function cancelSend() {
  machine.dispatch('CANCEL')
  try { await cancelSession() } catch { /* the engine keeps its own truth */ }
  renderProgressLine('')
  renderProgressBar(null)
  renderJourneyLine(msg('jrCancelled', undefined, 'Cancelled — nothing moved, nothing is waiting.'))
  const send = $('jrSend')
  if (send) send.disabled = !($('jrRecipient').value)
  setRoleFocus(null)
  const box = $('mbQrDoor')
  if (box) box.hidden = true
  const panel = $('mbCodePanel')
  if (panel) panel.hidden = true
  hideAcceptGate()
  const outcome = $('jrReceiveOutcome')
  if (outcome) outcome.hidden = true
  if (landingWatch) landingWatch.resolve({ ok: false, code: 'CANCELLED' })
  stopWatchdog()
  hideAnswerWords()
  roadBadge.to('hidden')
  renderRoadBadge()
}

/* ── BEAT 4 — RECEIVE (an arrivals surface, never a role) ───────────────── */

function renderPollLine(connected, checkedAt) {
  const el = $('jrPollLine')
  if (!el) return
  if (!connected) {
    el.textContent = msg('jrPollNoCloud', undefined, 'Direct transfers arrive live. The relay needs Cloud Sync — offers arrive on their own when it is connected.')
    return
  }
  const ago = checkedAt ? Math.max(0, Math.round((Date.now() - checkedAt) / 1000)) : null
  el.textContent = ago == null
    ? msg('jrPollIdle', undefined, 'Checking for incoming files every 60 s…')
    : msg('jrPollActive', ['60', String(ago)], `Checking for incoming files every 60 s · last checked ${ago}s ago`)
}

function offerCard(o) {
  const card = document.createElement('div')
  card.className = 'offer-card'
  const from = document.createElement('div')
  from.className = 'from-line'
  from.textContent = msg('jrOfferFrom', [o.fromName, o.fileName, fmtSize(o.size)], `From ${o.fromName} · ${o.fileName} (${fmtSize(o.size)})`)
  const code = document.createElement('div')
  code.className = 'code-line'
  code.textContent = msg('jrOfferCode', [o.verifyCode], `Code: ${o.verifyCode}`)
  const btns = document.createElement('div')
  btns.className = 'btn-row'
  const accept = document.createElement('button')
  accept.className = 'btn btn-primary btn-sm'
  accept.type = 'button'
  accept.textContent = msg('jrAccept', undefined, 'Accept')
  accept.addEventListener('click', () => acceptOffer(o, card))
  const decline = document.createElement('button')
  decline.className = 'btn btn-ghost btn-sm'
  decline.type = 'button'
  decline.textContent = msg('jrDecline', undefined, 'Decline')
  decline.addEventListener('click', () => declineOffer(o, card))
  btns.append(accept, decline)
  card.append(from, code, btns)
  return card
}

function renderOffers(offers) {
  const list = $('jrOfferList')
  if (!list) return
  list.textContent = ''
  const live = (offers || []).filter((o) => !o.refused)
  if (!live.length) {
    const empty = document.createElement('p')
    empty.className = 'card-help'
    empty.textContent = msg('jrNoOffers', undefined, 'Nothing waiting right now. Incoming files appear here — direct ones ask first.')
    list.append(empty)
    return
  }
  for (const o of live) {
    seenOfferIds.add(o.offerId)
    list.append(offerCard(o))
  }
}

/* THE RECEIVED LOG — plain words: who, what, when, which road. */
function arrivalLogLine({ from, name, road }) {
  const when = new Date().toLocaleTimeString()
  return msg('jrArrivalsLog', [name, from, when, road], `${name} from ${from} · saved ${when} · by ${road}`)
}

async function acceptOffer(o, card) {
  machine.dispatch('ARRIVE', { offer: { from: o.fromName, name: o.fileName } })
  const stateLine = document.createElement('p')
  stateLine.className = 'card-help'
  card.append(stateLine)
  try {
    const r = await door('MAILBOX_ACCEPT', { offerId: o.offerId, code: o.verifyCode })
    if (r.ok) {
      machine.dispatch('ACCEPT_OK', { name: o.fileName, road: msg('jrRoadRelay', undefined, 'your cloud') })
      stateLine.textContent = msg('jrSavedVerified', [o.fileName], `Saved · Verified — ${o.fileName}`)
      const log = document.createElement('p')
      log.className = 'card-help'
      log.textContent = arrivalLogLine({ from: o.fromName, name: o.fileName, road: msg('jrRoadRelay', undefined, 'your cloud') })
      card.append(log)
      card.querySelector('.btn-row')?.remove()
    } else {
      machine.dispatch('ACCEPT_FAIL', { reason: r.userMessage || '' })
      stateLine.textContent = msg('jrAcceptFailed', [r.userMessage || ''], `The incoming file could not be collected — ${r.userMessage || 'the door did not answer'}. Run the connection doctor below.`)
    }
  } catch (e) {
    machine.dispatch('ACCEPT_FAIL', { reason: String((e && e.message) || e) })
    stateLine.textContent = msg('jrAcceptFailed', [String((e && e.message) || e).slice(0, 120)], 'The incoming file could not be collected. Run the connection doctor below.')
  }
}

async function declineOffer(o, card) {
  machine.dispatch('DECLINE_OK')
  const r = await door('MAILBOX_DECLINE', { offerId: o.offerId })
  if (r.ok) card.remove()
  renderJourneyLine(msg('jrArrivalsDeclined', undefined, 'Declined — nothing was saved, nothing is waiting.'))
}

/* ── THE ROAD'S INCOMING SESSIONS (the bridge-offer consumers) ───────────── */

const activeIncoming = new Map() // sessionId → { card, lines }

async function pollRoadSignals() {
  const poll = await door('BRIDGE_SIGNAL_POLL')
  if (!poll.ok) return
  const offers = (poll.signals || []).filter((s) => s.envelope && s.envelope.kind === 'bridge-offer' && s.envelope.payload && s.envelope.payload.offer)
  for (const s of offers) {
    if (seenOfferIds.has('road-' + s.signalId)) continue
    seenOfferIds.add('road-' + s.signalId)
    const meta = s.envelope.payload || {}
    try { await door('BRIDGE_SIGNAL_CONSUME', { sessionId: s.envelope.sessionId, signalId: s.signalId }) } catch { /* best effort */ }
    /* R150 FIELD-HARNESS FIND (the G102 catch): the relay return-path was
       DEAD CODE — roadAnswerOffer read the answer's ROUTING id from the
       SEALED payload (which never carries senderMemberId) while the id rides
       the OUTER signal meta; the incoming spawn never passed it, so the
       receiver's machine-carried answer never rode the lane back and every
       relay dial expired at the ack budget ("Road unavailable"). The meta's
       senderMemberId is the routing truth — it reaches the answer put now. */
    await startIncomingRoadSession({ offerText: meta.offer, fromName: meta.fromName || 'a device', fileName: meta.fileName || '', size: Number(meta.size) || 0, sessionId: s.envelope.sessionId, senderMemberId: meta.senderMemberId || '' })
  }
}

async function startIncomingRoadSession({ offerText, fromName, fileName, size, sessionId, senderMemberId = '' }) {
  machine.dispatch('ARRIVE', { offer: { from: fromName, name: fileName || 'a file' } })
  setRoleFocus('receiver')
  const list = $('jrDirectInList')
  if (!list) return
  lastReceiveSessionId = sessionId // the accept gate + the outcome render HERE
  const card = document.createElement('div')
  card.className = 'offer-card'
  const from = document.createElement('div')
  from.className = 'from-line'
  from.textContent = msg('jrDirectInFrom', [fileName || 'a file', fmtSize(size)], `${fileName || 'A file'} (${fmtSize(size)}) — arriving from ${fromName}`)
  const stateLine = document.createElement('p')
  stateLine.className = 'card-help'
  card.append(from, stateLine)

  /* THE ONE-SPOT RELOCATION: the code panel + the accept gate + the outcome
     move INTO this card — the receiver's beat (LAW #69). */
  const panel = $('mbCodePanel')
  if (panel) card.append(panel)
  const gate = $('jrAcceptGate')
  if (gate) card.append(gate)
  const outcome = $('jrReceiveOutcome')
  if (outcome) card.append(outcome)

  /* the host the panel returns to on cancel (the send card) */
  card.dataset.codeHost = 'incoming'
  list.prepend(card)
  activeIncoming.set(sessionId, { card, stateLine })

  const r = await roadAnswerOffer({
    offerText,
    fromName,
    /* R150: the ROUTING id (the sender's member id from the signal meta) —
       the machine-carried answer addresses the sender's lane (the relay
       return-path lives; the words path is unchanged) */
    peerMemberId: senderMemberId || '',
    onLine: (t) => { stateLine.textContent = translateRoadLine(t || '') },
    codePanel: codePanelAdapter(),
    badge: roadBadge,
  })
  renderRoadBadge()
  if (!r.ok) {
    // the typed split: an offer that could not OPEN names its own class
    const openClass = r.code === 'SEAL' || r.code === 'SHAPE' || r.code === 'INCOMPLETE_OFFER'
    stateLine.textContent = r.nextStep || (openClass
      ? msg('jrDirectOpenFailed', undefined, 'A direct arrival could not be opened — the sender can press Send again.')
      : msg('jrDirectInFailed', undefined, 'The direct answer could not be built — the sender can press Send again.'))
    return
  }
  stateLine.textContent = msg('jrInConnected', undefined, 'The handshake is in — compare the 6-digit code, then answer on their screen.')
  /* R149 C-6 — THE ONE BOX: the receiver's answer words render in THE box
     (the send card's door) with the answer QR at the beat. Both surfaces
     stay visible — the answer words are THIS device's words now. */
  showAnswerWords(r)
  setRoleFocus(null)
}

async function onReceiverMatch() {
  const r = await confirmCode(true)
  if (!r.ok) return
  const role = $('mbCodeRole')
  if (role) role.textContent = msg('jrCodeMatched', undefined, 'Matched — the file may move now.')
  roadBadge.to('relay', {}) // the relay lane is proven the moment the confirm rode it
  renderRoadBadge()
  /* THE RECEIVE ACTIVATION — both doors listen; the hash verifies BEFORE the
     landing (the §5.6 law). R150 §5: the landing is a CEREMONY now —
     the Accept gate (Cure C) opens before the first byte; the page saves the
     verified bytes (Cure A); the 15 s watchdog (Cure B) makes the stuck
     "Receiving the file… 100%" structurally impossible. */
  landingWatch = createLandingWatchdog({ now: () => Date.now() })
  landingWatch.arm('progress') // any pump stall resolves typed within 15 s
  startWatchdog()
  const res = await activateReceive({
    onLine: (t) => renderRoadLine(t || ''),
    onProgress: (p) => {
      if (p && typeof p.percent === 'number') {
        if (landingWatch) {
          if (p.percent >= 100) landingWatch.arm('verify') // 100% lives only until the hash check — the watchdog bounds it
          else landingWatch.touch()
        }
        renderProgressLine(msg('jrReceivingProgress', ['the file', String(Math.round(p.percent))], `Receiving… ${Math.round(p.percent)}%`))
        renderProgressBar(p.percent)
      }
    },
    onIncoming: renderAcceptGate, // Cure C — the prompt BEFORE the first byte
    onVerdict: (v) => { if (v && v.code === 'ARRIVED') renderArrivalCard(v); else renderLandingVerdict(v) },
    landing: landingDoor, // Cure A — the page saves; the SW door is the typed fallback
  })
  if (res.ok) {
    if (res.sessionId) lastReceiveSessionId = res.sessionId
    machine.dispatch('ACCEPT_OK', { name: 'the file', road: msg('jrRoadDirect', undefined, 'direct') })
    renderProgressBar(null)
  }
}

async function onReceiverMismatch() {
  const r = await confirmCode(false)
  if (r.ok) {
    const panel = $('mbCodePanel')
    if (panel) panel.hidden = true
    renderJourneyLine(msg('jrCodeMismatchLine', undefined, 'The codes did not match — nothing moved. Start again when ready.'))
    setRoleFocus(null)
    roadBadge.to('hidden')
    renderRoadBadge()
  }
}

/* ── the doctor (v2 + the canonical roster truth) and the history ───────── */

async function runDoctor() {
  const rows = $('jrDoctorRows') || $('mbDoctorRows')
  if (!rows) return
  rows.textContent = ''
  const pending = document.createElement('p')
  pending.className = 'card-help'
  pending.textContent = msg('jrDoctorRunning', undefined, 'Testing every hop…')
  rows.append(pending)
  const r = await door('MAILBOX_DOCTOR')
  const roster = await door('TRANSFER_LIST_PEERS')
  const chainRows = roster.ok ? projectChainRoster(roster.peers || [], { selfId: roster.deviceId }) : []
  rows.textContent = ''
  const facts = {
    peerEverSeen: chainRows.length > 0,
    peerSeenAt: 0,
    directFound: false,
    relayReachable: !!(r.ok && !r.report.cloudDown),
    codeCompared: false,
    speedBps: 0,
    receiptReturned: false,
  }
  const { buildDoctorRows, doctorVerdict } = await import('../bridge/doctor2.js')
  const built = buildDoctorRows(facts)
  for (const hop of built) {
    const li = document.createElement('div')
    li.className = 'diag-hop'
    const g = document.createElement('span'); g.className = 'glyph'; g.textContent = hop.ok ? '✓' : '✗'
    const t = document.createElement('span')
    t.textContent = `${hop.line}${!hop.ok && hop.actionLine ? ' — ' + hop.actionLine : ''}`
    li.append(g, t)
    rows.append(li)
  }
  if (r.ok && r.report.hops) {
    const sub = document.createElement('p')
    sub.className = 'card-help'
    sub.textContent = msg('jrDoctorSub', undefined, 'The connection test\u2019s own hops:')
    rows.append(sub)
    for (const hop of r.report.hops) {
      const li = document.createElement('div')
      li.className = 'diag-hop'
      const g = document.createElement('span'); g.className = 'glyph'; g.textContent = hop.ok ? '✓' : '✗'
      const t = document.createElement('span')
      t.textContent = `${hop.hop}: ${hop.detail}${!hop.ok && hop.action ? ' — ' + hop.action : ''}`
      li.append(g, t)
      rows.append(li)
    }
  }
  const verdict = doctorVerdict(built)
  if (!verdict.ok && verdict.actionLine) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = verdict.actionLine
    rows.append(p)
  }
}

async function renderHistory() {
  const j = await door('MAILBOX_JOURNEYS')
  const rows = $('jrHistoryRows')
  if (!rows) return
  rows.textContent = ''
  /* R150 §5.1 — the received side's ledger rows merge into the history
     ("received · <name> · verified · just now") — the received files are
     ledgered beside the sent ones. */
  let arrivals = []
  try { arrivals = await readArrivals(chrome.storage.local) } catch { arrivals = [] }
  for (const row of arrivals.slice().reverse()) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = arrivalRowLine(row, Date.now())
    rows.append(p)
  }
  const list = (j.ok && j.journeys) || []
  if (!list.length && !arrivals.length) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = msg('jrHistoryEmpty', undefined, 'Nothing sent in the last 7 days.')
    rows.append(p); return
  }
  for (const item of list) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = `${item.fileName} → ${item.toName}: ${item.line || item.state}`
    rows.append(p)
  }
}

/* ── the poll lifecycle ─────────────────────────────────────────────────── */

async function pollOnce() {
  door('BRIDGE_PRESENCE_STAMP').catch(() => {})
  const st = await door('MAILBOX_STATUS')
  cloudConnected = !!(st.ok && st.status && st.status.connected)
  await renderRoster()
  renderPollLine(cloudConnected, cloudConnected ? Date.now() : 0)
  // the header's live truth — ONE writer (the R142 RG-3 law, carried over)
  const hs = $('mbHeaderStatus')
  if (hs) {
    hs.textContent = cloudConnected
      ? msg('mbHeaderLive', undefined, 'Direct is first — the cloud relay is ready')
      : msg('mbHeaderIdle', undefined, 'Direct first — the cloud relay is optional')
  }
  if (cloudConnected) {
    const p = await door('MAILBOX_POLL')
    if (p.ok) renderOffers(p.offers)
  }
  await pollRoadSignals()
  await renderArrivalsList() // the received side's ledger rows (the R150 arrivals list)
  await renderHistory()
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(pollOnce, 60000)
  /* the road's signals live 120 s — the read rides its own 5 s cadence while
     the page is visible (the honest 60 s poll keeps the mailbox offers). */
  setInterval(() => { if (!document.hidden) pollRoadSignals().catch(() => {}) }, 5000)
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollOnce() })
  window.addEventListener('focus', () => pollOnce())
}

/* ── the Cloud Sync door (NO BONDING HERE — the ONE next step) ──────────── */

function openCloudSync() {
  let handed = false
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({ type: 'UCRYPT_OPEN_SYNC_JOIN' }, '*')
      handed = true
    }
  } catch { /* cross-origin host — fall through */ }
  if (!handed) {
    try { chrome.runtime.openOptionsPage() } catch { /* standalone */ }
  }
  renderJourneyLine(msg('jrOpenedSync', undefined, 'Cloud Sync is opening — its two steps put your devices in the chain.'))
}

/* ── the file pickers ───────────────────────────────────────────────────── */

async function pickFile() {
  const input = $('jrFileInput')
  input.value = ''
  input.accept = ''
  input.multiple = true
  input.click()
  input.onchange = async () => {
    const files = Array.from((input.files && input.files) || [])
    if (!files.length) return
    const accepted = []
    for (const f of files) {
      if (f.size > 100 * 1024 * 1024) {
        $('jrFileName').textContent = msg('jrTooBig', [f.name], `${f.name} is over 100 MB — the honest cap.`)
        continue
      }
      accepted.push(f)
    }
    if (!accepted.length) return
    selectedFiles = accepted
    $('jrFileName').textContent = accepted.map((f) => `${f.name} · ${fmtSize(f.size)}`).join('  ·  ')
    $('jrSend').disabled = !($('jrRecipient').value)
  }
}

async function exportOffer() {
  const input = $('jrFileInput')
  input.value = ''
  input.multiple = false
  input.click()
  input.onchange = async () => {
    const f = input.files && input.files[0]
    if (!f) return
    const bytes = new Uint8Array(await f.arrayBuffer())
    let bin = ''
    for (let i = 0; i < bytes.length; i += 32768) bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, bytes.length)))
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    const sha256 = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
    const r = await door('MAILBOX_EXPORT_OFFER', { fileName: f.name, size: f.size, sha256, bytesB64: btoa(bin) })
    if (r.ok) {
      const blob = new Blob([Uint8Array.from(atob(r.fileB64), (c) => c.charCodeAt(0))], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = r.fileName
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 60000)
      const codeSuffix = r.verifyCode ? ` · Verification code: ${r.verifyCode}` : ''
      $('jrFallbackState').textContent = msg('jrExportDone', [r.fileName], `The file is saved — move it to the other device and press Import file there. (${r.fileName}${codeSuffix})`)
    } else {
      $('jrFallbackState').textContent = r.userMessage || msg('jrExportFailed', undefined, 'The export could not be built.')
    }
  }
}

async function importOffer() {
  const input = $('jrFileInput')
  input.value = ''
  input.multiple = false
  input.accept = '.ucrypt-offer'
  input.click()
  input.onchange = async () => {
    const f = input.files && input.files[0]
    if (!f) return
    const bytes = new Uint8Array(await f.arrayBuffer())
    let bin = ''
    for (let i = 0; i < bytes.length; i += 32768) bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, bytes.length)))
    const code = window.prompt(msg('jrImportCodePrompt', undefined, 'Type the verification code the sender showed you (6 digits):')) || ''
    const r = await door('MAILBOX_IMPORT_OFFER', { fileB64: btoa(bin), code: code.replace(/\s+/g, '') })
    if (r.ok) {
      $('jrFallbackState').textContent = msg('jrImportDone', [r.fileName, r.fromName], `Verified — ${r.fileName} from ${r.fromName}. Import complete.`)
    } else {
      $('jrFallbackState').textContent = r.userMessage || msg('jrImportFailed', undefined, 'The file could not be imported.')
    }
  }
}

function openUnlock() {
  let handed = false
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({ type: 'UCRYPT_OPEN_UNLOCK' }, '*')
      handed = true
    }
  } catch { /* cross-origin host — fall through */ }
  if (!handed) {
    try { chrome.runtime.openOptionsPage() } catch { /* standalone */ }
  }
  renderJourneyLine(msg('jrUnlocking', undefined, 'Unlock the vault on the main page — sending resumes right after.'))
}

/* ── wiring ─────────────────────────────────────────────────────────────── */

async function boot() {
  installPageTrap({ surface: 'transfer' })
  try { await bootTheme({ storage: chrome.storage }) } catch { /* the fallback stands */ }
  for (const el of document.querySelectorAll('[data-i18n]')) {
    const t = msg(el.getAttribute('data-i18n'), undefined, el.textContent)
    if (t) el.textContent = t
  }
  try { assertNoDeadEnds(machine) } catch (e) { console.error('[UCrypt journey]', e && e.message) }
  setRoleFocus(null)
  renderRoadBadge()

  $('jrPickFile').addEventListener('click', pickFile)
  $('jrRecipient').addEventListener('change', () => {
    machine.dispatch('CHOOSE_RECIPIENT', { to: $('jrRecipient').value })
    $('jrSend').disabled = !$('jrRecipient').value || !selectedFiles.length
  })
  $('jrSend').addEventListener('click', sendFiles)
  $('jrCancelSend').addEventListener('click', cancelSend)
  $('jrOpenSync').addEventListener('click', openCloudSync)
  $('jrExportOffer').addEventListener('click', exportOffer)
  $('jrImportOffer').addEventListener('click', importOffer)
  $('jrRunDoctor').addEventListener('click', runDoctor)

  /* THE ROLE AFFORDANCE (§6.2) — the collapsed role expands on click */
  $('jrReceiveToggle').addEventListener('click', () => {
    const arrivals = $('jrArrivalsCard')
    const sendCard = $('jrSendCard')
    if (arrivals.hidden) {
      arrivals.hidden = false
      sendCard.hidden = false
      setRoleFocus(null)
    } else {
      const showArrivals = !sendCard.hidden
      if (showArrivals) setRoleFocus('sender')
      else setRoleFocus('receiver')
    }
  })

  /* "Copy words" — the mortal toast (the §6.1 law's affordance). THE ONE
     BOX serves both roles (C-6): in the receiver role the state line
     confirms the copy with the send-back instruction. */
  $('jrCopyWords').addEventListener('click', async () => {
    const w = $('mbQrWords')
    if (!w || !w.value) return
    try {
      await navigator.clipboard.writeText(w.value)
      const btn = $('jrCopyWords')
      const old = btn.textContent
      btn.textContent = msg('jrCopied', undefined, 'Copied ✓')
      setTimeout(() => { btn.textContent = old }, 2500)
    } catch {
      w.select()
      try { document.execCommand('copy') } catch { /* the select still helps */ }
    }
    if (wordsRole === 'receiver') {
      setAnswerState(msg('jrAnswerCopied', undefined, 'Copied — paste these into the SENDER\u2019s reply box (the device that showed the first code).'))
    }
  })

  /* R148 §4.3 — THE RECEIVE DOOR'S EQUAL PROMINENCE (the K-1d cure),
     R150 §7.1 — routed to THE ONE UNIVERSAL DOOR: "Receive a file" opens
     THE paste door (mbReplyInput in the beat door — the second paste box
     is GONE, the CEO's consented trim), focused, scrolled into view. */
  $('jrReceiveFirstClass').addEventListener('click', () => {
    const doorEl = $('mbQrDoor')
    if (doorEl) doorEl.hidden = false
    const target = $('mbReplyInput')
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' })
      target.focus({ preventScroll: true })
    }
    renderJourneyLine(msg('jrReceiveFirstClassHint', undefined, 'Paste the sender\u2019s words below (or read their QR image) — the machine answers with YOUR words to send back.'))
  })

  /* THE DIRECT HANDSHAKE — now THE ONE UNIVERSAL DOOR (R150 §7.1, the CEO's
     consented trim; the paste/scan media, the camera-less parity; the door
     lives AT the beat). The box feeds THE UNIVERSAL DOOR — any envelope, any
     type, routed with instant typed feedback; nothing swallows: an OFFER
     spawns the receive flow, an ANSWER completes the pairing, a JOIN hands
     off to Cloud Sync, a corrupt paste names what to re-copy (LAW #72). */
  const qrInput = $('jrQrFileInput')
  $('mbReplySubmit').addEventListener('click', async () => {
    await driveUniversalDoor($('mbReplyInput').value, null)
  })
  $('mbReplyScan').addEventListener('click', () => {
    qrInput.value = ''
    qrInput.click()
    qrInput.onchange = async () => {
      const f = qrInput.files && qrInput.files[0]
      if (!f) return
      try {
        const text = await importQrImage(f)
        $('mbReplyInput').value = text
        renderJourneyLine(msg('jrQrRead', undefined, 'The QR image was read — press Connect to answer.'))
      } catch (e) {
        renderJourneyLine(String((e && e.message) || e).slice(0, 160))
      }
    }
  })

  /* THE ACCEPT GATE (R150 §5.3 — Cure C): the consent note's MECHANICS.
     Accept: the held bytes flow into the consented basket (no second
     prompt); Decline: nothing saved, the sender told (typed). */
  $('jrAcceptYes').addEventListener('click', async () => {
    hideAcceptGate()
    if (landingWatch) landingWatch.arm('progress') // the accepted basket's stall budget
    startWatchdog()
    const r = await answerIncoming({ accept: true }).catch(() => ({ ok: false }))
    if (r && r.ok) renderJourneyLine(translateRoadLine(msg('jrAcceptedNow', undefined, 'Accepted — the file moves into your consented basket.')))
    else if (r && r.landed && r.land && !r.land.ok) renderLandingVerdict(r.land)
  })
  $('jrAcceptNo').addEventListener('click', async () => {
    hideAcceptGate()
    if (landingWatch) landingWatch.resolve({ ok: false, code: 'DECLINED' })
    stopWatchdog()
    const r = await answerIncoming({ accept: false }).catch(() => ({ ok: false }))
    renderProgressLine('')
    renderProgressBar(null)
    renderJourneyLine(translateRoadLine(msg('jrDeclineSent', undefined, 'Declined — nothing was saved; the sender was told.')))
    try { roadBadge.to('hidden') } catch { /* already hidden */ }
    renderRoadBadge()
    if (r && r.ok) machine.dispatch('DECLINE_OK')
  })

  /* the code panel's human gate (the receiver's Match / Mismatch) */
  $('mbCodeMatch').addEventListener('click', onReceiverMatch)
  $('mbCodeMismatch').addEventListener('click', onReceiverMismatch)

  await pollOnce()
  startPolling()
  window.__ucryptJourney = { machine, door, renderRoster, openCloudSync, openUnlock, verdictNextStep, roadBadge, setRoleFocus }
}

/* the harness imports this module headless — the boot runs only in a real page */
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
}
