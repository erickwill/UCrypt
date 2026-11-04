/**
 * UCrypt — R142 §5.4 — THE TRANSFER PAGE (the ONE writer per panel).
 *
 * THE OWNER'S LAW (the capture, pinned e01c3af2): a chain is DIRECT. This
 * page's blocking "Before you start" gate is DEAD — it is a LIVE STATUS
 * STRIP of three honest lines (Devices / Direct / Cloud), NONE of which
 * gates the journey. The composer is ALWAYS reachable. The roster is the
 * CHAIN'S OWN (never blank under a green chain check — the F-5/A2 cure).
 * The journey picks the road AUTOMATICALLY and says which one in plain
 * words (§5.1): direct when possible, through the cloud when needed, always
 * end-to-end encrypted (the copy-congruence law, F-6).
 *
 * The panels and their ONE writers:
 *   mbStatusRows (this), mbHeaderStatus (this), mbRoadBadge (bridge/page),
 *   mbRecipient + mbSendJourney (this), mbDirectProgress (bridge/page),
 *   mbCodePanel (bridge/page), mbQrDoor (bridge/page), mbOfferList (this),
 *   mbDoctorRows (this), mbHistoryRows (this).
 *
 * Nothing closes without consent: no auto-dismiss, no auto-open, no timers
 * that vanish state (the popup law holds on every surface).
 */

import { bootTheme } from '../theme.js'
import * as SettledHouse from '../settled-house.js'
import { rosterProjection, emptyRosterTeaching, PRESENCE_TTL_MS } from '../bridge/presence-lite.js'
import { buildDoctorRows, doctorVerdict } from '../bridge/doctor2.js'
import { noRoadTruth, roadLabel } from '../bridge/session.js'
import { deriveRoadLedger, ledgerLines, typeAbsentIngredient } from '../bridge/road-ledger.js'
import { bundleToWordsToken, wordsTokenToBundle, parseBundleFrames, frameBundleText, buildBondText, parseBondText, BOND_BUNDLE_TTL_MS } from '../bridge/signal.js'
import {
  encodeWarmProfile, decodeWarmProfile, warmReDialPlan,
} from '../bridge/manual-bridge.js'
import {
  directSend, directReceive, confirmCode, submitReplyBundle, importQrImage,
  cancelSession, setRoadBadge, startFromIncomingBundle,
} from '../bridge/page.js'

// UCRYPT-28: MV3 CSP-compliant embed & parent theme synchronization + standalone web preview shim
;(function initTransferSurfaceAndPreviewShim() {
  if (typeof document !== 'undefined' && document.documentElement) {
    try {
      const isEmbed = (typeof window !== 'undefined' && window.self !== window.top) ||
        (typeof location !== 'undefined' && new URLSearchParams(location.search).get('embed') === '1')
      if (isEmbed) {
        document.documentElement.classList.add('in-embed')
        document.documentElement.classList.remove('is-standalone-transfer')
      } else {
        document.documentElement.classList.remove('in-embed')
        document.documentElement.classList.add('is-standalone-transfer')
      }
      const syncParentTheme = () => {
        try {
          if (window.parent && window.parent !== window && window.parent.document && window.parent.document.documentElement) {
            const pt = window.parent.document.documentElement.getAttribute('data-theme')
            if (pt === 'dark' || pt === 'light') {
              document.documentElement.setAttribute('data-theme', pt)
            }
          }
        } catch { /* cross-origin safe */ }
      }
      syncParentTheme()
      if (window.parent && window.parent !== window && window.parent.document && window.parent.document.documentElement && typeof MutationObserver === 'function') {
        const obs = new MutationObserver(syncParentTheme)
        obs.observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
      }
    } catch {
      document.documentElement.classList.add('in-embed')
    }
  }
  const g = typeof globalThis !== 'undefined' ? globalThis : window
  if (g.chrome && g.chrome.storage && g.chrome.storage.local) return
  const mem = {}
  const readStore = () => {
    try { return JSON.parse(localStorage.getItem('__ucrypt_preview_store__') || '{}') } catch { return mem }
  }
  const writeStore = (obj) => {
    try { localStorage.setItem('__ucrypt_preview_store__', JSON.stringify(obj)) } catch { Object.assign(mem, obj) }
  }
  const storageArea = {
    get(keys, cb) {
      const all = readStore()
      let res = {}
      if (!keys) res = { ...all }
      else if (typeof keys === 'string') { if (keys in all) res[keys] = all[keys] }
      else if (Array.isArray(keys)) { for (const k of keys) if (k in all) res[k] = all[k] }
      else if (typeof keys === 'object') { res = { ...keys }; for (const k of Object.keys(keys)) if (k in all) res[k] = all[k] }
      if (typeof cb === 'function') cb(res)
      return Promise.resolve(res)
    },
    set(items, cb) {
      const all = readStore()
      Object.assign(all, items || {})
      writeStore(all)
      if (typeof cb === 'function') cb()
      return Promise.resolve()
    },
    remove(keys, cb) {
      const all = readStore()
      const list = Array.isArray(keys) ? keys : [keys]
      for (const k of list) delete all[k]
      writeStore(all)
      if (typeof cb === 'function') cb()
      return Promise.resolve()
    },
  }
  g.chrome = {
    ...(g.chrome || {}),
    i18n: (g.chrome && g.chrome.i18n) || { getMessage: () => '' },
    storage: { local: storageArea, session: storageArea, onChanged: { addListener() {}, removeListener() {} } },
    runtime: {
      id: 'ucrypt-standalone-preview',
      lastError: null,
      getManifest: () => ({ version: '3.46.0', name: 'UCrypt' }),
      getURL: (p) => p,
      onMessage: { addListener() {}, removeListener() {} },
      sendMessage: (msgPayload, cb) => {
        const t = msgPayload && msgPayload.type
        let reply = { ok: true, status: { connected: false, unlocked: true }, chain: { bound: true, fingerprint: 'A9F4-7C2E-11B0' }, peers: [], offers: [], signals: [], journeys: [], unlocked: true, chainReady: true, readiness: 'ready', deviceId: 'preview-self' }
        if (typeof cb === 'function') cb(reply)
        return Promise.resolve(reply)
      },
      openOptionsPage: () => {},
    },
    tabs: { create: () => Promise.resolve({}), query: (_q, cb) => { if (cb) cb([]); return Promise.resolve([]) } },
  }
})()

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

let selectedFile = null
let lastPollAt = 0
let pollTimer = null
let cloudConnected = false
const seenOfferIds = new Set()
// R153 §4 — the road ledger's live facts (re-derived every poll — the beacon)
let lastLedgerFacts = { rostered: false, peerListed: false, peerSeenAt: 0, peerName: '' }
let lastLedger = null
let openRoadArmed = false
let lastRosterRows = []
// R155 §5 (ARC A, LAW #98) — THE ONE CHAIN TRUTH the page speaks: bound =
// the worker's chain keys are ready; fingerprint = the chain-root code.
// Every chain-presence surface on this page reads THIS and only this —
// never the peer count (the E-4/E-6 split-brain is dead by construction).

/* ── THE STATUS STRIP (three honest lines; NONE gates the journey) ───────── */

let chainTruth = { bound: false, fingerprint: '' }

function renderStatusStrip({ chainRows = [], connected = false, directFound = false, chain = chainTruth } = {}) {
  const rows = $('mbStatusRows')
  if (!rows) return
  rows.textContent = ''
  const mk = (cls, glyph, text) => {
    const li = document.createElement('li')
    li.className = 'readiness-row ' + cls
    const g = document.createElement('span'); g.className = 'glyph'; g.textContent = glyph
    const t = document.createElement('span'); t.textContent = text
    li.append(g, t)
    return li
  }
  const names = chainRows.map((r) => r.label).filter(Boolean)
  // R155 §5 (A.2, LAW #98) — ROW ONE IS THE CHAIN TRUTH (one source: the
  // worker's chain keys, never the peer count). A bound device is NEVER
  // told its chain does not exist; the cloud row that follows is the
  // ACCELERATOR, never the repair (the E-6 defect is dead by law).
  const bound = !!(chain && chain.bound)
  const fp = String((chain && chain.fingerprint) || '')
  if (bound && fp) {
    rows.append(mk('ok', '✓', names.length
      ? msg('mbStatusChainPresent', [fp, String(names.length)], `Chain present · ${fp} · ${names.length} device${names.length === 1 ? '' : 's'} paired`)
      : msg('mbStatusChainSolo', [fp], `Chain present · ${fp} · just this device — pair one below when ready`)))
  } else {
    // Truthful in BOTH not-ready cases (no sync code at all, or the vault
    // locked): the chain is not READY — never a denial of an existing chain.
    rows.append(mk('info', '•', msg('mbStatusChainNone', undefined, 'No chain is ready on this device yet — unlock the vault, or create or join one (Cloud Sync tab)')))
  }
  // Devices — ALWAYS true from the chain's own roster (never empty, never gating)
  rows.append(mk('ok', '✓', names.length
    ? msg('mbStatusDevices', [names.slice(0, 3).join(', '), String(names.length)], `In your chain: ${names.slice(0, 3).join(', ')} (${names.length})`)
    : msg('mbStatusDevicesNone', undefined, 'In your chain: just this device — add one below when you are ready')))
  // Direct — the honest direct truth (states, not gates)
  rows.append(mk(directFound ? 'ok' : 'info', directFound ? '✓' : '•', directFound
    ? msg('mbStatusDirectOk', undefined, 'Direct — available on this network')
    : msg('mbStatusDirectWait', undefined, 'Direct — waiting for the other device to open UCrypt (or use the QR handshake)')))
  // R155 §5 (A.2) — the pair hint: with the chain solo, the pairing door is
  // named as its own peer — the cloud row is never the only door on offer.
  if (bound && !names.length) {
    rows.append(mk('info', '•', msg('mbStatusPairHint', undefined, 'Pairing works with the cloud OFF — the invitation crosses by hand or QR.')))
  }
  // Cloud — the truth, with the direct alternative named (the F-6 cure)
  rows.append(mk(connected ? 'ok' : 'info', connected ? '✓' : '•', connected
    ? msg('mbStatusCloudOk', undefined, 'Cloud connected — the relay is ready if direct cannot reach')
    : msg('mbStatusCloudNo', undefined, 'Cloud not connected — direct and QR still work; connect for the automatic relay')))
  const btn = $('mbConnectCloud')
  if (btn) {
    btn.textContent = msg('mbConnectCloud', undefined, 'Connect Cloud Sync')
    btn.hidden = connected
  }
  const addDevBtn = $('mbAddDevice')
  if (addDevBtn) {
    addDevBtn.hidden = false
  }
  // UCRYPT-23: Update Cloud Sync style status chips in #mbRoadChipsStrip
  const chainDot = $('mbChipChainDot')
  const chainTxt = $('mbChipChainText')
  if (chainDot && chainTxt) {
    chainDot.className = 'sync-chip-dot ' + (bound && fp ? 'ok' : 'warn')
    chainTxt.textContent = bound && fp
      ? (names.length
        ? `Sync chain: ${fp} (${names.length} peer${names.length === 1 ? '' : 's'})`
        : `Sync chain: ${fp} (this device)`)
      : 'Sync chain: not bound yet'
  }
  const directDot = $('mbChipDirectDot')
  const directTxt = $('mbChipDirectText')
  if (directDot && directTxt) {
    directDot.className = 'sync-chip-dot ' + (directFound ? 'ok' : '')
    directTxt.textContent = directFound
      ? 'Direct road: active on network'
      : 'Direct road: ready (WebRTC / QR)'
  }
  const cloudDot = $('mbChipCloudDot')
  const cloudTxt = $('mbChipCloudText')
  if (cloudDot && cloudTxt) {
    cloudDot.className = 'sync-chip-dot ' + (connected ? 'ok' : 'warn')
    cloudTxt.textContent = connected
      ? 'Cloud relay: connected'
      : 'Cloud relay: not connected (optional)'
  }
  const hdr = $('mbHeaderStatus')
  if (hdr) {
    hdr.textContent = connected
      ? msg('mbHeaderLive', undefined, 'Direct is first — the cloud relay is ready')
      : msg('mbHeaderIdle', undefined, 'Direct first — the cloud relay is optional')
  }
  renderRoadLedgerRow(rows)
}

/* R153 §4 (R-1) — the ledger row: one li carrying the chip line + a details
   with the four typed stages (MEMBERSHIP → SIGNALING → ICE → DATACHANNEL).
   ONE writer: renderRoadLedgerRow. The beacon (R-7) re-derives on the signal
   cadence, so a road lost mid-session types itself within one probe cycle. */
export function renderRoadLedgerRow(chainRows) {
  const rows = $('mbStatusRows')
  if (!rows) return
  const sel = $('mbRecipient') || $('jrRecipient')
  const chosen = sel && sel.value ? chainRows.find((p) => p.deviceId === sel.value) : chainRows[0]
  const facts = {
    ...lastLedgerFacts,
    // R155 §5 (LAW #98) — membership keys on the ONE chain truth (the
    // worker's chain keys), NEVER on the peer count: a bound device with
    // zero paired peers is a CHAIN WAITING FOR ITS FIRST PAIR, not a
    // chain-less device.
    rostered: !!(chainTruth.bound || lastLedgerFacts.rostered),
    peerListed: !!chosen,
    peerSeenAt: chosen ? Number(chosen.lastSeen || 0) : 0,
    peerName: chosen ? chosen.label : '',
    cloudSignaling: cloudConnected,
  }
  lastLedgerFacts = facts
  let ledger
  try { ledger = deriveRoadLedger(facts) } catch { return }
  lastLedger = ledger
  const li = document.createElement('li')
  li.className = 'readiness-row info road-ledger-row'
  li.id = 'mbRoadLedgerRow'
  const g = document.createElement('span'); g.className = 'glyph'; g.textContent = '•'
  const t = document.createElement('span'); t.textContent = ledger.line
  li.append(g, t)
  if (ledger.action) {
    const a = document.createElement('span')
    a.className = 'card-help'
    a.style.marginLeft = '4px'
    a.textContent = '— ' + ledger.action
    li.append(a)
  }
  const old = document.getElementById('mbRoadLedgerRow')
  if (old) old.remove()
  rows.append(li)
  // the expandable why — the four stages, one line each (LAW #92: the why AND the cure)
  const det = document.createElement('details')
  det.id = 'mbRoadLedgerWhy'
  det.style.cssText = 'margin:2px 0 0 26px'
  const sum = document.createElement('summary')
  sum.textContent = msg('mbRoadWhy', undefined, 'Why this road state? (the typed chain)')
  sum.style.cssText = 'cursor:pointer;font-size:0.78rem;color:var(--muted)'
  const box = document.createElement('div')
  box.style.cssText = 'font-size:0.78rem;color:var(--muted);display:flex;flex-direction:column;gap:2px;margin-top:4px'
  for (const line of ledgerLines(ledger)) {
    const s = document.createElement('span'); s.textContent = line; box.append(s)
  }
  det.append(sum, box)
  const oldWhy = document.getElementById('mbRoadLedgerWhy')
  if (oldWhy) oldWhy.remove()
  rows.append(det)
  // R-2 — the bridge button surfaces exactly when the road is absent
  const openBtn = $('mbOpenRoadBtn')
  if (openBtn) {
    const noRoad = !ledger.road && ledger.tone === 'no-road'
    openBtn.hidden = !noRoad
    if (noRoad && chosen) {
      openBtn.textContent = msg('mbOpenRoadTo', [chosen.label], `Open a road to $1 (no cloud)`)
    } else if (noRoad) {
      openBtn.textContent = msg('mbOpenRoad', undefined, 'Open a road (no cloud)')
    }
  }
}

/* ── THE ROSTER (the chain's own — the F-5 law) ──────────────────────────── */

export async function renderRoster() {
  const legacySel = $('mbRecipient')
  const sel = legacySel || $('jrRecipient')
  const r = await door('BRIDGE_ROSTER')
  // R155 §5 (A.1, LAW #98) — the ONE chain truth lands here, from the ONE
  // store (the worker's chain keys) — every surface below reads it.
  if (r.ok && r.chain) chainTruth = { bound: !!r.chain.bound, fingerprint: String(r.chain.fingerprint || '') }
  if (!r.ok) {
    // The keys are not ready (locked vault / no sync code): the honest
    // not-ready state — never a silent strip, never a false denial.
    chainTruth = { bound: false, fingerprint: '' }
    renderRosterEmpty()
    renderStatusStrip({ chainRows: [], connected: false, chain: chainTruth })
    return []
  }
  const rows = rosterProjection(r.peers || [], { rendezvousAvailable: !!r.connected, selfId: r.self && r.self.memberId })
  const canWriteSelect = legacySel || (sel && !document.getElementById('jrSendCard'))
  if (canWriteSelect && sel) {
    sel.textContent = ''
    for (const p of rows) {
      const opt = document.createElement('option')
      opt.value = p.deviceId
      // R153 §4 (R-1) — the chip on every row is the ledger's one-line truth:
      // online rows stay plain; every non-road state NAMES its ingredient.
      let state = ''
      if (p.state === 'online' && cloudConnected) state = ''
      else if (p.state === 'online') state = ' · ⚪ ' + msg('mbPeerCalling', undefined, 'calling through the cloud')
      else if (!cloudConnected) state = ' · 🔴 ' + msg('mbPeerNoRoadSignal', undefined, 'no road — signaling is down')
      else state = ' · ' + msg('mbPeerOffline', undefined, 'last seen a while ago')
      opt.textContent = `${p.label}${state}`
      sel.append(opt)
    }
    const self = document.createElement('option')
    self.disabled = true
    self.textContent = msg('mbSelfOption', [String(r.self && r.self.name ? r.self.name : 'this device')], '(this device)')
    sel.append(self)
  }
  updateSendGate(rows) // R154 §5 (A.3a) — the pre-flight gate owns the Send truth
  renderWarmLine(sel ? sel.value : '', rows)
  lastRosterRows = rows
  renderStatusStrip({ chainRows: rows, connected: !!r.connected, chain: chainTruth })
  if (!rows.length) renderRosterEmpty()
  return rows
}

/* R153 §4 (R-4) — THE WARM RE-DIAL LINE: the last road with the chosen peer,
   typed honestly. Silent when the cloud can carry the call; the one bridge
   hop when it cannot. Never a silent dead road. */
function renderWarmLine(deviceId, rows) {
  const el = $('mbWarmLine')
  if (!el) return
  el.textContent = ''
  if (!deviceId) return
  let profile = null
  try { profile = decodeWarmProfile(localStorage.getItem('ucrypt:bridge:warm:' + deviceId) || '', { now: Date.now() }) } catch { profile = null }
  const plan = warmReDialPlan(profile, { cloudSignaling: cloudConnected })
  if (plan && plan.line) el.textContent = plan.line
}

export function renderRosterEmpty() {
  const teach = emptyRosterTeaching()
  const legacySel = $('mbRecipient')
  const sel = legacySel || $('jrRecipient')
  const canWriteSelect = legacySel || (sel && !document.getElementById('jrSendCard'))
  if (canWriteSelect && sel) {
    sel.textContent = ''
    const opt = document.createElement('option')
    opt.value = ''
    opt.textContent = msg('mbRosterEmpty', teach.line, teach.line)
    sel.append(opt)
  }
  const cta = $('mbAddDevice')
  if (cta) cta.hidden = false
}

/* R154 §5 (A.3a) — THE SEND PRE-FLIGHT GATE (the dead-click cure, LAW #87
   honest): Send enables ONLY when a REAL road is plausible — the cloud
   carries the relay (cloud up), or a real contact happened inside the
   presence TTL (cloud-less; LAW #87 forbids a fabricated green, so the
   gate keys on contact freshness, not on a colored chip). A gated Send
   shows WHY in one line (#mbSendWhy — this function is its ONE writer);
   the wake action is the road ledger's own Open-a-road button. */
export function updateSendGate(rows) {
  const sel = $('mbRecipient') || $('jrRecipient')
  const btn = $('mbSend')
  if (!btn) return
  const list = Array.isArray(rows) ? rows : []
  const picked = sel && sel.value ? list.find((p) => p.deviceId === sel.value) : null
  let open = !!(sel && sel.value && selectedFile)
  let why = ''
  if (sel && sel.value && selectedFile) {
    if (!list.length) {
      // R155 §5 (A.3, LAW #98) — the REAL reason, named: the chain may be
      // perfectly present — there is just no paired device yet.
      open = false
      why = msg('mbSendWhyNoPeer', undefined, 'No paired device yet — press “Pair a device” below (it takes a minute).')
    } else if (!picked) {
      open = false // the selection went stale under a roster re-render
      why = msg('mbSendWhyStaleSel', undefined, 'That device is no longer in the roster — re-pick the target.')
    } else if (!cloudConnected) {
      const fresh = Number(picked.lastSeen) > 0 && (Date.now() - Number(picked.lastSeen)) <= PRESENCE_TTL_MS
      open = fresh
      if (!fresh) {
        why = msg('mbSendWhyStale', [picked.label], `No live contact with ${picked.label} in the last 15 minutes — press “Open a road (no cloud)” to re-check, or wait for their next contact.`)
      }
    }
    // cloud up: the relay road is real regardless of the presence annotation —
    // the road ledger's badge names the road; the gate stays open (the honest
    // chip still annotates; a blocked relay on an unknown chip would be a
    // dead click of the worst class).
  }
  btn.disabled = !open
  const whyEl = $('mbSendWhy')
  if (whyEl) whyEl.textContent = open ? '' : why
}

/* ── R154 §5 — THE DEVICE BOND DOOR (the roster's front door) ────────────
   THE S1 CURE: the empty roster is legal ONLY with its pairing doors inline
   (the owner's E-1 annotation + LAW #97). The invitation is THIS device's
   bond stamp sealed under the chain group key — only a device holding the
   SAME chain secret can open it (the A.2.e gate, cryptographic). Each hop
   writes the ONE sealed peer map (chrome.storage.local — G123 survives). */

let bondStampSealed = ''
let bondWords = ''

function showBondDoor() {
  const doorEl = $('mbBondDoor')
  if (!doorEl) return
  doorEl.hidden = false
  if ('open' in doorEl) doorEl.open = true
  if (!$('mbBondState').textContent) {
    $('mbBondState').textContent = msg('mbBondIdle', undefined, 'Show your invitation on the other device — or paste their reply below. Both devices must share the same sync code.')
  }
  renderBondFingerprint()
  try { doorEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) } catch { /* the open is the signal */ }
}

/* R155 §7 (C.1) — the fingerprint block's ONE writer: the code comes from
   the ONE chain truth (BRIDGE_ROSTER's chain field); a not-ready vault
   says so honestly — the block never fabricates a code. */
async function renderBondFingerprint() {
  const fpEl = $('mbBondFp')
  const codeEl = $('mbBondFpCode')
  if (!fpEl || !codeEl) return
  fpEl.hidden = false
  try {
    const r = await door('BRIDGE_ROSTER')
    if (r.ok && r.chain && r.chain.bound && r.chain.fingerprint) {
      chainTruth = { bound: true, fingerprint: String(r.chain.fingerprint) }
      codeEl.textContent = r.chain.fingerprint
      codeEl.classList.remove('bond-fp-none')
    } else {
      chainTruth = { bound: false, fingerprint: '' }
      codeEl.textContent = msg('mbBondFpUnavailable', undefined, 'The vault is locked or no sync code is set — unlock UCrypt (or set the sync code) to show this device\u2019s chain code.')
      codeEl.classList.add('bond-fp-none')
    }
  } catch { /* the block never breaks the door */ }
}

async function bondFpCopy() {
  const b = $('mbBondFpCopy')
  try {
    const codeEl = $('mbBondFpCode')
    const text = chainTruth.fingerprint || (codeEl ? codeEl.textContent : '')
    if (!text) return
    await navigator.clipboard.writeText(text)
    if (b) {
      b.textContent = msg('mbBondFpCopied', undefined, 'Copied ✓ — compare with the other device')
      setTimeout(() => { b.textContent = msg('mbBondFpCopy', undefined, 'Copy code') }, 2500)
    }
  } catch (e) {
    const state = $('mbBondState')
    if (state) state.textContent = String((e && e.message) || e).slice(0, 200)
  }
}

function bondText(sealedB64) {
  return buildBondText({ sealedPayload: sealedB64 })
}

function renderBondFrames(text) {
  const holder = $('mbBondFrames')
  if (!holder) return
  holder.textContent = ''
  holder.hidden = false
  const frame = (t, i, n) => {
    const wrap = document.createElement('div')
    wrap.className = 'qr-frame'
    const label = document.createElement('p')
    label.className = 'card-help'
    label.textContent = n > 1 ? msg('mbQrFrameLabel', [String(i), String(n)], `Frame ${i} of ${n}`) : ''
    const img = document.createElement('div')
    img.className = 'qr-img'
    try {
      const url = (typeof QR !== 'undefined') ? QR.encode(t) : ''
      if (url) {
        const im = document.createElement('img')
        im.src = url
        im.alt = msg('mbBondQrAlt', [String(i)], `Pairing invitation frame ${i}`)
        im.width = 148
        im.height = 148
        img.append(im)
      } else {
        img.classList.add('qr-img-fallback') // R155 §7 (C.2, U-1): themed text, never white-on-white
        img.textContent = msg('mbQrUnavailable', undefined, '(the QR encoder is unavailable — use the words below)')
      }
    } catch {
      img.classList.add('qr-img-fallback') // R155 §7 (C.2, U-1): the fallback is themed text, never white-on-white
      img.textContent = msg('mbQrTooBig', undefined, '(this frame is too large — use the words below)')
    }
    wrap.append(label, img)
    return wrap
  }
  // one QR when it fits; the framed fallback otherwise (the words token
  // below is always the reliable carry)
  try {
    holder.append(frame(text, 1, 1))
  } catch {
    holder.textContent = ''
    const frames = frameBundleText(text)
    frames.forEach((f, k) => holder.append(frame(f, k + 1, frames.length)))
  }
}

async function bondInvite() {
  const state = $('mbBondState')
  try {
    // R155 (LAW #89 class) — the named action while the seal runs
    state.textContent = msg('mbPairBusy', undefined, 'Sealing your invitation…')
    const r = await door('BRIDGE_BOND_SEAL')
    if (!r.ok) throw new Error(r.userMessage || msg('mbBondSealFail', undefined, 'The invitation could not be sealed — unlock the vault (the chain keys must be ready) and try again.'))
    bondStampSealed = r.sealedB64
    const text = bondText(bondStampSealed)
    bondWords = bundleToWordsToken(text)
    renderBondFrames(text)
    const ta = $('mbBondWords')
    ta.value = bondWords
    ta.hidden = false
    $('mbBondCopyBtn').hidden = false
    $('mbBondShowBtn').textContent = msg('mbBondShowAgain', undefined, 'Refresh my invitation')
    state.textContent = msg('mbBondInvited', undefined, 'Invitation ready — show the QR (or send the words) to the other device. They press “Pair their reply” here with YOUR invitation on their side; then paste THEIR reply below.')
  } catch (e) {
    state.textContent = String((e && e.message) || e).slice(0, 200) // never silent (LAW #89)
  }
}

function bondSealedFromText(raw) {
  const text = String(raw || '').trim()
  if (!text) throw new Error(msg('mbBondNeedReply', undefined, 'Paste their reply (or read their QR image) first — nothing to pair yet.'))
  // one parse, three carries: the raw JSON (the QR), the words token (the
  // copy/paste), the multi-frame paste (one "i|n|chunk" line per frame)
  const attempts = [
    () => parseBondText(text),
    () => parseBondText(wordsTokenToBundle(text)),
    () => parseBondText(parseBundleFrames(text.split(/\n+/))),
  ]
  for (const attempt of attempts) {
    try {
      return attempt().sealed
    } catch (e) {
      if (e && e.code === 'BRIDGE_SIGNAL_EXPIRED') {
        throw new Error(msg('mbBondExpired', undefined, 'That invitation expired (10 minutes) — ask for a fresh one.'))
      }
    }
  }
  throw new Error(msg('mbBondBadText', undefined, 'That is not a pairing invitation — ask the other device to send their invitation words or QR.'))
}

async function bondLearn() {
  const state = $('mbBondState')
  try {
    const sealedB64 = bondSealedFromText($('mbBondReply').value)
    const r = await door('BRIDGE_BOND_LEARN', { sealedB64 })
    if (!r.ok) throw new Error(r.userMessage || msg('mbBondFail', undefined, 'The pairing could not complete — run the connection doctor below.'))
    const name = (r.learned && r.learned.label) || msg('mbPeerWord', undefined, 'a chain device')
    // R155 §6 (B.3, LAW #99) — the completion card teaches the ONE-TIME
    // law: the door is a door, not a subscription — and names the next step.
    state.textContent = msg('mbBondLearnedOk', [name], `✓ Paired with ${name} — they are in your device list now. Now let THEM pair YOU: show your invitation and paste it on their side.`)
    const once = document.createElement('span')
    once.className = 'card-help'
    once.style.display = 'block'
    once.style.marginTop = '4px'
    once.textContent = msg('mbBondOnceLine', undefined, 'Pair once — the device stays in your list through restarts and sleep. Re-pair only to repair.') + ' ' + msg('mbPairDoneNext', undefined, 'Next: pick them in “Send to” and send a file — the road opens automatically.')
    state.append(once)
    $('mbBondReply').value = ''
    if (!bondStampSealed) await bondInvite()
    await renderRoster()
  } catch (e) {
    state.textContent = String((e && e.message) || e).slice(0, 200) // the typed refusal (foreign chain, key change) lands here
  }
}

async function bondCopy() {
  try {
    await navigator.clipboard.writeText(bondWords || $('mbBondWords').value || '')
    const b = $('mbBondCopyBtn')
    b.textContent = msg('mbBondCopied', undefined, 'Copied ✓')
    setTimeout(() => { b.textContent = msg('mbBondCopy', undefined, 'Copy invitation') }, 2500)
  } catch (e) {
    $('mbBondState').textContent = String((e && e.message) || e).slice(0, 200)
  }
}

function bondScan() {
  const input = $('mbBondFileInput')
  input.value = ''
  input.click()
  input.onchange = async () => {
    const f = input.files && input.files[0]
    if (!f) return
    try {
      const r = await importQrImage(f)
      $('mbBondReply').value = r
      $('mbBondState').textContent = msg('mbBondRead', undefined, 'The QR image was read — press “Pair their reply” to complete the bond.')
    } catch (e) {
      $('mbBondState').textContent = String((e && e.message) || e).slice(0, 200)
    }
  }
}

/* ── THE SEND (the road is picked automatically; the badge says which) ───── */

async function sendFile() {
  if (!selectedFile) return
  const sel = $('mbRecipient') || $('jrRecipient')
  const toMemberId = sel ? sel.value : ''
  if (!toMemberId) return
  const btn = $('mbSend') || $('jrSend')
  if (btn) btn.disabled = true
  const peerName = sel && sel.selectedOptions && sel.selectedOptions[0] ? sel.selectedOptions[0].textContent.replace(/ · .*$/, '') : ''
  renderJourneyLine(msg('mbSending', undefined, 'Connecting directly…'))
  try {
    // ROAD 1/2 — THE DIRECT ROAD (the owner's law: point-to-point first)
    const direct = await directSend({
      file: selectedFile, peerMemberId: toMemberId, peerName, cloudConnected,
      onLine: renderJourneyLine,
      onProgress: (p) => import('../bridge/page.js').then((m) => m.directProgress(p)),
    })
    if (direct && direct.ok) {
      renderJourneyLine(msg('mbDirectDone', [peerName], `Sent — verified on ${peerName}'s device (direct).`))
      // R153 §4 (R-4) — THE WARM PROFILE: any successful road is remembered
      // (device-local, per peer) so the NEXT session re-dials warm — silent
      // through the cloud, or the one typed bridge hop when it is down.
      try {
        localStorage.setItem('ucrypt:bridge:warm:' + toMemberId,
          encodeWarmProfile({ deviceId: toMemberId, name: peerName, road: direct.road || '', savedAt: Date.now() }))
      } catch { /* the convenience never blocks the receipt */ }
      finishSend()
      return
    }
    if (direct && direct.demoted) {
      // ROAD 3 — the automatic relay; the announcement is the plain-words truth
      renderJourneyLine(direct.announcement)
      await relaySend({ toMemberId, toName: peerName })
      return
    }
    renderJourneyLine(direct && direct.userMessage ? direct.userMessage : msg('mbSendFailed', undefined, 'Could not send — Run the connection doctor below.'))
  } catch (e) {
    renderJourneyLine(String((e && e.message) || e).slice(0, 160))
  } finally {
    updateSendGate(lastRosterRows) // the gate re-derives the Send truth after every attempt
  }
}

async function relaySend({ toMemberId, toName }) {
  try {
    const bytes = new Uint8Array(await selectedFile.arrayBuffer())
    let bin = ''
    for (let i = 0; i < bytes.length; i += 32768) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, bytes.length)))
    }
    const bytesB64 = btoa(bin)
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    const sha256 = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
    const r = await door('MAILBOX_SEND', {
      fileName: selectedFile.name, size: selectedFile.size, sha256, toMemberId,
      toName, bytesB64,
    })
    if (r.ok) {
      renderJourneyLine(r.journey && r.journey.line ? r.journey.line : msg('mbDelivered', undefined, 'Delivered — their UCrypt picks it up automatically.'))
      try {
        localStorage.setItem('ucrypt:bridge:warm:' + toMemberId,
          encodeWarmProfile({ deviceId: toMemberId, name: toName, road: 'relay', savedAt: Date.now() }))
      } catch { /* the convenience never blocks the receipt */ }
      finishSend()
    } else {
      renderJourneyLine(r.userMessage || msg('mbSendFailed', undefined, 'Could not deliver — Run the connection doctor below.'))
    }
  } catch {
    renderJourneyLine(msg('mbSendFailed', undefined, 'Could not deliver — Run the connection doctor below.'))
  }
}

/* R153 §4 (R-2) — OPEN A ROAD: the bridge journey, armed. One click asks
   for the file (it waits — nothing moves until the road is up), then the
   send starts: cloud up → the relay carries the call automatically (R-3);
   cloud down → the QR/words door shows on its own (the two-hop bridge). */
function openRoad() {
  openRoadArmed = true
  if (selectedFile) { sendFile(); return }
  renderJourneyLine(msg('mbOpenRoadArmed', undefined, 'Choose the file — the road opens right after (nothing moves until both codes match).'))
  pickFile()
}

function finishSend() {
  selectedFile = null
  const fnEl = $('mbFileName') || $('jrFileName')
  if (fnEl) fnEl.textContent = ''
  const btn = $('mbSend') || $('jrSend')
  if (btn) btn.disabled = true
}

/* ── THE RECEIVE CARD (relay offers + the direct incoming) ───────────────── */

function renderPollLine(connected, checkedAt) {
  // ONE writer: this function is the only code path that touches mbPollLine.
  if (!connected) {
    $('mbPollLine').textContent = msg('mbPollNoCloud', undefined, 'Direct transfers arrive live. The relay needs Cloud Sync — offers arrive on their own when it is connected.')
    return
  }
  const ago = checkedAt ? Math.max(0, Math.round((Date.now() - checkedAt) / 1000)) : null
  $('mbPollLine').textContent = ago == null
    ? msg('mbPollIdle', undefined, 'Checking for incoming files every 60 s…')
    : msg('mbPollActive', ['60', String(ago)], `Checking for incoming files every 60 s · last checked ${ago}s ago`)
}

function renderOffers(offers) {
  const list = $('mbOfferList')
  list.textContent = ''
  const live = (offers || []).filter((o) => !o.refused)
  if (!live.length) {
    const empty = document.createElement('p')
    empty.className = 'card-help'
    empty.textContent = msg('mbNoOffers', undefined, 'Nothing waiting right now. Incoming files appear here — direct ones ask first.')
    list.append(empty)
    return
  }
  for (const o of live) {
    seenOfferIds.add(o.offerId)
    const card = document.createElement('div')
    card.className = 'offer-card'
    const from = document.createElement('div')
    from.className = 'from-line'
    from.textContent = msg('mbOfferFrom', [o.fromName, o.fileName, fmtSize(o.size)], `From ${o.fromName} · ${o.fileName} (${fmtSize(o.size)})`)
    const code = document.createElement('div')
    code.className = 'code-line'
    code.textContent = msg('mbOfferCode', [o.verifyCode], `Code: ${o.verifyCode}`)
    const btns = document.createElement('div')
    btns.className = 'btn-row'
    const accept = document.createElement('button')
    accept.className = 'btn btn-primary btn-sm'
    accept.type = 'button'
    accept.textContent = msg('mbAccept', undefined, 'Accept')
    accept.addEventListener('click', () => acceptOffer(o, card))
    const decline = document.createElement('button')
    decline.className = 'btn btn-ghost btn-sm'
    decline.type = 'button'
    decline.textContent = msg('mbDecline', undefined, 'Decline')
    decline.addEventListener('click', () => declineOffer(o, card))
    btns.append(accept, decline)
    card.append(from, code, btns)
    list.append(card)
  }
}

function fmtSize(n) {
  const b = Number(n) || 0
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

async function acceptOffer(o, card) {
  const r = await door('MAILBOX_ACCEPT', { offerId: o.offerId, code: o.verifyCode })
  const line = document.createElement('p')
  line.className = 'card-help'
  if (r.ok) {
    line.textContent = msg('mbSavedVerified', [o.fileName], `Saved · Verified — ${o.fileName}`)
    card.querySelector('.btn-row')?.remove()
  } else {
    line.textContent = r.userMessage || msg('mbAcceptFailed', undefined, 'The incoming file could not be collected — Run the connection doctor below.')
  }
  card.append(line)
}

async function declineOffer(o, card) {
  // the decline requires the click it names — no auto-dismiss, no timers
  const r = await door('MAILBOX_DECLINE', { offerId: o.offerId })
  if (r.ok) card.remove()
}

/* ── THE DIRECT INCOMING (the relay-signaled offers ask on their own) ────── */

async function pollDirectSignals() {
  const poll = await door('BRIDGE_SIGNAL_POLL')
  if (!poll.ok) return
  const list = $('mbDirectInList')
  if (!list) return
  const offers = (poll.signals || []).filter((s) => s.envelope && s.envelope.kind === 'bridge-offer')
  if (!offers.length) return
  for (const s of offers) {
    if (seenOfferIds.has('direct-' + s.signalId)) continue
    seenOfferIds.add('direct-' + s.signalId)
    try {
      const opened = await door('BRIDGE_OPEN', { sealedB64: s.envelope.payload.sealedB64 || '' })
      if (!opened.ok) continue
      const p = opened.payload
      const card = document.createElement('div')
      card.className = 'offer-card'
      const from = document.createElement('div')
      from.className = 'from-line'
      from.textContent = msg('mbDirectInFrom', [p.fileName || 'a file', fmtSize(p.size || 0)], `${p.fileName || 'A file'} (${fmtSize(p.size || 0)}) — arriving directly`)
      const btns = document.createElement('div')
      btns.className = 'btn-row'
      const accept = document.createElement('button')
      accept.className = 'btn btn-primary btn-sm'
      accept.type = 'button'
      accept.textContent = msg('mbAccept', undefined, 'Accept')
      accept.addEventListener('click', async () => {
        btns.remove()
        const line = document.createElement('p'); line.className = 'card-help'
        card.append(line)
        try {
          const res = await directReceive({ payload: p, onLine: (t) => { line.textContent = t || '' } })
          if (!res.ok) line.textContent = msg('mbDirectInFailed', undefined, 'The direct answer could not be built.')
        } catch (e) {
          line.textContent = String((e && e.message) || e).slice(0, 160)
        }
      })
      const decline = document.createElement('button')
      decline.className = 'btn btn-ghost btn-sm'
      decline.type = 'button'
      decline.textContent = msg('mbDecline', undefined, 'Decline')
      decline.addEventListener('click', async () => {
        await door('BRIDGE_SIGNAL_CONSUME', { sessionId: s.sessionId, signalId: s.signalId })
        await door('BRIDGE_SESSION_CLOSE', { sessionId: s.sessionId })
        card.remove()
      })
      btns.append(accept, decline)
      card.append(from, btns)
      list.append(card)
    } catch { /* a garbled offer never breaks the card */ }
  }
}

/* ── The fallback (.ucrypt-offer) — one file, no conversation (§5.7) ─────── */

async function exportOffer() {
  const input = $('mbFileInput')
  input.value = ''
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
      $('mbFallbackState').textContent = msg('mbExportDone', [r.fileName], `The file is saved — move it to the other device and press Import file there. (${r.fileName}${codeSuffix})`)
    } else {
      $('mbFallbackState').textContent = r.userMessage || msg('mbExportFailed', undefined, 'The export could not be built.')
    }
  }
}

async function importOffer() {
  const input = $('mbFileInput')
  input.value = ''
  input.accept = '.ucrypt-offer'
  input.click()
  input.onchange = async () => {
    const f = input.files && input.files[0]
    if (!f) return
    const bytes = new Uint8Array(await f.arrayBuffer())
    let bin = ''
    for (let i = 0; i < bytes.length; i += 32768) bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, bytes.length)))
    const code = window.prompt(msg('mbImportCodePrompt', undefined, 'Type the verification code the sender showed you (6 digits):')) || ''
    const r = await door('MAILBOX_IMPORT_OFFER', { fileB64: btoa(bin), code: code.replace(/\s+/g, '') })
    if (r.ok) {
      $('mbFallbackState').textContent = msg('mbImportDone', [r.fileName], `Verified — ${r.fileName} from ${r.fromName}. Import complete.`)
    } else {
      $('mbFallbackState').textContent = r.userMessage || msg('mbImportFailed', undefined, 'The file could not be imported.')
    }
  }
}

/* ── THE DOCTOR v2 (five plain-word hops, each with its ONE action) ──────── */

async function runDoctor() {
  const rows = $('jrDoctorRows') || $('mbDoctorRows')
  if (!rows) return
  rows.textContent = ''
  const pending = document.createElement('p')
  pending.className = 'card-help'
  pending.textContent = msg('mbDoctorRunning', undefined, 'Testing every hop…')
  rows.append(pending)
  const r = await door('MAILBOX_DOCTOR')
  const roster = await door('BRIDGE_ROSTER')
  if (roster.ok && roster.chain) chainTruth = { bound: !!roster.chain.bound, fingerprint: String(roster.chain.fingerprint || '') }
  const chainRows = roster.ok ? rosterProjection(roster.peers || [], { rendezvousAvailable: !!roster.connected, selfId: roster.self && roster.self.memberId }) : []
  rows.textContent = ''
  // R155 §5 (A.4, LAW #98) — THE CHAIN-TRUTH ROW: the doctor speaks the ONE
  // chain state too (whole-area: every surface, one truth — the fingerprint
  // first, so a two-machine comparison starts at the top).
  const chainHop = document.createElement('div')
  chainHop.className = 'diag-hop'
  const cg = document.createElement('span'); cg.className = 'glyph'; cg.textContent = (chainTruth.bound && chainTruth.fingerprint) ? '✓' : '✗'
  const ct = document.createElement('span')
  ct.textContent = (chainTruth.bound && chainTruth.fingerprint)
    ? msg('mbDoctorChainFp', [chainTruth.fingerprint], `Chain code: ${chainTruth.fingerprint} — this device is bound to a chain`)
    : msg('mbDoctorChainNone', undefined, 'Chain code: none ready — unlock the vault or set the sync code first (Cloud Sync tab)')
  chainHop.append(cg, ct)
  rows.append(chainHop)
  const facts = {
    peerEverSeen: chainRows.some((p) => p.lastSeen > 0),
    peerSeenAt: chainRows.reduce((a, p) => Math.max(a, p.lastSeen), 0),
    directFound: false,
    relayReachable: !!(r.ok && !r.report.cloudDown),
    codeCompared: false,
    speedBps: 0,
    receiptReturned: false,
  }
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
    sub.textContent = msg('mbDoctorSub', undefined, 'The connection test\u2019s own hops:')
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

/* ── The history drawer (reassurance, 7-day window) ──────────────────────── */

async function renderHistory() {
  const j = await door('MAILBOX_JOURNEYS')
  const rows = $('mbHistoryRows')
  rows.textContent = ''
  const list = (j.ok && j.journeys) || []
  if (!list.length) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = msg('mbHistoryEmpty', undefined, 'Nothing sent in the last 7 days.')
    rows.append(p); return
  }
  for (const item of list) {
    const p = document.createElement('p'); p.className = 'card-help'
    p.textContent = `${item.fileName} → ${item.toName}: ${item.line || item.state}`
    rows.append(p)
  }
}

/* ── The poll lifecycle — unconditional, honest (§7.7) ───────────────────── */

async function pollOnce() {
  // the presence heartbeat rides the poll cadence (the 5-minute law is the
  // worker's to enforce; the page just asks)
  door('BRIDGE_PRESENCE_STAMP').catch(() => {})
  const st = await door('MAILBOX_STATUS')
  cloudConnected = !!(st.ok && st.status && st.status.connected)
  await renderRoster()
  renderPollLine(cloudConnected, cloudConnected ? Date.now() : 0)
  if (cloudConnected) {
    const p = await door('MAILBOX_POLL')
    if (p.ok) renderOffers(p.offers)
    await renderReceipts()
  }
  await pollDirectSignals()
  if (!$('mbReceiveCard').hidden) await renderHistory()
}

async function renderReceipts() {
  const r = await door('MAILBOX_RECEIPTS')
  if (!r.ok) return
  const j = await door('MAILBOX_JOURNEYS')
  if (j.ok && j.journeys && j.journeys.length) {
    renderJourneyLine(j.journeys[j.journeys.length - 1].line || '')
  }
}

function renderJourneyLine(line) {
  // R156 feed mode: the journey line is the JOURNEY's surface (ONE writer —
  // LAW #69's one-spot law); the feed's lines ride its OWN why-line
  // (mbSendWhy) so the frozen flow's line is never contended.
  const own = $('mbSendWhy')
  if (document.getElementById('jrSendCard') && own) {
    own.textContent = line || ''
    return
  }
  const el = $('mbSendJourney')
  if (el) el.textContent = line || ''
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(pollOnce, 60000)
  // THE SIGNAL CADENCE: the direct handshakes live 120 s — a 60 s poll could
  // miss one near expiry. The signal read is a cheap index read; it rides its
  // own 5 s cadence while the page is visible (the offers keep the honest 60 s).
  setInterval(() => {
    if (!document.hidden) {
      pollDirectSignals().catch(() => {})
      // R153 §4 (R-7) — THE BEACON: the road ledger re-derives on this cheap
      // cadence from the CACHED facts (no extra doors, no fake pings) — a
      // road lost mid-session types itself within one probe cycle.
      try { renderRoadLedgerRow(lastRosterRows) } catch { /* the beacon never breaks the page */ }
    }
  }, 5000)
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) pollOnce()
  })
  window.addEventListener('focus', () => pollOnce())
}

/* ── wiring ──────────────────────────────────────────────────────────────── */

async function boot() {
  // THE THEME LAW (§6): the iframe resolves the SAME persisted preference as
  // its host and watches for the toggle — the mixed-theme class is dead.
  try { await bootTheme({ storage: chrome.storage }) } catch { /* the fallback stands */ }
  // UCRYPT-28: Apply Settled-House disclosure state to Device Transfer collapsible cards
  try { SettledHouse.applyAll(document) } catch { /* best-effort */ }
  // i18n pass over the static data-i18n surfaces (the ONE writer for each)
  for (const el of document.querySelectorAll('[data-i18n]')) {
    const t = msg(el.getAttribute('data-i18n'), undefined, el.textContent)
    if (t) el.textContent = t
  }
  // R156 (the R155-A port, D-3.5) — THE FEED-MODE ADAPTER: when the
  // ancestor's journey controller is on the page (jrSendCard present), it is
  // the PRIMARY path and owns the shared flow surfaces (the code panel, the
  // universal paste door, the journey line). THIS module becomes the FEED:
  // its own sections (the status strip, the bond door, the manual bridge)
  // wire as before; every shared flow id DEFERS to the journey — never a
  // second writer, never a bypass of the frozen seal.
  const journeyPrimary = !!document.getElementById('jrSendCard')
  // R155 §7 (C.1/C.2) — the i18n'd attribute surfaces (the boot pass covers
  // textContent only; aria-labels and placeholders carry their own keys)
  const stepsEl = $('mbBondSteps')
  if (stepsEl) stepsEl.setAttribute('aria-label', msg('mbBondStepsLabel', undefined, 'The pairing ritual in three steps'))
  const replyTa = $('mbBondReply')
  if (replyTa) replyTa.placeholder = msg('mbBondReplyHint', undefined, 'Paste their reply words here — or read their QR image.')
  const roleSendBtn = $('mbRoleSend')
  if (roleSendBtn) roleSendBtn.addEventListener('click', () => {
    $('mbSendCard').hidden = false
    $('mbReceiveCard').hidden = true
    renderRoster()
  })
  const roleReceiveBtn = $('mbRoleReceive')
  if (roleReceiveBtn) roleReceiveBtn.addEventListener('click', () => {
    $('mbReceiveCard').hidden = false
    $('mbSendCard').hidden = true
    pollOnce()
  })
  const pickBtn = $('mbPickFile')
  if (pickBtn) pickBtn.addEventListener('click', pickFile)
  const recipientSel = $('mbRecipient') || $('jrRecipient')
  if (recipientSel) recipientSel.addEventListener('change', () => { updateSendGate(lastRosterRows); renderWarmLine(recipientSel.value, lastRosterRows); renderRoadLedgerRow(lastRosterRows) })
  const sendBtn = $('mbSend')
  if (sendBtn) sendBtn.addEventListener('click', sendFile)
  // R153 §4 (R-2) — the bridge, first-class: the road opens from HERE
  const openRoadBtn = $('mbOpenRoadBtn')
  if (openRoadBtn) openRoadBtn.addEventListener('click', openRoad)
  // R153 §4 (R-2) — the answer side, first-class: one visible button opens
  // the handshake door (no buried details — the Z-3 cure on the receive side).
  // R156 feed mode: the ONE universal paste door is the journey's beat door
  // (mbReplyInput) — this button REVEALS and FOCUSES it, never a second box
  // (the R150 consented trim stands: the CEO — "keep only one!").
  const answerBtn = $('mbAnswerBridgeBtn')
  if (answerBtn) answerBtn.addEventListener('click', () => {
    const det = $('mbDirectIn')
    if (det) {
      det.open = true
      try { det.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* the open is the signal */ }
      const ta = $('mbInBundle')
      if (ta) { try { ta.focus({ preventScroll: true }) } catch { try { ta.focus() } catch { /* the scroll is the signal */ } } }
      return
    }
    const door = $('mbQrDoor')
    if (door) door.hidden = false
    const uni = $('mbReplyInput')
    if (uni) { try { uni.scrollIntoView({ behavior: 'smooth', block: 'center' }) } catch { /* the scroll is the signal */ } try { uni.focus({ preventScroll: true }) } catch { try { uni.focus() } catch { /* the scroll is the signal */ } } }
  })
  const cancelBtn = $('mbCancelSend')
  if (cancelBtn) cancelBtn.addEventListener('click', async () => {
    await cancelSession()
    renderJourneyLine(msg('mbCancelDone', undefined, 'Cancelled — nothing moved, nothing is waiting.'))
  })
  const connectCloudBtn = $('mbConnectCloud')
  if (connectCloudBtn) connectCloudBtn.addEventListener('click', () => {
    // R155 §8 (D.4, LAW #98) — THE ACCELERATOR'S DOOR, one click, the exact
    // cloud setup (the Z-2 contract): embedded → the host deep-links to
    // #sync-cloud (the #join precedent: the Sync tab AND the cloud overlay);
    // standalone → the same deep link opens in its own tab. NEVER again a
    // bare dump into Options, and NEVER a repair demand for a chain that
    // exists (the E-6 defect is dead).
    try {
      if (window.parent && window.parent !== window) {
        window.parent.location.hash = 'sync-cloud'
      } else if (chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: chrome.runtime.getURL('options.html#sync-cloud') })
      } else {
        chrome.runtime.openOptionsPage()
      }
    } catch { try { chrome.runtime.openOptionsPage() } catch { /* the click is the signal */ } }
  })
  // R154 §5 (A.2) — the pairing door opens INLINE (the S1 cure — never a
  // dump into Options with no path)
  const addDeviceBtn = $('mbAddDevice')
  if (addDeviceBtn) addDeviceBtn.addEventListener('click', showBondDoor)
  const quickPairInlineBtn = $('mbQuickPairInlineBtn')
  if (quickPairInlineBtn) quickPairInlineBtn.addEventListener('click', showBondDoor)
  const quickSendFocusBtn = $('mbQuickSendFocusBtn')
  if (quickSendFocusBtn) quickSendFocusBtn.addEventListener('click', () => {
    const sendCard = $('jrSendCard')
    if (sendCard) {
      sendCard.hidden = false
      try { sendCard.scrollIntoView({ behavior: 'smooth', block: 'start' }) } catch { /* best-effort */ }
    }
    const pick = $('jrPickFile')
    if (pick) { try { pick.focus({ preventScroll: true }) } catch { /* best-effort */ } }
  })
  const quickDoctorBtn = $('mbQuickDoctorBtn')
  if (quickDoctorBtn) quickDoctorBtn.addEventListener('click', () => {
    const diag = $('jrDiagnostics')
    if (diag) {
      diag.open = true
      try { diag.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) } catch { /* best-effort */ }
    }
    const runBtn = $('jrRunDoctor')
    if (runBtn) runBtn.click()
    else runDoctor()
  })
  const chipChain = $('mbChipChain')
  if (chipChain) chipChain.addEventListener('click', showBondDoor)
  const chipDirect = $('mbChipDirect')
  if (chipDirect) chipDirect.addEventListener('click', () => {
    const why = $('mbWhyDetails')
    if (why) why.open = !why.open
  })
  const chipCloud = $('mbChipCloud')
  if (chipCloud) chipCloud.addEventListener('click', () => {
    if (!cloudConnected && connectCloudBtn) connectCloudBtn.click()
    else {
      const why = $('mbWhyDetails')
      if (why) why.open = !why.open
    }
  })
  // the code panel's human gate (the receiver's Match / Mismatch)
  // R156 feed mode: the journey owns the shared gate in journey mode —
  // the feed defers (D-3.5: never a second writer on the frozen flow).
  if (!journeyPrimary) {
    $('mbCodeMatch').addEventListener('click', async () => {
      const r = await confirmCode(true)
      if (r.ok) $('mbCodeRole').textContent = msg('mbCodeMatched', undefined, 'Matched — the file may move now.')
    })
    $('mbCodeMismatch').addEventListener('click', async () => {
      const r = await confirmCode(false)
      if (r.ok) {
        hideCodePanelState()
        renderJourneyLine(msg('mbCodeMismatchLine', undefined, 'The codes did not match — nothing moved. Start again when ready.'))
      }
    })
  }
  // the reply bundle door (paste / scan / upload — the camera-less parity)
  // R156 feed mode: deferred to the journey (the beat door's own wiring).
  if (!journeyPrimary) {
    $('mbReplySubmit').addEventListener('click', async () => {
      try {
        const r = await submitReplyBundle($('mbReplyInput').value)
        if (r.ok) renderJourneyLine(msg('mbReplySent', undefined, 'The reply is in — the connection completes on the sender\u2019s screen.'))
      } catch (e) {
        renderJourneyLine(String((e && e.message) || e).slice(0, 160))
      }
    })
    $('mbReplyScan').addEventListener('click', () => {
      const input = $('mbQrFileInput')
      input.value = ''
      input.click()
      input.onchange = async () => {
        const f = input.files && input.files[0]
        if (!f) return
        try {
          const text = await importQrImage(f)
          $('mbReplyInput').value = text
          renderJourneyLine(msg('mbQrRead', undefined, 'The QR image was read — press Connect reply to answer.'))
        } catch (e) {
          renderJourneyLine(String((e && e.message) || e).slice(0, 160))
        }
      }
    })
  }
  const exportBtn = $('mbExportOffer')
  if (exportBtn) exportBtn.addEventListener('click', exportOffer)
  const importBtn = $('mbImportOffer')
  if (importBtn) importBtn.addEventListener('click', importOffer)
  const doctorBtn = $('mbRunDoctor')
  if (doctorBtn) doctorBtn.addEventListener('click', runDoctor)
  // R154 §5 — the bond door's wiring (the pairing doors, first-class)
  $('mbBondShowBtn').addEventListener('click', bondInvite)
  $('mbBondCopyBtn').addEventListener('click', bondCopy)
  $('mbBondCloseBtn').addEventListener('click', () => {
    const bd = $('mbBondDoor')
    if (bd) {
      if ('open' in bd) bd.open = false
      else bd.hidden = true
    }
  })
  $('mbBondLearnBtn').addEventListener('click', bondLearn)
  $('mbBondScanBtn').addEventListener('click', bondScan)
  // R155 §7 (C.1) — the chain code's copy (compare across machines)
  const fpCopyBtn = $('mbBondFpCopy')
  if (fpCopyBtn) fpCopyBtn.addEventListener('click', bondFpCopy)
  // THE CLOUD-FREE ENTRY (the receiver's door — words pasted or a QR image)
  // R156 feed mode: the mbDirectIn details live on the legacy composition
  // only; the merged page routes through the journey's universal door.
  const inConnectBtn = $('mbInConnect')
  if (inConnectBtn) inConnectBtn.addEventListener('click', async () => {
    try {
      const r = await startFromIncomingBundle($('mbInBundle').value, { onLine: (t) => { $('mbInState').textContent = t || '' } })
      if (r && r.ok) $('mbInState').textContent = msg('mbInConnected', undefined, 'The handshake is in — compare the 6-digit code, then answer on their screen.')
    } catch (e) {
      $('mbInState').textContent = String((e && e.message) || e).slice(0, 160)
    }
  })
  const inQrBtn = $('mbInQr')
  if (inQrBtn) inQrBtn.addEventListener('click', () => {
    const input = $('mbQrFileInput')
    input.value = ''
    input.click()
    input.onchange = async () => {
      const f = input.files && input.files[0]
      if (!f) return
      try {
        const text = await importQrImage(f)
        $('mbInBundle').value = text
        $('mbInState').textContent = msg('mbQrRead', undefined, 'The QR image was read — press Connect handshake to answer.')
      } catch (e) {
        $('mbInState').textContent = String((e && e.message) || e).slice(0, 160)
      }
    }
  })
  // R156 feed mode: the receive plane's poll cadence is the JOURNEY's own
  // (jrPollLine) — the feed's poll stays on the legacy composition only.
  if (!journeyPrimary) {
    const receiveCard = $('mbReceiveCard')
    if (receiveCard) receiveCard.hidden = false // receive is the default card — passive first
    await pollOnce()
    startPolling()
  } else {
    // In journeyPrimary (feed) mode, still populate #mbStatusStrip and #mbRoadLedgerRow on boot
    try {
      const st = await door('MAILBOX_STATUS')
      cloudConnected = !!(st.ok && st.status && st.status.connected)
      await renderRoster()
    } catch { /* feed status is non-blocking */ }
  }

  // UCRYPT-23: Seamless embedded height sync with options.html (#fileTransferFrame)
  try {
    if (window.parent && window.parent !== window) {
      const postHeight = () => {
        try {
          const wrap = document.querySelector('.transfer-wrap') || document.body
          const h = Math.max(520, Math.ceil((wrap && wrap.scrollHeight) || document.documentElement.scrollHeight || 640) + 12)
          window.parent.postMessage({ type: 'UCRYPT_TRANSFER_FRAME_HEIGHT', height: h }, '*')
        } catch { /* best-effort */ }
      }
      postHeight()
      setTimeout(postHeight, 150)
      setTimeout(postHeight, 500)
      if (typeof ResizeObserver === 'function') {
        const ro = new ResizeObserver(postHeight)
        ro.observe(document.body)
      }
      if (typeof MutationObserver === 'function') {
        const mo = new MutationObserver(postHeight)
        mo.observe(document.body, { childList: true, subtree: true, attributes: true })
      }
      document.addEventListener('toggle', postHeight, true)
    }
  } catch { /* best-effort */ }
}

function hideCodePanelState() {
  const panel = $('mbCodePanel')
  if (panel) panel.hidden = true
}

async function pickFile() {
  const input = $('mbFileInput') || $('jrFileInput')
  if (!input) return
  input.value = ''
  input.accept = ''
  input.click()
  input.onchange = async () => {
    const f = input.files && input.files[0]
    if (!f) return
    const fnEl = $('mbFileName') || $('jrFileName')
    if (f.size > 100 * 1024 * 1024) {
      if (fnEl) fnEl.textContent = msg('mbTooBig', undefined, 'Files over 100 MB are refused — the honest cap.')
      return
    }
    selectedFile = f
    if (fnEl) fnEl.textContent = `${f.name} · ${fmtSize(f.size)}`
    updateSendGate(lastRosterRows) // the gate owns the Send truth (A.3a)
    // R153 §4 (R-2) — the armed bridge journey continues on its own
    if (openRoadArmed) {
      openRoadArmed = false
      const sel = $('mbRecipient') || $('jrRecipient')
      if (sel && sel.value) sendFile()
    }
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && typeof document.querySelectorAll === 'function') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
}
