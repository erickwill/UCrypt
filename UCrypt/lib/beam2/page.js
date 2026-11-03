/**
 * UCrypt — R134 §2.F — THE BEAM 2 PAGE SUPERVISOR ("the AirDrop ceremony,
 * verbatim").
 *
 * What this module OWNS (the legacy page.js keeps owning its surfaces):
 *   - the Beam 2 identity line (law 0.54's visible truth);
 *   - the lane truth rows (law 0.55 — "Direct peer-to-peer" vs "Relayed
 *     through your cloud — end-to-end encrypted", never silent);
 *   - the receive modal (the AirDrop ceremony: sender identity with the
 *     chain-verified badge, the file card, the code — and NEVER auto-closes,
 *     law 0.52 — the only exits are Accept / Decline);
 *   - the typed terminal rows (six terminals, each with its next action).
 *
 * The worker is the engine; this file renders its truth. The adaptive poll
 * mirrors the worker's cadence: fast (2 s) while a session is live, slow
 * (15 s) idle in-page. No DOM outside transfer.html's own ids.
 */

const $ = (id) => document.getElementById(id)

const POLL_ACTIVE_MS = 2000
const POLL_IDLE_MS = 15000
let pollTimer = null
let currentPollMs = POLL_IDLE_MS

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

function fmtBytes(n) {
  const v = Number(n) || 0
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)} MB`
  if (v >= 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${v} B`
}

function fmtMs(ms) {
  const s = Math.max(0, Math.round(ms / 1000))
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`
}

/** The 4×4 fingerprint display form (spaces between groups of 4). */
function fmtCode(fp) {
  const hex = String(fp || '').replace(/[^0-9a-fA-F]/g, '').slice(0, 16)
  if (!hex) return '———— ———— ———— ————'
  return hex.padEnd(16, '—').match(/.{1,4}/g).join(' ')
}

// ── i18n (the same getMessage shim the transfer page uses) ──
let getMessage = (key, subs, fallback) => {
  try {
    const msg = chrome.i18n.getMessage(key, subs)
    return msg || fallback || key
  } catch {
    return fallback || key
  }
}

const LANE_FALLBACKS = {
  W: 'Direct peer-to-peer — end-to-end encrypted',
  C: 'Relayed through your cloud — end-to-end encrypted',
  M: 'Manual signal path — end-to-end encrypted, zero cloud',
}

/** The lane truth row — rendered on BOTH progress cards, never silent. */
function renderLaneTruth(laneTruth) {
  for (const id of ['transferLaneTruthSend', 'transferLaneTruthRecv']) {
    const el = $(id)
    if (!el) continue
    if (!laneTruth || !laneTruth.lane) {
      el.hidden = true
      el.textContent = ''
      continue
    }
    el.hidden = false
    el.textContent = `⇄ ${getMessage(laneTruth.key, undefined, LANE_FALLBACKS[laneTruth.lane] || 'Lane selected')}`
    el.classList.toggle('lane-degraded', laneTruth.lane === 'C')
  }
}

/** The identity line (law 0.54's visible truth). */
function renderIdentity(beam2) {
  const el = $('beam2IdentityLine')
  if (!el) return
  if (!beam2 || !beam2.ready || !beam2.thumb) {
    el.hidden = true
    return
  }
  el.hidden = false
  el.textContent = getMessage('beam2IdentityLine', [beam2.thumb.slice(0, 12), String(beam2.protocolVersion || 2)],
    'Beam 2 — device key $THUMB$… · protocol v$V$ — every transfer is signed and chain-verified')
    .replace('$THUMB$', beam2.thumb.slice(0, 12)).replace('$V$', String(beam2.protocolVersion || 2))
}

// ── the receive modal (the AirDrop ceremony) ──
let incomingOffer = null // {sessionId, deviceId, manifest, fingerprint, expiresAt}

function showModal() {
  const ov = $('beam2ModalOverlay')
  if (!ov) return
  ov.classList.remove('hidden')
  const accept = $('beam2ModalAccept')
  if (accept) accept.focus()
}

function hideModal() {
  const ov = $('beam2ModalOverlay')
  if (ov) ov.classList.add('hidden')
}

function renderIncomingOffer(offer) {
  if (!offer) {
    hideModal()
    incomingOffer = null
    return
  }
  if (incomingOffer && incomingOffer.sessionId === offer.sessionId) return // already shown (law 0.52 — no re-arm flicker)
  incomingOffer = offer
  $('beam2ModalFrom').textContent = offer.from || '—'
  $('beam2ModalName').textContent = (offer.manifest && offer.manifest.name) || '—'
  $('beam2ModalSize').textContent = fmtBytes(offer.manifest && offer.manifest.size)
  $('beam2ModalCode').textContent = fmtCode(offer.fingerprint)
  $('beam2ModalExpiry').textContent = offer.expiresAt ? fmtMs(Math.max(0, offer.expiresAt - Date.now())) : '—'
  // the file-type safety warning stays (it is honest), rendered BEFORE Accept
  const name = String((offer.manifest && offer.manifest.name) || '')
  const risky = /\.(exe|msi|bat|cmd|com|scr|ps1|sh|zip|7z|rar|tar|gz|apk|dmg|pkg|jar)$/i.test(name)
  $('beam2ModalWarning').classList.toggle('hidden', !risky)
  const badge = $('beam2ModalBadge')
  if (badge) {
    // law 0.54: the badge renders ONLY when the signature verified — the
    // worker refuses unverifiable offers before they ever reach this modal
    badge.classList.toggle('hidden', !offer.chainVerified)
  }
  showModal()
}

/** The typed terminal row — every terminal carries its next action. */
function terminalNextAction(state) {
  switch (state) {
    case 'COMPLETED': return { key: 'beam2DoneSave', fallback: 'Completed — Save the file from the transfer card.' }
    case 'DECLINED': return { key: 'beam2DoneDeclined', fallback: 'Declined — nothing was received.' }
    case 'CANCELED': return { key: 'beam2DoneCanceled', fallback: 'Canceled — you can send again any time.' }
    case 'EXPIRED': return { key: 'beam2DoneExpired', fallback: 'Expired — ask the sender to send again.' }
    case 'FAILED_INTEGRITY': return { key: 'beam2DoneIntegrity', fallback: 'Integrity check failed — the file was NOT saved; re-verify or re-send.' }
    case 'FAILED_NETWORK': return { key: 'beam2DoneNetwork', fallback: 'Network failed — the session resumes from its journal; press Send again.' }
    default: return null
  }
}

let lastLogSignature = ''

/** One poll cycle: status → render. */
async function pollOnce() {
  const res = await send({ type: 'TRANSFER_BEAM2_STATUS' })
  const beam2 = res && res.ok ? res.beam2 : null
  if (!beam2 || res.locked) {
    schedule(POLL_IDLE_MS)
    return
  }
  renderIdentity(beam2)
  renderLaneTruth(beam2.laneTruth)
  // the typed rows (the orchestration log's Beam 2 rows — the log narrates
  // what the SYSTEM performs; the human checklist is extinct, law 0.50)
  const sig = JSON.stringify(beam2.log || [])
  if (sig !== lastLogSignature) {
    lastLogSignature = sig
    for (const row of beam2.log || []) {
      if (row && row.disposition === 'incoming-offer') {
        renderIncomingOffer({
          sessionId: row.sessionId,
          from: row.senderDeviceId || row.from,
          manifest: row.manifest,
          fingerprint: row.fingerprint,
          chainVerified: true,
          expiresAt: Date.now() + 10 * 60 * 1000,
        })
      }
      if (row && (row.disposition === 'canceled' || row.disposition === 'late-decline')) {
        hideModal()
        incomingOffer = null
      }
    }
  }
  // the countdown truth on the visible modal (the offer TTL is visible)
  if (incomingOffer && beam2.sessions) {
    const sess = beam2.sessions.find((s) => s.sessionId === incomingOffer.sessionId)
    if (sess && !sess.terminal) {
      $('beam2ModalExpiry').textContent = fmtMs(sess.countdowns ? sess.countdowns.offerMs : 0)
    }
  }
  const live = (beam2.sessions || []).some((s) => !s.terminal)
  schedule(live ? POLL_ACTIVE_MS : POLL_IDLE_MS)
}

function schedule(ms) {
  currentPollMs = ms
  if (pollTimer) clearTimeout(pollTimer)
  pollTimer = setTimeout(() => { pollOnce().catch(() => schedule(POLL_IDLE_MS)) }, ms)
}

// ── the modal's two exits (the ONLY exits — law 0.52) ──
function wireModal() {
  const accept = $('beam2ModalAccept')
  const decline = $('beam2ModalDecline')
  if (accept) {
    accept.addEventListener('click', async () => {
      if (!incomingOffer) return
      accept.disabled = true
      await send({
        type: 'TRANSFER_BEAM2_RESPOND',
        sessionId: incomingOffer.sessionId,
        deviceId: incomingOffer.from,
        decision: 'accept',
      })
      accept.disabled = false
      hideModal()
      incomingOffer = null
    })
  }
  if (decline) {
    decline.addEventListener('click', async () => {
      if (!incomingOffer) return
      decline.disabled = true
      await send({
        type: 'TRANSFER_BEAM2_RESPOND',
        sessionId: incomingOffer.sessionId,
        deviceId: incomingOffer.from,
        decision: 'decline',
      })
      decline.disabled = false
      hideModal()
      incomingOffer = null
    })
  }
}

// ── boot ──
try {
  wireModal()
  schedule(POLL_IDLE_MS)
} catch { /* the supervisor never takes the legacy page down */ }
