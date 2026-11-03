/**
 * UCrypt — R153 §4 (R-1) — THE ROAD LEDGER (LAW #92).
 *
 * Every chain pair can print the typed reason chain for its road:
 *   MEMBERSHIP → SIGNALING → ICE → DATACHANNEL
 * Every "No road" chip can show this chain on demand — the why is already
 * law; R153 makes it deep (the contract's R-1). Membership never dresses as
 * presence; no bytes are ever loaded onto a nonexistent road; every absent
 * road is typed with its why AND its one cure.
 *
 * PURE — no DOM, no chrome.*, no WebRTC. The page gathers the honest facts
 * and renders the rows. Battery-pinned (tests/r153-road-ledger.test.mjs).
 */

export const ROAD_STAGES = Object.freeze(['MEMBERSHIP', 'SIGNALING', 'ICE', 'DATACHANNEL'])

export const ROAD_ROW_STATES = Object.freeze({
  OK: 'ok',
  MISSING: 'missing',
  UNKNOWN: 'unknown',
  NA: 'n/a', // the stage is not reachable yet — the ledger says why honestly
})

export const ROAD_CHIP_TONES = Object.freeze({
  DIRECT: 'direct',   // 🟢
  RELAY: 'relay',     // 🟡
  NO_ROAD: 'no-road', // 🔴
  UNKNOWN: 'unknown', // ⚪ presence honestly unknown
})

export function ledgerError(code, message) {
  const e = new Error(message)
  e.code = `ROAD_LEDGER_${code}`
  return e
}

/**
 * The honest facts the page gathers (every field optional — an absent fact
 * types UNKNOWN, never a fabricated state):
 *   rostered          — the chain exists on this device (a sync code is set)
 *   peerListed        — the peer is a member of this chain (the roster row)
 *   peerSeenAt        — the peer's last presence stamp (0 = never)
 *   peerSeenMaxAgeMs  — how fresh "online" means (the presence TTL)
 *   cloudSignaling    — the cloud bound answers (the relay door is usable)
 *   manualBridgeOpen  — a manual bridge (QR/words) handshake is in flight/open
 *   iceGathered       — count of ICE candidates gathered for the live pair
 *   stunReachable     — the SRFLX probe answered (the internet road's door)
 *   channelOpen       — the DataChannel is open right now
 *   liveRoad          — the road in use for the live session (bridge road id)
 *   peerName          — the peer's label (for the lines)
 */
export function deriveRoadLedger(facts = {}) {
  const f = {
    rostered: false,
    peerListed: false,
    peerSeenAt: 0,
    peerSeenMaxAgeMs: 15 * 60 * 1000,
    cloudSignaling: false,
    manualBridgeOpen: false,
    iceGathered: 0,
    stunReachable: false,
    channelOpen: false,
    liveRoad: null,
    peerName: '',
    ...facts,
  }
  const name = String(f.peerName || 'the other device')
  const peerOnline = f.peerListed && f.peerSeenAt > 0 && (Date.now() - f.peerSeenAt) <= f.peerSeenMaxAgeMs

  const rows = []
  const push = (stage, state, detail, action) => rows.push({ stage, state, detail: String(detail || ''), action: String(action || '') })

  /* 1 — MEMBERSHIP: is the peer part of this chain at all? */
  if (!f.rostered) {
    push('MEMBERSHIP', ROAD_ROW_STATES.MISSING,
      // R155 §5 (LAW #98) — the not-ready typing: never a denial of a chain
      // that exists but is locked.
      'no chain is ready on this device yet (unlock the vault or set the sync code)',
      'create a chain or join one with the 24 words (Cloud Sync tab)')
  } else if (!f.peerListed) {
    push('MEMBERSHIP', ROAD_ROW_STATES.MISSING,
      `${name} is not in your chain`,
      // R155 §5 (A.2, LAW #98) — the pairing door is INLINE on this page;
      // the cloud is an accelerator, NEVER the repair for membership.
      'add the device — press “Pair a device” below: show your invitation on the other screen, paste their reply here (one minute, no cloud)')
  } else {
    push('MEMBERSHIP', ROAD_ROW_STATES.OK,
      peerOnline ? `${name} is a chain member — seen just now` : `${name} is a chain member — presence unknown right now (UCrypt may be closed there)`,
      peerOnline ? '' : 'open UCrypt on the other device (or wake it) — then re-check')
  }

  /* 2 — SIGNALING: can the two peers exchange an offer/answer at all? */
  if (f.channelOpen || f.liveRoad) {
    push('SIGNALING', ROAD_ROW_STATES.OK, 'the handshake already completed for this session', '')
  } else if (f.manualBridgeOpen) {
    push('SIGNALING', ROAD_ROW_STATES.OK, 'a manual bridge (QR / words) is in flight — the handshake is human-paced', 'complete the exchange on the other device')
  } else if (f.cloudSignaling) {
    push('SIGNALING', ROAD_ROW_STATES.OK, 'the cloud relay carries the handshake envelopes (120 s TTL)', '')
  } else if (!f.rostered || !f.peerListed) {
    push('SIGNALING', ROAD_ROW_STATES.NA, 'not reachable yet — membership comes first', '')
  } else {
    push('SIGNALING', ROAD_ROW_STATES.MISSING,
      'no signaling path — the cloud bound is down and no bridge is open',
      'open a road with the bridge: one QR scan or words paste per side — zero cloud (the Open a road button)')
  }

  /* 3 — ICE: did the pair gather candidates (host = this network, srflx = internet)? */
  if (f.channelOpen || f.liveRoad) {
    push('ICE', ROAD_ROW_STATES.OK, 'the connection is established — no probe needed', '')
  } else if (rows[1].state === ROAD_ROW_STATES.MISSING || rows[1].state === ROAD_ROW_STATES.NA) {
    push('ICE', ROAD_ROW_STATES.NA, 'waits for a signaling path', '')
  } else if (Number(f.iceGathered) > 0) {
    push('ICE', ROAD_ROW_STATES.OK, `${f.iceGathered} candidate${Number(f.iceGathered) === 1 ? '' : 's'} gathered${f.stunReachable ? ' (host + internet)' : ' (host — this network)'}`, '')
  } else {
    push('ICE', ROAD_ROW_STATES.MISSING,
      'no route found between the devices yet',
      'put both devices on the same network for the direct road — or let the relay carry the file')
  }

  /* 4 — DATACHANNEL: is the encrypted pipe open? */
  if (f.channelOpen) {
    push('DATACHANNEL', ROAD_ROW_STATES.OK, 'the direct channel is open — end-to-end encrypted, the code gate armed', '')
  } else if (f.liveRoad === 'relay') {
    push('DATACHANNEL', ROAD_ROW_STATES.OK, 'the relay road is in use — the file rides your cloud, sealed end to end', '')
  } else if (rows[2].state === ROAD_ROW_STATES.MISSING || rows[2].state === ROAD_ROW_STATES.NA) {
    push('DATACHANNEL', ROAD_ROW_STATES.NA, 'waits for the route', '')
  } else {
    push('DATACHANNEL', ROAD_ROW_STATES.MISSING, 'the channel is not open yet — the code comparison opens it', 'complete the handshake on both screens')
  }

  /* THE ROAD VERDICT + the chip line (plain words, one line) */
  let road = null
  let tone = ROAD_CHIP_TONES.NO_ROAD
  let line = ''
  let action = ''
  if (f.channelOpen && f.liveRoad === 'relay') {
    road = 'relay'; tone = ROAD_CHIP_TONES.RELAY
    line = '🟡 RELAY · your cloud'
  } else if (f.channelOpen) {
    road = f.liveRoad || 'direct-lan'; tone = ROAD_CHIP_TONES.DIRECT
    line = road === 'direct-net' ? '🟢 DIRECT · internet' : '🟢 DIRECT · this network'
  } else if (f.liveRoad === 'relay') {
    road = 'relay'; tone = ROAD_CHIP_TONES.RELAY
    line = '🟡 RELAY · your cloud (connecting…)'
  } else if (f.manualBridgeOpen) {
    tone = ROAD_CHIP_TONES.UNKNOWN
    line = '⏳ The bridge is in flight — complete the handshake on the other device'
    action = 'scan their answer (or paste their words) to finish'
  } else if (!f.rostered) {
    tone = ROAD_CHIP_TONES.NO_ROAD
    line = `🔴 No road yet — no chain is ready on this device`
    action = 'unlock the vault, or create or join a chain (Cloud Sync tab)'
  } else if (!f.peerListed) {
    tone = ROAD_CHIP_TONES.NO_ROAD
    line = `🔴 No road to ${name} — not in your chain`
    // R155 §5 (A.2, LAW #98) — both next steps as equals, the pairing door
    // FIRST (the E-6 cure: the cloud is never presented as the repair for a
    // chain that exists — and membership grows by pairing, not by the cloud).
    action = 'add the device — press “Pair a device” below (one minute, no cloud) — or connect Cloud Sync for automatic discovery'
  } else if (!f.cloudSignaling) {
    tone = ROAD_CHIP_TONES.NO_ROAD
    line = `🔴 No road to ${name} — signaling is down`
    action = 'open a road with the bridge (two taps, zero cloud) — or reconnect Cloud Sync for the relay'
  } else {
    tone = ROAD_CHIP_TONES.UNKNOWN
    line = `⚪ Calling ${name} through your cloud — waiting for their answer`
    action = 'they may need to open UCrypt there (or accept on their screen)'
  }

  /* R-5 — THE PLATFORM HONESTY NOTE (typed once, where the why lives):
     MV3 extensions cannot multicast or scan the LAN — zero-touch discovery
     with ALL clouds dead and NO manual hop is a Chromium-platform limit.
     The manual bridge is the deliberate, sanctioned answer. */
  const platformNote = (!f.cloudSignaling && !f.channelOpen && !f.manualBridgeOpen && f.rostered && f.peerListed)
    ? 'Platform honesty: a browser extension cannot scan the network by itself (Chromium MV3 limits) — with every cloud down, ONE manual hop (the bridge) is how the first contact is made; after that the road re-dials warm.'
    : ''

  const missingStage = rows.find((r) => r.state === ROAD_ROW_STATES.MISSING)
  const absentIngredient = missingStage ? missingStage.stage : null

  return Object.freeze({ road, tone, line, action, rows, platformNote, absentIngredient })
}

/** The chip's expanded rows rendered as plain lines (the why-panel's body). */
export function ledgerLines(ledger) {
  const out = []
  for (const r of ledger.rows) {
    const glyph = r.state === 'ok' ? '✓' : r.state === 'missing' ? '✗' : r.state === 'n/a' ? '·' : '?'
    out.push(`${glyph} ${r.stage}: ${r.detail}${r.action ? ' — ' + r.action : ''}`)
  }
  if (ledger.platformNote) out.push(`ℹ ${ledger.platformNote}`)
  return out
}

/** R-4 — the warm re-dial's honest typing: WHICH ingredient is absent. */
export function typeAbsentIngredient(ledger) {
  if (ledger.road) return null
  switch (ledger.absentIngredient) {
    case 'MEMBERSHIP': return 'membership'
    case 'SIGNALING': return 'signaling'
    case 'ICE': return 'the network route'
    case 'DATACHANNEL': return 'the channel handshake'
    default: return 'an unknown ingredient (the ledger has no missing row — re-run the doctor)'
  }
}
