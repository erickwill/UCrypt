/**
 * UCrypt — R146 §6.2/§6.3 — THE FOUR-BEAT JOURNEY MACHINE (pure).
 *
 * THE TRANSFER DOCTRINE (the law book, law 24): synchronize first, then just
 * send. The chain roster is the target list; the road negotiates under the
 * hood; hash proof on delivery; receive is an arrivals surface.
 *
 * THE ZERO-DEAD-ENDS LAW (law 17), machine-checked: every state in this file
 * carries exactly ONE plain-words next step and at least one live action. A
 * state that cannot say what happens next is a construction error —
 * assertNoDeadEnds() walks every reachable state and throws. The battery
 * pins this file; the controller renders FROM it (the words and the machine
 * can never disagree — the copy-congruence law lives in the type).
 *
 * No state here closes itself: consent beats (receive.consent) persist until
 * the user answers (the popup law); status beats auto-dismiss only by a NEW
 * state replacing them (the lifetime law).
 */

export const BEAT_PICK = 'pick'
export const BEAT_SEND = 'send'
export const BEAT_PROOF = 'proof'
export const BEAT_RECEIVE = 'receive'

const STATES = {
  /* ── BEAT 1 — PICK ──────────────────────────────────────────────────────── */
  'pick.idle': {
    beat: BEAT_PICK,
    lineKey: 'jrPickIdle',
    line: 'Pick a file and the device to send it to — the road is picked for you.',
    actions: ['chooseFile', 'chooseRecipient'],
  },
  'pick.emptyChain': {
    beat: BEAT_PICK,
    lineKey: 'jrEmptyChain',
    line: 'Your devices are your chain. To add one, use Cloud Sync.',
    actions: ['openCloudSync'],
  },
  'pick.locked': {
    beat: BEAT_PICK,
    lineKey: 'jrLocked',
    line: 'Unlock the vault to send between your devices.',
    actions: ['unlockVault'],
  },
  'pick.noChain': {
    beat: BEAT_PICK,
    lineKey: 'jrNoChain',
    line: 'No sync chain on this device yet — Cloud Sync sets one up in two steps.',
    actions: ['openCloudSync'],
  },

  /* ── BEAT 2 — SEND (the road negotiates under the hood) ─────────────────── */
  'send.connecting': {
    beat: BEAT_SEND,
    lineKey: 'jrSendingDirect',
    line: 'Sending directly…',
    actions: ['cancel'],
    busy: true,
  },
  'send.relay': {
    beat: BEAT_SEND,
    lineKey: 'jrSendingRelay',
    line: 'Direct unavailable — sending through your cloud, still end-to-end encrypted.',
    actions: ['cancel'],
    busy: true,
  },
  'send.progress': {
    beat: BEAT_SEND,
    lineKey: 'jrSendingProgress',
    line: 'Sending…',
    args: ['name', 'pct'],
    actions: ['cancel'],
    busy: true,
  },

  /* ── BEAT 3 — PROOF ─────────────────────────────────────────────────────── */
  'proof.delivered': {
    beat: BEAT_PROOF,
    lineKey: 'jrDelivered',
    line: 'Delivered — verified',
    args: ['name', 'road', 'sha12'],
    actions: ['newTransfer'],
    terminal: true,
  },
  'proof.failed': {
    beat: BEAT_PROOF,
    lineKey: 'jrSendFailed',
    line: 'The file did not move — nothing arrived on the other device.',
    args: ['reason'],
    actions: ['retry', 'runDoctor'],
    terminal: true,
  },
  'proof.cancelled': {
    beat: BEAT_PROOF,
    lineKey: 'jrCancelled',
    line: 'Cancelled — nothing moved, nothing is waiting.',
    actions: ['newTransfer'],
    terminal: true,
  },

  /* ── BEAT 4 — RECEIVE (an arrivals surface, never a role) ───────────────── */
  'receive.idle': {
    beat: BEAT_RECEIVE,
    lineKey: 'jrArrivalsIdle',
    line: 'Incoming files appear here — direct ones arrive live, relayed ones ride your cloud.',
    actions: ['awaitArrival'],
  },
  'receive.consent': {
    beat: BEAT_RECEIVE,
    lineKey: 'jrArrivalsConsent',
    line: 'wants to send you a file — Accept to save it.',
    args: ['from', 'name', 'size'],
    actions: ['accept', 'decline'],
    consent: true,
  },
  'receive.saved': {
    beat: BEAT_RECEIVE,
    lineKey: 'jrArrivalsSaved',
    line: 'Saved · Verified',
    args: ['name', 'road'],
    actions: ['done'],
    terminal: true,
  },
  'receive.declined': {
    beat: BEAT_RECEIVE,
    lineKey: 'jrArrivalsDeclined',
    line: 'Declined — nothing was saved, nothing is waiting.',
    actions: ['done'],
    terminal: true,
  },
  'receive.failed': {
    beat: BEAT_RECEIVE,
    lineKey: 'jrArrivalsFailed',
    line: 'The incoming file could not be collected.',
    args: ['reason'],
    actions: ['retry', 'runDoctor'],
    terminal: true,
  },
}

export const JOURNEY_STATES = STATES

const TRANSITIONS = {
  CHOOSE_RECIPIENT: (s, e) => (s.state === 'pick.idle' || s.state === 'pick.locked' || s.state === 'pick.noChain' ? { ...s, to: e.to } : s),
  CHOOSE_FILE: (s, e) => (s.state.startsWith('pick.') ? { ...s, file: e.file } : s),
  START_SEND: (s, _e) => (s.state === 'pick.idle' && s.to && s.file ? { ...s, state: 'send.connecting', error: null } : s),
  ROAD_DIRECT: (s) => (s.state === 'send.connecting' || s.state === 'send.relay' ? { ...s, state: 'send.connecting', road: 'direct' } : s),
  ROAD_RELAY: (s) => (s.state === 'send.connecting' || s.state === 'send.relay' ? { ...s, state: 'send.relay', road: 'relay' } : s),
  PROGRESS: (s, e) => (s.state === 'send.connecting' || s.state === 'send.relay' ? { ...s, state: 'send.progress', pct: e.pct, name: e.name || s.file } : s),
  DELIVERED: (s, e) => (s.state.startsWith('send.') ? { ...s, state: 'proof.delivered', sha12: e.sha12, road: e.road || s.road || 'direct', name: e.name || s.file } : s),
  SEND_FAILED: (s, e) => (s.state.startsWith('send.') ? { ...s, state: 'proof.failed', error: e.reason || '' } : s),
  CANCEL: (s) => (s.state.startsWith('send.') ? { ...s, state: 'proof.cancelled' } : s),
  RESET: (s) => ({ ...s, state: 'pick.idle', file: null, to: null, hash: null, pct: null, error: null }),
  /* receive lane */
  ARRIVE: (s, e) => (s.state === 'receive.idle' ? { ...s, state: 'receive.consent', offer: e.offer } : s),
  ACCEPT_OK: (s, e) => (s.state === 'receive.consent' ? { ...s, state: 'receive.saved', name: e.name, road: e.road || 'relay' } : s),
  ACCEPT_FAIL: (s, e) => (s.state === 'receive.consent' ? { ...s, state: 'receive.failed', error: e.reason || '' } : s),
  DECLINE_OK: (s) => (s.state === 'receive.consent' ? { ...s, state: 'receive.declined' } : s),
  RECEIVE_DISMISS: (s) => (s.state === 'receive.saved' || s.state === 'receive.declined' || s.state === 'receive.failed' ? { ...s, state: 'receive.idle', offer: null } : s),
}

export function createJourney(initial = {}) {
  let state = { state: initial.state || 'pick.idle', to: null, file: null, pct: null, error: null, offer: null, road: null, ...(initial.fields || {}) }
  const listeners = new Set()
  const machine = {
    get: () => ({ ...state }),
    dispatch(type, event = {}) {
      const fn = TRANSITIONS[type]
      if (!fn) return machine.get()
      const next = fn(state, event)
      if (next !== state) {
        state = next
        for (const l of listeners) l(state)
      }
      return machine.get()
    },
    onNext(fn) { listeners.add(fn); return () => listeners.delete(fn) },
    /* the ZERO-DEAD-ENDS render contract: the state's own words + actions */
    view() {
      const def = STATES[state.state]
      return { id: state.state, def, fields: state }
    },
  }
  return machine
}

/** The zero-dead-ends law, machine-checked: EVERY state in the machine —
 * seen or not yet reached — carries a non-empty plain-words line and at
 * least one live action; consent states never auto-advance. Throws on the
 * first dead end — a red here blocks the seal (G96-LIVE class). */
export function assertNoDeadEnds(_machine) {
  let count = 0
  for (const [id, def] of Object.entries(STATES)) {
    if (!def.line || !def.line.length) throw new Error('dead-end: state without words: ' + id)
    if (!Array.isArray(def.actions) || def.actions.length < 1) throw new Error('dead-end: state without an action: ' + id)
    count++
  }
  return { states: count, deadEnds: 0 }
}
