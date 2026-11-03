/**
 * UCrypt — R136 §5.3 — THE BEAM 3 STATE MACHINE (law 0.56 in full).
 *
 *   IDLE → SIGNALING → PAIRED → OFFERING → TRANSFERRING → VERIFYING → DONE
 *   typed terminals: REFUSED, EXPIRED, DECLINED, INTERRUPTED, FAILED
 *
 * Illegal transitions THROW (BEAM3_STATE_ILLEGAL). The journal is
 * append-only; resume is a fold over legal transitions; the
 * receiver-offline case resumes without silent loss (S6) — never a restart
 * from zero. Terminals are typed: every terminal carries its next action.
 *
 * The Beam 2 machine's vocabulary (IDLE/OFFERED/…) is PRESERVED in
 * lib/beam2/session.js — the legacy bridge and old journals remain
 * readable (law 0.36); Beam 3 is an additions-only machine beside it.
 *
 * PURE — the store is injected; battery-pinned (TRF-MACHINE-*, G71).
 */

import { BEAM3_SIGNAL_TTL_MS } from './planes.js'

/** The journal storage key. */
export const BEAM3_JOURNAL_KEY = 'ucrypt:beam3:sessionJournal'

/** The live states. */
export const STATES3 = {
  IDLE: 'IDLE',
  SIGNALING: 'SIGNALING',
  PAIRED: 'PAIRED',
  OFFERING: 'OFFERING',
  TRANSFERRING: 'TRANSFERRING',
  VERIFYING: 'VERIFYING',
  DONE: 'DONE',
}

/** The five typed terminals (the brief's exact list). */
export const TERMINALS3 = {
  REFUSED: 'REFUSED',
  EXPIRED: 'EXPIRED',
  DECLINED: 'DECLINED',
  INTERRUPTED: 'INTERRUPTED',
  FAILED: 'FAILED',
}

/** The typed events. */
export const EVENTS3 = {
  SIGNAL: 'SIGNAL', // a signal was created/copied (intent declared, plane known)
  PAIR: 'PAIR', // the peer signal opened → the paired state (R136-F1's mandated advance)
  OFFER: 'OFFER', // the sender's manifest went out
  ACCEPT: 'ACCEPT',
  DECLINE: 'DECLINE',
  REFUSE: 'REFUSE', // a hostile/failed pre-offer gate (bad signal, transcript mismatch)
  BEGIN_TRANSFER: 'BEGIN_TRANSFER',
  CHUNKS_DONE: 'CHUNKS_DONE',
  VERIFY_OK: 'VERIFY_OK',
  VERIFY_FAIL: 'VERIFY_FAIL',
  NETWORK_FAIL: 'NETWORK_FAIL',
  INTERRUPT: 'INTERRUPT', // receiver offline / browser close — resumable
  EXPIRE: 'EXPIRE', // the 24h horizon fired on an unconsumed signal
  RESET: 'RESET', // back to IDLE after a terminal (the one user action)
}

/** The transition table — every LEGAL edge. */
export const TRANSITIONS3 = {
  [`${STATES3.IDLE}|${EVENTS3.SIGNAL}`]: STATES3.SIGNALING,
  [`${STATES3.IDLE}|${EVENTS3.PAIR}`]: STATES3.PAIRED, // receiving a peer signal jumps straight to paired
  [`${STATES3.IDLE}|${EVENTS3.EXPIRE}`]: TERMINALS3.EXPIRED,
  [`${STATES3.SIGNALING}|${EVENTS3.PAIR}`]: STATES3.PAIRED,
  [`${STATES3.SIGNALING}|${EVENTS3.EXPIRE}`]: TERMINALS3.EXPIRED,
  [`${STATES3.SIGNALING}|${EVENTS3.REFUSE}`]: TERMINALS3.REFUSED,
  [`${STATES3.PAIRED}|${EVENTS3.OFFER}`]: STATES3.OFFERING,
  [`${STATES3.PAIRED}|${EVENTS3.REFUSE}`]: TERMINALS3.REFUSED,
  [`${STATES3.PAIRED}|${EVENTS3.EXPIRE}`]: TERMINALS3.EXPIRED,
  [`${STATES3.PAIRED}|${EVENTS3.RESET}`]: STATES3.IDLE,
  [`${STATES3.OFFERING}|${EVENTS3.ACCEPT}`]: STATES3.TRANSFERRING,
  [`${STATES3.OFFERING}|${EVENTS3.DECLINE}`]: TERMINALS3.DECLINED,
  [`${STATES3.OFFERING}|${EVENTS3.REFUSE}`]: TERMINALS3.REFUSED,
  [`${STATES3.OFFERING}|${EVENTS3.NETWORK_FAIL}`]: TERMINALS3.INTERRUPTED,
  [`${STATES3.OFFERING}|${EVENTS3.EXPIRE}`]: TERMINALS3.EXPIRED,
  [`${STATES3.TRANSFERRING}|${EVENTS3.CHUNKS_DONE}`]: STATES3.VERIFYING,
  [`${STATES3.TRANSFERRING}|${EVENTS3.NETWORK_FAIL}`]: TERMINALS3.INTERRUPTED,
  [`${STATES3.TRANSFERRING}|${EVENTS3.VERIFY_FAIL}`]: TERMINALS3.FAILED,
  [`${STATES3.TRANSFERRING}|${EVENTS3.DECLINE}`]: TERMINALS3.DECLINED,
  [`${STATES3.VERIFYING}|${EVENTS3.VERIFY_OK}`]: STATES3.DONE,
  [`${STATES3.VERIFYING}|${EVENTS3.VERIFY_FAIL}`]: TERMINALS3.FAILED,
  [`${STATES3.VERIFYING}|${EVENTS3.NETWORK_FAIL}`]: TERMINALS3.INTERRUPTED,
  [`${TERMINALS3.INTERRUPTED}|${EVENTS3.BEGIN_TRANSFER}`]: STATES3.TRANSFERRING, // S6 resume — a fold, not a restart
  [`${TERMINALS3.EXPIRED}|${EVENTS3.RESET}`]: STATES3.IDLE, // the one-tap regenerate lands here first
  [`${TERMINALS3.DECLINED}|${EVENTS3.RESET}`]: STATES3.IDLE,
  [`${TERMINALS3.REFUSED}|${EVENTS3.RESET}`]: STATES3.IDLE,
  [`${TERMINALS3.FAILED}|${EVENTS3.RESET}`]: STATES3.IDLE,
  [`${STATES3.DONE}|${EVENTS3.RESET}`]: STATES3.IDLE,
}

export function beam3StateError(from, event, detail = '') {
  const e = new Error(`BEAM3_STATE_ILLEGAL: ${event} in ${from} ${detail}`.trim())
  e.code = 'BEAM3_STATE_ILLEGAL'
  e.from = from
  e.event = event
  return e
}

/** The pure step. Throws on an illegal edge. */
export function step3(state, event) {
  const next = TRANSITIONS3[`${state}|${event}`]
  if (!next) throw beam3StateError(state, event)
  return next
}

export function isTerminal3(state) {
  return Object.values(TERMINALS3).includes(state)
}

/**
 * The per-session machine — append-only journal (injected store), typed
 * countdowns, the 24h signal horizon.
 */
export class Beam3Machine {
  constructor({ sessionId, role, store, signalIssuedAt = Date.now() }) {
    if (!sessionId || !role || !store) throw beam3StateError('CONSTRUCTOR', 'INVALID', 'sessionId, role, store are required')
    this.sessionId = sessionId
    this.role = role
    this.store = store
    this.signalIssuedAt = Number(signalIssuedAt) || Date.now()
    this.signalExpiresAt = this.signalIssuedAt + BEAM3_SIGNAL_TTL_MS
    this.state = STATES3.IDLE
    this.lastAckedChunk = -1
    this.chunksSinceJournal = 0
  }

  async fire(event, meta = {}) {
    const from = this.state
    const to = step3(from, event)
    this.state = to
    await this.journal({ kind: 'transition', from, event, to, at: Date.now(), ...meta })
    return to
  }

  async noteChunk(lastAckedChunk, everyN = 16) {
    this.lastAckedChunk = Math.max(this.lastAckedChunk, Number(lastAckedChunk) || 0)
    this.chunksSinceJournal += 1
    if (this.chunksSinceJournal >= everyN) {
      this.chunksSinceJournal = 0
      await this.journal({ kind: 'progress', lastAckedChunk: this.lastAckedChunk, at: Date.now() })
    }
  }

  async flushProgress() {
    await this.journal({ kind: 'progress', lastAckedChunk: this.lastAckedChunk, at: Date.now() })
  }

  async journal(entry) {
    const all = (await this.store.get(BEAM3_JOURNAL_KEY)) || {}
    const list = all[this.sessionId] || []
    list.push({ ...entry, role: this.role })
    all[this.sessionId] = list
    await this.store.set(BEAM3_JOURNAL_KEY, all)
  }

  /** The signal's visible countdown ("valid until used, or 24 hours"). */
  signalCountdown(now = Date.now()) {
    return Math.max(0, this.signalExpiresAt - now)
  }

  expiredAt(now = Date.now()) {
    // S3 (the pinned law): expiry NEVER fires during a live session — the
    // signal horizon governs only the UNCONSUMED signal (IDLE/SIGNALING).
    // Once paired, the nonce is spent; the session lives until a typed
    // terminal or the user's reset.
    if (this.state === STATES3.IDLE || this.state === STATES3.SIGNALING) {
      if (now >= this.signalExpiresAt) return 'signal'
    }
    return null
  }
}

/**
 * THE RESUME SCAN — a fold over the append-only journal (S6): chunks
 * already acknowledged are not resent; the typed resume point derives from
 * the last legal transition.
 */
export async function scanResumable3(store, now = Date.now()) {
  const all = (await store.get(BEAM3_JOURNAL_KEY)) || {}
  const out = []
  for (const [sessionId, list] of Object.entries(all)) {
    if (!Array.isArray(list) || !list.length) continue
    let state = STATES3.IDLE
    let role = 'receiver'
    let lastAckedChunk = -1
    for (const e of list) {
      if (e.role) role = e.role
      if (e.kind === 'transition') state = e.to
      if (e.kind === 'progress' && Number.isFinite(e.lastAckedChunk)) lastAckedChunk = Math.max(lastAckedChunk, e.lastAckedChunk)
    }
    let resume
    if (isTerminal3(state)) resume = state === TERMINALS3.INTERRUPTED ? 'resume-transfer' : 'terminal'
    else if (state === STATES3.DONE) resume = 'terminal'
    else if (state === STATES3.TRANSFERRING || state === STATES3.VERIFYING) resume = 'resume-transfer'
    else if (state === STATES3.PAIRED) resume = 'await-offer'
    else if (state === STATES3.OFFERING) resume = 'await-answer'
    else resume = 'terminal'
    out.push({ sessionId, role, state, resume, lastAckedChunk })
  }
  return out
}
