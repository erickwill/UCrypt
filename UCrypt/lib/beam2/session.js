/**
 * UCrypt — R134 §2.E — LAW 0.56: CRASH-SAFE SESSIONS ("A crash is a pause,
 * not a loss").
 *
 * THE STATE MACHINE:
 *   IDLE → OFFERED → ACCEPTED → TRANSFERRING → VERIFYING
 *     → COMPLETED | DECLINED | CANCELED | EXPIRED | FAILED_INTEGRITY | FAILED_NETWORK
 *
 * The six typed terminals are preserved (the two-tab transfer's six states
 * lineage, now the Beam 2 machine's own). Illegal transitions THROW
 * (instrument-pinned — a red battery row, never a silent bend).
 *
 * TTLs: offer 10 minutes, session 30 minutes, both with visible countdowns.
 * A typed APPEND-ONLY session journal persists (chrome.storage.local in
 * production, injected store in tests) after EVERY transition and every N
 * chunks; on browser restart the session resumes — an offer still valid can
 * be accepted; a mid-transfer session resumes from the last journaled ack
 * (Lane C) or re-offers (Lane W).
 *
 * PURE — the store is injected; the battery runs the full machine.
 */

import { OFFER_TTL_MS, SESSION_TTL_MS } from './envelope.js'

export const BEAM2_JOURNAL_KEY = 'ucrypt:beam2:sessionJournal'

/** The live states (strings are the machine's own vocabulary). */
export const STATES = {
  IDLE: 'IDLE',
  OFFERED: 'OFFERED',
  ACCEPTED: 'ACCEPTED',
  TRANSFERRING: 'TRANSFERRING',
  VERIFYING: 'VERIFYING',
}

/** The six typed terminals — every session ends in exactly one of these. */
export const TERMINALS = {
  COMPLETED: 'COMPLETED',
  DECLINED: 'DECLINED',
  CANCELED: 'CANCELED',
  EXPIRED: 'EXPIRED',
  FAILED_INTEGRITY: 'FAILED_INTEGRITY',
  FAILED_NETWORK: 'FAILED_NETWORK',
}

/** The typed events the machine accepts. */
export const EVENTS = {
  OFFER: 'OFFER',
  ACCEPT: 'ACCEPT',
  DECLINE: 'DECLINE',
  CANCEL: 'CANCEL',
  BEGIN_TRANSFER: 'BEGIN_TRANSFER',
  CHUNKS_DONE: 'CHUNKS_DONE',
  VERIFY_OK: 'VERIFY_OK',
  VERIFY_FAIL: 'VERIFY_FAIL',
  NETWORK_FAIL: 'NETWORK_FAIL',
  EXPIRE: 'EXPIRE',
}

/** The transition table — every LEGAL (state, event) → nextState edge. */
export const TRANSITIONS = {
  [`${STATES.IDLE}|${EVENTS.OFFER}`]: STATES.OFFERED,
  [`${STATES.IDLE}|${EVENTS.EXPIRE}`]: TERMINALS.EXPIRED,
  [`${STATES.OFFERED}|${EVENTS.ACCEPT}`]: STATES.ACCEPTED,
  [`${STATES.OFFERED}|${EVENTS.DECLINE}`]: TERMINALS.DECLINED,
  [`${STATES.OFFERED}|${EVENTS.CANCEL}`]: TERMINALS.CANCELED,
  [`${STATES.OFFERED}|${EVENTS.EXPIRE}`]: TERMINALS.EXPIRED,
  [`${STATES.ACCEPTED}|${EVENTS.BEGIN_TRANSFER}`]: STATES.TRANSFERRING,
  [`${STATES.ACCEPTED}|${EVENTS.DECLINE}`]: TERMINALS.DECLINED, // late-decline-after-accept is HONORED (law §2.F) — typed, not silent
  [`${STATES.ACCEPTED}|${EVENTS.CANCEL}`]: TERMINALS.CANCELED,
  [`${STATES.ACCEPTED}|${EVENTS.NETWORK_FAIL}`]: TERMINALS.FAILED_NETWORK,
  [`${STATES.ACCEPTED}|${EVENTS.EXPIRE}`]: TERMINALS.EXPIRED,
  [`${STATES.TRANSFERRING}|${EVENTS.CHUNKS_DONE}`]: STATES.VERIFYING,
  [`${STATES.TRANSFERRING}|${EVENTS.CANCEL}`]: TERMINALS.CANCELED,
  [`${STATES.TRANSFERRING}|${EVENTS.NETWORK_FAIL}`]: TERMINALS.FAILED_NETWORK,
  [`${STATES.TRANSFERRING}|${EVENTS.EXPIRE}`]: TERMINALS.EXPIRED,
  [`${STATES.VERIFYING}|${EVENTS.VERIFY_OK}`]: TERMINALS.COMPLETED,
  [`${STATES.VERIFYING}|${EVENTS.VERIFY_FAIL}`]: TERMINALS.FAILED_INTEGRITY,
  [`${STATES.VERIFYING}|${EVENTS.CANCEL}`]: TERMINALS.CANCELED,
  [`${STATES.VERIFYING}|${EVENTS.NETWORK_FAIL}`]: TERMINALS.FAILED_NETWORK,
  [`${STATES.VERIFYING}|${EVENTS.EXPIRE}`]: TERMINALS.EXPIRED,
}

/** The typed state error — illegal transitions throw this, never a silent bend. */
export function beam2StateError(from, event, detail = '') {
  const e = new Error(`BEAM2_STATE_ILLEGAL: ${event} in ${from} ${detail}`.trim())
  e.code = 'BEAM2_STATE_ILLEGAL'
  e.from = from
  e.event = event
  return e
}

/**
 * The pure transition step. Throws on an illegal edge; returns the next
 * state otherwise. Every caller journals the (from, event, to) triple.
 */
export function step(state, event) {
  const key = `${state}|${event}`
  const next = TRANSITIONS[key]
  if (!next) throw beam2StateError(state, event)
  return next
}

export function isTerminal(state) {
  return Object.values(TERMINALS).includes(state)
}

/** The per-session machine — holds the journal and enforces the edges. */
export class Beam2Session {
  /**
   * @param {object} opts
   * @param {string} opts.sessionId
   * @param {string} opts.role 'sender' | 'receiver'
   * @param {{get:(k:string)=>Promise<any>, set:(k:string,v:any)=>Promise<void>}} opts.store
   * @param {number} [opts.journalChunkInterval] journal flush every N chunks (default 16)
   */
  constructor({ sessionId, role, store, journalChunkInterval = 16 }) {
    if (!sessionId || !role || !store) throw beam2StateError('CONSTRUCTOR', 'INVALID', 'sessionId, role, store are required')
    this.sessionId = sessionId
    this.role = role
    this.store = store
    this.journalChunkInterval = journalChunkInterval
    this.state = STATES.IDLE
    this.createdAt = Date.now()
    this.offerExpiresAt = this.createdAt + OFFER_TTL_MS
    this.sessionExpiresAt = this.createdAt + SESSION_TTL_MS
    this.lastAckedChunk = -1
    this.chunksSinceJournal = 0
    this.lane = null
  }

  /** Fire an event through the machine; journals the transition. Illegal → throw. */
  async fire(event, meta = {}) {
    const from = this.state
    const to = step(from, event)
    this.state = to
    await this.journal({ kind: 'transition', from, event, to, at: Date.now(), ...meta })
    return to
  }

  /**
   * Chunk progress journaling — every N chunks (crash-safety cadence) and
   * always with the last acked chunk so Lane C resumes from the journal.
   */
  async noteChunk(lastAckedChunk) {
    this.lastAckedChunk = Math.max(this.lastAckedChunk, Number(lastAckedChunk) || 0)
    this.chunksSinceJournal++
    if (this.chunksSinceJournal >= this.journalChunkInterval) {
      this.chunksSinceJournal = 0
      await this.journal({ kind: 'progress', lastAckedChunk: this.lastAckedChunk, at: Date.now() })
    }
  }

  /** Force a progress journal flush (call before a deliberate hard stop). */
  async flushProgress() {
    await this.journal({ kind: 'progress', lastAckedChunk: this.lastAckedChunk, at: Date.now() })
  }

  /** Append ONE entry to the append-only journal and persist it. */
  async journal(entry) {
    const all = (await this.store.get(BEAM2_JOURNAL_KEY)) || {}
    const list = all[this.sessionId] || []
    list.push({ ...entry, role: this.role })
    all[this.sessionId] = list
    await this.store.set(BEAM2_JOURNAL_KEY, all)
  }

  /** The visible countdowns (law §2.E: both with visible countdowns). */
  countdowns(now = Date.now()) {
    return {
      offerMs: Math.max(0, this.offerExpiresAt - now),
      sessionMs: Math.max(0, this.sessionExpiresAt - now),
    }
  }

  /** TTL truth: the typed EXPIRE event is legal only while a deadline holds. */
  expiredAt(now = Date.now()) {
    if (this.state === STATES.OFFERED && now >= this.offerExpiresAt) return 'offer'
    if (!isTerminal(this.state) && now >= this.sessionExpiresAt) return 'session'
    return null
  }
}

/**
 * THE RESUME SCAN — after a browser restart, read the journal and derive
 * each session's typed resume point (law §2.E: "a crash is a pause, not a
 * loss").
 * @param {{get:(k:string)=>Promise<any>}} store
 * @param {number} now
 * @returns {Promise<Array<{sessionId:string, role:string, state:string, resume:'accept'|'lane-c-resume'|'lane-w-re-offer'|'terminal', lastAckedChunk:number, offerExpiresAt:number}>>}
 */
export async function scanResumableSessions(store, now = Date.now()) {
  const all = (await store.get(BEAM2_JOURNAL_KEY)) || {}
  const out = []
  for (const [sessionId, list] of Object.entries(all)) {
    if (!Array.isArray(list) || !list.length) continue
    let state = STATES.IDLE
    let role = 'receiver'
    let lastAckedChunk = -1
    let offerExpiresAt = 0
    for (const e of list) {
      if (e.role) role = e.role
      if (e.kind === 'transition') {
        // the journal is append-only and every transition was legal when
        // written — the replay is a simple fold over the recorded `to`
        state = e.to
        if (e.to === STATES.OFFERED && !offerExpiresAt) offerExpiresAt = (Number(e.at) || now) + OFFER_TTL_MS
        if (Number.isFinite(e.offerExpiresAt)) offerExpiresAt = Math.max(offerExpiresAt, e.offerExpiresAt)
      }
      if (e.kind === 'progress' && Number.isFinite(e.lastAckedChunk)) lastAckedChunk = Math.max(lastAckedChunk, e.lastAckedChunk)
    }
    let resume
    if (isTerminal(state)) resume = 'terminal'
    else if (state === STATES.OFFERED && role === 'receiver') {
      resume = now < offerExpiresAt ? 'accept' : 'terminal'
      if (resume === 'terminal') state = TERMINALS.EXPIRED
    } else if (state === STATES.OFFERED && role === 'sender') {
      resume = 'lane-w-re-offer'
    } else if (state === STATES.ACCEPTED || state === STATES.TRANSFERRING) {
      resume = role === 'sender' ? 'lane-c-resume' : 'lane-c-resume'
      if (state === STATES.ACCEPTED && role === 'sender') resume = 'lane-w-re-offer'
    } else if (state === STATES.VERIFYING) {
      resume = 'lane-c-resume'
    } else {
      resume = 'terminal'
    }
    out.push({ sessionId, role, state, resume, lastAckedChunk, offerExpiresAt })
  }
  return out
}

/**
 * JOURNAL COMPACTION — terminal sessions' journals are kept bounded: the
 * full append-only history stays until a session is terminal AND older than
 * the retention window, then the session's entries drop (the typed verdict
 * row was already rendered; the journal is machinery, not a ledger of truth).
 */
export async function compactJournal(store, now = Date.now(), retentionMs = 60 * 60 * 1000) {
  const all = (await store.get(BEAM2_JOURNAL_KEY)) || {}
  let removed = 0
  for (const [sessionId, list] of Object.entries(all)) {
    if (!Array.isArray(list) || !list.length) continue
    const last = list[list.length - 1]
    const lastAt = Number(last && last.at) || 0
    if (isTerminal(last && last.to) && now - lastAt > retentionMs) {
      delete all[sessionId]
      removed++
    }
  }
  await store.set(BEAM2_JOURNAL_KEY, all)
  return { removed }
}
