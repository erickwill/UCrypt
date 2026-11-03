/**
 * UCrypt — R134 §2.C — THE BEAM 2 SIGNALING ENVELOPE ("the cloud rendezvous
 * as the mailbox").
 *
 * Typed control envelope (the law's exact shape):
 *   { v:2, type, sessionId, from, to, seq, ts, payload, sig }
 *
 * Message classes: HELLO, CAPS, OFFER, ACCEPT, DECLINE, CANCEL, ACK,
 * PROGRESS, COMPLETE, BYE. Reliability: per-session sequence numbers, dedupe
 * on receipt, gap detection, TTL with expiry sweep, mailbox compaction after
 * terminal states — NO ORPHAN CIPHERTEXT IS EVER LEFT BEHIND (the orphan
 * sweeper, battery-pinned).
 *
 * The envelope rides the EXISTING rendezvous plane inside the sealed payload
 * (the mailbox sees only ciphertext — law §2.G); this module is the typed
 * logic OVER that plane and is PURE — no DOM, no chrome.*, no fetch.
 */

/** The envelope schema version (v2 — Beam 2; the legacy plane is v:1). */
export const ENVELOPE_VERSION = 2

/** The exact message classes, named by the law. */
export const MESSAGE_CLASSES = ['HELLO', 'CAPS', 'OFFER', 'ACCEPT', 'DECLINE', 'CANCEL', 'ACK', 'PROGRESS', 'COMPLETE', 'BYE']

/** TTLs (the law): offers 10 minutes, everything else rides the session TTL. */
export const OFFER_TTL_MS = 10 * 60 * 1000
export const SESSION_TTL_MS = 30 * 60 * 1000

/** Terminal message classes — compaction clears a session's mail after these. */
export const TERMINAL_CLASSES = ['BYE', 'COMPLETE', 'DECLINE', 'CANCEL']

/** Maximum envelopes kept per session mailbox (compaction floor). */
export const MAILBOX_SESSION_CAP = 64

/** A typed invalid-envelope error (the gate's refusal shape). */
export function beam2EnvelopeError(code, detail) {
  const e = new Error(`BEAM2_ENVELOPE_${code}: ${detail}`)
  e.code = `BEAM2_ENVELOPE_${code}`
  return e
}

/**
 * Validate + normalize a Beam 2 envelope. Throws beam2EnvelopeError on any
 * structural violation. `draft:true` (the pre-sign build phase) tolerates an
 * empty sig — the SEAL step re-validates fully and demands it.
 */
export function validateEnvelope(env, { draft = false } = {}) {
  if (!env || typeof env !== 'object') throw beam2EnvelopeError('SCHEMA', 'envelope missing')
  if (env.v !== ENVELOPE_VERSION) throw beam2EnvelopeError('VERSION', `expected v:${ENVELOPE_VERSION}, got ${JSON.stringify(env.v)}`)
  if (!MESSAGE_CLASSES.includes(env.type)) throw beam2EnvelopeError('TYPE', `unknown message class: ${env.type}`)
  if (typeof env.sessionId !== 'string' || env.sessionId.length < 8) throw beam2EnvelopeError('SESSION', 'sessionId missing/short')
  if (typeof env.from !== 'string' || env.from.length < 4) throw beam2EnvelopeError('FROM', 'from missing')
  if (typeof env.to !== 'string' || env.to.length < 4) throw beam2EnvelopeError('TO', 'to missing')
  if (!Number.isInteger(env.seq) || env.seq < 0) throw beam2EnvelopeError('SEQ', 'seq must be a non-negative integer')
  if (!Number.isFinite(env.ts) || env.ts <= 0) throw beam2EnvelopeError('TS', 'ts must be a positive epoch ms')
  if (typeof env.payload !== 'object' || env.payload === null) throw beam2EnvelopeError('PAYLOAD', 'payload must be an object')
  if (typeof env.sig !== 'string' || (!draft && !env.sig.length)) throw beam2EnvelopeError('SIG', 'sig missing — every control message is signed (law 0.54)')
  return Object.freeze({ ...env })
}

/** Build a DRAFT envelope (empty sig — sign the payload, then sealEnvelope). */
export function buildEnvelope({ type, sessionId, from, to, seq, ts = Date.now(), payload = {}, sig = '' }) {
  return validateEnvelope({ v: ENVELOPE_VERSION, type, sessionId, from, to, seq, ts, payload, sig }, { draft: true })
}

/** Re-attach a signature and re-validate (the seal step after signing). */
export function sealEnvelope(env, sig) {
  return validateEnvelope({ ...env, sig })
}

/**
 * INBOUND TRACKER — per-session sequence numbers, dedupe, gap detection.
 * One instance per (peer, direction). The worker keeps one per active peer.
 */
export class InboundTracker {
  constructor() {
    /** @type {Map<string, number>} sessionId → highest contiguous seq delivered */
    this.expected = new Map()
    /** @type {Map<string, Set<number>>} sessionId → buffered out-of-order seqs */
    this.buffered = new Map()
    /** @type {Map<string, Set<string>>} sessionId → seen message keys (dedupe) */
    this.seen = new Map()
  }

  static messageKey(env) {
    return `${env.from}:${env.sessionId}:${env.seq}:${env.type}`
  }

  /**
   * Offer one envelope for delivery.
   * @returns {{deliver:boolean, reason?:'duplicate'|'gap'|'stale', gapFrom?:number, bufferedCount?:number}}
   */
  offer(env) {
    const sid = env.sessionId
    if (!this.expected.has(sid)) this.expected.set(sid, 0)
    if (!this.buffered.has(sid)) this.buffered.set(sid, new Set())
    if (!this.seen.has(sid)) this.seen.set(sid, new Set())
    const key = InboundTracker.messageKey(env)
    const seen = this.seen.get(sid)
    if (seen.has(key)) return { deliver: false, reason: 'duplicate' }
    seen.add(key)
    const exp = this.expected.get(sid)
    if (env.seq < exp) return { deliver: false, reason: 'stale' }
    if (env.seq === exp) {
      // deliver and drain any buffered successors
      this.expected.set(sid, exp + 1)
      let next = this.expected.get(sid)
      const buf = this.buffered.get(sid)
      while (buf.has(next)) {
        buf.delete(next)
        next += 1
        this.expected.set(sid, next)
      }
      return { deliver: true }
    }
    // env.seq > exp — a gap; buffer it and report
    this.buffered.get(sid).add(env.seq)
    return { deliver: false, reason: 'gap', gapFrom: exp, bufferedCount: this.buffered.get(sid).size }
  }

  /** The next seq this tracker expects for a session (gap diagnostics). */
  expectedSeq(sessionId) {
    return this.expected.get(sessionId) ?? 0
  }

  /** Outstanding buffered (out-of-order) seqs for a session. */
  pendingSeqs(sessionId) {
    return [...(this.buffered.get(sessionId) || [])].sort((a, b) => a - b)
  }

  /** Terminal cleanup — free the session's memory (compaction's twin). */
  release(sessionId) {
    this.expected.delete(sessionId)
    this.buffered.delete(sessionId)
    this.seen.delete(sessionId)
  }
}

/** OUTBOUND TRACKER — the per-session monotonic sender counter. */
export class OutboundTracker {
  constructor() {
    /** @type {Map<string, number>} */
    this.next = new Map()
  }

  /** Allocate the next seq for a session. */
  alloc(sessionId) {
    const cur = this.next.get(sessionId) ?? 0
    this.next.set(sessionId, cur + 1)
    return cur
  }

  release(sessionId) {
    this.next.delete(sessionId)
  }
}

/**
 * TTL SWEEP — split a mailbox list into live vs expired envelopes (clock-skew
 * honest: an envelope stamped in the future by a skewed clock is LIVE until
 * its ts; the sweep never uses local send-time assumptions, only expiry).
 * @param {Array<{expiresAt:number, sessionId:string, type:string}>} list
 * @param {number} now
 */
export function sweepExpired(list, now = Date.now()) {
  const live = []
  const expired = []
  for (const env of Array.isArray(list) ? list : []) {
    const exp = Number(env && env.expiresAt)
    if (!Number.isFinite(exp) || exp <= now) expired.push(env)
    else live.push(env)
  }
  return { live, expired }
}

/**
 * ORPHAN SWEEPER + COMPACTION — after a terminal class (BYE / COMPLETE /
 * DECLINE / CANCEL), the session's remaining envelopes are REMOVED, not
 * archived: no orphan ciphertext is ever left behind. Non-terminal sessions
 * keep only the newest MAILBOX_SESSION_CAP envelopes.
 * @param {Array<{sessionId:string, type:string, expiresAt:number}>} list
 * @param {number} now
 * @returns {{kept:Array, removed:number, sessionsCompacted:string[]}}
 */
export function compactMailbox(list, now = Date.now()) {
  const terminal = new Set()
  for (const env of Array.isArray(list) ? list : []) {
    if (env && TERMINAL_CLASSES.includes(env.type)) terminal.add(env.sessionId)
  }
  const kept = []
  let removed = 0
  const perSession = new Map()
  for (const env of Array.isArray(list) ? list : []) {
    const sid = env && env.sessionId
    if (terminal.has(sid)) {
      removed++
      continue
    }
    const exp = Number(env && env.expiresAt)
    if (!Number.isFinite(exp) || exp <= now) {
      removed++
      continue
    }
    kept.push(env)
  }
  // per-session cap: drop the OLDEST beyond the cap
  for (const env of kept) {
    const arr = perSession.get(env.sessionId) || []
    arr.push(env)
    perSession.set(env.sessionId, arr)
  }
  const trimmed = []
  const sessionsCompacted = []
  for (const [sid, arr] of perSession) {
    if (arr.length > MAILBOX_SESSION_CAP) {
      sessionsCompacted.push(sid)
      arr.sort((a, b) => (a.ts || 0) - (b.ts || 0))
      removed += arr.length - MAILBOX_SESSION_CAP
      trimmed.push(...arr.slice(arr.length - MAILBOX_SESSION_CAP))
    } else {
      trimmed.push(...arr)
    }
  }
  return { kept: trimmed, removed, sessionsCompacted }
}

/**
 * The session deadline map for a fresh offer (both TTLs named by the law).
 * @returns {{offerExpiresAt:number, sessionExpiresAt:number}}
 */
export function sessionDeadlines(now = Date.now()) {
  return { offerExpiresAt: now + OFFER_TTL_MS, sessionExpiresAt: now + SESSION_TTL_MS }
}

/** Countdown helper for the visible countdown rows (law §2.E). */
export function remainingMs(deadline, now = Date.now()) {
  return Math.max(0, (Number(deadline) || 0) - now)
}
