/**
 * UCrypt — R136 §6.4 — THE BEAM 3 SIGNAL (the manual plane's first-class
 * citizen + every plane's pairing token).
 *
 * The signal is the thing a human carries between machines (Plane C) or
 * the cloud relays (Plane B). Its contract (R136-F1's exact remediation):
 *   - it renders IN FULL with its validity in human words —
 *     "valid until used, or 24 hours";
 *   - it stays valid until CONSUMED (the nonce ledger) or 24 hours old;
 *   - Open signal advances the state machine to the PAIRED state — the
 *     roster, the both-screens code, and the full send/receive
 *     continuation render from there (the dead-end is extinct);
 *   - expiry is a TYPED terminal with a one-tap regenerate (a fresh nonce,
 *     in-flight sessions untouched);
 *   - replay is refused through the nonce ledger (S5).
 *
 * PURE — battery-pinned (TRF-SIGNAL-*, S3/S5, G74's S3 journey).
 */

import { BEAM3_SIGNAL_TTL_MS } from './planes.js'
import { freshNonce } from './nonce-ledger.js'

/** The signal record shape version. */
export const SIGNAL_VERSION = 3

/** Typed signal error. */
export function signalError(code, detail) {
  const e = new Error(`BEAM3_SIGNAL_${code}: ${detail}`)
  e.code = `BEAM3_SIGNAL_${code}`
  return e
}

/**
 * Build a fresh signal: {v, nonce, issuedAt, expiresAt, device} — the
 * envelope is sealed by the caller (the worker owns keys); this module
 * owns the LIFETIME semantics.
 */
export function buildSignal({ deviceId, deviceLabel = '', now = Date.now(), sessionId = '' }) {
  if (!deviceId) throw signalError('DEVICE', 'deviceId required')
  const issuedAt = Number(now) || Date.now()
  return {
    v: SIGNAL_VERSION,
    nonce: freshNonce(),
    sessionId: String(sessionId || ''),
    issuedAt,
    expiresAt: issuedAt + BEAM3_SIGNAL_TTL_MS,
    device: { id: String(deviceId), label: String(deviceLabel || '') },
  }
}

/**
 * Lifetime truth — the two-word validity the UI prints:
 *   consumed → 'consumed'; now ≥ expiresAt → 'expired'; otherwise 'live'.
 */
export function signalValidity(signal, { consumed = false, now = Date.now() } = {}) {
  if (!signal || typeof signal !== 'object') return { state: 'invalid', words: 'invalid signal' }
  if (consumed) return { state: 'consumed', words: 'used — this signal cannot be reused' }
  const exp = Number(signal.expiresAt) || 0
  if (exp <= now) return { state: 'expired', words: 'expired — regenerate to make a fresh one' }
  const hours = Math.max(0, Math.round((exp - now) / 3600000))
  return { state: 'live', words: `valid until used, or ${hours} hour${hours === 1 ? '' : 's'} left` }
}

/**
 * Open-signal gate (the receiver side): the signal must be structurally
 * sound, unconsumed, and inside its horizon — every refusal is TYPED and
 * each names its one-tap next action (the R136-F1 remediation's "typed
 * terminal with a one-tap regenerate").
 * @returns {{ok:true, signal}} or {ok:false, terminal:'expired'|'replay'|'invalid', words}
 */
export function openSignalGate(signal, { consumed = false, now = Date.now() } = {}) {
  if (!signal || typeof signal !== 'object' || !signal.nonce) {
    return { ok: false, terminal: 'invalid', words: 'This is not a UCrypt signal — ask the other device to copy its signal again.' }
  }
  if (String(signal.v) !== String(SIGNAL_VERSION)) {
    return { ok: false, terminal: 'invalid', words: 'This signal came from a different version — update both devices and try again.' }
  }
  if (consumed) {
    return { ok: false, terminal: 'replay', words: 'That signal was already used — signals are single-use. Ask the other device to regenerate.' }
  }
  const validity = signalValidity(signal, { consumed, now })
  if (validity.state === 'expired') {
    return { ok: false, terminal: 'expired', words: 'That signal expired before it was used — press Regenerate on the other device, or paste a fresh signal here.' }
  }
  return { ok: true, signal }
}

/**
 * REGENERATE — a fresh nonce/issuedAt for the SAME device + session
 * binding. In-flight sessions are untouched: the regenerate creates a new
 * signal object and the old one simply rests (its nonce was never
 * consumed — the sweep retires it at the horizon).
 */
export function regenerateSignal(previous, { now = Date.now() } = {}) {
  const prior = previous && typeof previous === 'object' ? previous : {}
  return buildSignal({ deviceId: prior.device ? prior.device.id : '', deviceLabel: prior.device ? prior.device.label : '', now, sessionId: prior.sessionId || '' })
}

/**
 * The render form of the signal for the copy box: base64 of the JSON (the
 * recordToManual lineage) — generous size, full fidelity.
 */
export function signalToText(signal) {
  try {
    return btoa(JSON.stringify(signal))
  } catch {
    throw signalError('ENCODE', 'the signal could not be encoded')
  }
}

/** Parse a pasted signal back (null when not a signal — typed upstream). */
export function signalFromText(text) {
  try {
    const obj = JSON.parse(atob(String(text || '').trim()))
    return obj && typeof obj === 'object' && obj.nonce ? obj : null
  } catch {
    return null
  }
}

/**
 * R138 §4.2 — THE ANSWER ENVELOPE (the two-way manual protocol's return
 * signal). An answer is a signal-shaped record bound to the inbound signal
 * it answers (refNonce + refSession), produced THE INSTANT the inbound
 * signal opens — it never depends on a cloud route, and its existence
 * PROVES the pairing (the sender applying it pairs and connects in one
 * bounded transition — the no-redo law).
 */
export function buildAnswer({ forSignal, deviceId, deviceLabel = '', now = Date.now() }) {
  if (!forSignal || typeof forSignal !== 'object' || !forSignal.nonce) {
    throw signalError('ANSWER_REF', 'the answer must bind an inbound signal')
  }
  if (!deviceId) throw signalError('DEVICE', 'deviceId required')
  const issuedAt = Number(now) || Date.now()
  return {
    v: SIGNAL_VERSION,
    ans: true, // the answer marker — the classifier's discriminant
    refNonce: String(forSignal.nonce),
    refSession: String(forSignal.sessionId || ''),
    nonce: freshNonce(),
    sessionId: String(forSignal.sessionId || ''),
    issuedAt,
    expiresAt: issuedAt + BEAM3_SIGNAL_TTL_MS,
    device: { id: String(deviceId), label: String(deviceLabel || '') },
  }
}

/**
 * THE CLASSIFIER (one paste box, one Open button — the journey advances by
 * what the record IS, never by a second manual mode): 'signal' (a peer's
 * discovery signal → the PAIRED path), 'answer' (the peer's answer bound
 * to MY session → the deterministic CONNECTED path), or null.
 */
export function classifySignalRecord(record) {
  if (!record || typeof record !== 'object' || !record.nonce) return null
  if (record.ans === true) {
    if (!record.refNonce) return null
    return 'answer'
  }
  return 'signal'
}
