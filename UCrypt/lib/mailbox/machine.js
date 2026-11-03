/**
 * UCrypt — R141 §7.2/§7.5 beats 3–4 + §7.6 — THE MAILBOX JOURNEY MACHINE
 * and the R141 §7.10 off-road file (.ucrypt-offer) — one module, two duties.
 *
 * THE MACHINE (matrix row 41's "re-created, not inherited"): the sender's
 * journey and the receiver's journey as ONE typed machine with a journal.
 * Honest by construction:
 *   - "Delivered" exists ONLY after the store's own write confirmation
 *     (the honest mailbox law — the relay said so, with a timestamp);
 *   - the card's waiting state shows AGE, never a countdown;
 *   - every failure names the ONE blocked hop and the ONE action (§7.9);
 *   - receipts advance the state; nothing auto-dismisses without the user.
 *
 * THE OFF-ROAD FILE (§7.10 — curing the copy/paste conversation class):
 * one self-contained <fileName>.ucrypt-offer — the SAME envelope, the SAME
 * chunks, the SAME verify code — moved by USB/email/SMB with the cloud
 * fully disconnected. Import validates exactly like the road does.
 *
 * PURE — battery-pinned (G88 extension, tests/r141-mailbox.test.mjs).
 */

import { ageSentence, mailboxError, transitionReceipt } from './protocol.js'

/* ── The journey machine ─────────────────────────────────────────────────── */

export const MAILBOX_STATES = {
  IDLE: 'IDLE',
  COMPOSING: 'COMPOSING',       // the file is picked, the recipient chosen
  SENDING: 'SENDING',           // the chunks are in flight (write hops named)
  DELIVERED: 'DELIVERED',       // the backend CONFIRMED the writes (with a timestamp)
  ACCEPTED: 'ACCEPTED',         // the receiver pressed Accept (receipt: accepted)
  VERIFIED: 'VERIFIED',         // the fingerprint auto-checked (receipt: verified)
  DECLINED: 'DECLINED',         // the receiver declined (receipt: declined)
  EXPIRED: 'EXPIRED',           // 7 days passed uncollected
  CANCELLED: 'CANCELLED',       // the user cancelled
  FAILED: 'FAILED',             // a named hop failed (detail carries hop + action)
}

const SENDER_EDGES = {
  IDLE: ['COMPOSING', 'CANCELLED'],
  COMPOSING: ['SENDING', 'CANCELLED'],
  SENDING: ['DELIVERED', 'FAILED', 'CANCELLED'],
  DELIVERED: ['ACCEPTED', 'VERIFIED', 'DECLINED', 'EXPIRED'],
  ACCEPTED: ['VERIFIED', 'EXPIRED'],
  VERIFIED: [],
  DECLINED: [],
  EXPIRED: [],
  CANCELLED: [],
  FAILED: [],
}

export function newMailboxJourney({ offerId, fromName, toName, fileName, size, verifyCode, now = Date.now() }) {
  return {
    role: 'sender',
    state: MAILBOX_STATES.IDLE,
    offerId, fromName, toName, fileName, size, verifyCode,
    createdAt: now,
    deliveredAt: null,
    receipt: null,
    hop: null, // the last named hop: { name, ok, detail, action }
    journal: [{ state: MAILBOX_STATES.IDLE, at: now }],
  }
}

export function stepJourney(j, to, { now = Date.now(), hop = null, receipt = null } = {}) {
  if (!j || !SENDER_EDGES[j.state]) throw mailboxError('MACHINE_SHAPE', 'the journey is malformed')
  if (!Object.values(MAILBOX_STATES).includes(to)) throw mailboxError('MACHINE_STATE', `unknown state ${String(to)}`)
  if (!SENDER_EDGES[j.state].includes(to)) throw mailboxError('MACHINE_EDGE', `a ${j.state} journey cannot step to ${to}`)
  const next = { ...j, state: to, journal: [...j.journal, { state: to, at: now }] }
  if (hop) next.hop = hop
  if (to === MAILBOX_STATES.DELIVERED) next.deliveredAt = now
  if (receipt) next.receipt = receipt
  return next
}

/** The receipt → state mapping (the sender's card reads the receiver's truth). */
export function applyReceipt(j, receipt, now = Date.now()) {
  if (!receipt || typeof receipt.state !== 'string') throw mailboxError('RECEIPT_SHAPE', 'the receipt is malformed')
  const map = { accepted: MAILBOX_STATES.ACCEPTED, verified: MAILBOX_STATES.VERIFIED, declined: MAILBOX_STATES.DECLINED, expired: MAILBOX_STATES.EXPIRED }
  const to = map[receipt.state]
  if (!to) throw mailboxError('RECEIPT_STATE', `unknown receipt state ${String(receipt.state)}`)
  return stepJourney(j, to, { now, receipt })
}

/** The waiting line: AGE, never a countdown. */
export function senderWaitingLine(j, now = Date.now()) {
  if (j.state === MAILBOX_STATES.DELIVERED) {
    const t = new Date(j.deliveredAt)
    const hh = String(t.getHours()).padStart(2, '0')
    const mm = String(t.getMinutes()).padStart(2, '0')
    return `Delivered to ${j.toName}'s mailbox at ${hh}:${mm} — their UCrypt picks it up automatically · ${ageSentence(j.createdAt, now)}`
  }
  if (j.state === MAILBOX_STATES.SENDING) return 'Sending — the mailbox write is in flight…'
  if (j.state === MAILBOX_STATES.FAILED) {
    return `Could not deliver — ${j.hop && j.hop.detail ? j.hop.detail : 'the mailbox could not be reached'} — ${j.hop && j.hop.action ? j.hop.action : 'Retry now'}`
  }
  return ''
}

/** The receiver's offer card line (§7.7): one truth, one writer. */
export function receiverOfferLine({ fromName, fileName, size, verifyCode }) {
  return `From ${fromName} · ${fileName} · Code ${verifyCode}`
}

/* ── The off-road file (.ucrypt-offer) ───────────────────────────────────── */

export const OFFROAD_MAGIC = 'ucrypt-offer'
export const OFFROAD_VERSION = 1

/** Export: ONE self-contained file — envelope + sealed chunks + the code. */
export function buildOffroadFile({ envelope, chunks }) {
  if (!envelope || !Array.isArray(chunks) || chunks.length !== Number(envelope.chunkCount)) {
    throw mailboxError('OFFROAD_SHAPE', 'the off-road file needs the envelope and every chunk')
  }
  return JSON.stringify({
    magic: OFFROAD_MAGIC,
    version: OFFROAD_VERSION,
    envelope,
    chunks,
  })
}

/** Import: the same validation the road applies (the envelope parse is the
 * caller's door — this validates the FILE shape and the chunk counts). */
export function parseOffroadFile(text) {
  let parsed
  try { parsed = JSON.parse(String(text || '')) } catch { throw mailboxError('OFFROAD_SHAPE', 'the file is not a valid .ucrypt-offer') }
  if (!parsed || parsed.magic !== OFFROAD_MAGIC) throw mailboxError('OFFROAD_MAGIC', 'this file is not a UCrypt offer file')
  if (Number(parsed.version) !== OFFROAD_VERSION) throw mailboxError('OFFROAD_VERSION', 'the offer file version is not supported')
  if (!parsed.envelope || typeof parsed.envelope !== 'object') throw mailboxError('OFFROAD_SHAPE', 'the offer file has no envelope')
  if (!Array.isArray(parsed.chunks) || parsed.chunks.length !== Number(parsed.envelope.chunkCount)) {
    throw mailboxError('OFFROAD_CHUNKS', 'the offer file is missing chunks')
  }
  return parsed
}

/* ── Receipt expiry helper shared by the poll ───────────────────────────── */

export function receiptToState(receipt, now = Date.now()) {
  try { return transitionReceipt(receipt, 'expired', now) } catch { return receipt }
}
