/**
 * UCrypt — R148 §4 — THE UNIVERSAL ENVELOPE DOOR (lib/road/envelope.js).
 *
 * LAW #72 — THE UNIVERSAL DOOR LAW: any valid sealed envelope (offer, answer,
 * relay-session join) pasted or scanned into ANY words surface of the transfer
 * area is understood, type-routed, and answered with instant typed feedback
 * inside the watchdog window. NO box may swallow an envelope. NO box is
 * role-locked: the machine routes by ENVELOPE TYPE, not by which box received
 * it. A wrong-type or corrupt paste is IMPOSSIBLE to miss: the surface names
 * what was received and what happens next.
 *
 * THE OWNER'S QUESTION IS THE SPEC (K1 RIGHT): "Does a code should be
 * generated to be pasted in the other instance?" — YES. The words protocol is
 * a TWO-WAY relay: the sender's OFFER words go to the receiver; the receiver
 * generates ANSWER words that go back; the sender pastes the answer; the road
 * establishes; the codes match on both screens. This module is the router
 * that makes the exchange impossible to misuse:
 *
 *   classifyEnvelopeText(text)  — pure shape+kind classification (no doors).
 *   routeEnvelope(text, doors)  — the full router: OFFER → the receive flow;
 *                                 ANSWER → the sender's handshake completes;
 *                                 mis-placed types → typed guidance; CORRUPT
 *                                 → a typed verdict that names what to do.
 *
 * The routes (every one answers INSIDE the watchdog window, never silence):
 *   OFFER + no live session      → the RECEIVE flow spawns (the owner's
 *                                  answer: the machine makes the code).
 *   OFFER + live SENDER session  → typed guidance (this is the OTHER side's
 *                                  words — paste them on the other device,
 *                                  or switch to Receive here).
 *   ANSWER + live SENDER session → the handshake completes (the code match
 *                                  surfaces, the road dials).
 *   ANSWER + live RECEIVER       → typed guidance (your own answer — the
 *                                  sender needs it, not you).
 *   ANSWER + no session          → typed guidance (the sender's reply box
 *                                  wants this).
 *   JOIN                         → typed guidance + the Cloud Sync hand-off.
 *   CORRUPT/EMPTY                → the typed verdict ("these words are not a
 *                                  complete UCrypt handshake — copy the
 *                                  whole block").
 *
 * PURE-ISH — the open door is injected (the page passes BRIDGE_OPEN); the
 * live-session probes are injected predicates. Battery: tests/r148-door.test.mjs.
 */
import { parseOfferEnvelope, wordsTokenToEnvelope, offerError } from './offer.js'

/** The typed envelope kinds (the ONLY routes this namespace emits). */
export const ENVELOPE_KINDS = Object.freeze({
  EMPTY: 'EMPTY',
  CORRUPT: 'CORRUPT',
  OFFER: 'OFFER',
  ANSWER: 'ANSWER',
  JOIN: 'JOIN',
  OFFER_COMPACT: 'OFFER_COMPACT', // the QR's face form — parses, but the sealed block rides the words
})

/** The envelope TTL guard (the parse's own clock — overridable for tests). */
export function classifyEnvelopeText(text, { now = Date.now() } = {}) {
  const t = String(text || '').trim()
  if (!t) return { kind: ENVELOPE_KINDS.EMPTY, detail: 'nothing was pasted — the box is empty' }

  /* 1 — the words token form (the house base32) — the completable form */
  if (!/^[\sA-Z2-7-]+$/i.test(t.replace(/\s/g, '')) || /[-]/.test(t)) {
    // the base32 words token carries dashes; try it first when dashes exist
  }
  try {
    const parsed = wordsTokenToEnvelope(t)
    return { kind: parsed.complete ? ENVELOPE_KINDS.OFFER : ENVELOPE_KINDS.OFFER_COMPACT, envelope: parsed.envelope, complete: parsed.complete, detail: 'the sealed handshake words' }
  } catch { /* not a words token — try the JSON forms */ }

  /* 2 — the raw JSON forms (the QR's compact face, or a copied full JSON) */
  try {
    const parsed = parseOfferEnvelope(t, { now })
    return { kind: parsed.complete ? ENVELOPE_KINDS.OFFER : ENVELOPE_KINDS.OFFER_COMPACT, envelope: parsed.envelope, complete: parsed.complete, detail: 'the handshake envelope (JSON form)' }
  } catch (e) {
    const code = e && e.code || ''
    if (code === 'ROAD_OFFER_EXPIRED') {
      return { kind: ENVELOPE_KINDS.CORRUPT, detail: 'this handshake EXPIRED (10 minutes) — ask the other device to show its words again', expired: true }
    }
    /* fall through to the join-signal probe */
  }

  /* 3 — the chain-join signal (Cloud Sync's zero-transport join — base64 JSON) */
  try {
    const raw = JSON.parse(atob(t.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')))
    if (raw && (raw.kind === 'join' || raw.kind === 'beam-join' || (raw.v === 1 && raw.kind))) {
      return { kind: ENVELOPE_KINDS.JOIN, detail: 'a chain-join signal (Cloud Sync\'s door)', joinKind: raw.kind }
    }
  } catch { /* not a join signal */ }

  return { kind: ENVELOPE_KINDS.CORRUPT, detail: 'these words are not a complete UCrypt handshake — copy the whole block (every word, the dashes included)' }
}

/**
 * THE ROUTER (LAW #72's body). Args:
 *   text        — the pasted/scanned text (any box, any role)
 *   doors:
 *     openDoor  — async ({ sealedB64 }) => { ok, payload } (BRIDGE_OPEN)
 *     liveSession() — { role: 'sender'|'receiver'|null } — THIS page's session
 *     startReceive(offerText) — async — spawns the receive flow for an offer
 *     completeHandshake(opened) — async — feeds the live sender session
 * Returns the typed route result the surface renders INLINE:
 *   { ok, kind, route, line, nextStep }
 */
export async function routeEnvelope(text, { openDoor, liveSession = () => ({ role: null }), startReceive, completeHandshake } = {}) {
  const cls = classifyEnvelopeText(text)
  if (cls.kind === ENVELOPE_KINDS.EMPTY) {
    return { ok: false, kind: cls.kind, route: 'verdict', line: 'The box is empty — paste the words (or read their QR image) first.', nextStep: 'paste' }
  }
  if (cls.kind === ENVELOPE_KINDS.CORRUPT) {
    return { ok: false, kind: cls.kind, route: 'verdict', line: `These words are not a complete UCrypt handshake — ${cls.detail}`, nextStep: 'recopy', expired: !!cls.expired }
  }
  if (cls.kind === ENVELOPE_KINDS.JOIN) {
    return { ok: false, kind: cls.kind, route: 'handoff-join', line: 'This is a chain-JOIN signal — it pairs a device with your Cloud Sync chain, not a file transfer. Cloud Sync is opening.', nextStep: 'cloud-sync' }
  }

  /* OFFER/ANSWER need the sealed payload OPENED (the role + nonce live inside). */
  const sealed = cls.envelope && cls.envelope.d
  let opened = null
  if (sealed && typeof openDoor === 'function') {
    const r = await openDoor({ sealedB64: sealed })
    if (r && r.ok) opened = r.payload || {}
  }
  const sealedRole = opened && opened.role
  const isAnswer = sealedRole === 'receiver'
  const isOffer = sealedRole === 'sender' || (!isAnswer && cls.complete)

  const live = liveSession() || { role: null }

  if (isOffer) {
    if (live.role === 'receiver') {
      return { ok: true, kind: ENVELOPE_KINDS.OFFER, route: 'receive', line: 'Their handshake is in — compare the 6-digit code, then send your words back.', nextStep: 'code', opened }
    }
    /* an OFFER pasted on a SENDER page (the owner's own K1 RIGHT move): the
       machine ANSWERS it — the receive flow spawns HERE (no box swallows). */
    if (typeof startReceive === 'function') {
      const r = await startReceive(text)
      const out = { ok: true, kind: ENVELOPE_KINDS.OFFER, route: 'receive-spawned', line: 'These are OFFER words (the sender\'s side) — this device just became the receiver for them: the code is on your screen. Send YOUR words back to the sender.', nextStep: 'answer-words', opened, receive: r }
      /* §5.2 — the spawn's TYPED verdict rides the route itself (the
         LEGACY_OFFER class surfaces even when the surface only reads the
         route; the failure LINE renders from receive.nextStep). */
      if (r && r.ok === false && r.code) { out.typed = true; out.code = r.code }
      return out
    }
    return { ok: true, kind: ENVELOPE_KINDS.OFFER, route: 'verdict', line: 'These are OFFER words — give them to the OTHER device (the receiver), or press "Receive a file" here and paste them.', nextStep: 'receive-here', opened }
  }

  if (isAnswer) {
    if (live.role === 'sender') {
      if (typeof completeHandshake === 'function') {
        const r = await completeHandshake({ opened, envelope: cls.envelope })
        return { ok: true, kind: ENVELOPE_KINDS.ANSWER, route: 'handshake-complete', line: 'Their reply is in — the road is dialing.', nextStep: 'road', opened, complete: r }
      }
      return { ok: false, kind: ENVELOPE_KINDS.ANSWER, route: 'verdict', line: 'The reply could not be delivered to the active session.', nextStep: 'retry' }
    }
    if (live.role === 'receiver') {
      return { ok: false, kind: ENVELOPE_KINDS.ANSWER, route: 'verdict', line: 'These are YOUR OWN answer words — the SENDER needs them, not you. Copy them (the button below) and send them back.', nextStep: 'copy-your-words' }
    }
    return { ok: false, kind: ENVELOPE_KINDS.ANSWER, route: 'verdict', line: 'These are ANSWER words — they belong in the SENDER\'S reply box (the device that showed the first code).', nextStep: 'sender-side' }
  }

  /* a completable envelope whose seal refused to open, or an unknown role */
  return { ok: false, kind: cls.kind, route: 'verdict', line: sealed ? 'The handshake could not be opened — it may be from a different chain, or the vault is locked on this device. Unlock and try again.' : 'This is the handshake\'s face (the QR form) — the sealed block rides the WORDS token: paste the full words (every word, the dashes included).', nextStep: sealed ? 'unlock' : 'full-words', opened }
}

export { offerError }
