/**
 * UCrypt — R147 §5.4 — THE CONFIRM ROUNDTRIP (lib/road/confirm.js).
 *
 * THE J-1 CURE (capture A4 — "They got a match code but the transfer doesn't
 * happened!"): the old confirm rode ONLY the WebRTC DataChannel, and when
 * that channel was not open, lib/bridge/page.js:521-525 swallowed the send
 * error and returned {ok:true} — a FALSE SUCCESS while nothing left the
 * machine. The sender then waited in silence.
 *
 * THE NEW LAW: the receiver's "The codes match" click sends a confirm
 * envelope over EVERY carrier the session has — the verified direct channel
 * AND the relay lane (idempotent: the first confirm the sender sees wins;
 * duplicates are consumed harmlessly). The function's return is TYPED: which
 * carrier actually accepted the send. A send that throws is a typed NONE —
 * never a false success.
 *
 * The sender listens on BOTH carriers for 120 s (the watchdog law). No
 * confirm inside the window = CONFIRM_TIMEOUT with the next step — silence
 * is a red class.
 *
 * PURE — the carriers are injected. Battery: tests/road/r147-confirm.test.mjs.
 */

/** The §5.4 watchdog (the ledgered number). */
export const CONFIRM_WATCHDOG_MS = 120 * 1000

export function confirmError(code, message) {
  const e = new Error(message)
  e.code = `ROAD_CONFIRM_${code}`
  return e
}

/**
 * Send the receiver's verdict. Every carrier is tried; failures are typed,
 * never swallowed. `dc` may be null (relay-only session) and `lane` may be
 * null (direct-only session) — at least one must exist.
 * @param {object} args
 *   matched    — true (the codes match) | false (mismatch — aborts)
 *   dc         — the verified DataChannel | null
 *   lane       — { put({ toMemberId, envelope }), myMemberId, peerMemberId } | null
 *   sessionId, code — the session + the 6-digit code (the envelope's payload)
 *   buildEnvelope — async ({ kind, sessionId, payload }) => envelope (the signal builder)
 * Returns { ok, via: 'direct'|'relay'|'both'|'none', failures: [...] }
 */
export async function sendConfirm({ matched, dc = null, lane = null, sessionId, code = '', buildEnvelope } = {}) {
  if (!dc && !lane) return { ok: false, via: 'none', failures: [{ carrier: 'all', error: 'no carrier exists for this session' }] }
  const failures = []
  let viaDirect = false
  let viaRelay = false

  if (dc) {
    try {
      if (dc.readyState !== 'open') throw new Error(`the channel is ${dc.readyState} — the direct carrier is not established`)
      dc.send(JSON.stringify({ t: matched ? 'code-ok' : 'code-mismatch', sessionId, code }))
      viaDirect = true
    } catch (e) {
      failures.push({ carrier: 'direct', error: String((e && e.message) || e).slice(0, 160) })
    }
  }
  if (lane && lane.put && lane.peerMemberId) {
    try {
      const env = await buildEnvelope({ kind: 'bridge-confirm', sessionId, payload: { matched: !!matched, code, fromMemberId: lane.myMemberId || '' } })
      const r = await lane.put({ toMemberId: lane.peerMemberId, envelope: env })
      if (r && r.ok) viaRelay = true
      else failures.push({ carrier: 'relay', error: (r && r.userMessage) || 'the relay lane refused the confirm' })
    } catch (e) {
      failures.push({ carrier: 'relay', error: String((e && e.message) || e).slice(0, 160) })
    }
  }

  const via = viaDirect && viaRelay ? 'both' : viaDirect ? 'direct' : viaRelay ? 'relay' : 'none'
  return { ok: via !== 'none', via, failures }
}

/**
 * The sender's wait: listen on BOTH carriers for the receiver's verdict.
 * Resolves typed — never throws, never waits silently past the watchdog.
 * @param {object} args
 *   dc            — the DataChannel | null
 *   lane          — { poll() → { signals } , consume({sessionId,signalId}) } | null
 *   sessionId
 *   timeoutMs     — default CONFIRM_WATCHDOG_MS (the §5.4 law)
 *   now           — the clock (tests inject)
 * Returns { ok:true, matched:true, via } | { ok:true, matched:false } |
 *          { ok:false, code:'CONFIRM_TIMEOUT', nextStep }
 */
export async function waitConfirm({ dc = null, lane = null, sessionId, timeoutMs = CONFIRM_WATCHDOG_MS, now = () => Date.now() } = {}) {
  const startedAt = now()
  return new Promise((resolve) => {
    let done = false
    const finish = (r) => { if (!done) { done = true; resolve(r) } }

    const fromEnvelope = (payload) => {
      if (!payload || typeof payload !== 'object') return null
      return { matched: payload.matched === true, via: 'relay' }
    }

    const timer = setInterval(() => {
      if (now() - startedAt > timeoutMs) {
        clearInterval(timer)
        finish({
          ok: false,
          code: 'CONFIRM_TIMEOUT',
          nextStep: 'They may be asleep — check both devices are online and unlocked, then send the words again.',
        })
      }
    }, 250)

    if (dc) {
      const onMsg = (ev) => {
        try {
          const m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
          if (m && (m.t === 'code-ok' || m.t === 'code-mismatch') && (!m.sessionId || m.sessionId === sessionId)) {
            clearInterval(timer)
            finish({ ok: true, matched: m.t === 'code-ok', via: 'direct' })
          }
        } catch { /* binary frames flow here too */ }
      }
      try { dc.addEventListener('message', onMsg) } catch { /* the channel died before the listen */ }
    }

    if (lane && lane.poll) {
      const pollTick = async () => {
        while (!done) {
          try {
            const poll = await lane.poll()
            for (const s of (poll && poll.signals) || []) {
              if (s.envelope && s.envelope.kind === 'bridge-confirm' && s.envelope.sessionId === sessionId) {
                const v = fromEnvelope(s.envelope.payload)
                try { await lane.consume({ sessionId, signalId: s.signalId }) } catch { /* already consumed */ }
                if (v) { clearInterval(timer); finish({ ok: true, matched: v.matched, via: 'relay' }) }
              }
            }
          } catch { /* a dead poll tick never ends the wait — the watchdog owns that */ }
          await new Promise((r) => setTimeout(r, 300))
        }
      }
      pollTick()
    }
  })
}
