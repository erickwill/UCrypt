/**
 * UCrypt — R147 §5.3 — THE DIALER (lib/road/dial.js — the road's brain).
 *
 * Two roads, tried in order, BOTH first-class:
 *   ROAD 1 — DIRECT (LAN): the WebRTC DataChannel bootstrapped from the
 *     compact offer's host candidate + the STUN servers (the R146 dead
 *     door — iceServersConfig() was defined at lib/bridge/page.js:266 and
 *     NEVER CALLED while newPc() hardcoded iceServers:[] — is WIRED here:
 *     the STUN list rides in through the transport adapter). ESTABLISHED
 *     only after the ping→pong proof crosses the channel (a 4-byte nonce
 *     round trip, 5 s budget).
 *   ROAD 2 — RELAY (the chain mailbox): the SAME lane that carries chain
 *     sync and presence — typed envelopes addressed by member id, polled
 *     by both sides (5 s during an active session). ESTABLISHED after the
 *     first round-trip envelope is acked.
 *
 * If ROAD 1 fails to establish inside 20 s, the dialer falls to ROAD 2
 * AUTOMATICALLY and says so in plain words. If both fail: the typed
 * UNAVAILABLE verdict with the next step — never a silent wait (LAW #68).
 *
 * The dialer owns NO DOM and NO chrome.* — the page module injects the
 * transport adapters (the real WebRTC + the door lane in the field; the
 * mock pair + the memory lane in the battery and in G98). Journal: every
 * decision + elapsed time rides out for "Show the technical detail".
 *
 * Battery: tests/road/r147-dial.test.mjs. G98: tools/r147-e2e.mjs.
 */

/** The typed dialer states (the ONLY states this namespace emits). */
export const ROAD_STATES = Object.freeze({
  IDLE: 'idle',
  CHOOSING: 'choosing',
  DIRECT_PROBING: 'direct-probing',
  DIRECT_VERIFIED: 'direct-verified',
  RELAY_ESTABLISHING: 'relay-establishing',
  RELAY_VERIFIED: 'relay-verified',
  UNAVAILABLE: 'unavailable',
})

/** The §5.3 budgets (the ledgered numbers). */
export const DIRECT_BUDGET_MS = 20 * 1000
export const PROOF_BUDGET_MS = 5 * 1000
export const RELAY_ACK_BUDGET_MS = 30 * 1000

export function dialError(code, message) {
  const e = new Error(message)
  e.code = `ROAD_DIAL_${code}`
  return e
}

/** The legal state walks (the truth law at the road layer). */
const LEGAL = {
  [ROAD_STATES.IDLE]: [ROAD_STATES.CHOOSING],
  [ROAD_STATES.CHOOSING]: [ROAD_STATES.DIRECT_PROBING, ROAD_STATES.RELAY_ESTABLISHING, ROAD_STATES.UNAVAILABLE],
  [ROAD_STATES.DIRECT_PROBING]: [ROAD_STATES.DIRECT_VERIFIED, ROAD_STATES.RELAY_ESTABLISHING, ROAD_STATES.UNAVAILABLE],
  [ROAD_STATES.DIRECT_VERIFIED]: [ROAD_STATES.RELAY_ESTABLISHING, ROAD_STATES.UNAVAILABLE, ROAD_STATES.IDLE],
  [ROAD_STATES.RELAY_ESTABLISHING]: [ROAD_STATES.RELAY_VERIFIED, ROAD_STATES.UNAVAILABLE],
  [ROAD_STATES.RELAY_VERIFIED]: [ROAD_STATES.IDLE],
  [ROAD_STATES.UNAVAILABLE]: [ROAD_STATES.IDLE],
}

/**
 * Create the dialer.
 * @param {object} adapters
 *   direct  — { connect({ role, offerSdp, answerSdp }) → { dc }, close() } —
 *             the WebRTC adapter (the page wires RTCPeerConnection with the
 *             STUN list; tests wire a loopback pair)
 *   relay   — { put({ toMemberId, envelope }) → { ok }, poll() → { signals },
 *             consume({ sessionId, signalId }) } — the signal-lane adapter
 *   log     — (line) => void (the plain-words line writer)
 *   now     — the clock (tests inject)
 */
export function createDialer({ direct = null, relay = null, log = () => {}, now = () => Date.now() } = {}) {
  let state = ROAD_STATES.IDLE
  let dc = null
  const journal = []
  const record = (event, detail = {}) => {
    journal.push({ at: now(), event, ...detail })
  }

  const to = (next) => {
    if (!LEGAL[state].includes(next)) throw dialError('STATE', `the road law forbids ${state} → ${next}`)
    record('state', { from: state, to: next })
    state = next
    return state
  }

  /** The ping→pong proof (both sides run it; each resolves on its own pong). */
  function proofOverChannel(channel, { budgetMs = PROOF_BUDGET_MS } = {}) {
    return new Promise((resolve) => {
      const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(4))))
      let done = false
      const finish = (ok, why = '') => {
        if (done) return
        done = true
        try { channel.removeEventListener('message', onMsg) } catch { /* closed */ }
        try { clearInterval(timer) } catch { /* already */ }
        resolve({ ok, why, rttMs: Date.now() - startedAt })
      }
      const onMsg = (ev) => {
        try {
          const m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
          if (m && m.t === 'road-pong' && m.n === nonce) finish(true)
        } catch { /* binary frames flow here too */ }
      }
      const startedAt = now()
      let timer = null
      try {
        channel.addEventListener('message', onMsg)
        channel.send(JSON.stringify({ t: 'road-ping', n: nonce }))
        timer = setInterval(() => {
          if (now() - startedAt > budgetMs) finish(false, 'the ping never returned')
        }, 120)
      } catch (e) {
        finish(false, String((e && e.message) || e))
      }
    })
  }

  /** The receiver's auto-answer to the proof (wired on the receiver's channel). */
  function answerPings(channel) {
    channel.addEventListener('message', (ev) => {
      try {
        const m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        if (m && m.t === 'road-ping') channel.send(JSON.stringify({ t: 'road-pong', n: m.n }))
      } catch { /* binary frames flow here too */ }
    })
  }

  return {
    get state() { return state },
    get dc() { return dc },
    journal() { return [...journal] },

    /** Open the session's road hunt. Never throws — every ending is typed. */
    async establish({ role, sessionId, offerSdp = '', answerSdp = '', toMemberId = '' } = {}) {
      if (state !== ROAD_STATES.IDLE) throw dialError('STATE', 'the dialer is not idle')
      to(ROAD_STATES.CHOOSING)
      const startedAt = now()
      record('hunt', { role, sessionId })

      /* ROAD 1 — DIRECT (when the adapters and the SDP both exist) */
      if (direct && offerSdp && answerSdp) {
        to(ROAD_STATES.DIRECT_PROBING)
        log('Trying the direct connection…')
        try {
          const conn = await direct.connect({ role, offerSdp, answerSdp })
          dc = conn && conn.dc ? conn.dc : null
          if (dc) {
            if (role === 'receiver') answerPings(dc)
            const proof = await proofOverChannel(dc)
            if (proof.ok) {
              to(ROAD_STATES.DIRECT_VERIFIED)
              record('direct-verified', { rttMs: proof.rttMs, elapsedMs: now() - startedAt })
              log('Direct — this network ✓')
              return { ok: true, road: 'direct', dc, proof, journal: this.journal() }
            }
            record('direct-proof-failed', { why: proof.why })
            log('The direct road did not complete its check — trying your cloud…')
            try { await direct.close() } catch { /* best effort */ }
            dc = null
          } else {
            record('direct-no-channel')
            log('The direct road did not open — trying your cloud…')
          }
        } catch (e) {
          record('direct-error', { error: String((e && e.message) || e).slice(0, 160) })
          log('The direct road did not open — trying your cloud…')
          try { await direct.close() } catch { /* best effort */ }
          dc = null
        }
      } else {
        record('direct-skipped', { why: !direct ? 'no direct adapter (the cloud-free door needs the answer SDP first)' : 'no answer SDP yet' })
      }

      /* ROAD 2 — RELAY (always first-class) */
      if (relay) {
        to(ROAD_STATES.RELAY_ESTABLISHING)
        log('Direct unavailable — sending through your cloud, still end-to-end encrypted.')
        try {
          // the round-trip proof: the first ack that comes back for THIS session
          const ackAt = now()
          const deadline = ackAt + RELAY_ACK_BUDGET_MS
          while (now() < deadline) {
            const poll = await relay.poll()
            const ack = (poll.signals || []).find((s) => s.envelope && s.envelope.kind === 'bridge-ack' && s.envelope.sessionId === sessionId)
            if (ack) {
              await relay.consume({ sessionId, signalId: ack.signalId }).catch(() => {})
              to(ROAD_STATES.RELAY_VERIFIED)
              record('relay-verified', { elapsedMs: now() - startedAt })
              log('Cloud relay ✓ — end-to-end encrypted')
              return { ok: true, road: 'relay', dc: null, journal: this.journal() }
            }
            await new Promise((r) => setTimeout(r, 300))
          }
          record('relay-ack-timeout', { budgetMs: RELAY_ACK_BUDGET_MS })
        } catch (e) {
          record('relay-error', { error: String((e && e.message) || e).slice(0, 160) })
        }
      }

      to(ROAD_STATES.UNAVAILABLE)
      const verdict = {
        ok: false,
        road: 'unavailable',
        code: 'ROAD_UNAVAILABLE',
        nextStep: 'Check that both devices are online and unlocked, then send again — the words token also works with no cloud at all.',
        journal: this.journal(),
      }
      log('Road unavailable — check that both devices are online, then send again.')
      record('unavailable', { elapsedMs: now() - startedAt })
      return verdict
    },

    /** Cancel-safe: the hunt stops, the adapters close, the state rests. */
    async close() {
      try { if (direct) await direct.close() } catch { /* already gone */ }
      dc = null
      record('closed')
      state = ROAD_STATES.IDLE
    },
  }
}
