/**
 * UCrypt — R147 §5.5 — THE ROAD BADGE (lib/road/badge.js — LAW #70).
 *
 * A badge may only name a road that is ESTABLISHED AND VERIFIED (post
 * ping-pong / post ack). Before establishment: "Choosing the road…".
 * Direct, verified: "Direct — this network ✓". Relay, verified:
 * "Cloud relay ✓ — end-to-end encrypted". Any failure: "Road unavailable —
 * [typed reason]". The badge NEVER reports intent as fact (the J-8 cure —
 * capture A2's badge said "Direct — this network" while nothing was
 * established).
 *
 * PURE — the state machine + the words live here; the DOM writer is the
 * page module (ONE writer). Battery: tests/road/r147-badge.test.mjs.
 */

/** The typed badge states (the ONLY states this namespace can emit). */
export const BADGE_STATES = Object.freeze({
  HIDDEN: 'hidden',                 // no active session — the badge rests
  CHOOSING: 'choosing',             // a session opened; no road established yet
  DIRECT_VERIFIED: 'direct',        // ping→pong crossed the channel
  RELAY_VERIFIED: 'relay',          // the first round-trip envelope acked
  UNAVAILABLE: 'unavailable',       // both roads failed — typed reason attached
})

/** The plain words per state (the §5.5 law's exact copy). */
export const BADGE_COPY = Object.freeze({
  hidden: '',
  choosing: 'Choosing the road…',
  direct: 'Direct — this network ✓',
  relay: 'Cloud relay ✓ — end-to-end encrypted',
  unavailable: 'Road unavailable',
})

/** The legal transitions (the truth law, as a machine):
 *  intent (CHOOSING) may only become a VERIFIED state or UNAVAILABLE —
 *  a badge may never jump to a named road before its proof arrived. */
const LEGAL = {
  [BADGE_STATES.HIDDEN]: [BADGE_STATES.CHOOSING],
  [BADGE_STATES.CHOOSING]: [BADGE_STATES.DIRECT_VERIFIED, BADGE_STATES.RELAY_VERIFIED, BADGE_STATES.UNAVAILABLE, BADGE_STATES.HIDDEN],
  [BADGE_STATES.DIRECT_VERIFIED]: [BADGE_STATES.RELAY_VERIFIED, BADGE_STATES.UNAVAILABLE, BADGE_STATES.HIDDEN], // demotion is legal — announced
  [BADGE_STATES.RELAY_VERIFIED]: [BADGE_STATES.UNAVAILABLE, BADGE_STATES.HIDDEN],
  [BADGE_STATES.UNAVAILABLE]: [BADGE_STATES.HIDDEN],
}

/** Create the badge machine (pure — no DOM). */
export function createRoadBadge(initial = BADGE_STATES.HIDDEN) {
  let state = initial
  let reason = ''
  return {
    get state() { return state },
    get reason() { return reason },
    /** Dispatch a transition; illegal jumps throw (the truth law is enforced,
     *  not advisory). A same-state dispatch is a no-op (idempotent render). */
    to(next, { reason: why = '' } = {}) {
      if (!Object.values(BADGE_STATES).includes(next)) throw new Error(`road badge: unknown state ${String(next)}`)
      if (next === state) return state
      if (!LEGAL[state].includes(next)) {
        throw new Error(`road badge: the truth law forbids ${state} → ${next} (intent is never reported as fact)`)
      }
      state = next
      reason = next === BADGE_STATES.UNAVAILABLE ? String(why || 'no reason given') : ''
      return state
    },
    /** The words the page renders (one writer reads this). */
    line() {
      if (state === BADGE_STATES.UNAVAILABLE) return `${BADGE_COPY.unavailable} — ${reason}`
      return BADGE_COPY[state]
    },
    /** The css class (the page maps it to the token colors). */
    cssClass() {
      return state === BADGE_STATES.DIRECT_VERIFIED ? 'road-badge road-direct'
        : state === BADGE_STATES.RELAY_VERIFIED ? 'road-badge road-relay'
        : state === BADGE_STATES.UNAVAILABLE ? 'road-badge road-failed'
        : 'road-badge'
    },
    visible() {
      return state !== BADGE_STATES.HIDDEN
    },
  }
}
