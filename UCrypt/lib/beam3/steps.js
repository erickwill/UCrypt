/**
 * UCrypt — R136 §6 — THE GUIDED WORKFLOW ("step evidence"). The Chief
 * Executive's annotations define the interaction contract and this module
 * is its engine:
 *
 *   INTENT → READINESS → PAIR → CONFIRM → TRANSFER → VERIFY → DONE
 *
 *   - exactly ONE active step at any moment, rendered as the prominent
 *     card (the accent treatment);
 *   - prior steps collapse as DONE (their summary line stays);
 *   - future steps are DIMMED (visible, inert);
 *   - steps advance BY COMPLETION, never by timers (the popup law —
 *     nothing advances, opens, or dismisses itself);
 *   - the fallback manual path is a first-class route: when chosen, its
 *     steps ARE the main flow (never a collapsed "fallback" among equals).
 *
 * PURE — battery-pinned (TRF-STEPS-*, G73/G74).
 */

/** The ordered steps (the evidence ladder). */
export const WORKFLOW_STEPS = ['INTENT', 'READINESS', 'PAIR', 'CONFIRM', 'TRANSFER', 'VERIFY', 'DONE']

/** The typed workflow events (completion facts, not timers). */
export const WORKFLOW_EVENTS = {
  INTENT_DECLARED: 'INTENT_DECLARED', // Send or Receive pressed (auto-arm rides this)
  READINESS_RESOLVED: 'READINESS_RESOLVED', // the strip is green (or the user chose manual)
  SIGNAL_COPIED: 'SIGNAL_COPIED', // Step 1 done: my signal is on the clipboard
  PEER_SIGNAL_OPENED: 'PEER_SIGNAL_OPENED', // Step 2 done: their signal opened → PAIRED
  CODE_CONFIRMED: 'CODE_CONFIRMED', // Step 3 done: the both-screens code matched
  DEVICE_CHOSEN: 'DEVICE_CHOSEN', // roster pick (when more than one device is visible)
  FILE_CHOSEN: 'FILE_CHOSEN', // sender: the file picker resolved
  OFFER_ACCEPTED: 'OFFER_ACCEPTED', // receiver: Accept pressed on the offer card
  TRANSFER_COMPLETE: 'TRANSFER_COMPLETE', // chunks done
  VERIFIED: 'VERIFIED', // the digest verified
  RESET: 'RESET',
}

/** The completion event each step waits for. */
const STEP_COMPLETION = {
  INTENT: WORKFLOW_EVENTS.INTENT_DECLARED,
  READINESS: WORKFLOW_EVENTS.READINESS_RESOLVED,
  PAIR: WORKFLOW_EVENTS.PEER_SIGNAL_OPENED,
  CONFIRM: WORKFLOW_EVENTS.CODE_CONFIRMED,
  TRANSFER: WORKFLOW_EVENTS.TRANSFER_COMPLETE,
  VERIFY: WORKFLOW_EVENTS.VERIFIED,
  DONE: null,
}

/** The typed workflow error. */
export function workflowError(code, detail) {
  const e = new Error(`BEAM3_WORKFLOW_${code}: ${detail}`)
  e.code = `BEAM3_WORKFLOW_${code}`
  return e
}

/**
 * A fresh workflow. `route` names the chosen path: 'auto' (the planes
 * decide) or 'manual' (the first-class manual route — its PAIR step is
 * "copy/paste the signal", promoted INTO the main flow per R136-F6).
 */
export function newWorkflow({ role = 'send', route = 'auto' } = {}) {
  if (!['send', 'receive'].includes(role)) throw workflowError('ROLE', 'role must be send|receive')
  if (!['auto', 'manual'].includes(route)) throw workflowError('ROUTE', 'route must be auto|manual')
  return { role, route, active: 'INTENT', done: [], history: [] }
}

/**
 * The pure advance. The event completes the ACTIVE step (or is a no-op
 * recorded in history when it belongs to a later step). Illegal events
 * THROW — the workflow never bends silently.
 * @returns {{active:string, done:string[], advanced:boolean}}
 */
export function advanceWorkflow(wf, event) {
  if (!wf || !WORKFLOW_STEPS.includes(wf.active)) throw workflowError('STATE', 'workflow corrupt')
  if (event === WORKFLOW_EVENTS.RESET) return newWorkflow({ role: wf.role, route: wf.route })
  const expected = STEP_COMPLETION[wf.active]
  if (!expected) {
    // DONE is absorbing
    return { ...wf, history: [...wf.history, { event, at: Date.now(), effect: 'absorbed' }] }
  }
  if (event !== expected) {
    // an event belonging to a LATER step is recorded, never applied
    const laterIdx = Object.values(STEP_COMPLETION).indexOf(event)
    const activeIdx = WORKFLOW_STEPS.indexOf(wf.active)
    if (laterIdx > activeIdx) return { ...wf, history: [...wf.history, { event, at: Date.now(), effect: 'recorded' }] }
    throw workflowError('EVENT', `${event} cannot complete ${wf.active}`)
  }
  const done = [...wf.done, wf.active]
  const nextIdx = WORKFLOW_STEPS.indexOf(wf.active) + 1
  return {
    ...wf,
    active: WORKFLOW_STEPS[nextIdx] || 'DONE',
    done,
    history: [...wf.history, { event, at: Date.now(), effect: 'advanced' }],
  }
}

/**
 * The render model for the step cards (the UI's one active / done-collapsed
 * / dimmed-future contract):
 * @returns {Array<{step:string, state:'active'|'done'|'dimmed', captionKey:string}>}
 */
export function workflowView(wf) {
  const idx = WORKFLOW_STEPS.indexOf(wf.active)
  return WORKFLOW_STEPS.map((s, i) => ({
    step: s,
    state: i < idx ? 'done' : i === idx ? 'active' : 'dimmed',
    captionKey: `beam3Step_${s}`,
  }))
}

/**
 * The PAIR step's caption depends on the route (the manual route's Step 1
 * is copy/paste — the CEO's annotation 3: "Step 1 — Copy your signal has
 * to be brought in evidence for the next steps").
 */
export function pairStepCaption(route) {
  return route === 'manual'
    ? { key: 'beam3PairStepManual', fallback: 'Step 1 — copy your signal and share it; Step 2 — paste theirs and press Open' }
    : { key: 'beam3PairStepAuto', fallback: 'Devices discover each other on your chain — confirm the code when it appears' }
}
