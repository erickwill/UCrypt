/* ════════════════════════════════════════════════════════════════════════
   R158 ARC A — THE ROLE CONGRUENCE GATE (LAW #104's living instance).

   THE E-7 CURE (the CEO's verbatim spec): "The button 'The codes match'
   has to be available only for the instance receiving the file, the same
   button must to be hidden in the sender instance!"

   - On the RECEIVING instance the compare actions ("The codes match" /
     "They do not match") render ONLY while the machine is in the
     receiver's consent state — they are the accept gate that lets the
     file move. The gating itself is the FROZEN handlers' (LAW #101
     intact): the file does NOT move before the accept, DOES after it,
     does NOT on reject (the G155 triplet, unchanged).
   - On the SENDING instance the actions are HIDDEN — never merely
     disabled. The sender's card is a read-only status: the code display
     + the living role line + the security semantics of its own copy.
   - THE SENDER'S MISSING TERMINAL STATE (D-2.3b): when the receiver has
     confirmed and the bytes are moving (send.progress / proof.delivered),
     the sender's role line becomes "Matched on the other side — the file
     is moving." (mbCodeSendMatched, i18n ×3).
   - THE PAIRING CARD'S DEMOTION DURING ACTIVE TRANSFER (D-2.3a): the
     bond door collapses while a journey is active — one journey per
     screen (the 13-yo bar).

   THE LAW OF THE LAYERS: this module is Layer-2 UI logic at the
   composition edge. It READS the frozen journey machine's truth
   (window.__ucryptJourney.machine) and toggles DOM visibility only.
   It NEVER touches the wire, the handshake, the code gate's handlers,
   or a single frozen byte. FAIL-SAFE: absent machine or unknown state →
   the actions stay hidden — a button whose role is unproven never
   renders (the secure default).
   ════════════════════════════════════════════════════════════════════════ */

/** THE PURE DECISION (exported for the battery — the affordance matrix's
 * machine-checked half). Inputs: the machine state id + the panel's
 * hidden flag. Output: the affordance cells per LAW #104.
 *   actionsHidden  — the compare actions' visibility cell
 *   senderMatched  — the sender's terminal-state line cell (D-2.3b)
 *   bondDemoted    — the pairing card's demotion cell during active journeys (D-2.3a)
 */
export function roleGateDecision(state, panelHidden) {
  const s = String(state || '')
  const receiverConsent = s === 'receive.consent'
  const receiverDone = s === 'receive.saved' || s === 'receive.declined' || s === 'receive.failed'
  const senderActive = s.startsWith('send.') || s.startsWith('proof.') // proof.* IS the sender's terminal lane
  const senderMoving = s === 'send.progress' || s === 'proof.delivered'
  if (panelHidden) return { actionsHidden: true, senderMatched: false, bondDemoted: senderActive || receiverConsent || receiverDone }
  if (receiverConsent) return { actionsHidden: false, senderMatched: false, bondDemoted: true }
  if (receiverDone) return { actionsHidden: true, senderMatched: false, bondDemoted: true } // the decision is made — the affordance retires
  if (senderActive) return { actionsHidden: true, senderMatched: senderMoving, bondDemoted: true }
  return { actionsHidden: true, senderMatched: false, bondDemoted: false } // unknown/idle — the fail-safe default
}

const ACTIONS_ID = 'mbCodeActions'
const PANEL_ID = 'mbCodePanel'
const ROLE_ID = 'mbCodeRole'
const BOND_ID = 'mbBondDoor'
const MATCHED_KEY = 'mbCodeSendMatched'
const MATCHED_FALLBACK = 'Matched on the other side — the file is moving.'

function matchedLine() {
  try {
    const t = chrome.i18n && chrome.i18n.getMessage ? chrome.i18n.getMessage(MATCHED_KEY) : ''
    return t || MATCHED_FALLBACK
  } catch {
    return MATCHED_FALLBACK
  }
}

function apply() {
  const panelEl = document.getElementById(PANEL_ID)
  const actionsEl = document.getElementById(ACTIONS_ID)
  const roleEl = document.getElementById(ROLE_ID)
  const bondEl = document.getElementById(BOND_ID)
  if (!panelEl || !actionsEl) return
  const journey = (typeof window !== 'undefined') ? window.__ucryptJourney : null
  const state = journey && journey.machine && typeof journey.machine.get === 'function'
    ? String(journey.machine.get().state || '')
    : ''
  const d = roleGateDecision(state, !!panelEl.hidden)
  actionsEl.hidden = d.actionsHidden
  if (d.senderMatched && roleEl && roleEl.textContent !== matchedLine()) {
    roleEl.textContent = matchedLine()
  }
  if (bondEl && d.bondDemoted && !bondEl.hidden) {
    bondEl.hidden = true // one journey per screen — the pairing door waits
  }
}

/* the page wiring — a real DOM only (the harness imports the decision pure) */
if (typeof document !== 'undefined' && document.getElementById(PANEL_ID)) {
  const boot = () => {
    apply()
    // the frozen drivers toggle the panel + the machine moves between
    // states — re-apply on BOTH signals (belt and braces).
    const panelEl = document.getElementById(PANEL_ID)
    if (panelEl && typeof MutationObserver === 'function') {
      new MutationObserver(apply).observe(panelEl, { attributes: true, attributeFilter: ['hidden'] })
    }
    const waitForMachine = (tries) => {
      const j = window.__ucryptJourney
      if (j && j.machine && typeof j.machine.onNext === 'function') {
        try { j.machine.onNext(apply) } catch { /* the gate re-applies on the next signal */ }
        apply()
        return
      }
      if (tries > 0) setTimeout(() => waitForMachine(tries - 1), 100)
    }
    waitForMachine(300) // ~30 s cap — the frozen boot is awaited; beyond it the fail-safe holds
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
}
