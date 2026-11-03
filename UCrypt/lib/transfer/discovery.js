/**
 * UCrypt — R107 "Discovery That Explains Itself" — THE DISCOVERY MODEL
 * (lib/transfer/discovery.js). New in v2.65.0.
 *
 * The pure, DOM-free law layer behind the CEO's S9 order: the Direct
 * transfer page must EXPLAIN ITS OWN EMPTINESS and the manual pairing dance
 * must teach its own second leg. Everything here is a pure function of the
 * worker's truthful TRANSFER_STATUS projection — no chrome.* calls, no DOM,
 * so the battery pins every row byte-for-byte (law 0.4: the census rows and
 * the battery rows carry the same symbols).
 *
 * The S9 forensic (releases/verification/r107-discovery-explains/) proved:
 *   F-R107-DISC-1  the empty device list rendered prose only — no
 *                  preconditions, no one-click actions (the amended 0.13);
 *   F-R107-CARRY-1 the hand-carried presence carrier died at the 2-minute
 *                  cloud envelope TTL (fixed by the carrier seal);
 *   F-R107-SELF-1  opening a device's OWN signal claimed "it now appears in
 *                  the device list" (fixed by the worker's self branch).
 */

/**
 * The precondition chain the panel renders, per side, IN THIS ORDER (the
 * DOM-order law): chain → cloud → availability → devices. Every ✗ row
 * carries a typed action id the page maps to a one-click control:
 *   chain          → 'setup'    (deep-link to the sync chain setup)
 *   cloud          → 'connect'  (deep-link to the cloud transport) AND,
 *                  when no capable transport exists, 'manual' (pair by
 *                  copy/paste) — both render when rendezvous is unavailable
 *   availability   → 'arm'      (turn availability on, one click)
 *   devices        → 'pair'     (open the manual pairing dance, focus paste)
 * An ALL-GREEN row set renders the truthful idle line instead of actions.
 *
 * @param {object} st the worker's TRANSFER_STATUS response (ok:true shape)
 * @returns {{rows: Array<{id:string, ok:boolean, actions:string[], detail:string}>, allGreen:boolean}}
 */
export function discoveryModel(st) {
  const status = st || {}
  const unlocked = !!status.unlocked
  const readiness = String(status.readiness || '')
  const chainReady = !!(unlocked && (status.chainReady || readiness === 'ready' || readiness === 'enable_availability'))
  const chainOk = chainReady && readiness !== 'no_sync_code'
  const rendezvousOk = !status.rendezvous || status.rendezvous.available !== false
  const availOk = !!(status.availability && status.availability.enabled)
  const peers = Array.isArray(status.peers) ? status.peers.filter(p => p && !p.mine) : []
  const peersOk = peers.length > 0

  const rows = [
    {
      id: 'chain',
      ok: chainOk,
      actions: chainOk ? [] : ['setup'],
      detail: !unlocked
        ? 'locked'
        : (chainOk ? 'ready' : 'no_chain'),
    },
    {
      id: 'cloud',
      // R107 truth rule: while the vault is LOCKED the panel never claims a
      // healthy cloud row — the capability is real but the user cannot act
      // on it; the unlock/setup row governs. (An ✗ with no action here is
      // the locked gate's own face, never a fake ✓.)
      ok: unlocked && rendezvousOk,
      // R107: when NO capable transport exists the row is ✗ AND the honest
      // answer is BOTH "connect your cloud" (the deep link) and "pair by
      // copy/paste" (the dance that works without any cloud). The manual
      // promotion never claims the cloud is required for discovery.
      // R117 §2 (the CEO's S1/S3; law 0.29 + 0.30): the connect actions NO
      // LONGER gate behind chainOk — the cloud rendezvous is per-device
      // configuration, and the fresh profile (chainless AND cloudless) is
      // exactly where the 13-year-old user must be able to fix the row.
      // The buttons open the overlays IN PLACE; the row itself stays ✗
      // until the rendezvous is real (the truth rule is untouched).
      actions: (unlocked && !rendezvousOk) ? ['connect', 'manual'] : [],
      detail: (unlocked && rendezvousOk) ? 'ready' : (unlocked ? 'no_rendezvous' : 'gated'),
    },
    {
      id: 'availability',
      ok: availOk,
      // The armed row's one-click Stop lives in the ARM STRIP next to the
      // countdown (always visible while armed) — row actions are for ✗ rows
      // only, so an all-green board renders zero stray buttons.
      // R117 §2 (law 0.29 + 0.26): the inline fix is the ONE the row can
      // actually use — with a chain, the arm button (per-device presence,
      // works truthfully); WITHOUT a chain the arm cannot seal a presence
      // record (the keys do not exist — the worker's typed no_sync_code),
      // so the row's honest inline fix is the JOIN button: the missing
      // precondition's own fix, adjacent to the words that name it.
      actions: availOk ? [] : (unlocked ? (chainOk ? ['arm'] : ['setup']) : []),
      detail: availOk ? 'armed' : (unlocked ? (chainOk ? 'unarmed' : 'gated') : 'gated'),
    },
    {
      id: 'devices',
      ok: peersOk,
      // R117 §2 (law 0.29): with a chain the demoted manual pair renders
      // LAST with its one-line condition (the fallback path, never hidden);
      // without a chain the honest inline fix is the JOIN button — the
      // manual dance is chain-keyed, and pretending otherwise would be a
      // dead end (0.26).
      actions: peersOk ? [] : (unlocked ? (chainOk ? ['pair'] : ['setup']) : []),
      detail: peersOk ? `visible:${peers.length}` : 'none',
    },
  ]
  return { rows, allGreen: chainOk && rendezvousOk && availOk && peersOk, peers }
}

/**
 * THE AUTO-ARM LAW (2.3): the transfer window arms availability BY DEFAULT
 * the moment it opens with a ready chain — bounded (10 minutes, the same
 * window the manual button always chose), visibly counted down, one-click
 * Stop, withdrawn on close/lock (the page already owns pagehide withdrawal
 * via availabilityOwnedHere). Privacy stays honest: presence was always
 * opt-in; the WINDOW's opening is now the opt-in and the copy says so.
 * Auto-arm fires ONLY when: unlocked + the sync chain's words are present
 * (readiness 'ready' OR 'enable_availability' — the worker's arm derives the
 * chain keys lazily in both) + not already armed. A locked vault or a
 * chainless device must NEVER auto-arm.
 */
export function shouldAutoArm(st) {
  const status = st || {}
  if (!status.unlocked) return false
  const readiness = String(status.readiness || '')
  if (readiness !== 'ready' && readiness !== 'enable_availability') return false
  if (status.availability && status.availability.enabled) return false
  return true
}

/**
 * The arm countdown: truthful remaining time to the window end. Negative →
 * expired (the caller renders the truthful terminal, never a negative count).
 */
export function armCountdown(expiresAtIso, now = Date.now()) {
  const end = Date.parse(expiresAtIso)
  if (!Number.isFinite(end)) return { valid: false, expired: true, text: '' }
  const remainMs = end - now
  if (remainMs <= 0) return { valid: true, expired: true, text: '0:00' }
  const totalSec = Math.floor(remainMs / 1000)
  const mins = Math.floor(totalSec / 60)
  const secs = totalSec % 60
  return { valid: true, expired: false, mins, secs, text: `${mins}:${String(secs).padStart(2, '0')}` }
}

/**
 * F-R107-SELF-1's page-side guard: a presence record whose `from` equals
 * this device's own id is the device's OWN signal — the worker now types it
 * (self:true) and the page renders the truthful redirect instead of the old
 * false "it now appears in the device list".
 */
export function isSelfPresence(openedFrom, ownDeviceId) {
  return !!openedFrom && !!ownDeviceId && String(openedFrom) === String(ownDeviceId)
}

/**
 * The manual pairing dance — the guided two-leg state machine (the reverse
 * leg the CEO's hands proved nobody teaches). States:
 *   'idle'            nothing exchanged yet — show both steps plainly
 *   'peer-learned'    OUR window opened THEIR signal — the reverse leg is
 *                     NOW the missing precondition: highlight "Copy my
 *                     signal" with the truthful reason
 *   'self-signal'     the pasted signal was our own — redirect it
 * The state advances ONLY on real worker results (never on timers).
 */
export function manualGuidance(event) {
  switch (event) {
    case 'peer-learned':
      return {
        state: 'peer-learned',
        copyKey: 'transferManualReverseLeg',
        highlight: 'copy',
      }
    case 'self-signal':
      return {
        state: 'self-signal',
        copyKey: 'transferManualSelfSignal',
        highlight: 'copy',
      }
    default:
      return { state: 'idle', copyKey: null, highlight: null }
  }
}

/**
 * The Advanced zone promotion law (2.4), as amended by R136 (the CEO's
 * F2): the manual zone is COLLAPSED by default and PROMOTED (opened +
 * promoted copy) exactly when the chain has NO transport at all — the
 * zero-transport law's UI face. R136: a connected sync cloud (Drive OR
 * WebDAV OR Dropbox) IS the transfer relay (Beam 3 Plane B) — a healthy
 * route exists whenever ANY cloud is connected, so the promotion's old
 * "WebDAV-capable folder missing" lie is retired at the root.
 */
export function manualZonePromotion(st) {
  const status = st || {}
  const rendezvousOk = !status.rendezvous || status.rendezvous.available !== false
  if (rendezvousOk) return { promote: false, copyKey: 'transferManualHealthyRoute' }
  // R136-F2 (the CEO's evidence): the connected cloud IS the relay — a
  // connected sync transport means the route is HEALTHY (Plane B carries
  // the transfer through the user's own cloud). The zone stays collapsed;
  // the healthy-route explainer names the cloud path.
  if (status.syncTransport) return { promote: false, copyKey: 'transferManualHealthyRoute' }
  // genuinely no cloud anywhere: manual pairing is a FIRST-CLASS path
  // (R136 §5.2 Plane C) — the promotion names it as the chosen route,
  // never as a broken fallback.
  return { promote: true, copyKey: 'transferManualPromo' }
}
