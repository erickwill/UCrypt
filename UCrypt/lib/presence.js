/**
 * UCrypt — R132 §2.1 — LAW 0.46: THE PRESENCE-HONESTY LAW (the CEO's S1).
 *
 * WHAT THE KING SAW: a device that was online — its browser open, its window
 * in front of him — rendered as "offline — last synced via cloud (45s ago)"
 * on the freshly joined instance's roster. The lie: the roster conflated
 * "no rendezvous exists on this transport" (it cannot know) with "the
 * rendezvous says the device is gone" (it knows it is offline).
 *
 * THE LAW: the roster's online/offline annotation is TRUTHFUL about what it
 * KNOWS — three states, derived from the transport's rendezvous capability
 * (the R127 S1 derivation), never a blanket "offline" for the undetectable:
 *
 *   1. ONLINE     — the rendezvous CONFIRMS the device is advertising now.
 *   2. OFFLINE    — the rendezvous EXISTS and says the device is not
 *                   advertising: a truthful offline, annotated with the
 *                   last-seen time.
 *   3. UNKNOWN    — this transport carries NO live presence at all (the
 *                   rendezvous capability is absent): "Online status unknown
 *                   — this chain's cloud doesn't support live presence — last
 *                   synced N ago." The last-sync timestamp is the honest
 *                   proxy. An online device is NEVER displayed as offline.
 *
 * PURE — no DOM, no chrome.*, no imports: the battery pins every branch
 * (the same discipline as rosterVisibilityState). Both rosters render from
 * this one law: the options page's device list AND the transfer page's peer
 * picker — one truth, two surfaces.
 */

export const PRESENCE_STATES = { ONLINE: 'online', OFFLINE: 'offline', UNKNOWN: 'unknown' }

/**
 * Derive the honest presence annotation for ONE roster row.
 * @param {{online?:boolean, syncAt?:number, lastSeen?:number}|null} peer the roster projection row
 * @param {{rendezvousAvailable?:boolean, fmtRelative?:(ms:number)=>string}} cap
 *        cap.rendezvousAvailable — the transport's rendezvous capability
 *        (worker statusMessage → status.rendezvous.available); when the
 *        capability is unavailable/absent the law reads UNKNOWN (never a
 *        fabricated offline).
 * @returns {{state:'online'|'offline'|'unknown', key:string, args:string[], fallback:string}}
 */
export function presenceAnnotation(peer, cap = {}) {
  const fmt = typeof cap.fmtRelative === 'function' ? cap.fmtRelative : (ms) => String(ms)
  const online = !!(peer && peer.online)
  if (online) {
    // State 1 — the rendezvous confirms it. (The self row never reaches this
    // module: the roster renders "(this device)" for itself by law.)
    return { state: PRESENCE_STATES.ONLINE, key: 'deviceListActiveNow', args: [], fallback: 'available now' }
  }
  if (cap.rendezvousAvailable) {
    // State 2 — the rendezvous EXISTS and says the device is not advertising:
    // a truthful offline, annotated with the last-seen time it knows.
    const lastSeen = Number(peer && peer.lastSeen) || 0
    const t = fmt(lastSeen)
    return { state: PRESENCE_STATES.OFFLINE, key: 'deviceListLastSeen', args: [t], fallback: `offline — last seen ${t}` }
  }
  // State 3 — no live presence on this transport (Google Drive / Dropbox /
  // GitHub / Custom / any capability-less cloud): the honest unknown, with
  // the last-sync stamp as the proxy. Never "offline".
  const syncAt = Number(peer && peer.syncAt) || 0
  const lastSeen = Number(peer && peer.lastSeen) || 0
  const at = syncAt || lastSeen
  if (!at) {
    return {
      state: PRESENCE_STATES.UNKNOWN,
      key: 'deviceListPresenceUnknownBare',
      args: [],
      fallback: 'online status unknown — this chain\'s cloud doesn\'t support live presence',
    }
  }
  const t = fmt(at)
  return {
    state: PRESENCE_STATES.UNKNOWN,
    key: 'deviceListPresenceUnknown',
    args: [t],
    fallback: `online status unknown — this chain's cloud doesn't support live presence — last synced ${t}`,
  }
}

/**
 * The roster row's badge class for the annotation (both themes render from
 * the same variable system): online = the ok tone, offline = the muted tone,
 * unknown = the neutral-help tone (a datum, not an alarm).
 */
export function presenceTone(state) {
  switch (state) {
    case PRESENCE_STATES.ONLINE: return 'ok'
    case PRESENCE_STATES.OFFLINE: return 'muted'
    default: return 'help'
  }
}
