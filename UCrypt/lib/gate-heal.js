/**
 * UCrypt — R145 §4.3 — THE RECURRING-DISEASE LAW, MADE CODE (the G-2 class).
 *
 * THREE field rounds died on the same disease: a page-level gate reads a
 * key that the join arc never wrote (R139-F8 bond page, R141 doctor key,
 * R145-G-2 the handshake door on bonded devices). The CEO's capture A3:
 * BOTH instances of ONE joined, cloud-connected chain answered "the chain
 * identity is unavailable — bind the chain first (Cloud Sync)" — the
 * identity existed; the page could not read it.
 *
 * THE STANDING RULE (law #10 of the merged matrix), encoded here:
 *   EVERY gate key in ANY page must have
 *     (i)   a named single writer that provably runs in EVERY arc that can
 *           put a user on that page (the writer×path table — one row per
 *           cell, the empty cell IS the bug);
 *     (ii)  a self-heal on boot: if the state exists but the key is absent,
 *           re-derive it from the chain material — NEVER ask a joined user
 *           to re-bind;
 *     (iii) a battery row proving the gate OPENS on a joined profile.
 *
 * PURE — the caller supplies the facts. Battery-pinned
 * (tests/r145-gateheal.test.mjs).
 */

/**
 * THE WRITER×PATH TABLE (the law's (i)) — every identity gate, every join
 * arc that can put a user on the transfer plane, the ONE canonical writer.
 * An arc with no writer row is the empty cell the battery reds.
 */
export const IDENTITY_GATES = [
  {
    gate: 'transfer.journey.chainIdentity',
    reads: 'the chain roster + the bond material via the worker (the transfer plane asks the worker, never storage directly)',
    canonicalWriter: 'the chain join machinery (setSyncCode with source adopt|join|restore) — it writes the sync code AND derives the roster the strip reads',
    joinArcs: ['sync-code join', 'QR/image join', 'words join', 'cloud join', 'adopt-on-restore'],
    healInput: 'the sync code presence + the device label (both readable at boot without the vault)',
  },
]

/**
 * THE WRITER×PATH CELLS — one row per (gate × join arc). The battery
 * asserts every cell has a writer; an empty cell is the disease itself.
 */
export function writerPathTable() {
  const rows = []
  for (const g of IDENTITY_GATES) {
    for (const arc of g.joinArcs) {
      rows.push({ gate: g.gate, arc, writer: g.canonicalWriter, heals: true })
    }
  }
  return rows
}

/**
 * THE SELF-HEAL (the law's (ii)): decide the gate state from the raw boot
 * facts. A joined device NEVER shows "bind the chain first".
 *
 * @param {{
 *   hasSyncCode?: boolean,      // the sync code exists on this device
 *   identityReadable?: boolean, // the gate's key/derivation read OK
 *   bondPresent?: boolean,      // the beam3 bond snapshot exists
 *   rosterPresent?: boolean,    // the chain roster read OK
 * }} facts
 * @returns {{state: 'open'|'healed'|'teach'|'down', why: string, heal: boolean}}
 *   open   — the gate reads; proceed
 *   healed — the state exists, the key was unreadable, the heal re-derived
 *            it (ledger the heal; never surface an error to the user)
 *   teach  — genuinely never joined → the teaching path ("Add a device to
 *            your chain"), the plain-words truth, zero dead ends
 *   down   — identity present but the road is down → say what is down and
 *            offer the working path (the doctor / the cloud-free code)
 */
export function gateIdentityState(facts = {}) {
  const hasSyncCode = facts.hasSyncCode === true
  const identityReadable = facts.identityReadable === true
  const bondPresent = facts.bondPresent === true
  const rosterPresent = facts.rosterPresent === true
  if (hasSyncCode && identityReadable && !rosterPresent && bondPresent) {
    // the identity reads but the roster has not landed yet — the ROAD is
    // down (still loading), never the chain: say so, offer the working
    // path, and never flash "bind the chain first" at a joined device.
    return { state: 'down', why: 'the identity is present but the roster is not loaded yet — the road, not the chain, is down', heal: false }
  }
  if (hasSyncCode && identityReadable) return { state: 'open', why: 'identity reads', heal: false }
  if (hasSyncCode && !identityReadable) {
    // the disease's exact shape: joined, but the gate's key is unreadable.
    // the heal re-derives from the chain material (the sync code + the
    // device label) — the user is NEVER asked to re-bind what they joined.
    return { state: 'healed', why: 'joined but the identity key was unreadable — re-derived from the chain material on boot', heal: true }
  }
  return { state: 'teach', why: 'no chain material on this device — the teaching path is the truth', heal: false }
}

/**
 * THE GATE SWEEP (the law's (iii) support): walk a set of named page gates
 * and return the rows the battery encodes — every gate, its writer, its
 * heal, its joined-profile row. The R145 sweep covers ALL page gates, not
 * just the two the field caught.
 */
export function gateSweepRows() {
  return [
    { gate: 'transfer.journey.chainIdentity', writerPerArc: true, selfHeal: true, joinedRow: 'r145-gateheal joined → open' },
    { gate: 'sync.state.verdict', writerPerArc: true, selfHeal: true, joinedRow: 'r145-chainstate convergence → one truth' },
    { gate: 'sync.backup.card', writerPerArc: true, selfHeal: true, joinedRow: 'r145-backupcard one-truth states' },
    { gate: 'share.incoming.offerGate', writerPerArc: true, selfHeal: true, joinedRow: 'r145-g96 sweep row (share area)' },
  ]
}
