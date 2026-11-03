/**
 * UCrypt — R146 §7.1 — THE DIRECT ROAD RECORD (H-3, the clinical record).
 *
 * The beam transport's honest confession, now with evidence: every failed
 * direct attempt records WHAT the road reached (the ICE state, the candidate
 * pairs tried, whether a TURN relay agreed, the failure class, when) so the
 * doctor prints WHY in plain words — never a bare "did not connect".
 *
 * Pure classification + a storage-backed record (injectable for the battery;
 * chrome.storage.session at runtime — session-scoped, never persisted to
 * disk, never leaves the device, no secrets inside: topology facts only).
 */

export const ROAD_CLASSES = {
  'no-route': 'No direct route — the devices could not agree on a path to each other.',
  'symmetric-nat': 'No direct route — both devices sit behind symmetric NATs, and no relay agreed to help.',
  'no-turn': 'No direct route — the devices could reach the helper (STUN) but no relay (TURN) was available to carry them.',
  'timeout': 'No direct route — the handshake took too long and was abandoned before a path opened.',
  'closed': 'No direct route — the other device closed its side before the road opened.',
  'unknown': 'No direct route — the attempt ended without a readable reason.',
}

/** The failure class from the attempt's own facts (pure, exhaustive — every
 * record lands in a named class; the doctor never prints a bare code). */
export function classifyRoadFailure(record = {}) {
  const ice = String(record.iceState || record.ice || '').toLowerCase()
  const pairs = Number(record.pairsTried) || 0
  const turn = !!(record.turnAgreed || record.relayAgreed)
  const bothNat = !!(record.symmetricNat || (record.natType === 'symmetric'))
  const lastErr = String(record.lastError || '').toLowerCase()
  if (ice === 'failed' && turn) return { klass: 'no-route', line: ROAD_CLASSES['no-route'] }
  if (bothNat && !turn) return { klass: 'symmetric-nat', line: ROAD_CLASSES['symmetric-nat'] }
  if (ice === 'failed' && !turn && pairs > 0) return { klass: 'no-turn', line: ROAD_CLASSES['no-turn'] }
  if (ice === 'closed' || lastErr.includes('closed')) return { klass: 'closed', line: ROAD_CLASSES['closed'] }
  if (ice === 'checking' || lastErr.includes('timeout') || lastErr.includes('timed out')) return { klass: 'timeout', line: ROAD_CLASSES['timeout'] }
  if (ice === 'failed') return { klass: 'unknown', line: ROAD_CLASSES['unknown'] }
  if (lastErr) return { klass: 'unknown', line: ROAD_CLASSES['unknown'] }
  return { klass: 'unknown', line: ROAD_CLASSES['unknown'] }
}

/** The doctor's road hop — plain words + the one action, ready to render. */
export function roadHop(record) {
  if (!record) return null
  const { klass, line } = classifyRoadFailure(record)
  const when = record.at ? new Date(Number(record.at)).toLocaleString() : ''
  return {
    ok: false,
    hop: 'Direct road',
    line: when ? `${line} (last attempt ${when})` : line,
    actionLine: 'The file still arrives — the cloud path carried it. Direct retries on its own.',
    klass,
  }
}

const ROAD_KEY = 'ucrypt:roadRecord:last'

/** Record one attempt (fire-and-forget at the call site; never throws). */
export async function recordRoadAttempt(storage, record) {
  try {
    if (!storage || !storage.session || !storage.session.set) return false
    const clean = {
      iceState: String(record.iceState || record.ice || '').slice(0, 32),
      pairsTried: Number(record.pairsTried) || 0,
      turnAgreed: !!record.turnAgreed,
      symmetricNat: !!record.symmetricNat,
      lastError: String(record.lastError || '').slice(0, 200),
      at: Number(record.at) || Date.now(),
    }
    await storage.session.set({ [ROAD_KEY]: clean })
    return true
  } catch { return false }
}

/** The last attempt's record (null when none — the doctor omits the hop). */
export async function lastRoadRecord(storage) {
  try {
    if (!storage || !storage.session || !storage.session.get) return null
    const got = await storage.session.get(ROAD_KEY)
    const rec = got && got[ROAD_KEY]
    return rec && typeof rec === 'object' ? rec : null
  } catch { return null }
}
