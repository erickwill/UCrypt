/**
 * UCrypt — R136 §3 (R136-F1) — THE SINGLE-USE NONCE LEDGER ("signals live
 * until consumed or 24 hours; replayed or duplicated signals are refused
 * through the single-use nonce ledger").
 *
 * Every Beam 3 signal (the manual code, the relay offer, the Plane A
 * handshake) carries a nonce. The ledger:
 *   - consumes a nonce exactly once (the second consume is a typed REPLAY);
 *   - records every attempt (consumed + replayed) with its outcome — the
 *     replay attempt is VISIBLE, never a silent swallow;
 *   - expires entries at the signal's 24-hour horizon (a nonce whose signal
 *     expired cannot be consumed — the typed EXPIRED terminal);
 *   - stays bounded (the ring cap — the storage law).
 *
 * PURE — the store is injected ({get,set}); battery-pinned (TRF-NONCE-*,
 * S5).
 */

/** The storage key (chrome.storage.local in production). */
export const BEAM3_NONCE_LEDGER_KEY = 'ucrypt:beam3:nonceLedger'

/** The ledger ring cap (entries). */
export const NONCE_LEDGER_CAP = 512

/** The typed nonce error. */
export function nonceError(code, detail) {
  const e = new Error(`BEAM3_NONCE_${code}: ${detail}`)
  e.code = `BEAM3_NONCE_${code}`
  return e
}

/** A fresh 128-bit nonce, hex (the signal's single-use identity). */
export function freshNonce() {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('')
}

/** Load the ledger (injected store; missing → empty). */
export async function loadLedger(store) {
  const v = await store.get(BEAM3_NONCE_LEDGER_KEY)
  return v && typeof v === 'object' ? v : { entries: {}, attempts: [] }
}

/** Persist within the ring cap (oldest attempts drop first). */
async function persist(store, ledger) {
  if (Array.isArray(ledger.attempts) && ledger.attempts.length > NONCE_LEDGER_CAP) {
    ledger.attempts = ledger.attempts.slice(ledger.attempts.length - NONCE_LEDGER_CAP)
  }
  await store.set(BEAM3_NONCE_LEDGER_KEY, ledger)
}

/**
 * CONSUME a nonce: exactly one success per nonce, ever.
 * @returns {{ok:true}} on first consume
 * @returns {{ok:false, reason:'replay', consumedAt:number}} on re-use
 * @returns {{ok:false, reason:'expired', expiresAt:number}} past the 24h horizon
 */
export async function consumeNonce(store, nonce, { now = Date.now(), ttlMs = 24 * 60 * 60 * 1000, issuedAt = 0 } = {}) {
  const n = String(nonce || '')
  if (!/^[0-9a-f]{32}$/.test(n)) throw nonceError('SHAPE', 'the nonce is not a 32-hex value')
  const ledger = await loadLedger(store)
  const entry = ledger.entries[n]
  const consumed = !!(entry && Number(entry.consumedAt) > 0)
  if (consumed) {
    ledger.attempts.push({ nonce: n, outcome: 'replay', at: now })
    await persist(store, ledger)
    return { ok: false, reason: 'replay', consumedAt: entry.consumedAt }
  }
  // issuance metadata rides the ledger when the issuer registered it
  // (issueNonce) — a consumer-only ledger anchors the horizon at first
  // touch (the skew-safe pattern from Beam 2's TTL law).
  const issued = Number(issuedAt) || Number(entry && entry.issuedAt) || now
  if (now - issued > ttlMs) {
    ledger.attempts.push({ nonce: n, outcome: 'expired', at: now })
    await persist(store, ledger)
    return { ok: false, reason: 'expired', expiresAt: issued + ttlMs }
  }
  ledger.entries[n] = { consumedAt: now, issuedAt: issued }
  ledger.attempts.push({ nonce: n, outcome: 'consumed', at: now })
  await persist(store, ledger)
  return { ok: true }
}

/**
 * ISSUE a nonce into the ledger (the sender registers the fresh signal so
 * the horizon is anchored even if the consumer's clock differs — the
 * skew-safe pattern from Beam 2's TTL law).
 */
export async function issueNonce(store, nonce, { now = Date.now() } = {}) {
  const n = String(nonce || '')
  if (!/^[0-9a-f]{32}$/.test(n)) throw nonceError('SHAPE', 'the nonce is not a 32-hex value')
  const ledger = await loadLedger(store)
  if (!ledger.entries[n]) {
    ledger.entries[n] = { issuedAt: now, consumedAt: 0 }
    await persist(store, ledger)
  }
  return { nonce: n, issuedAt: ledger.entries[n].issuedAt }
}

/**
 * The ledger sweep — drop consumed entries older than the horizon (the
 * bounded-memory rule; the attempts ring self-caps).
 */
export async function sweepLedger(store, { now = Date.now(), retentionMs = 25 * 60 * 60 * 1000 } = {}) {
  const ledger = await loadLedger(store)
  let removed = 0
  for (const [n, e] of Object.entries(ledger.entries)) {
    const lastTouch = Math.max(Number(e.issuedAt) || 0, Number(e.consumedAt) || 0)
    if (now - lastTouch > retentionMs) {
      delete ledger.entries[n]
      removed += 1
    }
  }
  await persist(store, ledger)
  return { removed }
}

/** Read-only: has this nonce been consumed? (the UI's replay diagnostics) */
export async function isConsumed(store, nonce) {
  const ledger = await loadLedger(store)
  const e = ledger.entries[String(nonce || '')]
  return !!e && Number(e.consumedAt) > 0
}

/** Read-only: the attempt ring (the replay evidence for the round record). */
export async function attemptRing(store) {
  const ledger = await loadLedger(store)
  return Array.isArray(ledger.attempts) ? ledger.attempts.slice() : []
}
