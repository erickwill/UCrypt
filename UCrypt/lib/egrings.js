/**
 * UCrypt — THE EVIDENCE RING (law 0.28, R115 — the glitch hunt's founding law).
 *
 * Every network-facing flow — connect, sync, share, transfer — records its
 * attempts as TYPED rings:
 *
 *   {
 *     at:        epoch ms,
 *     flow:      'connect' | 'sync' | 'share' | 'transfer' | 'http',
 *     transport: 'gdrive' | 'github' | 'dropbox' | 'webdav' | 'custom' | 'gist' | 'bridge' | …,
 *     stage:     the flow's own stage name ('auth-window', 'code', 'exchange',
 *                'probe', 'seal', 'refresh', 'request', …),
 *     outcome:   'ok' | 'fail',
 *     httpKind:  the HTTP method or 'oauth-window' (non-HTTP stages),
 *     status:    the HTTP status or the typed failure class number | null,
 *     elapsedMs: how long the stage took,
 *     retryTier: the attempt number (0 = first attempt),
 *     error:     the TYPED error kind ('auth_window_closed', 'timeout', …),
 *     message:   the error's own words — SANITIZED (≤180 chars).
 *   }
 *
 * LAWS THIS MODULE ENFORCES BY CONSTRUCTION:
 *   - Capped: the newest RING_CAP entries live; older fall off the ring.
 *   - Local-only: chrome.storage.local under 'ucrypt:egrings' — never synced,
 *     never exported except through the diagnostics module's own renderer.
 *   - No secrets: the sanitizer strips credential-bearing query parameters
 *     (secret / client_secret / code / token / access_token / refresh_token /
 *     key / password / appSecret) from any URL-ish text; headers and bodies
 *     are NEVER recorded; the message field is capped. The diagnostics
 *     no-secrets gate extends to the rings (machine-checked every round).
 *   - No credential-bearing URLs: a URL carrying any of the parameters above
 *     renders with the parameter VALUES redacted to '…'.
 *
 * The owner's one paste names the cause: Help → Export diagnostics renders
 * the last 10 rings.
 */

const RING_KEY = 'ucrypt:egrings'
export const RING_CAP = 64
export const RING_DIAG_LIMIT = 10

/** Query parameter names whose VALUES must never reach the ring. */
const SECRET_PARAMS = new Set([
  'secret', 'client_secret', 'app_secret', 'code', 'token', 'access_token',
  'refresh_token', 'key', 'password', 'passphrase', 'sig', 'signature', 'auth',
])

/**
 * The ring sanitizer (0.28). Redacts credential-bearing query values from any
 * text, collapses control characters, caps the length. Never throws.
 */
export function sanitizeRingText(text, cap = 180) {
  let s = String(text == null ? '' : text)
  try {
    const m = s.match(/https?:\/\/[^\s"']+/g)
    if (m) {
      for (const raw of m) {
        let safe = raw
        const qi = raw.indexOf('?')
        if (qi >= 0) {
          const base = raw.slice(0, qi)
          const pairs = raw.slice(qi + 1).split('&')
          const redacted = pairs.map((p) => {
            const eq = p.indexOf('=')
            if (eq < 0) return p
            const name = p.slice(0, eq).toLowerCase()
            return SECRET_PARAMS.has(name) ? `${p.slice(0, eq)}=…` : p
          })
          safe = `${base}?${redacted.join('&')}`
        }
        if (safe !== raw) s = s.split(raw).join(safe)
      }
    }
  } catch { /* leave the text as-is if URL redaction hiccups */ }
  // R115 — the token-shape redaction: even outside a URL, a known provider
  // secret/brand shape never survives into the ring (defense in depth for
  // the no-secrets gate — the diagnostics machine-check plants these shapes
  // and asserts the export carries none).
  s = s
    .replace(/(GOCSPX-|ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_-]{6,}/g, '$1…')
    .replace(/\b(access_token|refresh_token|client_secret|app_secret|id_dQw4w9WgXcQ)\b[\s"'=:]*[A-Za-z0-9._-]{6,}/gi, '$1=…')
  return s
    // R130 (FINDING R130-F5 — the resource pass, law 0.44): the bidi/format
    // classes (Cf — RTL overrides, zero-widths, soft hyphens, BOM) used to
    // ride the sanitize — a hostile domain riding an error message could
    // visually reverse a diagnostics line. The trust boundary now strips
    // them; lawful text is untouched (additions-only hardening).
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/g, '')
    .replace(/[\u0000-\u001f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, cap)
}

/** Typed error class for a thrown value (mirrors the SyncError kinds where
 * possible; OAuth-window failures get their own typed classes). */
export function typedRingError(err) {
  if (err && typeof err === 'object') {
    if (typeof err.kind === 'string' && err.kind) return err.kind
    const msg = String(err.message || err)
    if (err.name === 'AbortError' || err.name === 'TimeoutError' || /aborted|deadline/i.test(msg)) return 'timeout'
    if (/message port closed|receiving end|context invalidated/i.test(msg)) return 'worker_port_closed'
    if (/another.*(flow|auth).*pending|already.*(pending|progress)/i.test(msg)) return 'auth_flow_pending'
    if (/could not be loaded|cancelled|canceled|user (closed|cancelled|denied)/i.test(msg)) return 'auth_window_closed'
    return 'error'
  }
  return String(err || 'error').slice(0, 60) || 'error'
}

// --- Storage indirections (the battery mocks these) -------------------------

async function ringGet() {
  try {
    const r = await chrome.storage.local.get(RING_KEY)
    const v = r && r[RING_KEY]
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}

async function ringSet(rings) {
  try {
    await chrome.storage.local.set({ [RING_KEY]: rings })
  } catch { /* the ring never throws into its caller */ }
}

let _memRings = null // battery seam: when the storage shim is absent (node), rings ride memory
let _ringWriteChain = Promise.resolve() // R119: the ring writes serialize (one read-modify-write at a time)

/**
 * Record ONE ring entry. Fire-and-forget by design — a recording failure must
 * never perturb the flow it observes. Returns the entry that was recorded
 * (post-sanitize) for the battery to assert on.
 */
export async function recordRing(entry) {
  const rec = {
    at: Number.isFinite(entry && entry.at) ? entry.at : Date.now(),
    flow: String((entry && entry.flow) || 'http').slice(0, 24),
    transport: String((entry && entry.transport) || '').slice(0, 24),
    stage: String((entry && entry.stage) || '').slice(0, 32),
    outcome: (entry && entry.outcome) === 'ok' ? 'ok' : 'fail',
    httpKind: String((entry && entry.httpKind) || '').slice(0, 24),
    status: Number.isFinite(entry && entry.status) ? entry.status : null,
    elapsedMs: Number.isFinite(entry && entry.elapsedMs) ? Math.max(0, Math.round(entry.elapsedMs)) : null,
    retryTier: Number.isFinite(entry && entry.retryTier) ? Math.max(0, entry.retryTier) : 0,
    error: String((entry && entry.error) || '').slice(0, 48),
    message: sanitizeRingText(entry && entry.message),
  }
  // R119 (law 0.32/0.28) — THE RUNG RIDES THE RING: every ladder flow names
  // its rung ('fast' | 'guided' | 'manual') so the owner's diagnostics paste
  // names the rung AND the stage. Empty (non-ladder flows) stays empty — the
  // schema is additions-only, the pre-ladder rings render unchanged.
  const rung = String((entry && entry.rung) || '').slice(0, 12)
  if (rung) rec.rung = rung
  // R119 (the live proof's finding) — the writes SERIALIZE: two fire-and-
  // forget records racing (the rung row then the seal row) each read-modify-
  // wrote the storage and the LAST writer won — the earlier row was lost.
  // One chained writer keeps every row (the fire-and-forget contract and the
  // never-throws law unchanged).
  const run = _ringWriteChain.then(async () => {
    try {
      const rings = _memRings !== null ? _memRings : await ringGet()
      rings.push(rec)
      while (rings.length > RING_CAP) rings.shift() // capped — the newest live
      _memRings = rings
      await ringSet(rings)
    } catch { /* never throws into its caller */ }
    return rec
  })
  _ringWriteChain = run.catch(() => { /* the chain never breaks */ })
  return run
}

/**
 * Read the ring, newest LAST (chronological). `filter` matches on the flow
 * and/or transport fields when given.
 */
export async function recentRings({ flow, transport, limit } = {}) {
  let rings = _memRings !== null ? _memRings : await ringGet()
  if (flow) rings = rings.filter((r) => r.flow === flow)
  if (transport) rings = rings.filter((r) => r.transport === transport)
  if (limit && Number.isFinite(limit) && limit > 0) rings = rings.slice(-limit)
  return rings
}

/** The diagnostics renderer's slice: the last RING_DIAG_LIMIT rings. */
export async function diagnosticsRings() {
  return recentRings({ limit: RING_DIAG_LIMIT })
}

/** Test/reset seam. */
export async function _resetRingsForTest() {
  _memRings = []
  try { await chrome.storage.local.remove(RING_KEY) } catch { /* node shim */ }
}
