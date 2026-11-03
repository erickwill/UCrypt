/**
 * UCrypt — R150 §5 — THE LANDING CEREMONY (lib/road/landing.js).
 *
 * THE ROUND'S DECISIVE DEFECT (field capture B2, hash-pinned): "The transfer
 * file process worked until it arrived in the destination instance browser,
 * that keeps hanging on 'Receiving the file 100%' but doesn't save the file!"
 * The autopsy pinned the root: no 'downloads' permission (chrome.downloads is
 * UNDEFINED in the MV3 service worker, so the SW-side saver always failed)
 * and the receiver's failed landing was DROPPED SILENTLY — the bar sat at
 * 100% forever with zero output.
 *
 * THE CURES THIS MODULE CARRIES (LAW #80 — THE LANDING):
 *   Cure A — THE SAVER LIVES WHERE THE BYTES LIVE: the receiver's pump
 *     assembles the bytes IN THE TRANSFER PAGE, so the page saves them:
 *     bytesB64 → Blob → objectURL → chrome.downloads.download (the
 *     permission exists now). The SW door (BRIDGE_DELIVER_FILE) stays as a
 *     TYPED FALLBACK honoring {ok:true} | {ok:false, reason}.
 *   Cure A — the collision policy is OBSERVABLE: the next free
 *     "name (2).ext" suffix is computed from the names the download API
 *     actually reports; the arrival card states the policy and renders the
 *     SAVED name (the observed truth), never the requested one.
 *   Cure B — THE LANDING WATCHDOG: at 100% (or any pump stall) a 15-second
 *     budget; if the ceremony has not completed, the state resolves TYPED —
 *     AWAITING_FINAL_ACK / HASH_MISMATCH / SAVE_FAILED:<reason> /
 *     AWAITING_ACCEPT / EXPIRED — each with its ONE-button path. A stuck
 *     "Receiving the file… 100%" past 15 s is structurally impossible.
 *   Cure D — the resume lineage's honest state helper: a basket older than
 *     the pump's 10-minute window is EXPIRED (typed) — "the sender can send
 *     again; nothing partial is kept silently".
 *
 * PURE — no DOM; the downloads API, the Blob/URL doors and the clock are
 * injected. Battery: tests/r150-landing.test.mjs.
 */

/* ── the typed verdicts (the watchdog's vocabulary — ONE map) ─────────────── */

export const LANDING_WATCHDOG_MS = 15 * 1000

export const LANDING_PHASES = Object.freeze({
  ACCEPT: 'accept',     // the Accept door is open (Cure C) — no answer yet
  PROGRESS: 'progress', // bytes were moving; a stall would fire here
  VERIFY: 'verify',     // 100% — between the last chunk and the hash check
})

/** The verdict map: every code carries its line and its ONE-button path. */
export function landingVerdict(code, detail = '') {
  const d = String(detail || '').slice(0, 120)
  switch (code) {
    case 'AWAITING_ACCEPT':
      return { code, typed: true, line: 'Waiting for your Accept — nothing is saved until you accept.', actionKey: 'accept', actionLine: 'Accept now' }
    case 'AWAITING_FINAL_ACK':
      return { code, typed: true, line: 'The byte stream stalled — the last chunk was not confirmed.', actionKey: 're-request', actionLine: 'Re-request the last chunk' }
    case 'HASH_MISMATCH':
      return { code, typed: true, line: 'The copy arrived damaged (hash mismatch) — nothing was saved.', actionKey: 'try-again', actionLine: 'Try again' }
    case 'SAVE_FAILED':
      return { code, typed: true, line: `The file verified but the save failed${d ? ' — ' + d : ''}.`, actionKey: 'retry-save', actionLine: 'Retry save' }
    case 'EXPIRED':
      return { code, typed: true, line: 'The resume window closed — the sender can send again; nothing partial is kept silently.', actionKey: 'try-again', actionLine: 'Try again' }
    case 'DECLINED':
      return { code, typed: true, line: 'Declined — nothing was saved; the sender was told.', actionKey: 'try-again', actionLine: 'Try again' }
    case 'RECEIVE_TIMEOUT':
      return { code, typed: true, line: 'The transfer stalled — the sender can send again; the watermark holds for 10 minutes.', actionKey: 'try-again', actionLine: 'Try again' }
    default:
      return { code: String(code || 'UNKNOWN'), typed: true, line: d || 'The landing did not complete — the sender can send again.', actionKey: 'try-again', actionLine: 'Try again' }
  }
}

/** Map a pump/receiver code onto the verdict vocabulary (the honest aliasing):
 *  the pump's CORRUPT_ARRIVAL IS the hash mismatch (surface it, Cure B). */
export function verdictCodeFor(rawCode) {
  const c = String(rawCode || '')
  if (c === 'CORRUPT_ARRIVAL') return 'HASH_MISMATCH'
  if (c === 'LAND_FAILED' || c.startsWith('SAVE_FAILED')) return 'SAVE_FAILED'
  return c
}

/* ── Cure B — the landing watchdog (pure, injectable clock) ───────────────── */

export function createLandingWatchdog({ budgetMs = LANDING_WATCHDOG_MS, now = () => Date.now() } = {}) {
  let phase = null
  let armedAt = 0
  let resolved = null
  return {
    /** Arm (or re-arm) the budget at a phase; a resolve clears it.
     *  R150 battery fix: the membership check is by VALUE ('accept'/'progress'
     *  /'verify') — the old key lookup (LANDING_PHASES['accept']) was always
     *  undefined and silently demoted every phase to PROGRESS. */
    arm(p) {
      phase = Object.values(LANDING_PHASES).includes(p) ? p : LANDING_PHASES.PROGRESS
      armedAt = now()
      resolved = null
    },
    /** A live byte keeps the current phase's budget alive. */
    touch() { if (phase) armedAt = now() },
    /** The ceremony completed — the budget is retired (never fires after). */
    resolve(result) { if (!resolved) resolved = result || { ok: true } },
    get resolved() { return !!resolved },
    phaseName() { return phase },
    /** The typed verdict when the budget expired without a resolution. */
    expired() {
      if (resolved || !phase) return null
      if (now() - armedAt < budgetMs) return null
      return phase === LANDING_PHASES.ACCEPT
        ? landingVerdict('AWAITING_ACCEPT')
        : landingVerdict('AWAITING_FINAL_ACK')
    },
  }
}

/* ── Cure A — the filename laws (pure) ─────────────────────────────────────── */

/** The download-safe name (the SW saver's character vocabulary, kept). */
export function sanitizeDownloadName(name) {
  const s = String(name || '').replace(/[\\/:*?"<>|]/g, '_').replace(/^\.+/, '').trim()
  return s || 'received-file'
}

/** The path's basename (the download API reports full paths). */
export function baseNameOf(p) {
  const s = String(p || '')
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  return i >= 0 ? s.slice(i + 1) : s
}

/** THE COLLISION POLICY ("name (2).ext"): the next free suffix computed from
 *  the names the download attempt can observe. The FIRST free candidate wins;
 *  the original name is free → untouched. Case-insensitive (the Windows law). */
export function nextFreeName(name, taken = [], { startAt = 2 } = {}) {
  const n = sanitizeDownloadName(name)
  const low = (x) => String(x).toLowerCase()
  const takenLow = new Set((taken || []).map(low))
  if (!takenLow.has(low(n))) return n
  const dot = n.lastIndexOf('.')
  const stem = dot > 0 ? n.slice(0, dot) : n
  const ext = dot > 0 ? n.slice(dot) : ''
  for (let k = startAt; k < startAt + 1000; k++) {
    const cand = `${stem} (${k})${ext}`
    if (!takenLow.has(low(cand))) return cand
  }
  return `${stem} (${Date.now()})${ext}`
}

/** bytesB64 → Uint8Array (the page's decode — the bytes live here). */
export function b64ToBytes(b64) {
  const bin = atob(String(b64 || ''))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/* ── Cure A — THE PAGE SAVER (the bytes never leave the page) ──────────────── */

/**
 * Build the page-side saver. Every door is injected (testable; the journey
 * binds the real chrome.* doors).
 * @param {object} doors
 *   downloads  — chrome.downloads (may be null → the typed NO_DOWNLOADS_API)
 *   makeBlob(bytes) → Blob; createURL(blob) → string; revokeURL(url)
 *   lastError() → string|null (chrome.runtime.lastError's message)
 * Returns async save({ fileName, bytesB64 }) →
 *   { ok:true, downloadId, fileName: <the OBSERVED saved name>, requestedName } |
 *   { ok:false, code:'SAVE_FAILED:<REASON>', reason }
 */
export function createPageSaver({ downloads = null, makeBlob, createURL, revokeURL = () => {}, lastError = () => null } = {}) {
  const searchNames = async () => {
    if (!downloads || typeof downloads.search !== 'function') return []
    const items = await new Promise((resolve) => {
      try {
        downloads.search({}, (arr) => resolve(Array.isArray(arr) ? arr : []))
      } catch { resolve([]) }
    })
    return items.map((it) => baseNameOf(it && (it.filename || it.filenameBasic || ''))).filter(Boolean)
  }
  return {
    async save({ fileName = 'received-file', bytesB64 = '' } = {}) {
      if (!downloads || typeof downloads.download !== 'function') {
        return { ok: false, code: 'SAVE_FAILED:NO_DOWNLOADS_API', reason: 'the downloads API is unavailable here' }
      }
      const safe = sanitizeDownloadName(fileName)
      let candidate = safe
      try {
        candidate = nextFreeName(safe, await searchNames())
      } catch { /* the browser uniquifies as the net */ }
      const bytes = b64ToBytes(bytesB64)
      const url = createURL(makeBlob(bytes))
      let downloadId = null
      try {
        downloadId = await new Promise((resolve, reject) => {
          try {
            downloads.download({ url, filename: candidate, saveAs: false, conflictAction: 'uniquify' }, (id) => {
              const err = lastError()
              if (err) reject(new Error(err))
              else resolve(typeof id === 'number' ? id : null)
            })
          } catch (e) { reject(e) }
        })
      } catch (e) {
        try { revokeURL(url) } catch { /* best effort */ }
        return { ok: false, code: 'SAVE_FAILED:DOWNLOAD_REJECTED', reason: String((e && e.message) || e).slice(0, 120) }
      }
      // the OBSERVED name is the truth (a uniquify race may have renumbered)
      let observed = candidate
      try {
        if (downloads && typeof downloads.search === 'function' && Number.isFinite(downloadId)) {
          const found = await new Promise((resolve) => {
            try { downloads.search({ id: downloadId }, (arr) => resolve((Array.isArray(arr) && arr[0]) || null)) } catch { resolve(null) }
          })
          if (found && found.filename) observed = baseNameOf(found.filename) || candidate
        }
      } catch { /* the requested name stands */ }
      setTimeout(() => { try { revokeURL(url) } catch { /* gone */ } }, 60000)
      return { ok: true, downloadId, fileName: observed, requestedName: candidate }
    },
  }
}

/* ── Cure A — the arrivals ledger (the received side's own rows) ───────────── */

export const ARRIVALS_KEY = 'ucrypt:road-arrivals'

export function arrivalRow({ name, size = 0, sha12 = '', road = '', at = Date.now() } = {}) {
  return { kind: 'received', name: String(name || 'file'), size: Number(size) || 0, sha12: String(sha12 || ''), road: String(road || ''), verified: true, at: Number(at) || Date.now() }
}

/** The unit-on-number relative time ("just now", "42s ago", "3m ago"). */
export function relTime(atMs, nowMs = Date.now()) {
  const d = Math.max(0, Number(nowMs) - Number(atMs))
  if (d < 10 * 1000) return 'just now'
  if (d < 60 * 1000) return `${Math.round(d / 1000)}s ago`
  if (d < 60 * 60 * 1000) return `${Math.round(d / 60000)}m ago`
  if (d < 24 * 60 * 60 * 1000) return `${Math.round(d / 3600000)}h ago`
  return `${Math.round(d / 86400000)}d ago`
}

/** The ledger row line: "received · <name> · verified · just now". */
export function arrivalRowLine(row, nowMs = Date.now()) {
  return `received · ${row.name} · verified · ${relTime(row.at, nowMs)}`
}

/** The arrival card line: "Received — saved as <name> (<size>, verified)". */
export function arrivalCardLine(name, size) {
  const kb = Number(size) || 0
  const sizeLine = kb < 1024 ? `${kb} B` : kb < 1024 * 1024 ? `${(kb / 1024).toFixed(1)} KB` : `${(kb / 1024 / 1024).toFixed(1)} MB`
  return `Received — saved as ${name} (${sizeLine}, verified)`
}

/** Append one row (bounded — the ledger keeps the last 50). */
export async function recordArrival(storage, row) {
  const got = await storage.get(ARRIVALS_KEY)
  const rows = Array.isArray(got && got[ARRIVALS_KEY]) ? got[ARRIVALS_KEY] : []
  rows.push(row)
  await storage.set({ [ARRIVALS_KEY]: rows.slice(-50) })
  return rows
}

export async function readArrivals(storage) {
  const got = await storage.get(ARRIVALS_KEY)
  const rows = Array.isArray(got && got[ARRIVALS_KEY]) ? got[ARRIVALS_KEY] : []
  return rows.slice().sort((a, b) => Number(a.at) - Number(b.at))
}

/* ── Cure D — the resume lineage's honest state (the pump's 10-minute law) ── */

/** The receiver's watermark record state. The window default mirrors the
 *  pump's RESUME_WINDOW_MS (10 minutes) — kept locally to avoid the import
 *  cycle; the battery pins the two constants equal. */
export const RESUME_WINDOW_MS_LANDING = 10 * 60 * 1000

export function resumeRecordState(rec, nowMs = Date.now(), windowMs = RESUME_WINDOW_MS_LANDING) {
  if (!rec || !Number.isFinite(Number(rec.at))) return { present: false, fresh: false, expired: false, bytes: 0 }
  const at = Number(rec.at)
  const bytes = Number(rec.bytes) || 0
  const age = nowMs - at
  if (age >= 0 && age < windowMs) return { present: true, fresh: true, expired: false, bytes, age }
  return { present: true, fresh: false, expired: true, bytes, age: Math.max(0, age) }
}
