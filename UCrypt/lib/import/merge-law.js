/**
 * UCrypt — R160 ARC B′ — T8'S MERGE LAW FOR THE IMPORT POWER (G163).
 *
 * THE COMMANDED LAW (T8, carried by every round): newest-wins ·
 * conflicts-as-copies · summary-before-commit. The import journey's plan
 * machine: every incoming row lands in EXACTLY ONE typed class BEFORE
 * anything is written (the preview is the consent gate), and the merge is
 * transactional (the runner's journal unwinds on any failure — a failed
 * import leaves the vault untouched).
 *
 * THE FOUR CLASSES (ONE truth per row):
 *   adds        — not present in the vault → land (the vault's own add path)
 *   fills       — present, the vault's secret field EMPTY → the import fills
 *                 the empty field (newest-wins on the empty slot: the browser
 *                 export is the newest data the user has for that login)
 *   copies      — present with a DIFFERENT secret → CONFLICTS-AS-COPIES: the
 *                 vault copy stays authoritative; the browser's password is
 *                 preserved in the entry's password history with the typed
 *                 provenance ('import-conflict-copy') — user-resolvable,
 *                 never silently dropped (the old behavior), never silently
 *                 overwriting (the deepest layer's NEVER-OVERWRITE stands)
 *   duplicates  — present with the SAME secret → nothing to do
 *
 * PURE — zero network, zero chrome.* — the battery pins every row → class
 * (tests/r160-import-law.test.mjs), incl. the hostile-fixture gauntlet.
 */

/** The typed provenance every copy row carries (the history row's `source`). */
export const COPY_SOURCE = 'import-conflict-copy'

/** The law's words (the preview card's footer names the law it enforces). */
export const IMPORT_MERGE_LAW = 'T8 — newest-wins · conflicts-as-copies · summary-before-commit'

/** The vault key for a login row (the SAME normalization the R135 flow and
 * dedupeDecisions use: origin host, www stripped, case-folded). */
export function importKey(domainOrUrl, username) {
  let d = String(domainOrUrl || '').trim().toLowerCase()
  try {
    if (d.includes('://')) {
      const u = new URL(d)
      if (u.protocol === 'http:' || u.protocol === 'https:') d = u.hostname
    }
  } catch { /* the raw string stands */ }
  d = d.replace(/^www\./, '')
  return `${d}|${String(username || '').trim().toLowerCase()}`
}

function rowDomain(r) {
  return String(r && (r.domain ?? r.url) ? (r.domain ?? r.url) : '').trim()
}

/**
 * CLASSIFY THE WHOLE BATCH (summary-before-commit: the plan IS the preview).
 * @param {Array<{domain?:string,url?:string,username?:string,password?:string}>} rows
 * @param {Array<{domain?:string,username?:string,password?:string}>} existingEntries
 * @returns {{adds:Array, fills:Array, copies:Array, duplicates:Array,
 *            counts:{adds:number,fills:number,copies:number,duplicates:number,total:number}}}
 */
export function classifyImportPlan(rows, existingEntries) {
  const list = Array.isArray(rows) ? rows.filter((r) => r && typeof r === 'object') : []
  const existing = Array.isArray(existingEntries) ? existingEntries.filter((e) => e && typeof e === 'object') : []
  const byKey = new Map()
  for (const e of existing) {
    const k = importKey(e.domain, e.username)
    if (!byKey.has(k)) byKey.set(k, e)
  }
  const adds = []
  const fills = []
  const copies = []
  const duplicates = []
  const batchSeen = new Map() // in-batch dedupe: the FIRST occurrence wins the class
  for (const r of list) {
    const incomingPw = String(r.password ?? '')
    const key = importKey(rowDomain(r), r.username)
    const firstInBatch = batchSeen.get(key)
    if (firstInBatch) {
      // In-batch duplicate: same secret → nothing to do; a differing secret
      // is a conflict INSIDE the file — the copy class preserves it too.
      if (String(firstInBatch.password ?? '') === incomingPw) { duplicates.push(r); continue }
      const anchor = byKey.get(key) || { domain: rowDomain(firstInBatch), username: String(firstInBatch.username ?? ''), password: String(firstInBatch.password ?? '') }
      copies.push({ existing: anchor, incoming: r })
      continue
    }
    batchSeen.set(key, r)
    const cur = byKey.get(key)
    if (!cur) { adds.push(r); continue }
    const curPw = String(cur.password ?? '')
    if (curPw === incomingPw) { duplicates.push(r); continue }
    if (!curPw && incomingPw) {
      fills.push({ existing: cur, incoming: r, fields: ['password'] })
      continue
    }
    copies.push({ existing: cur, incoming: r })
  }
  return {
    adds, fills, copies, duplicates,
    counts: {
      adds: adds.length, fills: fills.length, copies: copies.length,
      duplicates: duplicates.length, total: list.length,
    },
  }
}

/**
 * THE SUMMARY-BEFORE-COMMIT CARD (masked — no secrets cross to the model;
 * the renderer shows domains + usernames only, the counts, and the law).
 */
export function buildImportPreview(plan) {
  const p = plan && typeof plan === 'object' ? plan : {}
  return {
    law: IMPORT_MERGE_LAW,
    counts: {
      adds: Number(p.counts && p.counts.adds) || 0,
      fills: Number(p.counts && p.counts.fills) || 0,
      copies: Number(p.counts && p.counts.copies) || 0,
      duplicates: Number(p.counts && p.counts.duplicates) || 0,
      total: Number(p.counts && p.counts.total) || 0,
    },
    addRows: (Array.isArray(p.adds) ? p.adds : []).map((r) => ({ domain: rowDomain(r), username: String(r.username ?? '') })),
    fillRows: (Array.isArray(p.fills) ? p.fills : []).map((f) => ({ domain: String((f.existing && f.existing.domain) ?? ''), username: String((f.existing && f.existing.username) ?? ''), fields: ['password'] })),
    copyRows: (Array.isArray(p.copies) ? p.copies : []).map((c) => ({ domain: String((c.existing && c.existing.domain) ?? ''), username: String((c.existing && c.existing.username) ?? '') })),
  }
}

/**
 * THE TYPED RESULT CARD (B′.2's shape: "12 added · 3 conflicts kept as
 * copies · 0 errors") — one sentence, every class named.
 */
export function resultCardWords({ added = 0, copies = 0, fills = 0, duplicates = 0, errors = 0 } = {}) {
  return `${Number(added) || 0} added · ${Number(copies) || 0} conflicts kept as copies · ${Number(fills) || 0} fields filled · ${Number(duplicates) || 0} duplicates · ${Number(errors) || 0} errors`
}

/**
 * THE TRANSACTIONAL JOURNAL — the pure half of the rollback discipline.
 * The runner records every mutation BEFORE it happens; unwind() replays the
 * undo doors in reverse order. The battery proves the vault-untouched row
 * with injected throwers (tests/r160-import-law.test.mjs).
 */
export function createImportJournal() {
  const steps = []
  return {
    record(step) { steps.push(step) },
    get size() { return steps.length },
    /** Undo everything in reverse; every undo door is injected and awaited.
     * @param {(step:object) => Promise<void>} undoDoor
     * @returns {Promise<number>} how many steps were unwound */
    async unwind(undoDoor) {
      let n = 0
      for (let i = steps.length - 1; i >= 0; i--) {
        try { await undoDoor(steps[i]); n++ } catch { /* the unwind never throws — best-effort in reverse */ }
      }
      return n
    },
  }
}
