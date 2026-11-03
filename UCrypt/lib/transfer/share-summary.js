/**
 * UCrypt — R160 ARC C′ — THE DATASET-SHARE SUMMARY CARD'S MODEL (G164).
 *
 * THE COMPLETION OF THE MANNERS (no new mechanism bytes — the share engine
 * is field-proven; LAW #91's whole-area pass on the dataset-share area):
 * the summary-before-commit card NAMES EVERY CLASS WITH COUNTS — the ten
 * classes the share's own transparency card enumerates (logins & passwords,
 * 2FA (TOTP) seeds, secure notes, custom fields, alias URIs, card entries,
 * address entries, bookmarks, browser history, forms) — so the offeror sees
 * exactly what the beam carries BEFORE the confirm, and the acceptor sees
 * the same census on arrival.
 *
 * PURE — the counts derive from the vault's entry list alone; the model
 * carries ZERO secrets (domains/usernames never ride it — only numbers and
 * class labels). The battery pins every class count
 * (tests/r160-share-summary.test.mjs).
 */

/** The ten share classes (the pair-scope card's own enumeration, keyed). */
export const SHARE_CLASSES = Object.freeze([
  { key: 'logins', label: 'logins' },
  { key: 'totp', label: 'authenticators' },
  { key: 'notes', label: 'secure notes' },
  { key: 'fields', label: 'custom fields' },
  { key: 'aliasUris', label: 'alias URIs' },
  { key: 'cards', label: 'card entries' },
  { key: 'addresses', label: 'address entries' },
  { key: 'bookmarks', label: 'bookmarks' },
  { key: 'history', label: 'history items' },
  { key: 'forms', label: 'form profiles' },
])

/** The T8 law's words (the card's footer names the law the merge enforces). */
export const SHARE_MERGE_LAW = 'newest-wins · conflicts-as-copies · sha both ends'

/**
 * COUNT THE TEN CLASSES over the vault's entry list.
 * @param {Array<object>} entries — the vault's entries (any shape; hostile
 *        rows count honestly or not at all, never throw)
 * @returns {{logins,totp,notes,fields,aliasUris,cards,addresses,bookmarks,history,forms}}
 */
export function countShareClasses(entries) {
  const list = Array.isArray(entries) ? entries.filter((e) => e && typeof e === 'object') : []
  const counts = { logins: 0, totp: 0, notes: 0, fields: 0, aliasUris: 0, cards: 0, addresses: 0, bookmarks: 0, history: 0, forms: 0 }
  for (const e of list) {
    const type = String(e.type || 'login')
    if (type === 'login') counts.logins += 1
    else if (type === 'totp') counts.totp += 1
    else if (type === 'note') counts.notes += 1
    else if (type === 'card') counts.cards += 1
    else if (type === 'address') counts.addresses += 1
    else if (type === 'bookmark') counts.bookmarks += 1
    else if (type === 'history') counts.history += 1
    else if (type === 'form') counts.forms += 1
    // the sub-attribute classes (any entry may carry them)
    if (Array.isArray(e.fields)) counts.fields += e.fields.filter((f) => f && typeof f === 'object' && f.name).length
    if (Array.isArray(e.uris)) counts.aliasUris += e.uris.filter((u) => typeof u === 'string' && u.trim()).length
  }
  return counts
}

/**
 * BUILD THE SUMMARY (the summary-before-commit card's whole model —
 * masked: numbers and labels only, zero vault content).
 * @param {Array<object>} entries
 * @param {{historyIncluded?:boolean, formsIncluded?:boolean, historyCap?:number}} opts
 * @returns {{law:string, classes:Array<{key,label,count,included}>, totals:{entries,includedClasses}}}
 */
export function buildShareSummary(entries, opts = {}) {
  const counts = countShareClasses(entries)
  const historyIncluded = opts.historyIncluded !== false
  const formsIncluded = opts.formsIncluded === true
  const cap = Number(opts.historyCap) || 0
  const classes = SHARE_CLASSES.map((c) => ({
    key: c.key,
    label: c.label,
    count: counts[c.key] || 0,
    included: c.key === 'history' ? historyIncluded : c.key === 'forms' ? formsIncluded : true,
  }))
  return {
    law: SHARE_MERGE_LAW,
    classes,
    totals: {
      entries: Array.isArray(entries) ? entries.length : 0,
      includedClasses: classes.filter((c) => c.included && c.count > 0).length,
      historyCap: cap,
    },
  }
}
