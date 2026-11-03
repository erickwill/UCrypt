/**
 * UCrypt — Bookmark restore-to-browser (R92 §3, the R42 canonical item).
 *
 * THE LAW (battery-pinned): restoring vault bookmarks into this browser is
 * NEVER automatic. It happens ONLY behind an explicit "Restore bookmarks
 * into this browser" button, only after a PREVIEW the user can read, and
 * only after an explicit CONFIRM. No duplicate creation: a vault bookmark
 * whose URL already exists in the target folder path is skipped.
 *
 * Pure module (no chrome.* calls) — the unit battery exercises every branch;
 * options.js performs the actual chrome.bookmarks.create sequence.
 *
 * Vault bookmark shape (lib/importers.js): { type:'bookmark', username:
 * <title>, meta: { url, folder: 'A/B' (joined path), visitedAt } }.
 */

/** The vault entries that carry restorable bookmarks. */
export function vaultBookmarkEntries(entries) {
  return (Array.isArray(entries) ? entries : []).filter(e => e && e.type === 'bookmark' && e.meta && typeof e.meta.url === 'string' && e.meta.url.trim())
}

/** Normalize a folder path: trim segments, drop empties, cap depth at 20. */
export function normalizeFolderPath(folder) {
  const parts = String(folder || '')
    .split('/')
    .map(s => s.trim())
    .filter(Boolean)
    .slice(0, 20)
  return parts
}

/**
 * Build the restore plan.
 * @param entries   vault entries (bookmark type)
 * @param existing  the Bookmarks-bar subtree from chrome.bookmarks.getTree()
 *                  (tree[0].children.find(n => n.id === '1')) — paths are
 *                  built RELATIVE to the bar, exactly where the restore
 *                  creates its root folder, so duplicate matching is
 *                  apples-to-apples.
 * @param rootTitle the folder created under the Bookmarks bar for the restore
 * @returns { rootTitle, folders: [path…], creates: [{path, title, url}],
 *          duplicates: n, skipped: [{url, reason}…] }
 */
export function buildBookmarkRestorePlan(entries, existing, rootTitle = 'UCrypt restored bookmarks') {
  const bookmarks = vaultBookmarkEntries(entries)
  // Index the browser's existing bookmarks by (normalized URL → set of folder paths).
  const existingByUrl = new Map()
  const walk = (node, path) => {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node.children)) {
      for (const c of node.children) {
        if (!c || typeof c !== 'object') continue
        if (Array.isArray(c.children)) {
          // A FOLDER: its title extends the path for everything under it.
          const childPath = path ? `${path}/${String(c.title || '').trim()}` : String(c.title || '').trim()
          walk(c, childPath)
        } else if (typeof c.url === 'string' && c.url) {
          // A BOOKMARK: recorded at ITS FOLDER's path — the bookmark's own
          // title never extends the path (the R92 battery caught this exact
          // bug in the first draft: 'Root/Work/Site' vs the plan's
          // 'Root/Work' — duplicates would silently never match).
          const key = normalizeBookmarkUrl(c.url)
          if (!existingByUrl.has(key)) existingByUrl.set(key, new Set())
          existingByUrl.get(key).add(path || '')
        }
      }
      return
    }
    if (typeof node.url === 'string' && node.url) {
      const key = normalizeBookmarkUrl(node.url)
      if (!existingByUrl.has(key)) existingByUrl.set(key, new Set())
      existingByUrl.get(key).add(path || '')
    }
  }
  walk(existing, '')
  const creates = []
  const skipped = []
  const folderSet = new Set()
  let duplicates = 0
  const seenInVault = new Set()
  for (const e of bookmarks) {
    const url = String(e.meta.url).trim()
    const key = normalizeBookmarkUrl(url)
    const title = String(e.username || url).trim() || url
    const pathParts = [rootTitle, ...normalizeFolderPath(e.meta.folder)]
    const path = pathParts.join('/')
    folderSet.add(path)
    // In-vault duplicate (same URL twice) — the first occurrence wins.
    const vaultKey = `${key}|${path}`
    if (seenInVault.has(vaultKey)) { duplicates++; continue }
    seenInVault.add(vaultKey)
    // Browser duplicate: same URL already present in the SAME folder path.
    const paths = existingByUrl.get(key)
    if (paths && paths.has(path)) { duplicates++; skipped.push({ url, title, reason: 'already in this browser (same folder)' }); continue }
    creates.push({ path, title: title.slice(0, 250), url })
  }
  return {
    rootTitle,
    folders: [...folderSet].sort(),
    creates,
    duplicates,
    skipped,
    total: bookmarks.length,
  }
}

/**
 * Normalize a URL for duplicate matching: lowercase scheme+host, drop the
 * trailing slash on the root path, drop the hash fragment. Query and the
 * rest of the path are kept (they distinguish real destinations).
 */
export function normalizeBookmarkUrl(url) {
  try {
    const u = new URL(String(url || '').trim())
    u.hash = ''
    let out = `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, '')}`
    if (u.search) out += u.search
    return out
  } catch {
    return String(url || '').trim().toLowerCase()
  }
}

/**
 * The creation sequence for a plan: folders first (shortest path first, each
 * created once), then the bookmarks under their folders. Returns steps the
 * caller executes against chrome.bookmarks.create — pure, unit-testable.
 */
export function planCreationSteps(plan) {
  const steps = []
  const folderByPath = new Map()
  const sorted = [...(plan.folders || [])].sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : 1))
  for (const path of sorted) {
    const parts = path.split('/')
    const parentPath = parts.slice(0, -1).join('/')
    const title = parts[parts.length - 1]
    const parent = parentPath ? folderByPath.get(parentPath) : { id: 'BOOKMARKS_BAR' }
    if (!parent) continue // unreachable by construction (sorted by depth)
    const step = { kind: 'folder', title, parentId: parent.id === 'BOOKMARKS_BAR' ? '1' : parent.id, path }
    steps.push(step)
    folderByPath.set(path, { id: `:${path}`, ...step })
  }
  for (const c of (plan.creates || [])) {
    const parent = folderByPath.get(c.path)
    steps.push({ kind: 'bookmark', title: c.title, url: c.url, parentId: parent ? (parent.id === 'BOOKMARKS_BAR' ? '1' : `:${c.path}`) : '1', path: c.path })
  }
  return steps
}
