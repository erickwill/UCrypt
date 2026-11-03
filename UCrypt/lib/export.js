/**
 * UCrypt — Plaintext CSV export for migration OUT (v2.9.0).
 *
 * Brave/Chrome/Edge/Firefox/Bitwarden all let users take their data OUT in a
 * browser-compatible CSV — data ownership is fundamental. UCrypt's encrypted
 * JSON export alone locked users in; this builds the exact header dialect the
 * Import Center accepts (Chrome: name,url,username,password,note) so a round
 * trip UCrypt → CSV → UCrypt (or → Brave) just works.
 *
 * SECURITY CONTRACT (enforced by the caller):
 *   - the vault must be UNLOCKED (decrypted entries are the input),
 *   - the user confirms TWICE (the CSV is plaintext — anyone with the file
 *     has every password),
 *   - the file is written by the OPTIONS page locally; nothing is uploaded.
 *
 * Pure module — no chrome access, unit-tested directly.
 */

/**
 * RFC-4180 field quoting: quotes around fields containing comma, quote,
 * CR/LF; embedded quotes doubled.
 */
export function csvField(value) {
  const s = String(value ?? '')
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"'
  return s
}

/**
 * Build the Chrome-dialect CSV string from decrypted login entries.
 * Only LOGIN entries (no TOTP tokens / imported other-data) — those have no
 * browser equivalent and would leak extra secrets (2FA seeds!) into the file.
 *
 * @param {Array<{domain,username,password,note?}>} entries
 * @returns {string} CSV text with header "name,url,username,password,note"
 */
export function buildBrowserCsv(entries) {
  const rows = [['name', 'url', 'username', 'password', 'note']]
  for (const e of (Array.isArray(entries) ? entries : [])) {
    if (!e || !e.domain || e.type) continue // logins only (imports set type)
    const domain = String(e.domain)
    rows.push([
      domain,
      'https://' + domain + '/',
      String(e.username ?? ''),
      String(e.password ?? ''),
      String(e.note ?? ''),
    ])
  }
  return rows.map(r => r.map(csvField).join(',')).join('\r\n') + '\r\n'
}
