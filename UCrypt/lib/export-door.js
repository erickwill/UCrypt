/**
 * ════════════════════════════════════════════════════════════════════════
 * R165 ARC G (the R163 carry, re-commanded and DUE) — THE EXPORT DOOR:
 * the encrypted-backup + consented-CSV export receipts.
 *
 * The EXPORT ACTIONS live on their sealed surfaces (the Export card's
 * encrypted JSON button; the CSV button with its double confirmation — both
 * untouched). THIS module is the door's typed memory: it builds the
 * envelope shape and the RECEIPTS that prove what left the device, under
 * what consent, with which integrity hash — and NO secret ever rides a
 * receipt (counts, sizes, hashes of ciphertext only; the CSV receipt
 * carries row counts, never cell values).
 *
 * Pure, dependency-free, engine-only — the battery drives every branch.
 * ════════════════════════════════════════════════════════════════════════
 */

/**
 * The encrypted-backup envelope (the exact shape the Import Center reads —
 * format ucrypt-vault-v1) + its integrity facts. The caller supplies the
 * SEALED blob (ciphertext) and the salt; nothing here ever sees plaintext.
 * @param {{blob: string|object, salt: string, at?: string}} input
 * @returns {{ok: boolean, envelope?: object, receipt?: object, error?: string}}
 */
export function buildEncryptedBackupEnvelope({ blob, salt, at } = {}) {
  if (!blob || !salt) return { ok: false, error: 'no sealed vault on this device yet — nothing to export' }
  const stamp = String(at || new Date().toISOString())
  const envelope = {
    format: 'ucrypt-vault-v1',
    encrypted: blob,
    salt,
    exportedAt: stamp,
  }
  const cipherText = typeof blob === 'string' ? blob : JSON.stringify(blob)
  return {
    ok: true,
    envelope,
    receipt: {
      kind: 'encrypted-backup',
      at: stamp,
      bytes: cipherText.length,
      // the SHA-256 of the CIPHERTEXT — integrity without exposure (the
      // plaintext is never seen here; the hash names the backup, not its keys)
      cipherSha256: null, // filled by the caller when a crypto seam is handy (async); the shape is typed now
      entries: null,      // NEVER a count of decrypted entries on this path — the sealed export counts nothing it cannot see
    },
  }
}

/**
 * THE CSV CONSENT RECORD (the double-confirmation law, typed): the CSV is
 * plaintext — the consent must be explicit TWICE and recorded with the row
 * count. A consent that is not twice-confirmed refuses (fail-closed).
 * @param {{confirmed1: boolean, confirmed2: boolean, rows: number, at?: string}} input
 * @returns {{ok: boolean, consent?: object, error?: string}}
 */
export function csvConsent({ confirmed1, confirmed2, rows, at } = {}) {
  const n = Math.max(0, Number(rows) || 0)
  if (!confirmed1 || !confirmed2) {
    return { ok: false, error: 'the plaintext CSV needs BOTH confirmations — the consent is not recorded and nothing was exported' }
  }
  if (n === 0) {
    return { ok: false, error: 'no login rows to export — the consent would be for an empty file' }
  }
  return {
    ok: true,
    consent: {
      kind: 'consented-csv',
      at: String(at || new Date().toISOString()),
      confirmations: 2,
      rows: n,
      warning: 'the file is NOT encrypted — anyone who can read it has every password',
    },
  }
}

/**
 * THE EXPORT-DOOR RECEIPT (copyable, privacy-shaped): what left, when, under
 * which consent, with which integrity facts — and NO secret material (no
 * cell values, no ciphertext, no passphrases; hashes and counts only).
 * @param {{encrypted?: object|null, csv?: object|null, at?: string}} door
 */
export function buildExportDoorReceipt({ encrypted, csv, at } = {}) {
  const stamp = String(at || new Date().toISOString())
  const L = []
  L.push('UCrypt export-door receipt (counts and hashes only — no secret material)')
  L.push(`at: ${stamp}`)
  if (encrypted && encrypted.ok) {
    L.push(`encrypted backup: exported (${String(encrypted.receipt && encrypted.receipt.bytes)} bytes of ciphertext${encrypted.receipt && encrypted.receipt.cipherSha256 ? `, sha256 ${encrypted.receipt.cipherSha256}` : ''})`)
  } else if (encrypted && encrypted.error) {
    L.push(`encrypted backup: NOT exported — ${String(encrypted.error).slice(0, 160)}`)
  }
  if (csv && csv.ok) {
    L.push(`consented CSV: exported (${csv.consent.rows} login rows, ${csv.consent.confirmations} confirmations recorded, warning shown: ${csv.consent.warning})`)
  } else if (csv && csv.error) {
    L.push(`consented CSV: NOT exported — ${String(csv.error).slice(0, 160)}`)
  }
  if (!encrypted && !csv) L.push('nothing left the device — no export ran')
  L.push('end of receipt')
  return L.join('\n')
}
