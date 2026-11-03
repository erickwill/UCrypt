# lib/import — the R150 CSV import engine (§8.1)

Pure, injectable, zero `chrome.*` — the page and the background door own all
I/O. Pipeline: `parseCsv → detectShape → normalizeRows → validateEntry →
dedupe → computeReceipt → previewRows`.
- `parseCsv(text)` → `{ rows: [{cells}], headers, delimiter }` — RFC4180-ish
  (quoted cells, `""` escapes, CRLF/LF, BOM); sniffs comma/semicolon/tab.
- `detectShape(headers)` → `chrome | firefox | bitwarden | generic | unknown`
  (the real header vocabularies, specificity order: `login_*` → firefox time
  columns → chrome's name/url/username/password → any url/user/pass triple).
- `normalizeRows(shape, rows, headers?)` → `{ entries, diagnostics }` — one
  entry per non-empty row (row numbers are FILE rows, header = row 1);
  firefox `timePasswordChanged` and bitwarden `login_totp` pass through.
- `validateEntry(e)` → `'ok' | 'needs-attention'` — never silently drop.
- `dedupe(entries, existing)` → `{ toAdd, toUpdate, duplicates, conflicts,
  attention }` — matches (url-normalized + username) then (name + username),
  against the vault AND within the batch; LWW on conflicts (the newer
  `timePasswordChanged` wins; without timestamps the import wins and the old
  copy stays in the report). `conflicts` is a report view; its rows live in
  `toUpdate` (import won) or `duplicates` (vault won).
- `computeReceipt(result)` → exact `{ imported, duplicatesSkipped,
  needsAttention, updated }` — the four sum to the non-empty data rows.
- `previewRows(entries, result)` → every data row exactly once, file order,
  status `ok | needs-attention | duplicate-of-existing`.

Write path: the page sends `IMPORT_APPLY { entries, updates }`; the door
routes adds through `vault.saveEntriesBatch` (re-dedupes, never overwrites)
and updates through `vault.updateEntry` (only previewed LWW winners),
re-checking the live vault before every write — a re-apply cannot duplicate.
Tests: `tests/r150-import.test.mjs`.
