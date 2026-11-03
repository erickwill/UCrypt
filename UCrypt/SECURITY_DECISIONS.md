# SECURITY_DECISIONS.md — manifest permission ledger

Every entry in `manifest.json` → `permissions`, `optional_permissions`, and
`host_permissions` must have an explicit, dated decision here. The release
test `tests/round45-test.mjs` (R45-D permission-diff) parses the manifest and
refuses ANY permission not present in this file, so a sneaky scope expansion
fails the build instead of shipping silently.


## v2.42.0 (R61 — 2026-09-29) — NO PERMISSION CHANGE

Brave-parity pairing round: guided pairing dialog, truthful four-state chain
wording (backed by the additive `ucrypt:lastPull` outcome ledger — plain
chrome.storage.local metadata, no secrets), and the first-class
`options.html#join` route. The manifest's `permissions`, `optional_permissions`,
`host_permissions`, `web_accessible_resources`, `content_scripts`, and
`externally_connectable` are byte-identical to v2.41.4. The pairing QR stays
words-only (`ucrypt-sync://<24 words>`); no device-revocation or
native-passkey claims were added; Channel A/OAuth surfaces untouched.

## permissions (granted at install)

| Permission | Decision | Rationale | Date |
|---|---|---|---|
| `storage` | APPROVED | Vault ciphertext, settings, ledgers — chrome.storage.local/sync/session are the extension's only persistence. | 2025-09 (v2.1.0) |
| `tabs` | APPROVED | Tab URLs feed domain matching (never full page content); tab-scoped save-prompt relay to the top frame (R22-F2). | 2025-09 (v2.1.0) |
| `activeTab` | APPROVED | Context-menu fill/save actions need the current tab grant at click time. | 2025-09 (v2.6.0) |
| `clipboardWrite` | APPROVED | Copy-password/copy-TOTP buttons only; never written automatically. | 2025-09 (v2.1.0) |
| `alarms` | APPROVED | Auto-lock enforcement, 15-min sync tick, daily breach check, R45 unlock-session keep-alive. | 2025-09 (v2.8.0) |
| `notifications` | APPROVED | Pull-complete and breach-findings notices only; no remote content. | 2025-09 (v2.8.0) |
| `contextMenus` | APPROVED | Fill login / suggest password / save login / card+identity fill menus. | 2025-09 (v2.6.0, v2.19.0) |

## R59 — lock-state push channel, closed-shadow page isolation, and the health window (2026-09-28, v2.41.3)

| Decision | Assessment | Rationale |
|---|---|---|
| `VAULT_LOCKED` / `VAULT_UNLOCKED` broadcast to all tabs on every lock/unlock path | APPROVED — security fix (P0, owner F2) | A locked vault must not leave picker/OTP/save surfaces (usernames, row metadata, Fill controls) in a page. The broadcast rides the existing `chrome.tabs.sendMessage` channel; tabs without the content script are skipped. The content script destroys surfaces and bumps a monotonic `vaultStateEpoch` so late replies can never re-render vault data. |
| Vault-derived in-page surfaces (autofill picker, OTP chip, card/identity picker) rendered inside a CLOSED ShadowRoot host | APPROVED — privacy hardening (owner §2.2) | The page world can see only a generic host element: no usernames, entry ids, row content, host attributes, or dataset. Row actions close over entry references nothing resolvable from page JS. The no-attachShadow fallback keeps MASKED labels only — raw identifiers never render in page-readable DOM. |
| Device-local `showIdentifiers` picker setting (default On, `chrome.storage.local` `ucrypt:behavior`) | APPROVED — UX with privacy trade-off made explicit | Full usernames are required for account selection; the closed shadow keeps them out of page reach. Off restores a masked/ordinal picker. Never synced; passwords/TOTP/note values are never rendered as identity. |
| Health full report in the extension-controlled vault window (`popup.html?window=1&surface=health`) | APPROVED — surface relocation, no new exposure | Health detail (including usernames in the full worst-list) stays extension-origin; the toolbar summary reveals domain + bits only. The tab fallback (`tab=1`) cannot write window bounds. No new permission, host permission, or web-accessible resource. |

## optional_permissions (granted only by an explicit user action)

| Permission | Decision | Rationale | Date |
|---|---|---|---|
| `privacy` | APPROVED (R45-C) | Grants access to `chrome.privacy.services.passwordSavingEnabled` so UCrypt can implement the opt-in "Save passwords with UCrypt" native-manager mode. Requested via `chrome.permissions.request` from the popup/options click. The API is feature-detected; `levelOfControl` is surfaced verbatim; disabling restores the pre-UCrypt browser value. Without this grant UCrypt never touches any browser setting. | 2025-09-25 (v2.36.0) |

## host_permissions

| Pattern | Decision | Rationale | Date |
|---|---|---|---|
| `<all_urls>` | APPROVED (re-reviewed R45) | Required for content-script field detection + autofill on user-surfaced logins. R45-C regression battery pins that the page world never receives vault lists/seeds/tokens, candidates transit memory only until the user chooses Save, and serving is registrable-domain-scoped. Content scripts run at `document_idle`, `all_frames` for embedded logins. | 2025-09 (v2.1.0), re-reviewed 2025-09-25 |

## Explicit non-permissions (standing refusals)

- NO `nativeMessaging` — no host process bridge.
- NO `debugger`, NO `proxy`, NO `webRequestBlocking`.
- NO `cookies` — autofill never needs cookie access.
- NO broad identity/OAuth scopes — cloud transports are user-configured
  (R45-B Mode 2); no consumer OAuth client ships in this build.
- NO telemetry / remote logging of any kind.
