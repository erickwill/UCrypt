# SECURITY_DECISIONS.md — Manifest Permission & Security Ledger

Every entry in `manifest.json` (`permissions`, `optional_permissions`, `host_permissions`, and `oauth2`) has an explicit architectural rationale documented below.

---

## 1. Required Permissions (`permissions`)

| Permission | Decision | Rationale |
|---|---|---|
| `storage` | APPROVED | Stores encrypted vault ciphertext, wordlists, sync metadata, and local preferences in `chrome.storage.local`, `chrome.storage.sync`, and `chrome.storage.session`. |
| `unlimitedStorage` | APPROVED | Allows large encrypted vaults, imported bookmark archives, and staged encrypted file transfers without hitting the 10 MB browser quota. |
| `tabs` | APPROVED | Reads active tab URLs for registrable-domain (eTLD+1) credential matching and relays lock/unlock state broadcasts to open tabs. |
| `activeTab` | APPROVED | Enables user-invoked toolbar and context-menu autofill/save actions on the active tab. |
| `clipboardWrite` | APPROVED | Copies user-requested usernames, passwords, TOTP codes, and recovery phrases, and clears the clipboard automatically after the configured timeout. |
| `alarms` | APPROVED | Drives inactivity auto-lock timers, periodic background cloud sync ticks, exponential backoff retry timers, and daily breach checks. |
| `notifications` | APPROVED | Displays local user notifications for sync completion, conflict detection, and breach alerts. |
| `contextMenus` | APPROVED | Provides right-click quick actions to fill logins, generate strong passwords, or save credentials. |
| `identity` | APPROVED | Powers one-click OAuth 2.0 PKCE / token flows for Google Drive (`drive.appdata`) and Dropbox cloud sync transports. |
| `bookmarks` | APPROVED | Enables encrypted bookmark backup, restoration, and sync across browsers. |
| `downloads` | APPROVED | Exports encrypted vault backups, recovery sheets, and decrypted transfer files to the user's Downloads folder. |
| `privacy` | APPROVED | Allows optional management of browser password-saving settings (`chrome.privacy.services.passwordSavingEnabled`) and WebRTC IP handling policies. |
| `history` | APPROVED | Supports optional browsing-history import and privacy hygiene tools in the Data & Security tabs. |

---

## 2. Host Permissions (`host_permissions`)

| Pattern | Decision | Rationale |
|---|---|---|
| `<all_urls>` | APPROVED | Required for content-script login form detection, passkey interception, and credential autofill across user-visited websites. Vault plaintext never enters the page world until the user explicitly triggers autofill on a verified registrable domain. |

---

## 3. In-Page & Cryptographic Isolation Controls

| Control | Implementation |
|---|---|
| **Lock-state broadcast (`VAULT_LOCKED` / `VAULT_UNLOCKED`)** | Locking the vault immediately broadcasts to all open tabs, tearing down any active autofill picker, TOTP chip, or save prompt and incrementing a monotonic state epoch. |
| **Closed Shadow DOM isolation** | In-page autofill pickers, TOTP chips, and save bars render inside a `closed` `ShadowRoot` so host page scripts cannot inspect DOM nodes, usernames, or entry metadata. |
| **Cryptographic key separation** | Local vault encryption keys and 24-word sync chain keys are derived independently via PBKDF2-HMAC-SHA256 (600,000 iterations) with distinct salts and domain labels. |
| **Explicit non-permissions** | No `nativeMessaging`, no `debugger`, no `proxy`, no `cookies`, and zero third-party analytics or telemetry endpoints. |
