# UCrypt — Product Description & Architecture

## What Is UCrypt?

UCrypt is a Chromium browser extension that combines four essential security tools into one local-first, zero-knowledge suite:

1. **Password & Passphrase Generator** — generates cryptographically secure passwords, diceware passphrases, PINs, and BIP-39 mnemonics using the Web Crypto API with rejection sampling (zero modulo bias).
2. **Encrypted Vault** — stores logins, 2FA (TOTP) secrets, WebAuthn passkeys, secure notes, payment cards, identities, and bookmarks encrypted with AES-256-GCM (PBKDF2-HMAC-SHA256 600,000 iterations or Argon2id), with intelligent in-page auto-fill and auto-save.
3. **Cross-Device Cloud Sync** — syncs your encrypted vault across devices using your choice of transport (one-click Google Drive or Dropbox OAuth sign-in, GitHub Gist, WebDAV, custom HTTPS PUT/GET URL, or Google Apps Script), encrypted end-to-end by a 24-word BIP-39 sync chain with QR pairing, per-entry merge, conflict resolution, and automatic exponential backoff retry.
4. **Device Transfer & Direct Share** — transfers end-to-end encrypted files between your synced devices (via direct WebRTC or encrypted cloud relay) or shares one-time encrypted packages with other UCrypt users.

---

## Why UCrypt Exists

| Challenge | How UCrypt Solves It |
|---|---|
| **Vendor lock-in** | Bring your own cloud (Google Drive, Dropbox, GitHub Gist, WebDAV, or any URL) and switch anytime. |
| **Subscription fees** | Free and open-source with zero feature paywalls. |
| **Server-side trust** | Client-side encryption only — your master passphrase and sync keys never leave your devices. |
| **Breach & password health visibility** | Built-in offline entropy auditing, reused-password detection, and k-anonymity HIBP breach checks. |
| **Browser telemetry** | Zero analytics, zero tracking servers, and built-in WebRTC IP leak & anti-phishing shields. |

---

## Two Keys, Two Purposes

```
┌──────────────────────────────────────────────────────────────┐
│  MASTER PASSPHRASE                                           │
│  (set locally — protects the vault on this device)           │
│  → PBKDF2-SHA256 (600,000 iterations) / Argon2id             │
│  → Derives AES-256-GCM local vault encryption key            │
│                                                              │
│  SYNC CHAIN CODE (24-word BIP-39 mnemonic)                   │
│  (links your devices — protects cross-device cloud sync)     │
│  → PBKDF2-SHA256 (600,000 iterations)                        │
│  → Derives AES-256-GCM sync encryption key + device identity │
│                                                              │
│  YOUR CLOUD STORAGE                                          │
│  Google Drive / Dropbox / GitHub Gist / WebDAV / Custom URL  │
│  → Stores only authenticated AES-256-GCM ciphertext          │
│  → Cannot read or decrypt your vault entries                 │
└──────────────────────────────────────────────────────────────┘
```

---

## Security & Privacy Guarantees

- **Zero-knowledge encryption**: Every vault item is encrypted with AES-256-GCM and a fresh 96-bit random IV before touching `chrome.storage.local` or any cloud transport.
- **No remote code**: All scripts are bundled locally (`script-src 'self'`).
- **Closed Shadow DOM in-page UI**: Autofill pickers and 2FA chips render inside closed ShadowRoots so host pages cannot inspect identifiers or credentials.
- **Universal migration**: Import and export across 17 password manager and browser formats (Chrome, Brave, Edge, Firefox, Safari, Bitwarden, 1Password, LastPass, KeePassXC, Dashlane, NordPass, Proton Pass, Enpass, RoboForm, CSV, JSON, and HTML bookmarks).
