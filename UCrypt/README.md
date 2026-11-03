# UCrypt — Zero-Trust Browser Password Manager & Security Suite

**Version 3.45.0** · **Manifest V3** · **Zero-Knowledge AES-256-GCM & PBKDF2-SHA256 (600,000 iterations)**

UCrypt is a local-first, zero-telemetry password manager, passkey authenticator, TOTP generator, encrypted file transfer tool, and browser privacy suite for Chromium browsers (Chrome, Brave, Edge, Vivaldi, Opera).

---

## Core Capabilities

### 1. Encrypted Vault
- **Zero-Knowledge Cryptography**: All credentials, notes, TOTP secrets, passkeys, and bookmarks are encrypted locally using WebCrypto **AES-256-GCM** with keys derived via **PBKDF2-HMAC-SHA256 (600,000 iterations)** or **Argon2id**.
- **Logins, Passkeys & 2FA**: Store website logins, generate RFC 6238 TOTP 6-digit codes, and manage WebAuthn passkeys (`navigator.credentials.create` / `.get`).
- **Vault Health & Breach Auditing**: Offline password entropy scoring, reused-password detection, stale-credential alerts, and k-anonymity HaveIBeenPwned (HIBP) range checks (only the first 5 hex characters of the SHA-1 hash ever leave your device).
- **Duress Mode & Dead-Man Switch**: Optional secondary duress password that opens a decoy vault under coercion, plus configurable inactivity lockouts.

### 2. Multi-Device Cloud Sync (`Options → Cloud Sync`)
- **24-Word BIP-39 Sync Chain**: Derive an independent sync encryption key and Ed25519 device identity from a 24-word recovery phrase.
- **One-Click OAuth & Self-Hosted Transports**:
  - **Google Drive** (`drive.appdata` private application folder) and **Dropbox** with persistent OAuth refresh tokens and silent background renewal.
  - **GitHub Gist**, **WebDAV** (Nextcloud, ownCloud, Fastmail, Synology), **Custom HTTPS PUT/GET**, and **Google Apps Script**.
- **Resilient Sync Engine**: CRDT-inspired per-item timestamp merge, side-by-side **Conflict Resolver** when local and remote vault hashes diverge, and automatic exponential backoff retry on transient network failures.

### 3. Device Transfer & Direct Share
- **Device Transfer (`Options → Device Transfer`)**: End-to-end encrypted file transfer between your paired devices over direct WebRTC data channels or encrypted cloud relay.
- **Direct Share (`Options → Direct Share`)**: Share encrypted files with other UCrypt users using ephemeral ECDH/AES-256-GCM keys and verifiable fingerprints.

### 4. Browser Privacy & Phishing Defense (`Options → Security`)
- **WebRTC IP Leak Shield**: Restricts WebRTC ICE candidate gathering so VPN/Tor users do not leak local or ISP IP addresses.
- **Anti-Phishing Homograph & Lookalike Detector**: Warns before autofilling on IDN homograph domains (Cyrillic/Greek lookalikes) or typosquatted login pages.
- **Clipboard Auto-Scrub**: Automatically clears copied passwords and TOTP codes from the system clipboard after a configurable countdown.

---

## Installation

1. Extract this extension folder to a permanent directory on your machine.
2. Navigate to `chrome://extensions` in your Chromium browser.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select the extension directory.

---

## Documentation

- [Quickstart Guide](docs/QUICKSTART.md)
- [User Guide (English)](docs/USER-GUIDE.md)
- [Benutzerhandbuch (Deutsch)](docs/USER-GUIDE.de.md)
- [用户指南 (中文)](docs/USER-GUIDE.zh.md)
- [Security Architecture & Decisions](SECURITY_DECISIONS.md)
