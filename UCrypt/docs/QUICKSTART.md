# UCrypt — Quickstart Guide

> **A zero-trust, local-first password manager and security suite for Chromium browsers.**
> Your passwords, passkeys, TOTP codes, and encrypted files are encrypted locally with AES-256-GCM before anything touches disk or your personal cloud.

---

## 1. Install the Extension (60 seconds)

### From a `.zip` release
1. Unzip the release archive into a permanent folder on your computer (for example `~/Apps/ucrypt-extension`).
2. Open **`chrome://extensions`** (or `brave://extensions`, `edge://extensions`).
3. Turn on **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the unzipped folder.
5. Click the puzzle-piece icon in your browser toolbar and **pin UCrypt** for one-click access.

---

## 2. Create Your Vault (90 seconds)

1. Click the UCrypt toolbar icon.
2. Choose a strong **master password** (or click **Generate** to roll a high-entropy passphrase).
3. Download or print your **Emergency Recovery Kit** (`.html`) and store it safely offline.
4. Your vault is now unlocked and ready.

---

## 3. Everyday Use

| Action | How |
|---|---|
| **Save a login** | Sign in to any website — UCrypt offers a discreet top-right bar to save or update credentials. |
| **Autofill a login** | Click the UCrypt badge inside username/password fields or press **`Ctrl+Shift+L`** (`Cmd+Shift+L` on macOS). |
| **Generate a password** | Open the popup **Generator** tab to create random passwords, diceware passphrases, or PINs. |
| **2FA (TOTP) codes** | Store a site's `otpauth://` secret in the login entry; UCrypt copies or autofills the 6-digit code automatically. |
| **Passkeys (WebAuthn)** | Register and sign in with hardware-independent passkeys stored inside your encrypted vault. |

---

## 4. Cloud Sync & Multi-Device Chain (Optional)

Open **Options → Cloud Sync** to keep multiple browsers and devices synchronized with zero-knowledge encryption:

1. **Start or join a sync chain**: Create a 24-word sync chain code (or scan the QR code from another device).
2. **Connect your cloud**:
   - **One-click sign-in**: Connect **Google Drive** (stored in your private `appDataFolder`) or **Dropbox** with automatic token refresh and permanent session custody.
   - **Self-hosted / power-user**: Connect **GitHub Gist**, **WebDAV** (Nextcloud, ownCloud, Synology), **Custom HTTPS PUT/GET URL**, or **Google Apps Script**.
3. **Automatic sync & Conflict Resolver**: UCrypt syncs automatically on unlock and at your chosen interval, with exponential backoff on transient network drops and a side-by-side **Conflict Resolver** if local and remote vaults diverge.

---

## 5. Device Transfer & Direct Share

- **Device Transfer (`Options → Device Transfer`)**: Send encrypted files directly between your paired devices over WebRTC (Direct Beam) or your encrypted cloud relay.
- **Direct Share (`Options → Direct Share`)**: Package a file with an ephemeral key and share a one-time encrypted package with another UCrypt user.
