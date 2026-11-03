# UCrypt Quickstart — from tarball to a working vault in five steps

*This quickstart rides inside the archive. The full guide (with every
message explained) is `docs/USER-GUIDE.md` — English, German and Chinese
editions included.*

---

## 1. Load it (2 minutes)

1. Unpack this archive into a folder you will keep (e.g. `UCrypt/`).
2. Open Chromium/Chrome → address bar → `chrome://extensions`.
3. Turn on **Developer mode** (top-right) → **Load unpacked** → pick the
   unpacked folder (the one containing `manifest.json`).
4. Pin UCrypt to your toolbar (the puzzle-piece icon → pin).

## 2. Lock your vault (1 minute)

Click the UCrypt icon → set a **master passphrase**. This passphrase is the
only key to your vault — it never leaves your device, and nobody can reset
it for you. Write it down somewhere safe.

## 3. Connect your cloud (3 minutes)

Security tab → Sync → pick your provider (Google Drive, Dropbox, GitHub
Gist, WebDAV or a custom URL) and follow the guided steps. Your vault is
uploaded **encrypted** — your provider stores ciphertext it cannot read.
Press **Sync now** once; after that, every change pushes automatically.

## 4. Add your second device (the 5-action promise)

On the **new** device, load UCrypt the same way, then either:

- **Scan the QR**: origin device → Cloud Sync → *Add a device* →
  **Download QR** (or **Copy pairing code**) → new device: drop the PNG on
  the drop zone (drag-drop, Ctrl+V, or the file picker) → confirm →
  **everything arrives**: the sync code, the cloud connection (when the
  origin opted in), and the current vault — one code, one confirm.
- **Type the words**: origin → **Copy pairing code** → new device →
  *Join existing chain* → paste → **Validate words** → confirm.

Words-only codes never auto-execute — that is the safe default. A complete
code (cloud included) only exists when the origin device explicitly opts in,
and the opt-in says exactly what it ships.

## 5. Send a file directly (no cloud at all)

Open **Direct Transfer** on both devices. The window explains itself: the
**Discovery checklist** shows chain · cloud · availability · devices, and
every ✗ row carries its one-click fix. The window **turns availability on
by itself** (10 minutes, a live countdown, **Stop** hides you instantly).
If a device is not listed and the cloud route is down, use **Advanced —
Manual pairing**: press **Copy my signal** on one device, paste it on the
other, press **Open signal** — then copy BACK so the first device sees the
second (the page says so and pulses the button). Then: choose the file →
pick the device → **Create offer** → the receiver **Accept** → the digest
is verified before anything is saved.

---

## When something does not work

Every failure names its fix. The ones you are most likely to meet:

| You see | It means | Do this |
|---|---|---|
| "Connection failed" / the connection test fails | No route to your provider (offline, firewall, egress blocked) | Check the network; the words-only pairing + a manual cloud connect always work without any auto-connect |
| "Test connection" says unauthorized / 401 | The sign-in or token expired | Re-do the provider sign-in on the Cloud transport card, then Test again |
| The joiner says "the origin device has no cloud connected" | The words-only carrier — by design | Connect the same cloud storage on the joiner, or re-pair with the Complete opt-in on the origin |
| A second transfer window shows nothing after an offer | Another window opened it (v2.63.0) | The window with the decision dialog has the offer; the silent one now says "A transfer offer was opened in another UCrypt window." |
| The device list is empty with no explanation | Cannot happen on v2.65.0 | The Discovery checklist names the missing step with its one-click fix; a pasted signal works for the full 10-minute window ("That signal expired…" means the window ended — copy a fresh signal) |

Everything else: `docs/USER-GUIDE.md` → Troubleshooting — every message,
the truthful cause, the next step. Nothing is ever a dead end.

*Build integrity: `BUILD.json` (in this archive) carries the payload
sha256 and the member count. `sha256sum` of the tarball must match the
published value in `RELEASES.json`.*
