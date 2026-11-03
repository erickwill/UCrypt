# UCrypt — User Guide

*The guide for everyone. If a step ever confuses you, the Troubleshooting
section at the end lists every message UCrypt can show and what to do —
nothing in this guide should ever be a dead end.*

---

## 1. What UCrypt is

UCrypt is a password manager that runs entirely inside your browser.

- Your passwords live in an **encrypted vault** on your device.
- Your **master passphrase** is the only key. It is never sent anywhere —
  not even to your cloud drive.
- If you want a second device to share the vault, you link them with a
  **sync code** (24 words) and copy the encrypted vault through **your own
  cloud drive** (Google Drive, Dropbox, GitHub Gist, WebDAV or any URL).
- You can also send a file directly to your other device with **direct
  transfer** — device to device, no middleman.

> 🌟 The one sentence to remember: **UCrypt never sees your data — only your
> devices do.**

---

## 2. Install (from the tarball)

1. Unzip `ucrypt-extension-v2.52.0.tar.gz` into a folder you will keep
   (for example `UCrypt/` in your Documents).
2. Open Chrome or Chromium and visit `chrome://extensions`.
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and pick the unzipped folder.
5. The UCrypt shield appears in your toolbar. Click the pin icon if you
   want it to stay.

**What you should see:** the UCrypt popup opens with
"Set up your master passphrase".
**If you see nothing:** check that you picked the folder that directly
contains `manifest.json` — not its parent folder.

---

## 3. Create your vault (the master passphrase)

1. Click the UCrypt shield.
2. Type a passphrase you can remember but nobody can guess (8+ characters).
3. Type it again to confirm, then press **Create vault**.

**What you should see:** the popup switches to the generator with a friendly
"Click generate ↓" hint, and a **Lock now** button appears at the bottom.

> ⚠️ **The honest truth:** if you forget the master passphrase, nobody can
> recover your passwords — not UCrypt, not your cloud drive, not anyone.
> Write it down and keep it safe. That is the price of true privacy, and it
> is worth paying.

---

## 4. The Getting-started checklist

Open **Settings** (the ⚙ in the popup). The Vault tab shows a
**"Getting started"** card with 4 steps, each with an **Open** button:

| Step | What it does |
|---|---|
| 1. Create your master passphrase | Encrypts the vault on this device |
| 2. Generate a 24-word sync code | The ONLY credential other devices need |
| 3. Connect a cloud drive | Where the encrypted backup lives |
| 4. Run your first sync | Push the encrypted vault to your cloud |

Do them in order. You can **Skip** a step and come back later — the
checklist keeps an honest count.

---

## 5. Your sync code — create it and PROVE your backup

The **sync code** is 24 words. It is the one key that links your devices
into a **sync chain**.

1. Settings → **Cloud Sync** → **Create sync chain**.
2. UCrypt shows the 24 words. **Write them on paper** (yes, real paper) and
   keep it somewhere safe.
3. Click the confirmation button to finish.

### The backup verification (do this — it takes one minute)

A backup you have never tested is a hope, not a backup. UCrypt lets you
PROVE your paper copy works:

1. Click **Verify backup** (on the Sync tab).
2. Type the words it asks for — exactly as they appear on your paper.
3. Wait for the green line.

**What you should see:** "Backup verified — your offline copy matches the
stored sync code."
**If you see:** "Not a match yet (word …)" — check the named word against
your paper copy. The state stays honest (not verified) until it truly
verifies. Nothing is faked here.

The chain status always tells the truth:

| Status | Meaning |
|---|---|
| "Sync code created — backup not verified" | Chain works, but test your paper copy |
| "Backup verified — cloud copy not confirmed yet" | Paper ✓, cloud not yet pushed/read |
| "Chain active — encrypted backup verified" | Everything checked — relax |
| "Chain needs attention — upload blocked…" | Read the message, usually the cloud drive |

---

## 6. Connect a cloud drive (your encrypted backup lives there)

Settings → **Cloud Sync** → click a transport card. UCrypt supports five.
The vault is uploaded **encrypted** — your provider stores a sealed file it
cannot read.

### WebDAV
Fill in the server URL, username, password → press **Test connection**.
**What you should see:** "✓ Server reachable" → press **Save**.

### Custom URL
Any HTTPS URL that answers like a storage endpoint → **Test connection** →
"✓ Server reachable" → **Save**.

### Google Drive
Two paths, both private to you:
- **Path A — your own Google credentials:** create a client ID + secret in
  Google Cloud Console, paste them in the Advanced section, press Connect,
  sign in with your Google account, and pick the drive file list. Your
  secret is stored sealed inside your vault on this device only.
- **Path B — the bridge:** deploy the small open-source bridge script (the
  Setup tab walks you through it with a checklist and auto-corrects common
  mistakes), then connect with one click.
**What you should see:** "Connected" and your Drive file list on the card.

### GitHub Gist
Paste a GitHub token with Gist scope → **Test** → "✓ Server reachable" →
**Save**. The encrypted vault becomes a secret Gist only your token can read.

### Dropbox
Connect once; UCrypt stores only a refresh token limited to **its own app
folder** — it cannot see the rest of your Dropbox. **What you should see:**
"Connected" + the folder name.

> 🔒 **The secret law:** every password, token and client secret UCrypt
> stores is sealed (encrypted) with your vault key, lives only on your
> device, is dropped the moment you lock, erased by **Disconnect**, and is
> never included in any export.

---

## 6a. The Sign-In Ladder — one click where your browser allows (new in R119)

Every cloud transport now shows its sign-in as a small **ladder with
three rungs**, top to bottom. You pick the rung that suits you — and no
rung is ever taken away.

**New in R120:** the walkthrough now *draws* each screen for you —
every important step shows a small picture of the console with the
button you need boxed in color, so you can check what you see before
you click.

| Rung | What it is | What you press |
|---|---|---|
| **Fast** | One click, where your browser allows it. UCrypt borrows your browser's own sign-in — no key, no secret, nothing to copy or store. | "Sign in with Google — one click" (shown only where your browser can really do it) |
| **Guided** | Your own key, in a few minutes, one time. The built-in walkthrough shows every click. | the walkthrough's steps below |
| **Manual** | The old reliable paths (the bridge, paste your own credentials). | the forms you already know |

The fast rung appears **only** where UCrypt's feature detection confirms
your browser can really do it — on a browser that cannot, it simply is
not shown (never a dead button). The guided rung is every card's face.
And every fast button carries the honest line: "Uses UCrypt's shared
sign-in — if it ever breaks, your own key (below) always works."

### Why does the guided rung ask for my own key?

"Google requires your own key because UCrypt has no company in the
middle — five minutes, one time, and the cloud is provably yours."

### The walkthrough, console by console

**Google Drive (about 3 minutes).**
1. Open `console.cloud.google.com` — the walkthrough carries the deep
   link, just click it.
2. Console → **"Credentials"** → **"OAuth client"** → as the type pick
   **"Chrome App"**.
3. Paste UCrypt's **extension ID**: open `chrome://extensions`, turn on
   **Developer mode**, and copy the long letters-and-numbers line under
   UCrypt.
4. The scope stays pinned to `drive.file` — the app may only touch files
   it created itself. Nothing secret is shared with UCrypt or anyone.
5. Two Google screens to expect at sign-in: the **account chooser**,
   then the **permission screen** — press **Allow**.
6. While the client sits in **Testing**, sign-ins stop working after 7
   days. **Publish to production** (a separate click) removes that
   expiry.

**GitHub (about 2 minutes).**
1. Open `github.com/settings/developers` → **"OAuth Apps"** →
   **"New OAuth App"**.
2. Give it any name and register it.
3. On the app's page switch the device flow on (**"Enable Device
   Flow"**) — that is what makes the 8-character code sign-in possible:
   UCrypt shows the code, you enter it at `github.com/login/device`,
   press authorize, and come back. Three actions, total. No secret ever
   exists to store.

**Dropbox (about 5 minutes).**
1. Open `dropbox.com/developers/apps` → **"Create app"**.
2. Choose **scoped access** (the app-folder kind fits — UCrypt only ever
   sees its own folder).
3. Copy the **App key** and paste it into UCrypt. With **PKCE** that is
   the whole story — the App key is public, an identifier and not a
   secret; no secret ever exists to copy.

**What you should see:** every console string above is quoted exactly as
the console shows it (the consoles belong to Google, GitHub and Dropbox —
their menus may render in your language; the names stay recognizable).

### The honest note about the fast rung

UCrypt's shared sign-in keys ship with the extension itself. Until they
land in a release, the fast rung simply is not shown and the guided rung
carries every card. Once they land: **one update, and the one-click
rungs light up by themselves** wherever your browser allows — you do not
have to redo anything.

---

## 7. Run your first sync

1. Press **Push** (or **Sync now**) on the Sync tab.
2. **What you should see:** a progress line, then a truthful last-sync
   timestamp and the chain status flipping to "Chain active".
3. Conflicts? If both devices changed things apart, UCrypt **merges both
   sides** and tells you what happened. It never silently drops an entry.

---

## 8. Join on a second device (QR, words, or the full pairing code)

1. Install UCrypt on the second device.
2. On device 1: Sync tab → **Add device** (reveals the sync code words + QR).
3. On device 2: popup first-run → **Join existing chain** (or Settings →
   Cloud Sync → **Join existing chain**) → type the 24 words or scan the QR.
   You can also press **Scan the pairing QR** and paste an image of the QR
   (Ctrl+V) or pick a screenshot file — the decoded code runs through the
   same checks as a typed or pasted one.
4. Press **Pull**. The vault arrives on device 2.

**The full pairing code (v1.3):** on device 1's Add-device sheet, the code
ALREADY carries the cloud connection settings next to the recovery words —
the provider, its address and the public client ID (never a secret). Press
**Copy pairing code** — one code carries the words AND the cloud settings.
Only the WebDAV sign-in is opt-in: tick **"Include the WebDAV sign-in in
this code so the new device connects automatically (its username and
password)"** if you want the new device to connect without typing it. On
device 2, paste that one code into the join box: the words land
automatically and the guided setup opens with the connection settings
already filled — press Connect and sign in. You will see **"Cloud setup
attached: Google Drive — ready. The connection settings are filled in; the
sign-in is the only step left."** One paste, one sign-in.

**What you should see:** chain state "Chain active — encrypted backup
verified" on both devices after one push/pull round.

> 💡 Up to 10 devices can share a chain. Left one behind? Remove it from
> the device list — it gets a tombstone so it can never come back uninvited.

## 8a. The Sync Beam — join without the cloud, device-to-device (R98)

When both devices are open at the same time, the join travels **directly** —
the Sync Beam. The cloud stays your durable backup; the beam is the fast
path. No UCrypt server exists in either role, ever.

1. **Device 1 (the origin):** Sync tab → **Add a device**. The pairing sheet
   opens and the beam turns on for 10 minutes — a truthful line names the
   window and reminds you that closing the sheet turns it off.
2. **Device 2 (the joiner):** join with the QR or the 24 words as above.
   Right after the words are saved, the Sync Beam stage appears: it shows
   your device fingerprint and asks the open device to accept.
3. **Device 1:** a dialog lands — the joiner's name, the SAME fingerprint on
   both screens, the request time. Compare the two screens, then
   **Accept** (or **Decline** — the joiner gets a clear refusal either way).
   The dialog never disappears on its own.
4. Accept fires the beam: your encrypted vault travels straight to the new
   device with live progress and a SHA-256 check. The new device's vault is
   live immediately.
5. **The last step is named:** the joiner sees "connect the same cloud
   storage" with the origin's provider and address (never the sign-in) —
   one click lands on the storage grid. From then on the cloud is the
   backup, and two open devices can beam again any time.

**No cloud at all?** The beam still works: the join signal is copy/paste
(staged right in the Sync Beam stage) and QR-to-QR where available — a chain
can be created, joined, and synchronized with zero infrastructure and zero
accounts.

> ⚠️ The 20 MB beam cap: a larger vault is refused with a clear message and
> the joiner is told to use the cloud path instead. The fingerprint is the
> honest check — if the two screens ever disagree, decline.

### Keyboard shortcuts (the honest map)

| Where | Keys | What happens |
|---|---|---|
| Any web page | `Ctrl+Shift+L` | Open UCrypt and fill the login for that page |
| Any web page | `Ctrl+Shift+U` | Suggest a strong password into the focused password field |
| Popup — Generate/Vault/2FA/Health/Sync | `←` / `→` | Move between the tabs |
| Popup — list rows | `Tab` + `Enter` | Walk the rows; Enter activates the focused button |
| Popup — any row | `Esc` | Close what UCrypt opened (nothing closes on a timer) |
| Save bubble / fill chip | `Esc` | Dismiss it — your choice, never an auto-dismiss |
| Browser | `chrome://extensions/shortcuts` | The browser page where you can change these shortcuts |

---

## 9. Direct transfer — send a file device-to-device

Open the transfer page from the popup's sync/share area. Two modes:

### Mode 1 — through the chain (one click)
1. **Receiver:** click **Receive**, then enable **Availability** ("Available
   until …" appears).
2. **Sender:** click **Send a file**, pick a file (up to 20 MB in this
   release), pick the device, send.
3. The receiver gets a card: **Accept** or **Decline** — nothing arrives
   without a human yes.
4. The file lands with its SHA-256 fingerprint verified. If one bit
   differed, UCrypt destroys the copy instead of saving it.

**How a transfer can end (all six, always shown honestly):** delivered ·
receiver declined · cancelled (by you) · interrupted (connection dropped —
try again, nothing was half-saved) · expired (the offer timed out — try
again) · failed (something broke — the message names it).

### Mode 2 — manual signaling (no cloud at all)
If both devices are open at the same time but share no cloud: the transfer
page shows **Fallback — manual signaling (copy / paste)**. Copy the signal from one
device, paste it on the other. Two pastes total, then the transfer runs
exactly as above.

> ⚠️ Files over 20 MB are refused with a clear message ("This file is over
> the 20 MB default limit of this release") and 0-byte files get "That file
> has no content." Nothing confusing, nothing silent.

---

## 10. Autofill — the two modes

Settings → **Security** → **Autofill behavior**:

- **Prompt mode** (default): "Nothing fills by itself. UCrypt shows the
  account dropdown and waits for your explicit selection every time."
- **Auto mode:** "Fill website password and sign in automatically, or
  suggest available passkeys." — for people who want speed.

**Saving a login:** type your credentials on a real site — UCrypt offers a
save bubble. Click it, review, save. Nothing is saved without your click.

**Filling manually:** popup → open the site's entry → **Fill on this page**.

---

## 11. Import & export

Settings → **Export / Import**:

- **Export vault (encrypted)** — a sealed file; imports only into UCrypt,
  and it never contains your cloud grants or secrets (the secret law).
- **Export decrypted CSV…** — asks twice (it is plaintext!); keep it
  momentarily, then shred it.
- **Import vault…** / CSV import — brings entries in with a preview before
  anything is written.

---

## 12. 2FA authenticator (TOTP)

The popup's **2FA** tab is a real authenticator: paste the `otpauth://` URI
your service shows (or enter the secret manually), and it computes live
codes. Secrets live encrypted inside the vault and sync with it. On a login
page, the UCrypt dropdown lists this site's tokens first — click one to fill
the verification field.

**Scan a QR image (new in R97):** instead of transcribing the URI, press
**Scan a QR image** in the Add panel and paste an image (Ctrl+V) or pick a
screenshot file. The QR is decoded on your device — nothing is uploaded —
and the decoded URI lands in the same paste box, where the live preview
shows the code before you save. Nothing is saved silently: you always see
the live preview and press Save yourself. A picture that is not a 2FA code
is refused with a message that tells you where it belongs (a pairing code
belongs on the Sync tab).

---

## 13. The health panel

Popup → **Health**: a report of your vault's shape — reused passwords, weak
passphrases, entries missing usernames. Every line names its fix. The full
report opens in the vault window.

Breached-password checks run entirely on this device against a bundled
list of the 10,001 most common leaked passwords — no network call, no
third-party lookup, your passwords never leave the device.

---

## 14. "Verify my setup" — one click, seven honest answers

Settings → **Security** → **Verify my setup**. It is strictly read-only
(it changes nothing) and answers:

| Check | Green means |
|---|---|
| Cloud transport reachable | Your drive answers |
| Sync chain joined | This device has a sync code |
| Sync code backup verified | Your paper copy was proven |
| Capture pipeline armed | Save-prompt machinery is ready |
| Toolbar badge compute | The badge follows the law |
| Storage within its caps | No structure grew out of bounds |
| Grants and secrets sealed | Every stored credential is sealed |

A red row names its fix in one sentence. That is the law.

---

## 15. Troubleshooting — every message, indexed

Messages are listed with what to do. If a message ever repeats and the fix
does not work, press **Test connection** on your transport card first — it
names the exact problem in most cases.

### Vault & lock
| Message | What to do |
|---|---|
| "Vault locked — unlock to use direct transfer." | Unlock the vault first. |
| "Vault is locked — unlock to run the health report." | Unlock, then open Health again. |

### Sync code & chain
| Message | What to do |
|---|---|
| "No sync chain yet" / "No sync chain on this device — create or join a sync chain first." | Create a chain (Settings → Cloud Sync) or join one from your other device. |
| "Not a match yet (word N)…" | Compare that word with your paper copy; retype it. |
| "Sync code created — backup not verified" | Run the backup verification (Section 5). |
| "Chain needs attention — upload blocked until cloud copy can be read" | Open the transport card and press Test connection. |

### Cloud transports
| Message | What to do |
|---|---|
| "Connection failed" | Check URL / user / password; for Drive check the setup card's checklist line that is not green. |
| "The cloud transport did not answer — open the Sync tab, press Test…" | The self-check's fix; run Test on the transport card. |
| "No cloud transport configured — cloud sync is optional; add one on the Sync tab when you want it." | Informational — cloud sync is optional by design. |

### Direct transfer
| Message | What to do |
|---|---|
| "This file is over the 20 MB default limit of this release." | Pick a smaller file. |
| "That file has no content." | The file is empty; pick a real file. |
| "Could not establish a direct route — the transfer stopped safely. Try again." | Put both devices on the same network and try again; manual signaling mode also works. |
| "The transfer timed out waiting for the other device — nothing was harmed. Try again." | Both pages must be open; retry. |
| "The other device declined the transfer." | The receiver pressed Decline — nothing was sent. |
| "A transfer is already active on this device — finish or cancel it first." | Finish or cancel the current transfer. |
| "That signal expired before it was used — press Regenerate on the other device, or paste a fresh signal here." | Signals are single-use. On the sending device press Regenerate for a fresh signal; here, paste a fresh one. |
| "The SHA-256 digest does not match the offer — nothing was saved." | Network corruption was caught; simply retry — safety worked. |
| "No paired device is currently available — the Discovery checklist above names the missing step." | Open the transfer window's Discovery checklist; turn availability on if that row shows ✗. |
| "The transfer rendezvous on your cloud is not answering right now (the rendezvous check just failed) — the manual route below is the road: one copy, one paste. UCrypt keeps retrying the cloud road automatically." | Use the manual route in the transfer window (Section 9, Mode 2): copy your signal, paste theirs, and paste yours back on the other device — or wait; the cloud road retries itself. |
| "The rendezvous storage is unreachable — check the cloud transport, or use manual copy/paste below." | Test the transport or switch to manual mode. |
| "The other device is not known on this chain yet — presence first contact is required." | Refresh the device list on both sides once. |

### Sync engine
| Message | What to do |
|---|---|
| Upload blocked / "412" style messages | Another device changed the cloud copy; UCrypt merges automatically — if asked, press Sync now. |
| "The badge decision is off-law — lock and unlock once…" | Lock and unlock; the badge recomputes. |
| "A stored credential is NOT sealed — lock and unlock the vault once (the migration seals it)…" | Lock + unlock once; the check turns green. |

### QR scan-from-image & the lock-time clipboard (new in R97)
| Message | What to do |
|---|---|
| "No QR code found in that image. Use the PNG from the other device’s “Download QR” button (ucrypt-pairing-….png) — keep its white border, avoid screenshots or re-saves — or paste the 24 words below." | Use the original PNG (not a screenshot) or paste the 24 words as text — both roads enter the same join. |
| "That image is too large — the limit is 8 MB." | Pick a smaller image — a cropped screenshot of just the QR code is ideal. |
| "That clipboard item is not an image." | Copy the picture itself (not a link to it), or pick the file with the file picker. |
| "Couldn't read that image — try a PNG or JPEG." | Save the picture as PNG or JPEG, then scan again. |
| "Clipboard cleared — the vault is locked." | Normal, and good: UCrypt emptied its copied secret from the clipboard the moment the vault locked. (If every UCrypt window was already closed at that moment, the clipboard could not be reached — copy again if in doubt.) |

**Still stuck?** Run **Verify my setup** (Section 14) — its seven answers
pinpoint the broken part, and every red row names its fix.

---

## 16. Kurzanleitung (Deutsch — die wichtigsten Schritte)

1. **Installieren:** Tarball entpacken → `chrome://extensions` →
   Entwicklermodus → **Load unpacked** → den entpackten Ordner wählen.
2. **Tresor anlegen:** Popup öffnen → Master-Passphrase zweimal eingeben →
   **Create vault**. Die Passphrase wird NIEMALS gesendet. Wer sie vergisst,
   kommt nicht mehr in den Tresor — aufschreiben!
3. **Sync-Code erstellen:** Einstellungen → Cloud Sync → **Create sync
   chain** → die 24 Wörter auf Papier schreiben → **Verify backup** drücken
   und die Wörter kontrollieren. Grün = dein Backup ist bewiesen.
4. **Cloud verbinden:** Cloud-Sync-Tab → Karte wählen (Google Drive,
   Dropbox, GitHub Gist, WebDAV oder eigene URL) → Daten eintragen →
   **Test connection** → „✓ Server reachable" → **Save**.
5. **Erster Sync:** **Push** drücken — danach zeigt die Kette „Chain active".
6. **Zweites Gerät:** dort UCrypt installieren → **Join existing chain** →
   die 24 Wörter eintippen (oder den QR scannen) → **Pull**.
7. **Datei senden:** Transfer-Seite öffnen → Empfänger: **Receive** +
   Verfügbarkeit an → Sender: **Send a file** (max. 20 MB) → Gerät wählen
   → Empfänger bestätigt → Fertig (SHA-256 geprüft).
8. **Alles prüfen:** Einstellungen → Security → **Verify my setup** —
   sieben ehrliche Antworten, jede rote Zeile nennt ihre Lösung.

---

## 17. 快速指南（中文 — 核心步骤）

1. **安装：** 解压 tarball → `chrome://extensions` → 开发者模式 →
   **加载已解压的扩展程序** → 选择解压后的文件夹。
2. **创建密码库：** 打开弹窗 → 输入两次主口令 → **Create vault**。
   主口令永远不会被发送；忘记它将无法恢复——请抄写保存。
3. **创建同步码：** 设置 → Cloud Sync → **Create sync chain** → 把 24 个
   单词抄到纸上 → 点击 **Verify backup** 核对。变绿即证明备份可用。
4. **连接云端：** Cloud Sync 标签 → 选择卡片（Google Drive、Dropbox、
   GitHub Gist、WebDAV 或自定义 URL）→ 填写 → **Test connection** →
   出现 "✓ Server reachable" 后 **Save**。
5. **首次同步：** 点击 **Push**，链条状态变为 "Chain active"。
6. **第二台设备：** 安装 UCrypt → **Join existing chain** → 输入 24 个
   单词（或扫描二维码）→ 点击 **Pull**。
7. **传文件：** 打开传输页 → 接收方点 **Receive** 并开启可用性 →
   发送方点 **Send a file**（最大 20 MB）→ 选择设备 → 接收方确认 →
   完成（SHA-256 已校验）。
8. **一键自检：** 设置 → Security → **Verify my setup** — 七项诚实检查，
   每个红行都会说明解决办法。

---

*UCrypt v2.52.0 — built with love that people will love. Everything in this
guide is anchored to real product behavior; nothing is aspirational.*

## 9a. Direct Share — one file to any UCrypt user, no chain needed

The File transfer tab in Settings carries a second handshake besides the
device transfer: **"Share a file"** (sending) and **"Have a share code?"**
(receiving). No sync chain, no cloud, no account — on either side. The
invitation travels through ANY text messenger; the security stays in the
cryptography.

### Sending (five actions)
1. **Choose file…** — up to 20 MB ("That file is over the 20 MB Direct
   Share limit — pick a smaller file." if it is bigger).
2. Optionally add a note. The warning is part of the design:
   "This note will be readable by the messenger you send it through."
3. **Create invitation** — a string starting with "UCRYPT-SHARE1:" appears
   with a visible countdown ("Expires in …", ten minutes) and a Cancel
   that kills it instantly.
4. Send the invitation in any messenger. When the reply arrives, paste it
   and press **Connect reply**.
5. The file streams only after the receiver accepts — twice.

### Receiving (five actions)
1. Paste the invitation under **"Have a share code?"** (or scan their QR —
   the in-person mode shows up to eight frames, scan them in order).
2. Door 1 asks: "Someone using UCrypt wants to share a file with you."
   **Reply & see** generates your reply, already copied — send it back in
   the same messenger. **Decline** sends nothing at all.
3. Door 2 shows the file: who it is from, the name, the size — and the
   **safety words**: four words that must match on BOTH screens. If you
   are in the same room, say them out loud.
4. **"Accept & receive"** — then the
   progress runs and the SHA-256 fingerprint is shown before you save.
5. Save keeps the file; nothing else is written anywhere.

Shares go **one at a time**: while a share is in progress, a further
invitation waits — finish or decline the first, and the door re-opens on
its own. If the direct connection fails, UCrypt tries one restart and
then says so honestly: "try the same network, or in person with the QRs."

**Share up to five files at once.** The sender picks up to five files
(20 MB each, 50 MB altogether) and ONE invitation covers them all — one
code, one handshake, one acceptance. Door 2 lists every file before you
accept, and the progress names the file it is on ("Receiving file 2 of
5… 40%"). Every file's fingerprint is checked the moment it lands, and
the "Shared files" list records each one. If the connection dies
halfway, what arrived intact is kept and the truth is stated plainly:
"Interrupted — 2 of 5 files arrived intact; the rest never came. The
keys are destroyed." Nothing partial is ever passed off as complete.


### The pickup — when the friend is offline (opt-in, one click)

If the receiver hasn't answered and the invitation is about to expire
(its last three minutes), the sender's card offers **"Hold for pickup on
your cloud"**. Accept it, pick how long the pickup lives (1 hour, 24
hours, or 7 days — 24 hours by default), and UCrypt seals the file with a
fresh 8-word code and uploads the sealed blob to YOUR OWN cloud (Google
Drive, Dropbox, or GitHub — WebDAV and Custom URL honestly cannot hold a
pickup; the live share still works when you are both online). You get ONE
pasteable notice — "UCRYPT-PICKUP1:" + a link + the code — to send in the
same messenger. Your cloud sees only ciphertext under a neutral name; the
messenger sees only the link and the code; nobody sees the file's name
until it is decrypted. The receiver pastes the notice under **"Have a
share code?"** — UCrypt recognizes it, downloads WITHOUT any account,
decrypts with the code, shows the file, and saves it after one click. The
pickup never joins your chain, dies the moment the file is saved, and you
can cancel it at any time — the file leaves your cloud immediately. When
a pickup expires, both sides say so honestly: "This pickup expired — ask
them to share again."

### The honest endings
- "Request expired — no reply or declined." — the sender can never know
  which one happened; that is the point.
- "This invitation was already used — share codes work exactly once."
- The four safety words differ → nothing was received; the reply code was
  modified or corrupted.

### The "Shared files" list (the one history a share keeps)

Under the File transfer tab, the **Shared files** card keeps the only
record Direct Share ever writes: the file's name, its size, the time, and
whether it was sent (↑) or received (↓). There is no person attached —
the handshake was anonymous by design, so the list has nothing to record.
The list lives only on this device (its own sealed-off storage slot — the
vault, the cloud copy, and every export/backup skip it), it holds at most
the latest 30 lines, and older lines fall off on their own. Before the
first share it says exactly that: "Nothing shared yet — shares leave no
trace anywhere but this list."

> ⚠️ The ephemeral keys die when the transfer ends: after a share, neither
> side can prove to anyone what was sent — or that anything was.
