# UCrypt — Full Description & Intentions

## What Is UCrypt?

UCrypt is a Chromium browser extension that combines three things into one privacy-first tool:

1. **Password generator** — generates cryptographically secure passwords, passphrases, PINs, and BIP-39 mnemonics using Web Crypto API with rejection sampling (zero modulo bias)
2. **Encrypted vault** — stores passwords for every website you use, encrypted with AES-256-GCM (PBKDF2 600,000 iterations, OWASP 2023 guidance), with auto-fill and auto-save
3. **Cross-device sync** — syncs the encrypted vault across your devices using YOUR choice of transport (Google Drive via a 3-minute Apps Script bridge, Dropbox, GitHub Gist, WebDAV, any custom URL, or plain manual export), keyed by a 24-word BIP-39 sync code with scannable QR pairing

## Why UCrypt Exists

Existing password managers have problems:

| Problem | How UCrypt solves it |
|---------|---------------------|
| **Lock-in to a cloud service** (1Password, LastPass) | You choose your own cloud — switch anytime |
| **Monthly subscription fees** | UCrypt is free, open-source, no account needed |
| **Server-side encryption** (trust the company) | Client-side only — your key never leaves your device |
| **No auto-fill on all sites** (free tiers limited) | Full auto-fill on ALL sites, no limits |
| **No breach monitoring** (premium feature) | 10,001 breached passwords bundled, daily checks free |
| **Closed source** (can't audit) | Fully open-source, all code readable |
| **Account required** (email, password, 2FA) | No accounts — just a master passphrase + sync code |

## How UCrypt Works

### Two Keys, Two Purposes

```
┌──────────────────────────────────────────────────────────┐
│  MASTER PASSPHRASE                                        │
│  (you set this once — protects the local vault)           │
│  → PBKDF2 (210,000 iterations) → AES-256-GCM key         │
│  → Encrypts/decrypts the vault on THIS device             │
│                                                            │
│  SYNC CODE (24-word BIP-39 mnemonic)                      │
│  (you generate this — protects cross-device sync)         │
│  → PBKDF2 (210,000 iterations) → AES-256-GCM key         │
│  → Encrypts/decrypts the sync blob on YOUR cloud          │
│                                                            │
│  YOUR CLOUD (you choose)                                  │
│  Google Drive / Dropbox / GitHub / WebDAV / Custom URL   │
│  → Only stores ciphertext — can't read your vault         │
│  → UCrypt encrypts BEFORE uploading — no plaintext ever   │
│    touches the cloud                                      │
└──────────────────────────────────────────────────────────┘
```

### Security Model

- **No accounts** — no email, no password, no OAuth from UCrypt
- **No remote code** — all JS bundled, CSP `script-src 'self'`
- **No plaintext at rest** — vault encrypted with AES-256-GCM before any storage
- **No plaintext in transit** — sync blob encrypted before it touches any cloud
- **No identity** — your cloud service knows only ciphertext + an anonymous hash
- **Defense in depth** — separate master key (local) + sync key (cross-device)
- **Open source** — every line of code is readable and auditable
- **No tracking** — no analytics, no telemetry, no external requests beyond your chosen cloud

### Privacy Guarantees

| Who | What they see | Can they decrypt? |
|-----|--------------|:---:|
| Google Drive | Encrypted blob file | ❌ |
| Dropbox | Encrypted blob at /ucrypt-vault.enc | ❌ |
| GitHub | Encrypted blob in a private Gist | ❌ |
| WebDAV server | Encrypted blob at user's URL | ❌ |
| UCrypt developers | Nothing — we don't run a server | ❌ |

**Nobody can read your vault without BOTH the master passphrase AND the sync code.**

## Features

### Password Generation (toolbar popup)
- Random passwords (length 4-256, all character types, exclusion rules)
- Diceware passphrases (EFF wordlists: 1,296 + 1,296 + 7,776 words)
- PIN codes (3-16 digits, no-repeats, no-sequences)
- Pronounceable passwords (consonant-vowel-consonant syllables)
- BIP-39 mnemonic seed phrases (12/15/18/21/24 words)
- Custom wordlist scraping (scrape any URL for words — no CORS in extension context)
- Quick presets (Banking, Email, Social, WiFi, Maximum, Quick)
- Clipboard auto-clear with countdown

### Vault (encrypted storage)
- AES-256-GCM encryption (PBKDF2 210,000 iterations)
- Auto-detect login forms on every page
- Auto-fill username + password (React/Vue-compatible value setter)
- Auto-save on form submission ("Save this password?" prompt)
- Auto-lock after 10 minutes of browser inactivity
- Emergency wipe (Ctrl+Shift+X) — destroys ALL data instantly

### Sync (cross-device)
- 24-word BIP-39 sync code (displayed as text + QR code for mobile pairing)
- 5 pluggable cloud transports:
  - Google Drive (paste a share link)
  - Dropbox (paste an access token)
  - GitHub Gist (paste a personal access token)
  - WebDAV (paste a URL)
  - Custom URL (any HTTP endpoint)
- Guided setup wizard for each transport (step-by-step, newbie-friendly)
- Manual export/import (always works, offline, no cloud needed)
- The sync code works across ALL transports — switch anytime

### Breach Monitoring
- 10,001 known-breached passwords bundled (offline, from SecLists)
- Daily check of all stored passwords (chrome.alarms)
- Desktop notification if a stored password is found in the breach database
- Password strength analyzer (dictionary, leet, sequences, keyboard walks, dates)

### Browser Integration
- Content script detects `<input type="password">` on every page
- Shows "UCrypt: Auto-fill available" overlay near password fields
- Fills username + password with one click
- Detects form submissions → "Save this password?" prompt
- (v2.95.0) Device Transfer rebuilt as THE HANDSHAKE: two-way manual pairing in six explicit steps (the answer signal exists the instant the peer's opens), discovery in seconds with live searching, one truthful readiness surface, deep-linked steps with Send as the last action, and a diagnostics drawer that opens itself only on anomaly
- (v2.94.0) In-page "suggest strong password" on signup/new-password fields — generates locally, fills the field AND its confirm twin, with Regenerate/Copy
- (v2.94.0) Right-click context menus: Fill login from vault / Suggest strong password / Save login for this page (http(s)-scoped)
- (v2.94.0) Keyboard commands: Ctrl+Shift+L (fill login) and Ctrl+Shift+U (suggest password), remappable
- (v2.7.0) **Universal Import Center** (Options → Export/Import): one door for every migration path INTO UCrypt —
  - **Sources**: Chrome, Edge, Brave, Vivaldi, Opera (Chromium CSV), Firefox (CSV + JSON), Safari, Bitwarden (CSV + JSON), LastPass, 1Password, Dashlane, KeePassXC/KeePass, RoboForm, NordPass, Enpass, generic CSV, bookmarks HTML, history CSV/JSON — auto dialect detection with a preview before anything is written
  - **Categories**: logins, 2FA token seeds (otpauth:// URIs + bare base32), secure notes, payment cards, identities/addresses, bookmarks (folders preserved), history records (visit counts), form-field data (Bitwarden fields, RoboForm Rf-Fields)
  - **Safety**: never-overwrite enforced at BOTH the plan and the save layer; per-category include/exclude; caps against pathological files; encrypted exports (Bitwarden password-protected JSON, Dashlane secured) are detected and rejected with actionable guidance
  - **Cloud wiring**: the batch persists with ONE encryption + ONE push; the report shows the transport (Google Drive / Dropbox / GitHub Gist / WebDAV / custom) with a "Sync again now" action
- Works on ALL websites (no blocklist)

## Intentions

1. **Be the most honest password manager** — no hidden server, no tracking, no lock-in. The user owns their data, their keys, and their cloud.

2. **Be the easiest to set up** — guided wizard walks the user through each transport step-by-step. No developer knowledge required.

3. **Be the most secure** — two independent encryption keys (master passphrase + sync code), client-side encryption only, zero plaintext ever leaves the device.

4. **Be the most portable** — works on ANY Chromium browser (Chrome, Brave, Vivaldi, Arc, Edge, Ungoogled Chromium). The sync code works across all transports. Manual export works offline.

5. **Be the most transparent** — fully open-source, auditable, no proprietary algorithms, no server-side logic.

6. **Be free** — no subscriptions, no premium tiers, no account requirements, no data collection.

## Comparison with Other Tools

| Feature | UCrypt | Bitwarden | 1Password | LastPass | Chrome PM |
|---------|--------|-----------|-----------|----------|-----------|
| Open source | ✅ | ✅ | ❌ | ❌ | ❌ |
| No account needed | ✅ | ❌ | ❌ | ❌ | ❌ |
| Choose your cloud | ✅ | ❌ | ❌ | ❌ | ❌ |
| Auto-fill all sites | ✅ | ✅ | ✅ | Freemium | ✅ |
| Breach monitoring | ✅ | Premium | ✅ | Premium | ❌ |
| Offline password gen | ✅ | ❌ | ❌ | ❌ | ❌ |
| BIP-39 mnemonic gen | ✅ | ❌ | ❌ | ❌ | ❌ |
| URL wordlist scraper | ✅ | ❌ | ❌ | ❌ | ❌ |
| QR code pairing | ✅ | ❌ | ❌ | ❌ | ❌ |
| Works on Brave | ✅ | ✅ | ✅ | ✅ | ❌ |
| Free (no subscription) | ✅ | Freemium | ❌ | Freemium | ✅ |
| No server dependency | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Universal import (17 dialects incl. bookmarks/history/notes/cards/2FA seeds)** | ✅ | Paid-tier CSV | ❌ | ✅ (passwords only) | ❌ |

## Technical Stack

- Manifest V3 (Chrome Web Store compatible)
- Web Crypto API (crypto.getRandomValues, AES-GCM, PBKDF2, SHA-256)
- chrome.storage.local + chrome.storage.sync
- chrome.alarms (daily breach check)
- chrome.notifications (breach alerts)
- Content scripts (form detection + auto-fill)
- No external dependencies — all JS bundled

## Version

v3.45.0 | Released 2026-11-03 — R181 "THE UNITED HOUSE" (one face, one session, forever). G333 THE ONE FACE: the Cloud Sync area's design extracted as canon (docs/R181-UI-CANON.md) and every area aligned additions-only — the Device Transfer tab unified first (canon card/status rows/buttons, the quick-nav transplanted, the embed header law alive, the beamJoin dialog canon classes), Cloud Sync the DEFAULT landing area (unlocked → sync; locked → unlock first, then the VAULT_UNLOCKED listener follows the unlock to Cloud Sync), the Wordlists empty-state CTA, the sync-chip err arm, the Direct Share tokens. G334 THE FOREVER SESSION: the renewal-era reconciliation (a newer custody mint answers 'renewed', never 'expired'), the tri-state custody row (CONNECTED / LOCKED-WILL-RESUME / SIGNED-OUT) ×3, the VAULT_UNLOCKED listener, the typed burn predicate re-proven (docs/R181-SESSION-MAP.md names the seats Q1–Q7). i18n 3,635 ×3.
v3.44.0 | Released 2026-11-02 — R180 "THE SEAL REBORN" = R179‡ "THE FOREVER CUSTODY" (‡ the workspace's own round title; the version ledger in AUDIT.md names every version between the R178 seal and this floor — 3.39.0–3.43.0 included — and the packer refuses to seal an unrowed version). The sign-in that never expires on UCrypt's side (the Lane C bank, the custody renewal clock, the save-door merge, the typed death only); the packer as the ONLY seal road (BUILD.json v3.44.0 with its own builtAt + its own recomputed payload digest — the unsealed v3.43.0 custody drift is dead at the root); the cycle row speaks ×3 (the named empty, the pull evidence, the merge fingerprints — 12 additive keys, presence-validated); the UI maturing (the Sync quick-nav, back-to-top, the empty-vault CTA, the last hardcoded-English cure); i18n 3,625 ×3.
v2.45.0 | Released 2026-10-04
v2.45.0 | Released 2026-10-04
v2.45.0 | Released 2026-10-04
v2.44.0 | Released 2026-10-04
v2.43.0 | Released 2026-10-04
v2.42.15 | Released 2026-10-02
v2.42.14 | Released 2026-10-02
v2.42.13 | Released 2026-10-02
v2.42.12 | Released 2026-10-02
v2.42.11 | Released 2026-10-02
v2.42.10 | Released 2026-10-02
v2.42.9 | Released 2026-10-01
v2.42.6 | Released 2026-10-01
v2.42.5 | Released 2026-10-01
v2.42.3 | Released 2026-09-29
v2.42.2 | Released 2026-09-29
v2.42.1 | Released 2026-09-29
v2.42.0 | Released 2026-09-28
v2.41.4 | Released 2026-09-28
v2.41.1 | Released 2026-09-28
v2.41.0 | Released 2026-09-28
v2.40.1 | Released 2026-09-28
v2.36.0 | Released 2026-09-25
v2.21.0 | Released 2026-09-22
v2.20.0 | Released 2026-09-22
v2.19.0 | Released 2026-09-22
v2.18.0 | Released 2026-09-22
v2.17.0 | Released 2026-09-21
v2.16.0 | Released 2025-09-23

- **v2.41.0 — Clinical Feature Reconciliation and Secure Recovery (R56)**: screenshot-evidenced restoration of lost canonical UX from quarantined lineage-B prior art — popup generator advanced controls, the resizable window-layer surface model (Vault window + settings gear + truthful tab fallback), the Sync & Devices card with re-authenticated Add-device reveal (verify-and-forget passphrase check, 60 s exposure countdown, words-only QR payload), Import Center browser-detection banner + override, and the light-theme CSS-variable fix (EV-3 bug regressed into the current generation). Insecure legacy flows (user-pasted Google client secret, Dropbox app-secret OAuth) documented and never restored; Channel A blocked pending owner authorization; five docs/feature-change-approvals/R56-<id>.md records; no source deletion.

- **v2.40.1 — Immutable Candidate and Owner Sign-off (R53)**: a version label must identify exactly one immutable byte sequence — the R52-era v2.40.0 Preview candidate (sha256 b323f009…, owner-stated) was superseded when its source tree changed before owner acceptance, so no v2.40.0 bytes may ever be served again and this patch version is the new immutable Preview candidate (archive SHA-256 published in releases/RELEASES.json; the packer refuses to overwrite an existing archive). The release ring models three distinct states — retracted (v2.39.0, SYNC SAFETY / Finding #121), superseded (v2.40.0), preview (2.40.1, Channel B) — with stable null and latest.tar.gz retired until an owner-accepted stable exists. Finding #121 (an unreadable remote treated as observed, letting syncNow upload over a copy it failed to read) is differentially PROVEN against the real vulnerable v2.15.0 archive bytes and DISPROVEN against extracted v2.40.1 bytes across the full failure matrix (malformed/HTML, empty/lost-write, wrong recovery words/foreign envelope, GCM failure, 401/429/5xx, network failure) with zero uploads and a byte-identical remote digest in every unreadable state; confirmed absence (404) remains the only state permitting a first-device push. A permanent candidate-identity guard compares archive BYTES (manifest version + build payload marker) against RELEASES.json and fails the release on any disagreement, on acceptance-JSON drift, on latest.tar.gz existing while stable is null, or on a retracted/superseded candidate being exposed. The in-extension owner acceptance route (Options → Security) displays the exact build payload hash + channel + runtime ID, the #121 cloud-safety outcome, and the last operation ledger — it can never set approved:true and never fabricates an in-session cloud-safety pass. Channel A (native Google Drive OAuth) stays a separate owner decision: scaffold, drive.file-only constraint, PKCE S256 fixture gate and client-secret scanner preserved, Drive OAuth disabled in the Channel B preview, no client secret anywhere.

- **v2.36.0 — Production Trust**: worker-memory-only unlock (session persistence REMOVED, sentinel-proven across all six vault states), credential-envelope sealing of every cloud secret (AAD-bound, locked sync reports locked), opt-in native-manager control with literal browser values (Chrome 153 matrix), Mode-2 honest cloud copy + Device Flow spike (unshipped), one-command release validation with manifest completeness enforcement.

- **v2.21.0 — Lazy Corpora + Popup Density + Large-Vault Virtualization**: the R29 record's declared next lenses shipped. The first design lazy-loaded the corpora in the service worker too — and the real-browser journey caught Chromium rejecting dynamic import() on ServiceWorkerGlobalScope (w3c/ServiceWorker#1356; module workers included), so the corrected split keeps breach.js STATIC in the worker (its three consumers — daily breach check, save-prompt strength verdict, health report — stay guaranteed-live) and drops wordlists.js from the worker entirely (the SW never generates passphrases): the worker wake parses 118 KB less. The popup/options pages stop loading both corpora as classic script tags (211 KB less parsed on every open — the popup is the most-opened surface) and load them lazily via lib/corpus.js (cached dynamic import, legal in pages and browser-proven), which VERIFIES the corpus global after load — missing data is a loud error through the normal failure paths, never a silent "no breaches" report (R30-F1). The popup gained a persisted compact-list toggle (single-line rows, tighter padding, ~2× visible entries; aria-pressed + localized tooltip) applied before first render (R30-F2, Brave parity). The options vault manager renders in 120-row chunks with an IntersectionObserver sentinel plus a keyboard-accessible "Show the remaining N entries" button; a per-password analysis memo removes the O(vault) analyze cost per keystroke; the search box and sort selector re-render from a local cache instead of a full round-trip per keystroke (R30-F3). Lens-reversal: an audit finding briefly attached a transportError note to the pull's garbage-skip exit — the round-25 battery caught it (setSyncCode reads the note-less shape as the KDF-upgrade signature and pushes; with a note it wrongly defers) — the finding was corrected, the contract documented at the exit and pinned by tests; stale classic-script/full-jitter doc comments corrected. Catalogs at 749 keys × 3 locales.
- **v2.20.0 — MV3 Wake-Session Restore + Backoff Floor + Unreadable-Remote Gate**: the lens-reversal audit caught the defect no journey could see — initVault() ran only on install/startup, so every service-worker recycle (~30s idle) woke with DEFAULT state while chrome.storage.session still held the unlocked session; the popup answered hasMaster:false and offered the SETUP WIZARD to an already-unlocked user (one accidental click from overwriting the vault), and the configured idle auto-lock degraded to the worker's lifetime. A per-lifetime boot promise now restores the session on every wake — the message router, the alarm handler and the unlock-pull debounce await it. The retry backoff traded full jitter for EQUAL jitter (delay in [cap/2, cap); a 0ms retry that could hammer a just-failed endpoint is impossible). The pull's transport leg no longer claims readable before the envelope/decrypt checks — a cloud copy this sync code cannot read downgrades to unreadable and is NEVER pushed over, with its own truthful reason (the 27a-3 fix the R27 record claimed but the source never carried). The card/identity picker declares its 8-row overflow honestly; a String(null) wart that rendered "— null" in the Sync row is dead; the 14 catalog keys with duplicate-case placeholder declarations dropped the dead ones (747 keys × 3 locales). New round-29 battery → 25 harnesses.
- **v2.19.0 — R27-Delta Audit + Card/Identity Form-Fill + i18n Completion**: the round audited the round-27 code itself and closed what its record claimed but the source lacked — a WebDAV 404 download clears the stored If-Match ETag (a server-side file deletion used to brick every recovery push with a permanent 412), wipe/transport-clear drop every derived state key, setSyncCode pulls BEFORE pushing on the existing-vault path, a skipTransport pull no longer converge-pushes over an unconsulted transport, and the garbage-skip sync exit renders as a failure — plus subtree anchor tracking, ArrowUp wrap, other-data-editor Enter-to-save + Tab trap, a summary-safe Enter guard, the locked prompt's small-frame gate, case-safe uris with trailing-dot strips, and a bounded error-body prefix read. Brave parity round three: imported cards and identities FILL real web forms via "Fill card / Fill identity" context menus — autocomplete-spec detection first, machine-name heuristics before human labels, select option-matching, a combined MM/YY expiry collapse, and a picker overlay for several entries. i18n waves 2/4/5/6 landed (transport wizard, vault rows/dialogs, popup health/sync, content overlays) — catalogs at 746 keys × 3 locales. New round-28 battery → 24 harnesses.

- **v2.18.0 — i18n Depth + Structured Data Editing**: a clinical audit of the round-26 code itself closed thirteen findings — the WebDAV ETag now tracks the last write (no more spurious 412 every other push) and never replays weak etags; the autoSyncTick retry no longer pushes over an unobserved remote; empty bridge answers are lost writes, not absences; caller aborts cut the retry backoff; Dropbox 409-as-absence requires the not_found tag; 5xx outages are no longer "invalid token"; the GitHub upload requires its files contract; the Custom-URL redirect guidance actually fires; the auto-fill bubble tracks scroll/resize; the locked prompt owns its overlay; the popup theme updates live. The other-data editor now edits everything — card number/expiry/CVC, identity fields, custom fields[], and history/form entries gained edit buttons with URL editing — with vault-side validation and holder/name mirroring; unrepresentable import rows are reported instead of vanishing; the cap-warning copy leak finally shipped fixed. The Import Center and the options-page static copy moved into the catalogs with German and Simplified-Chinese translations (217 new keys, 430 per locale in parity). 52 new checks → 1067 across 23 harnesses.

- **v2.17.0 — Cloud-Upload Hardening II + Brave-Parity II**: syncNow can no longer push over an unobserved remote (three-state transport pull); Google Drive enforces its JSON bridge contract (an HTML sign-in page is a failure, not a success) over HTTPS-only; GitHub gist discovery is three-state with pagination (a transient failure can never fork a second vault) and refuses over-cap blobs before the wire; 409/403 semantics are operation-aware (upload conflicts ≠ "first device", GitHub rate limits carry their reset time); Dropbox 401 teaches the four-hour token truth; empty stored files report a lost write instead of "nothing yet"; WebDAV gained If-Match optimistic concurrency and a PUT redirect guard; the options Sync tab shows failed pushes and Pull is pull-only; Bitwarden multi-URI imports land as alias domains; global Offer-to-save + Auto sign-in toggles gate only the proactive prompts; the editor gained a live strength meter, Enter-to-save and a focus trap; the auto-fill bubble anchors to the field with keyboard navigation, an "All logins…" hatch, and Esc closes every overlay; the popup honors the shared theme. 98 new checks → 1026 across 22 harnesses.
- **v2.16.0 — Brave-Parity Features + Upload Hardening**: the round dispatched three clinical audit agents over every path of the extension and implemented the findings: user-configurable auto-lock (1–60 min or Never, live-applied, popup hints render the real interval), alias domains per login (multi-URI serving at exact rank 0), device-local last-used tracking with a shared four-mode vault sort (Site / Username / Recently used / Recently changed), capped password history with Copy + Restore inside the entry editor, options-row Copy-username, and the context-menu save honoring the never-save exception. The upload path was hardened end-to-end: a single-flight sync mutex, no double-push in syncNow, an empty-vault push guard on every transport, Google Drive routed through the shared fetchWithRetry, real service error bodies surfaced, 429/503 Retry-After respected, Gist truncation detected, captive-portal HTML answers fail uploads truthfully, and push telemetry (bytes + duration) in the Sync tab. Proven in real Chromium: 71/71 frozen-source checks (journey 25) + 38/38 feature checks (journey 25b), zero console errors; 88 new unit checks → 928 across 21 harnesses.
- **v2.15.0 — Cloud-Truth Hardening**: the sync architecture made truthful and complete. The zero-config chrome.storage.sync first hop (lib/vault.js, chunked under the 8,192-byte item quota) now records an outcome ledger on EVERY write path — including the setSyncCode/restore push that used to bypass it — and the popup Sync tab gained a "Built-in browser sync" row that always shows a definite state (✓ chunks · time, or ⚠ the reason + guidance to configure a cloud transport): signed-out and de-Googled Helium-class profiles are no longer invisible. Dropbox + GitHub gained an optional advanced API-base-URL override (defaults unchanged) enabling gateways/proxies; the E2E rig emulates the real wire protocols of the Drive bridge, Dropbox REST and GitHub Gist REST, and a real-Chromium journey proved all three families end-to-end (device B adopting device A's exact gist — the anti-split-brain fix — plus a 120-row stress import, duplicate-import idempotency, live context-menu/command probes, and the live Chinese catalog). 50 new unit checks; 840 checks across 20 harnesses.
- **v2.14.0 — Different-Perspectives Journey Hardening**: round 23 re-attacked the product from angles no earlier round had browser-proven — 68 automated in-browser checks across three real Chromium devices, catching two real defects. **R23-F1 (HIGH)**: the extension-page CSP (`connect-src 'self' https:`) blocked the Wordlists-tab URL scraper on every `http://` page — the shipped feature died with "Failed to fetch"; the CSP now allows `http:` connections (still stricter than Chromium's MV3 default, which has no connect-src restriction) and the scraper is proven live end-to-end. **R23-F2 (MEDIUM)**: the popup Sync tab's "Entries" row counted logins only — a vault with imported notes/cards reported 5 while the synced blob carried 7; `getSyncStatus()` now exposes `totalCount` and the popup shows it. Newly browser-proven: the generator→signup loop (a GENERATED password fed into a real signup form, saved, served byte-identical), Firefox CSV + Bitwarden JSON imports (login + note + card, PAN spaces stripped), the imported-note EDIT dialog with a unicode patch verified in the vault and after sync, master-passphrase rotation (wrong-current is a provable no-op; old passphrase DEAD after rotation), per-site never-save exceptions (prompt blocks, removal restores), the Wordlist scraper, the popup health report, the Custom-URL transport over self-signed HTTPS (Test/Save/Sync-now, blob verified server-side), device-B restore through it (edited note intact), and a REAL browser restart (same profile: vault persists, session dies, vault returns LOCKED, rotated passphrase admits). Two environmental discoveries documented: the extension's own 0.5-min auto-lock alarm keeps the MV3 worker immortal (alarm wakes reset Chromium's 30s idle timer), and `chrome.runtime.reload()` re-confirmed the R22-F5 pathology. The German catalog was proven LIVE (`--lang=de` renders "Jetzt sperren"/"Erzeugen"). 36 new unit pins (tests/round23-test.mjs) bring the battery to 789 checks across 19 harnesses.

v2.13.0 | Released 2025-09-21

- **v2.13.0 — Deepest-Journey Field Hardening**: round 22 drove the real-Chromium journey one level deeper — 87 automated in-browser checks feeding data into every field type a login flow uses (email/tel usernames, password+confirm twins, current/new/confirm triplets, hidden/disabled/search/readonly traps, unicode secrets, two-step navigation, big and ad-sized iframes, 6-box OTP splits, multi-account pickers) — and caught four real defects, all fixed. **R22-F1 (HIGH)**: change-password forms captured the OLD password and ignored the NEW one; the capture now prefers a typed `autocomplete=new-password` field (submit watcher + context-menu save). **R22-F2 (MEDIUM)**: logins submitted inside small embedded frames were silently dropped; the save prompt now relays to the top frame through the worker (`SAVE_PROMPT_RELAY` → frameId 0), the way Chrome anchors its bubble outside the ad. **R22-F3 (LOW)**: readonly username fields are no longer fill candidates. **R22-F5 (HIGH)**: vault file-import restarted the whole extension (`chrome.runtime.reload()`), killing every open page and sometimes leaving the worker unbooted; the import now applies in place via `VAULT_IMPORT_APPLIED` → `reloadFromStorage()` (session cleared, keys dropped, storage re-read, truthful locked state). Also verified live: a second real transport (WebDAV over HTTPS with UTF-8 Basic auth) tested/saved/pushed, device-B restore, B→A rotation converging by LWW, B→A deletion propagating by tombstone, live alarm cadence (sync every 15 min), Chrome CSV import with quoted commas, and the own-export → wipe → re-import round-trip with the 2FA token intact. 57 new unit pins (tests/round22-test.mjs) bring the battery to 753 checks across 18 harnesses.
- **v2.11.0 — Form-Fill Serving Hardening**: a clinical audit of the fill /
  password-serving pipeline (content script → GET_ENTRIES → vault → back into
  the page) found and fixed eight defects (F1–F8). Serving: imported
  bookmarks/history can no longer surface as "saved logins" (bookmarks carry
  real hostnames; Fill used to write an EMPTY password over what the user had
  typed); serving matches per SITE (eTLD+1, Chrome/Brave parity) with
  exact-domain matches ranked first and the most recently updated login first
  in the list. Coverage: a debounced MutationObserver re-scan catches login
  forms SPAs mount after load (no watcher = no save prompt, ever); content
  scripts run in ALL frames (iframe login widgets) with a frame-size gate that
  keeps passive overlays out of tiny ad/tracking frames; two-step flows
  remember the username typed on step 1 via REMEMBER_USERNAME /
  GET_LAST_USERNAME — background WORKER MEMORY only, keyed by tab+domain,
  30-min TTL, 500-entry cap, never persisted, never synced. Honesty: the
  locked-vault prompt no longer claims "saved logins exist" (a locked vault
  cannot know that). Plus: the in-page submit-button finder re-aligned with
  lib/form-detector.js. Verified end-to-end in a simulated Chromium browsing
  session (8 scenarios, 48 in-browser checks, 0 console errors) plus the unit
  battery.

v2.10.0 | Released 2025-09-20

- **v2.10.0 — Localization & Data Stewardship**: a real chrome.i18n foundation —
  _locales/ catalogs in English, German and Simplified Chinese (176 keys, full
  parity, placeholder-validated), manifest default_locale + __MSG_ strings so the
  extension NAME and command descriptions localize in chrome://extensions and the
  store listing, localized context-menu titles and every background notification
  ($DOMAIN$/$ERROR$/$COUNT$ substitutions), and a data-i18n applier that
  localizes the full popup and the options navigation chrome with graceful
  English fallback (the HTML stays the source of truth — nothing is ever wiped;
  deep body copy tracked for v2.11+). Imported "other data" gains its missing
  EDIT flow: notes, cards, identities and bookmarks are retitled, re-noted and
  moved via a type-aware dialog backed by the atomic UPDATE_OTHER_ENTRY (one
  mutation, one persist, one cloud push, tombstoned renames; the pseudo-domain
  key model keeps logins untouchable and cross-type collisions impossible).
  updateEntry validation consolidated. TWO defects caught during browser QA and
  fixed: the other-data pane's Edit/Delete buttons were dead (NUL-joined keys
  inside HTML attributes are corrupted to U+FFFD by the HTML parser — the same
  root cause silently broke the pane's Delete since v2.8.0), and the senders'
  `{ type, ...data }` serialization let a payload `type` field clobber the
  message type on the wire (fixed with payload-first spreads + `entryType`).
  New files: lib/i18n.js, _locales/{en,de,zh_CN}/messages.json. 43 files.

- **v2.9.0 — Site Controls & Data Ownership (deep Brave-parity round)**: per-site
  "Never save" exceptions (save-prompt button, context-menu item, Security →
  Site settings; device-local like Brave's; autofill unaffected); save prompts
  that say what they do ("Update password for this login?" for existing
  usernames with a new password) with a pre-accept weak/breach warning from
  the offline analyzer; domain-ranked 2FA tokens in the page chip (exact ★ /
  same-site ◦ first); ATOMIC entry updates (UPDATE_ENTRY replaces the
  DELETE-then-SAVE edit path that could lose an entry on failure); two
  data-loss fixes (password updates and imports no longer wipe a login's
  imported note/fields/folder); per-login notes; hidden-by-default passwords
  with a reveal toggle; plaintext CSV export for migrating OUT
  (double-confirmed, Chrome dialect, never exports 2FA seeds); health-report
  CSV export in the popup. New files: lib/sites.js, lib/export.js. 39 files.

- **v2.8.0 — Cloud Lifecycle Hardening**: the import → cloud → restore pipeline clinically verified end-to-end. Restore-safety fix (a fresh device now PULLS and adopts the cloud copy before any push — the previous code clobbered the cloud with an empty vault because an empty array is truthy), awaited + recorded transport pushes with a truthful "Last cloud push" status in the Sync tab and popup, sync cadence locked in (push on every change; pull at every unlock, every 15 minutes via alarm, on chrome.storage.sync changes, and on demand; failed-push auto-retry), a 4-step cloud setup strip, a transport-without-sync-code warning, type-aware deletes for imported data, and logins-only sync counts. 37 files.
- **v2.7.0 — Universal Import Center**: migrate everything (passwords, notes, cards, identities, TOTP seeds, bookmarks, history, form data) from 17 source dialects — Chrome/Edge/Brave/Vivaldi/Opera, Firefox CSV+JSON, Safari, Bitwarden CSV+JSON, LastPass, 1Password, Dashlane, KeePassXC/KeePass, RoboForm, NordPass, Enpass, bookmarks HTML, history CSV/JSON. Auto dialect detection, per-category preview + selection, never-overwrite at plan AND save layers, one-encryption/one-push batch persistence, cloud transport status in the report. New file: lib/importers.js. 37 files.
- **v2.6.0 — Brave/Chrome parity round**: in-page "suggest strong password" (signup/new-password fields; fills password + confirm twin), context-menu integration (fill / suggest / save, http(s)-scoped), keyboard commands (Ctrl+Shift+L / Ctrl+Shift+U), and browser CSV import (Chrome/Brave/Edge, Firefox, Bitwarden dialects) with a never-overwrite policy. New file: lib/csv-import.js. 36 files.
- v2.5.0: Health Report (vault-wide offline audit with 0-100 score), 2FA autofill on sites, QR PNG export
- v2.4.0: TOTP authenticator + deletion-proof tombstone sync
- v2.3.1: prefs preservation + inline save errors
- v2.3.0: transport hardening + versioned sync KDF (600k)
- v2.2.0: clinical-audit hardening (7 findings fixed)
- v2.1.0: original audited release
