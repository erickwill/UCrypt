# UCrypt v3.45.0

The whole house now speaks with one voice: this release unifies every screen of the
extension, trims the repository down to what users actually need, and ships only after
full clinical verification. No subscription, no account, no telemetry — same as always.

## One face across every surface

- All eight settings tabs now lead with interactive summary pills and a quick-action
  toolbar. Click a pill or an action and the page opens the right card, scrolls smoothly
  to it, and focuses the control you need. Upgraded tabs: Vault, Security, Direct Share,
  Generator, Wordlists, and Export / Import.
- Task-first ordering: Vault Manager sits directly under the Vault card. Everything
  secondary — password health, vault health, autofill guide, sync doctor, device chain
  data, share ledger, diagnostics, bookmark restore, cross-browser import — now lives in
  collapsible sections that remember whether you left them open.
- The popup shows the same Cloud Sync status bar and pills as the settings page. One
  visual language, everywhere you look.
- Removed a developer-only panel and fixed contradictory copy in the mode banner.

## Documentation that respects your time

- Removed 17 internal development artifacts from the repository.
- docs/ now contains only the product guides: the Quickstart and the full user guide in
  English, German, and Chinese.
- README, DESCRIPTION, SECURITY_DECISIONS, VERSION, BUILD.json and the manifest were
  rewritten for readers, not for the workshop — no internal round codes, no law numbers,
  no jargon.

## Verified before sealing

- Unit tests: 21 / 21 passing.
- Live browser verification: 37 / 37 assertions passing across 10 suites, covering 27
  issues found and fixed this round.
- Verified in headless Chromium at 1440×900 and 460×720, with zero console errors — both
  inside chrome://extensions and in standalone browser tabs.

## Download and verify

Grab `ucrypt-extension-v3.45.0.tar.gz` from the Releases section, then check it before
use:

```
sha256sum ucrypt-extension-v3.45.0.tar.gz
```

The output must match:

```
54526b611784686aebcd6624d5bceb0ae322159d019c3d1a5fe8f187e67de3d8  ucrypt-extension-v3.45.0.tar.gz
```

(macOS: `shasum -a 256 <file>` · Windows: `certutil -hashfile <file> SHA256`)
