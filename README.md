# UCrypt

A password manager for Chromium browsers — Brave, Edge, Helium and more. Works in Chrome too.
Your vault stays on your device, encrypted with your key. Optional backup goes to your own
Google Drive, encrypted before it leaves your machine.

## Why another password manager?

Because the good ones all ask for the same three things: a subscription, an account on
their servers, and your trust that nothing will ever go wrong on their side. UCrypt asks
for none of that.

- **No subscription.** Everything works, free for personal use. Not a trial, not a free
  tier with the useful parts locked away.
- **No account with me.** Nothing to register, no email to hand over. Install, set your
  key, done.
- **No servers of mine.** There is nothing of mine to breach — no central database holding
  everyone's vaults. The quiet part of security is not collecting what attackers want.
- **No telemetry.** The extension doesn't phone home. Ever.
- **Your backup lives in your Drive.** Turn sync on and the vault lands in your own Google
  Drive — not mine — already encrypted, so not even Google can read what's inside.

1Password and Dashlane are subscriptions. Bitwarden wants an account on their servers.
LastPass has had more breach headlines than most people have passwords. UCrypt keeps your
secrets where they belong — on your machine, under your key — and charges you nothing.
Free for personal use isn't a promotion here. It's the point. Safety shouldn't be a
subscription.

## License

PolyForm Noncommercial License 1.0.0 (see LICENSE). Free for personal, non-commercial use.
Commercial use needs a separate license from the author (erickwill@gmail.com).

## Releases

The source tree on main mirrors the sealed release. The sealed tarball is the artifact —
verify it before use:

- Version: v3.48.0
- Built: ucrypt-extension-v3.48.0-hardened.tar.gz
- sha256: a7ed9aa85827c3db96e40e83dc552ed51f1871f0130d079762ece89f7f945bfd

Verify it:

```
sha256sum ucrypt-extension-v3.48.0.tar.gz
```

The output must match the digest above.
