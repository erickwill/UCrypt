# FEATURE-PARITY-MATRIX — R154 (LAW #94: nothing silently absent)

> Maintained by the R154 engineering session (verification lane). Opened per the
> R154 contract §10 (P.1–P.3). Every row: the CLAIM (provenance) × the v3.10.0
> bytes (disk) × the typed verdict × the cure or the consent. The matrix re-opens
> at every future round before new work (P.3).
>
> CLAIMS SOURCES ON THIS VOLUME: the worklog's QA-144 provenance record (the
> R143/R144 authority chain, reprinted so it survives the rollback), the R153
> claims audit (K-153-01..12), the field anchors E-1/E-2/E-3, the owner's §18
> consent rows. THE DETAIL MIRROR (B1, the R152 transcript) IS ABSENT ON THIS
> VOLUME — typed honestly, re-delivery requested; rows that need its detail
> type UNREHYDRATED-CLAIMED instead of an invented feature list (the
> no-hallucination law binds this matrix as hard as code).

Floor: v3.10.0 — sha256 8f18604eb6bada4fbbef6329a6f31608155597a4e0c8aea224426c7917a0dc85
(1,576,978 B, 161 members, 0444, three custody positions — re-proven at the R154 open)

## A. The sealed-lineage rounds (provenance-anchored, bytes lost to the rollback)

| # | Round / seal (provenance) | Claimed class | In the v3.10.0 bytes | Verdict | Cure or consent |
|---|---|---|---|---|---|
| 1 | R143 — v3.0.0 THE HANDSHAKE (sha 3fcebb7e…, 1,600,827 B, 160 members) | the sealed handshake: bundle build, code exchange, reply binding | PRESENT-CLASS — the R142-era bridge carries the whole class (lib/bridge/signal.js: buildOfferBundleText / words token / multi-frame frames; lib/bridge/page.js: the sealed offer/answer bundles, single-use, TTL); the R153 manual bridge made it first-class | PRESENT (class) · UNVERIFIABLE-BYTE-EXACT (the R143 bytes are lost) | No cure owed on the class; the R154 bond doors complete the SAME-CHAIN pairing over it (in flight — see B.2) |
| 2 | R144 — v3.1.0 THE CHAIN SHARE (sha 0a8427d3…, 1,619,011 B, 161 members) | chain-wide dataset share (logins/forms/configs), newest-wins + tombstones + conflict copies + merge summary | PRESENT — lib/beam3/chainshare.js (477 lines), lib/share/dataset-share.js, tests/r153-dataset-share.test.mjs; the R153 seal carried S-2 with the merge summary BEFORE commit | PRESENT | S-3 (history sync) stays OUT OF SCOPE — the owner's explicit ruling, carried verbatim in BUILD.json/VERSION (consented carry) |
| 3 | R145–R147 (the QA cadence rounds) | per-round feature claims | UNREHYDRATED-CLAIMED — the round records were erased by the rollback; the transcript mirror (B1) is the only detail source and is ABSENT on this volume | ABSENT-ON-VOLUME (claims) | Rehydration is B1-gated (contract §10.4); re-delivery requested at LINE 1 (LAW #96); never re-invented from memory |
| 4 | R148–R152 artifacts (the E-2 typed-error pins, the H-ledger, the wake map, the 41-second budget's original landing) | the evidence/verification artifact set | UNREHYDRATED-CLAIMED (same B1 gate); the R153 seal re-typed what the bytes could prove: Z-1 typed, the wake ladder pinned ≤31 s, C-2 the OAuth named errors | ABSENT-ON-VOLUME (artifacts) | Same B1 rehydration pass; the R154 gates (G123–G135) re-earn the classes fresh |

## B. The field anchors (the owner's evidence — the requirements rows)

| # | Anchor | Field fact | Root cause on the v3.10.0 base | Verdict | Cure |
|---|---|---|---|---|---|
| 1 | E-1 (Screenshot_20261022_204112.png, sha d6a199dc… — verified Table A) | DEVICE TRANSFER BLIND AT STEP ZERO: both instances show "No other device is in your chain yet." | H-6 PROVEN by the static audit: the roster read ONLY the cloud-learned sealed peer map + the cloud presence stamps; the join marked the roster dirty for the NEXT CLOUD envelope; with every cloud dead the roster was honestly empty forever. The R143–R152 direct-layer roster never re-materialized | ABSENT (the missing organ) | THE R154 CURE (in flight, verified on-contract): the device bond door (BRIDGE_BOND_SEAL/BOND_LEARN — the A.2.e same-chain gate, group-key sealed stamps) + THE ROAD-LEARN (every handshake learns the counterparty into the ONE sealed peer map, chrome.storage.local, G123 persists, lastSeen stamped at learn = presence writes the roster, cloud-less) |
| 2 | E-2 (Screenshot_20261022_204425.png, sha 100a1615…) | MNEMONIC DEAD: "Generate phrase" renders nothing | ROOT CAUSE TYPED (options.js:5971): LAB_GENERATING_MODES omits 'mnemonic' → switchLab:6006 hides the shared output card → renderLabSecret:6288 renders into display:none. The phrase was generated, then shown nowhere | ABSENT (the render) | THE R154 CURE (in flight, verified): the inline phrase card — the phrase rendered DIRECTLY BELOW the button (the owner's spec), copy/reveal/regenerate, zero-console class |
| 3 | E-3 (Screenshot_20261022_204731.png, sha e1bec193…) | DIRECT SHARE WORKING end-to-end (invitation code, countdown, reply paste, Connect reply) | The invitation/confirmation machinery IS in the base (the R112 direct-share line + the bridge engine) — the proven engine the contract orders ARC A to build ON | PRESENT (the model) | Protected: G134 re-tests the door on every engine-level touch; no transport rewrite (LAW #95: doors differ in SCOPE, never in MACHINERY) |
| 4 | §18 the owner's voice | "The previous version ucrypt-extension-v3.7.0 had it working perfectly!" — the v3.7.0-class pairing/transfer is the requirements row | The v3.7.0 bytes are not on this volume (the archive ends v2.99.0); the WORKING BEHAVIOR is anchored by the owner's memory + the field evidence | ANCHOR (not bytes) | P.2: the working behavior is the default wherever the current base differs; every divergence is typed in the close record |

## C. The floor versions (custody truth)

| Version | Bytes on this volume | Status |
|---|---|---|
| v3.7.0 (the owner's last working field version) | ABSENT (archive ends v2.99.0) | The parity ANCHOR by testimony, not bytes (P.2) — typed |
| v3.9.0 (7e313490…, the R153 contract's floor) | ABSENT — NOT re-provable on this volume (the R153 open typed it; the owner's B6 capture proves it RUNS in her custody) | The two-domain law (LAW #96) carries: her copy is the second domain |
| v3.10.0 (8f18604e…) | PRESENT, pin-exact ×3, 0444 | THE FLOOR — re-proven at the R154 open; archives byte-exact at close per the rotation law |
| v3.11.0 (the R154 target) | TO BE SEALED at close (§16.3) | The rotation: the workspace becomes v3.11.0; the owner is asked to download and keep the seal |

## D. The standing consented carries (nothing here is a defect)

1. S-3 history sync — OUT OF SCOPE pending the CEO's explicit ruling (the R153 contract typed it; the owner's later-hour field read governs ARC C).
2. The rotating 25th sync word (Brave's class) — logged as a cherry-pick candidate in docs/brave-model.md; ships only on a future contract.
3. The canonical UI freeze — inherited surfaces are not redesigned; ARC A/B touch broken or new-feature surfaces only (R-0.5).

## E. The matrix's own law

This file re-opens at EVERY round open (P.3) before new work. Absence is typed,
cured, or consented — never discovered by the owner in the field. The matrix's
rows are re-verified against the actual bytes at close (the G135 gate), and the
restore count + the closure % print in the R154-CLOSE record.
