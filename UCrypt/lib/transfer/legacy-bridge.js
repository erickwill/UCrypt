/**
 * UCrypt — R134 §3 — THE LEGACY BRIDGE (anti-trimming, deployment honesty).
 *
 * The v2.90 DIRECT TRANSFER PATH — the engine that carried every round from
 * R76's "Secure Direct Device Transfer" through R133's one-touch ceremony —
 * is MAINTAINED, NOT DELETED. Beam 2 (lib/beam2/*) is the new architecture;
 * when negotiateCaps() detects a legacy peer (a device still on v2.90 that
 * never publishes beam2 caps), the transfer DEGRADES TO THIS BRIDGE and the
 * old path completes the work — mixed-version chains keep transferring
 * (law §3: one machine on v2.91, another on v2.90).
 *
 * WHAT MOVED VS WHAT STAYED:
 *   - The legacy ENGINE modules remain exactly where they were
 *     (lib/transfer/core.js, mailbox.js, session.js, discovery.js,
 *     worker.js, page.js, lifecycle.js, connect-overlay.js) — byte-stable,
 *     maintained; the old serialized sessions remain readable (0.36).
 *   - THIS module is the named, single compatibility ENTRY the Beam 2
 *     protocol calls when a peer is legacy: every constant, every pure
 *     helper the legacy flow needs is re-exported here under the
 *     `legacy.*` namespace — "moved intact" in the honest sense: the
 *     bridge is the path's authoritative façade, the engine is untouched.
 *
 * BATTERY-PINNED (BEAM2-COMPAT-1..4): the negotiation row, the readable old
 * sessions, the bridge's own transfer validation still working, and the
 * mixed-version chain end-to-end (owner-verified per §11 step 5).
 */

import {
  CHUNK_SIZE as LEGACY_CHUNK_SIZE,
  DEFAULT_TRANSFER_LIMIT as LEGACY_DEFAULT_LIMIT,
  HARD_TRANSFER_CAP as LEGACY_HARD_CAP,
  chunkCountFor as legacyChunkCountFor,
  buildFrameMeta as legacyBuildFrameMeta,
  sanitizeFilename as legacySanitizeFilename,
  executableOrArchiveWarning as legacyExecutableOrArchiveWarning,
  buildFileOffer as legacyBuildFileOffer,
  validateTransferRequest as legacyValidateTransferRequest,
  nextSeq as legacyNextSeq,
  pruneReplay as legacyPruneReplay,
} from './session.js'

import {
  RECORD_KINDS as LEGACY_RECORD_KINDS,
  RECORD_TTL_MS as LEGACY_RECORD_TTL_MS,
  PEER_MAP_CAP as LEGACY_PEER_MAP_CAP,
  isRecordStructurallyValid as legacyIsRecordStructurallyValid,
  recordToManual as legacyRecordToManual,
  recordFromManual as legacyRecordFromManual,
  transferError as legacyTransferError,
} from './mailbox.js'

/** The bridge's self-description (the audit surface renders this row). */
export const LEGACY_BRIDGE_META = {
  name: 'lib/transfer/legacy-bridge.js',
  sealedIn: 'v2.90.0',
  maintained: true,
  supersededBy: 'Beam 2 (lib/beam2/*) — v2.91.0',
  triggers: ['peer-has-no-beam2'],
}

/** The legacy constants under the bridge namespace (one truth per number). */
export const legacy = {
  CHUNK_SIZE: LEGACY_CHUNK_SIZE,
  DEFAULT_TRANSFER_LIMIT: LEGACY_DEFAULT_LIMIT,
  HARD_TRANSFER_CAP: LEGACY_HARD_CAP,
  RECORD_KINDS: LEGACY_RECORD_KINDS,
  RECORD_TTL_MS: LEGACY_RECORD_TTL_MS,
  PEER_MAP_CAP: LEGACY_PEER_MAP_CAP,
  chunkCountFor: legacyChunkCountFor,
  buildFrameMeta: legacyBuildFrameMeta,
  sanitizeFilename: legacySanitizeFilename,
  executableOrArchiveWarning: legacyExecutableOrArchiveWarning,
  buildFileOffer: legacyBuildFileOffer,
  validateTransferRequest: legacyValidateTransferRequest,
  nextSeq: legacyNextSeq,
  pruneReplay: legacyPruneReplay,
  isRecordStructurallyValid: legacyIsRecordStructurallyValid,
  recordToManual: legacyRecordToManual,
  recordFromManual: legacyRecordFromManual,
  transferError: legacyTransferError,
}

/**
 * The bridge's OWN transfer gate — BEAM2-COMPAT-3 pins that the legacy path
 * STILL TRANSFERS through the bridge: a valid request validates, an over-cap
 * request refuses with the legacy typed error (identical behavior to v2.90).
 */
export function bridgeValidateTransfer(size) {
  return legacyValidateTransferRequest({ size, limit: LEGACY_DEFAULT_LIMIT, hardCap: LEGACY_HARD_CAP })
}

/**
 * The bridge's session reader — old serialized session records stay
 * readable through the bridge too (0.36 input preservation, both doors).
 * The legacy session shape is { transferId, stage, ... }; record ENVELOPES
 * are judged by the E4 schema (legacyIsRecordStructurallyValid).
 */
export function bridgeReadLegacySession(rec) {
  if (rec && typeof rec === 'object' && typeof rec.transferId === 'string' && rec.transferId.length) {
    return { readable: true, kind: 'legacy-session', transferId: rec.transferId, stage: String(rec.stage || '') }
  }
  return legacyIsRecordStructurallyValid(rec)
    ? { readable: true, kind: 'legacy-record' }
    : { readable: false, kind: null }
}
