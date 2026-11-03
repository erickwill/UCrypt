/**
 * UCrypt — R153 §4 (R-2/R-4) — THE MANUAL BRIDGE + THE WARM PROFILE.
 *
 * R-2 THE MANUAL BRIDGE (the zero-cloud LAN road — the cure for Z-3):
 *   Hop 1  Peer A "Open a road"  → a WebRTC offer rides a QR / a words token
 *   Hop 2  Peer B "Answer"       → scans / uploads the QR image / pastes the
 *          words, and answers with their own bundle
 *   (the answer completes on A — the DataChannel opens, the chip flips
 *   🟢 DIRECT · LAN; the safety-code human gate still guards every byte)
 *   Two hops, under a minute, zero cloud, zero console — a 13-year-old can
 *   do it. The bundle itself is SEALED by the chain group seal and SINGLE-USE
 *   with a 10-minute TTL (lib/bridge/signal.js — unchanged law).
 *
 * R-2.d THE BINDING: an answer is only valid for the offer it answers — the
 *   session ids must agree and the roles must oppose. A stolen QR answers
 *   nothing without the chain seal; a replayed answer fails the binding.
 *
 * R-4 THE WARM PROFILE: after ANY successful road, the per-pair transport
 *   truth is persisted (device-local, never synced). On a later session the
 *   page attempts the silent re-dial when a signaling path exists; when it
 *   does not, the chip types the EXACT absent ingredient and offers the one
 *   bridge hop — never a silent dead road.
 *
 * PURE — no DOM, no chrome.*, no WebRTC, no keys (the sealing lives where
 * the keys live). Battery-pinned (tests/r153-manual-bridge.test.mjs).
 */

import { parseOfferBundleText } from './signal.js'

export const WARM_PROFILE_VERSION = 1
export const WARM_PROFILE_TTL_MS = 7 * 24 * 60 * 60 * 1000 // 7 days — a stale road re-proves itself
export const WARM_PROFILE_MAX_BYTES = 2048

export function bridgeError(code, message) {
  const e = new Error(message)
  e.code = `MANUAL_BRIDGE_${code}`
  return e
}

/* ── R-2: the two-hop plan (the 13-year-old script, typed) ───────────────── */

/** The typed plan for one side. The page renders it verbatim before Hop 1. */
export function planBridgeSteps(side, { peerName = 'the other device' } = {}) {
  if (side !== 'opener' && side !== 'answerer') throw bridgeError('SHAPE', 'the side is opener or answerer')
  if (side === 'opener') {
    return Object.freeze([
      { hop: 1, line: `Choose the file — the road opens right after (the file waits, nothing moves until the road is up).` },
      { hop: 2, line: `Show the QR to ${peerName} — or send the words below through any messenger. Zero cloud.` },
      { hop: 3, line: `${peerName} scans (or uploads) your QR and answers with theirs — you accept, compare the 6-digit codes, and the road is open.` },
    ])
  }
  return Object.freeze([
    { hop: 1, line: `Get the road offer from ${peerName} — scan their QR, upload the QR image, or paste their words.` },
    { hop: 2, line: `Your answer appears as a QR and words — get it back to ${peerName} the same way.` },
    { hop: 3, line: `Compare the 6-digit codes on both screens — matching codes open the road. Nothing moves on a mismatch.` },
  ])
}

/* ── R-2.d: the answer↔offer binding ─────────────────────────────────────── */

/**
 * Validate that one answer bundle belongs to one offer bundle. Both are the
 * QR/words bundle TEXTS (the same format the doors already exchange). The
 * binding is typed: session agreement, role opposition, answer-after-offer.
 * Throws typed errors — a rejected answer names the exact reason.
 */
export function bindAnswerToOffer(offerText, answerText, { now = Date.now() } = {}) {
  const offer = parseOfferBundleText(offerText, { now })
  const answer = parseOfferBundleText(answerText, { now })
  if (answer.sessionId !== offer.sessionId) {
    throw bridgeError('BINDING', `the answer belongs to a different session (${answer.sessionId.slice(0, 6)}… ≠ ${offer.sessionId.slice(0, 6)}…) — a fresh offer is needed`)
  }
  if (answer.role === offer.role) {
    throw bridgeError('ROLE', `both bundles claim the ${offer.role} role — the answer must come from the other side`)
  }
  if (Number(answer.issuedAt) < Number(offer.issuedAt)) {
    throw bridgeError('ORDER', 'the answer predates the offer — a replay is refused')
  }
  return { offer, answer, sessionId: offer.sessionId }
}

/* ── R-4: the warm profile (device-local, per chain-pair) ────────────────── */

/**
 * The record: which road worked, with which peer, how recently. Stored under
 * `ucrypt:bridge:warm:<deviceId>` by the page (localStorage — device-local
 * convenience, never synced, never a secret: the road kind and the label).
 */
export function encodeWarmProfile({ deviceId, name = '', road = '', savedAt = Date.now() }) {
  if (!deviceId || typeof deviceId !== 'string') throw bridgeError('SHAPE', 'the warm profile needs the peer deviceId')
  if (road && !['direct-lan', 'direct-net', 'relay'].includes(road)) throw bridgeError('SHAPE', `unknown road ${String(road)}`)
  const rec = { v: WARM_PROFILE_VERSION, deviceId: String(deviceId), name: String(name || '').slice(0, 80), road, savedAt: Number(savedAt) }
  const json = JSON.stringify(rec)
  if (json.length > WARM_PROFILE_MAX_BYTES) throw bridgeError('SIZE', 'the warm profile overflowed — the name is too long')
  return json
}

export function decodeWarmProfile(raw, { now = Date.now() } = {}) {
  let rec
  try { rec = JSON.parse(String(raw || '')) } catch { throw bridgeError('SHAPE', 'the warm profile is not readable') }
  if (!rec || rec.v !== WARM_PROFILE_VERSION) throw bridgeError('VERSION', 'the warm profile version is unknown — it is rebuilt after the next road')
  if (typeof rec.deviceId !== 'string' || !rec.deviceId) throw bridgeError('SHAPE', 'the warm profile lost its deviceId')
  if (!Number.isFinite(rec.savedAt)) throw bridgeError('SHAPE', 'the warm profile lost its clock')
  if (now - rec.savedAt > WARM_PROFILE_TTL_MS) throw bridgeError('STALE', 'the warm profile expired (7 days) — the next road refreshes it')
  if (rec.road && !['direct-lan', 'direct-net', 'relay'].includes(rec.road)) throw bridgeError('SHAPE', 'the warm profile carries a foreign road')
  return rec
}

/**
 * The re-dial plan (the honest R-4 decision):
 *   silent  — a signaling path exists (cloud up): the relay lane re-dials
 *             automatically; no human hop needed.
 *   guided  — no signaling: the ONE bridge hop opens the road; the chip
 *             names the absent ingredient (never a silent dead road).
 *   fresh   — no usable profile: the ordinary journey runs.
 */
export function warmReDialPlan(profile, { cloudSignaling = false, now = Date.now() } = {}) {
  if (!profile) return Object.freeze({ mode: 'fresh', line: '' })
  const ageDays = Math.max(0, Math.round((now - profile.savedAt) / 86400000))
  const name = profile.name || 'the other device'
  const roadText = profile.road === 'direct-lan' ? 'DIRECT · this network'
    : profile.road === 'direct-net' ? 'DIRECT · internet'
    : profile.road === 'relay' ? 'your cloud relay' : 'a direct road'
  if (cloudSignaling) {
    return Object.freeze({
      mode: 'silent',
      line: `Last time (${ageDays === 0 ? 'today' : ageDays + 'd ago'}): ${roadText} with ${name} — the cloud carries the call automatically again.`,
    })
  }
  return Object.freeze({
    mode: 'guided',
    line: `Last time: ${roadText} with ${name}. The cloud is down, so the road needs its one bridge hop — press “Open a road”.`,
  })
}
