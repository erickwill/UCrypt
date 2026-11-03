/**
 * UCrypt — R140 §6 — THE RELAY ("the roads beneath the Bond").
 *
 * The from-scratch authority, exercised on the transport layer. THE BOND
 * (the journey machine) stands untouched in its laws; THE RELAY is the set
 * of roads beneath it, rebuilt as ONE named module with one responsibility:
 * given an availability, an offer, an answer, or a file chunk — and given
 * what this device truthfully HAS (a direct network path? a connected
 * cloud? nothing?) — deliver it, and report every hop.
 *
 * Brave is the named inspiration, and its lessons are law here:
 *   §6.1 A DEVICE IS NEVER NAMELESS — every device owns a stable record
 *        (id, name, platform, joined-at); the name defaults to
 *        "<Browser> on <OS>", is user-editable, and propagates through the
 *        roster, the availability, the offers, the answers, and every
 *        surface. A nameless placeholder is a BANNED class — an unknown
 *        name is a defect at the propagation layer, never a placeholder
 *        string (the banned literal is defined below as the detector).
 *   §6.2 THE CONNECTED CLOUD IS THE RENDEZVOUS BY DEFAULT — when a cloud is
 *        connected and healthy, availability, offers, and answers ride it
 *        automatically (Plane B is the FIRST-CLASS road); the unexplained
 *        cloud-verdict copy may render ONLY with classified evidence,
 *        NEVER while the cloud pill is green (one reactive truth, §7.2),
 *        and only after the retry ladder (1s/2s/4s/8s/16s) is exhausted —
 *        a cold-start race is not a dead cloud.
 *   §6.3 RECEIVING IS PASSIVE — the inbox polls itself every 2–4 s while
 *        the Receive intent is open and availability is armed, polls again
 *        on window focus, reports its own activity ("Checking for offers
 *        every 3 s · last checked 2 s ago") and its own failures per hop.
 *        A receiver who opens the page and waits MUST receive.
 *   §6.4 THE HONEST MAILBOX LAW — the sender may claim "the offer waits in
 *        its mailbox" ONLY with a confirmed relay write (the commit/etag
 *        receipt in hand) AND a known-true receiver read capability; the
 *        claim upgrades to "fetched" on the relay read; otherwise the copy
 *        tells the truth and hands over the manual route with the signal
 *        pre-copied. An unevidenced delivery promise is the law-21 class,
 *        banned on our own surfaces.
 *   §6.5 TWO BROWSERS, ONE MACHINE IS FIRST-CLASS — the relay is
 *        browser-agnostic (both profiles reach the same Drive); Plane A is
 *        taught the loopback path (127.0.0.1 host candidates connect
 *        without STUN on one machine); NO design may lean on shared
 *        localStorage, BroadcastChannel, or cross-browser message passing.
 *   §6.6 THE PLANE CHOOSER PRINTS THE ROAD — one honest reason each:
 *        "Direct — same network" / "Through your connected <cloud> —
 *        direct was not possible" / "Manual — no cloud is connected".
 *
 * PURE — no DOM, no chrome.*, no fetch, no timers at import time. The
 * pollers are classes the worker/page drive. Battery-pinned (tests/r140-
 * round.test.mjs + the G90 harness's real-transport variants).
 */

import { PLANES } from './planes.js'
import { CHAIN_RETRY_LADDER_MS, cloudGateFromChainState } from '../chain-state.js'

export { CHAIN_RETRY_LADDER_MS }

/** §6.6 — the plane chooser's honest reasons (the ONLY words it prints). */
export const RELAY_ROUTE_REASONS = {
  direct: { key: 'spineRouteDirect', words: 'Direct — same network' },
  relay: { key: 'spineRouteRelay', words: 'Through your connected cloud — direct was not possible' },
  relayCloud: { key: 'spineRouteRelayCloud', words: 'Through your connected {cloud} — direct was not possible' },
  manual: { key: 'spineRouteManual', words: 'Manual — no cloud is connected' },
  manualChosen: { key: 'spineRouteManualChosen', words: 'Manual — you chose the code road' },
}

/* ────────────────────────────────────────────────────────────────────────
 * §6.1 IDENTITY AND NAMES — a device is never nameless (the nameless
 * placeholder is killed forever; the detector constant below pins the
 * banned literal)
 * ──────────────────────────────────────────────────────────────────────── */

/** The banned placeholder class (the retired-strings sweep asserts ZERO). */
export const BANNED_NAME_PLACEHOLDER = 'Unnamed device'

/**
 * The default device name at install: "<Browser> on <OS>" (§6.1's exact
 * contract) parsed from the worker's own user-agent string. Chrome-family
 * browsers render honestly; an unparseable UA degrades to "Browser on
 * this device" — NEVER to a nameless placeholder.
 */
export function defaultDeviceName(userAgent = '') {
  const ua = String(userAgent || '')
  const browser = (() => {
    if (/Edg\//.test(ua)) return 'Edge'
    if (/OPR\//.test(ua)) return 'Opera'
    if (/Brave/.test(ua)) return 'Brave'
    if (/Chrome\//.test(ua)) return 'Chrome'
    if (/Chromium/.test(ua)) return 'Chromium'
    if (/Firefox\//.test(ua)) return 'Firefox'
    if (/Safari\//.test(ua)) return 'Safari'
    return 'Browser'
  })()
  const os = (() => {
    if (/Windows NT 10/.test(ua)) return 'Windows'
    if (/Windows/.test(ua)) return 'Windows'
    if (/Android/.test(ua)) return 'Android'
    if (/iPhone|iPad|iOS/.test(ua)) return 'iOS'
    if (/Mac OS X/.test(ua)) return 'macOS'
    if (/CrOS/.test(ua)) return 'ChromeOS'
    if (/Linux/.test(ua)) return 'Linux'
    return 'this device'
  })()
  return `${browser} on ${os}`
}

/**
 * THE NAME RENDER LAW: every surface that names a peer renders through
 * THIS. A record with a real label/name/id renders it; a genuinely empty
 * record renders the honest "this device" shape — the banned placeholder
 * is unrepresentable by construction.
 */
export function deviceDisplayName(record = {}) {
  const label = String(record.label || record.name || record.deviceLabel || '').trim()
  if (label && !isBannedPlaceholder(label)) return label
  const platform = String(record.platform || record.deviceType || '').trim()
  if (platform) return `Device (${platform})`
  return 'Device'
}

/** True when the string IS the banned class (the sweep's detector). */
export function isBannedPlaceholder(s) {
  return String(s || '').trim().toLowerCase() === BANNED_NAME_PLACEHOLDER.toLowerCase()
}

/* ────────────────────────────────────────────────────────────────────────
 * §6.2 THE EVIDENCE-BASED CLOUD GATE + §6.6 THE PLANE CHOOSER
 * ──────────────────────────────────────────────────────────────────────── */

/**
 * THE RELAY GATE (F3d at the root): the ONLY door that may print an
 * unexplained cloud verdict. It renders a CLOSED verdict only with
 * (a) no cloud connected — the proactive, honest manual-route offer from
 * the FIRST step, never discovered at the moment of failure — or (b) an
 * evidence-backed, ladder-exhausted verdict from the ONE reactive chain
 * truth. While the chain state is pending (a cold-start race, the ladder
 * still climbing) the gate is OPEN — a race is not a dead cloud. The gate
 * and the green pill both read deriveChainState, so a contradiction is
 * structurally unrepresentable.
 *
 * @param {{chainDerived?:Object, cloudLabel?:string}} facts
 * @returns {{closed:boolean, why:string, reasonKey:string, evidence:Object|null,
 *            words:string, manualFirst:boolean}}
 */
export function relayGate(facts = {}) {
  const chainDerived = facts.chainDerived || {}
  const gate = cloudGateFromChainState(chainDerived)
  if (!gate.closed) {
    return {
      closed: false,
      why: 'open',
      reasonKey: '',
      evidence: null,
      words: '',
      manualFirst: false,
    }
  }
  if (gate.reason === 'no-cloud-connected') {
    return {
      closed: true,
      why: 'no-cloud',
      reasonKey: 'spineGateNoCloud',
      evidence: null,
      words: 'No cloud is connected — the manual route is the road: one copy, one paste.',
      manualFirst: true, // proactive from the first step, never discovered at failure
    }
  }
  return {
    closed: true,
    why: gate.reason, // evidence-backed: auth | unreachable | bridge | unreadable
    reasonKey: 'spineGateEvidence',
    evidence: gate.evidence,
    words: `The cloud road is closed right now (${gate.reason}, probe ${gate.evidence && gate.evidence.probeName || 'pull-probe'}${gate.evidence && gate.evidence.status ? `, HTTP ${gate.evidence.status}` : ''}) — the manual route below is the road: one copy, one paste.`,
    manualFirst: true,
  }
}

/**
 * THE PLANE CHOOSER (§6.2's inversion cured + §6.6's honest reasons):
 * the connected cloud is the DEFAULT road. Priority:
 *   1. the user's explicit manual choice (Plane C) — honored, never punished;
 *   2. Plane A when a direct path is KNOWN (same network proven/advertised,
 *      the loopback variant included);
 *   3. Plane B when a cloud is connected on this device (the peer reaches
 *      the same user cloud by construction of the chain);
 *   4. Plane C — no cloud, no direct: the manual route proactively.
 * The reason is ONE honest sentence each (the gate copy lives in
 * RELAY_ROUTE_REASONS).
 */
export function choosePlane(input = {}) {
  const i = input || {}
  if (i.manualChosen) {
    return { plane: PLANES.C, reasonKey: RELAY_ROUTE_REASONS.manualChosen.key, reasonWords: RELAY_ROUTE_REASONS.manualChosen.words, degraded: false }
  }
  if (i.directKnown) {
    return { plane: PLANES.A, reasonKey: RELAY_ROUTE_REASONS.direct.key, reasonWords: RELAY_ROUTE_REASONS.direct.words, degraded: false }
  }
  if (i.cloudConnected && i.cloudHealthy !== false) {
    const reason = i.cloudLabel
      ? { key: RELAY_ROUTE_REASONS.relayCloud.key, words: RELAY_ROUTE_REASONS.relayCloud.words.replace('{cloud}', String(i.cloudLabel)) }
      : { key: RELAY_ROUTE_REASONS.relay.key, words: RELAY_ROUTE_REASONS.relay.words }
    return { plane: PLANES.B, reasonKey: reason.key, reasonWords: reason.words, degraded: false }
  }
  return { plane: PLANES.C, reasonKey: RELAY_ROUTE_REASONS.manual.key, reasonWords: RELAY_ROUTE_REASONS.manual.words, degraded: false }
}

/* ────────────────────────────────────────────────────────────────────────
 * §6.4 THE HONEST MAILBOX LAW — hop receipts or truth, never a promise
 * ──────────────────────────────────────────────────────────────────────── */

export const MAILBOX_CLAIMS = {
  WRITTEN: 'written',     // relay write confirmed + receiver read known-true → the receipt
  FETCHED: 'fetched',     // the relay read registered → the upgrade
  UNDELIVERABLE: 'undeliverable', // the truthful road: manual, signal pre-copied
  PENDING_PROOF: 'pending-proof', // the write is not confirmed yet — claim NOTHING yet
}

/**
 * THE MAILBOX CLAIM (the law's exact decision): the sender's waiting copy
 * derives from the two facts and NOTHING else.
 * @param {{
 *   writeReceipt?: { at:number, store?:string, commit?:string } | null,
 *   peerReadKnown?: boolean,
 *   offerFetchedAt?: number | null,
 *   peerName?: string,
 *   clock?: () => string,
 * }} f
 */
export function mailboxClaim(f = {}) {
  const receipt = f.writeReceipt || null
  const peerName = deviceDisplayName({ label: f.peerName })
  const hhmmss = (ts) => {
    try { return new Date(Number(ts)).toLocaleTimeString([], { hour12: false }) } catch { return String(ts) }
  }
  if (f.offerFetchedAt) {
    return {
      claim: MAILBOX_CLAIMS.FETCHED,
      key: 'spineMailFetched',
      words: `Offer fetched by ${peerName} at ${hhmmss(f.offerFetchedAt)}`,
      peerName,
      at: Number(f.offerFetchedAt),
    }
  }
  if (receipt && receipt.at && f.peerReadKnown) {
    return {
      claim: MAILBOX_CLAIMS.WRITTEN,
      key: 'spineMailWritten',
      words: `Offer written to your ${String(f.storeLabel || 'cloud')} at ${hhmmss(receipt.at)} · their device checks automatically`,
      peerName,
      at: Number(receipt.at),
      commit: receipt.commit || '',
    }
  }
  if (receipt && receipt.at) {
    return {
      claim: MAILBOX_CLAIMS.PENDING_PROOF,
      key: 'spineMailPendingProof',
      words: `Offer written to your ${String(f.storeLabel || 'cloud')} at ${hhmmss(receipt.at)} — delivery is confirmed when their device reads it; the manual route below works right now.`,
      peerName,
      at: Number(receipt.at),
    }
  }
  return {
    claim: MAILBOX_CLAIMS.UNDELIVERABLE,
    key: 'spineMailUndeliverable',
    words: `Their device is not reachable directly and the offer could not be delivered through your cloud — the manual route below is the road: one copy, one paste.`,
    peerName,
    at: 0,
  }
}

/* ────────────────────────────────────────────────────────────────────────
 * §6.3 THE INBOX THAT POLLS ITSELF
 * ──────────────────────────────────────────────────────────────────────── */

/** The inbox cadence constants (the contract's exact numbers). */
export const INBOX_POLL_MIN_MS = 2000
export const INBOX_POLL_MAX_MS = 4000

/**
 * THE INBOX POLLER — receiving is passive. While the Receive intent is
 * open and availability is armed, the inbox polls EVERY 2–4 s (jittered),
 * polls again on window focus, reports its own activity truthfully, and
 * reports its own failures per hop. A silent inbox is never silent about
 * why.
 */
export class InboxPoller {
  constructor({ onPoll, minMs = INBOX_POLL_MIN_MS, maxMs = INBOX_POLL_MAX_MS, now = Date.now } = {}) {
    if (typeof onPoll !== 'function') throw new Error('SPINE_INBOX: onPoll required')
    if (typeof now !== 'function') throw new Error('SPINE_INBOX: now required')
    this.onPoll = onPoll
    this.minMs = Math.max(500, Number(minMs) || INBOX_POLL_MIN_MS)
    this.maxMs = Math.max(this.minMs, Number(maxMs) || INBOX_POLL_MAX_MS)
    this._now = now
    this.timer = null
    this.stopped = true
    this.active = false // the Receive intent is open + availability armed
    this.lastCheckedAt = 0
    this.lastOkAt = 0
    this.lastError = null
    this.pollCount = 0
    this.offersSeen = 0
    this.periodSec = Math.round((this.minMs + this.maxMs) / 2 / 1000) || 3
  }

  /** The self-report line (the truth of the inbox's own activity). */
  statusLine() {
    if (!this.active) return { key: 'spineInboxIdle', words: 'The inbox checks when you open Receive with availability armed.' }
    if (this.lastError && !this.lastOkAt) {
      return { key: 'spineInboxFailing', words: `Checking for offers every ${this.periodSec} s · the last check failed (${String(this.lastError).slice(0, 80)}) — retrying.` }
    }
    const ago = this.lastCheckedAt ? Math.max(0, Math.round((this._now() - this.lastCheckedAt) / 1000)) : null
    return {
      key: 'spineInboxActive',
      words: ago == null
        ? `Checking for offers every ${this.periodSec} s…`
        : `Checking for offers every ${this.periodSec} s · last checked ${ago}s ago`,
      lastCheckedAt: this.lastCheckedAt,
      secondsAgo: ago,
    }
  }

  _delay() {
    // the 2–4 s jitter (the contract's cadence, the Bond's pollMin/Max law)
    return Math.round(this.minMs + Math.random() * (this.maxMs - this.minMs))
  }

  /** Arm/disarm the loop (armed = Receive open + availability armed). */
  setActive(on) {
    this.active = !!on
    if (this.active && this.stopped) this.start()
    if (!this.active) this.stop()
  }

  start() {
    this.stopped = false
    this._schedule()
  }

  _schedule() {
    if (this.stopped || !this.active) return
    if (this.timer) clearTimeout(this.timer)
    this.timer = setTimeout(async () => {
      await this.pollOnce()
      this._schedule()
    }, this._delay())
  }

  /** One poll: reported, typed, never thrown (the loop owns its failures). */
  async pollOnce() {
    this.pollCount += 1
    this.lastCheckedAt = this._now()
    try {
      const res = await this.onPoll()
      const offers = Array.isArray(res && res.offers) ? res.offers.length : 0
      this.offersSeen = Math.max(this.offersSeen, offers)
      this.lastOkAt = this._now()
      this.lastError = null
      return res
    } catch (e) {
      this.lastError = String((e && (e.code || e.message)) || e).slice(0, 120)
      return { ok: false, error: this.lastError }
    }
  }

  /** §6.3 — the focus law: a focus event polls AGAIN immediately. */
  onFocus() {
    if (!this.active || this.stopped) return Promise.resolve(null)
    if (this.timer) clearTimeout(this.timer)
    return this.pollOnce().then((r) => { this._schedule(); return r })
  }

  stop() {
    this.stopped = true
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }
}

/* ────────────────────────────────────────────────────────────────────────
 * §6.5 TWO BROWSERS, ONE MACHINE — the loopback path
 * ──────────────────────────────────────────────────────────────────────── */

/**
 * THE LOOPBACK HOST CANDIDATE (Plane A on one machine): a host/mDNS
 * candidate on the loopback interface (or two candidates whose host
 * addresses are identical) means the peers share THIS machine — WebRTC
 * connects without STUN. The banned assumptions are named so review can
 * never re-introduce them: no shared localStorage, no BroadcastChannel,
 * no cross-browser extension message passing.
 */
export function isLoopbackHostCandidate(candidateAddress = '') {
  const a = String(candidateAddress || '').trim()
  return a === '127.0.0.1' || a === '::1' || a === 'localhost'
}

export function sameMachineCandidates(localAddr = '', remoteAddr = '') {
  const l = String(localAddr || '').trim()
  const r = String(remoteAddr || '').trim()
  if (!l || !r) return false
  return l === r || (isLoopbackHostCandidate(l) && isLoopbackHostCandidate(r))
}

/** The topology facts the chooser consumes (pure over ICE inputs). */
export function topologyFacts({ localCandidateTypes = [], remoteCandidateTypes = [], localAddrs = [], remoteAddrs = [] } = {}) {
  const lt = Array.isArray(localCandidateTypes) ? localCandidateTypes : []
  const rt = Array.isArray(remoteCandidateTypes) ? remoteCandidateTypes : []
  const hostToLocal = (types) => types.some((t) => t === 'host' || t === 'mDNS')
  const loopback = (isLoopbackHostCandidate(localAddrs) && isLoopbackHostCandidate(remoteAddrs)) || sameMachineCandidates(localAddrs, remoteAddrs)
  return {
    sameNetwork: (hostToLocal(lt) && hostToLocal(rt)) || loopback,
    loopback,
    sharedStorageAssumption: false, // NEVER true — the banned class, pinned false forever
  }
}

/* ────────────────────────────────────────────────────────────────────────
 * THE RELAY HOPS (§6.6 — the diagnostics drawer's relay rows)
 * ──────────────────────────────────────────────────────────────────────── */

/** The relay hop names that join the Bond's per-hop table. */
export const RELAY_HOPS = ['arm', 'advertise', 'relayOfferWrite', 'relayOfferFetch', 'relayRead', 'inboxPoll', 'roster', 'render']

/** One hop record the worker reports (typed, bounded). */
export function relayHop(name, { ok = true, detail = '', at = Date.now() } = {}) {
  if (!RELAY_HOPS.includes(name)) throw new Error(`SPINE_HOP: unknown hop ${name}`)
  return { name, ok: !!ok, detail: String(detail || ''), at }
}
