/**
 * UCrypt — R147 §5.6 — THE BYTE PUMP (lib/road/pump.js).
 *
 * THE DATA PLANE the field proved missing (J-1: the code matched on both
 * screens and no byte ever moved). One pump, two roads:
 *
 *   DIRECT — the established DataChannel: 64 KiB binary chunks, each chunk
 *     acked (a cumulative ack frame covers every chunk), rolling SHA-256 on
 *     both ends, progress events per chunk, the completion envelope carries
 *     the final hash. The receiver verifies the hash BEFORE the arrival
 *     toast — only a verified hash may say "Received ✓ — hash verified".
 *     A mismatch is a typed CORRUPT_ARRIVAL with a re-request action.
 *   RELAY — the signal lane: chunks ride as bridge-chunk envelopes
 *     (8×64 KiB batches), the acks ride back as bridge-ack envelopes
 *     (a cumulative watermark), the receipt as bridge-receipt. The sender
 *     keeps ≤ 2 unacked batches in flight (flow control over a polled lane).
 *
 * RESUME: a 10-minute window — the receiver's watermark (bytes acked) is
 * recorded under ucrypt:road-resume:<sessionId>; a sender returning inside
 * the window queries it (bridge-resume envelope) and continues from there.
 *
 * THE MOVEMENT LAW (LAW #68): the pump's every wait is bounded and typed —
 * ACK_TIMEOUT and RECEIPT_TIMEOUT are states with next steps, never silence.
 *
 * PURE — no chrome.*, no DOM; the carriers, the storage, the landing door
 * and the clock are injected. Battery: tests/road/r147-pump.test.mjs.
 */

import { b64urlEncode, b64urlDecode } from './offer.js'

export const PUMP_CHUNK_BYTES = 64 * 1024
export const RESUME_WINDOW_MS = 10 * 60 * 1000
export const RELAY_BATCH_CHUNKS = 8
export const RELAY_MAX_IN_FLIGHT = 2
export const ACK_TIMEOUT_MS = 45 * 1000
export const RECEIPT_TIMEOUT_MS = 120 * 1000
export const RELAY_POLL_MS = 5 * 1000
/* R150 §5.4 — the resume handshake's bounded wait: the receiver owns the
 * resume truth (a fresh assembly holds NOTHING — the parts live in RAM only),
 * so the sender confirms the offset before the first byte moves. */
export const RESUME_ACK_TIMEOUT_MS = 5 * 1000

export function pumpError(code, message) {
  const e = new Error(message)
  e.code = `ROAD_PUMP_${code}`
  return e
}

/* ── shared helpers ──────────────────────────────────────────────────────── */

export function speedAndEta(sent, elapsedMs, total) {
  const secs = Math.max(0.001, elapsedMs / 1000)
  const bps = sent / secs
  const remain = Math.max(0, total - sent)
  const etaS = bps > 0 ? Math.round(remain / bps) : null
  const speedLine = bps > 1024 * 1024 ? `${(bps / 1024 / 1024).toFixed(1)} MB/s` : `${(bps / 1024).toFixed(1)} KB/s`
  const etaLine = etaS == null ? '' : etaS > 90 ? `${Math.round(etaS / 60)} min left` : `${etaS} s left`
  return { speedLine, etaLine, bps }
}

async function sha256OfParts(parts) {
  const total = parts.reduce((a, p) => a + p.length, 0)
  const all = new Uint8Array(total)
  let off = 0
  for (const p of parts) { all.set(p, off); off += p.length }
  const digest = await crypto.subtle.digest('SHA-256', all)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/* ── THE SENDER ──────────────────────────────────────────────────────────── */

/**
 * Pump the file to the receiver over the established road.
 * @param {object} args
 *   road        — 'direct' | 'relay'
 *   dc          — the verified channel (direct)
 *   lane        — { put, poll, consume, myMemberId, peerMemberId } (relay)
 *   sessionId, fileName, size, sha256Hex
 *   read        — async (offset, length) => Uint8Array (the page slices the File)
 *   buildEnvelope, storage — the relay road's lane + the resume store
 *   onProgress  — ({ phase:'sending', received, size, percent, speedLine, etaLine })
 *   now         — the clock
 * Returns { ok:true, receipt:{ sha256 } } |
 *          { ok:false, code:'ACK_TIMEOUT'|'RECEIPT_TIMEOUT'|'SEND_FAILED', nextStep }
 */
export async function pumpSend({
  road, dc = null, lane = null, sessionId, fileName = 'file', size = 0, sha256Hex = '',
  read, buildEnvelope, storage = null, onProgress = () => {}, now = () => Date.now(),
  relayPollMs = RELAY_POLL_MS,
} = {}) {
  if (road === 'direct' && !dc) return { ok: false, code: 'SEND_FAILED', nextStep: 'the direct channel is gone — send again' }
  if (road === 'relay' && (!lane || !lane.put)) return { ok: false, code: 'SEND_FAILED', nextStep: 'the relay lane is gone — send again' }
  const startedAt = now()

  /* the resume query — a returning sender continues from the receiver's mark */
  let startOffset = 0
  if (storage) {
    try {
      const got = await storage.get(`ucrypt:road-resume:${sessionId}`)
      const rec = got && got[`ucrypt:road-resume:${sessionId}`]
      if (rec && now() - Number(rec.at) < RESUME_WINDOW_MS) startOffset = Math.min(Number(rec.bytes) || 0, size)
    } catch { /* no resume record — start at zero */ }
  }

  const report = (received) => {
    const percent = size ? Math.min(100, Math.round((received / size) * 100)) : 100
    const { speedLine, etaLine } = speedAndEta(received - startOffset, now() - startedAt, size - startOffset)
    onProgress({ phase: 'sending', received, size, percent, speedLine, etaLine })
  }

  if (road === 'direct') {
    const header = { sessionId, fileName, size, sha256: sha256Hex, resumeFrom: startOffset }
    dc.send(JSON.stringify({ t: 'header', header }))
    /* R150 §5.4 — THE RESUME HANDSHAKE: the receiver answers resume-ack with
     * the offset it can actually continue from (a fresh assembly answers 0 —
     * nothing partial is kept silently across a restart). The sender honors
     * the receiver's truth and re-declares its header. Bounded; silence
     * proceeds exactly as before (older receivers never see a watermark). */
    if (startOffset > 0) {
      const ack = await waitResumeAck(dc, { timeoutMs: RESUME_ACK_TIMEOUT_MS, now })
      if (ack && Number(ack.from) < startOffset) {
        startOffset = Math.max(0, Math.min(Number(ack.from) || 0, size))
        dc.send(JSON.stringify({ t: 'header', header: { sessionId, fileName, size, sha256: sha256Hex, resumeFrom: startOffset } }))
      }
    }
    let sent = startOffset
    let ackedBytes = startOffset
    const onAck = (ev) => {
      try {
        const m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        if (m && m.t === 'ack') ackedBytes = Number(m.bytes) || ackedBytes
      } catch { /* binary frames flow here too */ }
    }
    dc.addEventListener('message', onAck)
    /* THE RECEIPT LISTENER RIDES FROM THE START (the race fix): the receiver
     * may verify and seal while the ack wait is still draining — the waiter
     * must be live before 'end' leaves.
     * R150 §5.3 — the DECLINE is TYPED on the sender too: the receiver's
     * explicit refusal rides {t:'declined'} — the sender learns "they
     * declined" (never a fake timeout, never a fake delivery). */
    const receiptPromise = new Promise((resolve) => {
      const startedAt = now()
      const onMsg = (ev) => {
        if (typeof ev.data !== 'string') return
        try {
          const m = JSON.parse(ev.data)
          if (m && m.t === 'sealed') {
            dc.removeEventListener('message', onMsg)
            resolve({ ok: !!m.ok, sha256: String(m.sha256 || '') })
          } else if (m && m.t === 'declined') {
            dc.removeEventListener('message', onMsg)
            resolve({ ok: false, declined: true })
          }
        } catch { /* ignore */ }
      }
      try { dc.addEventListener('message', onMsg) } catch { return resolve(null) }
      const timer = setInterval(() => {
        if (now() - startedAt > RECEIPT_TIMEOUT_MS) {
          clearInterval(timer)
          try { dc.removeEventListener('message', onMsg) } catch { /* gone */ }
          resolve(null)
        }
      }, 200)
    })
    report(sent)
    for (let off = startOffset; off < size; off += PUMP_CHUNK_BYTES) {
      const buf = await read(off, Math.min(PUMP_CHUNK_BYTES, size - off))
      // backpressure — the channel's own water level, polled (the honest wait)
      while (dc.bufferedAmount > 8 * 1024 * 1024) {
        await new Promise((r) => setTimeout(r, 40))
        if (dc.readyState !== 'open') {
          dc.removeEventListener('message', onAck)
          return { ok: false, code: 'SEND_FAILED', nextStep: 'the direct channel closed mid-flight — send again (the receiver keeps its watermark for 10 minutes)' }
        }
      }
      dc.send(buf)
      sent += buf.length
      report(sent)
    }
    dc.send(JSON.stringify({ t: 'end', sessionId, sha256: sha256Hex }))
    // the acks ride back; the watchdog bounds the wait (LAW #68)
    const deadline = now() + ACK_TIMEOUT_MS + Math.round((size / (64 * 1024)) * 8)
    while (now() < deadline) {
      if (ackedBytes >= size) break
      await new Promise((r) => setTimeout(r, 60))
    }
    dc.removeEventListener('message', onAck)
    if (ackedBytes < size) {
      return { ok: false, code: 'ACK_TIMEOUT', nextStep: 'the other device stopped confirming — check it is awake and unlocked, then send again' }
    }
    // THE RECEIPT — the receiver's verified hash rides back
    const receipt = await receiptPromise
    if (receipt && receipt.declined) return { ok: false, code: 'DECLINED', nextStep: 'they declined the transfer — nothing was saved on their side' }
    if (!receipt) return { ok: false, code: 'RECEIPT_TIMEOUT', nextStep: 'the file moved but the verification did not return — the receiver can confirm from the arrivals card' }
    if (!receipt.ok) return { ok: false, code: 'CORRUPT_ARRIVAL', nextStep: 'the copy arrived damaged — send again; nothing was saved on their side' }
    return { ok: true, receipt: { sha256: receipt.sha256 }, journal: { road, bytes: sent - startOffset, elapsedMs: now() - startedAt } }
  }

  /* ── the RELAY road ──
   * R150 §5.4 — the walk is RESUMABLE-RESTARTABLE: the receiver may answer a
   * resumed sender with the restart ack ({bytes:0, restart:true} — its
   * assembly holds nothing), and may DECLINE (a bridge-receipt with
   * declined:true). Both resolve typed, never silent. */
  const batchBytes = RELAY_BATCH_CHUNKS * PUMP_CHUNK_BYTES
  let resumeFrom = startOffset
  let ackedBytes = startOffset
  let inFlight = 0
  let sendFailed = null
  let restartFrom = null
  let restarts = 0
  const putBatch = async (b) => {
    try {
      const buf = await read(b.offset, b.end - b.offset)
      const env = await buildEnvelope({
        kind: 'bridge-chunk',
        sessionId,
        payload: { fileName, size, sha256: sha256Hex, offset: b.offset, total: size, dataB64: b64urlEncode(buf), resumeFrom },
      })
      const r = await lane.put({ toMemberId: lane.peerMemberId, envelope: env })
      if (!r || !r.ok) throw new Error((r && r.userMessage) || 'the relay lane refused a chunk')
    } catch (e) {
      sendFailed = String((e && e.message) || e).slice(0, 160)
    }
  }
  const honorRestart = () => {
    resumeFrom = Math.max(0, Math.min(Number(restartFrom) || 0, size))
    restartFrom = null
    ackedBytes = resumeFrom
    inFlight = 0
    report(resumeFrom)
  }
  const batches = []
  const rebuildBatches = () => {
    batches.length = 0
    for (let off = resumeFrom; off < size; off += batchBytes) batches.push({ offset: off, end: Math.min(off + batchBytes, size) })
  }
  rebuildBatches()
  report(startOffset)
  relayWalk: while (true) {
    for (let i = 0; i < batches.length; i++) {
      while (inFlight >= RELAY_MAX_IN_FLIGHT) {
        // the flow control: wait for an ack (bounded — the watchdog law)
        const step = await waitRelayAck({ lane, sessionId, target: batches[i].offset, buildEnvelope, storage, lane2: lane, onAcked: (b) => { ackedBytes = b; report(b) }, onRestart: (b) => { restartFrom = b }, deadlineAt: now() + ACK_TIMEOUT_MS, now, relayPollMs })
        if (sendFailed) return { ok: false, code: 'SEND_FAILED', nextStep: `the relay lane refused the transfer — ${sendFailed}` }
        if (step === 'declined') return { ok: false, code: 'DECLINED', nextStep: 'they declined the transfer — nothing was saved on their side' }
        if (step === 'restart') {
          if (++restarts > 3) return { ok: false, code: 'SEND_FAILED', nextStep: 'the resume could not be honored — send again' }
          honorRestart()
          rebuildBatches()
          i = -1
          break
        }
        if (!step) return { ok: false, code: 'ACK_TIMEOUT', nextStep: 'the other device stopped confirming — check it is awake, then send again' }
        inFlight -= 1
      }
      if (i < 0) continue // the walk restarted — rebuilt batches from the corrected offset
      await putBatch(batches[i])
      if (sendFailed) return { ok: false, code: 'SEND_FAILED', nextStep: `the relay lane refused the transfer — ${sendFailed}` }
      inFlight += 1
    }
    // drain: wait until the LAST batch is acked
    const drained = await waitRelayAck({ lane, sessionId, target: size, buildEnvelope, storage, onAcked: (b) => { ackedBytes = b; report(b) }, onRestart: (b) => { restartFrom = b }, deadlineAt: now() + ACK_TIMEOUT_MS + Math.round((size / batchBytes) * relayPollMs), now, relayPollMs })
    if (sendFailed) return { ok: false, code: 'SEND_FAILED', nextStep: `the relay lane refused the transfer — ${sendFailed}` }
    if (drained === 'declined') return { ok: false, code: 'DECLINED', nextStep: 'they declined the transfer — nothing was saved on their side' }
    if (drained === 'restart') {
      if (++restarts > 3) return { ok: false, code: 'SEND_FAILED', nextStep: 'the resume could not be honored — send again' }
      honorRestart()
      rebuildBatches()
      continue relayWalk
    }
    if (!drained) return { ok: false, code: 'ACK_TIMEOUT', nextStep: 'the other device stopped confirming — check it is awake, then send again' }
    break
  }
  // the receipt
  const receipt = await waitRelayReceipt({ lane, sessionId, deadlineAt: now() + RECEIPT_TIMEOUT_MS, now, relayPollMs })
  if (receipt && receipt.declined) return { ok: false, code: 'DECLINED', nextStep: 'they declined the transfer — nothing was saved on their side' }
  if (!receipt) return { ok: false, code: 'RECEIPT_TIMEOUT', nextStep: 'the file moved but the verification did not return — the receiver can confirm from the arrivals card' }
  if (!receipt.ok) return { ok: false, code: 'CORRUPT_ARRIVAL', nextStep: 'the copy arrived damaged — send again; nothing was saved on their side' }
  return { ok: true, receipt: { sha256: receipt.sha256 }, journal: { road, bytes: ackedBytes - startOffset, elapsedMs: now() - startedAt } }
}

/* ── the direct road's resume-ack wait (R150 §5.4 — bounded) ─────────────── */

function waitResumeAck(dc, { timeoutMs, now }) {
  return new Promise((resolve) => {
    let done = false
    const startedAt = now()
    const onMsg = (ev) => {
      if (typeof ev.data !== 'string') return
      try {
        const m = JSON.parse(ev.data)
        if (m && m.t === 'resume-ack') {
          done = true
          clearInterval(timer)
          try { dc.removeEventListener('message', onMsg) } catch { /* gone */ }
          resolve({ from: Number(m.from) || 0, expired: !!m.expired })
        }
      } catch { /* binary frames flow here too */ }
    }
    try { dc.addEventListener('message', onMsg) } catch { return resolve(null) }
    const timer = setInterval(() => {
      if (done || now() - startedAt > timeoutMs) {
        clearInterval(timer)
        try { dc.removeEventListener('message', onMsg) } catch { /* gone */ }
        if (!done) resolve(null)
      }
    }, 100)
  })
}

/* ── the direct road's receipt wait ──────────────────────────────────────── */

function waitDirectReceipt(dc, { timeoutMs, now }) {
  return new Promise((resolve) => {
    let done = false
    const startedAt = now()
    const onMsg = (ev) => {
      if (typeof ev.data !== 'string') return
      try {
        const m = JSON.parse(ev.data)
        if (m && m.t === 'sealed') {
          done = true
          dc.removeEventListener('message', onMsg)
          resolve({ ok: !!m.ok, sha256: String(m.sha256 || '') })
        }
      } catch { /* ignore */ }
    }
    try { dc.addEventListener('message', onMsg) } catch { return resolve(null) }
    const timer = setInterval(() => {
      if (done || now() - startedAt > timeoutMs) {
        clearInterval(timer)
        try { dc.removeEventListener('message', onMsg) } catch { /* gone */ }
        resolve(null)
      }
    }, 200)
  })
}

/* ── the relay road's ack/receipt waits ──────────────────────────────────── */

async function waitRelayAck({ lane, sessionId, target, buildEnvelope, storage, onAcked, onRestart, deadlineAt, now, relayPollMs }) {
  while (now() < deadlineAt) {
    try {
      const poll = await lane.poll()
      for (const s of (poll && poll.signals) || []) {
        if (!s.envelope || s.envelope.sessionId !== sessionId) continue
        if (s.envelope.kind === 'bridge-ack') {
          const p = s.envelope.payload || {}
          try { await lane.consume({ sessionId, signalId: s.signalId }) } catch { /* consumed */ }
          if (p.restart) {
            // R150 §5.4 — the receiver corrected the resume offset (it holds
            // nothing): the sender restarts from the receiver's truth.
            if (onRestart) onRestart(Number(p.from) || 0)
            return 'restart'
          }
          const bytes = Number(p.bytes) || 0
          if (bytes > 0 && onAcked) onAcked(bytes)
          if (bytes >= target) return true
        } else if (s.envelope.kind === 'bridge-receipt' && s.envelope.payload && s.envelope.payload.declined) {
          // R150 §5.3 — the typed DECLINE wakes the flow-control wait too
          // (never a fake ACK_TIMEOUT while the answer is in the lane).
          try { await lane.consume({ sessionId, signalId: s.signalId }) } catch { /* consumed */ }
          return 'declined'
        }
      }
    } catch { /* a dead tick never ends the wait — the watchdog owns that */ }
    await new Promise((r) => setTimeout(r, Math.min(relayPollMs, 500)))
  }
  return false
}

async function waitRelayReceipt({ lane, sessionId, deadlineAt, now, relayPollMs }) {
  while (now() < deadlineAt) {
    try {
      const poll = await lane.poll()
      for (const s of (poll && poll.signals) || []) {
        if (s.envelope && s.envelope.kind === 'bridge-receipt' && s.envelope.sessionId === sessionId) {
          try { await lane.consume({ sessionId, signalId: s.signalId }) } catch { /* consumed */ }
          const p = s.envelope.payload || {}
          if (p.declined) return { ok: false, declined: true }
          return { ok: !!p.ok, sha256: String(p.sha256 || '') }
        }
      }
    } catch { /* the watchdog owns the exit */ }
    await new Promise((r) => setTimeout(r, Math.min(relayPollMs, 500)))
  }
  return null
}

/* ── THE RECEIVER ────────────────────────────────────────────────────────── */

/**
 * Create the receiver's assembly state (one per incoming session).
 * The hash is verified BEFORE anything is saved (the §5.6 law).
 */
export function createReceiver({ fileName, size, sha256Hex, storage = null, sessionId = '', now = () => Date.now() } = {}) {
  const parts = []
  let received = 0
  let done = false
  return {
    get received() { return received },
    get done() { return done },
    /** One 64 KiB chunk (direct road) — returns the progress delta. */
    push(bytes) {
      if (done) throw pumpError('DONE', 'this session already ended')
      parts.push(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
      received += bytes.length
      return { received }
    },
    /** The cumulative ack line the receiver sends back. */
    ackFrame({ final = false } = {}) {
      return JSON.stringify({ t: 'ack', bytes: received, final })
    },
    /** Verify + land. ONLY a verified hash is saved; a mismatch is typed. */
    async verifyAndLand({ landing }) {
      const hash = await sha256OfParts(parts)
      if (hash !== String(sha256Hex || '')) {
        return { ok: false, code: 'CORRUPT_ARRIVAL', sha256: hash, nextStep: 'the copy arrived damaged — ask the sender to send it again; nothing was saved' }
      }
      let bin = ''
      for (const p of parts) {
        for (let i = 0; i < p.length; i += 32768) bin += String.fromCharCode.apply(null, p.subarray(i, Math.min(i + 32768, p.length)))
      }
      const bytesB64 = btoa(bin)
      const r = await landing({ fileName, bytesB64 })
      if (!r || !r.ok) return { ok: false, code: 'LAND_FAILED', nextStep: (r && r.userMessage) || 'the file verified but could not be saved' }
      done = true
      if (storage) {
        try { await storage.remove(`ucrypt:road-resume:${sessionId}`) } catch { /* best effort */ }
      }
      return { ok: true, sha256: hash, fileName }
    },
    /** The watermark the resume window reads (10 minutes). */
    async watermark() {
      if (storage) {
        try { await storage.set({ [`ucrypt:road-resume:${sessionId}`]: { bytes: received, fileName, at: now() } }) } catch { /* best effort */ }
      }
      return { bytes: received, fileName, at: now() }
    },
  }
}
