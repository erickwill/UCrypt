/**
 * UCrypt — R141 §7 — THE MAILBOX WORKER (the ONE road's worker side).
 *
 * The MAILBOX_* message handlers: the sender's four beats, the receiver's
 * zero-step poll, the receipts, the doctor, and the off-road file — all on
 * the chain's ALREADY-CONFIGURED endpoint (the same transport record vault
 * sync uses; the address algebra the autopsy's H1 proved necessary).
 *
 * The pre-flight gate runs BEFORE any file picker exists (§7.5): chain bound?
 * cloud connected? Either fails → one card, one action, zero jargon.
 *
 * The poll is UNCONDITIONAL (§7.7 — there is no availability concept left to
 * gate it). It runs on the vault-sync lifecycle; this module only answers
 * when polled. NOTHING here imports the retired transport — the clean room
 * imports the new family only.
 */

import {
  buildFileEnvelope, parseEnvelope, generateVerifyCode, formatVerifyCode,
  verifyCodesMatch, mailboxLayout, mailboxError, newReceipt, transitionReceipt,
  fingerprintMatches,
} from './protocol.js'
import {
  memoryMailboxStore, webdavMailboxBinding, driveMailboxBinding,
  deliverOffer, readInbox, fetchOffer, writeReceipt, readReceipt, mergeWrite,
  deliverSignal, readSignals, consumeSignal, sweepSessionSignals, stampPresence, readPresence,
} from './store.js'
import { groupSeal, groupOpen, signEnvelope, verifyEnvelopeSignature } from './crypto.js'
import { learnPeer } from '../transfer/mailbox.js' // R154 §5 (A.1): the bond learn writes the ONE sealed peer map — no cycle (transfer/mailbox.js imports no mailbox/* module)
import { runMailboxDoctor } from './doctor.js'
import { buildOffroadFile, parseOffroadFile, newMailboxJourney, stepJourney, applyReceipt, MAILBOX_STATES, senderWaitingLine } from './machine.js'
import { validateSignalEnvelope } from '../bridge/signal.js'
import { PRESENCE_HEARTBEAT_MS } from '../bridge/presence-lite.js'
import { deriveSafetyCode, formatSafetyCode } from '../bridge/safety-code.js'
import { fetchWithRetry } from '../transports/http.js'
import { ensureAccessToken, isFastOrAppDataMode } from '../transports/gdrive.js'

/* The session state (worker-lifetime): the journeys, the code space, the
 * chunk assembly buffers. All non-secret; the keys stay in the chain plane. */
const _journeys = new Map() // offerId → journey
const _seenCodes = new Set() // the fresh-per-transfer code law
const _mailStore = { store: null, id: null, key: null }

export function _resetMailboxStoreForTest() {
  _mailStore.store = null
  _mailStore.id = null
  _mailStore.key = null
}

function _transportFingerprint(rec) {
  if (!rec || !rec.id) return ''
  const c = rec.config || {}
  const wt = (c.webToken && c.webToken.token) || ''
  return [
    rec.id,
    rec.setAt || '',
    c.url || '',
    c.user || '',
    c.pass || '',
    c.signinMode || '',
    c.clientId || '',
    c.accessToken || '',
    c.token || '',
    c.refreshToken || '',
    wt,
  ].join('|')
}

/** Resolve the ONE road: the chain's configured endpoint (the transport
 * record vault sync already adopted). Returns the bound store or null. */
export async function mailboxStore({ getTransportRecord, storeOverride = null }) {
  if (storeOverride) return storeOverride // the battery's memory double (G92)
  const rec = await getTransportRecord()
  if (!rec || !rec.id) return null
  const fpKey = _transportFingerprint(rec)
  if (_mailStore.store && _mailStore.id === rec.id && _mailStore.key === fpKey) return _mailStore.store
  let store = null
  if (rec.id === 'webdav') {
    const cfg = rec.config || {}
    if (!cfg.url) return null
    const auth = cfg.user || cfg.pass
      ? { Authorization: 'Basic ' + btoa(`${String(cfg.user || '')}:${String(cfg.pass || '')}`) }
      : {}
    const davFetch = async (url, init) => {
      try {
        // R142-A4 CURE (the G93 field find): the store's contract reads 404 as
        // ABSENT ({ok:false}) — the bindings' 404 branches are load-bearing
        // (the presence reads, the empty-inbox poll, the receipt reads). The
        // wrapper must pass 404 through response-shaped, never throw it.
        const res = await fetchWithRetry(url, { redirect: 'manual', ...init, headers: { ...auth, ...(init.headers || {}) } },
          { context: 'Mailbox ' + (init.method || 'GET'), retries: 1, op: init.method === 'PUT' ? 'upload' : 'download', okStatuses: [404] })
        let text = null
        try { text = await res.clone().text() } catch { /* HEAD-shaped */ }
        return { ok: res.ok, status: res.status, headers: res.headers, text }
      } catch (e) {
        throw mailboxError('CLOUD', String((e && e.message) || e).slice(0, 160))
      }
    }
    store = webdavMailboxBinding({ davFetch, baseUrl: String(cfg.url).replace(/[^/]*$/, '') })
  } else if (rec.id === 'gdrive') {
    const cfg = rec.config || {}
    const useAppData = isFastOrAppDataMode(cfg) && !cfg.accessToken && !cfg.token
    const driveFetch = async (path, init = {}) => {
      let token = cfg.accessToken || cfg.token || ''
      if (!token) {
        try {
          token = await ensureAccessToken(cfg)
        } catch (e) {
          throw mailboxError('CLOUD', String((e && (e.userMessage || e.message)) || 'the Drive token is not available for the mailbox road').slice(0, 160))
        }
      }
      if (!token) throw mailboxError('CLOUD', 'the Drive token is not available for the mailbox road')
      const fetchFn = typeof globalThis.__ucryptFetchOverride === 'function'
        ? globalThis.__ucryptFetchOverride
        : fetch
      const res = await fetchFn(`https://www.googleapis.com${path}`, {
        method: init.method || 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          ...(init.body ? { 'Content-Type': init.contentType || 'application/json' } : {}),
          ...(init.headers || {}),
        },
        body: init.body || undefined,
      })
      if (res.status === 204) return {}
      const text = await res.text()
      try { return JSON.parse(text) } catch { return text }
    }
    store = driveMailboxBinding({ driveFetch, useAppData })
  } else {
    return null // custom/http roads: the mailbox rides webdav-or-drive only this round (the honest card says so)
  }
  _mailStore.store = store
  _mailStore.id = rec.id
  _mailStore.key = fpKey
  return store
}

async function sha256HexOfBytes(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * The message door. Every response is one of:
 *   { ok: true, ... } | { ok: false, code, userMessage } — typed, honest.
 */
export async function handleMailboxMessage(msg, deps = {}) {
  const {
    ensureChainReady, getTransportRecord, saveReceivedFile, rosterPeers,
    now = Date.now(),
  } = deps
  try {
    if (!msg || typeof msg.type !== 'string') throw mailboxError('DOOR', 'the mailbox message is malformed')

    if (msg.type === 'MAILBOX_STATUS') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      const { identity } = await ensureChainReady()
      const rec = await getTransportRecord()
      const connected = !!(store && rec)
      return {
        ok: true,
        status: {
          connected,
          transportId: rec && rec.id ? rec.id : '',
          memberId: identity.deviceId,
          memberName: identity.label || '',
          ready: connected,
          preflight: connected ? null : { code: 'NO_CLOUD', action: 'Connect Cloud Sync to transfer' },
        },
      }
    }

    if (msg.type === 'MAILBOX_ROSTER') {
      const { identity } = await ensureChainReady()
      const peers = (typeof rosterPeers === 'function' ? await rosterPeers() : []) || []
      return {
        ok: true,
        self: { memberId: identity.deviceId, name: identity.label || '' },
        peers: peers
          .filter((p) => p && p.deviceId && p.deviceId !== identity.deviceId)
          .map((p) => ({ memberId: p.deviceId, name: String(p.label || '') || 'a chain device' })),
      }
    }

    if (msg.type === 'MAILBOX_SEND') {
      const { fileName, size, sha256, toMemberId, toName, bytesB64 } = msg
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) {
        return { ok: false, code: 'NO_CLOUD', userMessage: 'Cloud Sync is not connected — Connect' }
      }
      const { chainKeys, identity } = await ensureChainReady()
      const code = generateVerifyCode(_seenCodes)
      const envelope = buildFileEnvelope({
        fromMemberId: identity.deviceId, fromName: identity.label || 'a chain device',
        toMemberId, fileName, size, sha256, verifyCode: code, now,
      })
      const bytes = Uint8Array.from(atob(String(bytesB64 || '')), (c) => c.charCodeAt(0))
      if (bytes.length !== Number(size)) throw mailboxError('SIZE_MISMATCH', 'the supplied bytes disagree with the declared size')
      // the sealed payload carries the sender's public key so the receiver's
      // open VERIFIES the signature (the signer identity rides the seal)
      const sealedPayload = { ...envelope, signPubJwk: identity.signPubJwk }
      const sealedEnvelope = await groupSeal(crypto.subtle, chainKeys.rendezvousGroup, sealedPayload)
      const sig = await signEnvelope(crypto.subtle, identity.signKeys.privateKey, sealedPayload)
      // the chunks: ciphertext-at-the-backend — each chunk group-sealed too
      // (the chunk count rides the envelope; the receiver opens each chunk
      // with the chain key and the fingerprint auto-checks the assembly)
      const chunks = []
      for (let i = 0; i < envelope.chunkCount; i++) {
        const start = i * envelope.chunkSize
        const slice = bytes.slice(start, Math.min(start + envelope.chunkSize, bytes.length))
        chunks.push(await groupSeal(crypto.subtle, chainKeys.rendezvousGroup, { i, b64: arrayBufferToB64(slice) }))
      }
      let j = newMailboxJourney({ offerId: envelope.offerId, fromName: envelope.fromName, toName: String(toName || 'the recipient'), fileName, size, verifyCode: formatVerifyCode(code), now })
      j = stepJourney(j, MAILBOX_STATES.COMPOSING, { now })
      j = stepJourney(j, MAILBOX_STATES.SENDING, { now, hop: { name: 'write', ok: true, detail: 'the mailbox write is in flight', action: '' } })
      const receipt0 = newReceipt(envelope.offerId, identity.deviceId, toMemberId, now)
      const delivered = await deliverOffer(store, { envelope: { ...envelope, sealed: sealedEnvelope, signature: sig }, chunks, senderMemberId: identity.deviceId })
      j = stepJourney(j, MAILBOX_STATES.DELIVERED, { now, hop: { name: 'write', ok: true, detail: 'the mailbox confirmed the writes', action: '' }, receipt: receipt0 })
      _journeys.set(envelope.offerId, j)
      return {
        ok: true,
        offerId: envelope.offerId,
        verifyCode: formatVerifyCode(code),
        indexCount: delivered.indexCount,
        journey: { state: j.state, line: senderLineFor(j, now) },
      }
    }

    if (msg.type === 'MAILBOX_POLL') {
      // UNCONDITIONAL — the §7.7 law. No availability exists to gate this.
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: true, connected: false, offers: [], pruned: 0, checkedAt: now }
      const { chainKeys, identity } = await ensureChainReady()
      const inbox = await readInbox(store, { memberId: identity.deviceId, now })
      const offers = []
      for (const row of inbox.offers) {
        try {
          const gotEnv = await store.get(mailboxLayout.inboxOffer(identity.deviceId, row.offerId))
          if (!gotEnv || !gotEnv.ok) continue
          const sealed = JSON.parse(gotEnv.text)
          const opened = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, sealed.sealed)
          // the signature verifies against the signer key that rode the seal
          await verifyEnvelopeSignature(crypto.subtle, opened.signPubJwk, opened, sealed.signature)
          const envelope = opened
          parseEnvelope(envelope, { now, selfMemberId: identity.deviceId })
          offers.push({
            offerId: envelope.offerId, fromName: envelope.fromName, fileName: envelope.fileName,
            size: envelope.size, verifyCode: formatVerifyCode(envelope.verifyCode),
            createdAt: envelope.createdAt, expiresAt: envelope.expiresAt,
          })
        } catch (e) {
          // a refused offer is named in the poll response, never silent
          offers.push({ offerId: row.offerId, refused: true, code: (e && e.code) || 'MAILBOX_INTERNAL', fromName: row.fromName || '', fileName: row.fileName || '' })
        }
      }
      return { ok: true, connected: true, offers, pruned: inbox.pruned, checkedAt: now }
    }

    if (msg.type === 'MAILBOX_ACCEPT') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: false, code: 'NO_CLOUD', userMessage: 'Cloud Sync is not connected — Connect' }
      const { chainKeys, identity } = await ensureChainReady()
      const { offerId, code } = msg
      const gotEnv = await store.get(mailboxLayout.inboxOffer(identity.deviceId, offerId))
      if (!gotEnv || !gotEnv.ok) throw mailboxError('OFFER_MISSING', 'the offer is no longer in the mailbox')
      const sealed = JSON.parse(gotEnv.text)
      const opened = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, sealed.sealed)
      await verifyEnvelopeSignature(crypto.subtle, opened.signPubJwk, opened, sealed.signature)
      const envelope = opened
      parseEnvelope(envelope, { now, selfMemberId: identity.deviceId })
      // THE CODE: the only human comparison (§7.6) — the accept dialog showed
      // the code; the accept confirms the human saw the same digits.
      if (!verifyCodesMatch(String(code || ''), envelope.verifyCode)) {
        throw mailboxError('CODE_MISMATCH', 'the verification code does not match — ask the sender to check')
      }
      const openedParts = []
      const { chunks } = await fetchOffer(store, {
        memberId: identity.deviceId, offerId, expectSha256: envelope.sha256,
        digestFn: async (sealedChunks) => {
          const parts = []
          for (const sc of sealedChunks) {
            const opened = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, sc)
            parts.push(b64ToBytes2(opened.b64))
          }
          const total = parts.reduce((a, p) => a + p.length, 0)
          const all = new Uint8Array(total)
          let off = 0
          for (const p of parts) { all.set(p, off); off += p.length }
          openedParts.push(all)
          return sha256HexOfBytes(all)
        },
      })
      // the fingerprint auto-checked inside fetchOffer (the DAMAGED refusal otherwise)
      const receiptAccepted = transitionReceipt(newReceipt(envelope.offerId, envelope.fromMemberId, identity.deviceId, now), 'accepted', now)
      await writeReceipt(store, { senderMemberId: envelope.fromMemberId, receipt: receiptAccepted })
      // the standard download path — nothing opens automatically (§7.7)
      if (typeof saveReceivedFile === 'function' && openedParts.length) {
        await saveReceivedFile({ fileName: envelope.fileName, bytesB64: arrayBufferToB64(openedParts[0]) })
      }
      const receiptVerified = transitionReceipt(receiptAccepted, 'verified', now)
      await writeReceipt(store, { senderMemberId: envelope.fromMemberId, receipt: receiptVerified })
      return { ok: true, offerId, fileName: envelope.fileName, size: envelope.size, verified: true }
    }

    if (msg.type === 'MAILBOX_DECLINE') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: false, code: 'NO_CLOUD', userMessage: 'Cloud Sync is not connected — Connect' }
      const { chainKeys, identity } = await ensureChainReady()
      const { offerId } = msg
      const gotEnv = await store.get(mailboxLayout.inboxOffer(identity.deviceId, offerId))
      if (!gotEnv || !gotEnv.ok) return { ok: true, offerId, gone: true }
      const sealed = JSON.parse(gotEnv.text)
      const envelope = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, sealed.sealed)
      const receipt = transitionReceipt(newReceipt(envelope.offerId, envelope.fromMemberId, identity.deviceId, now), 'declined', now)
      await writeReceipt(store, { senderMemberId: envelope.fromMemberId, receipt })
      await store.remove(mailboxLayout.inboxOffer(identity.deviceId, offerId))
      // the index row leaves with the envelope — the manifest never lists a
      // declined offer (the R141-13 harness find, cured here)
      await mergeWrite(store, mailboxLayout.inboxIndex(identity.deviceId), (cur) => {
        if (!cur || !Array.isArray(cur.offers)) return cur || { v: 1, memberId: identity.deviceId, offers: [] }
        return { ...cur, offers: cur.offers.filter((o) => o.offerId !== offerId) }
      })
      for (let i = 0; i < Number(envelope.chunkCount || 0); i++) {
        try { await store.remove(mailboxLayout.inboxChunk(identity.deviceId, offerId, i)) } catch { /* best-effort sweep */ }
      }
      return { ok: true, offerId, declined: true }
    }

    if (msg.type === 'MAILBOX_RECEIPTS') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: true, connected: false, receipts: [] }
      const { identity } = await ensureChainReady()
      const names = await store.list(`ucrypt-mailbox-v1/receipts/${identity.deviceId}/`)
      const receipts = []
      for (const n of names.slice(-40)) {
        const got = await store.get(n)
        if (got && got.ok) {
          try { receipts.push(JSON.parse(got.text)) } catch { /* a malformed receipt never breaks the card */ }
        }
      }
      // advance the journeys the receipts speak for
      for (const r of receipts) {
        const j = _journeys.get(r.offerId)
        if (j && j.state === MAILBOX_STATES.DELIVERED) {
          try { _journeys.set(r.offerId, applyReceipt(j, r, now)) } catch { /* illegal edges stay put */ }
        }
      }
      return { ok: true, connected: true, receipts: receipts.map((r) => ({ offerId: r.offerId, state: r.state, at: r.at })) }
    }

    if (msg.type === 'MAILBOX_JOURNEYS') {
      const journeys = [..._journeys.values()].map((j) => ({ offerId: j.offerId, state: j.state, line: senderLineFor(j, now), toName: j.toName, fileName: j.fileName, size: j.size, verifyCode: j.verifyCode, createdAt: j.createdAt }))
      return { ok: true, journeys }
    }

    if (msg.type === 'MAILBOX_DOCTOR') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      const { identity } = await ensureChainReady()
      const report = await runMailboxDoctor({ store: store || memoryMailboxStore(), selfMemberId: identity.deviceId, now })
      return { ok: true, report: { ...report, cloudDown: !store } }
    }

    if (msg.type === 'MAILBOX_EXPORT_OFFER') {
      // §7.10 — the off-road file: the SAME envelope + sealed chunks, cloud dead.
      const { chainKeys, identity } = await ensureChainReady()
      const { fileName, size, sha256, bytesB64 } = msg
      const code = generateVerifyCode(_seenCodes)
      const placeholderTo = identity.deviceId === '0'.repeat(32) ? 'f'.repeat(32) : '0'.repeat(32)
      const envelope = buildFileEnvelope({
        fromMemberId: identity.deviceId, fromName: identity.label || 'a chain device',
        toMemberId: placeholderTo, fileName, size, sha256, verifyCode: code, now,
      })
      const bytes = Uint8Array.from(atob(String(bytesB64 || '')), (c) => c.charCodeAt(0))
      const chunks = []
      for (let i = 0; i < envelope.chunkCount; i++) {
        const start = i * envelope.chunkSize
        const slice = bytes.slice(start, Math.min(start + envelope.chunkSize, bytes.length))
        const rawChunkB64 = arrayBufferToB64(slice)
        const sealedChunk = chainKeys && chainKeys.rendezvousGroup
          ? await groupSeal(crypto.subtle, chainKeys.rendezvousGroup, { i, b64: rawChunkB64 })
          : rawChunkB64
        chunks.push(sealedChunk)
      }
      const file = buildOffroadFile({ envelope: { ...envelope, toMemberId: null }, chunks })
      return {
        ok: true,
        fileName: `${fileName}.ucrypt-offer`,
        fileB64: arrayBufferToB64(new TextEncoder().encode(file)),
        verifyCode: formatVerifyCode(code),
      }
    }

    if (msg.type === 'MAILBOX_IMPORT_OFFER') {
      const { chainKeys, identity } = await ensureChainReady()
      const { fileB64, code } = msg
      const parsed = parseOffroadFile(new TextDecoder().decode(b64ToBytes2(String(fileB64 || ''))))
      const resolvedTo = parsed.envelope && parsed.envelope.fromMemberId === identity.deviceId
        ? (identity.deviceId === '0'.repeat(32) ? 'f'.repeat(32) : '0'.repeat(32))
        : identity.deviceId
      const envelope = { ...parsed.envelope, toMemberId: resolvedTo }
      parseEnvelope(envelope, { now, selfMemberId: resolvedTo })
      if (!verifyCodesMatch(String(code || ''), envelope.verifyCode)) {
        throw mailboxError('CODE_MISMATCH', 'the verification code does not match')
      }
      const openedParts = []
      for (const ch of parsed.chunks) {
        if (chainKeys && chainKeys.rendezvousGroup) {
          try {
            const dec = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, ch)
            if (dec && typeof dec.b64 === 'string') {
              openedParts.push(b64ToBytes2(dec.b64))
              continue
            }
          } catch {
            // Fall back to legacy unsealed base64 chunk if created by an older client
          }
        }
        openedParts.push(b64ToBytes2(ch))
      }
      const total = openedParts.reduce((a, p) => a + p.length, 0)
      const rawBytes = new Uint8Array(total)
      let off = 0
      for (const p of openedParts) { rawBytes.set(p, off); off += p.length }
      const expected = await sha256HexOfBytes(rawBytes)
      if (!fingerprintMatches(envelope.sha256, expected)) throw mailboxError('DAMAGED', 'the offer file is damaged (fingerprint mismatch)')
      const outB64 = arrayBufferToB64(rawBytes)
      if (typeof saveReceivedFile === 'function') {
        await saveReceivedFile({ fileName: envelope.fileName, bytesB64: outB64 })
      }
      return { ok: true, fileName: envelope.fileName, size: envelope.size, fromName: envelope.fromName, bytesB64: outB64, verified: true }
    }

    /* ── R142 §5 — THE BRIDGE DOORS (THE DIRECT ROAD's relay signaling + presence) ──
     * The direct road's SDP offer/answer rides the SAME chain endpoint as typed
     * BRIDGE envelopes (TTL 120 s, one index row per session, swept on close or
     * expiry). The presence doors carry the ≥ 15-minute TTL + heartbeat law.
     * The file landing door is the SAME saveReceivedFile law as MAILBOX_ACCEPT:
     * nothing ever opens automatically. */

    if (msg.type === 'BRIDGE_SIGNAL_PUT') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: false, code: 'NO_CLOUD', userMessage: 'Cloud Sync is not connected — the direct and QR paths still work' }
      const { toMemberId, envelope } = msg
      validateSignalEnvelope(envelope, { now })
      const delivered = await deliverSignal(store, { toMemberId, envelope })
      return { ok: true, ...delivered }
    }

    if (msg.type === 'BRIDGE_SIGNAL_POLL') {
      // UNCONDITIONAL like the mailbox poll — a dead road never gates the poller.
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: true, connected: false, signals: [], checkedAt: now }
      const { identity } = await ensureChainReady()
      const read = await readSignals(store, { memberId: identity.deviceId, now })
      return { ok: true, connected: true, signals: read.signals, checkedAt: now }
    }

    if (msg.type === 'BRIDGE_SIGNAL_CONSUME') {
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: false, code: 'NO_CLOUD', userMessage: 'Cloud Sync is not connected' }
      const { identity } = await ensureChainReady()
      const consumed = await consumeSignal(store, { memberId: identity.deviceId, sessionId: msg.sessionId, signalId: msg.signalId })
      return consumed
    }

    if (msg.type === 'BRIDGE_SESSION_CLOSE') {
      // THE SWEEP LAW: one index row per session, swept on close (cancel-safe
      // on the relay road too — G93 R9's no-orphans holds for signals).
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      if (!store) return { ok: true, swept: 0 }
      const { identity } = await ensureChainReady()
      const swept = await sweepSessionSignals(store, { memberId: identity.deviceId, sessionId: String(msg.sessionId || '') })
      return swept
    }

    if (msg.type === 'BRIDGE_SEAL') {
      // The group seal for the QR/words bundle payloads — keys NEVER leave the
      // chain plane; the page only ever sees sealed ciphertext.
      const { chainKeys } = await ensureChainReady()
      const sealed = await groupSeal(crypto.subtle, chainKeys.rendezvousGroup, msg.payload)
      return { ok: true, sealedB64: arrayBufferToB64(new TextEncoder().encode(JSON.stringify(sealed))) }
    }

    if (msg.type === 'BRIDGE_OPEN') {
      const { chainKeys } = await ensureChainReady()
      const sealedJson = new TextDecoder().decode(b64ToBytes2(String(msg.sealedB64 || '')))
      const opened = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, JSON.parse(sealedJson))
      return { ok: true, payload: opened }
    }

    if (msg.type === 'BRIDGE_PRESENCE_STAMP') {
      // The heartbeat: the cadence owns the stamp (the 5-minute law enforced
      // here — a stale stamp is not re-stamped from a spammy caller).
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      const recStamp = await getTransportRecord().catch(() => null)
      if (!store || !recStamp || !recStamp.id) return { ok: true, stamped: false }
      const { identity } = await ensureChainReady()
      const prevGot = await store.get(mailboxLayout.presence(identity.deviceId))
      let prev = null
      try { prev = prevGot && prevGot.ok ? JSON.parse(prevGot.text) : null } catch { prev = null }
      const last = Number(prev && prev.lastSeen) || 0
      if (now - last < PRESENCE_HEARTBEAT_MS) return { ok: true, stamped: false, lastSeen: last }
      await stampPresence(store, { memberId: identity.deviceId, now })
      return { ok: true, stamped: true, lastSeen: now }
    }

    if (msg.type === 'BRIDGE_ROSTER') {
      // THE F-5 LAW: the roster is the CHAIN'S OWN peer map — a dead road may
      // never blank it. Presence (when the road lives) rides the mailbox stamps
      // with the ≥ 15-minute TTL; when the road is down the states go unknown.
      const { chainKeys, identity } = await ensureChainReady()
      const peers = (typeof rosterPeers === 'function' ? await rosterPeers() : []) || []
      const rows = peers
        .filter((p) => p && p.deviceId && p.deviceId !== identity.deviceId)
        .map((p) => ({
          // R146 §6.2 — THE ONE DEVICE-TRUTH LAW: the full canonical row rides
          // (freshness, lane, entry counts, typed presence states) — the
          // v3.2.0 six-field strip is dead (the R146 autopsy ROSTER-1 cure).
          ...p,
          deviceId: p.deviceId,
          label: String(p.label || '') || 'a chain device',
          deviceType: String(p.deviceType || ''),
          lastSeen: Number(p.lastSeen) || 0,
          syncAt: Number(p.syncAt) || 0,
          entryCount: p.entryCount ?? null,
        }))
      const store = await mailboxStore({ getTransportRecord, storeOverride: deps.storeOverride })
      // THE CONNECTED TRUTH (the R142 matrix find): the test doubles inject a
      // store without a transport record — connected means BOTH (a live road
      // behind the store), never the store's mere presence.
      const recTruth = await getTransportRecord().catch(() => null)
      let presence = {}
      let connected = !!(store && recTruth && recTruth.id)
      if (store && connected) {
        presence = await readPresence(store, { memberIds: rows.map((r) => r.deviceId), now })
        for (const r of rows) {
          const st = presence[r.deviceId]
          if (st && Number(st.lastSeen) > r.lastSeen) r.lastSeen = Number(st.lastSeen)
        }
      }
      // R155 §5 (ARC A, LAW #98) — THE CHAIN TRUTH rides the roster response.
      // ONE store answers "is this device bound to a chain, and what is its
      // fingerprint": bound = the chain keys are READY (ensureChainReady
      // succeeded — the exact truth the bond door seals under), and the
      // fingerprint is the CHAIN'S OWN canonical code — chainTag, which IS
      // lib/sync.js syncFingerprint(words) (the SAME value the Sync tab
      // shows), dash-grouped and uppercased here. Both devices holding the
      // same sync code derive the SAME value — the Sync tab and the Device
      // Transfer strip agree by construction (no second split-brain).
      // Reaching this return at all means bound:true — a bound device can
      // NEVER again be reported chain-less by any surface that reads THIS
      // field (the E-4/E-6 split-brain dies at the source).
      let chainFingerprint = ''
      try {
        const tag = String(chainKeys.chainTag || '').replace(/[^0-9a-f]/gi, '')
        if (tag.length >= 8) {
          chainFingerprint = tag.slice(0, 8).replace(/^(..)(..)(..)(..)$/, '$1-$2-$3-$4').toUpperCase()
        } else {
          // the legacy/mock fallback: the chain ROOT hash, same grouping —
          // never a fabricated code, only a stable same-chain discriminator
          const rootBytes = chainKeys.chainRoot instanceof Uint8Array ? chainKeys.chainRoot : new Uint8Array(chainKeys.chainRoot)
          const rootHex = await sha256HexOfBytes(rootBytes)
          chainFingerprint = rootHex.slice(0, 8).replace(/^(..)(..)(..)(..)$/, '$1-$2-$3-$4').toUpperCase()
        }
      } catch { chainFingerprint = '' }
      return { ok: true, connected, self: { memberId: identity.deviceId, name: identity.label || '' }, peers: rows, chain: { bound: true, fingerprint: chainFingerprint } }
    }

    if (msg.type === 'BRIDGE_BOND_SEAL') {
      // R154 §5 (A.2) — THE DEVICE BOND INVITATION: THIS device's identity
      // stamp, sealed under the chain group key. Only a device holding the
      // SAME chain secret can open it — the cryptographic same-chain gate
      // (A.2.e): a stranger's bond door is unopenable by construction. The
      // stamp is the identityProvider row shape (public keys only — a public
      // key is not a secret, the R134 law); it is exactly what learnPeer's
      // TOFU accepts, so a bond lands straight in the sealed peer map.
      const { chainKeys, identity } = await ensureChainReady()
      const stamp = {
        kind: 'bond-stamp',
        deviceId: identity.deviceId,
        label: String(identity.label || ''),
        deviceType: String(identity.deviceType || ''),
        signPubJwk: identity.signPubJwk,
        agrPubJwk: identity.agrPubJwk,
        ts: Date.now(),
      }
      const sealed = await groupSeal(crypto.subtle, chainKeys.rendezvousGroup, stamp)
      const sealedB64 = arrayBufferToB64(new TextEncoder().encode(JSON.stringify(sealed)))
      return { ok: true, sealedB64, self: { deviceId: identity.deviceId, label: String(identity.label || '') } }
    }

    if (msg.type === 'BRIDGE_BOND_LEARN') {
      // R154 §5 (A.1/A.2) — THE BOND LEARN: open THEIR stamp under OUR chain
      // group key (a stranger stamp cannot open — the same-chain gate), then
      // TOFU-learn the peer into the sealed peer map (chrome.storage.local —
      // the bound survives restarts, G123) and stamp presence. A key change
      // on a KNOWN device is learnPeer's typed incident — never a silent
      // update. Every failure surfaces named (LAW #89 class).
      const { chainKeys, identity } = await ensureChainReady()
      let raw = ''
      try {
        raw = new TextDecoder().decode(b64ToBytes2(String(msg.sealedB64 || '')))
      } catch { throw mailboxError('BOND_STAMP', 'the reply is not a readable bond stamp') }
      let stamp = null
      try {
        stamp = await groupOpen(crypto.subtle, chainKeys.rendezvousGroup, JSON.parse(raw))
      } catch (e) {
        // THE SAME-CHAIN GATE, typed: the group seal only opens with the
        // chain's own key material — a foreign-chain stamp fails here.
        throw mailboxError('BOND_CHAIN', 'that stamp does not open under this chain — both devices must share the same sync code')
      }
      if (!stamp || stamp.kind !== 'bond-stamp' || !stamp.deviceId || !stamp.signPubJwk || !stamp.agrPubJwk) {
        throw mailboxError('BOND_STAMP', 'the opened reply is not a complete device bond stamp')
      }
      if (String(stamp.deviceId) === String(identity.deviceId)) {
        throw mailboxError('BOND_SELF', 'that stamp is THIS device — pair the other one')
      }
      const learned = await learnPeer(chainKeys, {
        deviceId: stamp.deviceId,
        signPubJwk: stamp.signPubJwk,
        agrPubJwk: stamp.agrPubJwk,
        label: String(stamp.label || ''),
        deviceType: String(stamp.deviceType || ''),
        labelSetAt: Number(stamp.ts) || 0,
      })
      return {
        ok: true,
        learned: { deviceId: learned.deviceId, label: String(learned.label || ''), deviceType: String(learned.deviceType || '') },
        self: { deviceId: identity.deviceId, name: String(identity.label || '') },
      }
    }

    if (msg.type === 'BRIDGE_CODE') {
      // §5.2-b4 — THE SYNC CODE the owner demands: derived worker-side from the
      // chain ROOT's sha256 (material the relay NEVER sees) + both session
      // nonces. Both devices derive the SAME code; it never crosses the wire.
      const { chainKeys } = await ensureChainReady()
      if (!chainKeys || !chainKeys.chainRoot) throw mailboxError('CODE_SEAL', 'the chain root is unavailable on this plane')
      const sealHex = await sha256HexOfBytes(chainKeys.chainRoot instanceof Uint8Array ? chainKeys.chainRoot : new Uint8Array(chainKeys.chainRoot))
      const code = await deriveSafetyCode({ chainSealHex: sealHex, nonceA: String(msg.nonceA || ''), nonceB: String(msg.nonceB || '') })
      return { ok: true, code, formatted: formatSafetyCode(code) }
    }

    if (msg.type === 'BRIDGE_FINGERPRINT') {
      // R147 §5.2 — THE CHAIN FINGERPRINT (the compact offer's f field): the
      // first 16 bytes of the chain root's sha256, hex. It rides the offer
      // envelope so the receiver can name the chain it is pairing with —
      // material the relay never sees in the clear (it rides the seal).
      const { chainKeys } = await ensureChainReady()
      if (!chainKeys || !chainKeys.chainRoot) throw mailboxError('CODE_SEAL', 'the chain root is unavailable on this plane')
      const sealHex = await sha256HexOfBytes(chainKeys.chainRoot instanceof Uint8Array ? chainKeys.chainRoot : new Uint8Array(chainKeys.chainRoot))
      return { ok: true, fingerprintHex: sealHex.slice(0, 32) }
    }

    if (msg.type === 'BRIDGE_DELIVER_FILE') {
      // The DIRECT road's landing FALLBACK (R150 §5 — the page owns the primary
      // save; the bytes live in the transfer page): the same saveReceivedFile
      // law as the mailbox accept — the user's consent gesture opened the
      // channel, the fingerprint was auto-checked by the assembler, nothing
      // ever opens automatically.
      // R150 LAW #80 — THE HANDLER NEVER LIES AGAIN (the B2 autopsy row): the
      // saver's TYPED result is honored — {ok:false, reason} (the R150 SW
      // contract), a legacy boolean false, or a throw all resolve typed
      // {ok:false, code:'SAVE_FAILED…', userMessage}; ok:true only when the
      // bytes truly reached the disk API.
      const { fileName, bytesB64 } = msg
      if (typeof saveReceivedFile !== 'function') return { ok: false, code: 'NO_SAVER', userMessage: 'this environment cannot save files' }
      let saved = null
      try {
        saved = await saveReceivedFile({ fileName: String(fileName || 'file'), bytesB64: String(bytesB64 || '') })
      } catch (e) {
        return { ok: false, code: 'SAVE_FAILED', userMessage: String((e && e.message) || e).slice(0, 160) }
      }
      if (saved && typeof saved === 'object') {
        if (saved.ok) return { ok: true, saved: true, fileName: String(saved.fileName || fileName || 'file') }
        return { ok: false, code: saved.code ? `SAVE_FAILED:${String(saved.code).replace(/^SAVE_FAILED:?/, '')}` : 'SAVE_FAILED', userMessage: String(saved.reason || saved.userMessage || 'the file could not be saved').slice(0, 160) }
      }
      if (!saved) return { ok: false, code: 'SAVE_FAILED', userMessage: 'the file could not be saved' }
      return { ok: true, saved: true, fileName: String(fileName || 'file') }
    }

    throw mailboxError('DOOR', `unknown mailbox message ${msg.type}`)
  } catch (e) {
    const code = (e && e.code) || 'MAILBOX_INTERNAL'
    return { ok: false, code, userMessage: mailboxUserMessage(code, e) }
  }
}

function senderLineFor(j, now) {
  return senderWaitingLine(j, now)
}

function mailboxUserMessage(code, e) {
  const map = {
    MAILBOX_NO_CLOUD: 'Cloud Sync is not connected — Connect',
    MAILBOX_QUOTA_OFFERS: 'The recipient\u2019s mailbox is full — they can collect or let offers expire',
    MAILBOX_QUOTA_BYTES: 'The recipient\u2019s mailbox is at its 200 MB guard',
    MAILBOX_CODE_MISMATCH: 'The verification code does not match — check the digits once more',
    MAILBOX_DAMAGED: 'The offer is damaged (fingerprint mismatch) — ask the sender to send it again',
    MAILBOX_EXPIRED: 'The offer has expired — offers live 7 days',
    MAILBOX_WRONG_RECIPIENT: 'This offer is addressed to another device',
    MAILBOX_SEAL_FOREIGN: 'This offer is not from your sync chain',
  }
  return map[code] || String((e && e.message) || code).replace(/^MAILBOX_[A-Z_]+: /, '').slice(0, 160)
}

function arrayBufferToB64(bytes) {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s)
}
function b64ToBytes2(b64) {
  const s = atob(String(b64 || ''))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}
function concatB64Chunks(chunks) {
  const parts = chunks.map(b64ToBytes2)
  const total = parts.reduce((a, p) => a + p.length, 0)
  const all = new Uint8Array(total)
  let off = 0
  for (const p of parts) { all.set(p, off); off += p.length }
  return all
}
