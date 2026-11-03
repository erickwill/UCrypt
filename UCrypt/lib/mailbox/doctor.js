/**
 * UCrypt — R141 §7.9 — THE MAILBOX DOCTOR (curing F4/F8: a doctor that says
 * only "it failed" is retired with the planes).
 *
 * Every probe names its hop; every red names the ONE blocked step and the
 * ONE action, derived from the single chain-state truth module. The probes:
 *   cloud    — is Cloud Sync connected at all? (chain-state verdict)
 *   write    — can THIS device write its own probe object? (sender's first hop)
 *   index    — can the recipient's index be read back? (the manifest hop)
 *   chunk    — can a written probe chunk be fetched? (the bulk hop)
 *   receipt  — can the receipt path be written? (the arrival-truth hop)
 *
 * A probe NEVER throws: it returns {hop, ok, detail, action} — the drawer
 * renders every hop's truth and the ONE action for the first red.
 *
 * PURE (store injected) — battery-pinned (G91 doctor rows).
 */

import { mailboxLayout, mailboxError } from './protocol.js'
import { assertStoreConformance } from './store.js'

export const MAILBOX_HOPS = ['cloud', 'write', 'index', 'chunk', 'receipt']

const ACTIONS = {
  cloud: 'Connect Cloud Sync to transfer',
  write: 'Retry now',
  index: 'Retry now',
  chunk: 'Retry now',
  receipt: 'Retry now',
}

/** Run every hop against the injected store. A red carries the typed detail
 * and the one action — never a bare failure. */
export async function runMailboxDoctor({ store, selfMemberId, peerMemberId = null, now = Date.now() }) {
  const results = []
  const push = (hop, ok, detail) => results.push({ hop, ok, detail: String(detail || '').slice(0, 200), action: ok ? '' : ACTIONS[hop] })

  try {
    assertStoreConformance(store)
    push('cloud', true, 'the mailbox store binding is alive')
  } catch (e) {
    push('cloud', false, e && e.code ? e.code : 'the store binding is malformed')
    return { ok: false, hops: results, firstRed: results[0] }
  }

  const probeName = mailboxLayout.inboxOffer(selfMemberId, `doctor-probe-${now}`)
  try {
    await store.put(probeName, JSON.stringify({ probe: true, at: now }))
    push('write', true, 'the write hop answered')
  } catch (e) {
    push('write', false, hopDetail(e))
    return { ok: false, hops: results, firstRed: results.find((r) => !r.ok) }
  }

  try {
    const got = await store.get(probeName)
    if (!got || !got.ok) throw mailboxError('PROBE', 'the probe object did not read back')
    push('index', true, 'the read-back hop answered')
  } catch (e) {
    push('index', false, hopDetail(e))
    return { ok: false, hops: results, firstRed: results.find((r) => !r.ok) }
  }

  try {
    const chunkName = mailboxLayout.inboxChunk(selfMemberId, `doctor-probe-${now}`, 0)
    await store.put(chunkName, 'probe-chunk')
    const c = await store.get(chunkName)
    if (!c || !c.ok) throw mailboxError('PROBE', 'the probe chunk did not read back')
    push('chunk', true, 'the chunk hop answered')
  } catch (e) {
    push('chunk', false, hopDetail(e))
    return { ok: false, hops: results, firstRed: results.find((r) => !r.ok) }
  }

  try {
    const receiptName = mailboxLayout.receipt(selfMemberId, `doctor-probe-${now}`)
    await store.put(receiptName, JSON.stringify({ v: 1, state: 'written', probe: true }))
    push('receipt', true, 'the receipt hop answered')
  } catch (e) {
    push('receipt', false, hopDetail(e))
    return { ok: false, hops: results, firstRed: results.find((r) => !r.ok) }
  }

  // cleanup is best-effort (probe objects are tiny and expire with the round)
  try { await store.remove(probeName) } catch { /* the probe file is inert */ }

  return { ok: true, hops: results, firstRed: null }
}

function hopDetail(e) {
  if (e && e.code === 'MAILBOX_FOLDER_MISSING') return 'the mailbox folder is missing on the cloud — the doctor\u2019s recreate lands it'
  if (e && e.code === 'MAILBOX_CONFLICT') return 'the write conflicted twice — another device is writing the same object'
  if (e && e.code) return e.code
  return String((e && e.message) || e).slice(0, 160)
}
