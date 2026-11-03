/**
 * UCrypt — Setup self-check (R93 §5, the acceptance round).
 *
 * A bounded, READ-ONLY diagnostic surface: "Verify my setup" on Settings.
 * Seven checks, green/red per row, one plain sentence per red, no auto-fixes,
 * no new permissions. It converts the acceptance protocol into product value:
 * every future user can see the same green rows the owner's protocol demands.
 *
 * LAWS:
 *  - read-only: nothing here mutates vault, storage, grants or UI state;
 *  - typed: every red row names the fix in one sentence (the 13-year-old law);
 *  - scope-frozen: exactly these seven checks, no hidden extras;
 *  - the pure helpers are unit-tested (battery, per-file regime); the
 *    orchestration takes INJECTED io so tests run without chrome.
 */

/**
 * The frozen check roster (order §5; the R121 §4.3 amendment appended
 * 'ladder' — the growth is COMMANDED by the R121 order, documented on its
 * census row, machine-gated (G24-ladder), and additions-only: the seven
 * original ids keep their order and meaning). R171: the growth is COMMANDED
 * again — 'spine' rides (the unbroken spine's zero-window probe verdict,
 * next to the existing rows; never replaces one).
 */
export const SELF_CHECK_IDS = Object.freeze([
  'transport', 'chain', 'backup', 'capture', 'badge', 'storage', 'grants',
  'ladder', 'spine',
])

/** The transports that climb the Sign-In Ladder (law 0.32) — the ladder
 * check emits ONE row per transport, in this order. */
export const LADDER_TRANSPORTS = Object.freeze(['gdrive', 'github', 'dropbox'])

/**
 * R121 §4.3 — the rung a stored transport record was won at. PURE: reads
 * field NAMES/presence only (never values — the record's grants are sealed
 * envelopes and stay that way). The REAL field names per transport (the
 * same shapes the lifecycle engine, ladder.js §RUNG_LIFECYCLE_KEYS, knows):
 *   gdrive:  signinMode/authMode 'fast' → fast; authMode 'oauth' → guided;
 *            authMode 'bridge' (or absent — the legacy bridge path) → manual
 *            (carrier 'bridge' — the Bridge is gdrive's manual rung).
 *   github:  signinMode 'fast' → fast; 'guided' → guided; a pasted `token`
 *            with no mode → manual (carrier 'pat'); the safe fallback is
 *            guided (the same rule ladder.js rungSafe uses).
 *   dropbox: signinMode 'fast' → fast; 'guided' → guided; a pasted `token`
 *            with no mode → manual (carrier 'pat' — the Advanced paste).
 * @param {string} transportId
 * @param {object} [stored] the stored record ({ id, config } or a flat config)
 * @returns {{ rung: 'fast'|'guided'|'manual'|'', carrier: string }}
 */
export function deriveLiveRung(transportId, stored) {
  const cfg = stored && stored.config && typeof stored.config === 'object' && !Array.isArray(stored.config)
    ? stored.config
    : (stored && typeof stored === 'object' ? stored : {})
  const id = String(transportId || (stored && stored.id) || '').trim().toLowerCase()
  const sm = String(cfg.signinMode || '').trim().toLowerCase()
  const present = (k) => cfg[k] !== undefined && cfg[k] !== null && String(cfg[k]) !== ''
  if (id === 'gdrive') {
    const am = String(cfg.authMode || '').trim().toLowerCase()
    if (sm === 'fast' || am === 'fast') return { rung: 'fast', carrier: 'fast' }
    if (am === 'oauth' || sm === 'guided') return { rung: 'guided', carrier: 'oauth' }
    return { rung: 'manual', carrier: 'bridge' }
  }
  if (id === 'github' || id === 'dropbox') {
    if (sm === 'fast') return { rung: 'fast', carrier: 'fast' }
    if (sm === 'guided') return { rung: 'guided', carrier: 'oauth' }
    if (present('token')) return { rung: 'manual', carrier: 'pat' }
    return { rung: 'guided', carrier: 'oauth' }
  }
  return { rung: '', carrier: '' }
}

/**
 * R121 §4.3 — the ladder-awareness audit (PURE). Takes the read-only probes
 * and answers, in one glance: which rung each ladder transport lives on,
 * whether the fast rung is offered/gracefully-absent/unavailable, and how
 * the transport's last connect attempt ended.
 *
 * @param {{ records?: Object<string,object|null>, detect?: Object<string,{available:boolean,reason:string}|null>, lastRing?: Object<string,{outcome:string,stage:string,rung:string,ts:number}|null> }} probes
 *   records[id]  → the stored record for a ladder transport (or null)
 *   detect[id]   → detectFastRung's result (or null)
 *   lastRing[id] → the newest connect ring (or null)
 * @returns {{ rows: Array<{transport, ok: boolean|null, rung, carrier, fastState, lastOutcome, detailKey, detail}>, ok: boolean, note: string }}
 *   ok rules (the truthful state line — never a false green, never a red for
 *   the graceful absence): a transport with no record → null (informational;
 *   the row names the missing precondition and the fix inline, 0.13/0.29);
 *   a connected transport → red ONLY when its last connect ring failed.
 */
export function auditLadderRungs(probes) {
  const { records = {}, detect = {}, lastRing = {} } = probes || {}
  const rows = []
  const glance = []
  for (const t of LADDER_TRANSPORTS) {
    const rec = records[t] || null
    const connected = !!(rec && (rec.id || rec.config || (typeof rec === 'object' && Object.keys(rec).length > 0)))
    if (!connected) {
      rows.push({ transport: t, ok: null, rung: '', carrier: '', fastState: '', lastOutcome: 'none', detailKey: 'scLadderNone', detail: '' })
      glance.push(`${t}: —`)
      continue
    }
    const { rung, carrier } = deriveLiveRung(t, rec)
    const d = detect[t] || null
    // The fast rung's availability state (the order's vocabulary):
    //   offered     — the shared sign-in is detectable here;
    //   absent      — the graceful absence (client-id-absent): lawful, never red;
    //   unavailable — the browser lacks the platform piece (typed reason).
    let fastState = 'n/a'
    if (d) fastState = d.available ? 'offered' : (d.reason === 'client-id-absent' ? 'absent' : 'unavailable')
    const ring = lastRing[t] || null
    const lastOutcome = ring ? (String(ring.outcome) === 'ok' ? 'ok' : 'fail') : 'none'
    const ok = lastOutcome !== 'fail'
    const carrierBit = carrier && carrier !== rung ? ` (${carrier})` : ''
    rows.push({
      transport: t, ok, rung, carrier, fastState, lastOutcome,
      detailKey: ok ? 'scLadderOk' : 'scLadderFail',
      detail: `${t}: rung=${rung}${carrierBit} fast=${fastState} lastConnect=${lastOutcome}`,
    })
    glance.push(`${t}: ${rung}${fastState !== 'n/a' ? `·fast-${fastState}` : ''}·${lastOutcome}`)
  }
  return { rows, ok: rows.every((r) => r.ok !== false), note: glance.join('  ') }
}

/** The sealed credential-envelope prefix (the 0.14 law's at-rest shape). */
export const SEALED_ENVELOPE_PREFIX = 'ucrypt:cred-env:'

/** True when a stored value is a sealed envelope (never the plaintext). */
export function isSealedEnvelope(v) {
  return typeof v === 'string' && v.startsWith(SEALED_ENVELOPE_PREFIX) && v.length > SEALED_ENVELOPE_PREFIX.length + 8
}

/**
 * §0.14 audit: every secret field of the transport record must be a sealed
 * envelope at rest. Pure: takes the raw stored config + the field list.
 * @returns {{ ok: boolean, sealed: number, offenders: string[], hasRecord: boolean }}
 */
export function auditGrantsSealed(rawConfig, secretFields) {
  if (!rawConfig || typeof rawConfig !== 'object') {
    return { ok: false, sealed: 0, offenders: [], hasRecord: false }
  }
  const offenders = []
  let sealed = 0
  for (const f of secretFields || []) {
    const v = rawConfig[f]
    if (v === undefined || v === null || v === '') continue // field absent — nothing to seal
    if (isSealedEnvelope(v)) sealed++
    else offenders.push(f)
  }
  return { ok: offenders.length === 0 && sealed > 0, sealed, offenders, hasRecord: true }
}

/**
 * Storage-growth law: the bounded structures stay inside their caps and the
 * storage.byte estimate stays inside Chrome's local quota. Pure.
 * @param {{ interruptedLedger: number, cleanupLedger: number, sessions: number, peers: number, localBytes: number, localBytesCap?: number }} m
 */
export function auditStorageCaps(m, cap = 8 * 1024 * 1024) {
  const caps = { interruptedLedger: 5, cleanupLedger: 20, sessions: 20, peers: 10, localBytes: cap }
  const over = Object.keys(caps).filter((k) => Number(m[k] || 0) > caps[k])
  return {
    ok: over.length === 0,
    over,
    caps,
    note: `interrupted=${m.interruptedLedger}/5 cleanup=${m.cleanupLedger}/20 sessions=${m.sessions}/20 peers=${m.peers}/10 storage=${Math.round((m.localBytes || 0) / 1024)} KB/${Math.round(cap / 1024)} KB`,
  }
}

/**
 * Badge law probe: the decision the worker's writer must have made for the
 * current tab context. Pure — takes the computed badge object + the law.
 */
export function badgeLawOk(badge, ctx) {
  if (!badge) return false
  if (ctx.incognito) return badge.text === '' // off in private windows
  if (!ctx.unlocked) return badge.text === '\u2022' // the locked marker, never a count
  if (ctx.protocol !== 'http:' && ctx.protocol !== 'https:') return badge.text === ''
  if (ctx.count > 9) return badge.text === '9+'
  return badge.text === String(Math.max(0, ctx.count || 0))
}

/**
 * Run the seven checks. `io` is injected (chrome in the worker; mocks in the
 * battery). Every row: { id, ok, labelKey, detail }. ok=true green,
 * ok=false red (with a typed fix sentence), ok=null informational.
 */
export async function runSelfChecks(io) {
  const rows = []

  // R121 §4.3 — the ladder probe is taken ONCE at the START of the run: the
  // ladder rows describe the state BEFORE this Verify run (the run's own
  // transport test — check 1 — legitimately writes its own connect ring,
  // and that result is already surfaced by the transport row itself; the
  // ladder rows must never read the run's own probe as a user failure).
  let ladderProbeResult = null
  try { ladderProbeResult = await io.ladderProbe() } catch (e) { ladderProbeResult = { __threw: String(e && e.message || e) } }

  // 1. Transport reachable (typed probe; informational when not configured).
  try {
    const rec = await io.getRawTransportRecord()
    if (!rec || !rec.id) {
      rows.push({ id: 'transport', ok: null, labelKey: 'scTransport', detailKey: 'scTransportNone' })
    } else if (await io.isLocked()) {
      rows.push({ id: 'transport', ok: null, labelKey: 'scTransport', detailKey: 'scTransportLocked' })
    } else {
      const opened = await io.getOpenedTransportRecord()
      // testConnection returns a TYPED MESSAGE STRING on success and throws
      // a SyncError (userMessage) on failure — both shapes are handled.
      const res = await io.testTransport(opened.id, opened.config)
      const ok = typeof res === 'string' && !!res.trim()
      rows.push({
        id: 'transport', ok, labelKey: 'scTransport',
        detailKey: ok ? 'scTransportOk' : 'scTransportFail',
        detail: ok ? String(res).slice(0, 140) : '',
      })
    }
  } catch (e) {
    rows.push({ id: 'transport', ok: false, labelKey: 'scTransport', detailKey: 'scTransportFail', detail: String((e && (e.userMessage || e.message)) || e).slice(0, 160) })
  }

  // 2. Chain joined (a sync code is set on this device).
  try {
    const st = await io.getSyncStatus()
    rows.push({
      id: 'chain', ok: !!st.syncEnabled, labelKey: 'scChain',
      detailKey: st.syncEnabled ? 'scChainOk' : 'scChainNone',
      detail: st.syncEnabled ? '' : '',
    })
  } catch (e) {
    rows.push({ id: 'chain', ok: false, labelKey: 'scChain', detailKey: 'scChainNone', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 3. Backup verified (the code was verified or adopted).
  try {
    const flag = await io.getBackupFlag()
    rows.push({
      id: 'backup', ok: !!(flag && flag.verified), labelKey: 'scBackup',
      detailKey: flag && flag.verified ? 'scBackupOk' : 'scBackupNone',
    })
  } catch (e) {
    rows.push({ id: 'backup', ok: false, labelKey: 'scBackup', detailKey: 'scBackupNone', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 4. Capture pipeline armed (fixture-free): content scripts registered +
  //    the never-save store readable + the worker relay present.
  try {
    const c = await io.captureProbe()
    const ok = !!(c.manifestContentScripts && c.neverSaveReadable && c.relayRegistered)
    rows.push({ id: 'capture', ok, labelKey: 'scCapture', detailKey: ok ? 'scCaptureOk' : 'scCaptureFail' })
  } catch (e) {
    rows.push({ id: 'capture', ok: false, labelKey: 'scCapture', detailKey: 'scCaptureFail', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 5. Badge compute (the pure law against the live decision).
  try {
    const b = await io.badgeProbe()
    rows.push({ id: 'badge', ok: badgeLawOk(b.badge, b.ctx), labelKey: 'scBadge', detailKey: b.badge && badgeLawOk(b.badge, b.ctx) ? 'scBadgeOk' : 'scBadgeFail', detail: `text=${JSON.stringify(b.badge && b.badge.text)} count=${b.ctx.count} unlocked=${b.ctx.unlocked}` })
  } catch (e) {
    rows.push({ id: 'badge', ok: false, labelKey: 'scBadge', detailKey: 'scBadgeFail', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 6. Storage growth within caps.
  try {
    const m = await io.storageProbe()
    const audit = auditStorageCaps(m)
    rows.push({ id: 'storage', ok: audit.ok, labelKey: 'scStorage', detailKey: audit.ok ? 'scStorageOk' : 'scStorageFail', detail: audit.note })
  } catch (e) {
    rows.push({ id: 'storage', ok: false, labelKey: 'scStorage', detailKey: 'scStorageFail', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 7. Grants sealed (the 0.14 audit as a green check).
  try {
    const g = await io.grantsProbe()
    if (!g.hasRecord) {
      rows.push({ id: 'grants', ok: null, labelKey: 'scGrants', detailKey: 'scGrantsNone' })
    } else {
      const audit = auditGrantsSealed(g.rawConfig, g.secretFields)
      rows.push({
        id: 'grants', ok: audit.ok, labelKey: 'scGrants',
        detailKey: audit.ok ? 'scGrantsOk' : 'scGrantsFail',
        detail: audit.ok ? `sealed=${audit.sealed}` : `plaintext fields: ${audit.offenders.join(', ')}`,
      })
    }
  } catch (e) {
    rows.push({ id: 'grants', ok: false, labelKey: 'scGrants', detailKey: 'scGrantsFail', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 8. The Sign-In Ladder's live rows (R121 §4.3 — one row per ladder
  //    transport: the rung it lives on, the fast rung's availability state,
  //    the last connect outcome. READ-ONLY: the probe reads the stored
  //    record's field PRESENCE, the feature detection, and the typed rings —
  //    no network, no grants decrypted, nothing mutated. The probe was
  //    snapshotted BEFORE check 1 — see the comment at the top).
  try {
    if (ladderProbeResult && ladderProbeResult.__threw) throw new Error(ladderProbeResult.__threw)
    const audit = auditLadderRungs(ladderProbeResult)
    for (const r of audit.rows) {
      rows.push({ id: 'ladder', ok: r.ok, labelKey: 'scLadder', detailKey: r.detailKey, detail: r.detail })
    }
  } catch (e) {
    rows.push({ id: 'ladder', ok: false, labelKey: 'scLadder', detailKey: 'scLadderFail', detail: String(e && e.message || e).slice(0, 120) })
  }

  // 9. THE SPINE ROW (R171 — the unbroken spine's zero-window probe, the
  //    contract's (b)): the service worker fetches the spine client's
  //    authorization URL and reads where Google's redirect lands — the
  //    sign-in page = ARMED (the persistent sign-in is available); the
  //    error page with the authError blob = UNARMED (the Console Item-ID
  //    row is not live yet; the decode, never a guess). NO window opens,
  //    no user data rides, nothing mutates. The row sits NEXT to the
  //    existing rows (additions-only); when the io door is absent the row
  //    is honestly skipped (informational) — the older battery's shape
  //    rides byte-true.
  try {
    if (typeof io.spineProbe !== 'function') {
      rows.push({ id: 'spine', ok: null, labelKey: 'scSpine', detailKey: 'scSpineNone', detail: '' })
    } else {
      const sp = await io.spineProbe()
      if (sp && sp.ok === 'armed') {
        rows.push({ id: 'spine', ok: true, labelKey: 'scSpine', detailKey: 'scSpineArmed', detail: String(sp.detail || '').slice(0, 200) })
      } else if (sp && sp.ok === 'unarmed') {
        rows.push({ id: 'spine', ok: null, labelKey: 'scSpine', detailKey: 'scSpineUnarmed', detail: (sp.blobCode ? String(sp.blobCode) + ' — ' : '') + String(sp.detail || '').slice(0, 200) })
      } else if (sp && sp.ok === 'offline') {
        rows.push({ id: 'spine', ok: null, labelKey: 'scSpine', detailKey: 'scSpineOffline', detail: String(sp.detail || '').slice(0, 120) })
      } else {
        rows.push({ id: 'spine', ok: null, labelKey: 'scSpine', detailKey: 'scSpineUntyped', detail: String((sp && sp.raw) || '').slice(0, 120) })
      }
    }
  } catch (e) {
    rows.push({ id: 'spine', ok: null, labelKey: 'scSpine', detailKey: 'scSpineUntyped', detail: String(e && e.message || e).slice(0, 120) })
  }

  const order = Object.fromEntries(SELF_CHECK_IDS.map((id, i) => [id, i]))
  rows.sort((a, b) => (order[a.id] ?? 99) - (order[b.id] ?? 99))
  const green = rows.filter((r) => r.ok === true).length
  const red = rows.filter((r) => r.ok === false).length
  const info = rows.filter((r) => r.ok === null).length
  return { ts: Date.now(), rows, green, red, info, allGreen: red === 0 }
}

/** True when every row of a result is green or informational (seal-time law). */
export function sealTimeGreen(result) {
  return !!result && result.rows.every((r) => r.ok !== false)
}
