/**
 * UCrypt — R135 — THE NEW SURFACES (Sync Doctor, Chain Data Types,
 * Cross-browser Import). New in v2.92.0 (additions-only on the sealed
 * v2.91.0 base — the sealed Password Health dashboard already renders in
 * the Security tab; this module adds the three surfaces R135 commands).
 *
 * Every card obeys the surface contract: typed idle/working/success/fail
 * states, a reason + a next step on every failure, a one-line inline
 * explainer, and the never-auto-close law (no timer dismisses anything;
 * every dialog closes ONLY on a user action).
 */

import { getMessage } from './i18n.js'
import { runSyncDoctor, SyncDiagnosticsLedger, classifyTokenEvent, TOKEN_OUTCOMES } from './sync-doctor.js'
import { getTransport } from './transports/index.js'
import { idDriftPreflight } from './cloud/id-doctor.js'
import { CHAIN_DATA_TYPES, defaultToggles, normalizeToggles } from './chaindata.js'
import { parsePasswordsCsv, parseBookmarksHtml, dryRunPreview, dedupeDecisions, secureWipe, buildImportReport, originOf } from './import-migration.js'
import { analyzePassword } from './analyzer.js'
import { boundedImport, watchdogLandingWords } from './import-watchdog.js'

const $id = (id) => document.getElementById(id)

function msg(key, fallback, subs = undefined) {
  try { return getMessage(key, subs, fallback) || fallback } catch { return fallback }
}

function el(tag, cls, text) {
  const n = document.createElement(tag)
  if (cls) n.className = cls
  if (text != null) n.textContent = text
  return n
}

async function bgSend(type, data = {}) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type, ...data }, (res) => resolve(res || { ok: false, error: 'no_response' }))
    } catch (e) {
      resolve({ ok: false, error: String(e && e.message || e) })
    }
  })
}

// --- 1. The Sync Doctor card ---------------------------------------------------

const _diagLedger = new SyncDiagnosticsLedger()

async function runDoctor() {
  const state = $id('syncDoctorState')
  const out = $id('syncDoctorOut')
  if (state) state.textContent = msg('syncDoctorWorking', 'Running the self-check…')
  if (out) out.textContent = ''
  // R164 ARC D — the IDENTITY row runs FIRST (the door's frame before the
  // door): the pinned key's derived ID vs chrome.runtime.id. A drift speaks
  // the honest sentence and the row is typed as a fail — fail-closed,
  // disabled + explained, never hidden, never removed (G187).
  try {
    const v = await idDriftPreflight()
    const row = document.createElement('p')
    row.className = 'card-help'
    row.setAttribute('role', 'status')
    row.id = 'idDoctorRow'
    row.textContent = v.ok
      ? `${msg('idDoctorRowLabel', 'Identity')}: ${msg('idDoctorRowOk', 'This install is the pinned build — the extension ID is verified against the pinned key.')}`
      : `${msg('idDoctorRowLabel', 'Identity')}: ${v.sentence || msg(v.sentenceKey, v.subs, v.sentence)}`
    if (out) out.appendChild(row)
  } catch { /* the identity row never blocks the doctor's own steps */ }
  // The probes are the honest local checks; reachability is the ONE network
  // probe (the provider's own endpoint — the doctor's purpose).
  const storage = chrome.storage && chrome.storage.local
  const keys = await storage.get(['ucrypt:sync:cloud', 'ucrypt:beam:lastLegs', 'ucrypt:sync:lastSnapshot'])
  const cloud = keys['ucrypt:sync:cloud'] || null
  const probes = {
    auth: async () => {
      if (!cloud || !cloud.connected) return { ok: false, detail: 'No cloud storage is connected yet.', next: 'Press “Choose cloud storage” and sign in.' }
      return { ok: true, detail: `A cloud transport is connected (${String(cloud.provider || 'provider').slice(0, 24)}).` }
    },
    token: async () => {
      if (!cloud || !cloud.connected) return { ok: false, detail: 'Without a connected transport there is no token to check.', next: 'Connect the cloud storage first.' }
      const outcome = classifyTokenEvent({ httpStatus: cloud.lastStatus || 200 })
      if (outcome.outcome === TOKEN_OUTCOMES.REAUTH_REQUIRED) return { ok: false, detail: outcome.why, next: outcome.next, repair: 'Sign in again from the cloud card above.', ownerFix: true }
      return { ok: true, detail: `The last sync step ended as “${outcome.outcome}”.` }
    },
    reachability: async () => {
      const base = String((cloud && cloud.vaultUrl) || '').replace(/\/[^/]*$/, '/')
      if (!base) return { ok: false, detail: 'No provider base URL is known yet.', next: 'Connect the cloud storage first.' }
      const t0 = Date.now()
      try {
        await fetch(base, { method: 'HEAD', mode: 'cors' })
        _diagLedger.record({ phase: 'doctor:reachability', tokenState: 'pass', httpStatus: 200, latencyMs: Date.now() - t0, errorClass: 'pass' })
        return { ok: true, detail: `The provider answered in ${Date.now() - t0} ms.` }
      } catch (e) {
        _diagLedger.record({ phase: 'doctor:reachability', tokenState: 'fail', httpStatus: null, latencyMs: Date.now() - t0, errorClass: 'network' })
        return { ok: false, detail: 'The provider did not answer the HEAD probe (offline, blocked, or a captive portal).', next: 'Check the network; the sync queue keeps every write meanwhile.' }
      }
    },
    mailbox: async () => {
      const legs = keys['ucrypt:beam:lastLegs']
      if (!legs) return { ok: true, detail: 'The direct-sync legs ledger is empty — nothing has failed.' }
      const last = legs.lastCloudLeg || legs.lastDirectByPeer
      const bad = last && last.ok === false
      return bad
        ? { ok: false, detail: `The last direct leg reported: ${String(last.reason || 'unknown')}.`, next: 'Open the transfer tab — the legs ledger shows the per-device truth.' }
        : { ok: true, detail: 'The direct-sync legs ledger is healthy.' }
    },
    snapshot: async () => {
      const snap = keys['ucrypt:sync:lastSnapshot']
      if (!snap || !snap.at) return { ok: false, detail: 'No snapshot has been recorded on this device yet.', next: 'Run one sync cycle from the cloud card above.' }
      return { ok: true, detail: `The last snapshot was recorded ${new Date(snap.at).toLocaleString()}.` }
    },
  }
  const steps = await runSyncDoctor(probes, { ledger: _diagLedger })
  if (out) {
    out.textContent = ''
    for (const s of steps) {
      const row = el('div', 'sync-doctor-row')
      const icon = s.status === 'pass' ? '✅' : (s.status === 'repair' ? '🛠' : '❌')
      row.appendChild(el('strong', null, `${icon} ${msg(`syncDoctorStep_${s.key}`, s.key)}`))
      row.appendChild(el('span', 'card-help', ` ${s.why}`))
      if (s.next) row.appendChild(el('div', 'card-help', `→ ${s.next}${s.ownerFix ? ` ${msg('syncDoctorOwnerFix', '(this step needs the account owner — engineering cannot repair it)')}` : ''}`))
      out.appendChild(row)
    }
  }
  if (state) {
    const fails = steps.filter((s) => s.status !== 'pass').length
    state.textContent = fails === 0
      ? msg('syncDoctorAllPass', 'All five steps passed.')
      : msg('syncDoctorFails', '$1$ step(s) need attention — the why and the next step are on each row.').replace('$1$', String(fails))
  }
}

async function exportDiagnostics() {
  const state = $id('syncDoctorState')
  const data = _diagLedger.exportRedacted()
  const text = JSON.stringify(data, null, 2)
  try {
    await navigator.clipboard.writeText(text)
    if (state) state.textContent = msg('syncDoctorExported', 'The redacted diagnostics ledger was copied to the clipboard (no tokens, no personal data).')
  } catch {
    const out = $id('syncDoctorOut')
    if (out) {
      const ta = el('textarea')
      ta.value = text
      ta.rows = 8
      ta.style.width = '100%'
      out.appendChild(ta)
    }
    if (state) state.textContent = msg('syncDoctorExportFallback', 'Clipboard unavailable — the ledger is shown below; copy it manually.')
  }
}

function initSyncDoctor() {
  const card = $id('syncDoctorCard')
  if (!card) return false
  const run = $id('syncDoctorRun')
  if (run) run.addEventListener('click', () => { runDoctor().catch((e) => console.warn('[UCrypt] SyncDoctor:', e)) })
  const exp = $id('syncDoctorExport')
  if (exp) exp.addEventListener('click', () => { exportDiagnostics().catch(() => {}) })
  // R164 Arc E — the Drive smoke (the lab half of S128): write → read back →
  // delete, all inside appDataFolder, all through the fast token seam. The
  // receipt prints in the doctor's own output — NO token, NO personal data.
  const smoke = $id('driveSmokeRun')
  if (smoke) smoke.addEventListener('click', async () => {
    const state = $id('syncDoctorState')
    const out = $id('syncDoctorOut')
    if (state) state.textContent = msg('driveSmokeRunning', 'Running the Drive smoke test…')
    try {
      const t = getTransport('gdrive')
      const mod = t && t._smoke ? t : await import('./transports/gdrive.js')
      const run = (t && t._smoke) ? t._smoke : (mod && mod.driveSmokeTest)
      if (typeof run !== 'function') throw new Error('the smoke leg is unavailable on this build')
      const r = await run()
      if (out) {
        const row = document.createElement('p')
        row.className = 'card-help'
        row.setAttribute('role', 'status')
        if (r && r.wrote && r.match && r.deleted) {
          row.textContent = msg('driveSmokeOk', [String(r.bytes)], `Smoke receipt: wrote ${r.bytes} bytes, read back byte-exact, deleted — the private folder works.`)
        } else {
          const why = !r || !r.wrote ? 'the write did not confirm' : (!r.match ? 'the read-back differed' : 'the delete did not confirm')
          row.textContent = `${msg('driveSmokeFailLabel', 'The smoke test stopped')}: ${why}`
        }
        out.appendChild(row)
      }
      if (state) state.textContent = r && r.wrote && r.match && r.deleted ? msg('driveSmokeDone', 'The Drive smoke test finished.') : ''
    } catch (e) {
      if (out) {
        const row = document.createElement('p')
        row.className = 'card-help'
        row.setAttribute('role', 'status')
        row.textContent = `${msg('driveSmokeFailLabel', 'The smoke test stopped')}: ${String((e && e.message) || e).slice(0, 200)}`
        out.appendChild(row)
      }
      if (state) state.textContent = ''
    }
  })

  // ── R165 ARC B — THE OAUTH VERDICT LADDER (one walk, four rungs, the
  // domain named on every failure) + ARC C (the reset row) + ARC F (the
  // copyable connection receipt — no token, no personal data). ──────────
  let _lastLadderWalk = null
  const ladderBtn = $id('oauthLadderRun')
  const resetBtn = $id('oauthLadderReset')
  const receiptBtn = $id('oauthLadderReceipt')
  const ladderState = () => $id('syncDoctorState')
  const ladderOut = () => $id('syncDoctorOut')
  const ladderFacts = () => {
    let extensionId = ''
    let clientId = ''
    try {
      extensionId = String(chrome.runtime.id || '')
      const m = chrome.runtime.getManifest()
      clientId = String((m && m.oauth2 && m.oauth2.client_id) || '')
    } catch { /* the receipt prints what it can verify */ }
    return { extensionId, clientId }
  }
  if (ladderBtn) ladderBtn.addEventListener('click', async () => {
    const state = ladderState()
    const out = ladderOut()
    ladderBtn.disabled = true
    if (state) state.textContent = msg('oauthLadderBusy', 'Checking the connection — four rungs…')
    try {
      const L = await import('./oauth-ladder.js')
      const g = await import('./transports/gdrive.js')
      const smokeFn = (g && g.driveSmokeTest) ? () => g.driveSmokeTest() : null
      const walk = await L.runConnectionCheck({ smoke: smokeFn })
      _lastLadderWalk = walk
      if (out) {
        for (const r of walk.rungs) {
          const row = document.createElement('div')
          row.className = 'sync-doctor-row'
          row.setAttribute('role', r.ok ? 'status' : 'alert')
          const head = document.createElement('strong')
          head.textContent = `${r.ok ? '✅' : '❌'} ${msg(`oauthLadderRung_${r.key}`, r.key)}${r.ok ? '' : ` — ${r.domain || 'FAILED'}`}`
          row.appendChild(head)
          const d = document.createElement('div')
          d.className = 'card-help'
          d.textContent = r.detail || ''
          row.appendChild(d)
          if (!r.ok && r.fix) {
            const f = document.createElement('div')
            f.className = 'card-help'
            f.textContent = `→ ${r.fix}`
            row.appendChild(f)
          }
          out.appendChild(row)
        }
      }
      if (state) {
        state.textContent = walk.allOk
          ? msg('oauthLadderAllPass', 'All four rungs passed — the door is wired end to end.')
          : msg('oauthLadderFails', 'A rung failed — its row names the domain that owns the fix (CODEBASE = UCrypt, CONSOLE = the Google-side binding, CONSENT = your own action).')
      }
      if (receiptBtn) receiptBtn.disabled = false
    } catch (e) {
      if (state) state.textContent = `${msg('oauthLadderFailLabel', 'The connection check stopped')}: ${String((e && e.message) || e).slice(0, 160)}`
    } finally {
      ladderBtn.disabled = false
    }
  })
  if (resetBtn) resetBtn.addEventListener('click', async () => {
    const state = ladderState()
    const out = ladderOut()
    resetBtn.disabled = true
    if (state) state.textContent = msg('oauthLadderResetting', 'Clearing the cached sign-in…')
    try {
      const L = await import('./oauth-ladder.js')
      const r = await L.resetConnection()
      if (out) {
        const row = document.createElement('div')
        row.className = 'sync-doctor-row'
        row.setAttribute('role', r.ok ? 'status' : 'alert')
        const head = document.createElement('strong')
        head.textContent = `${r.ok ? '✅' : '⚠️'} ${msg('oauthLadderResetHead', 'Reset connection')}`
        row.appendChild(head)
        const d = document.createElement('div')
        d.className = 'card-help'
        d.textContent = r.detail || ''
        row.appendChild(d)
        const steps = document.createElement('div')
        steps.className = 'card-help'
        const list = document.createElement('ul')
        list.style.margin = '4px 0 0 18px'
        for (const s of r.steps) {
          const li = document.createElement('li')
          li.textContent = s
          list.appendChild(li)
        }
        steps.appendChild(list)
        row.appendChild(steps)
        out.appendChild(row)
      }
      if (state) state.textContent = ''
    } catch (e) {
      if (state) state.textContent = `${msg('oauthLadderFailLabel', 'The connection check stopped')}: ${String((e && e.message) || e).slice(0, 160)}`
    } finally {
      resetBtn.disabled = false
    }
  })
  if (receiptBtn) receiptBtn.addEventListener('click', async () => {
    const state = ladderState()
    try {
      const L = await import('./oauth-ladder.js')
      if (!_lastLadderWalk) {
        if (state) state.textContent = msg('oauthLadderReceiptNone', 'Run the connection check first — the receipt carries its rung results.')
        return
      }
      const text = L.connectionReceipt(_lastLadderWalk, ladderFacts())
      try {
        await navigator.clipboard.writeText(text)
        if (state) state.textContent = msg('oauthLadderReceiptCopied', 'The connection receipt was copied — it carries NO token, NO personal data, NO vault material.')
      } catch {
        const out = ladderOut()
        if (out) {
          const ta = document.createElement('textarea')
          ta.value = text
          ta.rows = 8
          ta.style.width = '100%'
          out.appendChild(ta)
        }
        if (state) state.textContent = msg('syncDoctorExportFallback', 'Clipboard unavailable — the ledger is shown below; copy it manually.')
      }
    } catch (e) {
      if (state) state.textContent = `${msg('oauthLadderFailLabel', 'The connection check stopped')}: ${String((e && e.message) || e).slice(0, 160)}`
    }
  })
  return true
}

// --- 2. The Chain Data Types panel ---------------------------------------------

const CHAINDATA_KEY = 'ucrypt:chaindata:toggles'

function initChainData() {
  const card = $id('chainDataCard')
  if (!card) return false
  const host = $id('chainDataToggles')
  const state = $id('chainDataState')
  if (!host) return false
  const render = (toggles) => {
    host.textContent = ''
    for (const t of CHAIN_DATA_TYPES) {
      const label = el('label', 'mig-row')
      const cb = document.createElement('input')
      cb.type = 'checkbox'
      cb.checked = !!toggles[t.key]
      cb.dataset.type = t.key
      cb.id = `chaindataType_${t.key}`
      const span = el('span', null, '')
      span.appendChild(el('strong', null, msg(`chaindataType_${t.key}`, t.key)))
      span.appendChild(document.createTextNode(' — '))
      span.appendChild(el('span', 'card-help', msg(`chaindataType_${t.key}Help`, t.defaultOn ? 'On by default.' : 'Off by default (opt-in).')))
      label.appendChild(cb)
      label.appendChild(span)
      host.appendChild(label)
    }
  }
  const load = async () => {
    try {
      const res = await bgSend('CHAINDATA_GET')
      render(normalizeToggles(res && res.toggles))
    } catch {
      render(defaultToggles())
    }
  }
  load()
  const save = $id('chainDataSave')
  if (save) {
    save.addEventListener('click', async () => {
      const inputs = Array.from(host.querySelectorAll('input[type=checkbox]'))
      const toggles = {}
      for (const cb of inputs) toggles[cb.dataset.type] = cb.checked
      const res = await bgSend('CHAINDATA_SET', { toggles })
      if (state) {
        state.textContent = res && res.ok
          ? msg('chainDataSaved', 'Saved — a type toggled off on this device neither sends nor receives on the chain data lane.')
          : `${msg('xbImportFailed', 'The save failed')}: ${String((res && res.error) || 'unknown')}`
      }
    })
  }
  const reset = $id('chainDataReset')
  if (reset) {
    reset.addEventListener('click', async () => {
      await bgSend('CHAINDATA_SET', { toggles: defaultToggles() })
      render(defaultToggles())
      if (state) state.textContent = msg('chainDataResetDone', 'The defaults are back — history and open tabs stay off unless you opt in.')
    })
  }
  return true
}

// --- 3. The Cross-browser Import card (the extended §5 matrix) -------------------

let _importRows = []
let _importBookmarks = null
let _importWipeTargets = []

function initImport() {
  const card = $id('xbImportCard')
  if (!card) return false
  const file = $id('xbImportFile')
  const preview = $id('xbImportPreview')
  const state = $id('xbImportState')
  const confirmBtn = $id('xbImportConfirm')
  const cancelBtn = $id('xbImportCancel')
  if (!file) return false
  const reset = () => {
    secureWipe(_importWipeTargets)
    _importWipeTargets = []
    _importRows = []
    _importBookmarks = null
    if (preview) preview.textContent = ''
    if (confirmBtn) confirmBtn.disabled = true
  }
  file.addEventListener('change', async () => {
    const f = file.files && file.files[0]
    if (!f) return
    if (state) state.textContent = msg('xbImportParsing', 'Parsing locally — nothing leaves this device…')
    const text = await f.text()
    const looksHtml = /<DL|<DT|netscape/i.test(text.slice(0, 4000))
    let summary = ''
    if (looksHtml) {
      const bm = parseBookmarksHtml(text)
      summary = msg('xbImportBookmarks', '$1$ bookmark(s) in $2$ folder(s) parsed from the Netscape file.')
        .replace('$1$', String(bm.counts.bookmarks)).replace('$2$', String(bm.counts.folders))
      _importRows = []
      _importBookmarks = bm.tree
      if (bm.issues.length) summary += ` ${msg('xbImportIssues', 'Parser notes')}: ${bm.issues.slice(0, 3).join(', ')}`
    } else {
      _importBookmarks = null
      const parsed = parsePasswordsCsv(text)
      if (!parsed.rows.length) {
        if (state) state.textContent = `${msg('xbImportUnrecognized', 'The file was not recognized')}: ${(parsed.issues || []).join(', ')}. ${msg('xbImportTryExport', 'Export passwords from your current browser and pick that CSV.')}`
        reset()
        return
      }
      _importRows = parsed.rows
      const dry = dryRunPreview(parsed.rows, { analyzePassword })
      summary = `${msg('xbImportProfileDetected', 'Format detected: $1$').replace('$1$', parsed.profileLabel || parsed.profile || 'CSV')} — ${dry.counts.rows} row(s), ${dry.counts.duplicates} duplicate group(s), ${dry.counts.weak} weak, ${dry.counts.reused} reused.`
      if (Array.isArray(parsed.issues) && parsed.issues.length) {
        summary += ` ${msg('xbImportIssues', 'Parser notes')}: ${parsed.issues.slice(0, 4).join(', ')}${parsed.issues.length > 4 ? '…' : ''}`
      }
      summary += ` ${msg('xbImportDuplicateNote', 'Duplicates are offered as merge or replace, for the same site and username — every overwrite is recorded.')}`
    }
    if (preview) preview.textContent = summary
    if (confirmBtn) confirmBtn.disabled = false
    if (state) state.textContent = msg('xbImportParsed', 'Parsed in memory only — review the preview, then press Import. No network calls were made.')
  })
  if (cancelBtn) cancelBtn.addEventListener('click', () => { reset(); if (state) state.textContent = msg('xbImportCanceled', 'Canceled — the parsed bytes were wiped.') })
  if (confirmBtn) {
    confirmBtn.addEventListener('click', async () => {
      // R175 — THE IMPORT THAT ENDS (R-175.5, the E-33 cure): the journey is
      // BOUNDED — a live progress beat while the run moves, a typed landing
      // (counts or the watchdog row) at the end, and the controls RESTORED
      // on every exit. "Importing…" is a bounded state, never a residence.
      const watchLabel = state
      const startedAt = Date.now()
      if (state) state.textContent = msg('xbImportWorking', 'Importing…')
      if (confirmBtn) confirmBtn.disabled = true
      if (cancelBtn) cancelBtn.disabled = true
      const restore = () => {
        if (confirmBtn) { confirmBtn.disabled = false; confirmBtn.textContent = msg('xbImportConfirm', 'Import into the vault') }
        if (cancelBtn) cancelBtn.disabled = false
      }
      try {
        const res = await boundedImport(() => bgSend('R135_IMPORT_ROWS', { rows: _importRows, bookmarks: _importBookmarks }), {
          onTick: (secs) => {
            try {
              if (watchLabel && !watchLabel.dataset.landed) watchLabel.textContent = `${msg('xbImportWorking', 'Importing…')} ${secs}s`
            } catch { /* the beat never throws into its caller */ }
          },
        })
        if (watchLabel) watchLabel.dataset.landed = '1'
        // R175 — the watchdog row is its OWN landing (never re-thrown — the
        // bound's honest words render verbatim and the controls restore).
        if (res && res.watchdog) {
          if (state) state.textContent = watchdogLandingWords(Number(res.timeoutMs) || undefined)
          return
        }
        if (!res || !res.ok) throw new Error(String((res && res.error) || 'unknown'))
        const report = res.report || buildImportReport({ added: 0, updated: 0, skipped: 0, duplicatesResolved: 0, source: 'local' })
        reset()
        if (state) state.textContent = msg('xbImportDone', 'Import complete: +$1$ added, $2$ updated, $3$ skipped (every overwrite is in the audit log).')
          .replace('$1$', String(report.added)).replace('$2$', String(report.updated)).replace('$3$', String(report.skipped))
      } catch (e) {
        // R175 — the honest landing: a typed failure names its words. The
        // parsed rows stay (the owner may retry without re-picking the file).
        if (state) state.textContent = `${msg('xbImportFailed', 'The import failed')}: ${String(e && e.message || e)}`
      } finally {
        if (watchLabel) delete watchLabel.dataset.landed
        restore()
        void startedAt
      }
    })
  }
  return true
}

// --- Boot -----------------------------------------------------------------------

export function initR135Surfaces() {
  const which = []
  try { if (initSyncDoctor()) which.push('sync-doctor') } catch (e) { console.warn('[UCrypt] r135 sync-doctor:', e) }
  try { if (initChainData()) which.push('chain-data') } catch (e) { console.warn('[UCrypt] r135 chain-data:', e) }
  try { if (initImport()) which.push('import') } catch (e) { console.warn('[UCrypt] r135 import:', e) }
  return which
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { try { initR135Surfaces() } catch (e) { console.warn('[UCrypt] r135 surfaces:', e) } })
  } else {
    try { initR135Surfaces() } catch (e) { console.warn('[UCrypt] r135 surfaces:', e) }
  }
}
