/**
 * UCrypt — R146 §5.3 — THE PAGE ERROR TRAP (standing, every extension page).
 *
 * A dead page NEVER looks like a quiet page. Every page installs this trap
 * at boot; an uncaught error or rejection (i) logs to the doctor's ledger
 * (best-effort, fire-and-forget — the trap never depends on the reporter),
 * (ii) surfaces a typed, plain-words banner: "Something on this page failed
 * to start — Show details / Retry".
 *
 * THE SILENCE LAW (law 12): silence is a battery-red class. A control that
 * does nothing is a failing row BY DEFINITION, whether or not an exception
 * fired — this trap is the error-path half; the living sweep (G96-LIVE) is
 * the dispatch half.
 *
 * Injected doc/win keep the module battery-provable without a browser.
 */

export function formatTrapLine(err) {
  const e = err && typeof err === 'object' ? err : { message: String(err) }
  const msg = String(e.message || e.reason || 'unknown error').slice(0, 200)
  const src = e.filename || (e.error && e.error.filename) || ''
  const line = e.lineno || (e.error && e.error.lineno) || 0
  return src ? `${msg} (${String(src).split('/').pop()}${line ? ':' + line : ''})` : msg
}

const TRAP_BANNER_ID = 'ucryptPageTrap'

export function installPageTrap({ doc = null, win = null, surface = 'page', report = null } = {}) {
  const d = doc || (typeof document !== 'undefined' ? document : null)
  const w = win || (typeof window !== 'undefined' ? window : null)
  if (!d || !w) return { installed: false, errors: [] }

  const errors = []
  let banner = null

  function ensureBanner() {
    if (banner && banner.isConnected) return banner
    banner = d.getElementById(TRAP_BANNER_ID)
    if (banner) return banner
    banner = d.createElement('div')
    banner.id = TRAP_BANNER_ID
    banner.setAttribute('role', 'alert')
    banner.style.cssText = 'position:fixed;inset:auto 12px 12px 12px;z-index:2147483647;display:flex;flex-direction:column;gap:8px;padding:12px 14px;border:1px solid var(--amber, #b8860b);border-radius:12px;background:var(--card, #1d1f24);color:var(--text, #eee);font-size:0.85rem;box-shadow:0 8px 24px rgba(0,0,0,.35)'
    const line = d.createElement('div')
    line.className = 'ucrypt-trap-line'
    line.textContent = 'Something on this page failed to start — Show details for the error, or Retry to reload.'
    const row = d.createElement('div')
    row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap'
    const detailsBtn = d.createElement('button')
    detailsBtn.type = 'button'
    detailsBtn.className = 'btn btn-outline btn-sm ucrypt-trap-details'
    detailsBtn.textContent = 'Show details'
    const retryBtn = d.createElement('button')
    retryBtn.type = 'button'
    retryBtn.className = 'btn btn-primary btn-sm ucrypt-trap-retry'
    retryBtn.textContent = 'Retry'
    const pre = d.createElement('pre')
    pre.className = 'ucrypt-trap-pre'
    pre.style.cssText = 'display:none;max-height:180px;overflow:auto;font-size:0.72rem;white-space:pre-wrap;margin:0;color:var(--muted, #999)'
    detailsBtn.addEventListener('click', () => {
      const open = pre.style.display !== 'none'
      pre.style.display = open ? 'none' : 'block'
      detailsBtn.textContent = open ? 'Show details' : 'Hide details'
    })
    retryBtn.addEventListener('click', () => { try { w.location.reload() } catch { /* best-effort */ } })
    row.append(detailsBtn, retryBtn)
    banner.append(line, row, pre)
    ;(d.body || d.documentElement).appendChild(banner)
    return banner
  }

  function onTrap(errLike) {
    try {
      const err = errLike && errLike.error ? errLike.error : errLike
      const lineText = formatTrapLine(err)
      errors.push({ at: Date.now(), surface, line: lineText })
      if (errors.length > 20) errors.shift()
      const b = ensureBanner()
      const pre = b.querySelector('.ucrypt-trap-pre')
      if (pre) pre.textContent = errors.map((e) => '• ' + e.line).join('\n')
      try { console.error('[UCrypt trap]', surface, lineText) } catch { /* ignore */ }
      if (typeof report === 'function') { try { report({ surface, line: lineText, at: Date.now() }) } catch { /* never */ } }
    } catch { /* the trap itself never throws */ }
  }

  w.addEventListener('error', (ev) => onTrap(ev && ev.error ? ev : { error: ev && ev.message ? { message: ev.message, filename: ev.filename, lineno: ev.lineno } : ev }))
  w.addEventListener('unhandledrejection', (ev) => onTrap(ev && ev.reason ? { error: ev.reason } : ev))

  return { installed: true, surface, errors, bannerId: TRAP_BANNER_ID }
}
