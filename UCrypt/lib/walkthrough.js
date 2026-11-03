/**
 * UCrypt — THE ACCEPTANCE WALKTHROUGH ENGINE (R122 — "The Acceptance
 * Walkthrough and the Freeze", order §2).
 *
 * The re-test becomes a product: the owner's fifteen minutes stop chasing
 * documents and ride a guided, resumable, in-product walk. The engine is a
 * DECLARATIVE STEP MACHINE (0.25's focused-layer law): steps are data, the
 * overlay renders one step at a time, the OWNER advances (law 0.8 — nothing
 * auto-dismisses, nothing times out), progress persists in
 * chrome.storage.local and survives closes, updates and restarts.
 *
 * LAWS THIS MODULE OBEYS:
 *  - 0.8  prompt persistence: every step waits for the owner's explicit
 *         Confirm / Back / Close; no timers, no backdrop dismissal.
 *  - 0.13 every step: young-teen reading level, a what-you-should-see line,
 *         and a typed "if it did not happen" fix that names the repair;
 *         no dead ends — a skipped step is recorded honestly, never hidden.
 *  - 0.14 no secret ships or persists in the summary: the input step's
 *         answer is EPHEMERAL (consumed by the surface, never stored in the
 *         progress, never enters the summary — the summary carries the
 *         word "provided" instead); the whole summary text passes the same
 *         no-secrets discipline as the diagnostics export (the planted-
 *         secrets battery machine-checks it).
 *  - 0.25 pages render by state; this walk lives in ONE focused overlay.
 *  - 0.29 the fix button lives on the surface that named the problem:
 *         every step that points at a UCrypt surface carries a deep-link
 *         button that opens it (route), and every external step carries
 *         its link (url).
 *  - 0.34 live-currency: the build-check step reads the CURRENT bytes'
 *         BUILD.json — the walk always names the exact version + payload
 *         digest it is running on.
 *  - 0.35 the candidate-freeze: the acceptance pack's build-check step
 *         says "this exact version on BOTH machines" — the walk IS the
 *         re-test protocol v18.
 *
 * PURE CORE + INJECTED IO: every storage/timing touch goes through `io`
 * (chrome in the product; mocks in the battery). The pack validator, the
 * state machine, the summary builder and the secret scan are pure and
 * unit-tested (the per-file battery regime).
 */

/** The frozen step-type roster. Never grow it silently (the self-check's
 * roster law; every type has a renderer + a battery row). */
export const STEP_TYPES = Object.freeze([
  'build-check', // auto-reads BUILD.json (version + payload sha); instructs checking the other machine
  'link-out',    // an external console link (url) or an internal deep link (route)
  'input',       // an inline field — e.g. paste the pairing code (the answer is EPHEMERAL)
  'observe',     // what-you-should-see + an explicit Confirm button — the owner advances
  'capture',     // a diagnostics/self-check snapshot at this step (typed verdict, capped)
  'summary',     // the collected record — structured, resumable, no-secrets gated
])

/** Storage keys + pack ids (additions-only). */
export const WALK_STORAGE_KEY = 'ucrypt:walk:progress'
export const WELCOME_OFFER_KEY = 'ucrypt:walk:welcomeOffer'
export const PACK_IDS = Object.freeze({ acceptance: 'acceptance', welcome: 'welcome' })

/** The welcome pack's one-time offer lives only while the vault is fresh —
 * a dismissed offer never comes back (dismiss-only-by-action, 0.8). */
export const WELCOME_OFFER_STATES = Object.freeze({ pending: 'pending', accepted: 'accepted', dismissed: 'dismissed' })

/**
 * Validate a pack (PURE). Machine-gated at seal (G32): both packs must
 * validate, ids unique, every step's keys resolvable (the i18n gate checks
 * the catalogs; this checks the SHAPE).
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validatePack(pack) {
  const errors = []
  if (!pack || typeof pack !== 'object') return { ok: false, errors: ['pack is not an object'] }
  if (!Object.values(PACK_IDS).includes(pack.id)) errors.push(`pack.id ${JSON.stringify(pack && pack.id)} is not a known pack id`)
  if (!Array.isArray(pack.steps) || pack.steps.length === 0) errors.push('pack.steps must be a non-empty array')
  else {
    const seen = new Set()
    pack.steps.forEach((s, i) => {
      const at = `steps[${i}]`
      if (!s || typeof s !== 'object') { errors.push(`${at} is not an object`); return }
      if (!s.id || typeof s.id !== 'string') errors.push(`${at}.id missing`)
      else if (seen.has(s.id)) errors.push(`${at}.id ${s.id} is duplicated`)
      else seen.add(s.id)
      if (!STEP_TYPES.includes(s.type)) errors.push(`${at}.type ${JSON.stringify(s.type)} is not a step type`)
      if (typeof s.titleKey !== 'string' || !s.titleKey) errors.push(`${at}.titleKey missing`)
      if (typeof s.bodyKey !== 'string' || !s.bodyKey) errors.push(`${at}.bodyKey missing`)
      if (typeof s.fixKey !== 'string' || !s.fixKey) errors.push(`${at}.fixKey missing (0.13: every step names its repair)`)
      switch (s.type) {
        case 'build-check':
          if (s.route !== undefined && typeof s.route !== 'string') errors.push(`${at}.route must be a string`)
          break
        case 'link-out':
          if (typeof s.url !== 'string' || !/^https:\/\//.test(s.url || '')) {
            if (typeof s.route !== 'string' || !s.route) errors.push(`${at} needs url (https) or route`)
          }
          break
        case 'input':
          if (typeof s.placeholderKey !== 'string' || !s.placeholderKey) errors.push(`${at}.placeholderKey missing`)
          if (s.secret !== true) errors.push(`${at}.secret must be true — input answers are always ephemeral`)
          break
        case 'observe':
          if (typeof s.confirmKey !== 'string' || !s.confirmKey) errors.push(`${at}.confirmKey missing (the owner's Confirm label)`)
          break
        case 'capture':
          if (s.captureKind !== 'self-check' && s.captureKind !== 'diagnostics') errors.push(`${at}.captureKind must be 'self-check' or 'diagnostics'`)
          break
        case 'summary':
          if (i !== pack.steps.length - 1) errors.push(`${at}: the summary step must be the LAST step`)
          if (s.captureKind !== undefined && s.captureKind !== 'self-check' && s.captureKind !== 'diagnostics') errors.push(`${at}.captureKind must be 'self-check' or 'diagnostics'`)
          break
        default:
          errors.push(`${at}: unknown type ${s.type}`)
      }
    })
    if (pack.steps[pack.steps.length - 1] && pack.steps[pack.steps.length - 1].type !== 'summary') {
      errors.push('the last step must be the summary step')
    }
  }
  return { ok: errors.length === 0, errors }
}

/**
 * A fresh progress (PURE). `confirmed` maps stepId → the ISO time the owner
 * confirmed it (the resume unit: confirmed steps stay confirmed).
 */
export function initialProgress(pack, now = Date.now()) {
  return {
    packId: pack.id,
    index: 0,
    confirmed: {},   // stepId → ISO timestamp
    skipped: {},     // stepId → 'skipped' (the honest record)
    captures: {},    // stepId → { kind, at, ok, green, red, info, note } (typed verdict, capped — never a paste)
    answers: {},     // input stepId → true (PRESENCE ONLY — the value is never kept, 0.14)
    startedAt: now,
    updatedAt: now,
    finishedAt: null,
  }
}

/**
 * Resume a saved progress (PURE, total): a corrupt/partial/foreign save
 * repairs to a lawful shape instead of dead-ending (0.13). Index clamps to
 * the pack; unknown step ids drop out; confirmed steps keep their stamps.
 */
export function resumeProgress(pack, saved, now = Date.now()) {
  const fresh = initialProgress(pack, now)
  if (!saved || typeof saved !== 'object' || saved.packId !== pack.id) return fresh
  const ids = new Set(pack.steps.map((s) => s.id))
  const keep = (m) => {
    const out = {}
    for (const [k, v] of Object.entries(m || {})) if (ids.has(k)) out[k] = v
    return out
  }
  let idx = Number.isFinite(Number(saved.index)) ? Math.trunc(Number(saved.index)) : 0
  idx = Math.max(0, Math.min(pack.steps.length - 1, idx))
  return {
    ...fresh,
    index: idx,
    confirmed: keep(saved.confirmed),
    skipped: keep(saved.skipped),
    captures: keep(saved.captures),
    answers: keep(saved.answers),
    startedAt: Number.isFinite(Number(saved.startedAt)) ? Number(saved.startedAt) : fresh.startedAt,
    finishedAt: saved.finishedAt || null,
    updatedAt: now,
  }
}

/** The current step (PURE). */
export function currentStep(pack, progress) {
  const i = Math.max(0, Math.min(pack.steps.length - 1, progress.index || 0))
  return pack.steps[i]
}

/** The input step's typed answer state (PURE): 'filled' | 'empty' | 'skipped'. */
export function inputState(step, progress) {
  if (!step || step.type !== 'input') return 'empty'
  if (progress.skipped && progress.skipped[step.id]) return 'skipped'
  return progress.answers && progress.answers[step.id] ? 'filled' : 'empty'
}

/**
 * Advance (PURE): record the step's outcome and move to the next. For an
 * input step pass { provided: true } (PRESENCE ONLY — the engine never sees
 * the value) or { skipped: true }. For an observe/capture/build-check step
 * pass {} (the Confirm IS the record). Returns the next progress; at the
 * last step sets finishedAt.
 */
export function advance(pack, progress, { provided = false, skipped = false, capture = null } = {}, now = Date.now()) {
  const step = currentStep(pack, progress)
  const next = {
    ...progress,
    confirmed: { ...progress.confirmed },
    skipped: { ...progress.skipped },
    captures: { ...progress.captures },
    answers: { ...progress.answers },
    updatedAt: now,
  }
  if (skipped && step.type === 'input') {
    delete next.answers[step.id]
    next.skipped[step.id] = 'skipped'
    delete next.confirmed[step.id]
  } else {
    delete next.skipped[step.id]
    if (step.type === 'input') next.answers[step.id] = true // presence only (0.14)
    next.confirmed[step.id] = new Date(now).toISOString()
    // The capture rides any step that DECLARES captureKind (the capture
    // steps + the summary's self-check ride-along — protocol step (9)).
    if (capture && typeof step.captureKind === 'string') {
      next.captures[step.id] = {
        kind: String(capture.kind || step.captureKind || '').slice(0, 20),
        at: new Date(now).toISOString(),
        ok: capture.ok === true,
        green: Number(capture.green) || 0,
        red: Number(capture.red) || 0,
        info: Number(capture.info) || 0,
        note: String(capture.note || '').slice(0, 160), // the typed line only — never a paste
      }
    }
  }
  if (next.index >= pack.steps.length - 1) next.finishedAt = now
  else next.index = next.index + 1
  return next
}

/** Back (PURE): one step back, min 0; a re-confirmed step overwrites. */
export function goBack(pack, progress) {
  return { ...progress, index: Math.max(0, (progress.index || 0) - 1), updatedAt: Date.now() }
}

/** Restart (PURE): a brand-new progress for the pack. */
export function restart(pack, now = Date.now()) {
  return initialProgress(pack, now)
}

/** Counted totals (PURE) — the summary + the surface both use them. */
export function walkTotals(pack, progress) {
  const steps = pack.steps
  const confirmed = steps.filter((s) => progress.confirmed && progress.confirmed[s.id]).length
  const skipped = steps.filter((s) => progress.skipped && progress.skipped[s.id]).length
  const remaining = steps.length - confirmed - skipped
  return { total: steps.length, confirmed, skipped, remaining }
}

// ── The no-secrets scan (0.14 — the summary paste joins the no-secrets gate)
// ────────────────────────────────────────────────────────────────────────────
/** The forbidden shapes. The summary is BUILT safe (the engine never sees
 * answers), but the scan stands as the machine gate: any future editor of
 * buildSummary trips the battery. Patterns are shape-level (a 24-word line,
 * a sealed-envelope prefix, credential assignment shapes) — never a real
 * secret's value. */
export const SUMMARY_FORBIDDEN_SHAPES = Object.freeze([
  { name: 'sealed-envelope', re: /ucrypt:cred-env:/ },
  { name: 'long-word-line', re: /(^|\s)[a-z]{3,}(\s+[a-z]{3,}){11,}(\s|$)/i }, // ≥12 whitespace-separated words (the code lines)
  { name: 'client-secret-assign', re: /(clientSecret|client_secret)\s*[:=]\s*\S+/i },
  { name: 'refresh-token-assign', re: /(refreshToken|refresh_token|accessToken|access_token)\s*[:=]\s*\S+/i },
  { name: 'bearer', re: /Bearer\s+\S+/i },
  { name: 'paste-secret-marker', re: /BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/ },
  { name: 'pairing-code-shape', re: /(^|\s)m:(fast|guided|manual):(\S+\s+){7,}\S+/i },
])

/**
 * Scan a summary text (PURE). ok=false names the shape + the 1-based line.
 * The planted-secrets battery plants every shape and demands zero hits.
 */
export function scanSummary(text) {
  const hits = []
  const lines = String(text || '').split('\n')
  lines.forEach((line, i) => {
    for (const { name, re } of SUMMARY_FORBIDDEN_SHAPES) {
      if (re.test(line)) hits.push({ shape: name, line: i + 1 })
    }
  })
  return { ok: hits.length === 0, hits }
}

// ── The summary builder (the owner's ONE paste to the CSA) ─────────────────
/**
 * Build the structured summary text (PURE). Everything rides in as already-
 * safe primitives: the caller resolves the localized titles/labels and hands
 * them over; the engine composes. The resumable state is one line (the walk
 * resumes from its saved step — the paste never carries answers).
 *
 * @param {object} pack           the pack
 * @param {object} progress       the finished (or in-flight) progress
 * @param {object} info
 *   build      { version, payloadSha256 }   (0.34 — the CURRENT bytes)
 *   titles     { [stepId]: resolvedTitle }
 *   labels     { confirmed, skipped, noFindings, findingsHead, expected,
 *                observed, capturePrefix, packLabel, startedLabel, finishedLabel,
 *                resumeNote, noSecretsNote, versionLabel }
 *   findings   [{ stepId, expected, observed, captureNote }] — the failed/
 *              skipped steps in the CEO's template shape
 * @returns {string} the summary text (the caller scans it before showing Copy)
 */
export function buildSummary(pack, progress, info) {
  const { build = {}, titles = {}, labels = {}, findings = [] } = info || {}
  const totals = walkTotals(pack, progress)
  const L = (k, fb) => (labels && labels[k]) || fb
  const pad = (s) => String(s || '').replace(/\r?\n/g, ' ').slice(0, 200)
  const lines = []
  lines.push(`UCrypt ${pack.id === PACK_IDS.welcome ? 'welcome' : 'acceptance'} walkthrough — ${L('versionLabel', 'build')} ${build.version || '?'}`)
  if (build.payloadSha256) lines.push(`payload sha256: ${build.payloadSha256}`)
  lines.push(`${L('packLabel', 'pack')}: ${pack.id} · ${L('startedLabel', 'started')} ${progress.startedAt ? new Date(progress.startedAt).toISOString() : '?'}${progress.finishedAt ? ` · ${L('finishedLabel', 'finished')} ${new Date(progress.finishedAt).toISOString()}` : ''}`)
  lines.push(`steps: ${totals.total} · ${L('confirmed', 'confirmed')} ${totals.confirmed} · ${L('skipped', 'skipped')} ${totals.skipped}`)
  lines.push('')
  for (const s of pack.steps) {
    const title = pad(titles[s.id] || s.id)
    if (progress.confirmed && progress.confirmed[s.id]) {
      const cap = progress.captures && progress.captures[s.id]
      const capBit = cap ? ` — ${cap.kind} ${cap.ok ? 'ok' : 'attention'} (green ${cap.green} / red ${cap.red} / info ${cap.info})` : ''
      lines.push(`[ok]      ${s.id} · ${title}${capBit}`)
    } else if (progress.skipped && progress.skipped[s.id]) {
      lines.push(`[skipped] ${s.id} · ${title}`)
    } else {
      lines.push(`[pending] ${s.id} · ${title}`)
    }
  }
  lines.push('')
  lines.push(`${L('findingsHead', 'findings')} (step · expected · observed · capture):`)
  if (!findings.length) {
    lines.push(L('noFindings', '- none — every confirmed step matched its what-you-should-see'))
  } else {
    for (const f of findings) {
      lines.push(`- ${f.stepId} · ${L('expected', 'expected')}: ${pad(f.expected)} · ${L('observed', 'observed')}: ${pad(f.observed)}${f.captureNote ? ` · ${L('capturePrefix', 'capture')}: ${pad(f.captureNote)}` : ''}`)
    }
  }
  lines.push('')
  lines.push(L('resumeNote', 'This walk resumes from its saved step — reopen the walkthrough any time; confirmed steps stay confirmed.'))
  lines.push(L('noSecretsNote', 'NO SECRETS: this summary carries no codes, no words, no credentials — nothing was collected that could unlock anything.'))
  return lines.join('\n')
}

// ── The content packs (steps are DATA — 0.25; every string is an i18n key,
//    the ×3 resolution rides the locale catalogs + the machine gates) ───────

/** The ACCEPTANCE PACK — protocol v17 as steps (order §2.2). Ten steps
 * (0)–(9) — the EXACT protocol the owner's re-test follows, one step per
 * protocol line; step (9) is the self-check capture + the final summary in
 * one focused view, exactly as the protocol numbers it. On the frozen
 * candidate (0.35) the walk IS the re-test protocol v18. */
export const ACCEPTANCE_PACK = Object.freeze({
  id: PACK_IDS.acceptance,
  steps: Object.freeze([
    {
      id: 'aw0-build', type: 'build-check',
      titleKey: 'aw0Title', bodyKey: 'aw0Body', fixKey: 'aw0Fix',
      detailKey: 'aw0Detail', confirmKey: 'aw0Confirm', route: 'tab-security',
    },
    {
      id: 'aw1-console', type: 'link-out',
      titleKey: 'aw1Title', bodyKey: 'aw1Body', fixKey: 'aw1Fix',
      url: 'https://console.cloud.google.com/apis/credentials', linkLabelKey: 'aw1Link',
      link2: 'https://console.cloud.google.com/apis/credentials/consent', link2LabelKey: 'aw1Link2',
      confirmKey: 'aw1Confirm',
    },
    {
      id: 'aw2-ladder', type: 'observe',
      titleKey: 'aw2Title', bodyKey: 'aw2Body', fixKey: 'aw2Fix', seeKey: 'aw2See',
      confirmKey: 'aw2Confirm', route: 'tab-sync', captureKind: 'self-check',
    },
    {
      id: 'aw3-join', type: 'input',
      titleKey: 'aw3Title', bodyKey: 'aw3Body', fixKey: 'aw3Fix', seeKey: 'aw3See',
      placeholderKey: 'aw3Placeholder', secret: true, route: 'tab-sync',
      inputHelpKey: 'aw3InputHelp', skipKey: 'aw3Skip',
    },
    {
      id: 'aw4-save', type: 'observe',
      titleKey: 'aw4Title', bodyKey: 'aw4Body', fixKey: 'aw4Fix', seeKey: 'aw4See',
      confirmKey: 'aw4Confirm',
    },
    {
      id: 'aw5-config', type: 'observe',
      titleKey: 'aw5Title', bodyKey: 'aw5Body', fixKey: 'aw5Fix', seeKey: 'aw5See',
      confirmKey: 'aw5Confirm', route: 'tab-security',
    },
    {
      id: 'aw6-friend', type: 'observe',
      titleKey: 'aw6Title', bodyKey: 'aw6Body', fixKey: 'aw6Fix', seeKey: 'aw6See',
      confirmKey: 'aw6Confirm', route: 'tab-share',
    },
    {
      id: 'aw7-rename', type: 'observe',
      titleKey: 'aw7Title', bodyKey: 'aw7Body', fixKey: 'aw7Fix', seeKey: 'aw7See',
      confirmKey: 'aw7Confirm', route: 'tab-transfer',
    },
    {
      id: 'aw8-import', type: 'observe',
      titleKey: 'aw8Title', bodyKey: 'aw8Body', fixKey: 'aw8Fix', seeKey: 'aw8See',
      confirmKey: 'aw8Confirm', route: 'tab-data',
    },
    {
      id: 'aw9-final', type: 'summary',
      titleKey: 'aw9Title', bodyKey: 'aw9Body', fixKey: 'aw9Fix', seeKey: 'aw9See',
      captureKey: 'aw9Capture', captureKind: 'self-check',
      copyKey: 'aw9Copy', doneKey: 'aw9Done',
    },
  ]),
})

/** The WELCOME PACK — the store product's first five minutes (order §3).
 * Same engine, new-user content; ships with the activation's public debut. */
export const WELCOME_PACK = Object.freeze({
  id: PACK_IDS.welcome,
  steps: Object.freeze([
    {
      id: 'wl0-vault', type: 'observe',
      titleKey: 'wl0Title', bodyKey: 'wl0Body', fixKey: 'wl0Fix', seeKey: 'wl0See',
      confirmKey: 'wl0Confirm', route: 'tab-vault',
    },
    {
      id: 'wl1-code', type: 'observe',
      titleKey: 'wl1Title', bodyKey: 'wl1Body', fixKey: 'wl1Fix', seeKey: 'wl1See',
      confirmKey: 'wl1Confirm', route: 'tab-sync',
    },
    {
      id: 'wl2-cloud', type: 'link-out',
      titleKey: 'wl2Title', bodyKey: 'wl2Body', fixKey: 'wl2Fix',
      route: 'tab-sync', linkLabelKey: 'wl2Link',
      confirmKey: 'wl2Confirm',
    },
    {
      id: 'wl3-import', type: 'link-out',
      titleKey: 'wl3Title', bodyKey: 'wl3Body', fixKey: 'wl3Fix',
      route: 'tab-data', linkLabelKey: 'wl3Link',
      confirmKey: 'wl3Confirm',
    },
    {
      id: 'wl4-tabs', type: 'observe',
      titleKey: 'wl4Title', bodyKey: 'wl4Body', fixKey: 'wl4Fix', seeKey: 'wl4See',
      confirmKey: 'wl4Confirm', route: 'tab-transfer',
    },
    {
      id: 'wl5-done', type: 'summary',
      titleKey: 'wl5Title', bodyKey: 'wl5Body', fixKey: 'wl5Fix',
      copyKey: 'wl5Copy', doneKey: 'wl5Done',
    },
  ]),
})

/** The pack registry (the surface resolves a pack id → the pack). */
export function getPack(packId) {
  if (packId === PACK_IDS.acceptance) return ACCEPTANCE_PACK
  if (packId === PACK_IDS.welcome) return WELCOME_PACK
  return null
}

// ── Storage io (the product's real chrome wiring; the battery injects) ─────
/** Load the saved progress for a pack (typed degradation — a dead storage
 * reads as "no saved walk", never a throw). */
export async function loadProgress(packId, io) {
  try {
    const raw = await io.storage.get(WALK_STORAGE_KEY)
    const all = raw && typeof raw === 'object' ? raw[WALK_STORAGE_KEY] : null
    if (!all || typeof all !== 'object') return null
    return all[packId] || null
  } catch {
    return null
  }
}

/** Persist the progress (typed degradation — a failed write never breaks the
 * walk; the surface keeps its in-memory copy and the walk still completes). */
export async function saveProgress(progress, io) {
  try {
    const raw = await io.storage.get(WALK_STORAGE_KEY) || {}
    const all = (raw && typeof raw === 'object' && raw[WALK_STORAGE_KEY] && typeof raw[WALK_STORAGE_KEY] === 'object')
      ? raw[WALK_STORAGE_KEY] : {}
    all[progress.packId] = progress
    await io.storage.set({ [WALK_STORAGE_KEY]: all })
    return true
  } catch {
    return false
  }
}

/** The welcome offer's one-time state (0.8: dismiss-only-by-action). */
export async function loadWelcomeOffer(io) {
  try {
    const raw = await io.storage.get(WELCOME_OFFER_KEY)
    const st = raw && raw[WELCOME_OFFER_KEY]
    return st === WELCOME_OFFER_STATES.accepted || st === WELCOME_OFFER_STATES.dismissed ? st : WELCOME_OFFER_STATES.pending
  } catch {
    return WELCOME_OFFER_STATES.pending
  }
}

export async function saveWelcomeOffer(state, io) {
  try {
    await io.storage.set({ [WELCOME_OFFER_KEY]: state })
    return true
  } catch {
    return false
  }
}

/** Test-visible constants (additions-only). */
export const WALKTHROUGH_CONSTANTS = Object.freeze({ STEP_TYPES, WALK_STORAGE_KEY, WELCOME_OFFER_KEY, PACK_IDS, WELCOME_OFFER_STATES, SUMMARY_FORBIDDEN_SHAPES })
