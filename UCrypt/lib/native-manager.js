/**
 * UCrypt — Native password-manager control (v2.36.0, R45-C).
 *
 * HONEST PRODUCT BOUNDARY (the round order's §1 wording, binding):
 *   UCrypt does NOT automatically disable Chromium's native password manager
 *   merely because it is installed. The user must (1) opt into "Save
 *   passwords with UCrypt", (2) grant the OPTIONAL privacy permission, and
 *   (3) the browser must report that UCrypt controls
 *   chrome.privacy.services.passwordSavingEnabled. Only then does UCrypt
 *   turn the browser's save-password prompt off and rely on its own
 *   field-anchored Save/Update prompt.
 *
 *   UCrypt CANNOT read/write/delete the browser's native credential store,
 *   CANNOT guarantee removal of native autofill for credentials the browser
 *   already saved, and CANNOT replace Chromium's built-in autocomplete
 *   widget. The user may still need to disable "Auto sign-in" and delete
 *   browser-stored credentials manually. This is the platform boundary for
 *   EVERY extension password manager — documented, not hidden.
 *
 * Design notes:
 *   - chrome.privacy exists in a context ONLY when the optional "privacy"
 *     permission is granted, so every call is feature-detected first.
 *   - The previous native value is remembered ONCE (at first enable) so a
 *     later disable restores what the browser had before UCrypt touched it.
 *     If the browser hands control away (policy, another extension), the
 *     onChange listener re-evaluates and the UI is told the truth.
 *   - Nothing here is ever set without an explicit user action.
 */

const NM_KEY = 'ucrypt:nativeManager' // { enabled, prevValue, at }

function api() {
  try {
    return chrome.privacy?.services?.passwordSavingEnabled || null
  } catch {
    return null
  }
}

/**
 * Read the setting ONCE and return its flat fields. journey-45 finding:
 * `setting.get({})` resolves to a DETAILS OBJECT `{levelOfControl, value}` —
 * the code that treated it as a flat value shipped dead UI states (caught
 * live in the real-Chromium matrix, M2).
 */
async function readSetting(a) {
  const details = await a.get({})
  return {
    levelOfControl: details?.levelOfControl ?? null, // the browser's literal string
    value: typeof details?.value === 'boolean' ? details.value : null,
  }
}

async function hasPermission() {
  try {
    return await chrome.permissions.contains({ permissions: ['privacy'] })
  } catch {
    return false
  }
}

/**
 * Full status for the popup/options UI. Every field is literal — the UI
 * renders exactly what the browser reports, never an optimistic guess.
 *   supported       — the API exists in this context (permission granted)
 *   levelOfControl  — the browser's own string, verbatim:
 *                     not_controllable | controlled_by_other_extensions |
 *                     controllable_by_this_extension | controlled_by_this_extension
 *   controlling       — supported && levelOfControl === 'controlled_by_this_extension' && value === false
 *                       (UCrypt "on" = the BROWSER's save setting switched OFF; the
 *                       setting literally means "the browser offers to save passwords")
 */
export async function getNativeManagerStatus() {
  const permission = await hasPermission()
  const a = api()
  const supported = !!(permission && a)
  let levelOfControl = null
  let value = null
  if (supported) {
    try {
      const s = await readSetting(a)
      levelOfControl = s.levelOfControl
      value = s.value
    } catch { /* keep nulls — the UI shows the honest unknown */ }
  }
  let pref = { enabled: false, prevValue: null, at: 0 }
  try {
    const { [NM_KEY]: p } = await chrome.storage.local.get(NM_KEY)
    if (p) pref = { enabled: !!p.enabled, prevValue: p.prevValue ?? null, at: p.at || 0 }
  } catch { /* defaults */ }
  return {
    supported,
    permission,
    apiAvailable: !!a, // API object visible even before the permission lands? feature-truth either way
    levelOfControl,
    value: value ?? null,
    enabled: pref.enabled,
    prevValue: pref.prevValue,
    controlling: supported && levelOfControl === 'controlled_by_this_extension' && value === false,
  }
}

/**
 * ENABLE — called ONLY from a user gesture flow that already obtained the
 * optional permission (chrome.permissions.request must run in an extension
 * page with the gesture; the worker cannot request it).
 * SEMANTICS: passwordSavingEnabled TRUE means "the BROWSER offers to save".
 * UCrypt ON therefore SETS IT FALSE (suppress the native bubble), remembering
 * the browser's previous value once so a later disable restores it.
 */
export async function enableNativeManagerControl() {
  const a = api()
  if (!a) return { ok: false, error: 'The privacy API is not available in this browser' }
  if (!(await hasPermission())) return { ok: false, error: 'The optional privacy permission is not granted' }
  let cur
  try {
    cur = await readSetting(a)
  } catch (e) {
    return { ok: false, error: `The browser refused to report the setting (${e?.message || e})` }
  }
  // journey-45 finding (M3): when another extension/policy holds the setting,
  // Chromium's set() is a SILENT NO-OP — it does not throw and does not take
  // effect. The gate refuses BEFORE writing, so the UI never reports a
  // success that did not happen.
  if (cur.levelOfControl !== 'controllable_by_this_extension' && cur.levelOfControl !== 'controlled_by_this_extension') {
    return {
      ok: false,
      lockedBy: cur.levelOfControl,
      error: cur.levelOfControl === 'controlled_by_other_extensions'
        ? 'Another extension controls this browser setting — disable it there first'
        : 'Your organization or browser policy manages this setting — UCrypt cannot change it',
    }
  }
  try {
    await a.set({ value: false }) // browser save prompt OFF — UCrypt's takes over
  } catch (e) {
    return { ok: false, error: `The browser refused the setting (${e?.message || e})` }
  }
  const { [NM_KEY]: old } = await chrome.storage.local.get(NM_KEY)
  await chrome.storage.local.set({
    [NM_KEY]: {
      enabled: true,
      prevValue: old?.prevValue ?? cur.value, // remember the FIRST pre-UCrypt value
      at: Date.now(),
    },
  })
  return { ok: true, status: await getNativeManagerStatus() }
}

/**
 * DISABLE — turn UCrypt's control off and restore the browser's pre-UCrypt
 * value when UCrypt still controls the setting. Never touches anything the
 * browser took back (policy / another extension).
 */
export async function disableNativeManagerControl() {
  const a = api()
  if (!a) return { ok: false, error: 'The privacy API is not available in this browser' }
  const { [NM_KEY]: old } = await chrome.storage.local.get(NM_KEY)
  let restored = null
  try {
    const cur = await readSetting(a)
    if (cur.levelOfControl === 'controlled_by_this_extension') {
      const restoreTo = typeof old?.prevValue === 'boolean' ? old.prevValue : true
      await a.set({ value: restoreTo })
      restored = restoreTo
    }
  } catch (e) {
    return { ok: false, error: `The browser refused the restore (${e?.message || e})` }
  }
  await chrome.storage.local.set({ [NM_KEY]: { enabled: false, prevValue: null, at: Date.now() } })
  return { ok: true, restored, status: await getNativeManagerStatus() }
}

/**
 * CHANGE BROADCAST — wired in the service worker: when the browser itself
 * changes the setting (policy, another extension, the user in settings),
 * every open UCrypt page hears the truth immediately.
 */
export function wireNativeManagerObserver() {
  const a = api()
  if (!a?.onChange?.addListener) return
  try {
    a.onChange.addListener(async () => {
      const status = await getNativeManagerStatus()
      try {
        await chrome.runtime.sendMessage({ type: 'NATIVE_MANAGER_CHANGED', status })
      } catch { /* no page open — nothing to tell */ }
    })
  } catch { /* observer unavailable — status stays poll-based */ }
}
