/**
 * UCrypt — R137 §11 — LADDER HEALTH (the Sign-In Ladder completion).
 * New in v2.94.0 (additions-only on the sealed v2.93.0 base).
 *
 * The CEO's §11 item 5: a Ladder Health card that shows what is enabled,
 * what the browser policy blocks, and the next step for each blocked item,
 * so the ladder state is visible at a glance without hunting menus.
 *
 * The card is PURE: it derives rows from the user's settings + the honest
 * browser capability facts. It NEVER modifies browser settings — the stock
 * autofill entries deep-link to the browser's own controls (one click, where
 * Chromium allows) or render instruction cards for forks (Helium, Brave).
 */

/** The stock-autofill deep links (§11 item 3): one click where Chromium
 * allows; instruction names for forks whose settings pages differ. */
export const STOCK_AUTOFILL_DEEP_LINKS = Object.freeze({
  chrome: { autofill: 'chrome://settings/autofill', passwords: 'chrome://settings/passwords', instruction: false },
  edge: { autofill: 'edge://settings/passwordsAutofill', passwords: 'edge://settings/passwords', instruction: false },
  opera: { autofill: 'opera://settings/autofill', passwords: 'opera://settings/passwords', instruction: false },
  vivaldi: { autofill: 'vivaldi://settings/autofill', passwords: 'vivaldi://settings/passwords', instruction: false },
  brave: { autofill: 'brave://settings/autofill', passwords: 'brave://settings/passwords', instruction: false },
  helium: { autofill: null, passwords: null, instruction: true },
})

/**
 * Build the Ladder Health rows (§11 item 5). Each row: { id, labelKey,
 * state: 'enabled'|'off'|'blocked', why, nextKey, deepLink? } — the label
 * and next ride i18n keys; the states derive ONLY from the inputs.
 *
 * @param {object} settings — the user's ladder settings (autoSignin,
 *   devicePrompt, passkeySuggestions, exceptions)
 * @param {object} env — the honest browser facts { browser, conditionalMediation }
 */
export function buildLadderHealthRows(settings = {}, env = {}) {
  const s = settings && typeof settings === 'object' ? settings : {}
  const browser = String(env.browser || 'chrome')
  const links = STOCK_AUTOFILL_DEEP_LINKS[browser] || STOCK_AUTOFILL_DEEP_LINKS.chrome
  const rows = []
  rows.push({
    id: 'autoSignin',
    labelKey: 'ladderHealthAutoSignin',
    state: s.autoSignin === true ? 'enabled' : 'off',
    why: s.autoSignin === true ? 'ladderHealthAutoSigninEnabled' : 'ladderHealthAutoSigninOff',
    nextKey: s.autoSignin === true ? '' : 'ladderHealthEnableHint',
  })
  rows.push({
    id: 'devicePrompt',
    labelKey: 'ladderHealthDevicePrompt',
    state: s.devicePrompt === true ? 'enabled' : 'off',
    why: s.devicePrompt === true ? 'ladderHealthDevicePromptEnabled' : 'ladderHealthDevicePromptOff',
    nextKey: s.devicePrompt === true ? '' : 'ladderHealthEnableHint',
  })
  rows.push({
    id: 'passkeys',
    labelKey: 'ladderHealthPasskeys',
    state: env.conditionalMediation === true ? 'enabled' : (env.conditionalMediation === false ? 'blocked' : 'off'),
    why: env.conditionalMediation === true ? 'ladderHealthPasskeysEnabled' : (env.conditionalMediation === false ? 'ladderHealthPasskeysBlocked' : 'ladderHealthPasskeysUnknown'),
    nextKey: env.conditionalMediation === true ? '' : 'ladderHealthPasskeysNext',
  })
  rows.push({
    id: 'stockAutofill',
    labelKey: 'ladderHealthStockAutofill',
    state: links.instruction ? 'blocked' : 'enabled',
    why: links.instruction ? 'ladderHealthStockInstruction' : 'ladderHealthStockDeepLink',
    nextKey: 'ladderHealthStockNext',
    deepLink: links.instruction ? null : links.autofill,
    passwordsLink: links.instruction ? null : links.passwords,
  })
  const exceptions = Array.isArray(s.exceptions) ? s.exceptions : []
  rows.push({
    id: 'exceptions',
    labelKey: 'ladderHealthExceptions',
    state: exceptions.length > 0 ? 'enabled' : 'off',
    why: exceptions.length > 0 ? `ladderHealthExceptionsCount` : 'ladderHealthExceptionsEmpty',
    nextKey: '',
    count: exceptions.length,
  })
  return rows
}

/** The never-modify law, stated as data (the card renders it verbatim). */
export const LADDER_HEALTH_NEVER_MODIFIES = 'UCrypt never silently changes browser settings — the stock autofill entries open the browser\u2019s own controls for you.'
