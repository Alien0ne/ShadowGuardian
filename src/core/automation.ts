/** Globals left behind by automation frameworks and their drivers. */
const EXACT = [
  '__playwright__binding__',
  '__pwInitScripts',
  '__playwright_evaluation_script__',
  '__puppeteer_evaluation_script__',
  '__webdriver_evaluate',
  '__selenium_evaluate',
  '__webdriver_script_function',
  '__webdriver_script_func',
  '__webdriver_script_fn',
  '__fxdriver_evaluate',
  '__driver_unwrapped',
  '__webdriver_unwrapped',
  '__driver_evaluate',
  '__selenium_unwrapped',
  '__fxdriver_unwrapped',
  '_Selenium_IDE_Recorder',
  '_selenium',
  'calledSelenium',
  '__nightmare',
  '_phantom',
  'callPhantom',
  'phantom',
  'domAutomation',
  'domAutomationController',
  '__lastWatirAlert',
  '__lastWatirConfirm',
  '__lastWatirPrompt',
];

/** chromedriver injects `cdc_<random>_Array` style properties; Playwright injects `__pw_*` helpers. */
const PREFIXES = [/^cdc_[a-z0-9]+_/i, /^\$cdc_/, /^__pw_/, /^__playwright/, /^puppeteer_/];

/** Names of automation globals currently present on `window` or `document`. */
export function findAutomationGlobals(w: Window = window): string[] {
  const found = new Set<string>();
  const hosts: object[] = [w, w.document];
  for (const host of hosts) {
    for (const name of EXACT) {
      try {
        if (name in host) found.add(name);
      } catch {
        /* exotic host object */
      }
    }
    let keys: string[] = [];
    try {
      keys = Object.getOwnPropertyNames(host);
    } catch {
      keys = [];
    }
    for (const key of keys) {
      if (PREFIXES.some((re) => re.test(key))) found.add(key);
    }
  }
  try {
    const attrs = w.document.documentElement.getAttributeNames();
    for (const a of attrs) if (/^(selenium|webdriver|driver)$/i.test(a)) found.add(`html[${a}]`);
  } catch {
    /* no document element */
  }
  return Array.from(found);
}
