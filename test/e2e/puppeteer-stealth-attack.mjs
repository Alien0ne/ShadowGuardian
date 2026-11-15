// puppeteer-extra-plugin-stealth attack test against ShadowGuardian
//
// Puppeteer runs page.evaluate() in the page's main world, so ShadowGuardian's prototype patches should see
// these reads (unlike Patchright, which evaluates in an isolated world). The stealth plugin only hides
// automation fingerprints (navigator.webdriver, chrome.runtime, plugins, WebGL vendor and so on).
//
// Usage: node test/e2e/puppeteer-stealth-attack.mjs
//   SG_CLOAK=off|on|reorder   cloak setting passed to the demo page (default: not set, the demo's default "off")
//   SG_URL=http://host:port   demo server (default http://127.0.0.1:4003)
//   PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome   use an installed browser when Puppeteer's own download is missing

import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { decodeWatermarks, stripWatermarks } = await import(join(root, 'dist', 'index.js'));

const REAL_MARKER = 'With separate chaining every slot holds a small list';
const USER_ID = 'acct_demo_42';
const CLOAK = process.env.SG_CLOAK;
const PAGE_URL = `${process.env.SG_URL ?? 'http://127.0.0.1:4003'}/examples/demo/index.html?mode=poison${CLOAK ? `&cloak=${CLOAK}` : ''}`;

// Wait this long before each attack so a repeat of the same signal code is not hidden by the engine's cooldown.
// SG_GAP=0 shows what a scraper firing reads back to back produces.
const COOLDOWN_MS = Number(process.env.SG_GAP ?? 2300);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The demo markup wraps lines, so compare with whitespace collapsed.
const norm = (s) => stripWatermarks(String(s ?? '')).replace(/\s+/g, ' ');
const hasReal = (s) => norm(s).includes(REAL_MARKER);
const attributedTo = (s) => decodeWatermarks(String(s ?? '')).includes(USER_ID);

console.log('='.repeat(72));
console.log('PUPPETEER-EXTRA-PLUGIN-STEALTH vs SHADOWGUARDIAN');
console.log(`URL: ${PAGE_URL}`);
console.log('='.repeat(72));

puppeteer.use(StealthPlugin());
const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();
console.log(`Browser: ${await browser.version()}`);

await page.goto(PAGE_URL, { waitUntil: 'load' });
try {
  await page.waitForFunction(() => typeof window.__sg !== 'undefined', { timeout: 10000 });
} catch {
  console.log('FATAL: window.__sg never appeared. ShadowGuardian not initialized.');
  console.log(await page.evaluate(() => document.body.innerHTML.slice(0, 300)));
  await browser.close();
  process.exit(1);
}
await sleep(2000); // let the startup detectors finish

const getSignals = async () => JSON.parse(await page.evaluate(() => JSON.stringify(window.__sg.signals)));
const getScore = () => page.evaluate(() => window.__sg.score);

const baseline = await getSignals();
console.log(`\nStealth check: navigator.webdriver = ${await page.evaluate(() => navigator.webdriver)}, UA = ${await page.evaluate(() => navigator.userAgent)}`);
console.log(`Baseline: ${baseline.length} signals, score ${await getScore()}`);
for (const s of baseline) console.log(`  [${s.severity}] ${s.type}/${s.code}: ${s.message}`);

// Control: reading the signal list through page.evaluate must not itself raise signals.
const c1 = (await getSignals()).length;
await sleep(300);
const c2 = (await getSignals()).length;
console.log(`Control (two signal reads, no attack): ${c1} -> ${c2} signals`);

const results = [];
async function attack(label, name, run, { text = true, notes = '' } = {}) {
  console.log('\n' + '-'.repeat(72));
  console.log(`ATTACK ${label}: ${name}`);
  await sleep(COOLDOWN_MS); // the engine suppresses a repeated signal code for cooldownMs (2000 by default)
  const before = (await getSignals()).length;
  let out, error;
  try {
    out = await run();
  } catch (e) {
    error = e.message.split('\n')[0];
  }
  await sleep(400);
  const fresh = (await getSignals()).slice(before);
  const codes = [...new Set(fresh.map((s) => `${s.type}/${s.code}`))];
  const r = {
    label, name,
    detected: fresh.length > 0,
    domRead: fresh.some((s) => s.type === 'dom-read'),
    // null = not applicable (binary output) or the attack threw
    poisoned: error ? null : text ? !hasReal(out) : null,
    attributed: error ? null : text ? attributedTo(out) : null,
    error,
  };
  results.push(r);
  console.log(`  Detected:   ${r.detected ? 'YES' : 'NO'}  (${fresh.length} new signals${codes.length ? ': ' + codes.join(', ') : ''})`);
  if (error) {
    console.log(`  ERROR: ${error}`);
  } else if (text) {
    console.log(`  Poisoned:   ${r.poisoned ? 'YES (marker absent)' : 'NO (REAL CONTENT extracted)'}`);
    console.log(`  Attributed: ${r.attributed ? 'YES' : 'NO'}  watermarks: ${JSON.stringify(decodeWatermarks(String(out)))}`);
    console.log(`  Length: ${String(out).length} chars`);
    console.log(`  Preview: ${JSON.stringify(norm(out).slice(0, 160))}`);
  } else {
    console.log(`  Output: ${out?.length} bytes (binary, text checks not applicable)`);
  }
  if (notes) console.log(`  Notes: ${notes}`);
  return out;
}

await attack('a', 'page.evaluate -> innerHTML', () =>
  page.evaluate(() => document.querySelector('#lesson').innerHTML));

await attack('b', 'page.evaluate -> innerText', () =>
  page.evaluate(() => document.querySelector('#lesson').innerText));

await attack('c', 'page.evaluate -> textContent', () =>
  page.evaluate(() => document.querySelector('#lesson').textContent));

await attack('d', 'page.$eval -> innerHTML', () =>
  page.$eval('#lesson', (el) => el.innerHTML));

await attack('e', 'page.content()', () => page.content(),
  { notes: 'Puppeteer builds this in the page from document.documentElement.outerHTML' });

const shotPath = join(process.env.SG_SHOT_DIR ?? '/tmp', 'sg-puppeteer-stealth.png');
await attack('f', 'page.screenshot()', () => page.screenshot({ fullPage: true, path: shotPath }),
  { text: false, notes: `saved to ${shotPath}; pixels are captured by the browser, not by page JS` });

await attack('g', 'iframe prototype bypass -> innerHTML', () =>
  page.evaluate(() => {
    const f = document.createElement('iframe');
    document.body.appendChild(f);
    const getter = Object.getOwnPropertyDescriptor(f.contentWindow.Element.prototype, 'innerHTML').get;
    const result = getter.call(document.querySelector('#lesson'));
    f.remove();
    return result;
  }), { notes: 'takes an unpatched innerHTML getter from a fresh iframe realm' });

const cdp = await page.createCDPSession();
await attack('h', 'raw CDP -> DOM.getOuterHTML', async () => {
  const doc = await cdp.send('DOM.getDocument', { depth: 0 });
  const node = await cdp.send('DOM.querySelector', { nodeId: doc.root.nodeId, selector: '#lesson' });
  return (await cdp.send('DOM.getOuterHTML', { nodeId: node.nodeId })).outerHTML;
}, { notes: 'no page JavaScript runs on this path' });

await attack('i', "page.$$eval('#lesson p') -> textContent", () =>
  page.$$eval('#lesson p', (els) => els.map((e) => e.textContent).join('\n')));

const pageRead = await page.evaluate(() => window.__pageRead);
console.log(`\nThe page's own script read real content at load: ${hasReal(pageRead)}`);

const all = await getSignals();
const finalScore = await getScore();
await cdp.detach().catch(() => {});
await browser.close();

console.log('\n' + '='.repeat(72));
console.log('SUMMARY: PUPPETEER-EXTRA-PLUGIN-STEALTH vs SHADOWGUARDIAN');
console.log('='.repeat(72));
console.log(`Total signals: ${all.length} (baseline ${baseline.length}), final score: ${finalScore}`);
console.log(`Signal codes: ${[...new Set(all.map((s) => `${s.type}/${s.code}`))].join(', ') || '(none)'}`);

const cell = (v) => (v === null ? 'n/a' : v ? 'YES' : 'NO');
const rows = results.map((r) => [r.label, r.name, cell(r.detected), cell(r.poisoned), cell(r.attributed)]);
const head = ['#', 'Attack', 'Detected', 'Poisoned', 'Attributed'];
const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
const line = (r) => '| ' + r.map((c, i) => c.padEnd(w[i])).join(' | ') + ' |';
const rule = '+-' + w.map((n) => '-'.repeat(n)).join('-+-') + '-+';
console.log('\n' + rule);
console.log(line(head));
console.log(rule);
for (const r of rows) console.log(line(r));
console.log(rule);

const textual = results.filter((r) => r.poisoned !== null);
console.log(`Detected:   ${results.filter((r) => r.detected).length} / ${results.length}`);
console.log(`Poisoned:   ${textual.filter((r) => r.poisoned).length} / ${textual.length} (text attacks)`);
console.log(`Attributed: ${textual.filter((r) => r.attributed).length} / ${textual.length} (text attacks)`);
const errs = results.filter((r) => r.error);
if (errs.length) console.log(`Errors: ${errs.map((r) => `${r.label}: ${r.error}`).join('; ')}`);
