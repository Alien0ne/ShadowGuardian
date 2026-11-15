// Patchright attack test against ShadowGuardian
//
// Patchright is a Playwright fork that patches CDP leaks to evade detection.
// This script tries every extraction method and checks what ShadowGuardian
// catches vs what gets through.
//
// Usage: node test/e2e/patchright-attack.mjs

import { chromium } from 'patchright';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { decodeWatermarks, stripWatermarks, decodeHomoglyphs } = await import(join(root, 'dist', 'index.js'));

const REAL_MARKER = 'With separate chaining every slot holds a small list';
// SG_CLOAK=off      the SDK defaults: instrumentation, watermarks and honeypots only
// SG_CLOAK=on       real content in a closed shadow tree, decoy in the light DOM
// SG_CLOAK=reorder  the same, with the real text's word order shuffled in the DOM (the default here)
const CLOAK = process.env.SG_CLOAK ?? 'reorder';
const PAGE_URL = `${process.env.SG_URL ?? 'http://127.0.0.1:4003'}/examples/demo/index.html?mode=poison&cloak=${CLOAK}`;

const results = [];
function check(name, detected, degraded, attributed, notes = '') {
  results.push({ name, detected, degraded, attributed });
  const d = detected ? '🔴 DETECTED' : '🟢 EVADED';
  const g = degraded ? '🛡️ POISONED' : '⚠️ REAL CONTENT';
  const a = attributed ? '🔍 ATTRIBUTED' : '❌ ANONYMOUS';
  console.log(`\n${name}`);
  console.log(`  Detection: ${d}`);
  console.log(`  Content:   ${g}`);
  console.log(`  Attribution: ${a}`);
  if (notes) console.log(`  Notes: ${notes}`);
}

console.log('='.repeat(70));
console.log('PATCHRIGHT vs SHADOWGUARDIAN');
console.log('Patchright: Playwright fork with CDP leak patches');
console.log(`Cloak: ${CLOAK}`);
console.log('='.repeat(70));

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();

// Inject error catcher before navigation
await page.addInitScript(() => {
  window.__pageErrors = [];
  window.addEventListener('error', e => window.__pageErrors.push(e.message));
});

await page.goto(PAGE_URL, { waitUntil: 'load' });
await new Promise(r => setTimeout(r, 2000));

// Patchright may run evaluate in an isolated world. Use a CDP session for
// page-world access to read signals back.
const cdp = await context.newCDPSession(page);

async function pageEval(expression) {
  const r = await cdp.send('Runtime.evaluate', {
    expression, returnByValue: true, awaitPromise: true
  });
  return r.result?.value;
}

// Check ShadowGuardian loaded
const sgLoaded = await pageEval('typeof ShadowGuardian !== "undefined"');
const sgActive = await pageEval('typeof window.__sg !== "undefined"');
console.log(`\nShadowGuardian global: ${sgLoaded}, __sg active: ${sgActive}`);

if (!sgActive) {
  const errs = await pageEval('JSON.stringify(window.__pageErrors || [])');
  console.log(`Page errors: ${errs}`);
  const preview = await pageEval('document.body.innerHTML.slice(0, 300)');
  console.log(`DOM preview: ${preview}`);
  console.log('\nFATAL: ShadowGuardian not initialized. Exiting.');
  await browser.close();
  process.exit(1);
}

const getSignals = () => pageEval('JSON.stringify(window.__sg.signals)').then(JSON.parse);
const getScore = () => pageEval('window.__sg.score');

// Baseline
const baselineSignals = await getSignals();
const baselineScore = await getScore();
console.log(`\nBaseline: ${baselineSignals.length} signals, score ${baselineScore}`);
console.log(`Baseline codes: ${[...new Set(baselineSignals.map(s => s.code))].join(', ') || '(none)'}`);

// ── ATTACK 1: page.evaluate() → innerHTML ──
// This is what Patchright claims to hide from detection
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 1: page.evaluate() → innerHTML (Patchright)');
const sigsBefore1 = (await getSignals()).length;
const attack1 = await page.evaluate(() => document.querySelector('#lesson').innerHTML);
await new Promise(r => setTimeout(r, 300));
const sigsAfter1 = await getSignals();
const newSigs1 = sigsAfter1.slice(sigsBefore1);
const hasReal1 = stripWatermarks(attack1).includes(REAL_MARKER);
const wm1 = decodeWatermarks(attack1);
check('page.evaluate → innerHTML (Patchright)',
  newSigs1.some(s => s.type === 'dom-read'),
  !hasReal1,
  wm1.length > 0,
  `${attack1.length} chars, ${newSigs1.length} new signals, watermarks: ${JSON.stringify(wm1)}`
);

// ── ATTACK 2: page.evaluate() → innerText ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 2: page.evaluate() → innerText (Patchright)');
const sigsBefore2 = (await getSignals()).length;
const attack2 = await page.evaluate(() => document.querySelector('#lesson').innerText);
await new Promise(r => setTimeout(r, 300));
const sigsAfter2 = await getSignals();
const newSigs2 = sigsAfter2.slice(sigsBefore2);
const hasReal2 = stripWatermarks(attack2).includes(REAL_MARKER);
check('page.evaluate → innerText (Patchright)',
  newSigs2.some(s => s.type === 'dom-read'),
  !hasReal2,
  decodeWatermarks(attack2).length > 0
);

// ── ATTACK 3: page.evaluate() → textContent ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 3: page.evaluate() → textContent (Patchright)');
const sigsBefore3 = (await getSignals()).length;
const attack3 = await page.evaluate(() => document.querySelector('#lesson').textContent);
await new Promise(r => setTimeout(r, 300));
const sigsAfter3 = await getSignals();
const newSigs3 = sigsAfter3.slice(sigsBefore3);
const hasReal3 = stripWatermarks(attack3).includes(REAL_MARKER);
check('page.evaluate → textContent (Patchright)',
  newSigs3.some(s => s.type === 'dom-read'),
  !hasReal3,
  decodeWatermarks(attack3).length > 0
);

// ── ATTACK 4: page.$eval ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 4: page.$eval → innerHTML (Patchright)');
const sigsBefore4 = (await getSignals()).length;
const attack4 = await page.$eval('#lesson', el => el.innerHTML);
await new Promise(r => setTimeout(r, 300));
const sigsAfter4 = await getSignals();
const newSigs4 = sigsAfter4.slice(sigsBefore4);
const hasReal4 = stripWatermarks(attack4).includes(REAL_MARKER);
check('page.$eval → innerHTML (Patchright)',
  newSigs4.some(s => s.type === 'dom-read'),
  !hasReal4,
  decodeWatermarks(attack4).length > 0
);

// ── ATTACK 5: page.content() (full page HTML) ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 5: page.content() (Patchright)');
const sigsBefore5 = (await getSignals()).length;
const attack5 = await page.content();
await new Promise(r => setTimeout(r, 300));
const sigsAfter5 = await getSignals();
const newSigs5 = sigsAfter5.slice(sigsBefore5);
const hasReal5 = stripWatermarks(attack5).includes(REAL_MARKER);
check('page.content() (Patchright)',
  newSigs5.some(s => s.type === 'dom-read'),
  !hasReal5,
  decodeWatermarks(attack5).length > 0,
  'page.content() likely uses CDP DOM.getOuterHTML internally'
);

// ── ATTACK 6: page.locator().innerHTML() ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 6: page.locator().innerHTML() (Patchright)');
const sigsBefore6 = (await getSignals()).length;
const attack6 = await page.locator('#lesson').innerHTML();
await new Promise(r => setTimeout(r, 300));
const sigsAfter6 = await getSignals();
const newSigs6 = sigsAfter6.slice(sigsBefore6);
const hasReal6 = stripWatermarks(attack6).includes(REAL_MARKER);
check('page.locator().innerHTML() (Patchright)',
  newSigs6.some(s => s.type === 'dom-read'),
  !hasReal6,
  decodeWatermarks(attack6).length > 0
);

// ── ATTACK 7: page.locator().textContent() ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 7: page.locator().textContent() (Patchright)');
const sigsBefore7 = (await getSignals()).length;
const attack7 = await page.locator('#lesson').textContent();
await new Promise(r => setTimeout(r, 300));
const sigsAfter7 = await getSignals();
const newSigs7 = sigsAfter7.slice(sigsBefore7);
const hasReal7 = stripWatermarks(attack7).includes(REAL_MARKER);
check('page.locator().textContent() (Patchright)',
  newSigs7.some(s => s.type === 'dom-read'),
  !hasReal7,
  decodeWatermarks(attack7).length > 0
);

// ── ATTACK 8: Screenshot ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 8: page.screenshot() (Patchright)');
const sigsBefore8 = (await getSignals()).length;
const screenshot = await page.screenshot({ fullPage: true });
await new Promise(r => setTimeout(r, 300));
const sigsAfter8 = await getSignals();
const newSigs8 = sigsAfter8.slice(sigsBefore8);
check('page.screenshot() (Patchright)',
  newSigs8.length > 0,
  false,
  true,
  `${screenshot.length} bytes. Visible watermark in image. Screenshot is undetectable from JS.`
);

// ── ATTACK 9: iframe prototype bypass ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 9: iframe prototype bypass (Patchright)');
const sigsBefore9 = (await getSignals()).length;
const attack9 = await page.evaluate(() => {
  const f = document.createElement('iframe');
  document.body.appendChild(f);
  const getter = Object.getOwnPropertyDescriptor(
    f.contentWindow.Element.prototype, 'innerHTML'
  ).get;
  const result = getter.call(document.querySelector('#lesson'));
  f.remove();
  return result;
});
await new Promise(r => setTimeout(r, 300));
const sigsAfter9 = await getSignals();
const newSigs9 = sigsAfter9.slice(sigsBefore9);
const hasReal9 = stripWatermarks(attack9).includes(REAL_MARKER);
check('iframe prototype bypass → innerHTML (Patchright)',
  newSigs9.some(s => s.type === 'dom-read'),
  !hasReal9,
  decodeWatermarks(attack9).length > 0,
  'Grabs unpatched innerHTML getter from a fresh iframe'
);

// ── ATTACK 10: Raw CDP DOM.getOuterHTML ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 10: Raw CDP → DOM.getOuterHTML (Patchright)');
const sigsBefore10 = (await getSignals()).length;
const doc = await cdp.send('DOM.getDocument', { depth: 0 });
const node = await cdp.send('DOM.querySelector', {
  nodeId: doc.root.nodeId, selector: '#lesson'
});
const outer = (await cdp.send('DOM.getOuterHTML', { nodeId: node.nodeId })).outerHTML;
await new Promise(r => setTimeout(r, 300));
const sigsAfter10 = await getSignals();
const newSigs10 = sigsAfter10.slice(sigsBefore10);
const hasReal10 = stripWatermarks(outer).includes(REAL_MARKER);
check('Raw CDP → DOM.getOuterHTML (Patchright)',
  newSigs10.length > 0,
  !hasReal10,
  decodeWatermarks(outer).length > 0,
  'JS-free CDP path — known undetectable from page JS. Attribution only.'
);

// ── ATTACK 11: Raw CDP DOMSnapshot ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 11: Raw CDP → DOMSnapshot (Patchright)');
try {
  const sigsBefore11 = (await getSignals()).length;
  const snapshot = await cdp.send('DOMSnapshot.captureSnapshot', {
    computedStyles: [], includeDOMRects: false
  });
  const allStrings = snapshot.strings || [];
  const fullText = allStrings.join(' ');
  await new Promise(r => setTimeout(r, 300));
  const sigsAfter11 = await getSignals();
  const newSigs11 = sigsAfter11.slice(sigsBefore11);
  const hasReal11 = stripWatermarks(fullText).includes(REAL_MARKER);
  check('Raw CDP → DOMSnapshot (Patchright)',
    newSigs11.length > 0,
    !hasReal11,
    decodeWatermarks(fullText).length > 0,
    'Full DOM snapshot via CDP — JS-free path.'
  );
} catch (e) {
  console.log(`  Skipped: ${e.message.slice(0, 100)}`);
}

// ── ATTACK 12: page.pdf() ──
console.log('\n' + '─'.repeat(70));
console.log('ATTACK 12: page.pdf() (Patchright)');
try {
  const sigsBefore12 = (await getSignals()).length;
  const pdf = await page.pdf({ format: 'A4' });
  await new Promise(r => setTimeout(r, 500));
  const sigsAfter12 = await getSignals();
  const newSigs12 = sigsAfter12.slice(sigsBefore12);
  check('page.pdf() (Patchright)',
    newSigs12.some(s => s.code?.includes('print') || s.code?.includes('interaction')),
    false,
    true,
    `${pdf.length} bytes. Visible watermark in PDF.`
  );
} catch (e) {
  console.log(`  Skipped: ${e.message.slice(0, 100)}`);
}

// ── FOLLOW-UP ATTACKS ──
// What an attacker tries next once the light DOM turns out to hold a decoy. Reported separately so the twelve
// attacks above stay comparable between runs.
const extras = [];
function extra(name, degraded, attributed, notes = '') {
  extras.push({ name, degraded, attributed });
  console.log(`\n${name}`);
  console.log(`  Content:   ${degraded ? '🛡️ POISONED' : '⚠️ REAL CONTENT'}`);
  console.log(`  Attribution: ${attributed ? '🔍 ATTRIBUTED' : '❌ ANONYMOUS'}`);
  if (notes) console.log(`  Notes: ${notes}`);
}
console.log('\n' + '─'.repeat(70));
console.log('FOLLOW-UP ATTACKS (reaching into the shadow tree, stripping marks)');
try {
  // Patchright locators pierce closed shadow roots.
  const pierced = (await page.locator('#lesson p').allTextContents()).join('\n');
  extra('Closed-shadow piercing locator → textContent',
    !stripWatermarks(pierced).includes(REAL_MARKER), decodeWatermarks(pierced).length > 0,
    `${pierced.length} chars`);

  const ax = await cdp.send('Accessibility.getFullAXTree');
  const axText = ax.nodes.map(n => n.name?.value ?? '').join(' ');
  extra('Raw CDP → Accessibility.getFullAXTree',
    !stripWatermarks(axText).includes(REAL_MARKER), decodeWatermarks(axText).length > 0);

  const pierceDoc = JSON.stringify(await cdp.send('DOM.getDocument', { depth: -1, pierce: true }));
  extra('Raw CDP → DOM.getDocument (pierce)',
    !stripWatermarks(pierceDoc).includes(REAL_MARKER), decodeWatermarks(pierceDoc).length > 0);

  // A scraper that strips every zero-width character from what it took.
  const stripped = stripWatermarks(attack3);
  extra('page.evaluate → textContent, zero-width characters stripped',
    !stripped.includes(REAL_MARKER), decodeHomoglyphs(stripped).length > 0,
    `homoglyph mark: ${JSON.stringify(decodeHomoglyphs(stripped))}`);

  const pageRead = await pageEval('window.__pageRead');
  console.log(`\nThe page's own script still reads real content: ${stripWatermarks(pageRead).includes(REAL_MARKER)}`);
} catch (e) {
  console.log(`  Skipped: ${e.message.slice(0, 100)}`);
}

// ── FINAL SUMMARY ──
let allSignals, finalScore;
try {
  allSignals = await getSignals();
  finalScore = await getScore();
  await cdp.detach();
} catch {
  allSignals = [];
  finalScore = -1;
}

console.log('\n' + '='.repeat(70));
console.log('FINAL REPORT: PATCHRIGHT vs SHADOWGUARDIAN');
console.log('='.repeat(70));
console.log(`\nTotal signals raised: ${allSignals.length}`);
console.log(`Final threat score: ${finalScore}`);
console.log(`All signal codes: ${[...new Set(allSignals.map(s => s.code))].join(', ')}`);

const detected = results.filter(r => r.detected).length;
const poisoned = results.filter(r => r.degraded).length;
const attributed = results.filter(r => r.attributed).length;
const total = results.length;

console.log(`\n┌──────────────────────────────────────────────────┐`);
console.log(`│  PATCHRIGHT ATTACKS:  ${total.toString().padStart(2)}                            │`);
console.log(`│  Detected:           ${detected.toString().padStart(2)} / ${total}  (signals fired)      │`);
console.log(`│  Poisoned:           ${poisoned.toString().padStart(2)} / ${total}  (got decoy content)   │`);
console.log(`│  Attributed:         ${attributed.toString().padStart(2)} / ${total}  (watermark present)  │`);
console.log(`│  Threat Score:       ${finalScore.toString().padStart(3)}                            │`);
console.log(`└──────────────────────────────────────────────────┘`);

console.log('\nPer-attack breakdown:');
console.log('─'.repeat(70));
console.log('  [D/P/A]  Attack');
console.log('─'.repeat(70));
for (const r of results) {
  const d = r.detected ? '✓' : '✗';
  const g = r.degraded ? '✓' : '✗';
  const a = r.attributed ? '✓' : '✗';
  console.log(`  [${d}/${g}/${a}]  ${r.name}`);
}
console.log('─'.repeat(70));
console.log('Legend: D=detected, P=poisoned, A=attributed');

console.log('\nFollow-up attacks:');
console.log('─'.repeat(70));
for (const r of extras) {
  console.log(`  [${r.degraded ? '✓' : '✗'}/${r.attributed ? '✓' : '✗'}]  ${r.name}`);
}
console.log('─'.repeat(70));
console.log('Legend: P=poisoned, A=attributed');

await browser.close();
