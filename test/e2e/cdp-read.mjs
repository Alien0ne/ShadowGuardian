// End-to-end check against a real Chromium, driven over the raw DevTools Protocol.
//
// It reproduces the extraction this project exists for: attach to a page a person already opened, read the content
// container with Runtime.evaluate, and make no network request. Then it reads the same content without running any
// page JavaScript (DOM.getOuterHTML) to show what is, and is not, detectable.
//
//   npm run build && npm run test:e2e
//
// Needs Node 22+ (global WebSocket) and a Chromium binary. Set CHROME_BIN to override the binary.

import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { decodeWatermarks, stripWatermarks } = await import(join(root, 'dist', 'index.js'));

const REAL = 'With separate chaining every slot holds a small list';
const TYPES = { '.html': 'text/html', '.js': 'text/javascript' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
function check(name, ok, note = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${note ? `  (${note})` : ''}`);
}
function info(name, value) {
  console.log(`INFO  ${name}: ${value}`);
}

const server = createServer((req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname));
  const file = join(root, path);
  if (!file.startsWith(root) || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const pageUrl = `http://127.0.0.1:${server.address().port}/examples/demo/index.html?mode=poison`;

const profile = mkdtempSync(join(tmpdir(), 'sg-e2e-'));
const chrome = spawn(
  process.env.CHROME_BIN ?? 'chromium',
  ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--disable-gpu', pageUrl],
  { stdio: 'ignore' },
);

let ws;
try {
  const portFile = join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
  const port = readFileSync(portFile, 'utf8').split('\n')[0];
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = list.find((t) => t.type === 'page' && t.url.startsWith('http://127.0.0.1'));
    if (!target) await sleep(100);
  }

  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let nextId = 0;
  const pending = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      const id = ++nextId;
      pending.set(id, resolve);
      ws.send(JSON.stringify({ id, method, params }));
    });
  const evaluate = async (expression) => {
    const reply = await send('Runtime.evaluate', { expression, returnByValue: true });
    return reply.result?.result?.value;
  };
  const signals = async () => JSON.parse(await evaluate('JSON.stringify(window.__sg ? window.__sg.signals : null)'));

  for (let i = 0; i < 50 && !(await evaluate('Boolean(window.__sg)')); i++) await sleep(100);
  await sleep(300);

  // 0. Baseline: a page script reads real content, and nothing has fired for it.
  const baseline = await signals();
  const pageRead = await evaluate('window.__pageRead');
  check('page script read real content', typeof pageRead === 'string' && stripWatermarks(pageRead).includes(REAL));
  check('no dom-read signal for the page script', !baseline.some((s) => s.type === 'dom-read'));
  check('no cdp.runtime-enabled before the Runtime domain is enabled', !baseline.some((s) => s.code === 'cdp.runtime-enabled'));

  // 1. The documented attack: one Runtime.evaluate, no domain enabled, no network request.
  const before = (await signals()).length;
  const stolen = await evaluate(`document.querySelector('#lesson').innerHTML`);
  const afterRead = await signals();
  const readSignal = afterRead.find((s) => s.code === 'dom-read.detached');
  check('Runtime.evaluate innerHTML read raises dom-read.detached', Boolean(readSignal), `${afterRead.length - before} new signal(s)`);
  check('the read was answered with decoy content', typeof stolen === 'string' && !stripWatermarks(stolen).includes(REAL));
  check('the decoy still carries the account watermark', decodeWatermarks(stolen ?? '').includes('acct_demo_42'));
  if (readSignal) info('caller frames', JSON.stringify(readSignal.details.frames));

  // 2. Other read paths through Runtime.evaluate.
  for (const expression of [
    `document.documentElement.outerHTML`,
    `document.querySelector('#lesson').innerText`,
    `document.body.textContent`,
    `new XMLSerializer().serializeToString(document)`,
    `Array.from(document.querySelectorAll('#lesson p')).map(p => p.textContent).join('\\n')`,
    `document.querySelector('#lesson').cloneNode(true).innerHTML`,
    `(() => { const f = document.createElement('iframe'); document.body.appendChild(f); const g = Object.getOwnPropertyDescriptor(f.contentWindow.Element.prototype, 'innerHTML').get; return g.call(document.querySelector('#lesson')); })()`,
  ]) {
    const value = await evaluate(expression);
    check(`poisoned: ${expression.slice(0, 70)}`, typeof value === 'string' && value.length > 50 && !stripWatermarks(value).includes(REAL));
  }

  // 3. Code injected by the evaluation is still the evaluation: a script element added from it is not page code.
  const injected = await evaluate(`(() => { const s = document.createElement('script'); s.textContent = 'window.__injectedRead = document.querySelector("#lesson").textContent'; document.head.appendChild(s); return window.__injectedRead; })()`);
  check('poisoned: read from an injected <script> element', typeof injected === 'string' && !stripWatermarks(injected).includes(REAL));

  // 4. A JavaScript-free read. Not detectable from the page. Attribution is what remains.
  const countBefore = (await signals()).length;
  const doc = await send('DOM.getDocument', { depth: 0 });
  const node = await send('DOM.querySelector', { nodeId: doc.result.root.nodeId, selector: '#lesson' });
  const outer = (await send('DOM.getOuterHTML', { nodeId: node.result.nodeId })).result.outerHTML;
  const countAfter = (await signals()).length;
  const token = await evaluate('window.__sg.honeypotToken');
  check('DOM.getOuterHTML returns real content and raises no signal (known limit)', stripWatermarks(outer).includes(REAL) && countAfter === countBefore);
  check('...but the dump contains the honeypot token', outer.includes(token), token);
  check('...and decodes to the account id', decodeWatermarks(outer).includes('acct_demo_42'));
  check('...and names the account in the visible watermark', outer.includes(encodeURIComponent('demo.user@example.com')));

  // 5. Runtime domain side effects. Version-dependent, so reported and not asserted.
  await sleep(3500);
  check('still no cdp.runtime-enabled after a full probe interval', !(await signals()).some((s) => s.code === 'cdp.runtime-enabled'));
  await send('Runtime.enable');
  await sleep(3500);
  const all = await signals();
  info('cdp.runtime-enabled after Runtime.enable', JSON.stringify(all.find((s) => s.code === 'cdp.runtime-enabled')?.details ?? 'not raised on this browser version'));
  info('automation.headless', JSON.stringify(all.find((s) => s.code === 'automation.headless')?.details?.checks?.map((c) => c.name) ?? 'not raised'));
  info('all signal codes', [...new Set(all.map((s) => s.code))].join(', '));
  info('threat score', await evaluate('window.__sg.score'));
  info('browser', (await send('Browser.getVersion')).result.product);
} finally {
  try {
    ws?.close();
  } catch {}
  chrome.kill();
  server.close();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
