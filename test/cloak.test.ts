import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  protect,
  decodeHomoglyphs,
  decodeWatermarks,
  encodeHomoglyphs,
  stripHomoglyphs,
  stripWatermarks,
  type Guardian,
  type Signal,
} from '../src/index';

const REAL = 'Classic injection allocates memory in a remote process';
const LESSON =
  '<h2>Process Injection</h2>' +
  `<p>${REAL} and then writes the payload into that region, before a thread is started on it. The region is ` +
  'allocated as writable first and is switched to executable only after the copy, because a region that is both at ' +
  'once is an easy thing for a scanner to notice. The same sequence of calls appears in most public loaders.</p>' +
  '<p>The final step creates a <code>thread</code> whose start address points at the payload that was written earlier.</p>' +
  '<pre><code>VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);</code></pre>' +
  '<p>Each of these calls is visible to a userland hook, which is why later modules move to syscalls instead.</p>';

let guardian: Guardian | undefined;
let root: HTMLElement;

beforeEach(() => {
  document.body.innerHTML = `<nav>menu</nav><div id="lesson" class="article">${LESSON}</div>`;
  root = document.getElementById('lesson') as HTMLElement;
});

afterEach(() => {
  guardian?.stop();
  guardian = undefined;
});

const quiet = { cdp: false, headless: false, environment: false } as const;
const bare = { textWatermark: false, honeypots: false, watermark: false } as const;

/** What a reader with pristine accessors gets: the light DOM, child by child. Reads of descendants are not redirected. */
function lightText(): string {
  return Array.from(root.childNodes, (n) => n.textContent ?? '').join(' ');
}

describe('homoglyph watermark', () => {
  const text =
    'A hash table stores each key in a slot chosen by a hash function. Two different keys can land in the same ' +
    'slot, and the table needs a rule for what happens next. The two common rules are separate chaining and open ' +
    'addressing. With separate chaining every slot holds a small list of the colliding keys.';

  it('round-trips a payload and survives zero-width stripping', () => {
    const marked = encodeHomoglyphs(text, 'acct_81f3');
    expect(marked).not.toBe(text);
    expect(marked).toHaveLength(text.length);
    expect(decodeHomoglyphs(stripWatermarks(marked))).toEqual(['acct_81f3']);
    expect(stripHomoglyphs(marked)).toBe(text);
  });

  it('finds nothing in unmarked text and tolerates markup around the letters', () => {
    expect(decodeHomoglyphs(text)).toEqual([]);
    const marked = encodeHomoglyphs(text, 'u1');
    const half = Math.floor(marked.length / 2);
    expect(decodeHomoglyphs(`<p class="a">${marked.slice(0, half)}</p><span>${marked.slice(half)}</span>`)).toContain('u1');
  });
});

describe('cloak', () => {
  it('moves the real content into a closed shadow tree and leaves a marked decoy in the light DOM', () => {
    const listener = root.querySelector('h2')!;
    guardian = protect({ content: root, user: { id: 'acct_81f3' }, detectors: quiet, defenses: { cloak: true } });
    expect(guardian.cloaked).toBe(true);
    expect(root.shadowRoot).toBeNull();
    // The node itself moved, so listeners and state go with it.
    expect(root.contains(listener)).toBe(false);

    const light = lightText();
    expect(stripHomoglyphs(stripWatermarks(light))).not.toContain(REAL);
    expect(light.length).toBeGreaterThan(200);
    expect(decodeWatermarks(light)).toEqual(['acct_81f3']);
    expect(decodeHomoglyphs(stripWatermarks(light))).toContain('acct_81f3');
    expect(light).toContain(guardian.honeypotToken!);
  });

  it('answers the page’s own read of the root with the real content', () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, defenses: { cloak: true }, onSignal: (s) => signals.push(s) });
    expect(stripWatermarks(root.textContent!)).toContain(REAL);
    expect(stripWatermarks(root.innerHTML)).toContain(REAL);
    expect(signals.filter((s) => s.type === 'dom-read')).toHaveLength(0);
  });

  it('gives an untrusted caller the decoy even in observe mode', () => {
    guardian = protect({
      content: root,
      user: { id: 'u' },
      detectors: { ...quiet, domRead: { response: 'observe', untrusted: ['page'] } },
      defenses: { cloak: true },
    });
    for (const read of [root.innerHTML, root.textContent!, document.body.outerHTML]) {
      expect(stripHomoglyphs(stripWatermarks(read))).not.toContain(REAL);
    }
  });

  it('stop() puts the real nodes back', () => {
    const h2 = root.querySelector('h2')!;
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, defenses: { ...bare, cloak: true } });
    guardian.stop();
    guardian = undefined;
    expect(root.innerHTML).toBe(LESSON);
    expect(root.querySelector('h2')).toBe(h2);
    // A host keeps its shadow root for life. protect() must be able to cloak the same element again.
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, defenses: { ...bare, cloak: true } });
    expect(stripHomoglyphs(lightText())).not.toContain(REAL);
    expect(root.textContent).toContain(REAL);
  });

  it('reorder shuffles the real text in the DOM, keeps the watermark, and still serves the page real text', () => {
    guardian = protect({ content: root, user: { id: 'acct_81f3' }, detectors: quiet, defenses: { honeypots: false, watermark: false, cloak: { reorder: true } } });
    // Read as a shadow-piercing reader would: the nodes behind the root's own accessor.
    const pierced = guardian['ctx'].internal(() => guardian!['ctx'].contentRoot(root).textContent!);
    expect(stripWatermarks(pierced)).not.toContain(REAL);
    expect(decodeWatermarks(pierced)).toEqual(['acct_81f3']);
    expect(pierced).toContain('VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);');
    expect(stripWatermarks(root.textContent!)).toContain(REAL);
    guardian.stop();
    guardian = undefined;
    expect(stripWatermarks(root.innerHTML)).toBe(LESSON);
  });

  it('decoy and lockdown act on the real content and restore() brings it back', () => {
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, defenses: { ...bare, cloak: true } });
    guardian.lockdown();
    // What is drawn is the shadow container. The light DOM keeps the decoy throughout.
    const drawn = guardian['ctx'].contentRoot(root);
    expect(drawn.textContent).not.toContain(REAL);
    expect(drawn.textContent).toContain('paused');
    guardian.restore();
    expect(root.textContent).toContain(REAL);
  });
});

describe('foreign frame detector', () => {
  const tick = () => new Promise((r) => setTimeout(r, 20));

  it('reports a blank iframe that page code did not create and that is removed again', async () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    // Stands in for another JavaScript world: the element does not come from the page's createElement.
    const template = document.createElement('template');
    template.innerHTML = '<iframe></iframe>';
    const frame = template.content.firstChild as HTMLIFrameElement;
    document.body.appendChild(frame);
    frame.remove();
    await tick();
    expect(signals.map((s) => s.code)).toContain('dom-read.foreign-frame');
  });

  it('stays quiet for iframes the page creates itself', async () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    const frame = document.createElement('iframe');
    document.body.appendChild(frame);
    frame.remove();
    await tick();
    expect(signals.map((s) => s.code)).not.toContain('dom-read.foreign-frame');
  });
});
