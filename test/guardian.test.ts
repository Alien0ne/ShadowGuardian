import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { protect, decodeWatermarks, stripWatermarks, type Guardian, type Signal } from '../src/index';

const LESSON =
  '<h2>Process Injection</h2>' +
  '<p>Classic injection allocates memory in a remote process and then writes the payload into that region.</p>' +
  '<p>The final step creates a thread whose start address points at the payload that was written earlier.</p>' +
  '<pre><code>VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);</code></pre>' +
  '<p>Each of these calls is visible to a userland hook, which is why later modules move to syscalls.</p>';

let guardian: Guardian | undefined;
let root: HTMLElement;

beforeEach(() => {
  document.body.innerHTML = `<nav>menu</nav><main id="lesson">${LESSON}</main>`;
  root = document.getElementById('lesson') as HTMLElement;
});

afterEach(() => {
  guardian?.stop();
  guardian = undefined;
});

const quiet = { cdp: false, headless: false, environment: false } as const;

describe('protect()', () => {
  it('validates its input', () => {
    expect(() => protect({ content: '#missing', user: { id: 'u' } })).toThrow(/matched no elements/);
    expect(() => protect({ content: root, user: { id: '' } })).toThrow(/user\.id/);
  });

  it('allows one running instance at a time', () => {
    guardian = protect({ content: root, user: { id: 'u1' }, detectors: quiet });
    expect(() => protect({ content: root, user: { id: 'u2' } })).toThrow(/already running/);
  });

  it('stop() removes everything it added', () => {
    const before = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.get;
    guardian = protect({ content: root, user: { id: 'u1' }, detectors: quiet, defenses: { textWatermark: false } });
    expect(Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.get).not.toBe(before);
    expect(root.querySelector('[aria-hidden="true"]')).not.toBeNull();
    guardian.stop();
    guardian = undefined;
    expect(Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.get).toBe(before);
    expect(root.innerHTML).toBe(LESSON);
  });
});

describe('defences', () => {
  it('weaves an invisible, decodable watermark into prose and leaves code alone', () => {
    guardian = protect({ content: root, user: { id: 'acct_81f3' }, detectors: quiet });
    const html = root.innerHTML;
    expect(decodeWatermarks(html)).toEqual(['acct_81f3']);
    const code = root.querySelector('code')!.textContent!;
    expect(code).toBe(stripWatermarks(code));
    expect(stripWatermarks(root.querySelector('p:not([aria-hidden])')!.textContent!)).toContain('Classic injection allocates');
  });

  it('plants honeypots that appear in a DOM dump and are hidden from assistive technology', () => {
    guardian = protect({ content: root, user: { id: 'acct_81f3' }, detectors: quiet, defenses: { honeypots: { count: 3 } } });
    const token = guardian.honeypotToken!;
    expect(token).toMatch(/^[0-9A-F]{12}$/);
    const dump = root.outerHTML;
    expect(dump.split(token).length - 1).toBe(3);
    const decoys = Array.from(root.querySelectorAll('p[aria-hidden="true"]'));
    expect(decoys).toHaveLength(3);
    // Spread through the content, not clustered together.
    expect(decoys.some((d) => d.previousElementSibling?.getAttribute('aria-hidden') !== 'true')).toBe(true);
  });

  it('restores a removed honeypot and watermark overlay and reports tampering', async () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u', label: 'jane@example.com' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    const overlay = root.lastElementChild as HTMLElement;
    expect(overlay.getAttribute('style')).toContain(encodeURIComponent('jane@example.com'));
    overlay.remove();
    root.querySelector('p[aria-hidden="true"]')!.remove();
    await new Promise((r) => setTimeout(r, 20));
    expect(signals.map((s) => s.code).sort()).toEqual(['tamper.honeypot', 'tamper.watermark']);
    expect(root.querySelectorAll('p[aria-hidden="true"]')).toHaveLength(3);
    expect((root.lastElementChild as HTMLElement).getAttribute('style')).toContain('background-image');
  });
});

describe('DOM read detector', () => {
  it('lets page code read real content without a signal', () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: { ...quiet, domRead: { response: 'poison' } }, onSignal: (s) => signals.push(s) });
    expect(stripWatermarks(root.textContent!)).toContain('Classic injection allocates memory');
    expect(signals.filter((s) => s.type === 'dom-read')).toHaveLength(0);
  });

  // jsdom cannot produce a URL-less entry frame, so the untrusted path is exercised by declaring page code
  // untrusted. test/e2e/cdp-read.mjs covers the real thing against Chromium over CDP.
  it('poisons every read path for an untrusted caller and leaves the DOM intact', () => {
    const signals: Signal[] = [];
    guardian = protect({
      content: root,
      user: { id: 'acct_7' },
      detectors: { ...quiet, domRead: { response: 'poison', untrusted: ['page'] } },
      response: { cooldownMs: 0 },
      onSignal: (s) => signals.push(s),
    });
    const real = 'Classic injection allocates memory in a remote process';
    const reads: Record<string, string> = {
      innerHTML: root.innerHTML,
      outerHTML: root.outerHTML,
      textContent: root.textContent!,
      bodyOuterHTML: document.body.outerHTML,
      cloneNode: (root.cloneNode(true) as HTMLElement).innerHTML,
      serializer: new XMLSerializer().serializeToString(root),
      childText: root.querySelector('p:not([aria-hidden])')!.textContent!,
      textNode: root.querySelector('p:not([aria-hidden])')!.firstChild!.nodeValue!,
    };
    for (const [api, value] of Object.entries(reads)) {
      expect(stripWatermarks(value), api).not.toContain(real);
      expect(value.length, api).toBeGreaterThan(20);
    }
    // Structure and attribution survive in the decoy.
    expect(reads.innerHTML).toContain('<h2>');
    expect(reads.innerHTML).toContain(guardian.honeypotToken!);
    expect(decodeWatermarks(reads.innerHTML as string)).toEqual(['acct_7']);
    // Content outside the protected element is not scrambled.
    expect(reads.bodyOuterHTML).toContain('<nav>menu</nav>');
    expect(signals.every((s) => s.code === 'dom-read.page')).toBe(true);
    expect(signals.length).toBeGreaterThanOrEqual(8);

    guardian.stop();
    guardian = undefined;
    expect(stripWatermarks(root.innerHTML)).toContain(real);
  });

  it('block mode returns nothing', () => {
    guardian = protect({ content: root, user: { id: 'u' }, detectors: { ...quiet, domRead: { response: 'block', untrusted: ['page'] } } });
    expect(root.innerHTML).toBe('');
    expect(root.textContent).toBe('');
    expect((root.cloneNode(true) as HTMLElement).childNodes).toHaveLength(0);
  });

  it('detects and repairs removed hooks', async () => {
    const signals: Signal[] = [];
    const native = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')!;
    guardian = protect({ content: root, user: { id: 'u' }, detectors: { ...quiet, domRead: { integrityIntervalMs: 20 } }, onSignal: (s) => signals.push(s) });
    const hooked = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')!;
    Object.defineProperty(Element.prototype, 'innerHTML', native);
    await new Promise((r) => setTimeout(r, 80));
    expect(signals.some((s) => s.code === 'tamper.dom-read-hooks' && s.severity === 'critical')).toBe(true);
    expect(Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')!.get).toBe(hooked.get);
  });
});

describe('responses', () => {
  it('decoy swaps the real nodes out and restore() brings the same nodes back', () => {
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet });
    const heading = root.querySelector('h2')!;
    const clicked = vi.fn();
    heading.addEventListener('click', clicked);

    guardian.decoy();
    expect(guardian.level).toBe('decoy');
    expect(root.querySelector('h2')).not.toBe(heading);
    expect(stripWatermarks(root.textContent!)).not.toContain('Classic injection allocates memory');

    guardian.restore();
    expect(guardian.level).toBe('none');
    expect(root.querySelector('h2')).toBe(heading);
    heading.click();
    expect(clicked).toHaveBeenCalled();
  });

  it('lockdown shows the notice, and responses only escalate', () => {
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, response: { notice: 'Paused.' } });
    guardian.lockdown();
    expect(root.textContent).toBe('Paused.');
    guardian.obfuscate();
    expect(guardian.level).toBe('lockdown');
  });

  it('reports signals to the backend with identity and score', async () => {
    const transport = vi.fn();
    guardian = protect({
      content: root,
      user: { id: 'acct_1' },
      sessionId: 'sess_1',
      detectors: quiet,
      report: { transport, flushMs: 5 },
    });
    guardian.report({ type: 'print', code: 'print.attempt', severity: 'medium', message: 'x' });
    await new Promise((r) => setTimeout(r, 30));
    expect(transport).toHaveBeenCalledTimes(1);
    const payload = transport.mock.calls[0]![0];
    expect(payload).toMatchObject({ kind: 'signals', userId: 'acct_1', sessionId: 'sess_1', score: 20 });
    expect(payload.signals[0].code).toBe('print.attempt');
  });
});

describe('interaction guard', () => {
  it('reports print and save shortcuts and blocks save', () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    const save = new KeyboardEvent('keydown', { key: 's', ctrlKey: true, cancelable: true, bubbles: true });
    document.dispatchEvent(save);
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'p', metaKey: true, bubbles: true }));
    window.dispatchEvent(new Event('beforeprint'));
    expect(save.defaultPrevented).toBe(true);
    expect(signals.map((s) => s.code)).toEqual(['save.shortcut', 'print.attempt']);
  });

  it('flags a bulk copy from the selection, whatever triggered the copy', () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u', label: 'Jane' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    const selection = window.getSelection()!;
    selection.selectAllChildren(document.body);
    const setData = vi.fn();
    const copy = new Event('copy', { bubbles: true, cancelable: true }) as ClipboardEvent;
    Object.defineProperty(copy, 'clipboardData', { value: { setData } });
    document.dispatchEvent(copy);
    expect(signals.map((s) => s.code)).toEqual(['copy.bulk']);
    expect(setData.mock.calls[0]![1]).toContain('Licensed to Jane');
    expect(copy.defaultPrevented).toBe(true);
  });

  it('ignores a small copy', () => {
    const signals: Signal[] = [];
    guardian = protect({ content: root, user: { id: 'u' }, detectors: quiet, onSignal: (s) => signals.push(s) });
    const range = document.createRange();
    range.selectNodeContents(root.querySelector('h2')!);
    const selection = window.getSelection()!;
    selection.removeAllRanges();
    selection.addRange(range);
    document.dispatchEvent(new Event('copy', { bubbles: true, cancelable: true }));
    expect(signals).toHaveLength(0);
  });
});
