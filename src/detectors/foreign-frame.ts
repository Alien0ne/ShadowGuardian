import type { GuardContext } from '../core/context';
import { trap } from '../core/stack';

/**
 * Foreign frame detector.
 *
 * Code in an isolated world (Playwright and Patchright evaluation, an extension content script) cannot be seen from
 * the page, but the DOM it changes is shared. The standard way to get unpatched DOM accessors is to insert a blank
 * iframe, take the accessors from its window, and remove it again. The page's `MutationObserver` sees that iframe
 * come and go.
 *
 * To tell it from the page's own iframes, `document.createElement` is instrumented in the page's world and every
 * iframe created through it is remembered. A blank iframe that the page never created, and that is gone again
 * within a few seconds, was put there from outside the page's world.
 *
 * An iframe the page creates by parsing markup (`innerHTML`) is not remembered, so the check also requires the
 * frame to be blank and short-lived, which page markup rarely is.
 */

const TRANSIENT_MS = 5000;

type Win = Window & typeof globalThis;

export class ForeignFrameDetector {
  private known = new WeakSet<Node>();
  private seen = new WeakMap<Node, number>();
  private observer: MutationObserver | undefined;
  private undo: Array<() => void> = [];

  constructor(private readonly ctx: GuardContext) {}

  start(w: Win): void {
    if (typeof w.MutationObserver !== 'function') return;
    const proto = w.Document?.prototype;
    for (const prop of ['createElement', 'createElementNS'] as const) {
      const original = proto && Object.getOwnPropertyDescriptor(proto, prop);
      if (!original || original.configurable === false || typeof original.value !== 'function') continue;
      const native = original.value as (this: Document, ...args: unknown[]) => Element;
      const known = this.known;
      const hook = trap(function (this: unknown, ...args: unknown[]): Element {
        const el = native.apply(this as Document, args);
        if (el && el.localName === 'iframe') known.add(el);
        return el;
      });
      Object.defineProperty(proto, prop, { ...original, value: hook });
      this.undo.push(() => {
        if (Object.getOwnPropertyDescriptor(proto, prop)?.value === hook) Object.defineProperty(proto, prop, original);
      });
    }
    this.observer = new w.MutationObserver((records) => this.onMutations(records));
    this.observer.observe(w.document, { childList: true, subtree: true });
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = undefined;
    for (const u of this.undo.reverse()) u();
    this.undo = [];
  }

  private onMutations(records: MutationRecord[]): void {
    const now = Date.now();
    for (const record of records) {
      record.addedNodes.forEach((node) => {
        if (isFrame(node) && !this.known.has(node) && !this.ctx.ownNodes.has(node)) this.seen.set(node, now);
      });
      record.removedNodes.forEach((node) => {
        const added = this.seen.get(node);
        if (added === undefined) return;
        this.seen.delete(node);
        const frame = node as HTMLIFrameElement;
        if (now - added > TRANSIENT_MS || !isBlank(frame)) return;
        this.ctx.emit({
          type: 'dom-read',
          code: 'dom-read.foreign-frame',
          severity: 'high',
          confidence: 0.7,
          message:
            'A blank iframe was inserted and removed by code outside the page (isolated-world automation or an ' +
            'extension content script borrowing unpatched DOM accessors)',
          details: { livedMs: now - added, parent: (record.target as Element).localName ?? null },
        });
      });
    }
  }
}

function isFrame(node: Node): boolean {
  return node.nodeType === 1 && (node as Element).localName === 'iframe';
}

function isBlank(frame: HTMLIFrameElement): boolean {
  const src = frame.getAttribute('src');
  return !frame.hasAttribute('srcdoc') && (src === null || src === '' || src === 'about:blank');
}
