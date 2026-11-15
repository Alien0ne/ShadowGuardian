import type { GuardContext, GuardModule } from '../core/context';
import { randomId } from '../core/util';
import type { InteractionOptions } from '../types';

const DEFAULT_PRINT_NOTICE =
  'Printing or saving this content is not permitted under the Terms of Service. This attempt has been recorded.';

/**
 * Print, save and copy protection.
 *
 * Differences from the usual keyboard-shortcut approach:
 *
 * - Printing is blocked by a print stylesheet instead of wiping and restoring `document.body`. The stylesheet applies
 *   on every print path, including ones that raise no script event in time, and it does not destroy event listeners
 *   or framework state the way an `innerHTML` round-trip does.
 * - Copying is judged at the `copy` event from what is actually selected, so the context menu, the Edit menu and
 *   `document.execCommand('copy')` are covered, not only Ctrl+C.
 * - Copies are tracked cumulatively, which catches someone taking the whole page a section at a time.
 */
export class InteractionGuard implements GuardModule {
  readonly name = 'interaction';
  private undo: Array<() => void> = [];
  private style: HTMLStyleElement | undefined;
  private marker = `sg-${randomId(4)}`;
  private copiedChars = 0;
  private cumulativeReported = false;
  private lastPrint = 0;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: InteractionOptions = {},
  ) {}

  start(): void {
    const o = this.options;
    if (o.blockPrint !== false) this.installPrintStyle();

    this.listen(document, 'keydown', (e) => this.onKeyDown(e as KeyboardEvent), true);
    this.listen(document, 'keyup', (e) => this.onKeyUp(e as KeyboardEvent), true);
    this.listen(window, 'beforeprint', () => this.onPrint('beforeprint'));
    this.listen(document, 'copy', (e) => this.onCopy(e as ClipboardEvent), true);
    this.listen(document, 'cut', (e) => this.onCopy(e as ClipboardEvent), true);

    if (typeof window.matchMedia === 'function') {
      const mq = window.matchMedia('print');
      const handler = (e: MediaQueryListEvent) => {
        if (e.matches) this.onPrint('media-query');
      };
      if (typeof mq.addEventListener === 'function') {
        mq.addEventListener('change', handler);
        this.undo.push(() => mq.removeEventListener('change', handler));
      }
    }

    if (o.blockImageDrag !== false) {
      this.listen(document, 'dragstart', (e) => {
        if (this.ctx.relation(e.target) === 'inside') e.preventDefault();
      }, true);
    }
    if (o.blockContextMenu) {
      this.listen(document, 'contextmenu', (e) => {
        if (this.ctx.relation(e.target)) e.preventDefault();
      }, true);
    }
    this.hookDisplayCapture();
  }

  stop(): void {
    for (const u of this.undo.reverse()) u();
    this.undo = [];
    this.style?.remove();
    this.style = undefined;
    for (const root of this.ctx.roots) root.classList.remove(this.marker);
  }

  private listen(target: EventTarget, type: string, handler: (e: Event) => void, capture = false): void {
    target.addEventListener(type, handler, capture);
    this.undo.push(() => target.removeEventListener(type, handler, capture));
  }

  private installPrintStyle(): void {
    const notice = (this.options.printNotice ?? DEFAULT_PRINT_NOTICE).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    for (const root of this.ctx.roots) root.classList.add(this.marker);
    const style = document.createElement('style');
    style.textContent =
      `@media print {` +
      `.${this.marker} { visibility: hidden !important; font-size: 0 !important; }` +
      `.${this.marker} * { display: none !important; }` +
      `.${this.marker}::before { content: "${notice}"; visibility: visible !important; display: block !important; ` +
      `padding: 2em; font: 16px/1.5 sans-serif !important; color: #000; }` +
      `}`;
    (document.head || document.documentElement).appendChild(style);
    this.ctx.ownNodes.add(style);
    this.style = style;
  }

  private onKeyDown(e: KeyboardEvent): void {
    const mod = e.ctrlKey || e.metaKey;
    const key = (e.key || '').toLowerCase();
    if (mod && key === 'p') {
      this.onPrint('shortcut');
    } else if (mod && key === 's') {
      if (this.options.blockSave !== false) e.preventDefault();
      this.ctx.emit({
        type: 'save',
        code: 'save.shortcut',
        severity: 'medium',
        confidence: 0.9,
        message: 'Save page shortcut was pressed',
        details: { blocked: this.options.blockSave !== false },
      });
    }
  }

  private onKeyUp(e: KeyboardEvent): void {
    // PrintScreen only raises keyup, and only while the browser window has focus.
    if (e.key !== 'PrintScreen') return;
    this.ctx.emit({
      type: 'capture',
      code: 'capture.print-screen',
      severity: 'low',
      confidence: 0.5,
      message: 'The PrintScreen key was pressed',
      details: {},
    });
  }

  private onPrint(path: string): void {
    const now = Date.now();
    // One print action reaches this through several paths. Report it once.
    if (now - this.lastPrint < 1000) return;
    this.lastPrint = now;
    this.ctx.emit({
      type: 'print',
      code: 'print.attempt',
      severity: 'medium',
      confidence: 0.95,
      message: 'The page was sent to print',
      details: { path, blocked: this.options.blockPrint !== false },
    });
  }

  /** Text of the current selection that lies inside protected content. */
  private selectedProtectedText(): string {
    const selection = window.getSelection?.();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return '';
    return this.ctx.internal(() => {
      let text = '';
      for (let i = 0; i < selection.rangeCount; i++) {
        const range = selection.getRangeAt(i);
        for (const root of this.ctx.roots) {
          if (!range.intersectsNode(root)) continue;
          const clipped = range.cloneRange();
          const whole = document.createRange();
          whole.selectNodeContents(root);
          if (clipped.compareBoundaryPoints(Range.START_TO_START, whole) < 0) {
            clipped.setStart(whole.startContainer, whole.startOffset);
          }
          if (clipped.compareBoundaryPoints(Range.END_TO_END, whole) > 0) {
            clipped.setEnd(whole.endContainer, whole.endOffset);
          }
          text += clipped.toString();
        }
      }
      // A selection inside a cloaked root's shadow tree is reported re-scoped to the host, so the ranges above
      // come back empty. The selection's own text is still available.
      if (text === '' && this.ctx.cloaked.size > 0) {
        const node = selection.anchorNode;
        if (node && this.ctx.relation(node)) text = selection.toString();
      }
      return text;
    });
  }

  private onCopy(e: ClipboardEvent): void {
    const selected = this.selectedProtectedText();
    if (selected === '') return;
    const total = this.ctx.protectedText().length || 1;
    const ratio = selected.length / total;
    this.copiedChars += selected.length;
    const cumulative = this.copiedChars / total;
    const o = this.options;

    if (ratio >= (o.bulkCopyRatio ?? 0.6)) {
      const policy = o.onBulkCopy ?? 'annotate';
      this.applyCopyPolicy(e, selected, policy);
      this.ctx.emit({
        type: 'copy',
        code: 'copy.bulk',
        severity: 'medium',
        confidence: 0.9,
        message: 'Most of the protected content was copied in one action',
        details: { ratio: round(ratio), chars: selected.length, policy, event: e.type },
      });
      return;
    }
    if (!this.cumulativeReported && cumulative >= (o.cumulativeCopyRatio ?? 1.5)) {
      this.cumulativeReported = true;
      this.ctx.emit({
        type: 'copy',
        code: 'copy.cumulative',
        severity: 'medium',
        confidence: 0.7,
        message: 'The protected content was copied piece by piece',
        details: { cumulativeRatio: round(cumulative), chars: this.copiedChars },
      });
    }
  }

  private applyCopyPolicy(e: ClipboardEvent, selected: string, policy: InteractionOptions['onBulkCopy']): void {
    if (policy === 'allow') return;
    if (policy === 'block') {
      e.preventDefault();
      return;
    }
    const clipboard = e.clipboardData;
    if (!clipboard) return;
    const attribution =
      this.options.attribution ?? `\n\n[Licensed to ${this.ctx.user.label ?? this.ctx.user.id}. Not for redistribution.]`;
    const body = policy === 'truncate' ? `${selected.slice(0, this.options.truncateTo ?? 500)}…` : selected;
    clipboard.setData('text/plain', body + attribution);
    e.preventDefault();
  }

  /** Screen capture started from the page itself is rare on a content page and worth knowing about. */
  private hookDisplayCapture(): void {
    const media = navigator.mediaDevices as (MediaDevices & { getDisplayMedia?: Function }) | undefined;
    if (!media || typeof media.getDisplayMedia !== 'function') return;
    const proto = Object.getPrototypeOf(media) as object;
    const desc = Object.getOwnPropertyDescriptor(proto, 'getDisplayMedia');
    if (!desc || typeof desc.value !== 'function' || desc.configurable === false) return;
    const original = desc.value as Function;
    const ctx = this.ctx;
    Object.defineProperty(proto, 'getDisplayMedia', {
      ...desc,
      value: function (this: unknown, ...args: unknown[]): unknown {
        ctx.emit({
          type: 'capture',
          code: 'capture.display-media',
          severity: 'medium',
          confidence: 0.8,
          message: 'Screen capture was requested from the page',
          details: {},
        });
        return original.apply(this, args);
      },
    });
    this.undo.push(() => Object.defineProperty(proto, 'getDisplayMedia', desc));
  }
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
