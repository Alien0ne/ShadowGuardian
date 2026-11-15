import type { GuardContext } from '../core/context';
import { natives } from '../core/native';
import { scrambleText } from '../core/util';

export type ShieldLevel = 'none' | 'obfuscate' | 'decoy' | 'lockdown';

const LEVELS: ShieldLevel[] = ['none', 'obfuscate', 'decoy', 'lockdown'];

const DEFAULT_NOTICE =
  'Access to this content has been paused because automated extraction was detected. ' +
  'If you believe this is a mistake, reload the page or contact support.';

interface Stash {
  /** The real child nodes, detached from the document and held only here. */
  real: DocumentFragment;
  style: string | null;
}

/**
 * The content-side defence responses.
 *
 * - `obfuscate` blurs the content and blocks interaction. The real DOM is still there, so this is a deterrent and a
 *   visible warning, not a barrier.
 * - `decoy` moves the real nodes out of the document and leaves a scrambled copy in their place. Anything that reads
 *   the page from now on, by any means including a JavaScript-free CDP DOM dump, gets the decoy.
 * - `lockdown` moves the real nodes out and shows a notice.
 *
 * Real nodes are **moved**, not serialised and re-parsed, so event listeners and framework state survive a
 * `restore()`. Responses only escalate. `restore()` is the one way back down.
 */
export class ContentShield {
  private current: ShieldLevel = 'none';
  private stash = new Map<Element, Stash>();
  private veils = new Map<Element, HTMLElement>();

  constructor(
    private readonly ctx: GuardContext,
    private readonly notice: string = DEFAULT_NOTICE,
  ) {}

  get level(): ShieldLevel {
    return this.current;
  }

  obfuscate(): void {
    if (!this.escalate('obfuscate')) return;
    this.ctx.internal(() => {
      for (const root of this.ctx.roots) {
        const el = root as HTMLElement;
        this.stash.set(root, { real: root.ownerDocument.createDocumentFragment(), style: el.getAttribute('style') });
        el.style.setProperty('filter', 'blur(9px)', 'important');
        el.style.setProperty('user-select', 'none', 'important');
        el.style.setProperty('pointer-events', 'none', 'important');
        this.showVeil(root);
      }
    });
  }

  decoy(): void {
    if (!this.escalate('decoy')) return;
    this.swap((root, real) => {
      const copy = natives().cloneNode.call(real, true) as DocumentFragment;
      const walker = root.ownerDocument.createTreeWalker(copy, 4 /* NodeFilter.SHOW_TEXT */);
      const texts: Node[] = [];
      while (walker.nextNode()) texts.push(walker.currentNode);
      for (const t of texts) {
        const value = t.nodeValue ?? '';
        if (value.trim() !== '') t.nodeValue = scrambleText(value);
      }
      return copy;
    });
  }

  lockdown(): void {
    if (!this.escalate('lockdown')) return;
    this.swap((root) => {
      const fragment = root.ownerDocument.createDocumentFragment();
      const box = root.ownerDocument.createElement('div');
      box.setAttribute('role', 'alert');
      box.setAttribute('style', 'padding:2em;font:16px/1.5 sans-serif;text-align:center');
      box.textContent = this.notice;
      fragment.appendChild(box);
      return fragment;
    });
  }

  restore(): void {
    if (this.current === 'none') return;
    this.ctx.internal(() => {
      for (const [root, stash] of this.stash) {
        const el = root as HTMLElement;
        if (stash.real.childNodes.length > 0) {
          while (root.firstChild) root.removeChild(root.firstChild);
          root.appendChild(stash.real);
        }
        if (stash.style === null) el.removeAttribute('style');
        else el.setAttribute('style', stash.style);
      }
      for (const veil of this.veils.values()) veil.remove();
    });
    this.stash.clear();
    this.veils.clear();
    this.current = 'none';
    this.ctx.suspended = false;
  }

  private escalate(to: ShieldLevel): boolean {
    if (LEVELS.indexOf(to) <= LEVELS.indexOf(this.current)) return false;
    // Start each escalation from the real DOM so that stashes never nest.
    if (this.current !== 'none') this.restore();
    this.current = to;
    return true;
  }

  private swap(build: (root: Element, real: DocumentFragment) => DocumentFragment): void {
    this.ctx.suspended = true;
    this.ctx.internal(() => {
      // Under the cloak the real nodes live in the shadow container, so that is what gets swapped.
      for (const root of this.ctx.contentRoots) {
        const real = root.ownerDocument.createDocumentFragment();
        while (root.firstChild) real.appendChild(root.firstChild);
        this.stash.set(root, { real, style: (root as HTMLElement).getAttribute('style') });
        root.appendChild(build(root, real));
      }
    });
  }

  private showVeil(root: Element): void {
    const parent = root.parentElement;
    if (!parent) return;
    const veil = root.ownerDocument.createElement('div');
    veil.setAttribute('role', 'alert');
    veil.setAttribute(
      'style',
      'margin:1em 0;padding:1em 1.25em;border:1px solid currentColor;border-radius:6px;font:15px/1.5 sans-serif',
    );
    veil.textContent = this.notice;
    this.ctx.ownNodes.add(veil);
    parent.insertBefore(veil, root);
    this.veils.set(root, veil);
  }
}
