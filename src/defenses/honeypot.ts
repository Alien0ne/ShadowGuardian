import type { GuardContext, GuardModule } from '../core/context';
import { fnv1a, randomId } from '../core/util';
import type { HoneypotOptions } from '../types';

/**
 * Honeypot content.
 *
 * Decoy elements placed between the real blocks of the protected content. A person never sees them: they are
 * positioned off-screen, cannot be selected, and are hidden from assistive technology. Anything that serialises the
 * DOM gets them, so scraped output contains sentences that were never on the page, each carrying a token that
 * identifies the account and session.
 *
 * This is the layer that works when detection cannot: a CDP `DOM.getOuterHTML` call or an extension content script
 * raises no signal, and still walks away with marked content.
 *
 * Decoys carry no fixed class name or attribute to filter on, and the hiding technique varies between them.
 */

const DEFAULT_TEMPLATES: Array<(token: string) => string> = [
  (t) => `Reference copy ${t}. This material is licensed to a single account and each copy is individually marked.`,
  (t) => `Edition note ${t}: distribution of this section outside the licensed account is traceable to its source.`,
  (t) => `Document control number ${t}. Retain this identifier with any authorised excerpt.`,
  (t) => `Licence trace ${t}. Unauthorised republication of this content can be attributed using this marker.`,
];

const HIDING = [
  'position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden',
  'position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip-path:inset(50%);white-space:nowrap',
  'position:absolute;left:0;top:0;width:0;height:0;overflow:hidden;opacity:0',
];

export class Honeypots implements GuardModule {
  readonly name = 'honeypots';
  private decoys = new Map<HTMLElement, { root: Element; index: number }>();
  private observers: MutationObserver[] = [];
  private undo: Array<() => void> = [];
  readonly token: string;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: HoneypotOptions = {},
  ) {
    this.token = options.token ?? defaultToken(ctx.user.id, ctx.sessionId);
  }

  start(): void {
    const count = this.options.count ?? 3;
    for (const root of this.ctx.surfaces) {
      this.ctx.internal(() => {
        for (let i = 0; i < count; i++) this.place(root, i, count);
      });
      if (typeof MutationObserver !== 'function') continue;
      const observer = new MutationObserver(() => this.check(root));
      observer.observe(root, { childList: true, subtree: true });
      this.observers.push(observer);
    }
  }

  stop(): void {
    for (const o of this.observers) o.disconnect();
    this.observers = [];
    for (const u of this.undo) u();
    this.undo = [];
    for (const el of this.decoys.keys()) el.remove();
    this.decoys.clear();
  }

  private build(root: Element, index: number): HTMLElement {
    const doc = root.ownerDocument;
    const templates = this.options.templates ?? DEFAULT_TEMPLATES;
    const template = templates[index % templates.length] as (token: string) => string;
    // A block element between blocks, a span elsewhere, so the decoy reads like part of the document structure.
    const blocky = Array.from(root.children).some((c) => /^(P|DIV|SECTION|H[1-6]|UL|OL|PRE|ARTICLE)$/.test(c.tagName));
    const el = doc.createElement(blocky ? 'p' : 'span');
    el.className = `c${randomId(3)}`;
    el.setAttribute('aria-hidden', 'true');
    el.setAttribute(
      'style',
      `${HIDING[index % HIDING.length] as string};user-select:none;-webkit-user-select:none;pointer-events:none`,
    );
    el.textContent = template(this.token);

    if (this.options.canaryUrl) {
      const link = doc.createElement('a');
      const sep = this.options.canaryUrl.includes('?') ? '&' : '?';
      link.href = `${this.options.canaryUrl}${sep}t=${encodeURIComponent(this.token)}`;
      link.tabIndex = -1;
      link.rel = 'nofollow noopener';
      link.textContent = 'Full text';
      const trip = (event: Event) => {
        event.preventDefault();
        this.ctx.emit({
          type: 'honeypot',
          code: 'honeypot.triggered',
          severity: 'high',
          confidence: 0.95,
          message: 'A hidden canary link was activated, which a person cannot do',
          details: { event: event.type, token: this.token },
        });
      };
      link.addEventListener('click', trip);
      link.addEventListener('focus', trip);
      this.undo.push(() => {
        link.removeEventListener('click', trip);
        link.removeEventListener('focus', trip);
      });
      el.appendChild(doc.createTextNode(' '));
      el.appendChild(link);
    }
    this.ctx.ownNodes.add(el);
    return el;
  }

  private place(root: Element, index: number, count: number): void {
    const el = this.build(root, index);
    const children = Array.from(root.children).filter((c) => !this.ctx.ownNodes.has(c));
    // Spread the decoys through the content instead of clustering them at one end.
    const slot = Math.floor(((index + 1) * children.length) / (count + 1));
    const before = children[slot] ?? null;
    root.insertBefore(el, before);
    this.decoys.set(el, { root, index });
  }

  private check(root: Element): void {
    if (this.ctx.suspended) return;
    const missing: Array<{ el: HTMLElement; index: number }> = [];
    for (const [el, info] of this.decoys) {
      if (info.root === root && !root.contains(el)) missing.push({ el, index: info.index });
    }
    if (missing.length === 0) return;
    const count = this.options.count ?? 3;
    this.ctx.internal(() => {
      for (const { el, index } of missing) {
        this.decoys.delete(el);
        this.place(root, index, count);
      }
    });
    this.ctx.emit({
      type: 'tamper',
      code: 'tamper.honeypot',
      // The page's own re-rendering can do this too, so it is not treated as proof on its own.
      severity: 'medium',
      confidence: 0.5,
      message: 'Honeypot elements were removed from the protected content and have been restored',
      details: { removed: missing.length },
    });
  }
}

function defaultToken(userId: string, sessionId: string): string {
  return `${fnv1a(`u:${userId}`)}${fnv1a(`s:${sessionId}`).slice(0, 4)}`.toUpperCase();
}

/**
 * Derive the default honeypot token for a user and session. Run this on the server to search leaked text for a
 * known account's token.
 */
export function honeypotToken(userId: string, sessionId: string): string {
  return defaultToken(userId, sessionId);
}
