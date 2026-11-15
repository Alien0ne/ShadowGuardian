import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import { fnv1a, scrambleText, seededRandom } from '../core/util';
import type { CloakOptions } from '../types';
import { homoglyphCapacity, homoglyphCarriers, homoglyphEncoder } from './homoglyph';

/**
 * Content cloak.
 *
 * The DOM read detector works by instrumenting accessors in the page's JavaScript world. An isolated world
 * (Playwright and Patchright evaluation, an extension content script) has its own pristine accessors, and the CDP
 * `DOM` domain runs no JavaScript at all, so both read the light DOM without anything on the page noticing. No
 * amount of instrumentation fixes that. What can be changed is what the light DOM holds.
 *
 * The cloak moves the real nodes into a **closed shadow tree** on the protected element and leaves a scrambled,
 * watermarked copy in their place. The browser draws the shadow tree, so a person sees the real content. Everything
 * that serialises the light DOM (`innerHTML`, `textContent`, `outerHTML` of an ancestor, `page.content()`,
 * `DOM.getOuterHTML`) gets the decoy, in every JavaScript world, with no detection needed. `element.shadowRoot` is
 * `null` for a closed tree in every world too.
 *
 * The real nodes are moved, not copied, so their event listeners and state survive, and `stop()` moves them back.
 *
 * What still reaches the real text: a reader that walks into shadow trees through the browser itself, namely CDP
 * `DOMSnapshot.captureSnapshot`, `DOM.getDocument` with `pierce`, the accessibility tree, and Patchright's
 * closed-shadow locators. The opt-in `reorder` mode shuffles the real text's word order in the DOM and restores it
 * with CSS, which takes those away at a cost to accessibility. Pixels (screenshots, PDF) are always the real page.
 *
 * Costs to know about before turning it on:
 * - The page's own `querySelector('#content p')` finds decoy nodes. A trusted read of the root element itself
 *   (`root.innerHTML`, `root.textContent`) is answered with the real content by the DOM read detector.
 * - Stylesheets are copied into the shadow tree and matched against a copy of the ancestor chain. Selectors that
 *   depend on sibling position or on attributes of ancestors do not match.
 * - Content added to the root later lands in the light DOM, where it is not drawn. Cloak content that is complete.
 * - Events from the content are retargeted to the root when they leave the shadow tree.
 */

/** A closed shadow root cannot be recovered from its host, and a host can only have one. Kept for `protect()` after `stop()`. */
const shadows = new WeakMap<Element, ShadowRoot>();

const HIDDEN_SLOT_STYLE =
  'position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip-path:inset(50%);opacity:0;' +
  'pointer-events:none;user-select:none;-webkit-user-select:none';
const MEDIA_ATTRS = ['src', 'srcset', 'poster', 'data'];
const INLINE = new Set(
  'a abbr b bdi cite code del dfn em i ins kbd mark q s samp small span strong sub sup time u var'.split(' '),
);
const OPAQUE = new Set('pre script style textarea svg math select button template'.split(' '));
const GAP = '0.29em';

interface Entry {
  root: Element;
  shadow: ShadowRoot;
  real: HTMLElement;
}

interface Reordered {
  parent: Node;
  wrapper: HTMLElement;
  nodes: Node[];
  styles: Map<Element, string | null>;
}

export class Cloak implements GuardModule {
  readonly name = 'cloak';
  private entries: Entry[] = [];
  private reordered: Reordered[] = [];

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: CloakOptions = {},
  ) {}

  start(): void {
    for (const root of this.ctx.roots) {
      try {
        this.ctx.internal(() => this.cloak(root));
      } catch (error) {
        // Only some elements can host a shadow tree, and an element that already has one cannot take another.
        console.warn('[ShadowGuardian] cloak: this element cannot be cloaked and stays in the light DOM', root, error);
      }
    }
  }

  stop(): void {
    this.ctx.internal(() => {
      for (const { root, shadow, real } of this.entries) {
        while (root.firstChild) root.removeChild(root.firstChild);
        while (real.firstChild) root.appendChild(real.firstChild);
        // The shadow tree cannot be detached. A bare slot makes it draw the light DOM again.
        while (shadow.firstChild) shadow.removeChild(shadow.firstChild);
        shadow.appendChild(root.ownerDocument.createElement('slot'));
        this.ctx.cloaked.delete(root);
      }
    });
    this.entries = [];
  }

  /**
   * The second phase, run after the watermark and honeypot modules so that the marks they add to the real text end
   * up inside the shuffled words.
   */
  readonly reorderPhase: GuardModule = {
    name: 'cloakReorder',
    start: () => {
      if (!this.options.reorder) return;
      this.shuffle();
      // The shuffle is seeded, so undoing it for a trusted read and applying it again gives the same DOM.
      this.ctx.withRealOrder = (fn) => {
        if (this.ctx.suspended || this.reordered.length === 0) return fn();
        this.unshuffle();
        try {
          return fn();
        } finally {
          this.shuffle();
        }
      };
    },
    stop: () => {
      this.ctx.withRealOrder = (fn) => fn();
      this.unshuffle();
    },
  };

  private shuffle(): void {
    this.ctx.internal(() => {
      for (const { real } of this.entries) this.reorder(real);
    });
  }

  private unshuffle(): void {
    this.ctx.internal(() => {
      for (const r of this.reordered.reverse()) {
        for (const node of r.nodes) r.parent.insertBefore(node, r.wrapper);
        for (const [el, style] of r.styles) {
          if (style === null) el.removeAttribute('style');
          else el.setAttribute('style', style);
        }
        r.wrapper.remove();
      }
    });
    this.reordered = [];
  }

  private cloak(root: Element): void {
    const doc = root.ownerDocument;
    const shadow = shadows.get(root) ?? root.attachShadow({ mode: 'closed' });
    shadows.set(root, shadow);
    while (shadow.firstChild) shadow.removeChild(shadow.firstChild);

    if (this.options.copyStyles !== false) this.copyStyles(root, shadow);
    if (this.options.css) {
      const style = doc.createElement('style');
      style.textContent = this.options.css;
      shadow.appendChild(style);
    }

    // A copy of the ancestor chain, so that selectors such as `.article main p` still match. Every level is
    // `display: contents`: it takes part in selector matching and inheritance and draws no box of its own.
    const chain: Element[] = [];
    for (let cur: Element | null = root; cur; cur = cur.parentElement) chain.unshift(cur);
    let parent: Node = shadow;
    let real: HTMLElement | undefined;
    for (const original of chain) {
      const twin = doc.createElement(original.localName);
      if (original.id) twin.id = original.id;
      const cls = original.getAttribute('class');
      if (cls) twin.setAttribute('class', cls);
      twin.setAttribute('style', 'display:contents !important');
      parent.appendChild(twin);
      parent = twin;
      real = twin;
    }
    if (!real) return;

    while (root.firstChild) real.appendChild(root.firstChild);
    const decoy = natives().cloneNode.call(real, true) as Element;
    this.makeDecoy(decoy);
    while (decoy.firstChild) root.appendChild(decoy.firstChild);

    // The decoy is drawn into a clipped, inert 1px box. Drawn, so that `innerText` returns the decoy and not an
    // empty string. Inert, so that find-in-page, selection and assistive technology never reach it.
    const box = doc.createElement('div');
    box.setAttribute('aria-hidden', 'true');
    box.setAttribute('inert', '');
    box.setAttribute('style', HIDDEN_SLOT_STYLE);
    box.appendChild(doc.createElement('slot'));
    shadow.appendChild(box);

    this.ctx.cloaked.set(root, real);
    this.entries.push({ root, shadow, real });
  }

  private copyStyles(root: Element, shadow: ShadowRoot): void {
    const doc = root.ownerDocument;
    const N = natives();
    doc.querySelectorAll('style, link[rel~="stylesheet"]').forEach((sheet) => {
      if (N.contains.call(root, sheet)) return;
      shadow.appendChild(N.cloneNode.call(sheet, true));
    });
    try {
      const adopted = (doc as Document & { adoptedStyleSheets?: CSSStyleSheet[] }).adoptedStyleSheets;
      if (adopted && adopted.length > 0) {
        (shadow as ShadowRoot & { adoptedStyleSheets: CSSStyleSheet[] }).adoptedStyleSheets = Array.from(adopted);
      }
    } catch {
      /* constructable stylesheets are not available everywhere */
    }
  }

  /** Turn a clone of the real content into the copy a scraper is meant to take. */
  private makeDecoy(copy: Element): void {
    const scramble = this.options.decoy ?? ((text: string) => scrambleText(text));
    const payload = this.ctx.user.id;
    let mark = this.options.homoglyphs === false ? null : homoglyphEncoder(payload);
    const capacity = homoglyphCapacity(payload);
    let block: Node | null = null;
    // Real media URLs must not sit in the light DOM, and the media must not load twice.
    copy.querySelectorAll('img, video, audio, source, track, embed, object, iframe').forEach((el) => {
      for (const attr of MEDIA_ATTRS) el.removeAttribute(attr);
    });
    copy.querySelectorAll('script').forEach((el) => el.remove());
    const walker = copy.ownerDocument.createTreeWalker(copy, 4 /* NodeFilter.SHOW_TEXT */);
    const texts: Node[] = [];
    while (walker.nextNode()) texts.push(walker.currentNode);
    for (const node of texts) {
      const value = node.nodeValue ?? '';
      if (value.trim() === '' || node.parentElement?.localName === 'style') continue;
      const decoyText = scramble(value);
      if (mark) {
        // Honeypots are inserted between the top-level blocks later and would cut a frame that spans two of them.
        // A block with room for a whole frame starts a new one, so that it decodes on its own.
        let top: Node = node;
        while (top.parentNode && top.parentNode !== copy) top = top.parentNode;
        if (top !== block) {
          block = top;
          if (homoglyphCarriers(top.textContent ?? '') >= capacity) mark = homoglyphEncoder(payload);
        }
      }
      node.nodeValue = mark ? mark(decoyText) : decoyText;
    }
  }

  private reorder(el: Element): void {
    if (OPAQUE.has(el.localName) || this.ctx.ownNodes.has(el) || el.hasAttribute('contenteditable')) return;
    let run: Node[] = [];
    const flush = () => {
      if (run.length > 0) this.reorderRun(el, run);
      run = [];
    };
    for (const child of Array.from(el.childNodes)) {
      if (child.nodeType === 3) {
        run.push(child);
      } else if (child.nodeType === 1 && INLINE.has((child as Element).localName) && !this.ctx.ownNodes.has(child)) {
        run.push(child);
      } else {
        flush();
        if (child.nodeType === 1) this.reorder(child as Element);
      }
    }
    flush();
  }

  /** Replace one run of inline content with a flex line whose items are in shuffled DOM order. */
  private reorderRun(parent: Element, run: Node[]): void {
    const doc = parent.ownerDocument;
    const items: HTMLElement[] = [];
    const styles = new Map<Element, string | null>();
    let seedText = '';
    // Whether the previous item is followed by whitespace. An item that is not gets no gap before the next one.
    let spaced = true;
    const add = (item: HTMLElement, glued: boolean) => {
      item.style.setProperty('order', String(items.length));
      if (glued && items.length > 0) item.style.setProperty('margin-left', `-${GAP}`);
      items.push(item);
    };
    for (const node of run) {
      if (node.nodeType === 1) {
        const el = node as HTMLElement;
        styles.set(el, el.getAttribute('style'));
        add(el, !spaced);
        spaced = false;
        continue;
      }
      const text = node.nodeValue ?? '';
      seedText += text;
      const words = text.split(/\s+/);
      words.forEach((word, i) => {
        if (word === '') return;
        const span = doc.createElement('span');
        span.textContent = word;
        // The first word continues the previous item when no whitespace separates them.
        add(span, i === 0 && !spaced);
      });
      if (text !== '') spaced = /\s$/.test(text);
    }
    if (items.length < 3) {
      for (const [el, style] of styles) {
        if (style === null) el.removeAttribute('style');
        else el.setAttribute('style', style);
      }
      return;
    }

    const wrapper = doc.createElement('span');
    wrapper.setAttribute('style', `display:flex;flex-wrap:wrap;align-items:baseline;column-gap:${GAP}`);
    parent.insertBefore(wrapper, run[0] as Node);
    for (const node of run) if (node.nodeType === 3) parent.removeChild(node);
    const rand = seededRandom(parseInt(fnv1a(this.ctx.sessionId + seedText), 16));
    const order = items.slice();
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      const tmp = order[i] as HTMLElement;
      order[i] = order[j] as HTMLElement;
      order[j] = tmp;
    }
    for (const item of order) wrapper.appendChild(item);
    this.reordered.push({ parent, wrapper, nodes: run, styles });
  }
}
