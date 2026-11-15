import type { SignalInput, UserIdentity } from '../types';
import { natives } from './native';

/** A detector or defence. Modules are started in order and stopped in reverse. */
export interface GuardModule {
  readonly name: string;
  start(): void;
  stop(): void;
}

export type NodeRelation = 'covers' | 'inside' | null;

/** State shared by every module of one guardian instance. */
export class GuardContext {
  /** Elements ShadowGuardian itself added to the page: honeypots, watermark overlays, notices. */
  readonly ownNodes = new WeakSet<Node>();
  /** True while the response engine has swapped the content out. DOM-watching modules stand down. */
  suspended = false;
  /**
   * Cloaked roots, mapped to the element inside their closed shadow tree that holds the real content.
   * Filled by the cloak defence. Empty when cloaking is off.
   */
  readonly cloaked = new Map<Element, Element>();
  /**
   * Run `fn` while the real content is in its true DOM order. The cloak replaces this when it keeps the real text
   * shuffled (`reorder`), so that a trusted read by the page's own code still returns readable text.
   */
  withRealOrder: <T>(fn: () => T) => T = (fn) => fn();
  private depth = 0;

  constructor(
    readonly roots: Element[],
    readonly user: UserIdentity,
    readonly sessionId: string,
    readonly emit: (signal: SignalInput) => void,
  ) {}

  /** Run ShadowGuardian's own DOM work without tripping its own instrumentation. */
  internal<T>(fn: () => T): T {
    this.depth++;
    try {
      return fn();
    } finally {
      this.depth--;
    }
  }

  isInternal(): boolean {
    return this.depth > 0;
  }

  /** The element that holds the real content of `root`: the root itself, or its shadow container when cloaked. */
  contentRoot(root: Element): Element {
    return this.cloaked.get(root) ?? root;
  }

  /** Where the real content lives, one element per protected root. */
  get contentRoots(): Element[] {
    return this.roots.map((r) => this.contentRoot(r));
  }

  /**
   * Every tree that should carry marks: the real content, and for a cloaked root also the decoy left in the light
   * DOM, because that is the copy a scraper walks away with.
   */
  get surfaces(): Element[] {
    const out: Element[] = [];
    for (const root of this.roots) {
      const real = this.cloaked.get(root);
      if (real) out.push(real);
      out.push(root);
    }
    return out;
  }

  /**
   * How `node` relates to the protected content: `covers` when reading it would return a whole protected element
   * (it is one, or contains one), `inside` when it is part of one.
   */
  relation(node: unknown): NodeRelation {
    if (!node || typeof node !== 'object' || typeof (node as Node).nodeType !== 'number') return null;
    const n = node as Node;
    const contains = natives().contains;
    let inside = false;
    for (const root of this.roots) {
      if (n === root || contains.call(n, root)) return 'covers';
      if (contains.call(root, n)) inside = true;
    }
    for (const real of this.cloaked.values()) {
      if (n === real || contains.call(n, real)) return 'covers';
      if (contains.call(real, n)) inside = true;
    }
    return inside ? 'inside' : null;
  }

  /** Plain text of the protected content, read through native accessors. */
  protectedText(): string {
    const get = natives().textContentGet;
    return this.contentRoots.map((r) => get.call(r) ?? '').join('\n');
  }
}
