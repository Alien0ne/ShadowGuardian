import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import { captureCaller, trap } from '../core/stack';
import { scrambleText } from '../core/util';
import type { CallerKind, CallerOrigin, DomReadOptions, Severity } from '../types';
import { ForeignFrameDetector } from './foreign-frame';

/**
 * DOM read detector.
 *
 * Reading `innerHTML` raises no event, so there is nothing to listen for. Instead the read paths themselves are
 * instrumented: each accessor and method that can serialise protected content is wrapped, and when it is used on
 * protected content the caller is classified from its call stack.
 *
 * Page scripts have a URL in their entry frame. A DevTools console, a CDP `Runtime.evaluate` call and a bookmarklet
 * do not, and automation frameworks leave their own markers. Because the wrapper runs synchronously inside the read,
 * it can hand an untrusted caller decoy content while the real DOM stays intact for the person reading the page.
 *
 * Out of reach (see docs/research/attack-vectors.md): reads that never execute page-world JavaScript, namely the CDP
 * `DOM` and `DOMSnapshot` domains and code in an isolated world (Playwright and Patchright evaluation, extension
 * content scripts). Those are answered by the cloak defence, which changes what the light DOM holds, and by
 * honeypots and text watermarks. The one isolated-world technique that does leave a trace, a borrowed iframe, is
 * reported by the foreign frame detector started from here.
 */

type Win = Window & typeof globalThis;

interface ReadSpec {
  api: string;
  kind: 'getter' | 'method';
  proto: (w: Win) => object | undefined;
  prop: string;
  /** The node whose relation to the protected content decides whether the read is interesting. */
  subject: (self: unknown, args: unknown[]) => unknown;
  /** Extra precondition, for example `cloneNode(false)` copies no content. */
  applies?: (self: unknown, args: unknown[]) => boolean;
  /** `string` results are scrambled as text. `node` results are rebuilt from a poisoned clone. */
  result: 'html' | 'text' | 'node';
}

interface Patch {
  target: object;
  prop: string;
  original: PropertyDescriptor;
  installed: PropertyDescriptor;
  api: string;
}

const SPECS: ReadSpec[] = [
  { api: 'innerHTML', kind: 'getter', proto: (w) => w.Element?.prototype, prop: 'innerHTML', subject: (s) => s, result: 'html' },
  { api: 'outerHTML', kind: 'getter', proto: (w) => w.Element?.prototype, prop: 'outerHTML', subject: (s) => s, result: 'html' },
  { api: 'textContent', kind: 'getter', proto: (w) => w.Node?.prototype, prop: 'textContent', subject: (s) => s, result: 'text' },
  { api: 'innerText', kind: 'getter', proto: (w) => w.HTMLElement?.prototype, prop: 'innerText', subject: (s) => s, result: 'text' },
  { api: 'outerText', kind: 'getter', proto: (w) => w.HTMLElement?.prototype, prop: 'outerText', subject: (s) => s, result: 'text' },
  { api: 'nodeValue', kind: 'getter', proto: (w) => w.Node?.prototype, prop: 'nodeValue', subject: (s) => s, result: 'text', applies: isCharacterData },
  { api: 'data', kind: 'getter', proto: (w) => w.CharacterData?.prototype, prop: 'data', subject: (s) => s, result: 'text' },
  { api: 'getHTML', kind: 'method', proto: (w) => w.Element?.prototype, prop: 'getHTML', subject: (s) => s, result: 'html' },
  {
    api: 'cloneNode',
    kind: 'method',
    proto: (w) => w.Node?.prototype,
    prop: 'cloneNode',
    subject: (s) => s,
    result: 'node',
    applies: (s, args) => args[0] === true || isCharacterData(s),
  },
  {
    api: 'XMLSerializer.serializeToString',
    kind: 'method',
    proto: (w) => w.XMLSerializer?.prototype,
    prop: 'serializeToString',
    subject: (_s, args) => args[0],
    result: 'html',
  },
  {
    api: 'Range.cloneContents',
    kind: 'method',
    proto: (w) => w.Range?.prototype,
    prop: 'cloneContents',
    subject: (s) => (s as Range).commonAncestorContainer,
    result: 'node',
  },
  {
    api: 'Range.toString',
    kind: 'method',
    proto: (w) => w.Range?.prototype,
    prop: 'toString',
    subject: (s) => (s as Range).commonAncestorContainer,
    result: 'text',
  },
];

function isCharacterData(node: unknown): boolean {
  const t = (node as Node | null)?.nodeType;
  return t === 3 || t === 4 || t === 8;
}

const SEVERITY: Record<CallerKind, Severity> = {
  automation: 'high',
  detached: 'high',
  extension: 'low',
  page: 'info',
  unknown: 'info',
};

export class DomReadDetector implements GuardModule {
  readonly name = 'domRead';
  private patches: Patch[] = [];
  private realms = new WeakSet<object>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private foreignFrames: ForeignFrameDetector | undefined;
  private readonly mode: NonNullable<DomReadOptions['response']>;
  private readonly scope: NonNullable<DomReadOptions['scope']>;
  private readonly untrusted: Set<CallerKind>;
  private readonly decoy: (text: string) => string;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: DomReadOptions = {},
  ) {
    this.mode = options.response ?? 'observe';
    this.scope = options.scope ?? 'subtree';
    this.untrusted = new Set(options.untrusted ?? ['detached', 'automation']);
    this.decoy = options.decoy ?? ((text) => scrambleText(text));
  }

  start(): void {
    natives();
    this.instrument(window as Win);
    if (this.options.instrumentFrames !== false) this.instrumentFrameAccess(window as Win);
    if (this.options.foreignFrames !== false) {
      this.foreignFrames = new ForeignFrameDetector(this.ctx);
      this.foreignFrames.start(window as Win);
    }
    const every = this.options.integrityIntervalMs ?? 5000;
    if (every > 0) this.timer = natives().setInterval(() => this.verify(), every);
  }

  stop(): void {
    if (this.timer !== undefined) natives().clearInterval(this.timer);
    this.timer = undefined;
    this.foreignFrames?.stop();
    this.foreignFrames = undefined;
    for (const p of this.patches.reverse()) {
      try {
        Object.defineProperty(p.target, p.prop, p.original);
      } catch {
        /* a frame may have gone away */
      }
    }
    this.patches = [];
    this.realms = new WeakSet();
  }

  /** Install the read hooks into one JavaScript realm. */
  private instrument(w: Win): void {
    if (this.realms.has(w)) return;
    this.realms.add(w);
    for (const spec of SPECS) {
      const target = spec.proto(w);
      if (!target) continue;
      const original = Object.getOwnPropertyDescriptor(target, spec.prop);
      if (!original || original.configurable === false) continue;
      const native = spec.kind === 'getter' ? original.get : (original.value as unknown);
      if (typeof native !== 'function') continue;
      const nativeFn = native as (this: unknown, ...args: unknown[]) => unknown;
      const detector = this;
      const hook = trap(function (this: unknown, ...args: unknown[]): unknown {
        return detector.onRead(spec, this, args, nativeFn);
      });
      const installed: PropertyDescriptor =
        spec.kind === 'getter' ? { ...original, get: hook } : { ...original, value: hook };
      Object.defineProperty(target, spec.prop, installed);
      this.patches.push({ target, prop: spec.prop, original, installed, api: spec.api });
    }
  }

  /**
   * A fresh same-origin iframe is the standard way to obtain unpatched DOM accessors. Instrument a frame's realm
   * the moment a script reaches for it. Indexed access (`window[0]`, `frames[0]`) cannot be intercepted.
   */
  private instrumentFrameAccess(w: Win): void {
    const proto = w.HTMLIFrameElement?.prototype;
    if (!proto) return;
    for (const prop of ['contentWindow', 'contentDocument'] as const) {
      const original = Object.getOwnPropertyDescriptor(proto, prop);
      if (!original?.get || original.configurable === false) continue;
      const get = original.get;
      const detector = this;
      const hook = trap(function (this: unknown): unknown {
        const value = get.call(this) as (Window | Document | null) & object;
        try {
          const frameWindow = (prop === 'contentWindow' ? value : (value as Document | null)?.defaultView) as Win | null;
          // Touching a cross-origin window's properties throws, which is the same-origin test.
          if (frameWindow && frameWindow.Element) detector.instrument(frameWindow);
        } catch {
          /* cross-origin frame */
        }
        return value;
      });
      const installed = { ...original, get: hook };
      Object.defineProperty(proto, prop, installed);
      this.patches.push({ target: proto, prop, original, installed, api: `iframe.${prop}` });
    }
  }

  private onRead(
    spec: ReadSpec,
    self: unknown,
    args: unknown[],
    native: (this: unknown, ...args: unknown[]) => unknown,
  ): unknown {
    const ctx = this.ctx;
    if (ctx.isInternal() || ctx.suspended) return native.apply(self, args);
    if (spec.applies && !spec.applies(self, args)) return native.apply(self, args);
    let subject: unknown;
    try {
      subject = spec.subject(self, args);
    } catch {
      return native.apply(self, args);
    }
    const relation = ctx.relation(subject);
    if (!relation || (relation === 'inside' && this.scope === 'root')) return native.apply(self, args);

    const origin = captureCaller();
    const untrusted = this.isUntrusted(origin);
    // Under the cloak the light DOM holds the decoy. The page's own read of a cloaked root gets the real content.
    const real = untrusted ? undefined : this.realTarget(spec, self);
    // Main-world extension and userscript reads are worth knowing about even when they are served real content.
    if (!untrusted && origin.kind !== 'extension') return real ? this.readReal(real, args, native) : native.apply(self, args);
    const mode = untrusted ? this.mode : 'observe';

    ctx.emit({
      type: 'dom-read',
      code: `dom-read.${origin.kind}`,
      dedupKey: `dom-read.${origin.kind}:${spec.api}:${relation}`,
      severity: relation === 'inside' && origin.kind === 'detached' ? 'medium' : SEVERITY[origin.kind],
      confidence: origin.kind === 'automation' ? 0.95 : 0.8,
      message: `Protected content was read through ${spec.api} by ${describe(origin.kind)}`,
      details: { api: spec.api, relation, response: mode, frames: origin.frames.slice(0, 6) },
    });

    if (mode === 'observe') return real ? this.readReal(real, args, native) : native.apply(self, args);
    return ctx.internal(() =>
      mode === 'block' ? this.blocked(spec, self, args, native) : this.poisoned(spec, subject as Node, self, args, native),
    );
  }

  /** For a string read of a cloaked root itself, the shadow element that holds the real content. */
  private realTarget(spec: ReadSpec, self: unknown): Element | undefined {
    if (spec.kind !== 'getter' || spec.result === 'node' || spec.api === 'outerHTML') return undefined;
    return this.ctx.cloaked.get(self as Element);
  }

  private readReal(real: Element, args: unknown[], native: (this: unknown, ...args: unknown[]) => unknown): unknown {
    return this.ctx.internal(() => this.ctx.withRealOrder(() => native.apply(real, args)));
  }

  private isUntrusted(origin: CallerOrigin): boolean {
    if (!this.untrusted.has(origin.kind)) return false;
    try {
      if (this.options.trustCaller?.(origin)) return false;
    } catch {
      /* a throwing callback must not break the page's read */
    }
    return true;
  }

  private blocked(
    spec: ReadSpec,
    self: unknown,
    args: unknown[],
    native: (this: unknown, ...args: unknown[]) => unknown,
  ): unknown {
    if (spec.result !== 'node') return '';
    if (spec.api === 'cloneNode') return natives().cloneNode.call(self as Node, false);
    return (self as Range).startContainer.ownerDocument?.createDocumentFragment() ?? native.apply(self, args);
  }

  private poisoned(
    spec: ReadSpec,
    subject: Node,
    self: unknown,
    args: unknown[],
    native: (this: unknown, ...args: unknown[]) => unknown,
  ): unknown {
    if (spec.api === 'Range.cloneContents') {
      const fragment = native.apply(self, args) as Node;
      this.scrambleTextNodes(fragment);
      return fragment;
    }
    if (spec.result === 'text' && (spec.api !== 'textContent' || isCharacterData(subject))) {
      const value = native.apply(self, args);
      return typeof value === 'string' ? this.decoy(value) : value;
    }
    const clone = this.poisonedClone(subject);
    switch (spec.api) {
      case 'cloneNode':
        return clone;
      case 'textContent':
        return natives().textContentGet.call(clone);
      case 'XMLSerializer.serializeToString':
        return native.call(self, clone);
      default:
        // innerHTML, outerHTML, getHTML: run the native read against the poisoned clone.
        return native.apply(clone, args);
    }
  }

  /** Deep-clone `node` and scramble the text of every protected part of the copy. */
  private poisonedClone(node: Node): Node {
    const N = natives();
    const clone = N.cloneNode.call(node, true);
    const targets: Node[] = [];
    for (const root of this.ctx.roots) {
      if (node === root || N.contains.call(root, node)) {
        targets.length = 0;
        targets.push(clone);
        break;
      }
      if (N.contains.call(node, root)) {
        const twin = follow(clone, pathFrom(node, root));
        if (twin) targets.push(twin);
      }
    }
    for (const t of targets) this.scrambleTextNodes(t);
    return clone;
  }

  private scrambleTextNodes(root: Node): void {
    if (root.nodeType === 3) {
      root.nodeValue = this.decoy(root.nodeValue ?? '');
      return;
    }
    const doc = root.ownerDocument ?? (root as Document);
    const walker = doc.createTreeWalker(root, 4 /* NodeFilter.SHOW_TEXT */);
    const nodes: Node[] = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const n of nodes) {
      const text = n.nodeValue ?? '';
      if (text.trim() !== '') n.nodeValue = this.decoy(text);
    }
  }

  /** Detect hooks that were removed or replaced, report it, and put them back. */
  private verify(): void {
    const broken: string[] = [];
    for (const p of this.patches) {
      let current: PropertyDescriptor | undefined;
      try {
        current = Object.getOwnPropertyDescriptor(p.target, p.prop);
      } catch {
        continue;
      }
      const ok = current && current.get === p.installed.get && current.value === p.installed.value;
      if (ok) continue;
      broken.push(p.api);
      try {
        Object.defineProperty(p.target, p.prop, p.installed);
      } catch {
        /* made non-configurable by the tamperer */
      }
    }
    if (broken.length > 0) {
      this.ctx.emit({
        type: 'tamper',
        code: 'tamper.dom-read-hooks',
        severity: 'critical',
        confidence: 0.9,
        message: 'DOM read instrumentation was removed or replaced',
        details: { apis: broken },
      });
    }
  }
}

function describe(kind: CallerKind): string {
  switch (kind) {
    case 'automation':
      return 'an automation framework';
    case 'detached':
      return 'code with no script origin (DevTools console or CDP Runtime.evaluate)';
    case 'extension':
      return 'an extension or userscript';
    default:
      return 'a page script';
  }
}

/** Child indexes leading from `ancestor` down to `node`. */
function pathFrom(ancestor: Node, node: Node): number[] {
  const path: number[] = [];
  let cur: Node | null = node;
  while (cur && cur !== ancestor) {
    const parent: Node | null = cur.parentNode;
    if (!parent) return [];
    path.unshift(Array.prototype.indexOf.call(parent.childNodes, cur));
    cur = parent;
  }
  return path;
}

function follow(start: Node, path: number[]): Node | null {
  let cur: Node | null = start;
  for (const i of path) {
    cur = cur?.childNodes[i] ?? null;
    if (!cur) return null;
  }
  return path.length > 0 ? cur : null;
}
