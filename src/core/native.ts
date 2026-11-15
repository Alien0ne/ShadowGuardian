/**
 * Pristine references to platform functions.
 *
 * ShadowGuardian instruments several DOM APIs. Its own code must keep working through the originals, both to avoid
 * tripping its own detectors and to stay correct if a later script patches the same APIs. References are captured
 * lazily on first use, which is at `protect()` time: before ShadowGuardian installs anything, but possibly after other
 * scripts on the page have run. Load the SDK early.
 */

type AnyFn = (...args: never[]) => unknown;

export interface Natives {
  innerHTMLGet: (this: Element) => string;
  outerHTMLGet: (this: Element) => string;
  textContentGet: (this: Node) => string | null;
  cloneNode: (this: Node, deep?: boolean) => Node;
  contains: (this: Node, other: Node | null) => boolean;
  fetch: typeof fetch | undefined;
  sendBeacon: ((url: string, data?: BodyInit | null) => boolean) | undefined;
  consoleDebug: (...args: unknown[]) => void;
  toDataURL: ((this: HTMLCanvasElement, type?: string, quality?: number) => string) | undefined;
  getComputedStyle: typeof getComputedStyle;
  setInterval: typeof setInterval;
  clearInterval: typeof clearInterval;
  setTimeout: typeof setTimeout;
  clearTimeout: typeof clearTimeout;
  functionToString: (this: AnyFn) => string;
}

let cached: Natives | undefined;

function getter<T, R>(proto: object, prop: string): (this: T) => R {
  const d = Object.getOwnPropertyDescriptor(proto, prop);
  if (!d || !d.get) throw new Error(`ShadowGuardian: missing native accessor ${prop}`);
  return d.get as (this: T) => R;
}

export function natives(): Natives {
  if (cached) return cached;
  const w = window;
  cached = {
    innerHTMLGet: getter<Element, string>(w.Element.prototype, 'innerHTML'),
    outerHTMLGet: getter<Element, string>(w.Element.prototype, 'outerHTML'),
    textContentGet: getter<Node, string | null>(w.Node.prototype, 'textContent'),
    cloneNode: w.Node.prototype.cloneNode,
    contains: w.Node.prototype.contains,
    fetch: typeof w.fetch === 'function' ? w.fetch.bind(w) : undefined,
    sendBeacon:
      typeof w.navigator.sendBeacon === 'function' ? w.navigator.sendBeacon.bind(w.navigator) : undefined,
    consoleDebug: w.console.debug.bind(w.console),
    toDataURL: w.HTMLCanvasElement ? w.HTMLCanvasElement.prototype.toDataURL : undefined,
    getComputedStyle: w.getComputedStyle.bind(w),
    setInterval: w.setInterval.bind(w) as typeof setInterval,
    clearInterval: w.clearInterval.bind(w) as typeof clearInterval,
    setTimeout: w.setTimeout.bind(w) as typeof setTimeout,
    clearTimeout: w.clearTimeout.bind(w) as typeof clearTimeout,
    functionToString: Function.prototype.toString as (this: AnyFn) => string,
  };
  return cached;
}

/** Test hook: forget captured references so the next `natives()` call re-reads the platform. */
export function resetNatives(): void {
  cached = undefined;
}
