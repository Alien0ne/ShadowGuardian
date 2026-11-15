import type { GuardContext, GuardModule } from '../core/context';
import { captureCaller, trap } from '../core/stack';
import { matchesPattern } from '../core/util';
import type { CallerOrigin, ResourceOptions } from '../types';

/**
 * Resource access detector.
 *
 * Covers the ways script can get at the bytes of protected media after the page has loaded it:
 *
 * - **Scripted re-fetch.** `fetch()` or `XMLHttpRequest` for a protected image is answered from the HTTP cache
 *   without the server seeing anything unusual. Both are instrumented and the caller is classified.
 * - **Resource Timing.** A protected image normally appears with initiator `img`. The same URL showing up with
 *   initiator `fetch` or `xmlhttprequest` means script pulled it, including through a saved copy of `fetch` that
 *   bypasses the wrapper.
 * - **Canvas readback.** Drawing a protected image to a canvas and exporting it is the other in-page route to its
 *   pixels.
 *
 * Not observable: `Page.getResourceContent` and `Network.getResponseBody` over CDP, which read the browser's own
 * copy of the resource without touching the page. Per-user watermarking of the image itself, done on the server, is
 * the working defence there.
 */
export class ResourceDetector implements GuardModule {
  readonly name = 'resources';
  private undo: Array<() => void> = [];
  private observer: PerformanceObserver | undefined;
  private tainted = new WeakSet<object>();

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: ResourceOptions = {},
  ) {}

  start(): void {
    if (this.options.network !== false) this.hookNetwork();
    if (this.options.canvas !== false) this.hookCanvas();
    if (this.options.timing !== false) this.watchTiming();
  }

  stop(): void {
    for (const u of this.undo.reverse()) u();
    this.undo = [];
    this.observer?.disconnect();
    this.observer = undefined;
  }

  /** Absolute URLs of media referenced inside the protected content. */
  private protectedUrls(): Set<string> {
    const urls = new Set<string>();
    this.ctx.internal(() => {
      for (const root of this.ctx.contentRoots) {
        const media = root.querySelectorAll('img, source, video, audio, object, embed, image');
        media.forEach((el) => {
          for (const attr of ['src', 'poster', 'data', 'href', 'data-src']) {
            const v = el.getAttribute(attr);
            if (v) addUrl(urls, v);
          }
          const current = (el as HTMLImageElement).currentSrc;
          if (current) addUrl(urls, current);
          const srcset = el.getAttribute('srcset');
          if (srcset) for (const part of srcset.split(',')) addUrl(urls, (part.trim().split(/\s+/)[0] ?? ''));
        });
      }
    });
    return urls;
  }

  private isProtectedUrl(raw: unknown): string | null {
    let url: string;
    try {
      const value = typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : (raw as Request)?.url;
      if (!value) return null;
      url = new URL(value, location.href).href;
    } catch {
      return null;
    }
    if (this.options.patterns && matchesPattern(url, this.options.patterns)) return url;
    return this.protectedUrls().has(url) ? url : null;
  }

  private patch<T extends object>(target: T | undefined, prop: string, make: (original: Function) => Function): void {
    if (!target) return;
    const desc = Object.getOwnPropertyDescriptor(target, prop);
    if (!desc || typeof desc.value !== 'function' || desc.configurable === false) return;
    const original = desc.value as Function;
    Object.defineProperty(target, prop, { ...desc, value: make(original) });
    this.undo.push(() => Object.defineProperty(target, prop, desc));
  }

  private hookNetwork(): void {
    const detector = this;
    this.patch(window, 'fetch', (original) =>
      trap(function (this: unknown, ...args: unknown[]): unknown {
        detector.onRequest('fetch', args[0]);
        return original.apply(this, args);
      }),
    );
    this.patch(window.XMLHttpRequest?.prototype, 'open', (original) =>
      trap(function (this: unknown, ...args: unknown[]): unknown {
        detector.onRequest('XMLHttpRequest', args[1]);
        return original.apply(this, args);
      }),
    );
  }

  private onRequest(api: string, target: unknown): void {
    if (this.ctx.isInternal()) return;
    const url = this.isProtectedUrl(target);
    if (!url) return;
    const origin = captureCaller();
    if (origin.kind === 'page' || origin.kind === 'unknown') return;
    this.ctx.emit({
      type: 'resource-access',
      code: 'resource.untrusted-fetch',
      severity: origin.kind === 'extension' ? 'low' : 'high',
      confidence: 0.85,
      message: `Protected media was requested through ${api} by ${origin.kind} code`,
      details: { api, url, caller: origin.kind, frames: origin.frames.slice(0, 6) },
    });
  }

  private hookCanvas(): void {
    const detector = this;
    const ctx2d = window.CanvasRenderingContext2D?.prototype;
    const canvas = window.HTMLCanvasElement?.prototype;

    this.patch(ctx2d, 'drawImage', (original) =>
      trap(function (this: unknown, ...args: unknown[]): unknown {
        try {
          if (detector.isProtectedImage(args[0])) {
            const target = (this as CanvasRenderingContext2D).canvas;
            if (target) detector.tainted.add(target);
          }
        } catch {
          /* never break drawing */
        }
        return original.apply(this, args);
      }),
    );
    this.patch(ctx2d, 'getImageData', (original) =>
      trap(function (this: unknown, ...args: unknown[]): unknown {
        detector.onReadback('getImageData', (this as CanvasRenderingContext2D).canvas);
        return original.apply(this, args);
      }),
    );
    for (const method of ['toDataURL', 'toBlob']) {
      this.patch(canvas, method, (original) =>
        trap(function (this: unknown, ...args: unknown[]): unknown {
          detector.onReadback(method, this);
          return original.apply(this, args);
        }),
      );
    }
  }

  private isProtectedImage(source: unknown): boolean {
    if (!source || typeof source !== 'object') return false;
    if (this.tainted.has(source)) return true;
    if (this.ctx.relation(source) === 'inside') return true;
    const src = (source as HTMLImageElement).currentSrc || (source as HTMLImageElement).src;
    return typeof src === 'string' && src !== '' && this.isProtectedUrl(src) !== null;
  }

  private onReadback(api: string, canvas: unknown): void {
    if (this.ctx.isInternal() || !canvas || typeof canvas !== 'object' || !this.tainted.has(canvas)) return;
    const origin: CallerOrigin = captureCaller();
    const untrusted = origin.kind === 'detached' || origin.kind === 'automation';
    this.ctx.emit({
      type: 'resource-access',
      code: 'resource.canvas-readback',
      severity: untrusted ? 'high' : 'medium',
      confidence: untrusted ? 0.9 : 0.6,
      message: `Pixels of a protected image were read back from a canvas through ${api}`,
      details: { api, caller: origin.kind, frames: origin.frames.slice(0, 6) },
    });
  }

  private watchTiming(): void {
    if (typeof PerformanceObserver !== 'function') return;
    try {
      this.observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries() as PerformanceResourceTiming[]) {
          if (entry.initiatorType !== 'fetch' && entry.initiatorType !== 'xmlhttprequest') continue;
          const url = this.isProtectedUrl(entry.name);
          if (!url) continue;
          this.ctx.emit({
            type: 'resource-access',
            code: 'resource.scripted-refetch',
            severity: 'medium',
            confidence: 0.6,
            message: 'Protected media was re-fetched by script',
            details: {
              url,
              initiator: entry.initiatorType,
              // A transfer size of zero with a body means the response came from the HTTP cache.
              fromCache: entry.transferSize === 0 && entry.decodedBodySize > 0,
            },
          });
        }
      });
      this.observer.observe({ type: 'resource', buffered: false });
    } catch {
      this.observer = undefined;
    }
  }
}

function addUrl(set: Set<string>, value: string): void {
  if (!value || value.startsWith('data:')) return;
  try {
    set.add(new URL(value, location.href).href);
  } catch {
    /* not a URL */
  }
}
