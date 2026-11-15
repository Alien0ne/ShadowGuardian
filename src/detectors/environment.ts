import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import { matchesPattern } from '../core/util';
import type { EnvironmentOptions } from '../types';

/**
 * Environment detector: is the page running where, and how, the vendor intended?
 *
 * - **Host.** The content is being served from a hostname that is not the vendor's (copied HTML, a rehosting proxy).
 * - **Framing.** The page is embedded in another page. `frame-ancestors` in a CSP header is the real fix. This is the
 *   second layer for when a proxy strips headers.
 * - **Service workers.** A worker the vendor did not deploy controls the page and can copy every response.
 * - **Embedded shells.** Electron, WebView2, WKWebView, Tauri and NW.js hosts, where a privileged outer process has
 *   full access to the page.
 * - **Extension artefacts.** Nodes injected by extensions. Informational: most extensions are harmless.
 */
export class EnvironmentDetector implements GuardModule {
  readonly name = 'environment';
  private undo: Array<() => void> = [];
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: EnvironmentOptions = {},
  ) {}

  start(): void {
    this.checkHost();
    this.checkFraming();
    if (this.options.embeddedShell !== false) this.checkShell();
    if (this.options.allowedServiceWorkers) {
      void this.checkServiceWorkers();
      const sw = navigator.serviceWorker;
      if (sw && typeof sw.addEventListener === 'function') {
        const handler = () => void this.checkServiceWorkers();
        sw.addEventListener('controllerchange', handler);
        this.undo.push(() => sw.removeEventListener('controllerchange', handler));
      }
    }
    if (this.options.extensionArtifacts !== false) {
      // Extensions inject at document_idle or later, so look again after the page has settled.
      this.checkExtensions();
      this.timer = natives().setTimeout(() => this.checkExtensions(), 3000);
    }
  }

  stop(): void {
    for (const u of this.undo.reverse()) u();
    this.undo = [];
    if (this.timer !== undefined) natives().clearTimeout(this.timer);
    this.timer = undefined;
  }

  private checkHost(): void {
    const allowed = this.options.allowedHosts;
    if (!allowed || allowed.length === 0) return;
    const host = location.hostname.toLowerCase();
    if (hostAllowed(host, allowed)) return;
    this.ctx.emit({
      type: 'environment',
      code: 'environment.foreign-host',
      severity: 'critical',
      confidence: 1,
      message: 'Protected content is being served from a host that is not on the allow-list',
      details: { host },
    });
  }

  private checkFraming(): void {
    if (this.options.allowFraming) return;
    let framed: boolean;
    try {
      framed = window.top !== window.self;
    } catch {
      framed = true;
    }
    if (!framed) return;
    let ancestors: string[] = [];
    try {
      ancestors = Array.from(location.ancestorOrigins ?? []);
    } catch {
      ancestors = [];
    }
    this.ctx.emit({
      type: 'environment',
      code: 'environment.framed',
      severity: 'high',
      confidence: 1,
      message: 'The page is embedded in a frame',
      details: { ancestors, referrer: document.referrer },
    });
  }

  private checkShell(): void {
    const w = window as unknown as Record<string, unknown> & {
      process?: { versions?: Record<string, string> };
      chrome?: { webview?: unknown };
      webkit?: { messageHandlers?: unknown };
    };
    const ua = navigator.userAgent || '';
    const strong: string[] = [];
    const weak: string[] = [];

    if (/Electron\//i.test(ua) || w.process?.versions?.electron) strong.push('electron');
    if ('__TAURI__' in w || '__TAURI_INTERNALS__' in w) strong.push('tauri');
    if ('nw' in w && typeof w.nw === 'object') strong.push('nwjs');
    if (typeof w.require === 'function' && typeof w.module === 'object') strong.push('node-integration');
    if ('cefQuery' in w || 'CefSharp' in w) strong.push('cef');
    if (w.chrome?.webview) weak.push('webview2');
    // In-app browsers on iOS and Android are WebViews too, and are how many real customers arrive from social apps.
    if (/; wv\)/.test(ua)) weak.push('android-webview');
    if (w.webkit?.messageHandlers && !/Safari\//.test(ua)) weak.push('wkwebview');

    if (strong.length === 0 && weak.length === 0) return;
    this.ctx.emit({
      type: 'environment',
      code: 'environment.embedded-shell',
      severity: strong.length > 0 ? 'medium' : 'low',
      confidence: strong.length > 0 ? 0.9 : 0.6,
      message: 'The page is running inside an application shell instead of a regular browser',
      details: { shells: [...strong, ...weak] },
    });
  }

  private async checkServiceWorkers(): Promise<void> {
    const sw = navigator.serviceWorker;
    const allowed = this.options.allowedServiceWorkers;
    if (!sw || !allowed) return;
    const scripts = new Set<string>();
    try {
      if (sw.controller?.scriptURL) scripts.add(sw.controller.scriptURL);
      const registrations = await sw.getRegistrations();
      for (const r of registrations) {
        const worker = r.active ?? r.waiting ?? r.installing;
        if (worker?.scriptURL) scripts.add(worker.scriptURL);
      }
    } catch {
      return;
    }
    const unexpected = Array.from(scripts).filter((url) => !matchesPattern(url, allowed));
    if (unexpected.length === 0) return;
    this.ctx.emit({
      type: 'environment',
      code: 'environment.unexpected-service-worker',
      severity: 'high',
      confidence: 0.9,
      message: 'A service worker that is not on the allow-list is registered for this origin',
      details: { scripts: unexpected },
    });
  }

  private checkExtensions(): void {
    const found = this.ctx.internal(() => {
      const schemes = ['chrome-extension://', 'moz-extension://', 'safari-web-extension://'];
      const hits = new Set<string>();
      const selector = schemes
        .flatMap((s) => [`[src^="${s}"]`, `[href^="${s}"]`])
        .join(',');
      try {
        document.querySelectorAll(selector).forEach((el) => {
          const url = el.getAttribute('src') ?? el.getAttribute('href') ?? '';
          // Keep only the scheme and extension id. The rest is not needed and is the user's business.
          const m = /^[a-z-]+:\/\/[^/]+/i.exec(url);
          if (m) hits.add(m[0]);
        });
      } catch {
        /* selector unsupported */
      }
      return Array.from(hits);
    });
    if (found.length === 0) return;
    this.ctx.emit({
      type: 'environment',
      code: 'environment.extension-artifacts',
      severity: 'info',
      confidence: 0.9,
      message: 'Browser extensions have injected elements into the page',
      details: { origins: found },
    });
  }
}

/** `example.com` allows `example.com` and any subdomain of it. */
export function hostAllowed(host: string, allowed: string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((entry) => {
    const a = entry.toLowerCase().replace(/^\*\./, '');
    return h === a || h.endsWith(`.${a}`);
  });
}
