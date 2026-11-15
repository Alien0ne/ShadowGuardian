import { findAutomationGlobals } from '../core/automation';
import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import type { HeadlessOptions, Severity } from '../types';

export interface HeadlessCheck {
  name: string;
  /** Contribution to the score when the check trips, from 0 to 1. */
  weight: number;
  detail?: unknown;
}

/**
 * Headless and automation detector.
 *
 * Each check is a weak signal on its own, since every one of them has an innocent explanation somewhere. They are
 * weighted and summed, and only the total decides the severity. `navigator.webdriver` and framework globals are the
 * exceptions: they are definitive.
 */
export class HeadlessDetector implements GuardModule {
  readonly name = 'headless';
  private timer: ReturnType<typeof setInterval> | undefined;
  private reported = new Set<string>();

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: HeadlessOptions = {},
  ) {}

  start(): void {
    this.scan();
    const every = this.options.intervalMs ?? 5000;
    if (every > 0) this.timer = natives().setInterval(() => this.scan(), every);
  }

  stop(): void {
    if (this.timer !== undefined) natives().clearInterval(this.timer);
    this.timer = undefined;
  }

  private scan(): void {
    const checks = runHeadlessChecks();
    const fresh = checks.filter((c) => !this.reported.has(c.name));
    if (fresh.length === 0) return;
    for (const c of checks) this.reported.add(c.name);
    const score = Math.min(1, checks.reduce((sum, c) => sum + c.weight, 0));
    const severity: Severity = score >= 0.8 ? 'high' : score >= 0.5 ? 'medium' : score >= 0.25 ? 'low' : 'info';
    this.ctx.emit({
      type: 'automation',
      code: 'automation.headless',
      severity,
      confidence: score,
      message: 'The browser shows signs of headless or automated operation',
      details: { score, checks: checks.map((c) => ({ name: c.name, weight: c.weight, detail: c.detail })) },
    });
  }
}

interface NavigatorExtras {
  webdriver?: boolean;
  userAgentData?: { brands?: Array<{ brand: string }> };
  deviceMemory?: number;
}

/** Run every check once and return the ones that tripped. Exported for use outside the detector. */
export function runHeadlessChecks(w: Window = window): HeadlessCheck[] {
  const hits: HeadlessCheck[] = [];
  const nav = w.navigator as Navigator & NavigatorExtras;
  const ua = nav.userAgent || '';
  const isChromium = /Chrome\//.test(ua);
  const add = (name: string, weight: number, detail?: unknown) => hits.push({ name, weight, detail });

  if (nav.webdriver === true) add('navigator.webdriver', 1);

  const globals = findAutomationGlobals(w);
  if (globals.length > 0) add('automation-globals', 1, globals);

  if (/HeadlessChrome|PhantomJS|SlimerJS|Electron-headless/i.test(ua)) add('headless-user-agent', 1, ua);

  if (isChromium && !/Mobile|Android/i.test(ua)) {
    if (nav.plugins && nav.plugins.length === 0) add('no-plugins', 0.25);
    if (typeof (w as unknown as { chrome?: unknown }).chrome === 'undefined') add('missing-window.chrome', 0.3);
  }

  if (!nav.languages || nav.languages.length === 0) add('no-languages', 0.35);

  if (w.outerWidth === 0 && w.outerHeight === 0) add('zero-outer-size', 0.4);

  const renderer = webglRenderer(w);
  if (renderer && /SwiftShader|llvmpipe|softpipe|Software Rasterizer/i.test(renderer)) {
    add('software-webgl', 0.3, renderer);
  }

  // A stealth patch defines `webdriver` on the navigator instance, or replaces the prototype accessor with a
  // JavaScript function. Either leaves a trace that the unpatched browser does not have.
  try {
    if (Object.getOwnPropertyDescriptor(nav, 'webdriver')) add('patched-webdriver-instance', 0.6);
    const proto = Object.getPrototypeOf(nav) as object;
    const desc = Object.getOwnPropertyDescriptor(proto, 'webdriver');
    if (desc?.get && !isNative(desc.get)) add('patched-webdriver-getter', 0.6);
    for (const prop of ['plugins', 'languages', 'hardwareConcurrency'] as const) {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (d?.get && !isNative(d.get)) add(`patched-navigator.${prop}`, 0.5);
    }
  } catch {
    /* hardened navigator */
  }

  try {
    const N = (w as unknown as { Notification?: { permission?: string } }).Notification;
    // Old headless Chrome reports a denied notification permission without ever having asked.
    if (isChromium && N && N.permission === 'denied' && nav.plugins && nav.plugins.length === 0) {
      add('notification-denied-by-default', 0.2);
    }
  } catch {
    /* Notification unavailable */
  }

  const brands = nav.userAgentData?.brands;
  if (brands && brands.some((b) => /Headless/i.test(b.brand))) add('headless-ua-brand', 1);

  return hits;
}

function isNative(fn: (...args: never[]) => unknown): boolean {
  try {
    return /\{\s*\[native code\]\s*\}/.test(natives().functionToString.call(fn));
  } catch {
    return false;
  }
}

function webglRenderer(w: Window): string | undefined {
  try {
    const canvas = w.document.createElement('canvas');
    const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
    if (!gl) return undefined;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const value = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    return typeof value === 'string' ? value : undefined;
  } catch {
    return undefined;
  }
}
