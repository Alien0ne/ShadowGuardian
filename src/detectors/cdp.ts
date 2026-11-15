import { findAutomationGlobals } from '../core/automation';
import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import type { CdpOptions } from '../types';

/**
 * CDP connection detector.
 *
 * A page cannot see a DevTools Protocol socket. It can only look for side effects of an attached client:
 *
 * 1. **Console serialisation.** When a client has enabled the `Runtime` domain (DevTools does, and so do most
 *    automation libraries), console arguments are serialised for the remote end. Bait objects with accessors notice
 *    being inspected. V8 closed the best-known form (an own `stack` accessor on an Error) in 2025. Inherited
 *    `stack` accessors still react on Chromium 150, verified by test/e2e/cdp-read.mjs, and stay silent when no
 *    client is attached. Expect this to change again: the probe is a medium-confidence signal, not a foundation.
 *    Baits that react to console formatting itself (accessor `name`, `message`, `Symbol.toStringTag`) are not
 *    used, because they fire with no client attached.
 * 2. **Bindings.** `Runtime.addBinding` and framework init scripts add recognisable globals.
 * 3. **Debugger timing** (opt-in). A `debugger` statement only takes time when a debugger is attached and pausing.
 * 4. **Console API side-channel.** A plain-object property getter logged through `console.debug` fires only when a
 *    CDP client serialises it, complementing the Error-based serialisation probe.
 * 5. **Debugger timing (sensitive).** Runs `debugger` multiple times and checks for small overhead. Fires once.
 * 6. **Error.stack fingerprinting.** Checks for `stackTraceLimit` and `prepareStackTrace` modifications, and scans
 *    sampled stacks for automation markers.
 * 7. **requestAnimationFrame jitter.** Collects rAF timestamps and flags unrealistically fast or uniform timing.
 *
 * A client that attaches without enabling `Runtime` and never evaluates script is not detectable from the page.
 * The DOM read detector covers the moment such a client actually reads content through `Runtime.evaluate`.
 */
export class CdpDetector implements GuardModule {
  readonly name = 'cdp';
  private timer: ReturnType<typeof setInterval> | undefined;
  private serializationSeen = false;
  private bindingsSeen = new Set<string>();
  private consoleChannelSeen = false;
  private debuggerTimingSeen = false;
  private stackProbeSeen = false;
  private rafSeen = false;
  private rafHandle: number | undefined;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: CdpOptions = {},
  ) {}

  start(): void {
    this.probe();
    const every = this.options.intervalMs ?? 3000;
    if (every > 0) this.timer = natives().setInterval(() => this.probe(), every);
    this.startRafProbe();
  }

  stop(): void {
    if (this.timer !== undefined) natives().clearInterval(this.timer);
    this.timer = undefined;
    if (this.rafHandle !== undefined) {
      try { cancelAnimationFrame(this.rafHandle); } catch { /* rAF unavailable */ }
      this.rafHandle = undefined;
    }
  }

  private probe(): void {
    if (this.options.serializationProbe !== false) this.probeSerialization();
    this.probeConsoleChannel();
    this.probeBindings();
    if (this.options.debuggerProbe) this.probeDebugger();
    this.probeDebuggerTiming();
    this.probeStackFingerprint();
  }

  private probeSerialization(): void {
    if (this.serializationSeen) return;
    const tripped: string[] = [];
    const baits: unknown[] = [];
    const note = (name: string) => () => {
      tripped.push(name);
      return '';
    };

    // An Error whose own `stack` is an accessor.
    const own = new Error('sg');
    safeDefine(own, 'stack', note('error-own-stack'));
    baits.push(own);

    // An Error that inherits an accessor `stack` from its prototype.
    const inherited = new Error('sg');
    const proto = Object.create(Error.prototype) as object;
    safeDefine(proto, 'stack', note('error-proto-stack'));
    try {
      Object.setPrototypeOf(inherited, proto);
      delete (inherited as { stack?: string }).stack;
      baits.push(inherited);
    } catch {
      /* frozen prototype */
    }

    // The same, declared as a class accessor.
    try {
      class Bait extends Error {
        override get stack(): string {
          tripped.push('error-class-stack');
          return '';
        }
      }
      const instance = new Bait('sg');
      delete (instance as { stack?: string }).stack;
      baits.push(instance);
    } catch {
      /* own stack not deletable in this engine */
    }

    try {
      // `console.debug` is hidden at the default console level, so an open console stays clean.
      for (const bait of baits) natives().consoleDebug(bait);
    } catch {
      return;
    }
    if (tripped.length === 0) return;
    this.serializationSeen = true;
    this.ctx.emit({
      type: 'cdp',
      code: 'cdp.runtime-enabled',
      severity: 'medium',
      confidence: 0.7,
      message: 'A DevTools Protocol client with the Runtime domain enabled is attached (DevTools or automation)',
      details: { probes: Array.from(new Set(tripped)) },
    });
  }

  private probeBindings(): void {
    const fresh = findAutomationGlobals().filter((name) => !this.bindingsSeen.has(name));
    if (fresh.length === 0) return;
    for (const name of fresh) this.bindingsSeen.add(name);
    this.ctx.emit({
      type: 'cdp',
      code: 'cdp.bindings',
      severity: 'high',
      confidence: 0.9,
      message: 'Automation bindings are exposed on the page',
      details: { globals: fresh },
    });
  }

  private probeDebugger(): void {
    const started = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    const elapsed = performance.now() - started;
    if (elapsed < 100) return;
    this.ctx.emit({
      type: 'cdp',
      code: 'cdp.debugger-paused',
      severity: 'medium',
      confidence: 0.85,
      message: 'A debugger paused script execution',
      details: { pausedMs: Math.round(elapsed) },
    });
  }

  /**
   * Sensitive debugger timing probe. Runs `debugger` multiple times and checks for small timing
   * overhead that indicates a CDP client is attached, even without Debugger.enable. Fires once.
   * If an interactive debugger pauses execution (>50ms), it backs off and leaves that to `probeDebugger`.
   */
  private probeDebuggerTiming(): void {
    if (this.debuggerTimingSeen) return;
    this.debuggerTimingSeen = true;
    if (typeof performance === 'undefined') return;
    const samples: number[] = [];
    for (let i = 0; i < 5; i++) {
      const t = performance.now();
      // eslint-disable-next-line no-debugger
      debugger;
      const elapsed = performance.now() - t;
      if (elapsed > 50) return; // Interactive debugger paused; leave to probeDebugger.
      samples.push(elapsed);
    }
    const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
    if (avg < 2) return;
    this.ctx.emit({
      type: 'cdp',
      code: 'cdp.debugger-timing',
      severity: avg > 20 ? 'high' : 'medium',
      confidence: Math.min(0.85, 0.5 + avg / 30),
      message: 'Debugger statements show elevated execution time, suggesting CDP attachment',
      details: { avgMs: Math.round(avg * 10) / 10 },
    });
  }

  /**
   * Console API side-channel. Logs a bait object with a property getter through console.debug.
   * When a CDP client has Runtime enabled, V8 serialises the object for the `consoleAPICalled` event,
   * accessing the getter. Without Runtime the getter stays untouched.
   */
  private probeConsoleChannel(): void {
    if (this.consoleChannelSeen) return;
    let tripped = false;
    const bait = Object.create(null) as Record<string, unknown>;
    try {
      Object.defineProperty(bait, 'sg', {
        configurable: true,
        enumerable: true,
        get() { tripped = true; return 0; },
      });
    } catch { return; }
    try {
      natives().consoleDebug(bait);
    } catch { return; }
    if (!tripped) return;
    this.consoleChannelSeen = true;
    this.ctx.emit({
      type: 'cdp',
      code: 'cdp.console-channel',
      severity: 'medium',
      confidence: 0.7,
      message: 'Console argument properties are being serialised, indicating a connected CDP client',
      details: { method: 'property-accessor' },
    });
  }

  /**
   * Error.stack fingerprinting. Automation frameworks and stealth tools modify Error behaviour in
   * detectable ways: changing `stackTraceLimit`, overriding `prepareStackTrace`, or leaving framework
   * markers in stacks sampled from async contexts.
   */
  private probeStackFingerprint(): void {
    if (this.stackProbeSeen) return;
    const anomalies: string[] = [];

    // V8's default stackTraceLimit is 10. Frameworks often raise it; stealth tools sometimes lower it.
    try {
      const limit = (Error as unknown as { stackTraceLimit?: number }).stackTraceLimit;
      if (typeof limit === 'number' && limit !== 10) {
        anomalies.push(`stackTraceLimit=${limit}`);
      }
    } catch { /* not V8 */ }

    // Some frameworks override prepareStackTrace to customise stack formatting.
    try {
      const prepare = (Error as unknown as { prepareStackTrace?: unknown }).prepareStackTrace;
      if (typeof prepare === 'function') {
        anomalies.push('prepareStackTrace-overridden');
      }
    } catch { /* */ }

    // Check for source-map-support or similar stack rewriters that automation often installs.
    try {
      const stack = new Error('sg-probe').stack ?? '';
      const markers = [
        /pptr:/i, /__puppeteer/i, /__playwright/i, /UtilityScript/i,
        /__selenium/i, /__webdriver/i, /__driver_evaluate/i,
      ];
      for (const re of markers) {
        if (re.test(stack)) anomalies.push(`stack-marker:${re.source}`);
      }
    } catch { /* */ }

    if (anomalies.length === 0) return;
    this.stackProbeSeen = true;
    this.ctx.emit({
      type: 'automation',
      code: 'automation.stack-fingerprint',
      severity: anomalies.some((a) => a.startsWith('stack-marker:')) ? 'high' : 'low',
      confidence: 0.6 + 0.1 * Math.min(anomalies.length, 3),
      message: 'Error stack inspection reveals automation indicators',
      details: { anomalies },
    });
  }

  /**
   * requestAnimationFrame jitter probe. Real displays drive rAF at their refresh rate (typically
   * ~16.67ms at 60 Hz) with natural jitter. Headless browsers and virtual displays often fire rAF
   * at unrealistic rates (< 4ms) or with zero jitter. Fires once after collecting enough samples.
   */
  private startRafProbe(): void {
    if (this.rafSeen || typeof requestAnimationFrame === 'undefined') return;
    const timestamps: number[] = [];
    const N = 12;
    const collect = (ts: number): void => {
      timestamps.push(ts);
      if (timestamps.length < N) {
        this.rafHandle = requestAnimationFrame(collect);
        return;
      }
      this.rafHandle = undefined;
      const intervals: number[] = [];
      for (let i = 1; i < timestamps.length; i++) {
        intervals.push((timestamps[i] as number) - (timestamps[i - 1] as number));
      }
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
      const stddev = Math.sqrt(variance);

      // Headless: mean < 4ms (unrealistically fast) or stddev < 0.3ms with non-zero mean (too uniform).
      // Some virtual displays fire at exactly 1ms intervals.
      const tooFast = mean > 0 && mean < 4;
      const tooUniform = mean > 0 && stddev < 0.3;
      if (!tooFast && !tooUniform) return;
      this.rafSeen = true;
      this.ctx.emit({
        type: 'automation',
        code: 'automation.raf-jitter',
        severity: 'medium',
        confidence: tooFast ? 0.75 : 0.6,
        message: 'requestAnimationFrame timing suggests a headless or virtual display',
        details: {
          meanMs: Math.round(mean * 100) / 100,
          stddevMs: Math.round(stddev * 100) / 100,
          reason: tooFast ? 'unrealistic-rate' : 'zero-jitter',
        },
      });
    };
    this.rafHandle = requestAnimationFrame(collect);
  }
}

function safeDefine(target: object, prop: string, get: () => unknown): void {
  try {
    Object.defineProperty(target, prop, { configurable: true, enumerable: false, get });
  } catch {
    /* non-configurable in this engine */
  }
}
