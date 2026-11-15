import { GuardContext, type GuardModule } from './core/context';
import { natives } from './core/native';
import { randomId, resolveToggle } from './core/util';
import { Cloak } from './defenses/cloak';
import { Honeypots } from './defenses/honeypot';
import { TextWatermark } from './defenses/text-watermark';
import { VisibleWatermark } from './defenses/watermark';
import { CdpDetector } from './detectors/cdp';
import { DomReadDetector } from './detectors/dom-read';
import { EnvironmentDetector } from './detectors/environment';
import { HeadlessDetector } from './detectors/headless';
import { InteractionGuard } from './detectors/interaction';
import { ResourceDetector } from './detectors/resources';
import { ResponseEngine } from './response/engine';
import { collectFingerprint } from './response/fingerprint';
import { Reporter } from './response/reporter';
import { ContentShield, type ShieldLevel } from './response/shield';
import type { Fingerprint, ResponseApi, ShadowGuardianOptions, Signal, SignalInput } from './types';

type Listener = (signal: Signal) => void;

let active: Guardian | null = null;

function resolveContent(content: ShadowGuardianOptions['content']): Element[] {
  let elements: Element[];
  if (typeof content === 'string') elements = Array.from(document.querySelectorAll(content));
  else if (typeof (content as Element).nodeType === 'number') elements = [content as Element];
  else elements = Array.from(content as ArrayLike<Element>);
  elements = elements.filter((el) => el && el.nodeType === 1);
  // Nested roots would be instrumented twice. Keep the outermost ones.
  return elements.filter((el) => !elements.some((other) => other !== el && other.contains(el)));
}

/** A running ShadowGuardian instance. Create one with `protect()`. */
export class Guardian {
  readonly sessionId: string;
  private readonly ctx: GuardContext;
  private readonly engine: ResponseEngine;
  private readonly reporter: Reporter;
  private readonly shield: ContentShield;
  private readonly modules: GuardModule[] = [];
  private readonly listeners = new Set<Listener>();
  private honeypots: Honeypots | undefined;
  private running = false;

  constructor(private readonly options: ShadowGuardianOptions) {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      throw new Error('ShadowGuardian: protect() needs a browser. For server-side rendering use watermarkText().');
    }
    if (!options.user || !options.user.id) throw new Error('ShadowGuardian: `user.id` is required');
    const roots = resolveContent(options.content);
    if (roots.length === 0) {
      throw new Error('ShadowGuardian: `content` matched no elements. Call protect() after the content is in the DOM.');
    }
    this.sessionId = options.sessionId ?? randomId(12);
    this.ctx = new GuardContext(roots, options.user, this.sessionId, (input) => this.emit(input));
    this.shield = new ContentShield(this.ctx, options.response?.notice);
    this.reporter = new Reporter(
      options.report ?? {},
      { sessionId: this.sessionId, userId: options.user.id },
      () => this.engine.score,
    );
    const api: ResponseApi = {
      obfuscate: () => this.shield.obfuscate(),
      decoy: () => this.shield.decoy(),
      lockdown: () => this.shield.lockdown(),
      restore: () => this.shield.restore(),
      fingerprint: () => this.fingerprint(),
      get score() {
        return engine.score;
      },
    };
    const engine = new ResponseEngine(options.response ?? {}, {
      api,
      onFingerprint: (fp) => this.reporter.setFingerprint(fp),
      onSignal: (signal) => {
        this.reporter.push(signal);
        this.notify(signal);
      },
    });
    this.engine = engine;
    this.build();
  }

  private build(): void {
    const { detectors = {}, defenses = {} } = this.options;
    const ctx = this.ctx;

    // Defences first: they change the DOM, and the detectors should see the finished page.
    // The cloak goes before the others, so that they mark both the real content and the decoy it leaves behind.
    const cloakOptions = resolveToggle(defenses.cloak, false);
    const cloak = cloakOptions ? new Cloak(ctx, cloakOptions) : undefined;
    if (cloak) this.modules.push(cloak);
    const honeypots = resolveToggle(defenses.honeypots, true);
    if (honeypots) {
      this.honeypots = new Honeypots(ctx, honeypots);
      this.modules.push(this.honeypots);
    }
    const textWatermark = resolveToggle(defenses.textWatermark, true);
    if (textWatermark) this.modules.push(new TextWatermark(ctx, textWatermark));
    const watermark = resolveToggle(defenses.watermark, true);
    if (watermark) this.modules.push(new VisibleWatermark(ctx, watermark));
    if (cloak) this.modules.push(cloak.reorderPhase);

    const environment = resolveToggle(detectors.environment, true);
    if (environment) this.modules.push(new EnvironmentDetector(ctx, environment));
    const headless = resolveToggle(detectors.headless, true);
    if (headless) this.modules.push(new HeadlessDetector(ctx, headless));
    const cdp = resolveToggle(detectors.cdp, true);
    if (cdp) this.modules.push(new CdpDetector(ctx, cdp));
    const interaction = resolveToggle(detectors.interaction, true);
    if (interaction) this.modules.push(new InteractionGuard(ctx, interaction));
    const resources = resolveToggle(detectors.resources, true);
    if (resources) this.modules.push(new ResourceDetector(ctx, resources));
    const domRead = resolveToggle(detectors.domRead, true);
    if (domRead) this.modules.push(new DomReadDetector(ctx, domRead));
  }

  /** Start every enabled module. Called by `protect()`. */
  start(): this {
    if (this.running) return this;
    if (active && active !== this) {
      throw new Error('ShadowGuardian: another instance is already running. Call stop() on it first.');
    }
    active = this;
    this.running = true;
    natives();
    this.reporter.start();
    for (const module of this.modules) {
      try {
        module.start();
      } catch (error) {
        // One module failing on an unusual browser must not leave the page unprotected by the rest.
        console.warn(`[ShadowGuardian] module "${module.name}" failed to start`, error);
      }
    }
    return this;
  }

  /** Remove all instrumentation, listeners and injected elements, and restore the content if it was swapped. */
  stop(): void {
    if (!this.running) return;
    this.running = false;
    this.shield.restore();
    for (const module of this.modules.slice().reverse()) {
      try {
        module.stop();
      } catch (error) {
        console.warn(`[ShadowGuardian] module "${module.name}" failed to stop`, error);
      }
    }
    this.reporter.stop();
    if (active === this) active = null;
  }

  /** Subscribe to signals. Returns an unsubscribe function. */
  on(_event: 'signal', listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Signals raised so far, oldest first (the most recent 500). */
  get signals(): readonly Signal[] {
    return this.engine.signals;
  }

  /** Cumulative threat score from 0 to 100. */
  get score(): number {
    return this.engine.score;
  }

  /** The content response currently in force. */
  get level(): ShieldLevel {
    return this.shield.level;
  }

  /** The protected elements. */
  get content(): readonly Element[] {
    return this.ctx.roots;
  }

  /** True when the content is cloaked: the real nodes are in a closed shadow tree and the light DOM holds a decoy. */
  get cloaked(): boolean {
    return this.ctx.cloaked.size > 0;
  }

  /** The token embedded in this page's honeypots, or `undefined` when honeypots are off. */
  get honeypotToken(): string | undefined {
    return this.honeypots?.token;
  }

  /** Blur the content and show the notice. */
  obfuscate(): void {
    this.shield.obfuscate();
  }

  /** Replace the content with a scrambled copy. */
  decoy(): void {
    this.shield.decoy();
  }

  /** Remove the content and show the notice. */
  lockdown(): void {
    this.shield.lockdown();
  }

  /** Undo `obfuscate`, `decoy` or `lockdown`. */
  restore(): void {
    this.shield.restore();
  }

  /** Collect the browser fingerprint now. */
  fingerprint(): Fingerprint {
    return this.ctx.internal(() => collectFingerprint());
  }

  /** Raise a signal of your own, for example from server-pushed intelligence. It goes through the same rules. */
  report(signal: SignalInput): void {
    this.emit(signal);
  }

  /** Send queued signals to the backend now. */
  flush(): void {
    this.reporter.flush(false);
  }

  private emit(input: SignalInput): void {
    if (!this.running) return;
    this.engine.handle(input);
  }

  private notify(signal: Signal): void {
    const callbacks: Listener[] = Array.from(this.listeners);
    if (this.options.onSignal) callbacks.unshift(this.options.onSignal);
    for (const cb of callbacks) {
      try {
        cb(signal);
      } catch (error) {
        console.warn('[ShadowGuardian] signal listener threw', error);
      }
    }
  }
}

/**
 * Protect premium content on the current page.
 *
 * @example
 * const guardian = protect({
 *   content: '#lesson',
 *   user: { id: 'acct_81f3', label: 'jane@example.com' },
 *   report: { endpoint: '/api/shadowguardian' },
 * });
 */
export function protect(options: ShadowGuardianOptions): Guardian {
  return new Guardian(options).start();
}
