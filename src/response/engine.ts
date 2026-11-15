import { randomId, severityAtLeast } from '../core/util';
import type {
  Action,
  Fingerprint,
  ResponseApi,
  ResponseOptions,
  ResponseRule,
  Severity,
  Signal,
  SignalInput,
} from '../types';

/** Points a signal contributes to the threat score at full confidence. */
const WEIGHT: Record<Severity, number> = { info: 2, low: 8, medium: 20, high: 40, critical: 70 };

/**
 * Ready-made rule sets.
 *
 * - `monitor` (default): never touches the content. Signals are reported, and the extractor is fingerprinted on
 *   high-severity signals. Start here and watch your false-positive rate before going further.
 * - `deter`: additionally blurs the content once several independent signals agree.
 * - `strict`: swaps in decoy content on a confirmed automated read and locks the page on tampering or a foreign
 *   host.
 */
export const responsePresets: Record<'monitor' | 'deter' | 'strict', ResponseRule[]> = {
  monitor: [{ when: { minSeverity: 'high' }, actions: ['fingerprint'] }],
  deter: [
    { when: { minSeverity: 'high' }, actions: ['fingerprint'] },
    { when: { minScore: 60 }, actions: ['obfuscate'] },
  ],
  strict: [
    { when: { minSeverity: 'high' }, actions: ['fingerprint'] },
    { when: { minScore: 50 }, actions: ['obfuscate'] },
    { when: { type: ['dom-read', 'automation', 'honeypot'], minSeverity: 'high' }, actions: ['decoy'] },
    { when: { type: 'environment', minSeverity: 'critical' }, actions: ['lockdown'] },
    { when: { type: 'tamper', minSeverity: 'critical' }, actions: ['lockdown'] },
    { when: { minScore: 90 }, actions: ['lockdown'] },
  ],
};

export interface EngineHooks {
  api: ResponseApi;
  onSignal: (signal: Signal) => void;
  onFingerprint: (fingerprint: Fingerprint) => void;
}

/**
 * Turns raw detector output into signals, keeps the threat score, and runs the response rules.
 *
 * The score is the sum, capped at 100, of the strongest contribution seen for each distinct signal code. Repeating
 * one signal does not raise it. Independent detectors agreeing does.
 */
export class ResponseEngine {
  readonly signals: Signal[] = [];
  private contributions = new Map<string, number>();
  private lastEmitted = new Map<string, number>();
  private suppressed = new Map<string, number>();
  private readonly rules: ResponseRule[];
  private readonly cooldown: number;

  constructor(
    options: ResponseOptions,
    private readonly hooks: EngineHooks,
  ) {
    this.rules = options.rules ?? responsePresets.monitor;
    this.cooldown = options.cooldownMs ?? 2000;
  }

  get score(): number {
    let total = 0;
    for (const v of this.contributions.values()) total += v;
    return Math.min(100, Math.round(total));
  }

  handle(input: SignalInput): Signal | null {
    const now = Date.now();
    const key = input.dedupKey ?? input.code;
    const last = this.lastEmitted.get(key);
    if (last !== undefined && now - last < this.cooldown) {
      this.suppressed.set(key, (this.suppressed.get(key) ?? 0) + 1);
      return null;
    }
    this.lastEmitted.set(key, now);
    const confidence = Math.max(0, Math.min(1, input.confidence ?? 1));
    const signal: Signal = {
      id: randomId(6),
      type: input.type,
      code: input.code,
      severity: input.severity,
      confidence,
      message: input.message,
      details: input.details ?? {},
      timestamp: now,
      repeats: this.suppressed.get(key) ?? 0,
    };
    this.suppressed.delete(key);

    const contribution = WEIGHT[signal.severity] * confidence;
    if (contribution > (this.contributions.get(signal.code) ?? 0)) this.contributions.set(signal.code, contribution);

    this.signals.push(signal);
    if (this.signals.length > 500) this.signals.shift();

    // Rules run first so that a fingerprint they collect travels with this signal's report.
    for (const rule of this.rules) {
      if (!this.matches(rule, signal)) continue;
      for (const action of rule.actions) this.run(action, signal);
    }
    this.safely(() => this.hooks.onSignal(signal));
    return signal;
  }

  private matches(rule: ResponseRule, signal: Signal): boolean {
    const w = rule.when;
    if (w.type !== undefined) {
      const types = Array.isArray(w.type) ? w.type : [w.type];
      if (!types.includes(signal.type)) return false;
    }
    if (w.code !== undefined) {
      if (typeof w.code === 'string' ? w.code !== signal.code : !w.code.test(signal.code)) return false;
    }
    if (w.minSeverity !== undefined && !severityAtLeast(signal.severity, w.minSeverity)) return false;
    if (w.minScore !== undefined && this.score < w.minScore) return false;
    return true;
  }

  private run(action: Action, signal: Signal): void {
    const api = this.hooks.api;
    this.safely(() => {
      if (typeof action === 'function') return action(signal, api);
      switch (action) {
        case 'fingerprint':
          return this.hooks.onFingerprint(api.fingerprint());
        case 'obfuscate':
          return api.obfuscate();
        case 'decoy':
          return api.decoy();
        case 'lockdown':
          return api.lockdown();
      }
    });
  }

  /** A failing response or callback must never take the host page down with it. */
  private safely(fn: () => void): void {
    try {
      fn();
    } catch (error) {
      if (typeof console !== 'undefined') console.warn('[ShadowGuardian] response action failed', error);
    }
  }
}

