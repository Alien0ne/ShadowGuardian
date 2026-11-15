import { describe, expect, it, vi } from 'vitest';
import { ResponseEngine, responsePresets } from '../src/response/engine';
import type { ResponseApi, ResponseOptions, SignalInput } from '../src/types';

function setup(options: ResponseOptions = {}) {
  const api: ResponseApi = {
    obfuscate: vi.fn(),
    decoy: vi.fn(),
    lockdown: vi.fn(),
    restore: vi.fn(),
    fingerprint: vi.fn(() => ({ id: 'fp', components: {} })),
    score: 0,
  };
  const onSignal = vi.fn();
  const onFingerprint = vi.fn();
  const engine = new ResponseEngine(options, { api, onSignal, onFingerprint });
  return { engine, api, onSignal, onFingerprint };
}

const sig = (over: Partial<SignalInput> = {}): SignalInput => ({
  type: 'dom-read',
  code: 'dom-read.detached',
  severity: 'high',
  message: 'm',
  ...over,
});

describe('ResponseEngine', () => {
  it('suppresses repeats inside the cooldown and counts them', () => {
    vi.useFakeTimers();
    const { engine, onSignal } = setup({ cooldownMs: 1000 });
    expect(engine.handle(sig())).not.toBeNull();
    expect(engine.handle(sig())).toBeNull();
    expect(engine.handle(sig())).toBeNull();
    vi.advanceTimersByTime(1001);
    const next = engine.handle(sig());
    expect(next?.repeats).toBe(2);
    expect(onSignal).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it('scores distinct codes, not repeats', () => {
    const { engine } = setup({ cooldownMs: 0 });
    engine.handle(sig({ severity: 'medium', confidence: 1 }));
    engine.handle(sig({ severity: 'medium', confidence: 1 }));
    expect(engine.score).toBe(20);
    engine.handle(sig({ code: 'automation.headless', type: 'automation', severity: 'high', confidence: 0.5 }));
    expect(engine.score).toBe(40);
    engine.handle(sig({ code: 'a', severity: 'critical' }));
    engine.handle(sig({ code: 'b', severity: 'critical' }));
    expect(engine.score).toBe(100);
  });

  it('monitor preset fingerprints on high severity and never touches content', () => {
    const { engine, api, onFingerprint } = setup();
    engine.handle(sig({ severity: 'low', code: 'x' }));
    expect(onFingerprint).not.toHaveBeenCalled();
    engine.handle(sig());
    expect(onFingerprint).toHaveBeenCalledTimes(1);
    expect(api.obfuscate).not.toHaveBeenCalled();
    expect(api.decoy).not.toHaveBeenCalled();
  });

  it('strict preset swaps in a decoy on an automated read and locks down on a foreign host', () => {
    const { engine, api } = setup({ rules: responsePresets.strict });
    engine.handle(sig());
    expect(api.decoy).toHaveBeenCalled();
    engine.handle(sig({ type: 'environment', code: 'environment.foreign-host', severity: 'critical' }));
    expect(api.lockdown).toHaveBeenCalled();
  });

  it('runs custom actions and survives one that throws', () => {
    const custom = vi.fn();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { engine, onSignal } = setup({
      rules: [
        { when: { code: /^dom-read\./ }, actions: [() => { throw new Error('boom'); }, custom] },
        { when: { type: 'print' }, actions: [custom] },
      ],
    });
    engine.handle(sig());
    expect(custom).toHaveBeenCalledTimes(1);
    expect(onSignal).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalled();
  });
});
