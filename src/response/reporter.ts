import { natives } from '../core/native';
import { severityAtLeast } from '../core/util';
import type { Fingerprint, ReportOptions, ReportPayload, Signal } from '../types';
import { SDK_NAME, SDK_VERSION } from '../version';

const MAX_QUEUE = 200;

/**
 * Sends signals to the vendor's backend.
 *
 * Signals are batched for a short window. High and critical signals are sent at once, and the queue is flushed with
 * `sendBeacon` when the page is hidden so that a signal raised just before the tab closes is not lost. An optional
 * heartbeat lets the backend notice page views where the SDK never ran: a document fetched with no heartbeat
 * following it was fetched by something that did not execute the page.
 */
export class Reporter {
  private queue: Signal[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | undefined;
  private heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  private fingerprint: Fingerprint | undefined;
  private readonly onHidden = () => {
    if (document.visibilityState === 'hidden') this.flush(true);
  };

  constructor(
    private readonly options: ReportOptions,
    private readonly identity: { sessionId: string; userId: string },
    private readonly score: () => number,
  ) {}

  get enabled(): boolean {
    return Boolean(this.options.endpoint || this.options.transport);
  }

  start(): void {
    if (!this.enabled) return;
    document.addEventListener('visibilitychange', this.onHidden);
    window.addEventListener('pagehide', this.onHidden);
    const beat = this.options.heartbeatMs ?? 0;
    if (beat > 0) {
      this.send(this.payload('heartbeat', []), false);
      this.heartbeatTimer = natives().setInterval(() => this.send(this.payload('heartbeat', []), false), beat);
    }
  }

  stop(): void {
    this.flush(true);
    document.removeEventListener('visibilitychange', this.onHidden);
    window.removeEventListener('pagehide', this.onHidden);
    if (this.heartbeatTimer !== undefined) natives().clearInterval(this.heartbeatTimer);
    if (this.flushTimer !== undefined) natives().clearTimeout(this.flushTimer);
    this.heartbeatTimer = undefined;
    this.flushTimer = undefined;
  }

  /** Attach a fingerprint to the next report. */
  setFingerprint(fingerprint: Fingerprint): void {
    this.fingerprint = fingerprint;
  }

  push(signal: Signal): void {
    if (!this.enabled) return;
    this.queue.push(signal);
    if (this.queue.length > MAX_QUEUE) this.queue.splice(0, this.queue.length - MAX_QUEUE);
    if (severityAtLeast(signal.severity, 'high')) {
      this.flush(false);
    } else if (this.flushTimer === undefined) {
      this.flushTimer = natives().setTimeout(() => this.flush(false), this.options.flushMs ?? 2000);
    }
  }

  flush(unloading: boolean): void {
    if (this.flushTimer !== undefined) natives().clearTimeout(this.flushTimer);
    this.flushTimer = undefined;
    if (this.queue.length === 0) return;
    const batch = this.queue;
    this.queue = [];
    this.send(this.payload('signals', batch), unloading);
  }

  private payload(kind: ReportPayload['kind'], signals: Signal[]): ReportPayload {
    const payload: ReportPayload = {
      kind,
      sdk: { name: SDK_NAME, version: SDK_VERSION },
      sessionId: this.identity.sessionId,
      userId: this.identity.userId,
      // Origin and path only. Query strings and fragments can carry tokens.
      url: location.origin + location.pathname,
      sentAt: Date.now(),
      score: this.score(),
      signals,
    };
    if (this.fingerprint && kind === 'signals') {
      payload.fingerprint = this.fingerprint;
      this.fingerprint = undefined;
    }
    return payload;
  }

  private send(payload: ReportPayload, unloading: boolean): void {
    const { transport, endpoint, headers } = this.options;
    const requeue = () => {
      // Keep undelivered signals for the next flush, within the queue cap.
      if (payload.kind === 'signals') this.queue = payload.signals.concat(this.queue).slice(-MAX_QUEUE);
    };
    try {
      if (transport) {
        const result = transport(payload);
        if (result && typeof result.catch === 'function') result.catch(requeue);
        return;
      }
      if (!endpoint) return;
      const body = JSON.stringify(payload);
      const N = natives();
      const hasHeaders = headers && Object.keys(headers).length > 0;
      if ((unloading || !N.fetch) && !hasHeaders && N.sendBeacon) {
        if (!N.sendBeacon(endpoint, new Blob([body], { type: 'application/json' }))) requeue();
        return;
      }
      if (!N.fetch) return;
      N.fetch(endpoint, {
        method: 'POST',
        body,
        keepalive: true,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...(headers ?? {}) },
      })
        .then((res) => {
          if (!res.ok && res.status >= 500) requeue();
        })
        .catch(requeue);
    } catch {
      requeue();
    }
  }
}
