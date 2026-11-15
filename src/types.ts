/**
 * Public types for ShadowGuardian.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SignalType =
  | 'cdp'
  | 'dom-read'
  | 'resource-access'
  | 'automation'
  | 'environment'
  | 'print'
  | 'save'
  | 'copy'
  | 'capture'
  | 'honeypot'
  | 'tamper';

/** A single observation made by a detector or a defence. */
export interface Signal {
  /** Unique id for this emission. */
  id: string;
  type: SignalType;
  /** Stable machine-readable code, for example `dom-read.detached`. */
  code: string;
  severity: Severity;
  /** How sure the detector is, from 0 to 1. */
  confidence: number;
  message: string;
  details: Record<string, unknown>;
  /** Milliseconds since the epoch. */
  timestamp: number;
  /** How many identical signals were suppressed by the cooldown since the last emission. */
  repeats: number;
}

export type SignalInput = Pick<Signal, 'type' | 'code' | 'severity' | 'message'> & {
  confidence?: number;
  details?: Record<string, unknown>;
  /** Fine-grained dedup key for the cooldown filter. When set, only signals with the same key are suppressed. Defaults to `code`. */
  dedupKey?: string;
};

export interface UserIdentity {
  /**
   * Opaque account identifier. This is what gets embedded in invisible watermarks and honeypots,
   * so prefer an internal id over an email address.
   */
  id: string;
  /** Human-readable text for the visible watermark. Defaults to `id`. */
  label?: string;
}

/** Where a call into an instrumented API came from. */
export type CallerKind =
  /** A script with a URL: the page's own code. */
  | 'page'
  /** Code with no script URL: a DevTools console, CDP `Runtime.evaluate`, a bookmarklet. */
  | 'detached'
  /** A known automation framework's evaluation wrapper. */
  | 'automation'
  /** A browser extension or userscript running in the page's main world. */
  | 'extension'
  /** The stack could not be read or was empty. Treated as trusted. */
  | 'unknown';

export interface CallerOrigin {
  kind: CallerKind;
  /** Caller frames, innermost first, with ShadowGuardian's own frames removed. */
  frames: string[];
}

/* ------------------------------------------------------------------ */
/* Detector options                                                    */
/* ------------------------------------------------------------------ */

export interface DomReadOptions {
  /**
   * What an untrusted caller receives.
   * - `observe`: the real content. Only a signal is raised.
   * - `poison`: scrambled decoy content. The real DOM is untouched.
   * - `block`: an empty result.
   * @default 'observe'
   */
  response?: 'observe' | 'poison' | 'block';
  /**
   * `subtree` instruments reads of the protected elements, their ancestors and their descendants.
   * `root` skips descendants, which is cheaper on pages that read a lot of small nodes.
   * @default 'subtree'
   */
  scope?: 'root' | 'subtree';
  /** Caller kinds treated as untrusted. @default ['detached', 'automation'] */
  untrusted?: CallerKind[];
  /** Return true to trust a caller regardless of its classification. */
  trustCaller?: (origin: CallerOrigin) => boolean;
  /** Produces decoy text for `poison`. Receives one text node's content at a time. */
  decoy?: (text: string) => string;
  /** Also instrument same-origin iframes reached through `contentWindow` / `contentDocument`. @default true */
  instrumentFrames?: boolean;
  /** How often to verify the hooks are still installed, in ms. 0 disables. @default 5000 */
  integrityIntervalMs?: number;
  /**
   * Report blank iframes that are inserted and removed by code outside the page's JavaScript world. An isolated
   * world (Playwright and Patchright evaluation, an extension content script) does this to borrow unpatched DOM
   * accessors, and the insertion is visible to the page even though the code is not. @default true
   */
  foreignFrames?: boolean;
}

export interface CdpOptions {
  /** How often to re-run the probes, in ms. 0 runs them once. @default 3000 */
  intervalMs?: number;
  /** Probe for console argument serialisation, a side effect of an enabled `Runtime` domain. @default true */
  serializationProbe?: boolean;
  /**
   * Time a `debugger` statement. Pauses the page when DevTools is open, which is intrusive for
   * developers and customers alike. @default false
   */
  debuggerProbe?: boolean;
}

export interface HeadlessOptions {
  /** Re-scan for automation globals at this interval, in ms. 0 scans once. @default 5000 */
  intervalMs?: number;
}

export interface ResourceOptions {
  /** Extra URL patterns to treat as protected, beyond media referenced inside the protected content. */
  patterns?: Array<string | RegExp>;
  /** Instrument `fetch` and `XMLHttpRequest`. @default true */
  network?: boolean;
  /** Instrument canvas readback of protected images. @default true */
  canvas?: boolean;
  /** Watch Resource Timing for scripted re-fetches of protected media. @default true */
  timing?: boolean;
}

export type CopyPolicy = 'allow' | 'annotate' | 'truncate' | 'block';

export interface InteractionOptions {
  /** Hide protected content in print output with a print stylesheet. @default true */
  blockPrint?: boolean;
  /** Text shown in place of the content when printing. */
  printNotice?: string;
  /** Call `preventDefault()` on Ctrl/Cmd+S. @default true */
  blockSave?: boolean;
  /**
   * Share of the protected text, from 0 to 1, that a single copy may cover before it counts as a bulk copy.
   * @default 0.6
   */
  bulkCopyRatio?: number;
  /**
   * Total share of the protected text that may be copied across many small copies before it counts as bulk
   * copying. Catches section-by-section copying. @default 1.5
   */
  cumulativeCopyRatio?: number;
  /** What happens to a bulk copy. @default 'annotate' */
  onBulkCopy?: CopyPolicy;
  /** Characters kept by the `truncate` policy. @default 500 */
  truncateTo?: number;
  /** Appended to the clipboard by `annotate` and `truncate`. */
  attribution?: string;
  /** Stop protected images from being dragged out of the page. @default true */
  blockImageDrag?: boolean;
  /** Suppress the context menu on protected content. @default false */
  blockContextMenu?: boolean;
}

export interface EnvironmentOptions {
  /**
   * Hostnames the content may be served from. `example.com` also matches its subdomains.
   * When omitted the host check is skipped.
   */
  allowedHosts?: string[];
  /** Allow the page to be shown inside a frame. @default false */
  allowFraming?: boolean;
  /**
   * Service worker script URLs the vendor actually deploys. Any other registration raises a signal.
   * Pass `[]` if the site ships no service worker. When omitted the check is skipped.
   */
  allowedServiceWorkers?: Array<string | RegExp>;
  /** Check for Electron, WebView and similar host shells. @default true */
  embeddedShell?: boolean;
  /** Report DOM artefacts injected by browser extensions (informational). @default true */
  extensionArtifacts?: boolean;
}

/* ------------------------------------------------------------------ */
/* Defence options                                                     */
/* ------------------------------------------------------------------ */

export interface WatermarkOptions {
  /** Watermark text. Defaults to the user's label or id. */
  text?: string;
  /** @default 0.08 */
  opacity?: number;
  /** @default 14 */
  fontSize?: number;
  /** Rotation in degrees. @default -28 */
  angle?: number;
  /** Distance between repetitions in px. @default 220 */
  gap?: number;
  /** Any CSS colour. @default '#808080' */
  color?: string;
  /** Add the current date to the text. @default true */
  includeDate?: boolean;
}

export interface TextWatermarkOptions {
  /** Payload to embed. Defaults to the user's id. Keep it short: every byte costs eight invisible characters. */
  payload?: string;
  /** Text nodes with fewer words than this are left alone. @default 6 */
  minWords?: number;
  /** Upper bound on embedded marks per protected element. @default 200 */
  maxMarks?: number;
  /**
   * Selector for subtrees that must not be watermarked. Code is excluded by default, because invisible
   * characters would break it when a customer copies a snippet.
   * @default 'pre, code, kbd, samp, script, style, textarea, [contenteditable]'
   */
  exclude?: string;
  /** Watermark content that is added to the page later. @default true */
  observe?: boolean;
}

export interface CloakOptions {
  /**
   * Copy the document's `<style>` and stylesheet `<link>` elements into the shadow tree so the content keeps its
   * look. Selectors are matched against a copy of the root's ancestor chain (tag, id and class only).
   * @default true
   */
  copyStyles?: boolean;
  /** Extra CSS for the shadow tree. */
  css?: string;
  /** Produces the decoy text left in the light DOM. Receives one text node's content at a time. */
  decoy?: (text: string) => string;
  /**
   * Hide the account id in the decoy's letters as well (Latin letters swapped for identical Cyrillic ones), so the
   * stolen copy stays attributable after zero-width characters are stripped. Only the decoy is changed.
   * @default true
   */
  homoglyphs?: boolean;
  /**
   * Also shuffle the word order of the real text inside the shadow tree and put it back visually with CSS `order`.
   * This defeats readers that reach into the shadow tree (CDP `DOMSnapshot`, shadow-piercing locators).
   *
   * It has a real cost: screen readers and a person's own copy and paste follow DOM order and get the shuffled
   * text, and justified text loses its justification. Leave it off unless the content is worth that.
   * @default false
   */
  reorder?: boolean;
}

export interface HoneypotOptions {
  /** Number of decoy elements per protected element. @default 3 */
  count?: number;
  /** Token embedded in the decoys. Defaults to a value derived from the user and session. */
  token?: string;
  /** Sentence builders. Each receives the token and returns decoy text. */
  templates?: Array<(token: string) => string>;
  /** A URL only a crawler would ever request. The token is added as the `t` query parameter. */
  canaryUrl?: string;
}

/* ------------------------------------------------------------------ */
/* Response options                                                    */
/* ------------------------------------------------------------------ */

export type BuiltinAction = 'fingerprint' | 'obfuscate' | 'decoy' | 'lockdown';

export interface ResponseApi {
  obfuscate(): void;
  decoy(): void;
  lockdown(): void;
  restore(): void;
  fingerprint(): Fingerprint;
  readonly score: number;
}

export type Action = BuiltinAction | ((signal: Signal, api: ResponseApi) => void);

export interface ResponseRule {
  when: {
    type?: SignalType | SignalType[];
    code?: string | RegExp;
    minSeverity?: Severity;
    /** Matches once the cumulative threat score reaches this value (0 to 100). */
    minScore?: number;
  };
  actions: Action[];
}

export interface ResponseOptions {
  /** Rules evaluated for every signal. @default responsePresets.monitor */
  rules?: ResponseRule[];
  /** Identical signal codes are suppressed for this long, in ms. @default 2000 */
  cooldownMs?: number;
  /** Message shown by `obfuscate` and `lockdown`. */
  notice?: string;
}

export interface ReportPayload {
  kind: 'signals' | 'heartbeat';
  sdk: { name: string; version: string };
  sessionId: string;
  userId: string;
  url: string;
  sentAt: number;
  score: number;
  signals: Signal[];
  fingerprint?: Fingerprint;
}

export interface ReportOptions {
  /** URL that receives JSON `ReportPayload` documents by POST. */
  endpoint?: string;
  /** Extra request headers. Setting any disables `sendBeacon` in favour of `fetch`. */
  headers?: Record<string, string>;
  /** Replace the built-in transport entirely. */
  transport?: (payload: ReportPayload) => void | Promise<void>;
  /** Batch window in ms. High and critical signals flush immediately. @default 2000 */
  flushMs?: number;
  /**
   * Send a heartbeat at this interval, in ms, so the backend can notice a page view where the SDK never ran.
   * 0 disables. @default 0
   */
  heartbeatMs?: number;
}

export interface Fingerprint {
  /** Hash of all components. */
  id: string;
  components: Record<string, unknown>;
}

/* ------------------------------------------------------------------ */
/* Top-level options                                                   */
/* ------------------------------------------------------------------ */

export type Toggle<T> = boolean | T;

export interface ShadowGuardianOptions {
  /** The premium content to protect: a selector, an element, or a list of elements. */
  content: string | Element | ArrayLike<Element>;
  user: UserIdentity;
  /** Defaults to a random id. Pass your own to correlate with server-side sessions. */
  sessionId?: string;
  detectors?: {
    domRead?: Toggle<DomReadOptions>;
    cdp?: Toggle<CdpOptions>;
    headless?: Toggle<HeadlessOptions>;
    resources?: Toggle<ResourceOptions>;
    interaction?: Toggle<InteractionOptions>;
    environment?: Toggle<EnvironmentOptions>;
  };
  defenses?: {
    watermark?: Toggle<WatermarkOptions>;
    textWatermark?: Toggle<TextWatermarkOptions>;
    honeypots?: Toggle<HoneypotOptions>;
    /**
     * Move the real content into a closed shadow tree and leave a decoy in the light DOM. Off by default, because
     * it changes what the page's own scripts and styles can reach. See `CloakOptions`.
     */
    cloak?: Toggle<CloakOptions>;
  };
  response?: ResponseOptions;
  report?: ReportOptions;
  /** Called for every signal, after the cooldown filter. */
  onSignal?: (signal: Signal) => void;
}
