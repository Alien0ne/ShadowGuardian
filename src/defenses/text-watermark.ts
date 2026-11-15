import type { GuardContext, GuardModule } from '../core/context';
import type { TextWatermarkOptions } from '../types';

/**
 * Invisible text watermark.
 *
 * A short payload, normally the account id, is encoded as zero-width characters and woven into the text itself.
 * The characters render as nothing and are ignored by screen readers, and they travel with the text through every
 * route that copies it: `innerHTML`, a CDP DOM dump, an extension, the clipboard, a proxy capture, the
 * accessibility tree, HTML-to-Markdown conversion. A leaked copy can be decoded back to the account it was served to.
 *
 * It does not survive retyping, OCR, or a scraper that strips zero-width characters, which is why the visible
 * watermark and honeypots exist alongside it.
 *
 * `encodeWatermark`, `decodeWatermarks` and `watermarkText` are pure functions with no DOM dependency, so the same
 * mark can be applied during server-side rendering.
 */

const ZERO = '​'; // zero width space
const ONE = '‌'; // zero width non-joiner
const START = '⁠'; // word joiner
const END = '⁢'; // invisible times

const MARK_RE = /⁠([​‌]+)⁢/g;

/** Matches every character the watermark is made of. Useful for stripping marks before comparing text. */
export const WATERMARK_CHARS_RE = /[​‌⁠⁢]/g;

function utf8Encode(text: string): number[] {
  if (typeof TextEncoder === 'function') return Array.from(new TextEncoder().encode(text));
  const escaped = unescape(encodeURIComponent(text));
  return Array.from(escaped, (c) => c.charCodeAt(0));
}

function utf8Decode(bytes: number[]): string | null {
  try {
    if (typeof TextDecoder === 'function') return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    return decodeURIComponent(escape(String.fromCharCode(...bytes)));
  } catch {
    return null;
  }
}

function checksum(bytes: number[]): number {
  let sum = 0x5a;
  for (const b of bytes) sum = ((sum << 1) ^ b ^ (sum >>> 7)) & 0xff;
  return sum;
}

/** Encode `payload` as one invisible mark. */
export function encodeWatermark(payload: string): string {
  const bytes = utf8Encode(payload);
  bytes.push(checksum(bytes));
  let out = START;
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit--) out += (byte >> bit) & 1 ? ONE : ZERO;
  }
  return out + END;
}

/** Find every intact mark in `text` and return the distinct payloads, most frequent first. */
export function decodeWatermarks(text: string): string[] {
  const counts = new Map<string, number>();
  MARK_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = MARK_RE.exec(text)) !== null) {
    const bits = match[1] as string;
    if (bits.length < 16 || bits.length % 8 !== 0) continue;
    const bytes: number[] = [];
    for (let i = 0; i < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | (bits[i + j] === ONE ? 1 : 0);
      bytes.push(byte);
    }
    const check = bytes.pop() as number;
    if (checksum(bytes) !== check) continue;
    const payload = utf8Decode(bytes);
    if (payload !== null) counts.set(payload, (counts.get(payload) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([payload]) => payload);
}

/** Remove all watermark characters from `text`. */
export function stripWatermarks(text: string): string {
  return text.replace(WATERMARK_CHARS_RE, '');
}

/**
 * Insert a mark into plain text after every `everyWords` words. The mark is placed directly after whitespace, at the
 * start of a word, where a zero-width character cannot change how the line wraps.
 */
export function watermarkText(text: string, payload: string, everyWords = 40): string {
  const mark = encodeWatermark(payload);
  let words = 0;
  let inserted = false;
  const out = text.replace(/(\s+)(?=\S)/g, (ws: string) => {
    words++;
    if (words % everyWords === 0) {
      inserted = true;
      return ws + mark;
    }
    return ws;
  });
  if (inserted) return out;
  // Short text: place a single mark at the first word boundary, or at the end when there is none.
  const boundary = text.search(/\s\S/);
  return boundary >= 0 ? text.slice(0, boundary + 1) + mark + text.slice(boundary + 1) : text + mark;
}

const DEFAULT_EXCLUDE = 'pre, code, kbd, samp, script, style, textarea, [contenteditable]';

export class TextWatermark implements GuardModule {
  readonly name = 'textWatermark';
  private observer: MutationObserver | undefined;
  private marked = new WeakSet<Node>();
  private counts = new WeakMap<Element, number>();
  private readonly mark: string;

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: TextWatermarkOptions = {},
  ) {
    this.mark = encodeWatermark(options.payload ?? ctx.user.id);
  }

  start(): void {
    const surfaces = this.ctx.surfaces;
    for (const root of surfaces) this.apply(root, root);
    if (this.options.observe === false || typeof MutationObserver !== 'function') return;
    this.observer = new MutationObserver((records) => {
      if (this.ctx.suspended) return;
      for (const record of records) {
        record.addedNodes.forEach((node) => {
          const root = surfaces.find((r) => r.contains(node));
          if (root) this.apply(node, root);
        });
      }
    });
    for (const root of surfaces) this.observer.observe(root, { childList: true, subtree: true });
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = undefined;
  }

  private apply(start: Node, root: Element): void {
    const minWords = this.options.minWords ?? 6;
    const maxMarks = this.options.maxMarks ?? 200;
    const exclude = this.options.exclude ?? DEFAULT_EXCLUDE;
    this.ctx.internal(() => {
      const doc = root.ownerDocument;
      const nodes: Text[] = [];
      if (start.nodeType === 3) {
        nodes.push(start as Text);
      } else if (start.nodeType === 1) {
        const walker = doc.createTreeWalker(start, 4 /* NodeFilter.SHOW_TEXT */);
        while (walker.nextNode()) nodes.push(walker.currentNode as Text);
      }
      let count = this.counts.get(root) ?? 0;
      for (const node of nodes) {
        if (count >= maxMarks) break;
        if (this.marked.has(node)) continue;
        const parent = node.parentElement;
        if (!parent || this.isOwn(parent) || (exclude && parent.closest(exclude))) continue;
        const text = node.data;
        if (text.includes(START)) {
          this.marked.add(node);
          continue;
        }
        const boundaries: number[] = [];
        const re = /\s(?=\S)/g;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) boundaries.push(m.index + 1);
        if (boundaries.length + 1 < minWords) continue;
        const at = boundaries[Math.floor(boundaries.length / 2)] as number;
        node.data = text.slice(0, at) + this.mark + text.slice(at);
        this.marked.add(node);
        count++;
      }
      this.counts.set(root, count);
    });
  }

  private isOwn(el: Element): boolean {
    for (let cur: Element | null = el; cur; cur = cur.parentElement) {
      if (this.ctx.ownNodes.has(cur)) return true;
    }
    return false;
  }
}
