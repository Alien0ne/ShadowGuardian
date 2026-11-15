import type { Severity } from '../types';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityAtLeast(a: Severity, b: Severity): boolean {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b];
}

/** 32-bit FNV-1a, returned as 8 hex characters. Not cryptographic. Used for ids and fingerprints. */
export function fnv1a(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

export function randomId(bytes = 8): string {
  const buf = new Uint8Array(bytes);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  let out = '';
  for (let i = 0; i < buf.length; i++) out += (buf[i] as number).toString(16).padStart(2, '0');
  return out;
}

/** Small deterministic PRNG (mulberry32), so decoy output is stable for a given seed. */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle<T>(items: T[], rand: () => number): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = out[i] as T;
    out[i] = out[j] as T;
    out[j] = tmp;
  }
  return out;
}

/**
 * Default decoy generator. Shuffles the words of a text while keeping its whitespace layout, so the result has the
 * same shape and vocabulary as the original and is useless as content. A single long token has its characters
 * shuffled instead.
 */
export function scrambleText(text: string, seed = 0x5347): string {
  const parts = text.split(/(\s+)/);
  const wordIdx: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] as string;
    if (p !== '' && !/^\s+$/.test(p)) wordIdx.push(i);
  }
  if (wordIdx.length === 0) return text;
  const rand = seededRandom(seed ^ parseInt(fnv1a(text), 16));
  if (wordIdx.length === 1) {
    const i = wordIdx[0] as number;
    const word = parts[i] as string;
    if (word.length > 3) parts[i] = shuffle(Array.from(word), rand).join('');
    return parts.join('');
  }
  const shuffled = shuffle(
    wordIdx.map((i) => parts[i] as string),
    rand,
  );
  wordIdx.forEach((i, n) => {
    parts[i] = shuffled[n] as string;
  });
  return parts.join('');
}

export function matchesPattern(value: string, patterns: Array<string | RegExp>): boolean {
  return patterns.some((p) => (typeof p === 'string' ? value.includes(p) : p.test(value)));
}

export function resolveToggle<T extends object>(value: boolean | T | undefined, enabledByDefault: boolean): T | null {
  if (value === false) return null;
  if (value === undefined) return enabledByDefault ? ({} as T) : null;
  if (value === true) return {} as T;
  return value;
}
