/**
 * Homoglyph watermark.
 *
 * The zero-width watermark is removed by one regular expression. This one hides the payload in the letters
 * themselves: a Latin letter that has a visually identical Cyrillic twin carries one bit, `0` as the Latin letter and
 * `1` as the twin. Stripping invisible characters does not touch it, and it survives every route that copies text.
 *
 * It changes the text, so it is **not** applied to content a person reads: find-in-page, screen readers, spell
 * checkers and copied code would all see the foreign letters. ShadowGuardian applies it to decoy text only (the
 * cloak's light-DOM copy), which no person ever sees and only a scraper collects.
 *
 * Normalising the text back to Latin (a confusables fold) removes it. Nothing embedded in text survives an attacker
 * who knows the exact scheme, which is why the marks are layered.
 *
 * Pure functions with no DOM dependency.
 */

const PAIRS: Array<[string, string]> = [
  ['a', 'а'],
  ['c', 'с'],
  ['e', 'е'],
  ['i', 'і'],
  ['j', 'ј'],
  ['o', 'о'],
  ['p', 'р'],
  ['s', 'ѕ'],
  ['x', 'х'],
  ['y', 'у'],
];

const TO_TWIN = new Map(PAIRS);
const TO_LATIN = new Map(PAIRS.map(([latin, twin]) => [twin, latin] as [string, string]));

/** Frame marker. Plain Latin text is all zero bits, so it can never contain this by accident. */
const PREAMBLE = [1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1];

function utf8(text: string): number[] {
  const escaped = unescape(encodeURIComponent(text));
  return Array.from(escaped, (c) => c.charCodeAt(0));
}

function fromUtf8(bytes: number[]): string | null {
  try {
    return decodeURIComponent(escape(String.fromCharCode(...bytes)));
  } catch {
    return null;
  }
}

function checksum(bytes: number[]): number {
  let sum = 0xa7;
  for (const b of bytes) sum = ((sum << 1) ^ b ^ (sum >>> 7)) & 0xff;
  return sum;
}

function frameBits(payload: string): number[] {
  const bytes = utf8(payload).slice(0, 255);
  const body = [bytes.length, ...bytes, checksum(bytes)];
  const bits = PREAMBLE.slice();
  for (const byte of body) for (let bit = 7; bit >= 0; bit--) bits.push((byte >> bit) & 1);
  return bits;
}

/**
 * A stateful encoder, for marking a sequence of text nodes with one continuous bit stream. The frame repeats for as
 * long as there are carrier letters.
 */
export function homoglyphEncoder(payload: string): (text: string) => string {
  const bits = frameBits(payload);
  let at = 0;
  return (text) => {
    let out = '';
    for (const ch of text) {
      const twin = TO_TWIN.get(ch);
      if (twin === undefined) {
        out += ch;
        continue;
      }
      out += bits[at % bits.length] === 1 ? twin : ch;
      at++;
    }
    return out;
  };
}

/** Number of carrier letters one complete copy of the mark needs. */
export function homoglyphCapacity(payload: string): number {
  return frameBits(payload).length;
}

/** Number of carrier letters in `text`. */
export function homoglyphCarriers(text: string): number {
  let n = 0;
  for (const ch of text) if (TO_TWIN.has(ch)) n++;
  return n;
}

/** Hide `payload` in the letters of `text`. Text with too few carrier letters holds only part of a frame. */
export function encodeHomoglyphs(text: string, payload: string): string {
  return homoglyphEncoder(payload)(text);
}

/** Put the Latin letters back. */
export function stripHomoglyphs(text: string): string {
  let out = '';
  for (const ch of text) out += TO_LATIN.get(ch) ?? ch;
  return out;
}

function scan(text: string, counts: Map<string, number>): void {
  const bits: number[] = [];
  for (const ch of text) {
    if (TO_TWIN.has(ch)) bits.push(0);
    else if (TO_LATIN.has(ch)) bits.push(1);
  }
  const byteAt = (pos: number): number => {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | (bits[pos + j] as number);
    return byte;
  };
  outer: for (let i = 0; i + PREAMBLE.length + 16 <= bits.length; i++) {
    for (let j = 0; j < PREAMBLE.length; j++) if (bits[i + j] !== PREAMBLE[j]) continue outer;
    let pos = i + PREAMBLE.length;
    const length = byteAt(pos);
    pos += 8;
    if (length === 0 || pos + (length + 1) * 8 > bits.length) continue;
    const bytes: number[] = [];
    for (let k = 0; k < length; k++, pos += 8) bytes.push(byteAt(pos));
    if (checksum(bytes) !== byteAt(pos)) continue;
    const payload = fromUtf8(bytes);
    if (payload !== null) counts.set(payload, (counts.get(payload) ?? 0) + 1);
  }
}

/**
 * Find homoglyph marks in `text` and return the distinct payloads, most frequent first. Markup is tolerated: the
 * text is scanned as given and again with tags removed, since tag names would otherwise interrupt a frame.
 */
export function decodeHomoglyphs(text: string): string[] {
  const counts = new Map<string, number>();
  scan(text, counts);
  if (text.includes('<')) scan(text.replace(/<[^>]*>/g, ''), counts);
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([payload]) => payload);
}
