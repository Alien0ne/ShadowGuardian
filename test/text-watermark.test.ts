import { describe, expect, it } from 'vitest';
import { decodeWatermarks, encodeWatermark, stripWatermarks, watermarkText } from '../src/defenses/text-watermark';
import { scrambleText } from '../src/core/util';

describe('text watermark', () => {
  it('round-trips a payload, including non-ASCII', () => {
    for (const payload of ['acct_81f3', 'ユーザー42', 'a']) {
      expect(decodeWatermarks(`before ${encodeWatermark(payload)}after`)).toEqual([payload]);
    }
  });

  it('is invisible: stripping the marks gives the original text back', () => {
    const text = 'The quick brown fox jumps over the lazy dog. '.repeat(20);
    const marked = watermarkText(text, 'acct_1', 10);
    expect(marked).not.toBe(text);
    expect(stripWatermarks(marked)).toBe(text);
    expect(decodeWatermarks(marked)).toEqual(['acct_1']);
  });

  it('marks short text too', () => {
    expect(decodeWatermarks(watermarkText('two words', 'x'))).toEqual(['x']);
    expect(decodeWatermarks(watermarkText('word', 'x'))).toEqual(['x']);
  });

  it('rejects corrupted marks', () => {
    const mark = encodeWatermark('acct_1');
    const corrupted = mark.slice(0, 10) + (mark[10] === '​' ? '‌' : '​') + mark.slice(11);
    expect(decodeWatermarks(corrupted)).toEqual([]);
  });

  it('survives word scrambling, as used for decoy content', () => {
    const marked = watermarkText('alpha beta gamma delta epsilon zeta eta theta', 'acct_9', 3);
    expect(decodeWatermarks(scrambleText(marked))).toEqual(['acct_9']);
  });

  it('orders payloads by frequency when several accounts appear', () => {
    const text = watermarkText('a b c d e f g h i j', 'major', 2) + ' ' + watermarkText('k l', 'minor');
    expect(decodeWatermarks(text)).toEqual(['major', 'minor']);
  });
});

describe('scrambleText', () => {
  it('keeps the words and whitespace layout and changes the order', () => {
    const text = 'one two three four five six seven eight nine ten';
    const out = scrambleText(text);
    expect(out).not.toBe(text);
    expect(out.split(' ').sort()).toEqual(text.split(' ').sort());
    expect(scrambleText(text)).toBe(out);
  });
});
