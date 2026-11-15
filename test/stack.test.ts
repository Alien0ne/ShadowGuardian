import { describe, expect, it } from 'vitest';
import { callerFrames, classifyFrames, parseFrames, trap, captureCaller } from '../src/core/stack';

const classify = (stack: string) => classifyFrames(callerFrames(parseFrames(stack)));

describe('stack classification', () => {
  it('treats a script URL entry frame as page code', () => {
    const origin = classify(
      `Error\n    at HTMLDivElement.__sgTrap__ [as innerHTML] (https://site.test/sg.js:1:10)\n    at render (https://site.test/app.js:10:5)\n    at https://site.test/app.js:20:1`,
    );
    expect(origin.kind).toBe('page');
    expect(origin.frames).toHaveLength(2);
  });

  it('flags a CDP Runtime.evaluate / console read as detached', () => {
    const origin = classify(
      `Error\n    at captureCaller (https://site.test/sg.js:1:1)\n    at HTMLDivElement.__sgTrap__ [as innerHTML] (https://site.test/sg.js:1:10)\n    at <anonymous>:1:44`,
    );
    expect(origin.kind).toBe('detached');
  });

  it('flags a detached entry even when it goes through page helpers', () => {
    const origin = classify(
      `Error\n    at HTMLDivElement.__sgTrap__ [as innerHTML] (https://site.test/sg.js:1:10)\n    at jQuery.fn.html (https://site.test/jquery.js:2:100)\n    at <anonymous>:1:20`,
    );
    expect(origin.kind).toBe('detached');
  });

  it('recognises Puppeteer and Playwright evaluation wrappers', () => {
    expect(
      classify(`Error\n    at HTMLElement.__sgTrap__ (https://s.test/sg.js:1:1)\n    at pptr:evaluate;file%3A%2F%2F%2Fx.js%3A3%3A30:1:40`).kind,
    ).toBe('automation');
    expect(
      classify(
        `Error\n    at HTMLElement.__sgTrap__ (https://s.test/sg.js:1:1)\n    at eval (eval at evaluate (:234:30), <anonymous>:1:44)\n    at UtilityScript.evaluate (<anonymous>:236:17)\n    at UtilityScript.<anonymous> (<anonymous>:1:44)`,
      ).kind,
    ).toBe('automation');
  });

  it('recognises main-world extension code', () => {
    expect(
      classify(`Error\n    at HTMLElement.__sgTrap__ (https://s.test/sg.js:1:1)\n    at chrome-extension://abcdef/content.js:5:9`).kind,
    ).toBe('extension');
  });

  it('handles Firefox frames and the Firefox console', () => {
    expect(classify(`__sgTrap__@https://s.test/sg.js:1:1\nrender@https://s.test/app.js:3:4`).kind).toBe('page');
    expect(classify(`__sgTrap__@https://s.test/sg.js:1:1\n@debugger eval code:1:1`).kind).toBe('detached');
  });

  it('ignores engine-internal frames and returns unknown for an empty stack', () => {
    expect(classify(`Error\n    at HTMLElement.__sgTrap__ (https://s.test/sg.js:1:1)\n    at Array.forEach (<anonymous>)`).kind).toBe('unknown');
    expect(classify('').kind).toBe('unknown');
  });

  it('page eval still resolves to page code', () => {
    expect(
      classify(
        `Error\n    at HTMLElement.__sgTrap__ (https://s.test/sg.js:1:1)\n    at eval (eval at run (https://s.test/app.js:1:1), <anonymous>:1:1)\n    at run (https://s.test/app.js:1:1)`,
      ).kind,
    ).toBe('page');
  });

  it('trap() keeps its name and captureCaller sees the test file as page code', () => {
    const fn = trap(function () {
      return captureCaller();
    });
    expect(fn.name).toBe('__sgTrap__');
    expect(fn().kind).toBe('page');
  });
});
