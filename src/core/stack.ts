import type { CallerKind, CallerOrigin } from '../types';

/**
 * Every instrumented function is created through `trap()`, which gives it this name. The name is assigned from an
 * object-literal key, so it survives minification, and it lets the classifier find where ShadowGuardian's own frames
 * end and the caller's frames begin in any engine's stack format.
 */
export const TRAP_NAME = '__sgTrap__';

type AnyThis = unknown;

/** Wrap `fn` in a function whose runtime name is `TRAP_NAME`. `this` and arguments pass through. */
export function trap<A extends unknown[], R>(fn: (this: AnyThis, ...args: A) => R): (this: AnyThis, ...args: A) => R {
  const holder = {
    __sgTrap__(this: AnyThis, ...args: A): R {
      return fn.apply(this, args);
    },
  };
  return holder.__sgTrap__;
}

const AUTOMATION_RE =
  /pptr:|__puppeteer_evaluation_script__|__playwright_evaluation_script__|UtilityScript|__selenium_evaluate|__webdriver_evaluate|__driver_evaluate|__fxdriver_evaluate/;
const EXTENSION_RE = /(?:chrome|moz|safari-web|ms-browser)-extension:\/\/|user-script:|userscript\.html/i;
/** A frame that names a real script: a URL, or a filesystem path as seen under Node-based test runners. */
const SOURCE_RE = /(?:https?|file|blob|data|webpack|webpack-internal|vite|node):|(?:^|[\s(@])\/[^\s:()]+\.[cm]?[jt]sx?[:?)]/i;
/** Engine-internal frames that say nothing about who the caller is. */
const BUILTIN_RE = /\(<anonymous>\)$|\(native\)$|\[native code\]$|^at new Promise \(<anonymous>\)/;

export function parseFrames(stack: string | undefined): string[] {
  if (!stack) return [];
  const lines = stack
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
  // V8 puts the error message on the first line. Other engines start with a frame.
  if (lines.length > 0 && !/^at\s|@/.test(lines[0] as string)) lines.shift();
  return lines;
}

/** Remove ShadowGuardian's own frames: everything up to and including the outermost trap frame. */
export function callerFrames(frames: string[]): string[] {
  let last = -1;
  for (let i = 0; i < frames.length; i++) {
    if ((frames[i] as string).includes(TRAP_NAME)) last = i;
  }
  return last >= 0 ? frames.slice(last + 1) : frames;
}

/**
 * Decide who called an instrumented API from the frames of the call stack.
 *
 * The decision rests on the **entry frame**, the outermost frame of the stack. Page code is always entered from a
 * script with a URL (a script tag, a module, an event listener). Code injected through a console or a CDP
 * `Runtime.evaluate` call is entered from an anonymous script with no URL, even when it goes on to call the page's
 * own helpers, such as `jQuery('#content').html()`.
 */
export function classifyFrames(frames: string[]): CallerOrigin {
  const meaningful = frames.filter((f) => !BUILTIN_RE.test(f));
  if (meaningful.length === 0) return { kind: 'unknown', frames };
  let kind: CallerKind;
  const entry = meaningful[meaningful.length - 1] as string;
  if (meaningful.some((f) => AUTOMATION_RE.test(f))) kind = 'automation';
  else if (EXTENSION_RE.test(entry)) kind = 'extension';
  else if (SOURCE_RE.test(entry)) kind = 'page';
  else kind = 'detached';
  return { kind, frames };
}

interface StackLimitHost {
  stackTraceLimit?: number;
}

/** Capture and classify the current caller. Call this from inside a `trap()`-wrapped function. */
export function captureCaller(): CallerOrigin {
  const host = Error as unknown as StackLimitHost;
  const previous = host.stackTraceLimit;
  let stack: string | undefined;
  try {
    // The entry frame matters, so the default depth of 10 is not enough for deep call chains.
    if (typeof previous === 'number') host.stackTraceLimit = 64;
    stack = new Error().stack;
  } catch {
    stack = undefined;
  } finally {
    if (typeof previous === 'number') host.stackTraceLimit = previous;
  }
  return classifyFrames(callerFrames(parseFrames(stack)));
}
