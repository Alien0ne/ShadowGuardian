import { natives } from '../core/native';
import { fnv1a } from '../core/util';
import type { Fingerprint } from '../types';

/**
 * Collect a browser fingerprint for the extractor.
 *
 * The purpose is correlation on the backend: tying an extraction signal to later sessions from the same browser,
 * and binding a session to the browser it was created in. It is collected only when a response rule asks for it,
 * not on every page view. Tell your users about it in your privacy notice.
 */
export function collectFingerprint(w: Window = window): Fingerprint {
  const nav = w.navigator as Navigator & { deviceMemory?: number; webdriver?: boolean };
  const components: Record<string, unknown> = {};
  const put = (key: string, read: () => unknown) => {
    try {
      components[key] = read();
    } catch {
      components[key] = null;
    }
  };

  put('userAgent', () => nav.userAgent);
  put('platform', () => nav.platform);
  put('languages', () => Array.from(nav.languages ?? []));
  put('timezone', () => Intl.DateTimeFormat().resolvedOptions().timeZone);
  put('timezoneOffset', () => new Date().getTimezoneOffset());
  put('screen', () => [w.screen.width, w.screen.height, w.screen.colorDepth, w.devicePixelRatio]);
  put('viewport', () => [w.innerWidth, w.innerHeight, w.outerWidth, w.outerHeight]);
  put('hardwareConcurrency', () => nav.hardwareConcurrency);
  put('deviceMemory', () => nav.deviceMemory ?? null);
  put('maxTouchPoints', () => nav.maxTouchPoints);
  put('webdriver', () => nav.webdriver === true);
  put('plugins', () => (nav.plugins ? nav.plugins.length : null));
  put('cookieEnabled', () => nav.cookieEnabled);
  put('webgl', () => webgl(w));
  put('canvas', () => canvasHash(w));

  // The viewport changes as the window is resized, so it is reported but kept out of the stable id.
  const { viewport: _viewport, ...stable } = components;
  return { id: fnv1a(JSON.stringify(stable)) + fnv1a(JSON.stringify(stable).split('').reverse().join('')), components };
}

function webgl(w: Window): unknown {
  const canvas = w.document.createElement('canvas');
  const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
  if (!gl) return null;
  const ext = gl.getExtension('WEBGL_debug_renderer_info');
  return {
    vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
    renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
  };
}

function canvasHash(w: Window): string | null {
  const canvas = w.document.createElement('canvas');
  canvas.width = 220;
  canvas.height = 40;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.textBaseline = 'top';
  ctx.font = '15px Arial';
  ctx.fillStyle = '#f60';
  ctx.fillRect(100, 1, 80, 24);
  ctx.fillStyle = '#069';
  ctx.fillText('ShadowGuardian ☃ 1.0', 2, 12);
  ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
  ctx.fillText('ShadowGuardian ☃ 1.0', 4, 14);
  const toDataURL = natives().toDataURL;
  return toDataURL ? fnv1a(toDataURL.call(canvas)) : null;
}
