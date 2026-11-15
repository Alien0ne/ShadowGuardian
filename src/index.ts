export { Guardian, protect } from './guardian';
export { responsePresets } from './response/engine';
export { collectFingerprint } from './response/fingerprint';
export type { ShieldLevel } from './response/shield';
export {
  WATERMARK_CHARS_RE,
  decodeWatermarks,
  encodeWatermark,
  stripWatermarks,
  watermarkText,
} from './defenses/text-watermark';
export { honeypotToken } from './defenses/honeypot';
export { decodeHomoglyphs, encodeHomoglyphs, stripHomoglyphs } from './defenses/homoglyph';
export { runHeadlessChecks } from './detectors/headless';
export type { HeadlessCheck } from './detectors/headless';
export { hostAllowed } from './detectors/environment';
export { classifyFrames, parseFrames } from './core/stack';
export { scrambleText } from './core/util';
export { SDK_VERSION as version } from './version';
export type * from './types';
