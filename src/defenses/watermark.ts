import type { GuardContext, GuardModule } from '../core/context';
import { natives } from '../core/native';
import type { WatermarkOptions } from '../types';

/**
 * Visible watermark.
 *
 * A tiled, rotated, low-opacity label identifying the account, laid over the protected content. It is the defence
 * for every pixel-based route: screenshots, screen recording, OCR and vision models all capture it.
 *
 * Two things differ from a plain overlay element:
 *
 * - It lives **inside** the protected element, so a dump of that element's HTML carries the label as well.
 * - It is tamper-resistant. If it is removed, hidden or restyled it is put back and a signal is raised. Inline
 *   `!important` declarations mean a stylesheet alone cannot hide it.
 */
export class VisibleWatermark implements GuardModule {
  readonly name = 'watermark';
  private overlays = new Map<Element, HTMLElement>();
  private observers: MutationObserver[] = [];
  private restoredPosition = new Map<Element, string>();
  private css = '';

  constructor(
    private readonly ctx: GuardContext,
    private readonly options: WatermarkOptions = {},
  ) {}

  start(): void {
    this.css = this.buildCss();
    for (const root of this.ctx.roots) this.attach(root);
  }

  stop(): void {
    for (const o of this.observers) o.disconnect();
    this.observers = [];
    for (const overlay of this.overlays.values()) overlay.remove();
    this.overlays.clear();
    for (const [root, position] of this.restoredPosition) (root as HTMLElement).style.position = position;
    this.restoredPosition.clear();
  }

  /** The label text, as rendered. */
  label(): string {
    const o = this.options;
    const base = o.text ?? this.ctx.user.label ?? this.ctx.user.id;
    return o.includeDate === false ? base : `${base} · ${new Date().toISOString().slice(0, 10)}`;
  }

  private buildCss(): string {
    const o = this.options;
    const fontSize = o.fontSize ?? 14;
    const gap = o.gap ?? 220;
    const angle = o.angle ?? -28;
    const color = o.color ?? '#808080';
    const text = escapeXml(this.label());
    const svg =
      `<svg xmlns="http://www.w3.org/2000/svg" width="${gap}" height="${gap}">` +
      `<text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle" ` +
      `font-family="sans-serif" font-size="${fontSize}" fill="${escapeXml(color)}" ` +
      `transform="rotate(${angle} ${gap / 2} ${gap / 2})">${text}</text></svg>`;
    const url = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
    return [
      'position:absolute',
      'inset:0',
      'top:0',
      'left:0',
      'width:100%',
      'height:100%',
      'display:block',
      'visibility:visible',
      `opacity:${o.opacity ?? 0.08}`,
      'pointer-events:none',
      'user-select:none',
      '-webkit-user-select:none',
      'z-index:2147483646',
      'transform:none',
      'clip-path:none',
      'filter:none',
      `background-image:url("${url}")`,
      'background-repeat:repeat',
      'mix-blend-mode:normal',
    ]
      .map((d) => `${d} !important`)
      .join(';');
  }

  private attach(root: Element): void {
    this.ctx.internal(() => {
      const el = root as HTMLElement;
      if (natives().getComputedStyle(el).position === 'static') {
        this.restoredPosition.set(root, el.style.position);
        el.style.position = 'relative';
      }
      this.insert(root);
    });
    if (typeof MutationObserver !== 'function') return;
    const observer = new MutationObserver(() => this.check(root));
    observer.observe(this.ctx.contentRoot(root), { childList: true, attributes: true, attributeFilter: ['style', 'class', 'hidden'], subtree: true });
    this.observers.push(observer);
  }

  private insert(root: Element): HTMLElement {
    const overlay = root.ownerDocument.createElement('div');
    overlay.setAttribute('aria-hidden', 'true');
    overlay.setAttribute('style', this.css);
    this.ctx.ownNodes.add(overlay);
    // Under the cloak the light DOM is not what is drawn, so the overlay goes next to the real content.
    this.ctx.contentRoot(root).appendChild(overlay);
    this.overlays.set(root, overlay);
    return overlay;
  }

  private check(root: Element): void {
    if (this.ctx.suspended) return;
    const overlay = this.overlays.get(root);
    if (!overlay) return;
    const tampered = this.ctx.internal((): string | null => {
      if (overlay.parentNode !== this.ctx.contentRoot(root)) {
        overlay.remove();
        this.insert(root);
        return 'removed';
      }
      if (overlay.getAttribute('style') !== this.css || overlay.hasAttribute('hidden') || overlay.className !== '') {
        overlay.removeAttribute('hidden');
        overlay.removeAttribute('class');
        overlay.setAttribute('style', this.css);
        return 'restyled';
      }
      return null;
    });
    if (!tampered) return;
    this.ctx.emit({
      type: 'tamper',
      code: 'tamper.watermark',
      severity: 'high',
      confidence: 0.9,
      message: `The visible watermark was ${tampered} and has been restored`,
      details: { change: tampered },
    });
  }
}

function escapeXml(value: string): string {
  return value.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
