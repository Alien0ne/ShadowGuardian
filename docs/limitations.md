# Limitations

Read these before deploying.

- **Not DRM.** Content that a browser renders can be copied by whoever controls that browser. ShadowGuardian raises the cost, catches the common tools, and makes leaks attributable. It does not make extraction impossible.
- **Page JavaScript has blind spots.** The CDP `DOM` and `Page` domains, isolated worlds (Patchright, Playwright evaluation, extension content scripts), OS-level screenshots, the accessibility tree, and process memory cannot be observed from a page. The defences provide attribution for these, not detection. The opt-in `cloak` makes light-DOM reads return a decoy, but it still does not detect them.
- **The read hooks can be evaded** by someone who knows they are there: through a reference saved before `protect()` ran, through `window[0]`-style frame access, or by reading text through an API that is not instrumented. Removal of the hooks is detected and reported. Load the SDK early.
- **A stripped watermark is gone.** A scraper that removes zero-width characters and off-screen elements defeats the invisible marks. Three independent marks exist for this reason, and detection exists alongside them.
- **CDP probes are version-dependent.** Browser vendors close these side channels over time. Treat `cdp.*` signals as supporting evidence.
- **Opening DevTools is not a crime.** A developer customer inspecting your page will raise `cdp` and possibly `dom-read` signals. The default response only reports, and the score rewards agreement between independent detectors.
- **You still need server-side controls.** Rate limits, session binding, cache headers, CSP `frame-ancestors`, and an inventory of your content APIs are outside what a browser SDK can do.

## Accessibility and privacy

- Honeypots are `aria-hidden`, off-screen, and unselectable. Screen-reader users never hear them and they do not appear in copied selections.
- Zero-width watermark characters are skipped by screen readers. Code blocks are excluded by default, so copied snippets stay valid.
- ShadowGuardian does not degrade the accessibility tree, render text to canvas, or scramble DOM order. Those techniques lock out assistive-technology users and are not offered.
- The browser fingerprint is collected only when a response rule asks for it, not on every page view. It is still personal data in most jurisdictions. Disclose it in your privacy notice.
- The visible watermark shows whatever you pass as `user.label`. The invisible marks embed `user.id`. Use an opaque id.
