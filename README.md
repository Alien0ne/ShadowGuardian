# ShadowGuardian

A content protection SDK for web platforms that serve paid content (online courses, ebooks, premium docs).

It detects silent content extraction, the kind that makes no network request and trips no copy handler, and makes every copy traceable to the account it was served to.

```ts
import { protect } from 'shadowguardian';

protect({
  content: '#lesson',
  user: { id: 'acct_81f3', label: 'jane@example.com' },
  report: { endpoint: '/api/shadowguardian' },
});
```

## The problem

Paid-content sites protect against the obvious ways of copying: bot managers, print handlers, copy warnings, domain locks, watermark overlays. None of that fires when someone connects to a Chrome window where the customer is already logged in, reads `innerHTML` over the DevTools Protocol, and converts the HTML to Markdown locally. No request, no event, no log line.

ShadowGuardian watches the read itself.

## How it works

Three layers, each independent of the others:

1. **Attribution.** Zero-width watermarks, honeypot sentences, visible labels. Always on, needs no detection. Whatever copies the content copies the marks.
2. **Detection.** DOM read instrumentation, CDP side-channel probes, headless and automation scoring, interaction monitoring, environment checks.
3. **Response.** Signals feed a threat score and rule engine. Default is report only. Opt-in: poison reads with decoy content, obfuscate, or lockdown.

## Tested against real stealth tools

| Tool | Engine | Detected | Poisoned | Attributed |
|------|--------|----------|----------|------------|
| [undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) | Chromium (Selenium) | 12/15 (80%) | 12/15 (80%) | 14/15 (93%) |
| [puppeteer-extra-plugin-stealth](https://github.com/berstend/puppeteer-extra) | Chromium (main world) | 7/9 (78%) | 7/8 (88%) | 8/8 (100%) |
| [nodriver](https://github.com/ultrafunkamsterdam/nodriver) | Chromium (raw CDP) | 4/6 (67%) | 4/6 (67%) | 6/6 (100%) |
| [CloakBrowser](https://github.com/CloakHQ/CloakBrowser)\* | Chromium (Playwright wrapper) | 5/12 (42%) | 10/12 (83%) | 12/12 (100%) |
| [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) | Chromium (isolated world) | 3/12 (25%) | 10/12 (83%) | 12/12 (100%) |
| [Camoufox](https://github.com/daijro/camoufox) | Firefox (Xray sandbox) | 3/15 (20%) | 14/15 (93%) | 14/15 (93%) |

\*CloakBrowser was tested with system Chromium, not the patched binary (requires a license key). Results with the real binary may differ.

Detected = a signal fired. Poisoned = attacker got scrambled decoy content. Attributed = extracted content carries watermarks traceable to the account.

Test scripts for each tool are in `test/e2e/`.

## Features

| Layer | Modules |
|-------|---------|
| Detectors | `domRead` (all DOM accessors, caller classification), `cdp` (Runtime domain, debugger timing, console side-channel, Error.stack fingerprinting), `headless` (webdriver, UA, framework globals, WebGL), `resources` (re-fetch, canvas readback), `interaction` (print, save, copy, screenshot), `environment` (framing, foreign host, service workers, Electron/WebView) |
| Defences | `textWatermark` (zero-width account encoding), `honeypots` (invisible decoy sentences), `watermark` (visible tiled label), `cloak` (Shadow DOM decoy with homoglyph marks, see [cloaking docs](docs/cloaking.md)) |
| Responses | report, fingerprint, obfuscate, decoy, lockdown, custom callback |

## Installation

```bash
npm install github:Alien0ne/ShadowGuardian
```

Or build the drop-in script:

```bash
git clone https://github.com/Alien0ne/ShadowGuardian && cd ShadowGuardian
npm install && npm run build      # dist/shadowguardian.global.js
```

```html
<script src="/js/shadowguardian.global.js"></script>
<script>
  ShadowGuardian.protect({ content: '#lesson', user: { id: 'acct_81f3' } });
</script>
```

ESM, CommonJS and type declarations. No runtime dependencies.

## Quick start

```ts
import { protect, responsePresets } from 'shadowguardian';

const guardian = protect({
  content: '#lesson',
  user: { id: 'acct_81f3', label: 'jane@example.com' },
  detectors: { domRead: { response: 'poison' } },
  defenses: { cloak: { reorder: true } },
  response: { rules: responsePresets.deter },
  report: { endpoint: '/api/shadowguardian' },
});
```

Full configuration guide: [docs/usage.md](docs/usage.md)

## Documentation

- [Usage and configuration](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Cloaking](docs/cloaking.md)
- [Limitations and accessibility](docs/limitations.md)

## Development

```bash
npm install
npm test            # unit tests (vitest + jsdom)
npm run build       # dist/: ESM, CJS, IIFE, type declarations
npm run test:e2e    # real Chromium over CDP (19 checks)
```

## License

[Apache 2.0](LICENSE)
