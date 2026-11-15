# Architecture

ShadowGuardian is a single browser bundle with no runtime dependencies. This document explains how the parts fit together and why they are built the way they are.

## Design principles

1. **Watch the read, not the network.** Silent extraction makes no request and raises no user-gesture event. The one thing it must do is read the content, so that is what gets instrumented.
2. **Assume detection fails.** Several extraction routes cannot be seen from a page at all. The defences mark the content at page load, before any detection runs, so a copy taken by an undetectable route is still attributable.
3. **Signals, not verdicts.** Every detector has innocent explanations. Detectors emit scored signals, and a rule engine decides what to do. Nothing destructive happens by default.
4. **Never harm the legitimate reader.** No accessibility degradation, no content rendered to canvas, no broken copy-paste of code snippets, and a failing module never takes the host page down.
5. **Leave no mess.** `stop()` restores every patched API and removes every injected node.

## Components

```
protect(options)
   |
   v
Guardian ----------------------------------------------------------------+
   |  owns                                                               |
   +-- GuardContext      roots, user, session, emit(), internal()        |
   |                                                                     |
   +-- modules (GuardModule: start / stop)                               |
   |     defences:  Honeypots, TextWatermark, VisibleWatermark           |
   |     detectors: Environment, Headless, Cdp, Interaction,             |
   |                Resources, DomRead                                   |
   |           | ctx.emit(SignalInput)                                   |
   |           v                                                         |
   +-- ResponseEngine    cooldown -> Signal -> score -> rules -> actions |
   |           |                         |                               |
   |           v                         v                               |
   +-- Reporter (batch, beacon,     ContentShield                        |
   |             heartbeat)         (obfuscate / decoy / lockdown)       |
   +---------------------------------------------------------------------+
```

### GuardContext (`src/core/context.ts`)

Shared state for one instance.

- `roots`: the protected elements.
- `relation(node)`: returns `covers` when reading `node` would return a whole protected element (it is one, or an ancestor like `<body>`), `inside` when `node` is part of one, otherwise `null`.
- `internal(fn)`: runs ShadowGuardian's own DOM work with a re-entrancy flag set so its reads pass straight through the instrumentation.
- `ownNodes`: elements ShadowGuardian added, so modules can tell them from content.
- `suspended`: set while the content is swapped out, so DOM-watching modules stand down.

### Native references (`src/core/native.ts`)

Original accessors and functions are captured once, before anything is patched. All internal work goes through them. This keeps ShadowGuardian from tripping its own detectors and from breaking if another script patches the same APIs later.

### Stack classification (`src/core/stack.ts`)

This is the core of read detection. Every instrumented function is created by `trap()`, which gives it a fixed runtime name that survives minification. When a trap fires on protected content, it captures a stack, drops everything up to the outermost trap frame, and classifies what remains:

| Caller kind | How it is recognised | Example |
|-------------|----------------------|---------|
| `automation` | A known evaluation wrapper anywhere in the stack | `pptr:evaluate`, `UtilityScript.evaluate` |
| `extension` | The entry frame has an extension URL scheme | `chrome-extension://…/inject.js` |
| `page` | The entry frame names a script URL | `https://site/app.js:10:5` |
| `detached` | The entry frame has no URL | `at <anonymous>:1:34` |
| `unknown` | No usable frames | Treated as trusted |

The decision rests on the entry frame (the outermost one). Code typed into a console or sent through `Runtime.evaluate` starts in an anonymous script, and stays `detached` even when it calls the page's own helpers (`jQuery('#lesson').html()`) or injects a `<script>` element. Page code, including its `eval` and its event handlers, starts in a script with a URL.

### Detectors (`src/detectors/`)

Each implements `GuardModule` and calls `ctx.emit()`.

- **DomRead** patches the read accessors and methods on the DOM prototypes. On a read of protected content by an untrusted caller, it emits a signal and, depending on `response`, returns the real value (`observe`), a scrambled clone (`poison`), or nothing (`block`). The decision is made synchronously inside the read, so the untrusted caller never sees the real value. It also instruments same-origin iframes as they are reached through `contentWindow`, because a fresh iframe is the standard source of unpatched accessors. It periodically verifies that its hooks are still installed.
- **Cdp** logs bait objects through `console.debug` and watches whether their accessors are touched (this happens when a client has enabled the `Runtime` domain). It also polls for automation bindings.
- **Headless** runs a weighted checklist and reports one score.
- **Resources** wraps `fetch`, `XMLHttpRequest.open`, and the canvas export methods, tracks which canvases have had protected images drawn to them, and watches Resource Timing for protected URLs loaded by script.
- **Interaction** installs a print stylesheet and listens for print, save, copy, and capture gestures. Copies are measured against the protected text, per copy and cumulatively.
- **Environment** checks host, framing, service worker registrations, application shells, and extension artefacts.

### Defences (`src/defenses/`)

- **TextWatermark** walks the protected text nodes and inserts one encoded mark per paragraph-sized node. A mark consists of a start character, the payload bytes plus a checksum byte as zero-width bits, and an end character. Code-like elements are excluded. New content is marked as it is added.
- **Honeypots** inserts decoy elements between the content's blocks. They have random class names and varied hiding styles, so there is no single selector to strip them by. Removed decoys are replaced.
- **Cloak** (opt-in) moves the real nodes of each root into a closed shadow tree and leaves a scrambled copy in the light DOM. It starts before the other defences and registers the shadow container in `GuardContext.cloaked`, so that honeypots and the text watermark mark both trees (`ctx.surfaces`) and everything that needs the real content finds it (`ctx.contentRoot`). The shadow tree holds copies of the document's stylesheets and a `display: contents` copy of the root's ancestor chain for selector matching. The decoy is slotted into a clipped, inert 1px box so that `innerText` returns it and nothing else can reach it. A second phase, `reorder`, runs after the marks are in place: each run of inline content becomes a flex line whose word spans are in shuffled DOM order with CSS `order` restoring the visual order. `ctx.withRealOrder` undoes and reapplies the shuffle around a trusted read.
- **Homoglyph mark** (`homoglyph.ts`) is a pure encoder and decoder. Ten Latin letters with identical Cyrillic twins carry one bit each. A frame is a 16-bit preamble, a length byte, the payload, and a checksum, repeated for as long as there are carrier letters. It is applied to the cloak's decoy only.
- **VisibleWatermark** appends an overlay with an SVG background inside each protected element, so an HTML dump of the element includes the label. A `MutationObserver` restores it if it is removed or restyled.

### Response (`src/response/`)

- **ResponseEngine** applies a per-code cooldown, assigns ids and timestamps, maintains the score, and evaluates the rules. Rules run before listeners, so a fingerprint collected by a rule is sent with the signal that caused it.
- **ContentShield** implements `obfuscate`, `decoy`, and `lockdown`. `decoy` and `lockdown` move the real nodes into a detached fragment. They are not serialised, so listeners and framework state survive `restore()`. While the real nodes are out of the document, every extraction route (including ones that cannot be detected) sees only the decoy.
- **Reporter** batches signals, flushes immediately on high severity, uses `sendBeacon` on page hide, and can send heartbeats.
- **collectFingerprint** gathers stable browser properties on demand.

## Lifecycle

1. `protect()` resolves the content elements, builds the context and modules, and captures native references.
2. Defences start first. They change the DOM, and detectors should see the finished page.
3. Detectors start. `DomRead` goes last so that nothing ShadowGuardian does during start-up is observed.
4. Signals flow: detector, engine, rules, then reporter and listeners.
5. `stop()` restores the content if it was swapped, stops modules in reverse order, and flushes the reporter.

## Scoring

| Severity | Points at confidence 1 |
|----------|------------------------|
| info | 2 |
| low | 8 |
| medium | 20 |
| high | 40 |
| critical | 70 |

A signal contributes `points × confidence`. For each signal code, only the strongest contribution counts. The total is capped at 100. Repetition does not raise the score. Corroboration from a different detector does.

## Signal codes

| Code | Severity | Raised by |
|------|----------|-----------|
| `dom-read.detached` | high (medium for a descendant node) | DomRead |
| `dom-read.automation` | high | DomRead |
| `dom-read.extension` | low | DomRead |
| `dom-read.foreign-frame` | high | DomRead (foreign frame detector) |
| `cdp.runtime-enabled` | medium | Cdp |
| `cdp.bindings` | high | Cdp |
| `cdp.debugger-paused` | medium | Cdp (opt-in) |
| `automation.headless` | info to high, by score | Headless |
| `resource.untrusted-fetch` | high (low for extensions) | Resources |
| `resource.scripted-refetch` | medium | Resources |
| `resource.canvas-readback` | medium or high | Resources |
| `print.attempt` | medium | Interaction |
| `save.shortcut` | medium | Interaction |
| `copy.bulk` | medium | Interaction |
| `copy.cumulative` | medium | Interaction |
| `capture.print-screen` | low | Interaction |
| `capture.display-media` | medium | Interaction |
| `environment.foreign-host` | critical | Environment |
| `environment.framed` | high | Environment |
| `environment.unexpected-service-worker` | high | Environment |
| `environment.embedded-shell` | low or medium | Environment |
| `environment.extension-artifacts` | info | Environment |
| `honeypot.triggered` | high | Honeypots |
| `tamper.dom-read-hooks` | critical | DomRead |
| `tamper.watermark` | high | VisibleWatermark |
| `tamper.honeypot` | medium | Honeypots |

## Extending

A new detector is a class with `name`, `start()`, and `stop()` that calls `ctx.emit()`. Register it in `Guardian.build()`. To feed in intelligence from elsewhere (such as a server-side velocity alert pushed to the page), call `guardian.report({ type, code, severity, message })`. It goes through the same score and rules.
