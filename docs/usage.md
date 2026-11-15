# Usage

Call `protect()` once the content is in the DOM, as early as you can. The earlier it runs, the fewer scripts will have saved references to the unpatched DOM accessors.

```ts
import { protect, responsePresets } from 'shadowguardian';

const guardian = protect({
  // What to protect: a selector, an element, or a list of elements.
  content: '#lesson',

  // Who it was served to. `id` goes into the invisible watermark and the honeypots, so use an opaque
  // account id. `label` is the text of the visible watermark.
  user: { id: 'acct_81f3', label: 'jane@example.com' },

  // Your server-side session id, to correlate reports with requests.
  sessionId: window.APP_SESSION_ID,

  detectors: {
    domRead: { response: 'poison' },          // observe | poison | block
    interaction: { onBulkCopy: 'annotate' },  // allow | annotate | truncate | block
    environment: {
      allowedHosts: ['example.com'],          // also matches subdomains
      allowedServiceWorkers: [],              // the site ships none, so any worker is suspicious
    },
  },

  defenses: {
    watermark: { opacity: 0.08 },
    honeypots: { count: 4, canaryUrl: '/library/full-text' },
    cloak: true,                              // read "Cloaking" below first
  },

  response: { rules: responsePresets.deter },

  report: { endpoint: '/api/shadowguardian', heartbeatMs: 30000 },

  onSignal(signal) {
    console.debug(signal.code, signal.severity, signal.details);
  },
});

guardian.score;        // 0 to 100
guardian.signals;      // everything raised so far
guardian.restore();    // undo obfuscate / decoy / lockdown
guardian.stop();       // remove all instrumentation
```

Every module is on by default and can be switched off with `false` or configured with an options object. All options are documented in [`src/types.ts`](../src/types.ts).

## Response rules

The default preset, `monitor`, never touches the content. Run it in production first and look at what it reports before you turn anything stronger on. A false positive that blurs a paying customer's lesson is worse than a missed scrape.

```ts
import { responsePresets } from 'shadowguardian';

responsePresets.monitor; // report + fingerprint on high severity
responsePresets.deter;   // + obfuscate when the score reaches 60
responsePresets.strict;  // + decoy on automated reads, lockdown on tampering or a foreign host
```

Or write your own:

```ts
protect({
  // ...
  response: {
    rules: [
      { when: { minSeverity: 'high' }, actions: ['fingerprint'] },
      { when: { type: 'dom-read', minSeverity: 'high' }, actions: ['decoy'] },
      { when: { code: /^tamper\./ }, actions: [(signal, api) => api.lockdown()] },
      { when: { minScore: 80 }, actions: [() => fetch('/api/session/revoke', { method: 'POST' })] },
    ],
  },
});
```

The score is the sum (capped at 100) of the strongest contribution from each signal code. One detector firing repeatedly does not raise it. Two different detectors agreeing does.

## Receiving reports

Reports are JSON documents sent by POST:

```json
{
  "kind": "signals",
  "sdk": { "name": "shadowguardian", "version": "0.1.0" },
  "sessionId": "9f1c0b7a52e44d10a3b8c6e1",
  "userId": "acct_81f3",
  "url": "https://example.com/course/4",
  "sentAt": 1794758400000,
  "score": 72,
  "signals": [
    {
      "type": "dom-read",
      "code": "dom-read.detached",
      "severity": "high",
      "confidence": 0.8,
      "message": "Protected content was read through innerHTML by code with no script origin",
      "details": { "api": "innerHTML", "relation": "covers", "response": "poison", "frames": ["at <anonymous>:1:34"] }
    }
  ],
  "fingerprint": { "id": "5d0c9a1e77b3f204", "components": { "userAgent": "...", "webgl": { "renderer": "..." } } }
}
```

Reports come from the client, so treat them as evidence to weigh, not proof. Authenticate the request with your normal session cookie and trust your own session's user id over the `userId` field.

With `heartbeatMs` set, the SDK also sends `kind: "heartbeat"` documents. If a lesson was fetched but no heartbeat ever arrives, the fetcher did not run the page, which is its own signal.

## Tracing a leak

When your content shows up somewhere it shouldn't, run the leaked text through the decoder:

```ts
import { decodeWatermarks, honeypotToken } from 'shadowguardian';

// Zero-width watermarks are embedded in every paragraph. The decoder extracts the account id.
decodeWatermarks(leakedText);   // ['acct_81f3']

// Honeypot tokens are hash strings buried inside hidden decoy sentences scattered through the
// content. They are not a prefix or a header. To check whether leaked text contains a specific
// account's honeypot, derive the token and search for it:
const token = honeypotToken('acct_81f3', sessionId);
leakedText.includes(token);     // true if the decoy sentence survived the copy
```

Both helpers are pure functions and run in Node.

Three independent marks exist so that stripping one does not remove them all: zero-width watermarks sit in the text nodes, honeypot tokens sit in hidden decoy elements, and (with cloak enabled) homoglyph marks are encoded in the letters themselves. A scraper would need to strip all three to remove attribution.

## Server-side rendering

`protect()` needs a browser. The text watermark does not:

```ts
import { watermarkText } from 'shadowguardian';

const html = renderLesson(lesson, { transformText: (t) => watermarkText(t, user.id) });
```

Marking text on the server covers routes that never run your JavaScript: proxies, replayed requests, direct API access. If your content is rendered by React, Vue or another framework that owns its text nodes, prefer server-side marking and set `defenses.textWatermark: false` on the client.
