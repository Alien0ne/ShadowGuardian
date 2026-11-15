# Cloaking

## Why cloaking exists

The read hooks live in the page's JavaScript world. [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) (a Playwright fork that removes the usual CDP leaks) runs `page.evaluate` and its locators in an isolated world: a separate JavaScript context that shares the DOM but has its own untouched prototypes. Extension content scripts work the same way. The CDP `DOM` domain runs no JavaScript at all. None of these call the hooks, and a read leaves nothing for the page to notice. More instrumentation cannot fix this.

What you can change is what the light DOM holds. With `defenses.cloak` on:

- The real nodes are moved into a closed shadow tree on the protected element. The browser draws that tree, so the page looks the same. Listeners and state on the nodes survive, and `stop()` moves them back.
- A scrambled copy stays in the light DOM. Every reader of the light DOM gets it, in any JavaScript world: `innerHTML`, `textContent`, `innerText`, `page.content()`, `DOM.getOuterHTML`. `element.shadowRoot` returns `null`.
- The decoy carries the zero-width watermark, the honeypots, and a homoglyph mark: the account id hidden in the letters themselves (Latin letters swapped for identical Cyrillic ones). This survives a scraper that strips zero-width characters. `decodeHomoglyphs(text)` reads it back. Only the decoy is altered this way, never text a person reads.
- The page's own read of the root (`root.innerHTML`, `root.textContent`) returns the real content.

Setting `cloak: { reorder: true }` goes further. It targets readers that walk into shadow trees through the browser (CDP `DOMSnapshot`, `DOM.getDocument` with `pierce`, Patchright's closed-shadow locators): the real text's words are shuffled in the DOM and put back in visual order with CSS `order`.

## Measured against Patchright

`test/e2e/patchright-attack.mjs` runs twelve extraction methods with Patchright 1.64 against the demo (headless Chromium, `domRead.response: 'poison'`). Select the mode with `SG_CLOAK=off|on|reorder`.

| | No cloak | `cloak` | `cloak` + `reorder` |
|---|---|---|---|
| Detected | 3 / 12 | 3 / 12 | 3 / 12 |
| Poisoned | 1 / 12 | 9 / 12 | 10 / 12 |
| Attributed | 12 / 12 | 12 / 12 | 12 / 12 |

## What cloaking costs

The demo defaults to `cloak: { reorder: true }` because the test matrix shows it has the biggest impact against isolated-world and Firefox-based tools. Check these tradeoffs against your page before turning it on.

- **Your own scripts.** `document.querySelector('#content p')` finds decoy nodes. Events from the content are retargeted to the root. Code that works on the content should hold references taken before `protect()`.
- **Styles.** `<style>` and stylesheet `<link>` elements are copied into the shadow tree and matched against a copy of the root's ancestor chain (tag, id, class). Selectors that depend on sibling position or ancestor attributes will not match. Pass extra rules with `cloak: { css }`.
- **Late content.** Nodes added to the root after `protect()` land in the light DOM and are not drawn. Changes to the moved nodes themselves keep working. Cloak content that is complete when `protect()` runs.
- **Host element.** Only elements that can host a shadow tree can be cloaked (`div`, `main`, `article`, `section`, `p`, `span`, headings, and a few more). Others are left alone with a console warning.
- **`reorder` hurts accessibility.** Screen readers and a person's own copy/paste follow DOM order and get the shuffled words. Find-in-page matches single words only. A scraper written against this exact scheme can sort the words by their computed `order`. It stops generic extraction, not a targeted tool.
- **Pixels are untouched.** Screenshots, PDF and OCR see the real page. The visible watermark handles that case.
