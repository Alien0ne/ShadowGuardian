#!/usr/bin/env python3
"""Camoufox attack test against ShadowGuardian.

Camoufox is a Firefox-based anti-detect browser that patches fingerprints at the C++ level.
Unlike Chromium-based tools, it runs on Gecko, so Shadow DOM, prototype chains and isolated
worlds all behave differently.

IMPORTANT DISCOVERY: Camoufox / Playwright-on-Firefox (Juggler) runs page.evaluate() in an
isolated world (Firefox sandbox with Xray vision).  This means:
  - DOM nodes and `document` are shared, but prototype chains are separate.
  - ShadowGuardian's monkey-patches on Element.prototype.innerHTML etc. are on the PAGE
    world's prototypes, not the sandbox's.  So page.evaluate() naturally sees UNPATCHED
    native DOM accessors.
  - Page-set globals (window.__sg, ShadowGuardian) are invisible to page.evaluate() unless
    accessed through `window.wrappedJSObject`.

This is the most important anti-detect browser test: if the defenses still work (watermarks,
honeypots, Shadow DOM cloak), they work at the DOM data layer, not just the JS prototype
layer.  If they don't, we've found a real bypass.

Usage: python3 -I test/e2e/camoufox-attack.py
Env:   SG_URL (default http://127.0.0.1:4003), SG_CLOAK (off | on | reorder; unset leaves the demo default)
"""
import json
import os
import re
import site
import sys
import time

# `python3 -I` drops the user site directory, which is where pip --break-system-packages installs to.
_user_site = site.getusersitepackages()
if _user_site not in sys.path:
    sys.path.append(_user_site)

# The system Playwright (0.0.0) lacks the `contrast` parameter that Camoufox injects as a
# default for new_page()/new_context().  Patch the defaults before importing the sync API
# so the wrapper never passes unsupported kwargs.
import camoufox.utils as _cu  # noqa: E402

_cu.STOCK_MEDIA_DEFAULTS = {
    k: v for k, v in _cu.STOCK_MEDIA_DEFAULTS.items()
    if k != 'contrast'
}

from camoufox.sync_api import Camoufox  # noqa: E402

REAL_MARKER = 'With separate chaining every slot holds a small list'
BASE = os.environ.get('SG_URL', 'http://127.0.0.1:4003')
CLOAK = os.environ.get('SG_CLOAK')
PAGE_URL = f'{BASE}/examples/demo/index.html?mode=poison' + (f'&cloak={CLOAK}' if CLOAK else '')

# The text watermark alphabet, from src/defenses/text-watermark.ts.
ZERO = '​'   # zero width space
ONE = '‌'    # zero width non-joiner
START = '⁠'  # word joiner
END = '⁢'    # invisible times

WM_CHARS_RE = re.compile('[​‌⁠⁢]')
MARK_RE = re.compile('⁠([​‌]+)⁢')
ANY_ZW_RE = re.compile('[​‌‍⁠⁡⁢⁣⁤﻿]')


def checksum(data):
    total = 0x5A
    for b in data:
        total = ((total << 1) ^ b ^ (total >> 7)) & 0xFF
    return total


def decode_watermarks(text):
    """Return the distinct payloads of every valid mark in `text`."""
    found = []
    for m in MARK_RE.finditer(text or ''):
        bits = m.group(1)
        if len(bits) % 8 or len(bits) < 16:
            continue
        data = [int(''.join('1' if c == ONE else '0' for c in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
        body, check = data[:-1], data[-1]
        if checksum(body) != check:
            continue
        try:
            payload = bytes(body).decode('utf-8')
        except UnicodeDecodeError:
            continue
        if payload not in found:
            found.append(payload)
    return found


def strip_watermarks(text):
    return WM_CHARS_RE.sub('', text or '')


def has_marker(text):
    """True when the real lesson text is readable in `text`, with marks stripped and whitespace collapsed."""
    flat = re.sub(r'\s+', ' ', strip_watermarks(text))
    return REAL_MARKER in flat


results = []
SCREENSHOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'camoufox-screenshot.png')


def line(char='-', width=78):
    print(char * width)


def main():
    line('=')
    print('CAMOUFOX vs SHADOWGUARDIAN')
    print('Camoufox: Firefox-based anti-detect browser with C++ fingerprint patches')
    print(f'URL: {PAGE_URL}')
    line('=')

    with Camoufox(headless=True, i_know_what_im_doing=True) as browser:
        page = browser.new_page()
        try:
            run(page)
        finally:
            try:
                page.close()
            except Exception:
                pass


def run(page):
    ua = page.evaluate('navigator.userAgent')
    print(f'User-Agent: {ua}')

    page.goto(PAGE_URL, wait_until='load')

    # Camoufox / Juggler runs page.evaluate() in an isolated world (Firefox sandbox).
    # The page world's globals are accessible through wrappedJSObject.
    deadline = time.time() + 15
    active = False
    while time.time() < deadline:
        active = page.evaluate(
            '(function() { return typeof window.wrappedJSObject !== "undefined"'
            ' && typeof window.wrappedJSObject.__sg !== "undefined"; })()')
        if active:
            break
        time.sleep(0.25)

    print(f'ShadowGuardian active (via wrappedJSObject): {active}')

    # Also check if we're in the isolated world
    isolated = page.evaluate(
        '(function() { return typeof window.wrappedJSObject !== "undefined"'
        ' && typeof window.ShadowGuardian === "undefined"'
        ' && typeof window.wrappedJSObject.ShadowGuardian !== "undefined"; })()')
    print(f'Running in isolated world (Xray sandbox): {isolated}')

    if not active:
        preview = page.evaluate('document.body.innerHTML.slice(0, 300)')
        print(f'DOM preview: {preview}')
        print('FATAL: ShadowGuardian not initialized.')
        sys.exit(1)
    time.sleep(2)  # let the start-up detectors finish

    # All signal reads go through wrappedJSObject to reach the page world.
    def signals():
        raw = page.evaluate(
            '(function() {'
            '  var sg = window.wrappedJSObject.__sg;'
            '  var arr = [];'
            '  for (var i = 0; i < sg.signals.length; i++) {'
            '    var s = sg.signals[i];'
            '    arr.push({ severity: s.severity, code: s.code, message: s.message, type: s.type });'
            '  }'
            '  return JSON.stringify(arr);'
            '})()')
        return json.loads(raw)

    def score():
        return page.evaluate(
            '(function() { return window.wrappedJSObject.__sg.score; })()')

    webdriver = page.evaluate('navigator.webdriver')
    print(f'navigator.webdriver: {webdriver}')
    baseline = signals()
    print(f'Baseline: {len(baseline)} signals, score {score()}')
    for s in baseline:
        print(f"  [{s.get('severity')}] {s.get('code')}: {s.get('message')}")

    def attack(name, fn):
        line()
        print(f'ATTACK: {name}')
        before = len(signals())
        try:
            text = fn()
            error = None
        except Exception as exc:
            text, error = None, f'{type(exc).__name__}: {str(exc).splitlines()[0][:160]}'
        time.sleep(0.4)
        new = signals()[before:]
        if error or text is None:
            print(f'  ERROR / no data: {error}')
            results.append(dict(name=name, detected=bool(new), poisoned=None, attributed=None,
                                codes=sorted({s['code'] for s in new}), length=0))
            return
        if isinstance(text, bytes):
            # Screenshot: store it and record it
            with open(SCREENSHOT_PATH, 'wb') as f:
                f.write(text)
            codes = sorted({s['code'] for s in new})
            results.append(dict(name=name, detected=bool(new), poisoned=None, attributed=None,
                                codes=codes, length=len(text)))
            print(f'  Detection:   {"DETECTED" if new else "EVADED"}  ({len(new)} new signals)')
            print(f'  Content:     SCREENSHOT ({len(text)} bytes, saved to {SCREENSHOT_PATH})')
            print(f'  Attribution: VISUAL WATERMARK PRESENT (if configured)')
            return
        if not isinstance(text, str):
            text = json.dumps(text)
        codes = sorted({s['code'] for s in new})
        detected = any(s.get('type') == 'dom-read' for s in new)
        real = has_marker(text)
        marks = decode_watermarks(text)
        zero_width = len(ANY_ZW_RE.findall(text))
        results.append(dict(name=name, detected=detected, poisoned=not real, attributed=bool(marks),
                            codes=codes, length=len(text), other_signals=bool(new) and not detected))
        print(f"  Detection:   {'DETECTED' if detected else 'EVADED'}  "
              f"({len(new)} new signals: {', '.join(codes) or 'none'})")
        print(f"  Content:     {'POISONED (marker absent)' if not real else 'REAL CONTENT (marker present)'}")
        print(f"  Attribution: {'ATTRIBUTED ' + json.dumps(marks) if marks else 'ANONYMOUS'}"
              f"  ({zero_width} zero-width chars)")
        print(f'  Length:      {len(text)} chars')
        print(f'  Preview:     {strip_watermarks(text).strip()[:140]!r}')

    # === PRIMARY ATTACKS ===
    # These run in the isolated world (Firefox Xray sandbox), which means they use
    # native/unpatched DOM accessors.  ShadowGuardian's prototype traps are on the PAGE
    # world's prototypes, so these bypass the JS-level interception entirely.

    # a-c: page.evaluate() reads -- isolated world, native accessors
    attack('a. page.evaluate innerHTML',
           lambda: page.evaluate("document.querySelector('#lesson').innerHTML"))

    attack('b. page.evaluate innerText',
           lambda: page.evaluate("document.querySelector('#lesson').innerText"))

    attack('c. page.evaluate textContent',
           lambda: page.evaluate("document.querySelector('#lesson').textContent"))

    # d: page.content() -- full page HTML via Juggler protocol
    attack('d. page.content() full page HTML',
           lambda: page.content())

    # e-f: Playwright locator methods -- go through Juggler, likely isolated world too
    attack('e. locator inner_html()',
           lambda: page.locator('#lesson').inner_html())

    attack('f. locator text_content()',
           lambda: page.locator('#lesson').text_content())

    # g: screenshot -- binary, not interceptable from JS
    attack('g. page.screenshot()',
           lambda: page.screenshot(full_page=True))

    # === ADVANCED ATTACKS ===

    # h: iframe prototype bypass -- in the isolated world these are already unpatched,
    #    but this tests the technique explicitly
    attack('h. iframe prototype bypass innerHTML', lambda: page.evaluate("""(function() {
        var f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          var get = Object.getOwnPropertyDescriptor(f.contentWindow.Element.prototype, 'innerHTML').get;
          return get.call(document.querySelector('#lesson'));
        } finally { f.remove(); }
    })()"""))

    attack('h2. iframe prototype bypass textContent', lambda: page.evaluate("""(function() {
        var f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          var get = Object.getOwnPropertyDescriptor(f.contentWindow.Node.prototype, 'textContent').get;
          return get.call(document.querySelector('#lesson'));
        } finally { f.remove(); }
    })()"""))

    attack('h3. iframe XMLSerializer', lambda: page.evaluate("""(function() {
        var f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          return new f.contentWindow.XMLSerializer().serializeToString(document.querySelector('#lesson'));
        } finally { f.remove(); }
    })()"""))

    # i: TreeWalker text extraction
    attack('i. TreeWalker text node extraction', lambda: page.evaluate("""(function() {
        var el = document.querySelector('#lesson');
        var walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        var parts = [];
        while (walker.nextNode()) parts.push(walker.currentNode.data);
        return parts.join('');
    })()"""))

    # j: Range / Selection extraction
    attack('j. Range.toString()', lambda: page.evaluate("""(function() {
        var el = document.querySelector('#lesson');
        var range = document.createRange();
        range.selectNodeContents(el);
        return range.toString();
    })()"""))

    # k: outerHTML
    attack('k. page.evaluate outerHTML',
           lambda: page.evaluate("document.querySelector('#lesson').outerHTML"))

    # === FIREFOX-SPECIFIC: PAGE WORLD READS VIA wrappedJSObject ===
    # These execute in the page world by calling through wrappedJSObject, so
    # ShadowGuardian's prototype patches ARE active.

    attack('l. wrappedJSObject innerHTML (page world)', lambda: page.evaluate(
        """(function() {
            var el = window.wrappedJSObject.document.querySelector('#lesson');
            return el.innerHTML;
        })()"""))

    attack('l2. wrappedJSObject textContent (page world)', lambda: page.evaluate(
        """(function() {
            var el = window.wrappedJSObject.document.querySelector('#lesson');
            return el.textContent;
        })()"""))

    # Final report
    final = signals()
    final_score = score()
    line('=')
    print('FINAL REPORT: CAMOUFOX vs SHADOWGUARDIAN')
    line('=')
    print(f'Total signals raised: {len(final)}')
    print(f'Final threat score:   {final_score}')
    print(f"All signal codes:     {', '.join(sorted({s['code'] for s in final}))}")

    def mark(value):
        return {True: 'YES', False: 'NO', None: 'n/a'}[value]

    total = len(results)
    print()
    print(f"{'Attack':<55} {'Detect':<7} {'Poison':<7} {'Attrib':<7}")
    line()
    for r in results:
        print(f"{r['name'][:54]:<55} {mark(r['detected']):<7} {mark(r['poisoned']):<7} {mark(r['attributed']):<7}")
    line()
    detected_count = sum(1 for r in results if r['detected'])
    poisoned_count = sum(1 for r in results if r['poisoned'])
    attrib_count = sum(1 for r in results if r['attributed'])
    print(f"{'TOTAL':<55} "
          f"{detected_count}/{total:<5} "
          f"{poisoned_count}/{total:<5} "
          f"{attrib_count}/{total:<5}")
    print()
    print('Detect = a dom-read signal fired for this attack; Poison = real marker absent from what was extracted;')
    print('Attrib = a valid zero-width watermark decoded from what was extracted.')
    print()
    print('Signal codes per attack:')
    for r in results:
        print(f"  {r['name']}: {', '.join(r['codes']) or '(none)'}  ({r['length']} chars)")

    # Key finding
    print()
    line('=')
    print('KEY FINDING: FIREFOX ISOLATED WORLD')
    line('=')
    isolated_attacks = [r for r in results if r['name'].startswith(('a.', 'b.', 'c.', 'e.', 'f.', 'h.', 'h2.', 'h3.', 'i.', 'j.', 'k.'))]
    page_world_attacks = [r for r in results if r['name'].startswith('l')]
    if isolated_attacks and page_world_attacks:
        iso_detected = sum(1 for r in isolated_attacks if r['detected'])
        iso_poisoned = sum(1 for r in isolated_attacks if r['poisoned'])
        pw_detected = sum(1 for r in page_world_attacks if r['detected'])
        pw_poisoned = sum(1 for r in page_world_attacks if r['poisoned'])
        print(f'Isolated world attacks:  {iso_detected}/{len(isolated_attacks)} detected, {iso_poisoned}/{len(isolated_attacks)} poisoned')
        print(f'Page world attacks:      {pw_detected}/{len(page_world_attacks)} detected, {pw_poisoned}/{len(page_world_attacks)} poisoned')
        if iso_detected < pw_detected or iso_poisoned < pw_poisoned:
            print('>>> Firefox Xray sandbox bypasses prototype-level defenses.')
            print('>>> Watermarks and Shadow DOM cloak are the remaining defense layers.')


if __name__ == '__main__':
    main()
