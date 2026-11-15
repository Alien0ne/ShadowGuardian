#!/usr/bin/env python3
"""nodriver attack test against ShadowGuardian.

nodriver drives Chrome directly over CDP without any WebDriver/Selenium layer.
It patches nothing and uses no automation flags — it is a pure async CDP client.

Usage: python3 -I test/e2e/nodriver-attack.py
Env:   SG_URL (default http://127.0.0.1:4003), SG_CLOAK (off | on | reorder; unset leaves the demo default),
       SG_CHROME (default /usr/bin/chromium)
"""
import asyncio
import json
import os
import re
import site
import sys

# `python3 -I` drops the user site directory, which is where pip --break-system-packages installs to.
_user_site = site.getusersitepackages()
if _user_site not in sys.path:
    sys.path.append(_user_site)

import nodriver  # noqa: E402
import nodriver.cdp.dom as cdp_dom  # noqa: E402
import nodriver.cdp.dom_snapshot as cdp_ds  # noqa: E402

REAL_MARKER = 'With separate chaining every slot holds a small list'
BASE = os.environ.get('SG_URL', 'http://127.0.0.1:4003')
CLOAK = os.environ.get('SG_CLOAK')
PAGE_URL = f'{BASE}/examples/demo/index.html?mode=poison' + (f'&cloak={CLOAK}' if CLOAK else '')
CHROME = os.environ.get('SG_CHROME', '/usr/bin/chromium')

# The text watermark alphabet, from src/defenses/text-watermark.ts.
ZERO, ONE, START, END = '​', '‌', '⁠', '⁢'
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


def line(char='-', width=78):
    print(char * width)


def mark(value):
    return {True: 'YES', False: 'NO', None: 'n/a'}[value]


async def main():
    line('=')
    print('NODRIVER vs SHADOWGUARDIAN')
    print(f'nodriver {nodriver.__version__}, headless, {CHROME}')
    print(f'URL: {PAGE_URL}')
    line('=')

    browser = await nodriver.start(
        headless=True,
        browser_executable_path=CHROME,
        browser_args=[
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--window-size=1280,900',
        ],
    )
    try:
        tab = browser.main_tab
        await run(browser, tab)
    finally:
        try:
            browser.stop()
        except Exception:
            pass


async def run(browser, tab):
    # Navigate
    await tab.get(PAGE_URL)
    await tab.sleep(1)

    # Wait for ShadowGuardian init
    active = False
    for _ in range(60):
        try:
            result = await tab.evaluate('typeof window.__sg !== "undefined"', return_by_value=True)
            if result is True or result == 'true':
                active = True
                break
        except Exception:
            pass
        await tab.sleep(0.25)

    print(f'ShadowGuardian active: {active}')
    if not active:
        try:
            preview = await tab.evaluate('document.body.innerHTML.slice(0, 300)', return_by_value=True)
            print(f'DOM preview: {preview}')
        except Exception as e:
            print(f'DOM preview error: {e}')
        print('FATAL: ShadowGuardian not initialized.')
        sys.exit(1)

    await tab.sleep(2)  # let the start-up detectors finish

    async def signals():
        raw = await tab.evaluate('JSON.stringify(window.__sg.signals)', return_by_value=True)
        return json.loads(raw)

    async def score():
        return await tab.evaluate('window.__sg.score', return_by_value=True)

    webdriver_val = await tab.evaluate('navigator.webdriver', return_by_value=True)
    ua = await tab.evaluate('navigator.userAgent', return_by_value=True)
    print(f'navigator.webdriver: {webdriver_val}')
    print(f'userAgent: {ua}')
    baseline = await signals()
    baseline_score = await score()
    print(f'Baseline: {len(baseline)} signals, score {baseline_score}')
    for s in baseline:
        print(f"  [{s.get('severity')}] {s.get('code')}: {s.get('message')}")

    async def attack(name, fn):
        line()
        print(f'ATTACK: {name}')
        before = len(await signals())
        try:
            text = await fn()
            error = None
        except Exception as exc:
            text, error = None, f'{type(exc).__name__}: {str(exc).splitlines()[0][:160]}'
        await tab.sleep(0.4)
        new = (await signals())[before:]
        if error or text is None:
            print(f'  ERROR / no data: {error}')
            results.append(dict(name=name, detected=bool(new), poisoned=None, attributed=None,
                                codes=sorted({s['code'] for s in new}), length=0))
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

    # a. JS evaluate innerHTML
    async def attack_a():
        return await tab.evaluate("document.querySelector('#lesson').innerHTML", return_by_value=True)
    await attack('a. JS evaluate innerHTML', attack_a)

    # b. JS evaluate innerText
    async def attack_b():
        return await tab.evaluate("document.querySelector('#lesson').innerText", return_by_value=True)
    await attack('b. JS evaluate innerText', attack_b)

    # c. JS evaluate textContent
    async def attack_c():
        return await tab.evaluate("document.querySelector('#lesson').textContent", return_by_value=True)
    await attack('c. JS evaluate textContent', attack_c)

    # d. Full page HTML via JS
    async def attack_d():
        return await tab.evaluate('document.documentElement.outerHTML', return_by_value=True)
    await attack('d. Full page HTML via JS', attack_d)

    # e. Raw CDP: DOM.getDocument + DOM.querySelector + DOM.getOuterHTML
    async def attack_e():
        doc = await tab.send(cdp_dom.get_document(depth=-1, pierce=True))
        lesson_id = await tab.send(cdp_dom.query_selector(node_id=doc.node_id, selector='#lesson'))
        html = await tab.send(cdp_dom.get_outer_html(node_id=lesson_id))
        return html
    await attack('e. CDP DOM.getDocument + querySelector + getOuterHTML', attack_e)

    # f. Raw CDP: DOMSnapshot.captureSnapshot
    async def attack_f():
        snapshots, strings = await tab.send(cdp_ds.capture_snapshot(computed_styles=[]))
        return ' '.join(strings)
    await attack('f. CDP DOMSnapshot.captureSnapshot strings', attack_f)

    # Final report
    final = await signals()
    final_score = await score()
    line('=')
    print('FINAL REPORT: NODRIVER vs SHADOWGUARDIAN')
    line('=')
    print(f'Total signals raised: {len(final)}')
    print(f'Final threat score:   {final_score}')
    print(f"All signal codes:     {', '.join(sorted({s['code'] for s in final}))}")

    total = len(results)
    print()
    print(f"{'Attack':<58} {'Detect':<7} {'Poison':<7} {'Attrib':<7}")
    line()
    for r in results:
        print(f"{r['name'][:57]:<58} {mark(r['detected']):<7} {mark(r['poisoned']):<7} {mark(r['attributed']):<7}")
    line()
    print(f"{'TOTAL':<58} "
          f"{sum(1 for r in results if r['detected'])}/{total:<5} "
          f"{sum(1 for r in results if r['poisoned'])}/{total:<5} "
          f"{sum(1 for r in results if r['attributed'])}/{total:<5}")
    print('Detect = a dom-read signal fired for this attack; Poison = real marker absent from what was extracted;')
    print('Attrib = a valid zero-width watermark decoded from what was extracted.')
    print()
    print('Signal codes per attack:')
    for r in results:
        print(f"  {r['name']}: {', '.join(r['codes']) or '(none)'}")


if __name__ == '__main__':
    asyncio.run(main())
