#!/usr/bin/env python3
"""undetected-chromedriver attack test against ShadowGuardian.

undetected-chromedriver patches the ChromeDriver binary (the `cdc_` variables) and launches Chrome without the
usual automation flags. It still speaks the Selenium WebDriver protocol, so every read goes through ChromeDriver.

Usage: python3 -I test/e2e/uc-attack.py
Env:   SG_URL (default http://127.0.0.1:4003), SG_CLOAK (off | on | reorder; unset leaves the demo default),
       SG_CHROME (default /usr/bin/chromium), SG_CHROMEDRIVER (a chromedriver binary; it is copied before patching)
"""
import json
import os
import re
import shutil
import site
import sys
import tempfile
import time

# `python3 -I` drops the user site directory, which is where pip --break-system-packages installs to.
_user_site = site.getusersitepackages()
if _user_site not in sys.path:
    sys.path.append(_user_site)

import undetected_chromedriver as uc  # noqa: E402
from selenium.webdriver.common.by import By  # noqa: E402

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


def launch():
    options = uc.ChromeOptions()
    options.binary_location = CHROME
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1280,900')
    kwargs = dict(options=options, browser_executable_path=CHROME, version_main=150, use_subprocess=True)
    driver_bin = os.environ.get('SG_CHROMEDRIVER')
    if driver_bin:
        # uc patches the driver binary in place, so it gets a private copy.
        tmp = tempfile.mkdtemp(prefix='uc-driver-')
        copy = os.path.join(tmp, 'chromedriver')
        shutil.copy2(driver_bin, copy)
        kwargs['driver_executable_path'] = copy
    return uc.Chrome(**kwargs)


def main():
    line('=')
    print('UNDETECTED-CHROMEDRIVER vs SHADOWGUARDIAN')
    print(f'undetected-chromedriver {uc.__version__}, headless, {CHROME}')
    print(f'URL: {PAGE_URL}')
    line('=')

    driver = launch()
    try:
        run(driver)
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def run(driver):
    caps = driver.capabilities
    print(f"Browser: {caps.get('browserName')} {caps.get('browserVersion')}, "
          f"chromedriver {caps.get('chrome', {}).get('chromedriverVersion', '?').split(' ')[0]}")

    driver.get(PAGE_URL)
    deadline = time.time() + 15
    active = False
    while time.time() < deadline:
        active = driver.execute_script('return typeof window.__sg !== "undefined"')
        if active:
            break
        time.sleep(0.25)
    print(f'ShadowGuardian active: {active}')
    if not active:
        print('DOM preview:', driver.execute_script('return document.body.innerHTML.slice(0, 300)'))
        print('FATAL: ShadowGuardian not initialized.')
        sys.exit(1)
    time.sleep(2)  # let the start-up detectors finish

    def signals():
        return json.loads(driver.execute_script('return JSON.stringify(window.__sg.signals)'))

    def score():
        return driver.execute_script('return window.__sg.score')

    print(f"navigator.webdriver: {driver.execute_script('return navigator.webdriver')}")
    print(f"userAgent: {driver.execute_script('return navigator.userAgent')}")
    baseline = signals()
    print(f'Baseline: {len(baseline)} signals, score {score()}')
    for s in baseline:
        print(f"  [{s.get('severity')}] {s.get('code')}: {s.get('message')}")

    def attack(name, fn):
        line()
        print(f'ATTACK: {name}')
        # The engine suppresses a repeated signal code for 2000 ms (cooldownMs). Waiting it out keeps one attack's
        # signal from hiding the next attack's.
        time.sleep(2.3)
        before = len(signals())
        try:
            text = fn()
            error = None
        except Exception as exc:  # the attack itself failed
            text, error = None, f'{type(exc).__name__}: {str(exc).splitlines()[0][:160]}'
        time.sleep(0.4)
        new = signals()[before:]
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

    # a-c: execute_script, which runs in the page's main world
    attack('a. execute_script innerHTML',
           lambda: driver.execute_script("return document.querySelector('#lesson').innerHTML"))
    attack('b. execute_script innerText',
           lambda: driver.execute_script("return document.querySelector('#lesson').innerText"))
    attack('c. execute_script textContent',
           lambda: driver.execute_script("return document.querySelector('#lesson').textContent"))

    # d: page_source. ChromeDriver serialises the document itself.
    attack('d. driver.page_source', lambda: driver.page_source)

    # e-f: WebDriver element commands
    attack("e. find_element.get_attribute('innerHTML')",
           lambda: driver.find_element(By.ID, 'lesson').get_attribute('innerHTML'))
    attack('f. find_element.text', lambda: driver.find_element(By.ID, 'lesson').text)
    attack("f2. find_element.get_property('textContent')",
           lambda: driver.find_element(By.ID, 'lesson').get_property('textContent'))
    attack("f3. find_element.get_dom_attribute / outerHTML",
           lambda: driver.find_element(By.ID, 'lesson').get_attribute('outerHTML'))

    # g: raw CDP through ChromeDriver
    def cdp_outer_html():
        doc = driver.execute_cdp_cmd('DOM.getDocument', {'depth': -1, 'pierce': True})

        def find(node):
            attrs = node.get('attributes') or []
            pairs = dict(zip(attrs[::2], attrs[1::2]))
            if pairs.get('id') == 'lesson':
                return node
            for key in ('children', 'shadowRoots'):
                for child in node.get(key) or []:
                    hit = find(child)
                    if hit:
                        return hit
            if node.get('contentDocument'):
                return find(node['contentDocument'])
            return None

        node = find(doc['root'])
        if not node:
            raise RuntimeError('#lesson not found in DOM.getDocument')
        return driver.execute_cdp_cmd('DOM.getOuterHTML', {'nodeId': node['nodeId']})['outerHTML']

    attack('g. CDP DOM.getDocument + DOM.getOuterHTML', cdp_outer_html)

    def cdp_shadow_dump():
        doc = driver.execute_cdp_cmd('DOM.getDocument', {'depth': -1, 'pierce': True})
        out = []

        def walk(node):
            if node.get('nodeType') == 3:
                out.append(node.get('nodeValue', ''))
            for key in ('children', 'shadowRoots'):
                for child in node.get(key) or []:
                    walk(child)

        def find(node):
            attrs = node.get('attributes') or []
            if dict(zip(attrs[::2], attrs[1::2])).get('id') == 'lesson':
                return node
            for key in ('children', 'shadowRoots'):
                for child in node.get(key) or []:
                    hit = find(child)
                    if hit:
                        return hit
            return None

        walk(find(doc['root']))
        return ' '.join(out)

    attack('g2. CDP DOM.getDocument pierce, text nodes incl. shadow roots', cdp_shadow_dump)

    attack('g3. CDP DOMSnapshot.captureSnapshot strings',
           lambda: ' '.join(driver.execute_cdp_cmd('DOMSnapshot.captureSnapshot', {'computedStyles': []})['strings']))

    attack('g4. CDP Runtime.evaluate innerHTML',
           lambda: driver.execute_cdp_cmd('Runtime.evaluate', {
               'expression': "document.querySelector('#lesson').innerHTML", 'returnByValue': True,
           })['result'].get('value'))

    # h: clean prototypes from a fresh iframe
    attack('h. iframe prototype bypass innerHTML', lambda: driver.execute_script("""
        const f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          const get = Object.getOwnPropertyDescriptor(f.contentWindow.Element.prototype, 'innerHTML').get;
          return get.call(document.querySelector('#lesson'));
        } finally { f.remove(); }
    """))
    attack('h2. iframe prototype bypass textContent', lambda: driver.execute_script("""
        const f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          const get = Object.getOwnPropertyDescriptor(f.contentWindow.Node.prototype, 'textContent').get;
          return get.call(document.querySelector('#lesson'));
        } finally { f.remove(); }
    """))
    attack('h3. iframe XMLSerializer', lambda: driver.execute_script("""
        const f = document.createElement('iframe');
        f.style.display = 'none';
        document.documentElement.appendChild(f);
        try {
          return new f.contentWindow.XMLSerializer().serializeToString(document.querySelector('#lesson'));
        } finally { f.remove(); }
    """))

    # Final report
    final = signals()
    final_score = score()
    line('=')
    print('FINAL REPORT: UNDETECTED-CHROMEDRIVER vs SHADOWGUARDIAN')
    line('=')
    print(f'Total signals raised: {len(final)}')
    print(f'Final threat score:   {final_score}')
    print(f"All signal codes:     {', '.join(sorted({s['code'] for s in final}))}")

    def mark(value):
        return {True: 'YES', False: 'NO', None: 'n/a'}[value]

    total = len(results)
    print()
    print(f"{'Attack':<62} {'Detect':<7} {'Poison':<7} {'Attrib':<7}")
    line()
    for r in results:
        print(f"{r['name'][:61]:<62} {mark(r['detected']):<7} {mark(r['poisoned']):<7} {mark(r['attributed']):<7}")
    line()
    print(f"{'TOTAL':<62} "
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
    main()
