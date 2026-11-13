# VitalsSniper Challenger M3-2 Test Suite
# Headless Playwright UI & WCAG 2.2 Stress Test
# Punctuation invariant: strictly zero em-dashes and zero en-dashes (hyphens or colons only)

import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from playwright.sync_api import sync_playwright

def run_tests():
    print("=" * 60)
    print("CHALLENGER M3-2: HEADLESS PLAYWRIGHT UI & WCAG 2.2 STRESS TEST")
    print("=" * 60)

    popup_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "popup.html"))
    file_url = "file:///" + popup_path.replace("\\", "/")
    print(f"Loading popup HTML: {file_url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
        context = browser.new_context(viewport={"width": 450, "height": 800}, device_scale_factor=1)
        page = context.new_page()

        # Suppress or log errors gracefully
        page.goto(file_url, wait_until="load")
        page.wait_for_timeout(500)

        failures = []

        # -----------------------------------------------------------------
        # TEST 1: Viewport & Body Dimension / Horizontal Overflow Invariant
        # -----------------------------------------------------------------
        print("\n--- TEST 1: Body Dimensions & Horizontal Overflow Invariant ---")
        body_dims = page.evaluate("""() => {
            const b = document.body;
            return {
                clientWidth: b.clientWidth,
                scrollWidth: b.scrollWidth,
                offsetWidth: b.offsetWidth,
                hasOverflow: b.scrollWidth > b.clientWidth
            };
        }""")
        print(f"Body dimensions: clientWidth={body_dims['clientWidth']}, scrollWidth={body_dims['scrollWidth']}, offsetWidth={body_dims['offsetWidth']}")
        
        if body_dims["clientWidth"] != 440:
            msg = f"FAIL: Expected body clientWidth == 440, observed {body_dims['clientWidth']}"
            print(msg)
            failures.append(msg)
        else:
            print("PASS: body clientWidth == 440")

        if body_dims["scrollWidth"] != 440:
            msg = f"FAIL: Expected body scrollWidth == 440, observed {body_dims['scrollWidth']}"
            print(msg)
            failures.append(msg)
        else:
            print("PASS: body scrollWidth == 440")

        if body_dims["hasOverflow"]:
            msg = "FAIL: Body has horizontal overflow (scrollWidth > clientWidth)"
            print(msg)
            failures.append(msg)
        else:
            print("PASS: Zero horizontal overflow (hasOverflow == False)")

        # -----------------------------------------------------------------
        # TEST 2: #btnOpenSettings Bounding Rect Right Edge & Visibility
        # -----------------------------------------------------------------
        print("\n--- TEST 2: #btnOpenSettings Bounding Rect & Visibility ---")
        settings_btn = page.evaluate("""() => {
            const btn = document.querySelector('#btnOpenSettings');
            if (!btn) return null;
            const rect = btn.getBoundingClientRect();
            const style = window.getComputedStyle(btn);
            const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
            return {
                left: rect.left,
                right: rect.right,
                top: rect.top,
                bottom: rect.bottom,
                width: rect.width,
                height: rect.height,
                isVisible: isVisible
            };
        }""")

        if not settings_btn:
            msg = "FAIL: #btnOpenSettings not found in DOM"
            print(msg)
            failures.append(msg)
        else:
            print(f"#btnOpenSettings: left={settings_btn['left']:.1f}, right={settings_btn['right']:.1f}, width={settings_btn['width']:.1f}, height={settings_btn['height']:.1f}, isVisible={settings_btn['isVisible']}")
            if not settings_btn["isVisible"]:
                msg = "FAIL: #btnOpenSettings is not visible"
                print(msg)
                failures.append(msg)
            else:
                print("PASS: #btnOpenSettings is visible")

            if settings_btn["right"] > 440:
                msg = f"FAIL: #btnOpenSettings right edge ({settings_btn['right']}) exceeds 440px body"
                print(msg)
                failures.append(msg)
            else:
                print(f"PASS: #btnOpenSettings right edge ({settings_btn['right']:.1f}px) is <= 440px (fully within viewport)")

            if settings_btn["width"] < 24 or settings_btn["height"] < 24:
                msg = f"FAIL: #btnOpenSettings dimensions ({settings_btn['width']}x{settings_btn['height']}) below 24x24px"
                print(msg)
                failures.append(msg)
            else:
                print("PASS: #btnOpenSettings meets >= 24x24px touch target requirement")

        # -----------------------------------------------------------------
        # TEST 3: Enumerate Interactive Elements (WCAG 2.2 Criterion 2.5.8)
        # -----------------------------------------------------------------
        print("\n--- TEST 3: Interactive Touch Targets (Default View) ---")
        interactive_elements = page.evaluate("""() => {
            const selectors = 'button, a, input, select, textarea, [role="button"], .tool-btn, .pro-tag, .tab-btn, .action-btn, .close-btn, .sub-tab-btn, .tone-tab, .filter-chip, .pipeline-status-select, .activation-link, .footer-link';
            const els = Array.from(document.querySelectorAll(selectors));
            const results = [];
            for (const el of els) {
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                    continue;
                }
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) continue;

                const tag = el.tagName.toLowerCase();
                const id = el.id ? '#' + el.id : '';
                const cls = el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\\s+/).join('.') : '';
                const label = (el.innerText || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder') || '').slice(0, 30).trim();

                results.push({
                    selector: `${tag}${id}${cls}`,
                    label: label,
                    width: Math.round(rect.width * 10) / 10,
                    height: Math.round(rect.height * 10) / 10,
                    right: Math.round(rect.right * 10) / 10
                });
            }
            return results;
        }""")

        print(f"Audited {len(interactive_elements)} visible interactive elements in default view:")
        undersized_count = 0
        for idx, el in enumerate(interactive_elements, 1):
            is_valid = el["width"] >= 23.5 and el["height"] >= 23.5
            status = "PASS" if is_valid else "FAIL"
            print(f"  {idx:02d}. [{status}] {el['selector']} | \"{el['label']}\" -> {el['width']}x{el['height']}px (right: {el['right']}px)")
            if not is_valid:
                undersized_count += 1
                msg = f"FAIL: Undersized interactive element: {el['selector']} ({el['width']}x{el['height']}px)"
                failures.append(msg)

        if undersized_count == 0:
            print("PASS: 100% of visible interactive elements satisfy WCAG 2.2 >= 24x24px threshold")
        else:
            print(f"FAIL: {undersized_count} interactive elements failed size threshold")

        # -----------------------------------------------------------------
        # TEST 4: Settings Modal Form Labels & Input IDs Association
        # -----------------------------------------------------------------
        print("\n--- TEST 4: Settings Modal Form Labels & Associations ---")
        settings_audit = page.evaluate("""() => {
            const modal = document.querySelector('#settingsModal');
            if (!modal) return { found: false, labels: [] };
            const labels = Array.from(modal.querySelectorAll('label.form-label'));
            const results = labels.map(l => {
                const forAttr = l.getAttribute('for');
                const targetEl = forAttr ? document.getElementById(forAttr) : null;
                return {
                    labelText: l.innerText.trim(),
                    forAttr: forAttr,
                    targetExists: !!targetEl,
                    targetTag: targetEl ? targetEl.tagName.toLowerCase() : null,
                    targetId: targetEl ? targetEl.id : null
                };
            });
            return { found: true, labels: results };
        }""")

        if not settings_audit["found"]:
            msg = "FAIL: #settingsModal not found in DOM"
            print(msg)
            failures.append(msg)
        else:
            labels = settings_audit["labels"]
            print(f"Found {len(labels)} Settings form labels (expected: 6):")
            if len(labels) != 6:
                msg = f"FAIL: Expected exactly 6 labels in Settings modal, found {len(labels)}"
                print(msg)
                failures.append(msg)

            for idx, item in enumerate(labels, 1):
                valid = bool(item["forAttr"]) and item["targetExists"] and item["forAttr"] == item["targetId"]
                status = "PASS" if valid else "FAIL"
                print(f"  {idx}. [{status}] Label: \"{item['labelText']}\" -> for=\"{item['forAttr']}\" -> Target: <{item['targetTag']} id=\"{item['targetId']}\">")
                if not valid:
                    msg = f"FAIL: Label \"{item['labelText']}\" invalid association (for='{item['forAttr']}', targetExists={item['targetExists']})"
                    failures.append(msg)

        # -----------------------------------------------------------------
        # TEST 5: Modal Stress Test & Child Interactive Target Sizing
        # -----------------------------------------------------------------
        print("\n--- TEST 5: Modal Dialogue Stress Test & Touch Targets ---")
        modals = [
            ("#settingsModal", ".settings-box"),
            ("#competitorModal", ".competitor-box"),
            ("#pipelineModal", ".pipeline-box"),
            ("#bulkAuditModal", ".bulk-box")
        ]

        for modal_id, box_selector in modals:
            # Display modal
            page.evaluate(f"document.querySelector('{modal_id}').style.display = 'block';")
            
            modal_metrics = page.evaluate(f"""() => {{
                const modal = document.querySelector('{modal_id}');
                const box = modal ? modal.querySelector('{box_selector}') : null;
                if (!box) return null;
                const rect = box.getBoundingClientRect();
                const style = window.getComputedStyle(box);

                // Find all interactive elements inside this modal
                const els = Array.from(box.querySelectorAll('button, a, input, select, textarea, [role="button"], .close-btn, .activation-close, .btn-activate, .btn-deactivate'));
                const interactive = [];
                for (const el of els) {{
                    const s = window.getComputedStyle(el);
                    if (s.display === 'none' || s.visibility === 'hidden') continue;
                    const r = el.getBoundingClientRect();
                    if (r.width === 0 && r.height === 0) continue;
                    interactive.push({{
                        tag: el.tagName.toLowerCase(),
                        id: el.id,
                        cls: el.className,
                        width: Math.round(r.width * 10) / 10,
                        height: Math.round(r.height * 10) / 10
                    }});
                }}

                return {{
                    boxWidth: Math.round(rect.width * 10) / 10,
                    maxWidth: style.maxWidth,
                    fitsInside390: rect.width <= 390.5,
                    interactiveCount: interactive.length,
                    undersized: interactive.filter(i => i.width < 23.5 || i.height < 23.5)
                }};
            }}""")

            if not modal_metrics:
                msg = f"FAIL: Box {box_selector} not found in {modal_id}"
                print(msg)
                failures.append(msg)
            else:
                fit_status = "PASS" if modal_metrics["fitsInside390"] else "FAIL"
                print(f"Modal {modal_id} ({box_selector}): width={modal_metrics['boxWidth']}px, maxWidth={modal_metrics['maxWidth']}, fits<=390: [{fit_status}]")
                if not modal_metrics["fitsInside390"]:
                    msg = f"FAIL: Modal {modal_id} width ({modal_metrics['boxWidth']}px) exceeds 390px"
                    failures.append(msg)
                
                undersized = modal_metrics["undersized"]
                print(f"  Interactive targets inside modal: {modal_metrics['interactiveCount']} elements, undersized: {len(undersized)}")
                for u in undersized:
                    msg = f"FAIL: Undersized target in {modal_id}: <{u['tag']} id=\"{u['id']}\" class=\"{u['cls']}\"> ({u['width']}x{u['height']}px)"
                    print(f"    {msg}")
                    failures.append(msg)

            # Hide modal again
            page.evaluate(f"document.querySelector('{modal_id}').style.display = 'none';")

        # -----------------------------------------------------------------
        # TEST 6: Zero CLS Image Dimension Attributes
        # -----------------------------------------------------------------
        print("\n--- TEST 6: Zero CLS Image Dimension Attributes ---")
        img_audit = page.evaluate("""() => {
            const brandIcon = document.querySelector('.brand-icon');
            const siteFavicon = document.querySelector('.site-favicon');
            return {
                brandIcon: brandIcon ? {
                    width: brandIcon.getAttribute('width'),
                    height: brandIcon.getAttribute('height')
                } : null,
                siteFavicon: siteFavicon ? {
                    width: siteFavicon.getAttribute('width'),
                    height: siteFavicon.getAttribute('height')
                } : null
            };
        }""")
        print(f"Image attributes: brandIcon={img_audit['brandIcon']}, siteFavicon={img_audit['siteFavicon']}")
        if not img_audit["brandIcon"] or img_audit["brandIcon"]["width"] != "20" or img_audit["brandIcon"]["height"] != "20":
            msg = f"FAIL: .brand-icon missing or incorrect width/height attributes (expected 20x20, got {img_audit['brandIcon']})"
            failures.append(msg)
        else:
            print("PASS: .brand-icon has width=\"20\" height=\"20\" (0 CLS)")

        if not img_audit["siteFavicon"] or img_audit["siteFavicon"]["width"] != "14" or img_audit["siteFavicon"]["height"] != "14":
            msg = f"FAIL: .site-favicon missing or incorrect width/height attributes (expected 14x14, got {img_audit['siteFavicon']})"
            failures.append(msg)
        else:
            print("PASS: .site-favicon has width=\"14\" height=\"14\" (0 CLS)")
        # -----------------------------------------------------------------
        # TEST 7: Input Aria Labels
        # -----------------------------------------------------------------
        print("\n--- TEST 7: Input Accessibility (Aria Labels) ---")
        aria_audit = page.evaluate("""() => {
            const inputs = ['#manualTargetInput', '#competitorUrlInput', '#bulkUrlsInput'];
            return inputs.map(sel => {
                const el = document.querySelector(sel);
                return {
                    selector: sel,
                    exists: !!el,
                    ariaLabel: el ? el.getAttribute('aria-label') : null
                };
            });
        }""")
        for item in aria_audit:
            valid = item["exists"] and bool(item["ariaLabel"])
            status = "PASS" if valid else "FAIL"
            print(f"  [{status}] {item['selector']} -> aria-label: \"{item['ariaLabel']}\"")
            if not valid:
                msg = f"FAIL: Input {item['selector']} missing aria-label"
                failures.append(msg)

        # -----------------------------------------------------------------
        # TEST 8: Multi-Viewport Stress Testing
        # -----------------------------------------------------------------
        print("\n--- TEST 8: Multi-Viewport Dimension Stability ---")
        viewports = [
            {"width": 390, "height": 600, "name": "Exact 390x600"},
            {"width": 500, "height": 800, "name": "Standard Preview 500x800"},
            {"width": 1280, "height": 800, "name": "Desktop 1280x800"}
        ]
        for vp in viewports:
            vp_page = browser.new_page(viewport={"width": vp["width"], "height": vp["height"]})
            vp_page.goto(file_url, wait_until="load")
            vp_page.wait_for_timeout(200)
            dims = vp_page.evaluate("""() => {
                const b = document.body;
                return {
                    clientWidth: b.clientWidth,
                    scrollWidth: b.scrollWidth,
                    hasOverflow: b.scrollWidth > b.clientWidth
                };
            }""")
            vp_pass = dims["clientWidth"] == 440 and not dims["hasOverflow"]
            vp_status = "PASS" if vp_pass else "FAIL"
            print(f"  [{vp_status}] Viewport {vp['name']}: clientWidth={dims['clientWidth']}px, scrollWidth={dims['scrollWidth']}px, hasOverflow={dims['hasOverflow']}")
            if not vp_pass:
                failures.append(f"FAIL: Body layout unstable under viewport {vp['name']}")
            vp_page.close()

        browser.close()

    # -----------------------------------------------------------------
    # TEST 9: Zip Archive POSIX Forward Slash & Integrity Check
    # -----------------------------------------------------------------
    print("\n--- TEST 9: Zip Archive Forward-Slash & Integrity Verification ---")
    import zipfile
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    web_dir = os.path.join(workspace_root, "web") if os.path.isdir(os.path.join(workspace_root, "web")) else os.path.join(workspace_root, "vitalssniper_web")
    zip_paths = [
        os.path.join(web_dir, "private_releases", "vitalssniper_pro.zip")
    ]
    for zp in zip_paths:
        if not os.path.exists(zp):
            msg = f"FAIL: Zip archive does not exist at {zp}"
            print(msg)
            failures.append(msg)
            continue
        with zipfile.ZipFile(zp, "r") as z:
            corrupt = z.testzip()
            if corrupt is not None:
                msg = f"FAIL: Corrupted entry in {zp}: {corrupt}"
                print(msg)
                failures.append(msg)
            else:
                print(f"PASS: CRC32 integrity check passed for {os.path.basename(zp)}")

            entries = z.infolist()
            print(f"  Examining {len(entries)} entries in {zp}:")
            has_backslash = False
            for entry in entries:
                if "\\" in entry.filename:
                    has_backslash = True
                    msg = f"FAIL: Windows backslash found in zip entry: {entry.filename}"
                    print(f"    {msg}")
                    failures.append(msg)
            if not has_backslash:
                print(f"  PASS: 100% of {len(entries)} entries in {os.path.basename(zp)} use POSIX forward slashes (0 backslashes).")

    # -----------------------------------------------------------------
    # TEST 10: Zero Em-Dash & Zero En-Dash Scan Across Entire Codebase
    # -----------------------------------------------------------------
    print("\n--- TEST 10: Zero Em-Dash & Zero En-Dash Codebase Scan ---")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    excluded_dirs = {".git", "node_modules"}
    binary_exts = {".png", ".ico", ".zip", ".woff", ".woff2", ".ttf", ".eot"}
    dash_violations = []
    scanned_count = 0

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in binary_exts:
                continue
            fpath = os.path.join(root, f)
            # Skip the test runner itself from self-flagging search tokens
            if os.path.abspath(fpath) == os.path.abspath(__file__):
                continue
            scanned_count += 1
            with open(fpath, "rb") as fp:
                data = fp.read()
            if b"\xe2\x80\x94" in data:
                dash_violations.append((fpath, "UTF-8 em-dash (\\xe2\\x80\\x94)"))
            if b"\xe2\x80\x93" in data:
                dash_violations.append((fpath, "UTF-8 en-dash (\\xe2\\x80\\x93)"))
            if b"&" + b"mdash;" in data:
                dash_violations.append((fpath, "HTML entity &mdash;"))
            if b"&" + b"ndash;" in data:
                dash_violations.append((fpath, "HTML entity &ndash;"))
            if b"&" + b"#8212;" in data:
                dash_violations.append((fpath, "HTML entity &#8212;"))
            if b"&" + b"#8211;" in data:
                dash_violations.append((fpath, "HTML entity &#8211;"))

    print(f"Scanned {scanned_count} files in {base_dir}:")
    if len(dash_violations) == 0:
        print(f"PASS: Exactly 0 em-dash and 0 en-dash violations detected across {scanned_count} files.")
    else:
        for p, violation_type in dash_violations:
            msg = f"FAIL: Dash violation in {p} ({violation_type})"
            print(f"  {msg}")
            failures.append(msg)

    print("\n" + "=" * 60)
    if len(failures) == 0:
        print("VERDICT: CONFIRM (PASS) : ALL 10 TEST SUITES PASSED WITH 0 FAILURES")
        print("=" * 60)
        return True
    else:
        print(f"VERDICT: CHALLENGE (FAIL) : {len(failures)} FAILURES DETECTED:")
        for f in failures:
            print(f"  - {f}")
        print("=" * 60)
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
