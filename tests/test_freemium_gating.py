# Test Freemium Gating and PRO Modal Behavior
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from playwright.sync_api import sync_playwright

def run_test():
    popup_path = os.path.abspath("popup.html")
    file_url = "file:///" + popup_path.replace("\\", "/")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        page.goto(file_url)
        page.evaluate("() => localStorage.clear()")
        page.reload()
        page.wait_for_timeout(400)

        pro_text = page.inner_text("#proTag")
        print("Pro Tag Text (Free User):", pro_text)
        assert pro_text == "ACTIVATE", f"Expected ACTIVATE, got {pro_text}"

        # 1. Click Bulk Audit as free user
        page.click("#btnBulkAudit")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("1. Bulk Audit -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 2. Click Settings as free user
        page.click("#btnOpenSettings")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("2. Settings -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 3. Click Urgency Tone as free user
        page.click("#toneUrgency")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("3. Urgency Tone -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 4. Click Soft-Sell Tone as free user
        page.click("#toneSoftSell")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("4. Soft-Sell Tone -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 5. Click Direct Tone as free user
        page.click("#toneAggressive")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("5. Direct Tone -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 6. Click Loom Tab as free user
        page.click("#tabLoom")
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        print("6. Loom Tab -> Pro Upgrade Modal display:", disp)
        assert disp == "flex", f"Expected flex, got {disp}"
        page.click("#proUpgradeClose")

        # 7. Test PDF exports 1, 2, 3 (allowed) and 4 (gated)
        for i in range(1, 4):
            page.click("#btnExportCard")
            page.wait_for_timeout(100)
            disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
            count = page.evaluate("() => localStorage.getItem('vs_lifetime_pdf_exports')")
            print(f"Export {i}: modal_disp={disp}, count in storage={count}")
            assert disp == "none", f"Export {i} should not be blocked by modal"
            assert str(count) == str(i), f"Expected count {i}, got {count}"

        # 4th export must trigger upgrade modal!
        page.click("#btnExportCard")
        page.wait_for_timeout(100)
        disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#proUpgradeModal')).display")
        count = page.evaluate("() => localStorage.getItem('vs_lifetime_pdf_exports')")
        print(f"Export 4: modal_disp={disp}, count in storage={count}")
        assert disp == "flex", f"4th export must trigger upgrade modal, got {disp}"
        page.click("#proUpgradeClose")

        # 8. Activate PRO via Demo Key
        page.click("#proTag") # Opens pro upgrade modal
        page.click("#btnProUpgradeEnterKey") # Opens activation modal
        page.fill("#licenseKeyInput", "VS-PRO-DEMO-2026")
        page.click("#btnActivateLicense")
        page.wait_for_timeout(500)

        pro_text_after = page.inner_text("#proTag")
        print("Pro Tag Text after activation:", pro_text_after)
        assert pro_text_after == "PRO", f"Expected PRO, got {pro_text_after}"
        page.click("#activationClose")

        # 9. Verify Bulk Audit now opens for PRO user
        page.click("#btnBulkAudit")
        bulk_disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#bulkAuditModal')).display")
        print("Bulk Audit display for PRO user:", bulk_disp)
        assert bulk_disp == "flex", f"Expected bulk modal flex, got {bulk_disp}"
        page.click("#bulkAuditClose")

        # 10. Verify Settings opens for PRO user
        page.click("#btnOpenSettings")
        settings_disp = page.evaluate("() => window.getComputedStyle(document.querySelector('#settingsModal')).display")
        print("Settings display for PRO user:", settings_disp)
        assert settings_disp == "flex", f"Expected settings modal flex, got {settings_disp}"
        page.click("#settingsClose")

        # 11. Verify Urgency Tone selectable for PRO user
        page.click("#toneUrgency")
        tone_active = page.evaluate("() => document.querySelector('#toneUrgency').classList.contains('active')")
        print("Urgency tone active for PRO user:", tone_active)
        assert tone_active == True

        # 12. Verify Loom Tab selectable for PRO user
        page.click("#tabLoom")
        loom_active = page.evaluate("() => document.querySelector('#tabLoom').classList.contains('active')")
        print("Loom tab active for PRO user:", loom_active)
        assert loom_active == True

        # 14. Verify deactivation resets PRO status, active tone to data-driven, and active channel to email
        page.on("dialog", lambda dialog: dialog.accept())
        page.click("#proTag") # Opens activation modal (since PRO)
        page.wait_for_timeout(200)
        page.click("#btnDeactivateKey")
        page.wait_for_timeout(300)

        pro_text_deactivated = page.inner_text("#proTag")
        print("Pro Tag Text after deactivation:", pro_text_deactivated)
        assert pro_text_deactivated == "ACTIVATE", f"Expected ACTIVATE, got {pro_text_deactivated}"

        data_driven_active = page.evaluate("() => document.querySelector('#toneDataDriven').classList.contains('active')")
        print("Data-driven tone active after deactivation:", data_driven_active)
        assert data_driven_active == True, "Data-driven tone must be active after deactivation"

        email_channel_active = page.evaluate("() => document.querySelector('#tabEmail').classList.contains('active')")
        print("Email channel active after deactivation:", email_channel_active)
        assert email_channel_active == True, "Email channel must be active after deactivation"

        browser.close()
        print("ALL FREEMIUM GATING AND DEACTIVATION TESTS PASSED!")

if __name__ == "__main__":
    run_test()
