import asyncio
import re
from playwright import async_api
from playwright.async_api import expect

async def run_test():
    pw = None
    browser = None
    context = None

    try:
        # Start a Playwright session in asynchronous mode
        pw = await async_api.async_playwright().start()

        # Launch a Chromium browser in headless mode with custom arguments
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--window-size=1280,720",
                "--disable-dev-shm-usage",
                "--ipc=host",
                "--single-process"
            ],
        )

        # Create a new browser context (like an incognito window)
        context = await browser.new_context()
        # Wider default timeout to match the agent's DOM-stability budget;
        # auto-waiting Playwright APIs (expect, locator.wait_for) inherit this.
        context.set_default_timeout(15000)

        # Open a new page in the browser context
        page = await context.new_page()

        # Interact with the page elements to simulate user flow
        # -> navigate
        await page.goto("http://localhost:5173/")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Navigate to the popup page at 'http://localhost:5173/popup.html'.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Navigate to the popup page at 'http://localhost:5173/popup.html'.
        # ACTIVATE button
        elem = page.get_by_role("button", name="ACTIVATE")
        await elem.click(timeout=10000)
        
        # -> Click the 'ACTIVATE' PRO badge to open the activation UI.
        # ACTIVATE button
        elem = page.get_by_role("button", name="ACTIVATE")
        await elem.click(timeout=10000)
        
        # -> Click the 'Already have a license key? Enter key →' link to open the license key entry form.
        # Already have a license key? Enter key → button
        elem = page.get_by_role("button", name="Already have a license key?")
        await elem.click(timeout=10000)
        
        # -> Enter a malformed license into the 'License Key or WebAudits.pro API Key' field and click the 'Unlock PRO Features' button.
        # VS-PRO-XXXX-XXXX or wba_live_... text field
        elem = page.get_by_role("textbox", name="License Key or WebAudits.pro")
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("INVALID-KEY-XXXX-0000")
        
        # -> Enter a malformed license into the 'License Key or WebAudits.pro API Key' field and click the 'Unlock PRO Features' button.
        # Unlock PRO Features button
        elem = page.get_by_role("button", name="Unlock PRO Features")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> A validation error message is visible stating the license key format is invalid.
        # Assert-outcome: passed
        # Assert: The page shows the validation message about invalid key format.
        await expect(page.locator("#activationBackdrop").nth(0)).to_contain_text("Invalid key format. Expected pattern: VS-PRO-XXXX-XXXX or wba_live_...", timeout=15000), "The page shows the validation message about invalid key format."
        # Assert-outcome: passed
        # Assert: The license input contains the submitted malformed value.
        await expect(page.get_by_role("textbox", name="License Key or WebAudits.pro").nth(0)).to_have_attribute("value", "INVALID-KEY-XXXX-0000", timeout=15000), "The license input contains the submitted malformed value."
        
        # --> The activation prompt is still shown (no active subscription badge was displayed).
        # Assert-outcome: passed
        # Assert: The activation UI still displays the 'Activate VitalsSniper PRO' prompt, indicating no active badge.
        await expect(page.locator("#activationBackdrop").nth(0)).to_contain_text("Activate VitalsSniper PRO", timeout=15000), "The activation UI still displays the 'Activate VitalsSniper PRO' prompt, indicating no active badge."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    