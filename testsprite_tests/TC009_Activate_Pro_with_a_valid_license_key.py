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
        
        # -> Open the popup page at /popup.html (navigate to the popup page) so the activation UI can be used.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'ACTIVATE' button to open the activation UI.
        # ACTIVATE button
        elem = page.get_by_role("button", name="ACTIVATE")
        await elem.click(timeout=10000)
        
        # -> Click the "Already have a license key? Enter key →" link to reveal the license activation form.
        # Already have a license key? Enter key → button
        elem = page.get_by_role("button", name="Already have a license key?")
        await elem.click(timeout=10000)
        
        # -> Enter the demo license key into the 'License Key or WebAudits.pro API Key' field and click the 'Unlock PRO Features' button.
        # VS-PRO-XXXX-XXXX or wba_live_... text field
        elem = page.get_by_role("textbox", name="License Key or WebAudits.pro")
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("VS-PRO-0000-0000")
        
        # -> Enter the demo license key into the 'License Key or WebAudits.pro API Key' field and click the 'Unlock PRO Features' button.
        # Unlock PRO Features button
        elem = page.get_by_role("button", name="Unlock PRO Features")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> No success confirmation was shown in the activation modal after submitting the license key.
        # Assert-outcome: failed
        # Assert: Expected success confirmation to be visible in the activation modal.
        await expect(page.locator("#activationBackdrop").nth(0)).to_contain_text("License activated", timeout=15000), "Expected success confirmation to be visible in the activation modal."
        
        # --> No active subscription badge (PRO active status) was visible on the page after the activation attempt.
        # Assert-outcome: failed
        # Assert: Expected an active subscription badge or 'PRO Active' status to be visible on the page.
        await expect(page.get_by_role("contentinfo").nth(0)).to_contain_text("PRO Active", timeout=15000), "Expected an active subscription badge or 'PRO Active' status to be visible on the page."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    