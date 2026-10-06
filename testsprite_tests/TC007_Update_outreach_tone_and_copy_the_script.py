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
        
        # -> Open the outreach generator by navigating to the popup page (open http://localhost:5173/popup.html).
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Data' tone button and read the email preview (look for the 'Subject:' line) to capture the generated script.
        # Data button
        elem = page.get_by_role("button", name="Data")
        await elem.click(timeout=10000)
        
        # -> Click the 'Urgency' tone button to change the outreach tone and then verify the email preview updates to reflect the Urgency tone.
        # Urgency button
        elem = page.get_by_role("button", name="Urgency")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal by clicking the modal's Close (X) button, then click the 'Urgency' tone button again to observe whether the preview updates or the upgrade modal reappears.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal by clicking the modal's Close (X) button, then click the 'Urgency' tone button again to observe whether the preview updates or the upgrade modal reappears.
        # Urgency button
        elem = page.get_by_role("button", name="Urgency")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal by clicking the '×' Close button, then click the 'Urgency' tone button to confirm whether the upgrade modal reappears and blocks the tone.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal by clicking the '×' Close button, then click the 'Urgency' tone button to confirm whether the upgrade modal reappears and blocks the tone.
        # Urgency button
        elem = page.get_by_role("button", name="Urgency")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal, click the 'Data' tone to show the preview, then click the 'Copy 3-Sentence Email' button and check for a copy confirmation message.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal, click the 'Data' tone to show the preview, then click the 'Copy 3-Sentence Email' button and check for a copy confirmation message.
        # Data button
        elem = page.get_by_role("button", name="Data")
        await elem.click(timeout=10000)
        
        # -> Close the PRO upgrade modal, click the 'Data' tone to show the preview, then click the 'Copy 3-Sentence Email' button and check for a copy confirmation message.
        # Copy 3-Sentence Email button
        elem = page.get_by_role("button", name="Copy 3-Sentence Email")
        await elem.click(timeout=10000)
        
        # -> Click the 'Urgency' tone button and check whether selecting it opens a PRO upgrade modal or updates the email preview.
        # Urgency button
        elem = page.get_by_role("button", name="Urgency")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Selecting the Urgency tone opened a PRO upgrade modal that blocked the outreach UI, preventing verification of the Urgency/Soft-Sell tones.
        await page.get_by_role("button", name="Close PRO upgrade modal").nth(0).scroll_into_view_if_needed()
        # Assert-outcome: failed
        # Assert: Expected the PRO upgrade modal to not appear when selecting the Urgency tone.
        await expect(page.get_by_role("button", name="Close PRO upgrade modal").nth(0)).to_be_visible(timeout=15000), "Expected the PRO upgrade modal to not appear when selecting the Urgency tone."
        
        # --> Test blocked by environment/access constraints during agent run
        # Reason: TEST BLOCKED The test could not be fully completed because the Urgency and Soft-Sell outreach tones are gated behind a PRO upgrade modal. Observations: - The Data tone produced a full email preview (Subject and body) and clicking 'Copy 3-Sentence Email' showed the 'Copied to Clipboard!' confirmation. - Selecting the Urgency tone opens a PRO upgrade modal that overlays and blocks the outreach UI...
        raise AssertionError("Test blocked during agent run: " + "TEST BLOCKED The test could not be fully completed because the Urgency and Soft-Sell outreach tones are gated behind a PRO upgrade modal. Observations: - The Data tone produced a full email preview (Subject and body) and clicking 'Copy 3-Sentence Email' showed the 'Copied to Clipboard!' confirmation. - Selecting the Urgency tone opens a PRO upgrade modal that overlays and blocks the outreach UI..." + " - the exported script cannot reproduce a PASS in this environment.")
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    