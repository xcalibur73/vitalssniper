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
        
        # -> Open the popup page at http://localhost:5173/popup.html (the extension popup page) so the manual audit controls can be used.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Fill 'https://example.com' into the 'Audit custom URL' field and click the 'Inspect' button to run a manual audit.
        # Target URL to audit text field
        elem = page.get_by_role("textbox", name="Target URL to audit")
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("https://example.com")
        
        # -> Fill 'https://example.com' into the 'Audit custom URL' field and click the 'Inspect' button to run a manual audit.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> A health score is displayed in the score box.
        await page.get_by_text("100", exact=True).nth(0).scroll_into_view_if_needed()
        # Assert-outcome: passed
        # Assert: Health score element is visible on the page.
        await expect(page.get_by_text("100", exact=True).nth(0)).to_be_visible(timeout=15000), "Health score element is visible on the page."
        
        # --> Telemetry cards are visible and the Highlight LCP control is present.
        await page.get_by_text("LIGHT", exact=True).nth(0).scroll_into_view_if_needed()
        # Assert-outcome: passed
        # Assert: A telemetry card entry is visible on the page.
        await expect(page.get_by_text("LIGHT", exact=True).nth(0)).to_be_visible(timeout=15000), "A telemetry card entry is visible on the page."
        await page.get_by_role("button", name="Highlight LCP").nth(0).scroll_into_view_if_needed()
        # Assert-outcome: passed
        # Assert: The Highlight LCP control is visible.
        await expect(page.get_by_role("button", name="Highlight LCP").nth(0)).to_be_visible(timeout=15000), "The Highlight LCP control is visible."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    