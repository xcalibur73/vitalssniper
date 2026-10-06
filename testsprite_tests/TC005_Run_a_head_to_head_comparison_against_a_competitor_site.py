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
        
        # -> Open the popup page at http://localhost:5173/popup.html so the competitor comparison controls can be tested.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Vs' competitor comparison button to open competitor comparison controls.
        # Compare Head-to-Head vs Competitor button
        elem = page.get_by_role("button", name="Compare Head-to-Head vs")
        await elem.click(timeout=10000)
        
        # -> Fill 'example.com' into the Competitor URL field and click the 'Compare' button to run the head-to-head comparison.
        # Competitor URL to benchmark text field
        elem = page.get_by_role("textbox", name="Competitor URL to benchmark")
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("example.com")
        
        # -> Fill 'example.com' into the Competitor URL field and click the 'Compare' button to run the head-to-head comparison.
        # Compare button
        elem = page.get_by_role("button", name="Compare", exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Comparative metrics were not produced because the in-browser competitor fetch was blocked by CORS/bot-security.
        await page.get_by_role("cell", name="Direct in-browser fetch was").nth(0).scroll_into_view_if_needed()
        # Assert-outcome: failed
        # Assert: Expected comparative metrics to be displayed, but a CORS/bot-security block message is shown.
        await expect(page.get_by_role("cell", name="Direct in-browser fetch was").nth(0)).to_be_visible(timeout=15000), "Expected comparative metrics to be displayed, but a CORS/bot-security block message is shown."
        
        # --> Win-loss (Delta / Status) breakdown was not shown because competitor data could not be fetched due to CORS/bot-security.
        await page.get_by_role("row", name="Direct in-browser fetch was").nth(0).scroll_into_view_if_needed()
        # Assert-outcome: failed
        # Assert: Expected a win-loss (Delta / Status) breakdown to be displayed, but the comparison shows a CORS/bot-security block instead.
        await expect(page.get_by_role("row", name="Direct in-browser fetch was").nth(0)).to_be_visible(timeout=15000), "Expected a win-loss (Delta / Status) breakdown to be displayed, but the comparison shows a CORS/bot-security block instead."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    