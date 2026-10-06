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
        
        # -> Open the comparison popup by navigating to the page at http://localhost:5173/popup.html so the competitor comparison UI can be used.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Vs' (Compare Head-to-Head) button to open the competitor comparison UI.
        # Compare Head-to-Head vs Competitor button
        elem = page.get_by_role("button", name="Compare Head-to-Head vs")
        await elem.click(timeout=10000)
        
        # -> Fill 'posthog.com' into the competitor URL field and click the 'Compare' button to run the head‑to‑head comparison.
        # Competitor URL to benchmark text field
        elem = page.get_by_role("textbox", name="Competitor URL to benchmark")
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("posthog.com")
        
        # -> Fill 'posthog.com' into the competitor URL field and click the 'Compare' button to run the head‑to‑head comparison.
        # Compare button
        elem = page.get_by_role("button", name="Compare", exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> The comparison results include the active Target Site as the Prospect in the results table.
        # Assert-outcome: passed
        # Assert: Checks the comparison table header includes a 'Prospect' column (the active target).
        await expect(page.locator("thead").nth(0)).to_contain_text("Prospect", timeout=15000), "Checks the comparison table header includes a 'Prospect' column (the active target)."
        
        # --> Comparative metrics are shown in the results table (for example, a 'DOM Elements' row comparing Prospect and Competitor).
        # Assert-outcome: passed
        # Assert: Checks the comparison table contains the 'DOM Elements' metric row.
        await expect(page.locator("#comparisonTableBody").nth(0)).to_contain_text("DOM Elements", timeout=15000), "Checks the comparison table contains the 'DOM Elements' metric row."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    