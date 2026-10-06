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
        
        # -> Open the popup page at http://localhost:5173/popup.html so the popup-based manual audit UI can be tested.
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Inspect' button to run a manual audit using the active site context.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # -> Click the 'Inspect' button to run a manual audit using the active site context.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # -> Click the 'Inspect' button to run a manual audit using the active site context.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # -> Click the 'Inspect' button in the popup UI to run a manual audit using the active site context.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # -> Click the 'Copy raw diagnostic metrics JSON' button to retrieve raw diagnostic metrics for Core Web Vitals and look for LCP/CLS/INP and attribution information.
        # JSON button
        elem = page.get_by_role("button", name="JSON")
        await elem.click(timeout=10000)
        
        # -> Click the 'Highlight LCP' button to attempt to reveal or highlight the LCP element and surface element-level attribution information.
        # Highlight LCP button
        elem = page.get_by_role("button", name="Highlight LCP")
        await elem.click(timeout=10000)
        
        # -> Open the main site page (http://localhost:5173/) in a new tab and check for any LCP highlighting, Core Web Vitals diagnostics, or attribution overlays.
        # Open URL in new tab
        page = await context.new_page()
        await page.goto("http://localhost:5173/")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Search the main site page for 'Largest Contentful Paint' or other Core Web Vitals diagnostic text and, if not found, click the 'Highlight LCP' button to reveal element-level attribution.
        # Highlight LCP button
        elem = page.get_by_role("button", name="Highlight LCP")
        await elem.click(timeout=10000)
        
        # -> Click the 'Inspect' button on the main site page to run a manual audit in the active site context.
        # Inspect button
        elem = page.get_by_role("button", name="Inspect")
        await elem.click(timeout=10000)
        
        # -> Click the 'JSON' button labeled 'JSON' (Copy raw diagnostic metrics JSON) on the main site page.
        # JSON button
        elem = page.get_by_role("button", name="JSON")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Core Web Vitals diagnostics (e.g. 'Largest Contentful Paint') were not displayed after running the manual audit.
        # Assert-outcome: failed
        # Assert: Expected the page to display "Largest Contentful Paint" text after running the manual audit.
        await expect(page.locator("#btnCopyJson").nth(0)).to_contain_text("Largest Contentful Paint", timeout=15000), "Expected the page to display \"Largest Contentful Paint\" text after running the manual audit."
        
        # --> Element-level attribution highlighting did not appear when 'Highlight LCP' was used.
        # Assert-outcome: failed
        # Assert: Expected the page to show an LCP highlight or attribution containing "Largest Contentful Paint" after clicking Highlight LCP.
        await expect(page.locator("#btnHighlightLcp").nth(0)).to_contain_text("Largest Contentful Paint", timeout=15000), "Expected the page to show an LCP highlight or attribution containing \"Largest Contentful Paint\" after clicking Highlight LCP."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    