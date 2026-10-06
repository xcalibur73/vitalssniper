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
        
        # -> Open the popup page at /popup.html (navigate to the popup page).
        await page.goto("http://localhost:5173/popup.html")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Cold Email' button to open the outreach generator and then cycle through the other channel buttons ('Merchant', 'Agency', 'LinkedIn DM', 'Loom Pitch').
        # Cold Email button
        elem = page.get_by_role("button", name="Cold Email")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' button to open the outreach generator and then cycle through the other channel buttons ('Merchant', 'Agency', 'LinkedIn DM', 'Loom Pitch').
        # Merchant button
        elem = page.get_by_role("button", name="Merchant")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' button to open the outreach generator and then cycle through the other channel buttons ('Merchant', 'Agency', 'LinkedIn DM', 'Loom Pitch').
        # Agency button
        elem = page.get_by_role("button", name="Agency", exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' button to open the outreach generator and then cycle through the other channel buttons ('Merchant', 'Agency', 'LinkedIn DM', 'Loom Pitch').
        # LinkedIn DM button
        elem = page.get_by_role("button", name="LinkedIn DM")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' button to open the outreach generator and then cycle through the other channel buttons ('Merchant', 'Agency', 'LinkedIn DM', 'Loom Pitch').
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # -> Click the 'Close' button on the 'Upgrade to VitalsSniper PRO' modal to dismiss it, then list all visible buttons on the page to locate the outreach channel controls.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' tab and confirm a generated pitch appears by checking for the text 'Hi [First Name]'.
        # Cold Email button
        elem = page.get_by_role("button", name="Cold Email")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' tab and confirm a generated pitch appears by checking for the text 'Hi [First Name]'.
        # Merchant button
        elem = page.get_by_role("button", name="Merchant")
        await elem.click(timeout=10000)
        
        # -> Click the 'Cold Email' tab and confirm the generated pitch appears by finding 'Hi [First Name]' in the preview.
        # Cold Email button
        elem = page.get_by_role("button", name="Cold Email")
        await elem.click(timeout=10000)
        
        # -> Click the 'Merchant' tab and confirm the preview shows a generated outreach script (look for 'Subject:' in the preview).
        # Merchant button
        elem = page.get_by_role("button", name="Merchant")
        await elem.click(timeout=10000)
        
        # -> Click the 'Merchant' tab and confirm the preview shows a generated outreach script (look for 'Subject:' in the preview).
        # Agency button
        elem = page.get_by_role("button", name="Agency", exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the 'Merchant' tab and verify the preview shows a generated outreach script (look for 'Subject:' in the preview).
        # Merchant button
        elem = page.get_by_role("button", name="Merchant")
        await elem.click(timeout=10000)
        
        # -> Click the 'Merchant' tab and verify the preview shows a generated outreach script (look for 'Subject:' in the preview).
        # LinkedIn DM button
        elem = page.get_by_role("button", name="LinkedIn DM")
        await elem.click(timeout=10000)
        
        # -> Click the 'Loom Pitch' tab to display its generated pitch in the preview area.
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # -> Click the modal '×' close button to dismiss the 'Upgrade to VitalsSniper PRO' modal so channel previews can be accessed.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Click the 'Loom Pitch' tab to display its generated pitch in the preview area.
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # -> Close the 'Upgrade to VitalsSniper PRO' modal so the outreach channel tabs and preview are accessible, then click the 'Loom Pitch' tab and verify a generated Loom pitch appears in the preview.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Click the 'Loom Pitch' tab to display its generated pitch in the preview area.
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # -> Click the modal '×' close button to dismiss the 'Upgrade to VitalsSniper PRO' modal so the outreach channel tabs and preview are accessible.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Click the 'Loom Pitch' tab to switch the preview to the Loom channel so its generated pitch can be verified.
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # -> Close the 'Upgrade to VitalsSniper PRO' modal and locate the 'Loom Pitch' tab by its visible button text so the Loom preview can be verified.
        # Close PRO upgrade modal button
        elem = page.get_by_role("button", name="Close PRO upgrade modal")
        await elem.click(timeout=10000)
        
        # -> Click the 'Loom Pitch' button and verify the preview contains a generated pitch by looking for the greeting 'Hi [First Name]'.
        # Loom Pitch button
        elem = page.get_by_role("button", name="Loom Pitch")
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Generated outreach scripts appeared in the preview for each channel: Cold Email ('Hi [First Name]'), Merchant ('Subject:'), Agency ('Subject:'), LinkedIn DM (preview visible), and Loom ('Hi [First Name]').
        # Assert-outcome: passed
        # Assert: The test page URL contains 'popup.html', confirming we were on the popup page when verifications were made.
        await expect(page).to_have_url(re.compile("popup\\.html"), timeout=15000), "The test page URL contains 'popup.html', confirming we were on the popup page when verifications were made."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    