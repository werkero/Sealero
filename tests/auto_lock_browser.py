"""Browser regression for the 15-minute idle lock with refresh persistence.

The vault locks after 15 minutes without activity; time in the
background counts as idle, and a page refresh neither locks nor resets
the countdown. Requires a real browser run (Playwright cannot run in
this sandbox): run with Vite serving the web package (for example, run
`pnpm dev` from the repo root, then):
  python tests/auto_lock_browser.py http://localhost:5173
"""

import sys

from playwright.sync_api import sync_playwright


def run(base_url: str) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{base_url.rstrip('/')}/login")
        page.wait_for_load_state("networkidle")

        page.locator("#login-email").fill("preview@example.test")
        page.locator("#login-password").fill("throwaway-login")
        page.locator("form").first.locator("button[type=submit]").click()
        page.locator("#master-password").wait_for()
        page.locator("#master-password").fill("throwaway-master")
        page.locator("form").first.locator("button[type=submit]").click()
        page.get_by_role("button", name="Open Gitea Workspace").wait_for()

        # Controllable wall clock: the idle timer runs on Date.now().
        page.evaluate("""() => {
          let wallClockNow = Date.now()
          Date.now = () => wallClockNow
          window.advanceAutoLockTestClock = (deltaMs) => { wallClockNow += deltaMs }
          window.readAutoLockTestClock = () => wallClockNow
        }""")

        # 14 idle minutes: still unlocked.
        page.evaluate("window.advanceAutoLockTestClock(14 * 60 * 1000)")
        page.wait_for_timeout(200)
        page.get_by_role("button", name="Open Gitea Workspace").wait_for()

        # Activity resets the window: 14 more idle minutes, still unlocked.
        page.mouse.move(400, 300)
        page.evaluate("window.advanceAutoLockTestClock(14 * 60 * 1000)")
        page.wait_for_timeout(200)
        page.get_by_role("button", name="Open Gitea Workspace").wait_for()

        # 2 further idle minutes (16 since the last activity): locked.
        page.evaluate("window.advanceAutoLockTestClock(2 * 60 * 1000)")
        page.locator("#master-password").wait_for(timeout=5000)

        # The vault is already locked, so a refresh must still show the lock screen.
        page.reload()
        page.locator("#master-password").wait_for(timeout=5000)

        browser.close()
        print("auto-lock idle scenario passed")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173")
