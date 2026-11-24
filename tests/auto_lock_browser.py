"""Browser regression for auto-lock after a hidden tab outlasts the threshold.

Run with Vite serving the web package (for example, run `pnpm dev` from `web/`):
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

        page.evaluate("""() => {
          let visibilityState = document.visibilityState
          let wallClockNow = Date.now()
          let monotonicNow = performance.now()
          Date.now = () => wallClockNow
          Object.defineProperty(performance, 'now', {
            configurable: true,
            value: () => monotonicNow,
          })
          Object.defineProperty(document, 'visibilityState', {
            configurable: true,
            get: () => visibilityState,
          })
          window.advanceAutoLockTestClocks = ({ wallClockDeltaMs, monotonicDeltaMs }) => {
            wallClockNow += wallClockDeltaMs
            monotonicNow += monotonicDeltaMs
          }
          window.readAutoLockTestClocks = () => ({ wallClockNow, monotonicNow })
          window.setVisibilityForAutoLockTest = (nextState) => {
            visibilityState = nextState
            document.dispatchEvent(new Event('visibilitychange'))
          }
        }""")
        page.evaluate("window.setVisibilityForAutoLockTest('hidden')")
        page.wait_for_function("document.visibilityState === 'hidden'")

        hidden_clocks = page.evaluate("window.readAutoLockTestClocks()")
        # Simulate frozen timers: advance only the monotonic clock, while wall time moves backwards.
        page.evaluate("window.advanceAutoLockTestClocks({ wallClockDeltaMs: -120_000, monotonicDeltaMs: 61_000 })")
        resumed_clocks = page.evaluate("window.readAutoLockTestClocks()")
        assert resumed_clocks["wallClockNow"] < hidden_clocks["wallClockNow"], "Expected wall clock to move backwards"
        assert resumed_clocks["monotonicNow"] - hidden_clocks["monotonicNow"] >= 60_000, "Expected at least 60 seconds of monotonic elapsed time"
        page.get_by_role("button", name="Open Gitea Workspace").wait_for()

        page.evaluate("window.setVisibilityForAutoLockTest('visible')")
        page.wait_for_function("document.visibilityState === 'visible'")
        page.locator("#master-password").wait_for(timeout=2_000)
        assert "/unlock" in page.url, f"Expected an immediate lock after returning from hidden state; got {page.url}"
        browser.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173")
