"""Browser regression for language preference persistence.

Run with Vite serving the web package:
  python tests/language_persistence_browser.py http://localhost:5173
"""

import base64
import json
import sys

from playwright.sync_api import sync_playwright


def run(base_url: str) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{base_url.rstrip('/')}/login", wait_until="networkidle")

        language_selector = page.locator(".language-control select")
        language_selector.wait_for(state="visible")
        language_selector.select_option("zh-Hans")
        page.get_by_role("heading", name="登录").wait_for()
        assert page.evaluate("window.localStorage.getItem('sealero.language')") == "zh-Hans"
        assert language_selector.input_value() == "zh-Hans"

        page.reload(wait_until="networkidle")
        restored_selector = page.locator(".language-control select")
        restored_selector.wait_for(state="visible")
        assert restored_selector.input_value() == "zh-Hans"
        assert page.evaluate("window.localStorage.getItem('sealero.language')") == "zh-Hans"
        page.get_by_role("heading", name="登录").wait_for()
        assert page.locator("html").get_attribute("lang") == "zh-Hans"

        page.locator("#login-email").fill("preview@example.test")
        page.locator("#login-password").fill("throwaway-login")
        page.get_by_role("button", name="继续进入保险库").click()
        page.locator("#master-password").wait_for()
        page.locator("#master-password").fill("throwaway-master")
        page.get_by_role("button", name="解锁预览").click()
        page.locator(".vault-item-row").first.wait_for()
        page.get_by_role("button", name="设置").click()
        page.get_by_role("heading", name="设置", exact=True).wait_for()
        assert "/settings" in page.url
        assert page.locator(".settings-select-control select").input_value() == "zh-Hans"

        page.get_by_role("button", name="深色").click()
        assert page.evaluate("document.documentElement.dataset.theme") == "dark"
        assert page.evaluate("window.localStorage.getItem('sealero.appearance')") == "dark"

        secret = "do-not-render-this-import-password"
        page.evaluate("""(secret) => {
          const input = document.querySelector('#vault-import-file');
          const csv = ['name,url,username,password,note', `Imported Entry,https://import.example.test,alice,${secret},local note`, ',,,,needs naming'].join(String.fromCharCode(10));
          const file = new File([csv], 'local.csv', { type: 'text/csv', lastModified: 0 });
          const transfer = new DataTransfer();
          transfer.items.add(file);
          input.files = transfer.files;
          input.dispatchEvent(new Event('change', { bubbles: true }));
        }""", secret)
        page.get_by_role("heading", name="导入预览").wait_for()
        page.get_by_text("导入文件没有修改时间，无法判断新旧，请手动选择。", exact=True).wait_for()
        page.get_by_role("button", name="检查重复项").click()
        page.get_by_text("新增：2", exact=False).wait_for()
        page.get_by_text("无网站（未命名条目）", exact=True).wait_for()
        assert secret not in page.locator("body").inner_text()
        assert secret not in page.evaluate("JSON.stringify(Object.entries(window.localStorage))")
        assert page.get_by_role("button", name="应用导入").is_disabled()

        def b64(length: int) -> str:
            return base64.b64encode(bytes([7]) * length).decode()

        kdf_params = '{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}'
        wrapping = {
            "ciphertext": b64(16),
            "dek_version": 1,
            "kdf_params": kdf_params,
            "kdf_salt": b64(16),
            "kind": "kek",
            "master_password_version": 1,
            "nonce": b64(12),
        }
        recovery = {**wrapping, "kind": "recovery_key"}
        recovery.pop("master_password_version")
        backup = {
            "backup_format_version": 3,
            "created_at": "2026-11-22T12:00:00Z",
            "dek_wrappings": [wrapping, recovery],
            "items": [],
            "manifest": {"ciphertext": b64(16), "nonce": b64(12)},
            "source_user_id": "123e4567-e89b-42d3-a456-426614174000",
        }
        page.locator("#vault-backup-file").set_input_files({
            "name": "backup.json",
            "mimeType": "application/json",
            "buffer": json.dumps(backup, separators=(",", ":")).encode(),
        })
        page.get_by_text("已识别备份格式 3 容器", exact=False).wait_for()
        page.get_by_text("尚未验证真实性或完整性", exact=False).wait_for()
        page.get_by_role("button", name="打开健康检查").click()
        assert "/settings/health" in page.url
        page.locator(".security-page-heading h1").wait_for()
        page.locator(".security-back").click()
        page.get_by_role("heading", name="设置", exact=True).wait_for()
        assert page.url.rstrip("/").endswith("/settings")
        browser.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173")
