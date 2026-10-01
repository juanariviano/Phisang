"""Browser check using the isolated file-guard build and mocked network traffic."""
import asyncio
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "backend/data/file-guard-web-build"
OUTPUT = ROOT / "backend/data/file-guard-ui"


async def run():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="chromium", headless=True)
        page = await browser.new_page()
        calls, errors = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))

        async def route(request_route):
            path = urlsplit(request_route.request.url).path
            if path == "/api/v1/scans":
                await request_route.fulfill(json={"scans": []})
            elif path == "/api/v1/analyze":
                calls.append(path)
                await request_route.fulfill(status=400, json={"error_code": "unsupported_content",
                    "message": "Phisang scans webpages, not files. Enter a webpage URL instead."})
            else:
                file = (DIST / (path.lstrip("/") or "index.html")).resolve()
                if not file.is_relative_to(DIST.resolve()) or not file.is_file():
                    await request_route.abort()
                    return
                mime = {".js": "application/javascript", ".css": "text/css"}.get(file.suffix, "text/html")
                await request_route.fulfill(body=file.read_bytes(), content_type=mime)

        await page.route("**/*", route)
        await page.goto("https://phisang.test/")
        await page.locator('#url-input').fill("https://example.org/report.pdf?download=1")
        await page.get_by_role("button", name="Peel URL", exact=True).click()
        await expect(page.get_by_text("Phisang scans webpages, not files. Enter a webpage URL instead.", exact=True)).to_be_visible()
        assert calls == []
        await page.screenshot(path=str(OUTPUT / "website-file-rejected.png"))
        # An extensionless destination error from the API is also readable.
        await page.locator('#url-input').fill("https://example.org/download")
        await page.get_by_role("button", name="Peel URL", exact=True).click()
        await expect(page.get_by_text("Phisang scans webpages, not files. Enter a webpage URL instead.", exact=True)).to_be_visible()
        assert len(calls) == 1 and not errors
        await browser.close()

        context = await pw.chromium.launch_persistent_context(
            user_data_dir=str(OUTPUT / f"profile-{uuid4().hex}"), channel="chromium", headless=True,
            args=[f"--disable-extensions-except={ROOT / 'extension'}", f"--load-extension={ROOT / 'extension'}"])
        worker = context.service_workers[0] if context.service_workers else await context.wait_for_event("serviceworker")
        extension_id = worker.url.split("/")[2]
        await worker.evaluate("""async () => {
          await Phisang.rememberResult('https://example.org/home', {
            classification:'benign', normalized_url:'https://example.org/home', page:{status:'ok'}, verdict:'safe'
          });
        }""")
        requests = []

        async def reject_network(route):
            requests.append(route.request.url)
            await route.abort()

        await context.route("http://**/*", reject_network)
        await context.route("https://**/*", reject_network)
        page = context.pages[0]
        page.on("pageerror", lambda error: errors.append(str(error)))
        tab_id = await worker.evaluate("async () => (await chrome.tabs.query({}))[0].id")
        url = f"chrome-extension://{extension_id}/checking.html?" + urlencode({
            "url": "https://example.org/setup.exe", "tabId": tab_id})
        await page.goto(url)
        await expect(page.get_by_role("heading", name="File scanning is not supported")).to_be_visible()
        await expect(page.get_by_role("button", name="Go back")).to_be_visible()
        assert page.url == url and requests == [] and not errors
        await page.screenshot(path=str(OUTPUT / "extension-file-rejected.png"))
        await context.close()
    print("Website and extension file rejection passed; no file scan or download request.")


if __name__ == "__main__":
    asyncio.run(run())
