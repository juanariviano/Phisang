"""Desktop/mobile smoke check of the built UI, with every network request mocked."""
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "web/dist"
OUTPUT = ROOT / "backend/data/ui-check"


async def run():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="chromium", headless=True)
        fixture = await browser.new_page(viewport={"width": 1440, "height": 900})
        await fixture.set_content('<body style="font:24px sans-serif;padding:70px;background:#fafafa"><h1>Example account page</h1><p>Sign in to manage your account.</p><label>Password <input type="password"></label></body>')
        jpeg = await fixture.screenshot(type="jpeg")
        await fixture.close()
        for width in (1280, 390):
            context = await browser.new_context(viewport={"width": width, "height": 950},
                reduced_motion="no-preference" if width == 1280 else "reduce")
            page = await context.new_page()
            # A controllable ReadableStream proves the UI renders before EOF.
            await page.add_init_script("""(() => {
              const original = window.fetch.bind(window);
              window.__holdExplanation = true;
              window.fetch = async (...args) => {
                if (String(args[0]).endsWith('/analyze')) {
                  const encoder = new TextEncoder();
                  const frame = (type, value) => encoder.encode(`event: ${type}\\ndata: ${JSON.stringify(value)}\\n\\n`);
                  return new Response(new ReadableStream({start(controller) {
                    controller.enqueue(frame('progress', {stage:'history', label:'Checking saved scans', status:'complete'}));
                    controller.enqueue(frame('progress', {stage:'page', label:'Inspecting the website', detail:'Opening the page on our server.', status:'running'}));
                    window.__scanUpdate = () => controller.enqueue(frame('progress', {stage:'page', label:'Inspecting the website', detail:'Reading the page content for signs of phishing.', status:'running'}));
                    original(...args).then(r => r.json()).then(value => {
                      controller.enqueue(frame('done', value)); controller.close();
                    }).catch(error => controller.error(error));
                  }}), {headers:{'content-type':'text/event-stream'}});
                }
                const response = await original(...args);
                if (!String(args[0]).endsWith('/explain') || !response.ok) return response;
                const answer = await response.json();
                const encoder = new TextEncoder();
                const frame = (type, value) => encoder.encode(`event: ${type}\\ndata: ${JSON.stringify(value)}\\n\\n`);
                return new Response(new ReadableStream({start(controller) {
                  controller.enqueue(frame('snapshot', {summary:'The model found a warning', reasons:[], advice:[]}));
                  window.__finishExplanation = () => { controller.enqueue(frame('done', answer)); controller.close(); };
                  if (!window.__holdExplanation) window.__finishExplanation();
                }}), {headers:{'content-type':'text/event-stream'}});
              };
            })();""")
            calls = []
            errors = []
            scan_gate = asyncio.Event()
            page.on("pageerror", lambda err: errors.append(str(err)))
            result = dict(scan_id="test_scan", normalized_url="https://example.org/", classification="phishing",
                confidence=94, risk_score=.94, verdict="malicious", decision_stage="page", policy_version="test",
                evidence_scan_id="test_scan", scanned_at="2026-09-30T01:00:00+00:00",
                threat_intel={"matched": False, "feed_status": "ok"},
                signals=["Page model flagged the HTML.", '<img src=x onerror="alert(1)">'],
                page={"status": "ok", "preview_available": True, "page_title": "Example account page"},
                domain_info={"status": "ok", "domain": "example.org", "registrar": "Example Registrar",
                             "registered_at": "2000-01-02T00:00:00Z", "nameservers": ["ns.example.org"]})
            fail_explain = False
            async def route(request_route):
                nonlocal result
                request = request_route.request
                path = urlsplit(request.url).path
                if urlsplit(request.url).hostname != "phisang.test":
                    await request_route.abort()
                elif path == "/api/v1/scans":
                    await request_route.fulfill(json={"scans": []})
                elif path == "/api/v1/analyze":
                    assert request.headers.get("accept") == "text/event-stream"
                    calls.append(("scan", request.post_data_json))
                    await scan_gate.wait()
                    await request_route.fulfill(json=result)
                elif path.endswith("/preview"):
                    await request_route.fulfill(content_type="image/jpeg", body=jpeg)
                elif path.endswith("/explain"):
                    assert request.headers.get("accept") == "text/event-stream"
                    calls.append(("explain", None))
                    if fail_explain:
                        await request_route.fulfill(status=502, json={"message": "The explanation service could not respond. Please try again."})
                    else:
                        await request_route.fulfill(json={"summary": "The model found a warning, but that is not proof of fraud.",
                            "reasons": ["The page asks for a password.", "A login form alone is normal."],
                            "advice": ["Use a known bookmark."], "included_screenshot": True})
                else:
                    file = (DIST / (path.lstrip("/") or "index.html")).resolve()
                    assert file.is_relative_to(DIST.resolve())
                    mime = {".js": "application/javascript", ".css": "text/css", ".html": "text/html"}.get(file.suffix, "application/octet-stream")
                    await request_route.fulfill(content_type=mime, body=file.read_bytes())
            await context.route("**/*", route)
            await page.goto("http://phisang.test/")
            assert await page.get_by_role("button", name="Wikipedia", exact=True).count() == 0
            assert await page.get_by_role("button", name="GitHub", exact=True).count() == 0
            peel_button = page.get_by_role("button", name="Peel URL", exact=True)
            await peel_button.hover(position={"x": 8, "y": 8})
            assert await peel_button.evaluate("el => getComputedStyle(el).transform") == "none"
            assert await page.locator("main").get_attribute("data-layout") == "columns"
            if width == 1280:
                form = await page.locator("form").bounding_box()
                aside = await page.locator("[data-result-region]").bounding_box()
                assert aside["x"] > form["x"] + form["width"]
            await page.get_by_label("URL to peel").fill("https://example.org/")
            await page.get_by_role("button", name="Peel URL", exact=True).click()
            await page.locator("[data-scanning=true] .banana-scan-fruit").wait_for()
            await page.get_by_role("progressbar", name="Scan in progress").wait_for()
            await page.get_by_text("Opening the page on our server.", exact=True).wait_for()
            await page.evaluate("window.__scanUpdate()")
            await page.get_by_text("Reading the page content for signs of phishing.", exact=True).wait_for()
            assert await page.locator('[data-scan-stage="history"]').get_attribute("data-stage-status") == "complete"
            assert await page.get_by_role("progressbar", name="Scan in progress").get_attribute("aria-valuenow") is None
            animation = await page.locator(".banana-scan-fruit").evaluate("el => getComputedStyle(el).animationName")
            assert animation == ("banana-scan-sway" if width == 1280 else "none")
            await page.screenshot(path=str(OUTPUT / f"scanning-{width}.png"), full_page=True)
            scan_gate.set()
            await page.get_by_role("heading", name="High risk", exact=True).wait_for()
            assert await page.get_by_role("progressbar", name="Scan in progress").count() == 0
            await page.get_by_role("img", name="High risk: rotten banana", exact=True).wait_for()
            await page.get_by_text("94%", exact=True).wait_for()
            assert await page.get_by_role("meter", name="Estimated risk").get_attribute("aria-valuenow") == "94"
            assert await page.locator(".banana-fly").count() == 3
            fly_animation = await page.locator(".banana-fly").first.evaluate("el => getComputedStyle(el).animationName")
            assert fly_animation == ("banana-fly-drift" if width == 1280 else "none")
            await page.wait_for_function("document.querySelector('main').dataset.layout === 'stacked' && document.querySelector('[data-result-region]').getBoundingClientRect().top > document.querySelector('form').getBoundingClientRect().bottom")
            assert not any(call[0] == "explain" for call in calls)
            await page.get_by_role("img", name="Website preview captured during this scan").wait_for()
            await page.get_by_role("button", name="Explain this result").click()
            await page.get_by_role("heading", name="Why this result?").wait_for()
            await page.get_by_text("Writing explanation…", exact=True).wait_for()
            await page.get_by_text("The model found a warning", exact=True).wait_for()
            assert await page.get_by_text("Use a known bookmark.", exact=True).count() == 0
            await page.evaluate("window.__holdExplanation = false; window.__finishExplanation()")
            await page.get_by_text("Use a known bookmark.", exact=True).wait_for()
            assert sum(c[0] == "explain" for c in calls) == 1
            await page.get_by_text("About this domain", exact=True).click()
            await page.get_by_text("Example Registrar", exact=True).wait_for()
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            await page.screenshot(path=str(OUTPUT / f"result-{width}.png"), full_page=True)
            result = dict(result, classification="benign")  # Model score still makes the displayed verdict high-risk.
            await page.get_by_role("button", name="Rescan", exact=True).click()
            assert await page.locator("main").get_attribute("data-layout") == "stacked"
            await page.get_by_role("button", name="Explain this result").wait_for()
            await page.get_by_role("img", name="High risk: rotten banana", exact=True).wait_for()
            assert [c[1] for c in calls if c[0] == "scan"][-1]["rescan"] is True
            fail_explain = True
            await page.get_by_role("button", name="Explain this result").click()
            await page.get_by_role("button", name="Try Explain again").wait_for()
            fail_explain = False
            await page.get_by_role("button", name="Try Explain again").click()
            await page.get_by_role("heading", name="Why this result?").wait_for()
            await page.get_by_label("URL to peel").fill("https://example.net/")
            result = dict(result, scan_id="failed", classification="unavailable", risk_score=None,
                          verdict="unknown", page={"status": "unavailable"}, error_code="page_unavailable")
            await page.get_by_role("button", name="Peel URL", exact=True).click()
            await page.get_by_text("This result will not be reused. Your next scan will try again.").wait_for()
            assert await page.get_by_role("meter", name="Estimated risk").count() == 0
            assert await page.locator(".banana-fly").count() == 0
            assert [c[1] for c in calls if c[0] == "scan"][-1]["rescan"] is False
            assert not errors, errors
            await context.close()
        await browser.close()
    print("Desktop/mobile passed: static Peel button, no examples, risk percentage, rotten high-risk banana/flies (including benign classification), unavailable score omitted, streaming, stacked layout, Rescan, reduced motion.")


if __name__ == "__main__":
    asyncio.run(run())
