"""Load the unpacked extension in Chromium; all API/website traffic is mocked."""
import asyncio
import json
from pathlib import Path
from uuid import uuid4

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "backend/data/extension-ui-check"


async def run():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=str(OUTPUT / f"profile-{uuid4().hex}"), channel="chromium", headless=True,
            args=[f"--disable-extensions-except={ROOT / 'extension'}", f"--load-extension={ROOT / 'extension'}"],
            viewport={"width": 1000, "height": 900},
        )
        worker = context.service_workers[0] if context.service_workers else await context.wait_for_event("serviceworker")
        extension_id = worker.url.split('/')[2]
        # Real extension APIs, but no API server, database, or provider requests.
        await worker.evaluate("""() => {
          self.__calls = [];
          self.fetch = async (url, options) => {
            __calls.push({url, options});
            if (url.endsWith('/analyze')) {
              chrome.runtime.sendMessage({type:'SCAN_PROGRESS', tabId:self.__tabId,
                progress:{stage:'page', label:'Inspecting the website', detail:'Reading the page content.', status:'running'}}).catch(() => {});
              await new Promise(resolve => { self.__releaseScan = resolve; });
              return Response.json(self.__fresh);
            }
            return Response.json({explanation: self.__saved});
          };
        }""")
        page = context.pages[0]
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        result = dict(scan_id='request', evidence_scan_id='original', normalized_url='https://example.org/',
            classification='benign', risk_score=.94, verdict='malicious', served_from_history=True,
            page={'status': 'ok', 'preview_available': True, 'page_title': '<img src=x onerror=alert(1)>',
                  'final_url': 'https://accounts.example.net/sign-in'},
            domain_info={'status': 'ok', 'domain': 'example.org', 'registrar': 'Example Registrar',
                         'registered_at': '2000-01-02T00:00:00Z'},
            signals=['The page model found a warning.'])
        answer = dict(summary='Saved explanation from SQL.', reasons=['A sign-in page with mixed findings.'],
                      advice=['Verify the address.'], included_screenshot=True)
        fixture = await context.new_page()
        await fixture.set_content('<h1>Example sign-in page</h1>')
        jpeg = await fixture.screenshot(type='jpeg')
        await fixture.close()

        async def route(request_route):
            if request_route.request.url.endswith('/preview'):
                await request_route.fulfill(content_type='image/jpeg', body=jpeg)
            else:
                await request_route.abort()
        await context.route('http://**/*', route)
        await context.route('https://**/*', route)
        await page.add_init_script("""(() => {
          const original = window.fetch.bind(window);
          window.__explainCalls = 0;
          window.fetch = async (url, options) => {
            if (!String(url).endsWith('/explain')) return original(url, options);
            window.__explainCalls++;
            const encoder = new TextEncoder();
            const frame = (event, data) => encoder.encode(`event: ${event}\\ndata: ${JSON.stringify(data)}\\n\\n`);
            return new Response(new ReadableStream({start(controller) {
              controller.enqueue(frame('snapshot', {summary:'This appears to be an account sign-in', reasons:[], advice:[]}));
              window.__finishExplain = () => {
                controller.enqueue(frame('done', {summary:'This appears to be an account sign-in. The address changed to accounts.example.net.',
                  reasons:['Mixed findings.'], advice:['Verify the destination.'], included_screenshot:true}));
                controller.close();
              };
              window.__failExplain = () => { controller.enqueue(frame('error', {message:'Provider interrupted.'})); controller.close(); };
            }}), {headers:{'content-type':'text/event-stream'}});
          };
        })();""")
        await page.goto(f'chrome-extension://{extension_id}/popup.html')
        await worker.evaluate("""async ({result, answer}) => {
          const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
          self.__tabId = tab.id; self.__saved = answer;
          self.__fresh = {...result, scan_id:'fresh', evidence_scan_id:'fresh', served_from_history:false, explanation:null};
          await chrome.storage.session.set({['tab:'+tab.id]: {url:result.normalized_url, result}});
        }""", {'result': result, 'answer': answer})
        await page.reload()
        await page.get_by_text(answer['summary'], exact=True).wait_for()
        await page.get_by_role('heading', name='High risk', exact=True).wait_for()
        assert await page.locator('.banana-fly').count() == 2
        assert await page.get_by_role('meter').get_attribute('aria-valuenow') == '94'
        assert await page.get_by_role('button', name='Explain this result').count() == 0
        assert await page.evaluate('window.__explainCalls') == 0
        await page.get_by_alt_text('Website preview captured during this scan').wait_for()
        assert await page.get_by_alt_text('Website preview captured during this scan').evaluate('img => img.complete && img.naturalWidth > 0')
        await page.get_by_text('About this domain', exact=True).click()
        await page.get_by_text('Example Registrar', exact=True).wait_for()
        await page.get_by_text('Scan details', exact=True).click()
        await page.get_by_text('<img src=x onerror=alert(1)>', exact=True).wait_for()
        assert await page.locator('dd img').count() == 0
        await page.screenshot(path=str(OUTPUT / 'popup-saved.png'), full_page=True)

        await page.get_by_role('button', name='Rescan', exact=True).click()
        await page.get_by_text('Reading the page content.', exact=True).wait_for()
        await page.get_by_role('progressbar').wait_for()
        await page.locator('.banana-scan-fruit').wait_for()
        await page.screenshot(path=str(OUTPUT / 'popup-scanning.png'), full_page=True)
        await worker.evaluate('self.__releaseScan()')
        await page.get_by_role('button', name='Explain this result').wait_for()
        assert await page.get_by_text(answer['summary'], exact=True).count() == 0
        await page.get_by_role('button', name='Explain this result').click()
        await page.get_by_text('This appears to be an account sign-in', exact=True).wait_for()
        assert await page.locator('.explanation').get_attribute('aria-busy') == 'true'
        await page.evaluate('window.__failExplain()')
        await page.get_by_role('button', name='Try Explain again').click()
        await page.get_by_text('This appears to be an account sign-in', exact=True).wait_for()
        await page.evaluate('window.__finishExplain()')
        await page.get_by_text('Verify the destination.', exact=True).wait_for()
        assert await page.locator('.explanation').get_attribute('aria-busy') == 'false'
        assert await page.evaluate('window.__explainCalls') == 2
        calls = await worker.evaluate('self.__calls')
        scans = [json.loads(call['options']['body']) for call in calls if call['url'].endswith('/analyze')]
        assert scans == [{'url': 'https://example.org/', 'client': 'extension', 'rescan': True}]

        # Warning page uses the same cached explanation and remains readable on mobile.
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.emulate_media(reduced_motion='reduce')
        await page.goto(f'chrome-extension://{extension_id}/blocked.html')
        await page.get_by_text(answer['summary'], exact=True).wait_for()
        await page.get_by_role('button', name='Go back', exact=True).wait_for()
        await page.get_by_role('button', name='Rescan', exact=True).wait_for()
        assert await page.locator('.banana-fly').first.evaluate('el => getComputedStyle(el).animationName') == 'none'
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.screenshot(path=str(OUTPUT / 'warning-mobile.png'), full_page=True)
        # Incomplete scans lose the old score/explanation and retain a retry action.
        await worker.evaluate("""() => { self.__fresh = {...self.__fresh, scan_id:'failed', evidence_scan_id:'failed',
          classification:'unavailable', risk_score:null, error_code:'page_unavailable', page:{status:'unavailable'}}; }""")
        await page.get_by_role('button', name='Rescan', exact=True).click()
        await page.get_by_role('progressbar').wait_for()
        await worker.evaluate('self.__releaseScan()')
        await page.get_by_text('This result will not be reused. Your next scan will try again.', exact=True).wait_for()
        assert await page.get_by_role('meter').count() == 0
        assert await page.locator('.banana-fly').count() == 0
        assert await page.get_by_role('button', name='Rescan', exact=True).is_enabled()

        # The initial navigation screen streams progress, then hands off to the
        # real service worker, which stores the result and opens the warning page.
        checking_result = dict(result, classification='phishing')
        await page.add_init_script('self.__checkingResult = ' + json.dumps(checking_result) + ';' + """
          if (location.pathname.endsWith('/checking.html')) {
            self.fetch = async (url, options) => {
              self.__scanBody = JSON.parse(options.body);
              const encoder = new TextEncoder();
              const frame = (event, data) => encoder.encode(`event: ${event}\\ndata: ${JSON.stringify(data)}\\n\\n`);
              return new Response(new ReadableStream({start(controller) {
                controller.enqueue(frame('progress', {stage:'domain', label:'Looking up domain details', status:'running'}));
                self.__finishScan = () => { controller.enqueue(frame('done', self.__checkingResult)); controller.close(); };
              }}), {headers:{'content-type':'text/event-stream'}});
            };
          }
        """)
        tab_id = await worker.evaluate('self.__tabId')
        await page.goto(f'chrome-extension://{extension_id}/checking.html?url=https%3A%2F%2Fexample.org%2F&tabId={tab_id}')
        await page.get_by_text('Looking up domain details', exact=True).wait_for()
        await page.get_by_role('progressbar').wait_for()
        assert await page.evaluate('self.__scanBody') == {'url': 'https://example.org/', 'client': 'extension', 'rescan': False}
        await page.evaluate('self.__finishScan()')
        await page.wait_for_url(f'chrome-extension://{extension_id}/blocked.html')
        await page.get_by_text(answer['summary'], exact=True).wait_for()
        assert not errors, errors
        await context.close()
    print('Unpacked extension passed: cached explanation, preview, domain, redirects, safe text, risk, banana, Rescan progress, partial streaming/retry, mobile, reduced motion.')


if __name__ == '__main__':
    asyncio.run(run())
