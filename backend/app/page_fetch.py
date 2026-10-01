"""Hardened headless-browser fetcher for untrusted, caller-supplied URLs."""

import asyncio
import time
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

from .config import settings
from .content_guard import UnsupportedContent, check_page_headers, check_page_url
from .scan_progress import report
from .url_guard import UrlRejected, check_static, classify_ip, resolve_public, validate

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECT_HOPS = 5

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36")

STRIP_TAGS = ["script", "style", "svg", "template", "noscript"]
BLOCKED_RESOURCE_TYPES = frozenset({"media"})

CHROMIUM_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-client-side-phishing-detection",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-breakpad",
    "--disable-extensions",
    "--disable-default-apps",
    "--disable-field-trial-config",
    "--metrics-recording-only",
    "--no-pings",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=OptimizationHints,NetworkTimeServiceQuerying,MediaRouter,"
    "Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater,"
    "OptimizationGuideModelDownloading",
]


class FetchFailed(Exception):
    """Fetching failed for a reason that is safe to report to the caller."""


class _HostCache:
    """Short-lived record of hosts already proven public, to spare repeat DNS."""

    def __init__(self, ttl: float = 30.0):
        self._ttl = ttl
        self._entries = {}

    def approved(self, host: str) -> bool:
        expiry = self._entries.get(host)
        if expiry is None:
            return False
        if expiry < time.monotonic():
            self._entries.pop(host, None)
            return False
        return True

    def approve(self, host: str) -> None:
        self._entries[host] = time.monotonic() + self._ttl


class Fetcher:
    def __init__(self, *, max_concurrency: int = 2, nav_timeout: float = 20.0,
                 settle: float = 1.5, max_html_bytes: int = 5_000_000,
                 total_timeout: float = 45.0, proxy: dict = None):
        self.nav_timeout = nav_timeout
        self.settle = settle
        self.max_html_bytes = max_html_bytes
        self.total_timeout = total_timeout
        self._proxy = proxy
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._host_cache = _HostCache()
        self._playwright = None
        self._browser = None

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            channel="chromium", headless=True, proxy=self._proxy, args=CHROMIUM_ARGS)

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def _guard_route(self, route, request):
        """Vet every request the page makes, including each redirect hop."""
        try:
            if request.is_navigation_request():
                check_page_url(request.url)
            if (request.resource_type in BLOCKED_RESOURCE_TYPES or
                    (not settings.page_preview_enabled and request.resource_type in {"image", "font"})):
                await route.abort()
                return
            host, port = check_static(request.url)
            if not self._host_cache.approved(host):
                await resolve_public(host, port)
                self._host_cache.approve(host)
            await route.continue_()
        except (UrlRejected, UnsupportedContent):
            await route.abort()
        except Exception:
            # A guard that cannot decide must refuse, never fall through.
            try:
                await route.abort()
            except Exception:
                pass

    async def _resolve_redirects(self, context, url: str) -> str:
        """Walk the redirect chain here, validating each hop, and return the end.

        context.route() is only invoked for the request the page starts with:
        Chromium follows 3xx responses internally, so a public host redirecting
        to an internal address would otherwise be fetched unchecked. Resolving
        the chain first means the page is only ever pointed at a vetted URL.
        """
        current = url
        for _ in range(MAX_REDIRECT_HOPS):
            check_page_url(current)
            await validate(current)
            try:
                response = await context.request.head(
                    current, max_redirects=0, timeout=self.nav_timeout * 1000)
            except Exception as exc:
                raise FetchFailed(_safe_reason(exc)) from None
            try:
                if response.status not in REDIRECT_STATUSES:
                    # Some sites reject HEAD. The browser response is still
                    # checked before extracting HTML or running the model.
                    if 200 <= response.status < 300:
                        check_page_headers(response.headers)
                    return current
                location = response.headers.get("location")
                if not location:
                    return current
                current = urljoin(current, location)
            finally:
                await response.dispose()
        raise FetchFailed("too many redirects")

    async def _verify_peers(self, response) -> None:
        """Confirm the IPs actually connected to were public.

        The pre-flight check resolves DNS itself, so a rebinding attacker could
        still hand Chromium a different answer. This inspects the address the
        browser really reached, closing that window.
        """
        seen = response
        while seen is not None:
            addr = await seen.server_addr()
            if addr and addr.get("ipAddress"):
                reason = classify_ip(addr["ipAddress"])
                if reason:
                    raise FetchFailed(f"target resolves to a {reason}")
            request = seen.request.redirected_from
            seen = await request.response() if request else None

    async def fetch(self, url: str) -> dict:
        check_page_url(url)
        await validate(url)
        async with self._semaphore:
            try:
                return await asyncio.wait_for(self._fetch_once(url), self.total_timeout)
            except asyncio.TimeoutError:
                raise FetchFailed("fetch exceeded the time budget") from None
            except (UrlRejected, UnsupportedContent):
                raise
            except FetchFailed:
                raise
            except Exception as exc:
                # Includes disconnected Chromium/new_context failures.
                raise FetchFailed(_safe_reason(exc)) from None

    async def _fetch_once(self, url: str) -> dict:
        from playwright.async_api import Error as PlaywrightError

        started = time.monotonic()
        context = await self._browser.new_context(
            user_agent=CHROME_UA, viewport={"width": 1440, "height": 900},
            locale="en-US", ignore_https_errors=True, accept_downloads=False,
            java_script_enabled=True, service_workers="block")
        try:
            target = await self._resolve_redirects(context, url)
            unsupported = []

            async def guard(route, request):
                if request.is_navigation_request():
                    try:
                        check_page_url(request.url)
                    except UnsupportedContent as exc:
                        if request.frame == page.main_frame:
                            unsupported.append(exc)
                        await route.abort()
                        return
                await self._guard_route(route, request)

            await context.route("**/*", guard)
            page = await context.new_page()
            page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))

            def inspect_response(response):
                if response.request.is_navigation_request() and response.frame == page.main_frame:
                    try:
                        check_page_url(response.url)
                        if 200 <= response.status < 300:
                            check_page_headers(response.headers)
                    except UnsupportedContent as exc:
                        unsupported.append(exc)

            page.on("response", inspect_response)
            page.on("download", lambda _: unsupported.append(UnsupportedContent()))

            # Any Playwright error after navigation (a renderer crash during the
            # settle wait, a page closed mid-read) is a failed fetch, not a 500.
            try:
                response = await page.goto(target, wait_until="load",
                                           timeout=self.nav_timeout * 1000)
                if response is None:
                    raise FetchFailed("target returned no response")

                check_page_url(response.url)
                if 200 <= response.status < 300:
                    check_page_headers(response.headers)

                await self._verify_peers(response)
                if self.settle:
                    await page.wait_for_timeout(self.settle * 1000)

                if unsupported:
                    raise unsupported[0]
                check_page_url(page.url)

                html = await page.content()
                title = (await page.title() or "")[:200]
            except PlaywrightError as exc:
                if unsupported:
                    raise unsupported[0]
                raise FetchFailed(_safe_reason(exc)) from None
            if len(html.encode("utf-8", "ignore")) > self.max_html_bytes:
                raise FetchFailed("page is larger than the size limit")

            screenshot = None
            preview_budget = min(3.0, self.total_timeout - (time.monotonic() - started) - 1.0)
            if settings.page_preview_enabled and 200 <= response.status < 300 and preview_budget > 0:
                try:
                    await report("page", "Inspecting the website", "Capturing a preview of the page.")
                    screenshot = await asyncio.wait_for(page.screenshot(type="jpeg", quality=60,
                        full_page=False, animations="disabled", timeout=preview_budget * 1000), preview_budget)
                    if len(screenshot) > 600_000:
                        screenshot = None
                except (PlaywrightError, asyncio.TimeoutError):
                    pass  # A preview failure must not discard a valid reading.
            # A script can navigate again while the preview is being captured.
            if unsupported:
                raise unsupported[0]
            check_page_url(page.url)
            return {"status": response.status, "final_url": page.url,
                    "title": title, "html": html, "screenshot": screenshot}
        finally:
            await context.close()


def _safe_reason(exc: Exception) -> str:
    """Map a Playwright error to a message that leaks nothing internal."""
    text = str(exc)
    if "ERR_NAME_NOT_RESOLVED" in text:
        return "host could not be resolved"
    if "Timeout" in text or "ERR_TIMED_OUT" in text:
        return "target did not respond in time"
    if "ERR_CONNECTION_REFUSED" in text:
        return "target refused the connection"
    if "ERR_ABORTED" in text or "ERR_BLOCKED" in text:
        return "navigation was blocked by the URL guard"
    if "ERR_PROXY" in text:
        return "upstream proxy is unavailable"
    return "target could not be loaded"


def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for element in soup.find_all(STRIP_TAGS):
        element.decompose()
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    return str(soup)


def page_signals(html: str) -> dict:
    """Structural facts about the page that are safe to hand back to a caller."""
    soup = BeautifulSoup(html, "html.parser")
    inputs = soup.find_all("input")
    return {
        "forms": len(soup.find_all("form")),
        "password_inputs": sum(
            1 for i in inputs if (i.get("type") or "").lower() == "password"),
        "inputs": len(inputs),
        "links": len(soup.find_all("a")),
        "iframes": len(soup.find_all("iframe")),
    }
