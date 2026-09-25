"""Fetch rendered HTML from live URLs with Playwright and save them as
standalone .html files, mirroring the layout of ai/markuplm/examples/.

Noise tags (script, style, svg, template, noscript) and HTML comments are
stripped by default, matching the preprocessing in the training notebooks.

Run with no arguments to be prompted for a URL, or pass them directly:

    python scripts/fetch_html.py https://example.com
    python scripts/fetch_html.py https://example.com --label phishing --out examples
    python scripts/fetch_html.py --urls-file links.txt --out fetched
    python scripts/fetch_html.py https://example.com --raw

To keep your own IP out of the target's logs, route the browser through a proxy
and confirm the egress address before scraping:

    python scripts/fetch_html.py --check-ip --proxy http://host:8080
    python scripts/fetch_html.py https://suspicious.example --tor

A proxy that cannot be reached fails the run; traffic never falls back to a
direct connection.

Requires:
    pip install playwright && playwright install chromium
"""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Comment

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36")

DEFAULT_STRIP_TAGS = ["script", "style", "svg", "template", "noscript"]

TOR_PROXY = "socks5://127.0.0.1:9050"
IP_CHECK_URL = "https://api.ipify.org?format=json"


def resolve_proxy(args):
    """Build Playwright's proxy dict, preferring flags over $FETCH_HTML_PROXY."""
    server = TOR_PROXY if args.tor else (args.proxy or os.environ.get("FETCH_HTML_PROXY"))
    if not server:
        return None
    proxy = {"server": server}
    username = args.proxy_username or os.environ.get("FETCH_HTML_PROXY_USER")
    password = args.proxy_password or os.environ.get("FETCH_HTML_PROXY_PASS")
    if username:
        # Chromium ignores credentials on SOCKS proxies; only http/https honour them.
        if server.startswith("socks"):
            sys.exit("Chromium does not support authentication on SOCKS proxies.\n"
                     "Use an http/https proxy, or an authless local SOCKS listener (e.g. Tor).")
        proxy["username"] = username
        proxy["password"] = password or ""
    return proxy


def slugify(netloc: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", netloc).strip("_").lower()
    return slug or "page"


def clean_html(html: str, strip_tags: list, strip_comments: bool) -> str:
    soup = BeautifulSoup(html, "html.parser")
    if strip_tags:
        for element in soup.find_all(strip_tags):
            element.decompose()
    if strip_comments:
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
    return str(soup)


def normalize(url: str) -> str:
    return url if urlsplit(url).scheme else "https://" + url


def collect_urls(args) -> list:
    urls = list(args.urls)
    if args.urls_file:
        for line in Path(args.urls_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        try:
            entered = input("URL: ").strip()
        except EOFError:
            entered = ""
        if entered:
            urls.append(entered)
    return [normalize(u) for u in urls]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("urls", nargs="*", help="One or more URLs to fetch")
    parser.add_argument("--urls-file", help="Text file with one URL per line (# comments allowed)")
    parser.add_argument("--out", default="fetched", help="Output directory (default: fetched)")
    parser.add_argument("--label", choices=["benign", "phishing"],
                        help="Write into <out>/<label>/ instead of <out>/ directly")
    parser.add_argument("--wait-until", default="load",
                        choices=["commit", "domcontentloaded", "load", "networkidle"],
                        help="Playwright navigation wait state (default: load)")
    parser.add_argument("--settle", type=float, default=1.5,
                        help="Extra seconds to wait after navigation for late JS (default: 1.5)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Navigation timeout in seconds (default: 30)")
    parser.add_argument("--screenshot", action="store_true",
                        help="Also save a full-page .png next to each .html")
    parser.add_argument("--headful", action="store_true",
                        help="Run a visible browser; helps on sites that block headless")
    parser.add_argument("--strip", nargs="*", default=DEFAULT_STRIP_TAGS, metavar="TAG",
                        help=f"Tags to remove (default: {' '.join(DEFAULT_STRIP_TAGS)})")
    parser.add_argument("--keep-comments", action="store_true",
                        help="Keep HTML comments instead of stripping them")
    parser.add_argument("--raw", action="store_true",
                        help="Save the page exactly as rendered, with no cleaning")
    parser.add_argument("--stdout", action="store_true",
                        help="Print the HTML to stdout instead of writing files")

    proxy_group = parser.add_argument_group("proxy / network privacy")
    proxy_group.add_argument("--proxy", metavar="URL",
                             help="Route all traffic through this proxy, e.g. "
                                  "http://host:8080 or socks5://127.0.0.1:9050. "
                                  "Falls back to $FETCH_HTML_PROXY")
    proxy_group.add_argument("--tor", action="store_true",
                             help=f"Shorthand for --proxy {TOR_PROXY} (needs a running Tor daemon)")
    proxy_group.add_argument("--proxy-username", metavar="USER",
                             help="Proxy username (http/https only); or $FETCH_HTML_PROXY_USER")
    proxy_group.add_argument("--proxy-password", metavar="PASS",
                             help="Proxy password (http/https only); or $FETCH_HTML_PROXY_PASS. "
                                  "Prefer the env var to keep it out of shell history")
    proxy_group.add_argument("--check-ip", action="store_true",
                             help="Print the egress IP before fetching, to confirm the proxy "
                                  "is really in use. Works with no URLs given")
    args = parser.parse_args()

    if args.tor and args.proxy:
        parser.error("--tor and --proxy are mutually exclusive")

    proxy = resolve_proxy(args)
    urls = collect_urls(args) if not (args.check_ip and not args.urls and not args.urls_file) else []
    if not urls and not args.check_ip:
        parser.error("no URLs given")

    try:
        from playwright.sync_api import Error as PlaywrightError, sync_playwright
    except ImportError:
        sys.exit("playwright is not installed. Run:\n"
                 "    pip install playwright\n"
                 "    playwright install chromium")

    out_dir = Path(args.out) / args.label if args.label else Path(args.out)
    if not args.stdout:
        out_dir.mkdir(parents=True, exist_ok=True)

    failures = []
    with sync_playwright() as playwright:
        try:
            # channel="chromium" is the full browser; the default headless shell is
            # fingerprinted and refused by many of the sites this dataset targets.
            browser = playwright.chromium.launch(
                channel="chromium",
                headless=not args.headful,
                proxy=proxy,
                args=["--disable-blink-features=AutomationControlled",
                      # WebRTC can reveal the real IP even behind a proxy.
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                      # Chromium otherwise chats with Google on every launch, which
                      # widens the footprint and, via phishing detection, can block
                      # the very pages this script exists to capture. A few
                      # browser-level connections survive these flags.
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
                      "--disable-features=OptimizationHints,NetworkTimeServiceQuerying,"
                      "MediaRouter,Translate,AutofillServerCommunication,"
                      "CertificateTransparencyComponentUpdater,"
                      "OptimizationGuideModelDownloading"])
        except PlaywrightError as exc:
            sys.exit(f"could not launch Chromium: {str(exc).splitlines()[0]}\n"
                     "If the browser is missing, run: playwright install chromium")
        context = browser.new_context(user_agent=CHROME_UA,
                                      viewport={"width": 1440, "height": 900},
                                      locale="en-US",
                                      ignore_https_errors=True,
                                      accept_downloads=False)
        page = context.new_page()
        # Phishing pages sometimes trigger auto-downloads or alert()/confirm()
        # popups; refuse the former and auto-dismiss the latter so a page never
        # writes a file to disk or blocks navigation waiting on a dialog.
        page.on("dialog", lambda dialog: dialog.dismiss())

        if args.check_ip:
            label = proxy["server"] if proxy else "direct connection (no proxy)"
            try:
                page.goto(IP_CHECK_URL, wait_until="load", timeout=args.timeout * 1000)
                print(f"egress IP via {label}: {page.inner_text('body').strip()}")
            except PlaywrightError as exc:
                sys.exit(f"IP check failed via {label}: {str(exc).splitlines()[0]}\n"
                         "The proxy is unreachable; no page was fetched.")

        for url in urls:
            try:
                response = page.goto(url, wait_until=args.wait_until,
                                     timeout=args.timeout * 1000)
                if args.settle:
                    page.wait_for_timeout(args.settle * 1000)
                html = page.content()
            except PlaywrightError as exc:
                failures.append((url, str(exc).splitlines()[0]))
                print(f"FAIL {url}: {str(exc).splitlines()[0]}", file=sys.stderr)
                continue

            status = response.status if response else "?"
            raw_size = len(html)
            if not args.raw:
                html = clean_html(html, args.strip, not args.keep_comments)

            if args.stdout:
                print(html)
                continue

            slug = slugify(urlsplit(page.url).netloc)
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
            dest = out_dir / f"{slug}_{digest}.html"
            dest.write_text(html, encoding="utf-8")
            if args.screenshot:
                page.screenshot(path=str(dest.with_suffix(".png")), full_page=True)
            size = (f"{len(html):,d} bytes" if args.raw
                    else f"{raw_size:,d} -> {len(html):,d} bytes")
            print(f"OK  [{status}] {size}  {page.title()!r} -> {dest}")

        browser.close()

    if failures:
        sys.exit(f"\n{len(failures)} of {len(urls)} URL(s) failed")


if __name__ == "__main__":
    main()
