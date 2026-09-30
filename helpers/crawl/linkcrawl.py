"""Page drivers that record usage in the instrumented (logged-in) context.

drive  - visit the target plus given routes (hash routes for SPAs).
crawl  - BFS over same-origin in-app links to auto-discover pages.

Both harvest usage after every navigation (a full page load resets window, so we
merge per page) and return (responses, used).
"""
import re
from urllib.parse import urlparse

from helpers.instrument import harvest

_ASSET_RE = re.compile(
    r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|json|pdf|mp4|webm)$", re.I)

def _visit(page, url, settle_ms):
    # Navigate to a page. For a same-path hash link (SPA router) switch the hash
    # instead of a full load, so hash routes actually change the view.
    current = page.url.split("#")[0]
    if "#" in url:
        base, frag = url.split("#", 1)
        if base and current == base:
            page.evaluate("(h) => { location.hash = h; }", "#" + frag)
        else:
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
    else:
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
    page.wait_for_timeout(settle_ms)

def drive(ctx, url, routes, settle_ms=3000):
    # The target plus explicit routes. routes are hash fragments like '#/admin'.
    page = ctx.new_page()
    responses, used = {}, set()
    _visit(page, url, settle_ms)
    r, u = harvest(page)
    responses.update(r)
    used.update(u)
    for route in routes:
        _visit(page, url.split("#")[0] + route if route.startswith("#") else route, settle_ms)
        r, u = harvest(page)
        responses.update(r)
        used.update(u)
    page.close()
    return responses, used

def _in_app_links(page, base_host):
    # Same-origin, non-asset, non-logout links found on the current page.
    hrefs = page.evaluate("() => [...document.querySelectorAll('a[href]')].map(a => a.href)")
    out = []
    for href in hrefs:
        parsed = urlparse(href)
        if parsed.scheme not in ("http", "https") or parsed.hostname != base_host:
            continue
        if _ASSET_RE.search(parsed.path) or "logout" in href.lower():
            continue
        out.append(href)
    return out

def crawl(ctx, start_url, max_pages=40, settle_ms=3000):
    # BFS over in-app links, harvesting usage on every page. Returns
    # (responses, used, visited_urls).
    base_host = urlparse(start_url).hostname
    page = ctx.new_page()
    seen, queue = set(), [start_url]
    responses, used = {}, set()
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            _visit(page, url, settle_ms)
        except Exception:
            continue
        r, u = harvest(page)
        responses.update(r)
        used.update(u)
        for link in _in_app_links(page, base_host):
            if link not in seen and link not in queue:
                queue.append(link)
    page.close()
    return responses, used, sorted(seen)
