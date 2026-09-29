#!/usr/bin/env python3
"""Interactive over-exposure detector.

Opens a real Chrome, you log in by hand, press y, then it re-drives the app with
your live session and reports:
  - over_fetch: API response fields the frontend never reads (needless exposure)
  - sensitive_exposure: fields whose name looks sensitive (password/token/ssn/...)

The usage signal comes from instrumenting fetch/XHR/JSON.parse and watching which
fields the app actually reads, so it holds up on minified SPA bundles where a
static grep does not.

Usage:
  python3 exposure-detect.py TARGET_URL [--routes '#/a,#/b'] [--out FILE]

Needs: python playwright + Chrome  (pip install playwright)
Env:   EXPOSE_HEADLESS=1  run headless (for targets that need no login)
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

# HIGH: credentials, secrets, keys, PII, security answers, privilege flags. Exposing
# any of these to a client is a real problem regardless of the app.
HIGH = [
    r"pass(word|wd|phrase)?", r"pwd", r"secret", r"token", r"api[_-]?key",
    r"private[_-]?key", r"client[_-]?secret", r"hash", r"salt", r"ssn",
    r"social[_-]?security", r"dob", r"date[_-]?of[_-]?birth", r"credit[_-]?card",
    r"cvv", r"iban", r"security[_-]?answer", r"security[_-]?question", r"encrypt",
    r"credential", r"client[_-]?id", r"totp", r"\botp\b", r"seed", r"mnemonic",
    r"is[_-]?admin", r"\brole\b", r"internal", r"debug",
]

# LOW: display and bookkeeping fields. Over-fetched, but low value to an attacker.
LOW = [
    r"created_?at", r"updated_?at", r"deleted_?at", r"deleted_?date", r"^id$",
    r"status", r"colou?r", r"image", r"icon", r"favicon", r"avatar", r"url$",
    r"^uri$", r"caption", r"title", r"^text$", r"subtitle", r"video", r"greeting",
    r"background", r"dismiss", r"^message$", r"^show", r"enabled", r"placeholder",
    r"label", r"speed", r"mapping", r"overlay", r"^link",
]

SENSITIVE = HIGH  # the sensitive-name check uses the HIGH list

_ASSET_RE = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|json)$", re.I)

# Installed before app code: wraps every JSON response (fetch + XHR) in a Proxy
# that records read field names into window.__used, and stashes raw responses.
INSTRUMENT_JS = r"""
(() => {
  window.__used = new Set();
  window.__responses = {};
  const origParse = JSON.parse;
  const isPlain = (v) => Array.isArray(v) || (v && Object.getPrototypeOf(v) === Object.prototype);
  const wrap = (obj) => {
    if (!isPlain(obj)) return obj;
    return new Proxy(obj, {
      get(t, prop, r) {
        const val = Reflect.get(t, prop, r);
        if (typeof prop === 'string' && prop !== 'then' && prop !== 'length' && !/^\d+$/.test(prop)) {
          window.__used.add(prop);
        }
        return isPlain(val) ? wrap(val) : val;
      },
    });
  };
  const stash = (u, data) => {
    try { window.__responses[new URL(u).pathname] = data; }
    catch (e) { window.__responses[u] = data; }
  };
  const origJson = Response.prototype.json;
  Response.prototype.json = function () {
    const u = this.url;
    return origJson.call(this).then((data) => { stash(u, data); return wrap(data); });
  };
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener('load', () => {
      try {
        const ct = this.getResponseHeader('content-type') || '';
        if (ct.includes('json') && this.responseText) stash(this.responseURL, origParse(this.responseText));
      } catch (e) { /* not json */ }
    });
    return origSend.apply(this, arguments);
  };
  JSON.parse = function (t, r) {
    const data = origParse.call(JSON, t, r);
    return isPlain(data) ? wrap(data) : data;
  };
})();
"""

def walk(obj, out):
    # Collect scalar leaf field names; traverse dicts and lists.
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                walk(v, out)
            else:
                out.add(k)
    elif isinstance(obj, list):
        for item in obj:
            walk(item, out)

def sensitive_hit(leaf):
    low = leaf.lower()
    for pat in SENSITIVE:
        if re.search(pat, low):
            return pat
    return None

def severity(leaf):
    # Rank an over-fetched field so the serious ones stand out from metadata noise.
    if sensitive_hit(leaf):
        return "high"
    low = leaf.lower()
    if any(re.search(p, low) for p in LOW):
        return "low"
    return "medium"

def is_api(path):
    # A captured JSON response worth analyzing: not a static asset (i18n bundles etc.).
    return not path.startswith("/assets") and not _ASSET_RE.search(path)

def sample_value(obj, leaf):
    # First scalar value found for this field name, so a high-risk leak can be shown.
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == leaf and not isinstance(v, (dict, list)):
                return v
            if isinstance(v, (dict, list)):
                got = sample_value(v, leaf)
                if got is not None:
                    return got
    elif isinstance(obj, list):
        for item in obj:
            got = sample_value(item, leaf)
            if got is not None:
                return got
    return None

def short(value, limit=80):
    text = value if isinstance(value, str) else json.dumps(value)
    return text if len(text) <= limit else text[:limit] + "..."

def analyze(responses, used):
    findings = []
    values = {}
    for ep, data in responses.items():
        if not is_api(ep):
            continue
        leaves = set()
        walk(data, leaves)
        for leaf in sorted(leaves):
            if leaf not in used:
                sev = severity(leaf)
                finding = {"type": "over_fetch", "endpoint": ep, "field": leaf, "severity": sev}
                if sev == "high":                       # capture the value only for high-risk
                    finding["value"] = sample_value(data, leaf)
                    values.setdefault(ep, {})[leaf] = finding["value"]
                findings.append(finding)
            matched = sensitive_hit(leaf)
            if matched:
                findings.append({"type": "sensitive_exposure", "endpoint": ep,
                                 "field": leaf, "matched": matched})
    by = {}
    for f in findings:
        slot = by.setdefault(f["endpoint"], {"over_fetch": [], "sensitive_exposure": []})
        slot[f["type"]].append(f["field"])
    summary = {
        "endpoints": len([e for e in responses if is_api(e)]),
        "over_fetch": sum(1 for f in findings if f["type"] == "over_fetch"),
        "sensitive_exposure": sum(1 for f in findings if f["type"] == "sensitive_exposure"),
    }
    return {"summary": summary, "by_endpoint": by, "values": values, "findings": findings}

def harvest(page, responses, used):
    cap = page.evaluate("() => ({responses: window.__responses, used: Array.from(window.__used)})")
    responses.update(cap.get("responses") or {})
    used.update(cap.get("used") or [])

def main():
    ap = argparse.ArgumentParser(description="Interactive over-exposure detector")
    ap.add_argument("url")
    ap.add_argument("--routes", default="", help="SPA hash routes to also visit, comma-separated")
    ap.add_argument("--out", default="exposure-findings.json")
    ap.add_argument("--settle", type=int, default=3000, help="ms to wait per page for XHRs")
    args = ap.parse_args()

    headless = os.environ.get("EXPOSE_HEADLESS", "").lower() in ("1", "true", "yes")
    routes = [r.strip() for r in args.routes.split(",") if r.strip()]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=headless)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(args.url, wait_until="domcontentloaded")

        print("\nA Chrome window is open at %s." % args.url)
        print("Log in there. When you are done, come back here.")
        try:
            input("Type y + Enter to start detection: ")
        except EOFError:
            pass  # piped input / no tty -> proceed

        # Instrument the session now, then re-drive with a fresh page in the same
        # (logged-in) context so responses and reads are captured.
        ctx.add_init_script(INSTRUMENT_JS)
        det = ctx.new_page()
        responses, used = {}, set()
        det.goto(args.url, wait_until="domcontentloaded", timeout=60000)
        det.wait_for_timeout(args.settle)
        harvest(det, responses, used)
        for route in routes:
            det.evaluate("(h) => { location.hash = h; }", route)
            det.wait_for_timeout(args.settle)
            harvest(det, responses, used)

        browser.close()

    result = analyze(responses, used)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    # Colorize only when writing to a terminal (skip when piped/redirected).
    tty = sys.stdout.isatty()
    yellow = "\033[1;33m" if tty else ""
    red = "\033[1;31m" if tty else ""
    dim = "\033[2m" if tty else ""
    reset = "\033[0m" if tty else ""

    # Tier every over-fetched field so serious exposure leads and metadata collapses.
    high_total = 0
    for ep in result["by_endpoint"]:
        tiers = {"high": [], "medium": [], "low": []}
        for field in result["by_endpoint"][ep]["over_fetch"]:
            tiers[severity(field)].append(field)
        high_total += len(tiers["high"])
        result["by_endpoint"][ep]["_tiers"] = tiers

    s = result["summary"]
    print("\n%d endpoint(s)  over-fetch: %d  (%s%d high-risk%s, review first)\n" %
          (s["endpoints"], s["over_fetch"], red, high_total, reset))
    for ep in sorted(result["by_endpoint"]):
        t = result["by_endpoint"][ep]["_tiers"]
        if not any(t.values()):
            continue
        print("%s%s%s" % (yellow, ep, reset))
        for field in t["high"]:
            val = result.get("values", {}).get(ep, {}).get(field)
            print("    %s! %s%s = %s%s%s" % (red, field, reset, dim, short(val), reset))
        for field in t["medium"]:
            print("      %s" % field)
        if t["low"]:
            print("    %s+%d low-value: %s%s" % (dim, len(t["low"]), ", ".join(t["low"]), reset))
        print("")
    print("findings written to %s" % args.out)

if __name__ == "__main__":
    main()
