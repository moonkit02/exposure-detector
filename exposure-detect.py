#!/usr/bin/env python3
"""Interactive over-exposure detector (main).

Opens a real Chrome, you log in by hand, press y, then it drives the app with
your live session and reports API response fields the frontend never reads
(over-fetch) plus sensitive-named fields, tiered by risk with the leaked value
shown for high-risk ones.

This file holds the field-comparison logic. The browser work lives in helpers/:
  helpers/login/session.py   - start Chrome, wait for login
  helpers/crawl/linkcrawl.py - drive routes, or crawl in-app links
  helpers/instrument.py      - the usage instrumentation

Usage:
  python3 exposure-detect.py TARGET_URL [--crawl] [--routes '#/a,#/b']
        [--max-pages N] [--settle MS] [--out FILE]

Needs: python playwright + Chrome  (pip install playwright)
Env:   EXPOSE_HEADLESS=1  run headless (targets that need no login)
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # make helpers importable
from helpers.login.session import start_chrome, wait_for_login
from helpers.crawl.linkcrawl import crawl, drive
from helpers.instrument import INSTRUMENT_JS

# HIGH: credentials, secrets, keys, PII, security answers, privilege flags.
HIGH = [
    r"pass(word|wd|phrase)?", r"pwd", r"secret", r"token", r"api[_-]?key",
    r"private[_-]?key", r"client[_-]?secret", r"hash", r"salt", r"ssn",
    r"social[_-]?security", r"dob", r"date[_-]?of[_-]?birth", r"credit[_-]?card",
    r"cvv", r"iban", r"security[_-]?answer", r"security[_-]?question", r"encrypt",
    r"credential", r"client[_-]?id", r"totp", r"\botp\b", r"seed", r"mnemonic",
    r"is[_-]?admin", r"\brole\b", r"internal", r"debug",
]

# LOW: display and bookkeeping fields, low value to an attacker.
LOW = [
    r"created_?at", r"updated_?at", r"deleted_?at", r"deleted_?date", r"^id$",
    r"status", r"colou?r", r"image", r"icon", r"favicon", r"avatar", r"url$",
    r"^uri$", r"caption", r"title", r"^text$", r"subtitle", r"video", r"greeting",
    r"background", r"dismiss", r"^message$", r"^show", r"enabled", r"placeholder",
    r"label", r"speed", r"mapping", r"overlay", r"^link",
]

SENSITIVE = HIGH  # the sensitive-name check uses the HIGH list

_ASSET_RE = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|json)$", re.I)

def sensitive_hit(leaf):
    low = leaf.lower()
    for pat in SENSITIVE:
        if re.search(pat, low):
            return pat
    return None

def severity(leaf):
    # Rank an over-fetched field so serious ones stand out from metadata noise.
    if sensitive_hit(leaf):
        return "high"
    low = leaf.lower()
    if any(re.search(p, low) for p in LOW):
        return "low"
    return "medium"

def is_api(path):
    # A captured JSON response worth analyzing: not a static asset.
    return not path.startswith("/assets") and not _ASSET_RE.search(path)

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

def sample_value(obj, leaf):
    # First scalar value found for this field name, to show a high-risk leak.
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
                if sev == "high":
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

def report(result, out_path):
    # Console: tier every over-fetched field, high-risk first with its value.
    tty = sys.stdout.isatty()
    yellow = "\033[1;33m" if tty else ""
    red = "\033[1;31m" if tty else ""
    dim = "\033[2m" if tty else ""
    reset = "\033[0m" if tty else ""

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
    print("findings written to %s" % out_path)

def main():
    ap = argparse.ArgumentParser(description="Interactive over-exposure detector")
    ap.add_argument("url")
    ap.add_argument("--crawl", action="store_true", help="auto-discover pages via in-app links")
    ap.add_argument("--routes", default="", help="SPA hash routes to visit, comma-separated")
    ap.add_argument("--max-pages", dest="max_pages", type=int, default=40)
    ap.add_argument("--settle", type=int, default=3000, help="ms to wait per page for XHRs")
    ap.add_argument("--out", default="exposure-findings.json")
    args = ap.parse_args()

    headless = os.environ.get("EXPOSE_HEADLESS", "").lower() in ("1", "true", "yes")
    routes = [r.strip() for r in args.routes.split(",") if r.strip()]

    pw, browser, ctx, _ = start_chrome(args.url, headless)
    if not headless:
        wait_for_login()
    ctx.add_init_script(INSTRUMENT_JS)  # instrument AFTER login, before driving
    if args.crawl:
        responses, used, visited = crawl(ctx, args.url, args.max_pages, args.settle)
        print("crawled %d page(s)" % len(visited))
    else:
        responses, used = drive(ctx, args.url, routes, args.settle)
    browser.close()
    pw.stop()

    result = analyze(responses, used)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    report(result, args.out)

if __name__ == "__main__":
    main()
