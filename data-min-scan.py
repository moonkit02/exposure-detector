#!/usr/bin/env python3
"""Data-minimization scanner (Phase 1).

Finds API response fields the frontend never uses (over-fetch, Class A) and
fields whose name looks sensitive (Class B). Standalone: it logs in (optional),
reads the frontend code, discovers the API calls, hits them itself, and diffs
each response against the frontend. No ZAP, no browser, stdlib only.

Detection is written blind to any target: Class A is purely structural (field
present in a response, not referenced in the frontend), and Class B matches
field names against a general sensitive-name list.

Usage:
  python3 data-min-scan.py URL [USERNAME] [PASSWORD] [options]

Accepted inputs:
  url                   the running app, e.g. https://target
  username password     optional creds for a heuristic token login
  --pages p1,p2         frontend pages to read (default "/")
  --sensitive FILE      newline list of sensitive-name regexes (optional)
  --allow FILE          newline list of field leaf names to ignore (optional)
  --ground-truth FILE   ground-truth.json to score against (optional)
  --out FILE            findings JSON path (default ./data-min-findings.json)

Output: JSON at --out with scan, findings[], summary, and score (if scored).
"""

import argparse
import datetime
import json
import re
import sys
import urllib.parse
import urllib.request

DEFAULT_SENSITIVE = [
    r"pass(word|wd)?", r"pwd", r"secret", r"token", r"api[_-]?key",
    r"private[_-]?key", r"hash", r"salt", r"ssn", r"social[_-]?security",
    r"dob", r"date[_-]?of[_-]?birth", r"credit[_-]?card", r"cvv",
    r"is[_-]?admin", r"role", r"internal", r"debug", r"totp",
]

# API path shapes to look for in the frontend when a call is not a literal
# fetch()/axios() (covers Angular/HttpClient and similar). ponytail: covers the
# common prefixes; an app with bespoke prefixes needs the browser-capture path.
API_PREFIX = re.compile(r"['\"](/(?:rest|api|graphql|v\d+)/[A-Za-z0-9_./\-]*)['\"]")

# Bearer token for authed capture, set once after login. ponytail: module-level
# so it does not thread through every call; the script is single-run.
AUTH_HEADER = {}

def http_get(url):
    # Return (status, body) or (None, "") on failure. Sends the auth header when
    # one is set, so authed endpoints return real data.
    headers = {"User-Agent": "data-min-scan"}
    headers.update(AUTH_HEADER)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except Exception as exc:
        print(f"warn: GET {url} failed: {exc}", file=sys.stderr)
        return None, ""

def post_json(url, body):
    # POST a JSON body, return the parsed JSON reply or None.
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "data-min-scan"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None

def extract_token(obj):
    # Pull a token out of common login-reply shapes.
    for path in (("authentication", "token"), ("token",), ("access_token",),
                 ("jwt",), ("data", "token"), ("accessToken",)):
        cur = obj
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                cur = None
                break
        if isinstance(cur, str) and cur:
            return cur
    return None

def login(base_url, user, password):
    # Heuristic token login: try common login endpoints and body shapes, keep
    # the first token that comes back. ponytail: bespoke auth needs an adapter.
    candidates = [
        ("/rest/user/login", {"email": user, "password": password}),
        ("/api/auth/login", {"username": user, "password": password}),
        ("/api/login", {"email": user, "password": password}),
        ("/login", {"username": user, "password": password}),
    ]
    for path, body in candidates:
        reply = post_json(base_url + path, body)
        if reply is None:
            continue
        token = extract_token(reply)
        if token:
            return token, path
    return None, None

def same_origin(base_url, url):
    a, b = urllib.parse.urlparse(base_url), urllib.parse.urlparse(url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)

def build_corpus(base_url, pages):
    # Concatenate reachable frontend code: inline scripts plus same-origin .js
    # bundles. External CDN scripts are skipped (not this app's usage).
    parts = []
    for page in pages:
        page_url = urllib.parse.urljoin(base_url + "/", page.lstrip("/"))
        status, html = http_get(page_url)
        if not html:
            continue
        parts.extend(re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I))
        for src in re.findall(r"<script[^>]*\bsrc=['\"]([^'\"]+)['\"]", html, re.I):
            js_url = urllib.parse.urljoin(page_url, src)
            if not same_origin(base_url, js_url):
                continue
            _, js = http_get(js_url)
            if js:
                parts.append(js)
    return "\n".join(parts)

def discover_api_urls(corpus, base_url, cap=80):
    # Endpoints the frontend calls: literal fetch/axios args plus any API-shaped
    # path string (Angular http.get, etc.). GET only, deduped, capped.
    paths = set(re.findall(r"(?:fetch|axios\.\w+|axios)\(\s*['\"]([^'\"]+)['\"]", corpus))
    paths.update(API_PREFIX.findall(corpus))
    urls = set()
    for path in paths:
        if any(c in path for c in "{}$"):  # skip obvious templates
            continue
        urls.add(urllib.parse.urljoin(base_url + "/", path.lstrip("/")))
    return sorted(urls)[:cap]

def capture_responses(api_urls):
    # Hit each endpoint, keep only 200s that parse as JSON. Identity is the path.
    responses = {}
    for url in api_urls:
        status, body = http_get(url)
        if status != 200 or not body:
            continue
        try:
            data = json.loads(body)
        except ValueError:
            continue
        responses[urllib.parse.urlparse(url).path] = data
    return responses

def walk_fields(obj, prefix=""):
    # Yield (json_path, leaf) for every scalar leaf; containers are traversed.
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (dict, list)):
                yield from walk_fields(value, path)
            else:
                yield path, key
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_fields(item, prefix + "[]")

def is_referenced(leaf, corpus):
    # True if the frontend appears to read this field. Biased to false negatives.
    e = re.escape(leaf)
    patterns = [
        r"\." + e + r"\b",
        r"\[\s*['\"]" + e + r"['\"]\s*\]",
        r"['\"]" + e + r"['\"]",
        r"[{,]\s*" + e + r"\s*[,}:]",
    ]
    return any(re.search(p, corpus) for p in patterns)

def sensitive_hit(leaf, patterns):
    low = leaf.lower()
    for pat in patterns:
        if re.search(pat, low):
            return pat
    return None

def scan(base_url, pages, sensitive_patterns, allow):
    corpus = build_corpus(base_url, pages)
    api_urls = discover_api_urls(corpus, base_url)
    responses = capture_responses(api_urls)
    findings = []
    for endpoint, data in responses.items():
        seen = set()
        for path, leaf in walk_fields(data):
            if (endpoint, leaf) in seen or leaf in allow:
                continue
            seen.add((endpoint, leaf))
            if not is_referenced(leaf, corpus):
                findings.append({
                    "type": "over_fetch", "endpoint": endpoint, "field": leaf,
                    "reason": "Returned in response, not referenced in the frontend",
                    "severity": "low",
                })
            matched = sensitive_hit(leaf, sensitive_patterns)
            if matched:
                findings.append({
                    "type": "sensitive_exposure", "endpoint": endpoint, "field": leaf,
                    "reason": "Field name matches the sensitive list",
                    "severity": "medium", "matched": matched,
                })
    summary = {
        "over_fetch": sum(1 for f in findings if f["type"] == "over_fetch"),
        "sensitive_exposure": sum(1 for f in findings if f["type"] == "sensitive_exposure"),
        "endpoints": len(responses),
    }
    scan_meta = {
        "base_url": base_url, "pages": pages,
        "endpoints": sorted(responses.keys()),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    return {"scan": scan_meta, "findings": findings, "summary": summary}

def score(findings, gt):
    found_of = {f"{f['endpoint']}:{f['field']}" for f in findings if f["type"] == "over_fetch"}
    found_se = {f"{f['endpoint']}:{f['field']}" for f in findings if f["type"] == "sensitive_exposure"}
    exp_of, exp_se = set(gt.get("over_fetch", [])), set(gt.get("sensitive", []))

    def rate(found, expected):
        tp = sorted(found & expected)
        fn = sorted(expected - found)
        fp = sorted(found - expected)
        return {
            "expected": len(expected), "found": len(found), "true_pos": len(tp),
            "false_neg": fn, "false_pos": fp,
            "recall": round(len(tp) / len(expected), 3) if expected else 1.0,
            "precision": round(len(tp) / len(found), 3) if found else 1.0,
        }

    return {"over_fetch": rate(found_of, exp_of), "sensitive": rate(found_se, exp_se)}

def read_lines(path):
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

def main():
    ap = argparse.ArgumentParser(description="Data-minimization scanner (Phase 1)")
    ap.add_argument("url")
    ap.add_argument("username", nargs="?")
    ap.add_argument("password", nargs="?")
    ap.add_argument("--pages", default="/")
    ap.add_argument("--sensitive")
    ap.add_argument("--allow")
    ap.add_argument("--ground-truth", dest="ground_truth")
    ap.add_argument("--out", default="data-min-findings.json")
    args = ap.parse_args()

    base_url = args.url.rstrip("/")
    if args.username and args.password:
        token, path = login(base_url, args.username, args.password)
        if token:
            AUTH_HEADER["Authorization"] = "Bearer " + token
            print(f"logged in via {path}, token captured")
        else:
            print("warn: login failed, continuing unauthenticated", file=sys.stderr)

    pages = [p.strip() for p in args.pages.split(",") if p.strip()]
    sensitive_patterns = read_lines(args.sensitive) if args.sensitive else DEFAULT_SENSITIVE
    allow = set(read_lines(args.allow)) if args.allow else set()

    result = scan(base_url, pages, sensitive_patterns, allow)

    if args.ground_truth:
        with open(args.ground_truth) as fh:
            result["score"] = score(result["findings"], json.load(fh))

    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)

    s = result["summary"]
    print(f"endpoints: {s['endpoints']}  over_fetch: {s['over_fetch']}  "
          f"sensitive: {s['sensitive_exposure']}")
    if result["scan"]["endpoints"]:
        print("captured:", ", ".join(result["scan"]["endpoints"]))
    if "score" in result:
        for cls in ("over_fetch", "sensitive"):
            r = result["score"][cls]
            print(f"{cls:12} recall={r['recall']} precision={r['precision']} "
                  f"FN={r['false_neg']} FP={r['false_pos']}")
    print(f"findings written to {args.out}")

if __name__ == "__main__":
    main()
