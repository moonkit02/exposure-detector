# exposure-detector

Interactive scanner for data-minimization flaws: API response fields the frontend
never uses (**over-fetch**) and sensitive-named fields (**sensitive exposure**).

It opens a real browser, you log in by hand, then it re-drives the app with your
session and watches which response fields the app actually reads. Because it
watches real usage (not the source text), it holds up on minified SPA bundles
where a static scan does not.

## Requirements

Python 3 with Playwright and Chrome:

```sh
pip install playwright
```

Chrome is used via Playwright's `channel="chrome"`.

## Usage

```sh
python3 exposure-detect.py TARGET_URL [--routes '#/a,#/b'] [--out FILE] [--settle MS]
```

A real Chrome opens at the target. Log in there, then type `y` + Enter. It
re-drives the target (plus any `--routes`) with your session and prints findings.

- `--routes` — SPA hash routes to also visit so their calls fire (comma-separated).
- `--out` — findings JSON path (default `exposure-findings.json`).
- `--settle` — ms to wait per page for XHRs (default 3000).
- Env `EXPOSE_HEADLESS=1` — run headless (for targets that need no login).

## Output

Per endpoint, over-fetched fields are tiered by risk:

```
/api/account
    ! password_hash = $2y$10$...      high: credentials/secrets/PII/privilege (shown with value)
    ! ssn = 123-45-6789
      address                         medium: other over-fetched fields to review
      phone
    +3 low-value: created_at, id, ... low: metadata, collapsed
```

It also writes `exposure-findings.json`. That file contains the real leaked
values for high-risk fields, so **treat it as secrets** — it is gitignored;
delete it after use.

## How it works

Instruments `fetch` / `XMLHttpRequest` / `JSON.parse` in the page with a Proxy
that records which field names the app reads. `over-fetch = returned fields − read fields`.

## Scope and limits

- Needs a **JSON API** (SPA or API-backed). A server-rendered MPA (e.g. DVWA) has
  no JSON to analyze, so it finds nothing by design.
- **Coverage = pages driven.** Reach the data pages via `--routes`, or (planned) an
  integrated crawler / record mode.
- Tiers are **name heuristics** (`HIGH` / `LOW` lists at the top of the script);
  edit them to taste.
