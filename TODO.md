# data-min-scanner TODO

## Phase 1 (done 2026-09-28)
- [x] Scaffold scanner dir
- [x] Capture: read frontend pages, discover API calls, hit them, record JSON
- [x] Class B: sensitive field-name match
- [x] Class A: over-fetch (field not referenced in frontend corpus)
- [x] Score against over-exposed-web ground-truth.json (100/100, but same-target)
- [x] Update PRD artifact with build status + first score

## Real-target run (2026-09-29)
- [x] webapp3 Juice Shop with login: sensitive works (found real password/totpSecret leak), over-fetch degrades on minified bundle
- Conclusion: over-fetch needs runtime usage signal on SPA bundles; static grep too weak

## Later
- [ ] Runtime usage signal (which fields reach the rendered DOM) — the real fix for over-fetch on SPAs
- [ ] Casing normalization (snake/camel) for name transforms
- [ ] Value-based sensitive detection (entropy + Luhn/JWT/PEM regex) to complement name match
- [ ] --har mode (read a crawl HAR instead of own capture)
- [ ] Field allowlist + HAR import input
- [ ] Headless-browser capture for SPAs with dynamic URLs
