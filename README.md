# exposure-detector

A standalone scanner for data-minimization flaws in web APIs. It finds two things:

- **Over-fetch (Class A):** response fields the frontend never uses. Extra data
  on the wire widens the attack surface for no reason.
- **Sensitive exposure (Class B):** response fields whose name looks sensitive
  (password, token, ssn, hash, totp, ...), which no client should receive. This
  maps to OWASP API3:2023.

It logs in (optional), reads the frontend code, discovers the API calls, hits
them itself, and diffs each response against the frontend. Python stdlib only,
no ZAP and no browser.

## Usage

```sh
python3 data-min-scan.py URL [USERNAME] [PASSWORD] [options]
```

Examples:

```sh
# unauthenticated
python3 data-min-scan.py http://127.0.0.1:8000

# with a heuristic token login
python3 data-min-scan.py https://target admin@example.com secret
```

## Inputs

| Input | Required | Notes |
| --- | --- | --- |
| `URL` | Yes | The running app |
| `USERNAME PASSWORD` | No | Heuristic token login (tries common login shapes) |
| `--pages p1,p2` | No | Frontend pages to read (default `/`) |
| `--sensitive FILE` | No | Newline list of sensitive-name regexes (overrides default) |
| `--allow FILE` | No | Newline list of field names to ignore |
| `--ground-truth FILE` | No | `ground-truth.json` to score against |
| `--out FILE` | No | Findings JSON path (default `data-min-findings.json`) |

## Output

JSON at `--out` with `scan`, `findings[]` (`type`, `endpoint`, `field`,
`reason`, `severity`), `summary`, and `score` when a ground truth is given.

## Known limits

- Sensitive detection is name-based only. It does not inspect values, so a
  secret in an innocently-named field is missed. Value checks (entropy, Luhn,
  JWT shape) are a planned complement.
- Over-fetch uses a static grep of the frontend. On a large minified SPA bundle
  almost every field name matches somewhere, so it under-reports. The fix is a
  runtime signal (which fields reach the rendered DOM), not a bigger regex.
- Endpoint discovery reads literal API paths from the frontend. An app that
  builds URLs at runtime needs the deferred headless-browser capture.
