# siteaudit

[![CI](https://github.com/AKPAN-THANKGOD/siteaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/AKPAN-THANKGOD/siteaudit/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

A fast, **zero-dependency** web security misconfiguration auditor. Point it at a site you own,
get prioritized findings with remediation advice, and plug the results straight into GitHub
code scanning via **SARIF**.

> ⚠️ **Authorized use only.** Scan systems you own or have written permission to test.
> Non-local targets require the explicit `--authorized` flag.

## Install

```bash
git clone https://github.com/AKPAN-THANKGOD/siteaudit && cd siteaudit
pip install -e .
```

## Usage

```bash
siteaudit http://localhost:8000                          # local targets need no flag
siteaudit https://staging.example.com --authorized       # remote targets do
siteaudit https://staging.example.com --authorized -f html -o report.html
siteaudit https://staging.example.com --authorized -f sarif -o results.sarif --fail-on high
siteaudit https://staging.example.com --authorized --checks headers,cookies
```

Exit codes: `0` clean (below `--fail-on`), `1` findings at/above threshold, `2` usage or
authorization error, `3` target unreachable.

## What it checks

| Check | Looks for |
|-------|-----------|
| `headers` | HSTS (presence, max-age), CSP quality (`unsafe-inline`/`unsafe-eval`, wildcards), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, COOP, version/technology disclosure |
| `cookies` | Missing `Secure` / `HttpOnly` / `SameSite`, `SameSite=None` without `Secure`; severity raised for session-like cookie names |
| `cors` | Reflected `Origin` (with/without credentials), `null` origin trust, wildcard ACAO |
| `exposed` | `.env`, `.git`, `.svn`, config backups, SQL dumps, backup archives, `phpinfo`, Spring actuator, `server-status`, `.DS_Store`, public API schema, missing `security.txt` |
| `tls` | No HTTP→HTTPS redirect, invalid certificate, expiring certificate, legacy protocol |

## Design decisions

- **Zero dependencies.** Built on `urllib`, `ssl` and `http.cookies`-style parsing, so it installs
  anywhere and has no supply-chain surface of its own.
- **Signature-based probes.** Exposed-file checks validate *content* (e.g. `.git/HEAD` must start
  with `ref:`), so apps that return 200 for every path don't generate false positives.
- **Reports never leak secrets.** When `/.env` is exposed, the report records status and size only,
  never the file's contents.
- **Safe by default.** Low request volume, `--delay` for rate limiting, an authorization gate for
  remote targets, and no exploitation: the tool only observes.
- **Fault isolation.** A crashing check is recorded as a warning and never aborts the audit.
- **Pluggable.** Add a check by writing one function with `@register("name")` in
  `src/siteaudit/checks/`.

## Use in CI (GitHub code scanning)

```yaml
- run: pip install siteaudit   # or: pip install .
- run: siteaudit https://staging.example.com --authorized -f sarif -o results.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

## Development

```bash
pip install -e ".[dev]"
pytest -q          # unit tests + integration tests against local throwaway servers
ruff check .
```

The integration tests spin up a deliberately vulnerable local server and a hardened one, then
assert the scanner finds the former's flaws and stays quiet on the latter.

## Limitations & roadmap

- Passive/light-touch only: not a replacement for a full DAST tool or manual testing.
- Planned: cookie prefix checks (`__Host-`), subresource integrity (SRI) check, CSP reporting
  endpoint detection, `--config` file with allow/deny rules, PyPI release, async probing.

## License

MIT
