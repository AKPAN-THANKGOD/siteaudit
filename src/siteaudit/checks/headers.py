"""Security response header checks."""
from __future__ import annotations

import re

from ..core import Context, register
from ..models import Finding, Severity


def parse_csp(value: str) -> "dict[str, list[str]]":
    directives: "dict[str, list[str]]" = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = bits[1:]
    return directives


@register("headers")
def run(ctx: Context) -> "list[Finding]":
    r, url = ctx.base, ctx.target
    out: "list[Finding]" = []

    def add(slug, title, sev, desc, fix, evidence=""):
        out.append(Finding(f"headers.{slug}", title, sev, desc, fix, url, evidence))

    # --- HSTS (HTTPS only) ---
    if url.lower().startswith("https://"):
        hsts = r.header("strict-transport-security")
        if not hsts:
            add("hsts-missing", "Missing Strict-Transport-Security header", Severity.MEDIUM,
                "Without HSTS, browsers may be downgraded to HTTP by a network attacker.",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.")
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not m:
                add("hsts-invalid", "HSTS header has no max-age", Severity.MEDIUM,
                    "A policy without max-age is ignored by browsers.",
                    "Add a max-age of at least 15552000 (180 days).", hsts)
            elif int(m.group(1)) < 15_552_000:
                add("hsts-short", "HSTS max-age is short", Severity.LOW,
                    "A short max-age shrinks the window in which HSTS protects users.",
                    "Raise max-age to at least 15552000 (180 days); 1 year is common.", hsts)

    # --- CSP ---
    csp_raw = r.header("content-security-policy")
    csp = parse_csp(csp_raw) if csp_raw else {}
    if not csp_raw:
        add("csp-missing", "Missing Content-Security-Policy header", Severity.MEDIUM,
            "CSP is the main defence-in-depth control against XSS and data injection.",
            "Deploy a CSP, starting with `default-src 'self'` and tightening per resource type.")
    else:
        script_src = csp.get("script-src", csp.get("default-src"))
        if script_src is None:
            add("csp-no-script-restriction", "CSP does not restrict scripts", Severity.MEDIUM,
                "Neither script-src nor default-src is set, so scripts load from anywhere.",
                "Add `script-src 'self'` (plus nonces/hashes where needed).", csp_raw)
        else:
            has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            or s == "'strict-dynamic'" for s in script_src)
            if "'unsafe-inline'" in script_src and not has_nonce:
                add("csp-unsafe-inline", "CSP allows 'unsafe-inline' scripts", Severity.MEDIUM,
                    "'unsafe-inline' largely negates CSP's XSS protection.",
                    "Use nonces or hashes instead of 'unsafe-inline'.", csp_raw)
            if "'unsafe-eval'" in script_src:
                add("csp-unsafe-eval", "CSP allows 'unsafe-eval'", Severity.LOW,
                    "Permits eval()-style code execution, widening the XSS attack surface.",
                    "Remove 'unsafe-eval' and refactor code that depends on it.", csp_raw)
            if any(s in ("*", "data:", "http:") for s in script_src):
                add("csp-wildcard-source", "CSP allows scripts from overly broad sources",
                    Severity.MEDIUM,
                    "Wildcard, data: or http: sources let attackers host script anywhere.",
                    "List only the specific origins you trust.", csp_raw)

    # --- Clickjacking ---
    xfo = (r.header("x-frame-options") or "").upper()
    if "frame-ancestors" not in csp and xfo not in ("DENY", "SAMEORIGIN"):
        add("clickjacking", "No clickjacking protection", Severity.MEDIUM,
            "The page can be framed by any site, enabling UI-redress attacks.",
            "Send `Content-Security-Policy: frame-ancestors 'none'` (or 'self').")

    if (r.header("x-content-type-options") or "").lower() != "nosniff":
        add("nosniff-missing", "Missing X-Content-Type-Options: nosniff", Severity.LOW,
            "Browsers may MIME-sniff responses and execute content as an unexpected type.",
            "Send `X-Content-Type-Options: nosniff`.")

    if not r.header("referrer-policy"):
        add("referrer-policy-missing", "Missing Referrer-Policy header", Severity.LOW,
            "Full URLs (possibly containing tokens) may leak to third parties via Referer.",
            "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.")

    if not r.header("permissions-policy"):
        add("permissions-policy-missing", "Missing Permissions-Policy header", Severity.INFO,
            "Powerful browser features (camera, geolocation, ...) are not explicitly restricted.",
            "Send a Permissions-Policy that disables features you do not use.")

    if not r.header("cross-origin-opener-policy"):
        add("coop-missing", "Missing Cross-Origin-Opener-Policy header", Severity.INFO,
            "Without COOP the page shares a browsing context group with cross-origin windows.",
            "Send `Cross-Origin-Opener-Policy: same-origin` where compatible.")

    # --- Technology disclosure ---
    server = r.header("server")
    if server and re.search(r"\d+\.\d+", server):
        add("server-version", "Server header discloses a version number", Severity.LOW,
            "Version banners help attackers match the stack to known CVEs.",
            "Configure the server to emit only the product name, or remove the header.", server)
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        value = r.header(name)
        if value:
            add(f"disclosure-{name}", f"{name} header discloses technology", Severity.LOW,
                "Technology disclosure aids reconnaissance.",
                f"Remove the {name} header.", value)
    return out
