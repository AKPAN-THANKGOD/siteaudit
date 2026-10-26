"""Set-Cookie attribute checks."""
from __future__ import annotations

import re

from ..core import Context, register
from ..models import Finding, Severity

SENSITIVE = re.compile(r"(sess|sid|auth|token|jwt|login|remember)", re.I)


def parse_set_cookie(raw: str) -> "tuple[str, dict[str, str]]":
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: "dict[str, str]" = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


@register("cookies")
def run(ctx: Context) -> "list[Finding]":
    https = ctx.target.lower().startswith("https://")
    missing: "dict[str, list[str]]" = {"secure": [], "httponly": [], "samesite": [], "none": []}
    sensitive_missing: "dict[str, list[str]]" = {"secure": [], "httponly": []}

    for raw in ctx.base.header_all("set-cookie"):
        name, attrs = parse_set_cookie(raw)
        if not name:
            continue
        sensitive = bool(SENSITIVE.search(name))
        if https and "secure" not in attrs:
            missing["secure"].append(name)
            if sensitive:
                sensitive_missing["secure"].append(name)
        if "httponly" not in attrs:
            missing["httponly"].append(name)
            if sensitive:
                sensitive_missing["httponly"].append(name)
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            missing["samesite"].append(name)
        elif samesite == "none" and "secure" not in attrs:
            missing["none"].append(name)

    out: "list[Finding]" = []

    def add(slug, title, sev, desc, fix, names):
        if names:
            out.append(Finding(f"cookies.{slug}", title, sev, desc, fix, ctx.target,
                               "cookies: " + ", ".join(sorted(set(names)))))

    add("secure-missing", "Cookies set without the Secure flag",
        Severity.MEDIUM if sensitive_missing["secure"] else Severity.LOW,
        "Cookies without Secure can be sent over plain HTTP and intercepted.",
        "Add the Secure attribute.", missing["secure"])
    add("httponly-missing", "Cookies set without the HttpOnly flag",
        Severity.MEDIUM if sensitive_missing["httponly"] else Severity.LOW,
        "Script-readable cookies can be stolen via XSS.",
        "Add HttpOnly to cookies that JavaScript does not need to read.", missing["httponly"])
    add("samesite-missing", "Cookies set without a SameSite attribute", Severity.LOW,
        "Without SameSite, behaviour varies by browser and CSRF exposure may increase.",
        "Set SameSite=Lax (or Strict) explicitly.", missing["samesite"])
    add("samesite-none-insecure", "SameSite=None cookies without Secure", Severity.MEDIUM,
        "Browsers reject SameSite=None cookies that are not Secure.",
        "Add the Secure attribute or use SameSite=Lax.", missing["none"])
    return out
