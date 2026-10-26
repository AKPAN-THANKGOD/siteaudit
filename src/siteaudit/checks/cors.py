"""CORS misconfiguration checks (reflected / null origins)."""
from __future__ import annotations

from ..core import Context, register
from ..http import fetch
from ..models import Finding, Severity

PROBE_ORIGIN = "https://siteaudit-probe.example"


@register("cors")
def run(ctx: Context) -> "list[Finding]":
    out: "list[Finding]" = []
    for index, origin in enumerate((PROBE_ORIGIN, "null")):
        r = fetch(ctx.target, headers={"Origin": origin}, timeout=ctx.timeout, verify=ctx.verify)
        if r is None:
            continue
        acao = r.header("access-control-allow-origin")
        creds = (r.header("access-control-allow-credentials") or "").lower() == "true"
        if acao == origin:
            label = "null origin" if origin == "null" else "arbitrary origin"
            out.append(Finding(
                "cors.reflected-origin-credentials" if creds else "cors.reflected-origin",
                f"CORS trusts any {label}" + (" with credentials" if creds else ""),
                Severity.HIGH if creds else Severity.MEDIUM,
                "The server echoes an attacker-controlled Origin back in "
                "Access-Control-Allow-Origin" + (", and allows credentials, so a malicious site "
                "can read authenticated responses." if creds else "."),
                "Validate Origin against a strict allow-list; never reflect it blindly.",
                ctx.target, f"Origin: {origin} -> ACAO: {acao}, ACAC: {creds}"))
        elif acao == "*" and index == 0:
            out.append(Finding(
                "cors.wildcard", "CORS allows all origins (*)",
                Severity.MEDIUM if creds else Severity.INFO,
                "Any site can read this response. Fine for public data, risky otherwise.",
                "Restrict to known origins if the response is not fully public.",
                ctx.target, f"ACAO: *, ACAC: {creds}"))
    return out
