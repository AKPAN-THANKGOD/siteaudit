from __future__ import annotations

import html
import json
from collections import Counter

from .models import Severity
from .scanner import ScanResult

SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}


def render_text(result: ScanResult) -> str:
    lines = [f"siteaudit {result.version} - {result.target}", ""]
    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        lines.append(f"[{f.severity.name:<8}] {f.title}  ({f.check_id})")
        lines.append(f"           {f.description}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
        lines.append(f"           fix: {f.remediation}")
        lines.append("")
    counts = Counter(f.severity.name for f in result.findings)
    summary = ", ".join(f"{counts[s.name]} {s.name.lower()}"
                        for s in sorted(Severity, reverse=True) if counts[s.name]) or "clean"
    lines.append(f"Summary: {summary} | checks: {', '.join(result.checks_run)} "
                 f"| {result.duration:.1f}s")
    for err in result.errors:
        lines.append(f"warning: check error - {err}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "siteaudit", "version": result.version, "target": result.target,
        "duration_seconds": round(result.duration, 3), "checks_run": result.checks_run,
        "errors": result.errors, "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def render_sarif(result: ScanResult) -> str:
    rules: dict = {}
    results = []
    for f in result.findings:
        rules.setdefault(f.check_id, {
            "id": f.check_id, "name": f.check_id.replace(".", "-"),
            "shortDescription": {"text": f.title}, "help": {"text": f.remediation},
        })
        results.append({
            "ruleId": f.check_id, "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.description}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "siteaudit", "version": result.version,
                                      "rules": list(rules.values())}}, "results": results}],
    }, indent=2)


def render_html(result: ScanResult) -> str:
    e = html.escape
    rows = "".join(
        f'<article class="f {f.severity.name.lower()}"><h3><span class="b">{f.severity.name}</span> '
        f"{e(f.title)}</h3><p>{e(f.description)}</p>"
        + (f"<p class='ev'>Evidence: <code>{e(f.evidence)}</code></p>" if f.evidence else "")
        + f"<p><strong>Fix:</strong> {e(f.remediation)}</p><small>{e(f.check_id)}</small></article>"
        for f in result.findings
    ) or "<p>No findings.</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>siteaudit report - {e(result.target)}</title>
<style>
:root{{--bg:#fff;--fg:#1c1e21;--card:#f5f6f8;--bd:#d8dce2}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14161a;--fg:#e6e8eb;--card:#1e2126;--bd:#343a42}}}}
body{{font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:820px;margin:2rem auto;padding:0 1rem}}
.f{{background:var(--card);border:1px solid var(--bd);border-left-width:6px;border-radius:8px;padding:.75rem 1rem;margin:1rem 0}}
.critical{{border-left-color:#b00020}}.high{{border-left-color:#e53935}}.medium{{border-left-color:#fb8c00}}
.low{{border-left-color:#fbc02d}}.info{{border-left-color:#1e88e5}}
.b{{font-size:.7rem;padding:.1rem .45rem;border-radius:4px;border:1px solid var(--bd);vertical-align:middle}}
code{{word-break:break-all}}
</style></head><body>
<h1>siteaudit report</h1><p><strong>{e(result.target)}</strong><br>
{len(result.findings)} findings &middot; {result.duration:.1f}s &middot; v{e(result.version)}</p>
{rows}</body></html>"""


RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif, "html": render_html}