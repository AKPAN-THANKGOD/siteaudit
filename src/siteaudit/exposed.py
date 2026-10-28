"""Detect well-known sensitive files that should not be web-accessible.

Each probe validates the *content signature* of the response, so soft-404 pages that return
HTTP 200 for everything do not produce false positives. Evidence never includes file contents,
so reports cannot leak the secrets they discover.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

from ..core import Context, register
from ..http import Response, fetch
from ..models import Finding, Severity

_ENV_LINE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)


def _not_html(r: Response) -> bool:
    return b"<html" not in r.body[:512].lower()


@dataclass(frozen=True)
class Probe:
    slug: str
    path: str
    title: str
    severity: Severity
    matcher: Callable[[Response], bool]
    fix: str


PROBES = [
    Probe("env-file", "/.env", "Environment file exposed", Severity.CRITICAL,
          lambda r: _not_html(r) and bool(_ENV_LINE.search(r.body)),
          "Block dotfiles at the web server and rotate every secret in the file."),
    Probe("git-head", "/.git/HEAD", "Git repository exposed", Severity.HIGH,
          lambda r: r.body.startswith(b"ref:"),
          "Deny access to /.git and deploy build artifacts, not working copies."),
    Probe("svn-db", "/.svn/wc.db", "Subversion metadata exposed", Severity.HIGH,
          lambda r: r.body.startswith(b"SQLite format 3"),
          "Deny access to /.svn and deploy exports, not checkouts."),
    Probe("wp-config-backup", "/wp-config.php.bak", "WordPress config backup exposed",
          Severity.CRITICAL, lambda r: b"DB_PASSWORD" in r.body,
          "Delete backup files from the web root and rotate database credentials."),
    Probe("actuator-env", "/actuator/env", "Spring Boot actuator /env exposed", Severity.HIGH,
          lambda r: b"propertySources" in r.body,
          "Restrict actuator endpoints to an internal network or require authentication."),
    Probe("phpinfo", "/phpinfo.php", "phpinfo() page exposed", Severity.MEDIUM,
          lambda r: b"phpinfo()" in r.body or b"PHP Version" in r.body,
          "Remove phpinfo files from production."),
    Probe("server-status", "/server-status", "Apache server-status exposed", Severity.MEDIUM,
          lambda r: b"Apache Server Status" in r.body,
          "Restrict mod_status to localhost or an admin network."),
    Probe("backup-archive", "/backup.zip", "Backup archive exposed", Severity.HIGH,
          lambda r: r.body.startswith(b"PK\x03\x04"),
          "Remove backups from the web root; store them off-server."),
    Probe("sql-dump", "/backup.sql", "SQL dump exposed", Severity.HIGH,
          lambda r: _not_html(r) and bool(re.search(rb"(CREATE TABLE|INSERT INTO)", r.body)),
          "Remove database dumps from the web root; store them off-server."),
    Probe("ds-store", "/.DS_Store", ".DS_Store file exposed", Severity.LOW,
          lambda r: r.body.startswith(b"\x00\x00\x00\x01Bud1"),
          "Delete .DS_Store files and block dotfiles at the web server."),
    Probe("openapi-docs", "/openapi.json", "API schema publicly accessible", Severity.INFO,
          lambda r: b'"openapi"' in r.body[:2048] or b'"swagger"' in r.body[:2048],
          "Confirm the API schema is meant to be public; otherwise require authentication."),
]


@register("exposed")
def run(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for probe in PROBES:
        url = urljoin(ctx.target, probe.path)
        r = fetch(url, timeout=ctx.timeout, verify=ctx.verify, follow_redirects=False)
        if r is not None and r.status == 200 and probe.matcher(r):
            out.append(Finding(f"exposed.{probe.slug}", probe.title, probe.severity,
                               f"{probe.path} is served to unauthenticated clients.",
                               probe.fix, url, f"HTTP 200, {len(r.body)} bytes (content redacted)"))
        if ctx.delay:
            time.sleep(ctx.delay)

    sec_url = urljoin(ctx.target, "/.well-known/security.txt")
    r = fetch(sec_url, timeout=ctx.timeout, verify=ctx.verify, follow_redirects=False)
    if r is not None and not (r.status == 200 and b"Contact:" in r.body):
        out.append(Finding("exposed.security-txt-missing", "No security.txt published",
                           Severity.INFO,
                           "Researchers have no standard way to report vulnerabilities to you.",
                           "Publish /.well-known/security.txt (RFC 9116).", sec_url))
    return out