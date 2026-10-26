"""Transport security checks: HTTP->HTTPS redirect, certificate validity, protocol version."""
from __future__ import annotations

import socket
import ssl
import time
from typing import Optional
from urllib.parse import urlsplit

from ..core import Context, register
from ..http import fetch
from ..models import Finding, Severity


def days_until_expiry(cert: dict, now: Optional[float] = None) -> float:
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    return (expires - (now if now is not None else time.time())) / 86400


@register("tls")
def run(ctx: Context) -> "list[Finding]":
    parts = urlsplit(ctx.target)
    out: "list[Finding]" = []

    if parts.scheme == "http":
        r = fetch(ctx.target, follow_redirects=False, timeout=ctx.timeout)
        location = (r.header("location") if r else None) or ""
        if not (r and 300 <= r.status < 400 and location.lower().startswith("https://")):
            out.append(Finding(
                "tls.no-https", "Site served over plain HTTP without redirecting to HTTPS",
                Severity.MEDIUM,
                "Traffic, including credentials and cookies, can be read or modified in transit.",
                "Serve the site over HTTPS and redirect all HTTP requests (301) to it.",
                ctx.target))
        return out

    host, port = parts.hostname, parts.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert, version = tls.getpeercert(), tls.version()
    except ssl.SSLCertVerificationError as err:
        out.append(Finding("tls.certificate-invalid", "TLS certificate failed verification",
                           Severity.HIGH,
                           "Browsers will warn users, and clients cannot authenticate the server.",
                           "Install a valid certificate from a trusted CA that matches the hostname.",
                           ctx.target, str(err.verify_message)))
        return out
    except (OSError, ssl.SSLError):
        return out

    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        out.append(Finding("tls.legacy-protocol", f"Legacy protocol negotiated: {version}",
                           Severity.MEDIUM, "Deprecated protocols have known weaknesses.",
                           "Require TLS 1.2 or newer.", ctx.target, version))
    if cert and "notAfter" in cert:
        days = days_until_expiry(cert)
        if days < 14:
            sev = Severity.MEDIUM
        elif days < 30:
            sev = Severity.LOW
        else:
            return out
        out.append(Finding("tls.certificate-expiring", "TLS certificate expires soon", sev,
                           "An expired certificate causes outages and browser warnings.",
                           "Renew the certificate and automate renewal (e.g. ACME).",
                           ctx.target, f"{days:.0f} days remaining"))
    return out
