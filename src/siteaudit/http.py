"""Tiny HTTP layer on urllib (no third-party dependencies)."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "siteaudit/0.1 (authorized security audit)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


def _wrap(url: str, status: int, resp, max_bytes: int) -> Response:
    try:
        body = resp.read(max_bytes)
    except OSError:
        body = b""
    return Response(url=url, status=status, headers=list(resp.headers.items()), body=body)


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    verify: bool = True,
    max_bytes: int = 262_144,
) -> Response | None:
    """Fetch a URL. Returns None on connection/TLS failure; HTTP errors are returned as responses."""
    handlers: list = []
    if not verify:
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=insecure))
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _wrap(resp.geturl(), resp.status, resp, max_bytes)
    except urllib.error.HTTPError as err:
        try:
            return _wrap(url, err.code, err, max_bytes)
        finally:
            err.close()
    except (urllib.error.URLError, OSError, ValueError):
        return None