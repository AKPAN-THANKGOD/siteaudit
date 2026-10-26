import time
import unittest

from siteaudit.checks import cookies, headers, tls
from siteaudit.core import Context
from siteaudit.http import Response
from siteaudit.models import Severity


def ctx(url="https://example.test/", hdrs=None):
    return Context(target=url, base=Response(url, 200, hdrs or [], b""))


def ids(findings):
    return {f.check_id for f in findings}


class HeaderTests(unittest.TestCase):
    def test_bare_response_flags_core_headers(self):
        found = ids(headers.run(ctx()))
        for expected in ("headers.hsts-missing", "headers.csp-missing",
                         "headers.clickjacking", "headers.nosniff-missing"):
            self.assertIn(expected, found)

    def test_hardened_response_has_no_low_or_higher(self):
        hdrs = [
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Server", "nginx"),
        ]
        bad = [f for f in headers.run(ctx(hdrs=hdrs)) if f.severity >= Severity.LOW]
        self.assertEqual(bad, [])

    def test_csp_unsafe_inline_without_nonce(self):
        hdrs = [("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")]
        self.assertIn("headers.csp-unsafe-inline", ids(headers.run(ctx(hdrs=hdrs))))

    def test_csp_unsafe_inline_ignored_with_nonce(self):
        hdrs = [("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'")]
        self.assertNotIn("headers.csp-unsafe-inline", ids(headers.run(ctx(hdrs=hdrs))))

    def test_short_hsts_and_version_disclosure(self):
        hdrs = [("Strict-Transport-Security", "max-age=60"), ("Server", "Apache/2.4.49")]
        found = ids(headers.run(ctx(hdrs=hdrs)))
        self.assertIn("headers.hsts-short", found)
        self.assertIn("headers.server-version", found)

    def test_hsts_not_required_on_http(self):
        found = ids(headers.run(ctx(url="http://example.test/")))
        self.assertNotIn("headers.hsts-missing", found)


class CookieTests(unittest.TestCase):
    def test_session_cookie_flags(self):
        found = {f.check_id: f for f in cookies.run(
            ctx(hdrs=[("Set-Cookie", "sessionid=abc; Path=/")]))}
        self.assertEqual(found["cookies.httponly-missing"].severity, Severity.MEDIUM)
        self.assertEqual(found["cookies.secure-missing"].severity, Severity.MEDIUM)
        self.assertIn("cookies.samesite-missing", found)

    def test_well_configured_cookie(self):
        hdrs = [("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")]
        self.assertEqual(cookies.run(ctx(hdrs=hdrs)), [])

    def test_samesite_none_requires_secure(self):
        hdrs = [("Set-Cookie", "pref=1; HttpOnly; SameSite=None")]
        self.assertIn("cookies.samesite-none-insecure", ids(cookies.run(ctx(hdrs=hdrs))))


class TlsHelperTests(unittest.TestCase):
    def test_days_until_expiry(self):
        now = time.time()
        future = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(now + 10 * 86400))
        past = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(now - 86400))
        self.assertAlmostEqual(tls.days_until_expiry({"notAfter": future}, now), 10, delta=0.01)
        self.assertLess(tls.days_until_expiry({"notAfter": past}, now), 0)


if __name__ == "__main__":
    unittest.main()
