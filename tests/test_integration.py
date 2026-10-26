"""End-to-end tests against throwaway local HTTP servers."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from siteaudit.cli import main
from siteaudit.http import fetch
from siteaudit.report import render_html, render_json, render_sarif
from siteaudit.scanner import scan

LOCAL_CHECKS = ["headers", "cookies", "cors", "exposed"]


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        origin = self.headers.get("Origin")
        ctype, body = "text/html", b"<html>hello</html>"
        if self.path == "/.env":
            ctype, body = "text/plain", b"DB_PASSWORD=hunter2\nSECRET_KEY=abc\n"
        elif self.path == "/.git/HEAD":
            ctype, body = "text/plain", b"ref: refs/heads/main\n"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Set-Cookie", "sessionid=abc; Path=/")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HardenedHandler(BaseHTTPRequestHandler):
    """Returns 200 + HTML for every path (soft-404) to prove probes don't false-positive."""

    server_version = "nginx"  # stop BaseHTTPRequestHandler advertising its own version banner
    sys_version = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b"<html>ok</html>"
        self.send_response(200)
        for k, v in {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Set-Cookie": "sid=x; Secure; HttpOnly; SameSite=Lax",
            "Content-Length": str(len(body)),
        }.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln, cls.vuln_url = serve(VulnerableHandler)
        cls.safe, cls.safe_url = serve(HardenedHandler)

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.safe.shutdown()

    def run_scan(self, url):
        return scan(url, fetch(url), only=LOCAL_CHECKS)

    def test_vulnerable_server_findings(self):
        found = {f.check_id for f in self.run_scan(self.vuln_url).findings}
        for expected in ("exposed.env-file", "exposed.git-head",
                         "cors.reflected-origin-credentials", "cookies.httponly-missing",
                         "headers.csp-missing", "headers.server-version"):
            self.assertIn(expected, found)

    def test_secrets_are_never_in_report(self):
        result = self.run_scan(self.vuln_url)
        for render in (render_json, render_sarif, render_html):
            self.assertNotIn("hunter2", render(result))

    def test_hardened_server_has_no_actionable_findings(self):
        result = self.run_scan(self.safe_url)
        self.assertEqual([f.check_id for f in result.findings if int(f.severity) >= 1], [])
        self.assertEqual(result.errors, [])

    def test_sarif_is_valid_shape(self):
        doc = json.loads(render_sarif(self.run_scan(self.vuln_url)))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertTrue(run["results"])
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in run["results"]} <= rule_ids)

    def test_cli_exit_codes(self):
        self.assertEqual(main([self.vuln_url, "--checks", "headers,cookies"]), 1)
        self.assertEqual(main([self.safe_url, "--checks", "headers,cookies,cors,exposed"]), 0)
        self.assertEqual(main([self.vuln_url, "--fail-on", "none", "--checks", "headers"]), 0)

    def test_cli_refuses_remote_without_authorization(self):
        self.assertEqual(main(["https://example.com"]), 2)


if __name__ == "__main__":
    unittest.main()
