import hashlib
import hmac
import http.server
import json
import threading
import unittest

from protocolz_providers import MitigationRequest, ProviderError, WebhookProvider, build_provider

SECRET = b"s3cret"


class Receiver(http.server.BaseHTTPRequestHandler):
    calls = []
    mode = "ok"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        ts, sig = self.headers["X-ProtocolZ-Timestamp"], self.headers["X-ProtocolZ-Signature"]
        good = "sha256=" + hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        Receiver.calls.append((json.loads(body), hmac.compare_digest(sig, good)))
        if Receiver.mode == "500":
            self.send_response(500); self.send_header("Content-Length", "0"); self.end_headers(); return
        if Receiver.mode == "redirect":
            self.send_response(307); self.send_header("Location", "http://evil.invalid/"); self.send_header("Content-Length", "0"); self.end_headers(); return
        out = b"not json" if Receiver.mode == "badjson" else json.dumps({"handle": "h-1"} if Receiver.mode != "nohandle" else {}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

    def log_message(self, *a):
        pass


class WebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/hook"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        Receiver.calls.clear(); Receiver.mode = "ok"

    def prov(self, **kw):
        return WebhookProvider(self.url, SECRET, timeout=3, allow_insecure_loopback=True, **kw)

    def test_signed_mitigation_and_withdraw(self):
        p = self.prov()
        handle = p.request_mitigation(MitigationRequest("203.0.113.5", "udp flood", 600))
        self.assertEqual(handle, "h-1")
        p.withdraw(handle)
        (m, ok1), (w, ok2) = Receiver.calls
        self.assertTrue(ok1 and ok2)
        self.assertEqual(m, {"action": "mitigate", "target": "203.0.113.5", "reason": "udp flood", "ttl_seconds": 600})
        self.assertEqual(w, {"action": "withdraw", "handle": "h-1"})

    def test_error_paths(self):
        req = MitigationRequest("203.0.113.0/24", "x")
        for mode in ("500", "badjson", "nohandle", "redirect"):
            Receiver.mode = mode
            with self.assertRaises(ProviderError, msg=mode):
                self.prov().request_mitigation(req)

    def test_unreachable(self):
        p = WebhookProvider("http://127.0.0.1:1/x", SECRET, timeout=1, allow_insecure_loopback=True)
        with self.assertRaises(ProviderError):
            p.request_mitigation(MitigationRequest("203.0.113.5", "x"))

    def test_url_policy(self):
        for url, loop in (("http://example.com/x", True), ("http://127.0.0.1/x", False), ("ftp://x/y", True), ("https:///x", False)):
            with self.assertRaises(ProviderError, msg=url):
                WebhookProvider(url, SECRET, allow_insecure_loopback=loop)
        WebhookProvider("https://hooks.example.com/x", SECRET)

    def test_request_validation(self):
        for kw in ({"target": "not-an-ip"}, {"target": "1.2.3.4", "ttl_seconds": 5}, {"target": "1.2.3.4", "reason": "x" * 201}):
            with self.assertRaises(ProviderError):
                MitigationRequest(**{"reason": "r", **kw})

    def test_build_provider_requires_secret_env(self):
        cfg = {"url": self.url, "secret_env": "PZ_TEST_SECRET", "allow_insecure_loopback": True}
        with self.assertRaises(ProviderError):
            build_provider("webhook", cfg, environ={})
        self.assertIsInstance(build_provider("webhook", cfg, environ={"PZ_TEST_SECRET": "x"}), WebhookProvider)
        with self.assertRaises(ProviderError):
            build_provider("cloudflare", cfg, environ={})


if __name__ == "__main__":
    unittest.main()
