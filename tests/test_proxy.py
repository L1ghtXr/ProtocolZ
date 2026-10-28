import asyncio
import http.server
import json
import threading
import unittest

from protocolz_dp.proxy import ProxyConfig, ReverseProxy


class Origin(http.server.BaseHTTPRequestHandler):
    def _reply(self, body=b""):
        data = json.dumps({"path": self.path, "xff": self.headers.get_all("X-Forwarded-For"),
                           "real_ip": self.headers.get("X-Real-IP"), "body_len": len(body),
                           "has_te": self.headers.get("Transfer-Encoding")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._reply()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self._reply(self.rfile.read(n))

    def log_message(self, *a):
        pass


async def raw(port, data: bytes, wait=5.0) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    try:
        return await asyncio.wait_for(r.read(), wait)
    finally:
        w.close()


def status(resp: bytes) -> int:
    return int(resp.split(b" ", 2)[1]) if resp else 0


def get(path="/", extra=""):
    return f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode()


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.oport = self.origin.server_address[1]

    async def asyncTearDown(self):
        self.origin.shutdown()
        self.origin.server_close()

    async def start(self, **kw):
        cfg = ProxyConfig(listen_port=0, origin_port=self.oport, **kw)
        proxy = ReverseProxy(cfg)
        port = await proxy.start()
        self.addAsyncCleanup(proxy.stop)
        return proxy, port

    async def test_forwards_and_adds_security_headers(self):
        _, port = await self.start()
        resp = await raw(port, get("/hello?a=1"))
        head, _, body = resp.partition(b"\r\n\r\n")
        self.assertEqual(status(resp), 200)
        self.assertIn(b"X-Content-Type-Options: nosniff", head)
        self.assertIn(b"Connection: close", head)
        self.assertEqual(json.loads(body)["path"], "/hello?a=1")

    async def test_spoofed_forwarding_headers_are_discarded(self):
        _, port = await self.start()
        resp = await raw(port, get("/", "X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\n"))
        seen = json.loads(resp.partition(b"\r\n\r\n")[2])
        self.assertEqual(seen["xff"], ["127.0.0.1"])
        self.assertIsNone(seen["real_ip"])

    async def test_post_body_is_forwarded(self):
        _, port = await self.start()
        body = b"x" * 5000
        resp = await raw(port, b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n" + body)
        self.assertEqual(json.loads(resp.partition(b"\r\n\r\n")[2])["body_len"], 5000)

    async def test_rate_limit_returns_429_with_retry_after(self):
        proxy, port = await self.start(rate=0.001, burst=3)
        codes = [status(await raw(port, get())) for _ in range(6)]
        self.assertEqual(codes, [200, 200, 200, 429, 429, 429])
        resp = await raw(port, get())
        self.assertIn(b"Retry-After: 1", resp)
        self.assertEqual(proxy.stats["rate_limited"], 4)

    async def test_request_smuggling_and_malformed_inputs_rejected(self):
        proxy, port = await self.start(rate=1000, burst=1000)
        cases = {
            "transfer-encoding": (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501),
            "dup content-length": (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", 400),
            "bad content-length": (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\n", 400),
            "no host": (b"GET / HTTP/1.1\r\n\r\n", 400),
            "two hosts": (b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400),
            "method": (b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n", 405),
            "absolute target": (b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
            "obs-fold": (b"GET / HTTP/1.1\r\nHost: x\r\n folded: y\r\n\r\n", 400),
            "bad version": (b"GET / HTTP/9.9\r\nHost: x\r\n\r\n", 400),
            "garbage line": (b"NOT-HTTP\r\n\r\n", 400),
            "body too big": (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n", 413),
        }
        for name, (data, want) in cases.items():
            self.assertEqual(status(await raw(port, data)), want, name)

    async def test_oversized_headers_431(self):
        _, port = await self.start(max_header_bytes=2048)
        self.assertEqual(status(await raw(port, get("/", "X-Pad: " + "a" * 5000 + "\r\n"))), 431)

    async def test_block_patterns_match_raw_and_decoded_target(self):
        proxy, port = await self.start(block_patterns=(r"\.\./", r"(?i)union\s+select"))
        self.assertEqual(status(await raw(port, get("/a/../etc/passwd"))), 403)

    async def test_encoded_traversal_blocked(self):
        _, port = await self.start(block_patterns=(r"\.\./",))
        self.assertEqual(status(await raw(port, get("/a/%2e%2e/etc"))), 403)
        self.assertEqual(status(await raw(port, get("/ok"))), 200)

    async def test_connection_limit_per_ip(self):
        proxy, port = await self.start(max_conns_per_ip=2)
        held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
        await asyncio.sleep(0.1)
        r, w = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(r.read(), 2), b"")  # closed immediately
        self.assertEqual(proxy.stats["conn_limit"], 1)
        for _, hw in held + [(r, w)]:
            hw.close()

    async def test_slowloris_header_timeout(self):
        proxy, port = await self.start(head_timeout=0.3)
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n")  # never finishes
        resp = await asyncio.wait_for(r.read(), 3)
        self.assertEqual(status(resp), 408)
        w.close()

    async def test_origin_down_gives_502(self):
        cfg = ProxyConfig(listen_port=0, origin_port=1)
        proxy = ReverseProxy(cfg)
        port = await proxy.start()
        self.addAsyncCleanup(proxy.stop)
        self.assertEqual(status(await raw(port, get())), 502)

    async def test_events_are_audited(self):
        import tempfile, pathlib
        from protocolz_common.events import EventLog
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(pathlib.Path(d) / "e.jsonl")
            proxy = ReverseProxy(ProxyConfig(listen_port=0, origin_port=self.oport, block_patterns=("secret",)), events=log)
            port = await proxy.start()
            self.addAsyncCleanup(proxy.stop)
            await raw(port, get("/secret"))
            rec = json.loads(log.path.read_text().splitlines()[0])
            self.assertEqual(rec["type"], "proxy.blocked")
            self.assertEqual(rec["client"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
