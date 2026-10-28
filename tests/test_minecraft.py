import asyncio
import unittest

from protocolz_dp.minecraft import (RAKNET_MAGIC, BedrockRelay, BedrockShieldConfig, Handshake, Incomplete,
                                    JavaShield, JavaShieldConfig, ProtocolError, classify_bedrock,
                                    parse_java_handshake, read_varint)


def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def handshake(addr="mc.example.org", port=25565, state=2, proto=765, pid=0) -> bytes:
    a = addr.encode()
    body = varint(pid) + varint(proto) + varint(len(a)) + a + port.to_bytes(2, "big") + varint(state)
    return varint(len(body)) + body


class VarintTests(unittest.TestCase):
    def test_known_values(self):
        for n, enc in ((0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"), (25565, b"\xdd\xc7\x01"),
                       (2147483647, b"\xff\xff\xff\xff\x07")):
            self.assertEqual(read_varint(enc, 0), (n, len(enc)))
            self.assertEqual(varint(n), enc)

    def test_incomplete_and_too_long(self):
        with self.assertRaises(Incomplete):
            read_varint(b"\x80", 0)
        with self.assertRaises(ProtocolError):
            read_varint(b"\x80\x80\x80\x80\x80\x01", 0)


class HandshakeParseTests(unittest.TestCase):
    def test_valid(self):
        data = handshake()
        hs = parse_java_handshake(data + b"extra login bytes")
        self.assertEqual(hs, Handshake(765, "mc.example.org", 25565, 2, len(data)))

    def test_incomplete_at_every_prefix(self):
        data = handshake()
        for i in range(len(data)):
            with self.assertRaises(Incomplete, msg=i):
                parse_java_handshake(data[:i])

    def test_invalid_variants(self):
        bad = {
            "wrong packet id": handshake(pid=1),
            "bad state 0": handshake(state=0),
            "bad state 4": handshake(state=4),
            "zero length": b"\x00",
            "huge length": varint(100000) + b"x" * 10,
            "legacy ping": b"\xfe\x01\xfa",
            "http garbage": b"GET / HTTP/1.1\r\n\r\n",
            "control chars": handshake(addr="a\x01b"),
            "trailing in packet": varint(len(handshake()) - 1 + 1)[:0] + (lambda h: varint(len(h[1:]) + 1) + h[1:] + b"\x00")(handshake()),
            "non-utf8 addr": (lambda body: varint(len(body)) + body)(
                varint(0) + varint(765) + varint(2) + b"\xff\xfe" + (25565).to_bytes(2, "big") + varint(1)),
            "addr length lies": (lambda body: varint(len(body)) + body)(
                varint(0) + varint(765) + varint(200) + b"abc" + (25565).to_bytes(2, "big") + varint(1)),
        }
        for name, data in bad.items():
            with self.assertRaises((ProtocolError, Incomplete), msg=name) as cm:
                parse_java_handshake(data)
            if name != "huge length":
                self.assertIsInstance(cm.exception, ProtocolError, name)

    def test_forge_marker_allowed(self):
        self.assertEqual(parse_java_handshake(handshake(addr="host\x00FML\x00")).address, "host\x00FML\x00")


class BackendCapture:
    """Minimal TCP backend recording what it receives; replies with b'BACKEND'."""

    def __init__(self):
        self.received = []
        self.server = None

    async def start(self):
        async def handle(r, w):
            data = await asyncio.wait_for(r.read(4096), 3)
            self.received.append(data)
            w.write(b"BACKEND")
            await w.drain()
            w.close()

        self.server = await asyncio.start_server(handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def talk(port, data: bytes, wait=2.0) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    try:
        return await asyncio.wait_for(r.read(), wait)
    except ConnectionError:  # RST: server rejected us before reading our bytes -- counts as "closed"
        return b""
    except asyncio.TimeoutError:
        return b"<timeout>"
    finally:
        w.close()


class JavaShieldTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = BackendCapture()
        self.bport = await self.backend.start()
        self.addAsyncCleanup(self.backend.stop)

    async def shield(self, **kw):
        s = JavaShield(JavaShieldConfig(listen_port=0, backend_port=self.bport, **kw))
        port = await s.start()
        self.addAsyncCleanup(s.stop)
        return s, port

    async def test_valid_handshake_is_proxied_with_buffered_bytes(self):
        s, port = await self.shield()
        resp = await talk(port, handshake(state=1) + b"\x01\x00")
        self.assertEqual(resp, b"BACKEND")
        self.assertEqual(self.backend.received[0], handshake(state=1) + b"\x01\x00")
        self.assertEqual(s.stats["proxied"], 1)

    async def test_split_handshake_is_reassembled(self):
        s, port = await self.shield()
        data = handshake()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(data[:5]); await w.drain(); await asyncio.sleep(0.1)
        w.write(data[5:]); await w.drain()
        self.assertEqual(await asyncio.wait_for(r.read(), 2), b"BACKEND")
        w.close()

    async def test_invalid_traffic_never_reaches_backend(self):
        s, port = await self.shield(conn_rate=1000, conn_burst=1000)
        for junk in (b"GET / HTTP/1.1\r\n\r\n", b"\xfe\x01\xfa", handshake(pid=7), b"\xff" * 2000):
            self.assertEqual(await talk(port, junk), b"")
        self.assertEqual(self.backend.received, [])
        self.assertGreaterEqual(s.stats["invalid_handshake"], 4)

    async def test_handshake_timeout(self):
        s, port = await self.shield(handshake_timeout=0.3)
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"\x10")  # starts a packet and stalls
        self.assertEqual(await asyncio.wait_for(r.read(), 3), b"")
        self.assertEqual(s.stats["handshake_timeout"], 1)
        w.close()

    async def test_connection_rate_limit(self):
        s, port = await self.shield(conn_rate=0.001, conn_burst=2, login_burst=100, login_rate=100)
        results = [await talk(port, handshake(state=1)) for _ in range(4)]
        self.assertEqual(results, [b"BACKEND", b"BACKEND", b"", b""])
        self.assertEqual(s.stats["conn_rate_limited"], 2)

    async def test_login_rate_limit_is_separate_from_status_pings(self):
        s, port = await self.shield(conn_rate=1000, conn_burst=1000, login_rate=0.001, login_burst=1)
        self.assertEqual(await talk(port, handshake(state=2)), b"BACKEND")
        self.assertEqual(await talk(port, handshake(state=2)), b"")      # 2nd login blocked
        self.assertEqual(await talk(port, handshake(state=1)), b"BACKEND")  # status still fine
        self.assertEqual(s.stats["login_rate_limited"], 1)

    async def test_concurrent_connection_cap(self):
        s, port = await self.shield(max_conns_per_ip=1, handshake_timeout=5)
        held_r, held_w = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        self.assertEqual(await talk(port, handshake()), b"")
        self.assertEqual(s.stats["conn_limit"], 1)
        held_w.close()

    async def test_proxy_protocol_v1_header(self):
        s, port = await self.shield(proxy_protocol_v1=True)
        await talk(port, handshake(state=1))
        first_line = self.backend.received[0].split(b"\r\n", 1)[0]
        self.assertTrue(first_line.startswith(b"PROXY TCP4 127.0.0.1 127.0.0.1 "), first_line)
        self.assertTrue(self.backend.received[0].endswith(handshake(state=1)))

    async def test_backend_down_closes_client(self):
        s = JavaShield(JavaShieldConfig(listen_port=0, backend_port=1))
        port = await s.start()
        self.addAsyncCleanup(s.stop)
        self.assertEqual(await talk(port, handshake()), b"")
        self.assertEqual(s.stats["backend_unavailable"], 1)


def ping(n=33):
    return b"\x01" + b"\x00" * 8 + RAKNET_MAGIC + b"\x00" * 8


class BedrockClassifyTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_bedrock(ping()), "unconnected_ping")
        self.assertEqual(classify_bedrock(b"\x05" + RAKNET_MAGIC + b"\x0b" + b"\x00" * 400), "open_conn_1")
        self.assertEqual(classify_bedrock(b"\x07" + RAKNET_MAGIC + b"\x00" * 17), "open_conn_2")
        self.assertEqual(classify_bedrock(b"\x84\x00\x00\x00"), "connected")
        for bad in (b"", b"\x01", b"\x01" + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 8, b"\x05" + b"\x00" * 30,
                    b"\x07" + RAKNET_MAGIC + b"\x00" * 3, b"\x42" * 100, b"\x01" * 2000, b"GET / HTTP/1.1"):
            self.assertEqual(classify_bedrock(bad), "invalid", bad[:20])


class Client(asyncio.DatagramProtocol):
    def __init__(self):
        self.q = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.q.put_nowait(data)


class Backend(asyncio.DatagramProtocol):
    def __init__(self):
        self.got = []

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.got.append(data)
        self.t.sendto(b"PONG:" + data[:1], addr)


class BedrockRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        self.be = Backend()
        bt, _ = await loop.create_datagram_endpoint(lambda: self.be, local_addr=("127.0.0.1", 0))
        self.addAsyncCleanup(lambda: bt.close())
        self.bport = bt.get_extra_info("sockname")[1]

    async def relay(self, **kw):
        r = BedrockRelay(BedrockShieldConfig(listen_port=0, backend_port=self.bport, **kw))
        port = await r.start()
        self.addAsyncCleanup(r.stop)
        loop = asyncio.get_running_loop()
        c = Client()
        ct, _ = await loop.create_datagram_endpoint(lambda: c, remote_addr=("127.0.0.1", port))
        self.addCleanup(ct.close)
        return r, ct, c

    async def recv(self, c, wait=1.0):
        try:
            return await asyncio.wait_for(c.q.get(), wait)
        except asyncio.TimeoutError:
            return None

    async def test_valid_ping_gets_backend_reply(self):
        r, ct, c = await self.relay()
        ct.sendto(ping())
        self.assertEqual(await self.recv(c), b"PONG:\x01")
        self.assertEqual(self.be.got, [ping()])

    async def test_invalid_datagrams_dropped(self):
        r, ct, c = await self.relay()
        for junk in (b"\x01\x02\x03", b"hello", b"\x42" * 50):
            ct.sendto(junk)
        self.assertIsNone(await self.recv(c, 0.4))
        self.assertEqual(self.be.got, [])
        self.assertEqual(r.stats["invalid_datagram"], 3)

    async def test_connected_traffic_without_session_is_dropped(self):
        r, ct, c = await self.relay()
        ct.sendto(b"\x84\x00\x00\x00")
        self.assertIsNone(await self.recv(c, 0.4))
        self.assertEqual(r.stats["no_session"], 1)

    async def test_session_carries_connected_traffic_after_open(self):
        r, ct, c = await self.relay()
        ct.sendto(b"\x05" + RAKNET_MAGIC + b"\x0b" + b"\x00" * 100)
        self.assertEqual(await self.recv(c), b"PONG:\x05")
        ct.sendto(b"\x84\x01\x02\x03")
        self.assertEqual(await self.recv(c), b"PONG:\x84")

    async def test_ping_rate_limit(self):
        r, ct, c = await self.relay(ping_rate=0.001, ping_burst=2)
        for _ in range(6):
            ct.sendto(ping())
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.2)
        self.assertEqual(len(self.be.got), 2)
        self.assertEqual(r.stats["ping_rate_limited"], 4)

    async def test_idle_sessions_are_swept(self):
        r, ct, c = await self.relay(idle_timeout=0.2)
        ct.sendto(ping())
        await self.recv(c)
        self.assertEqual(len(r.sessions), 1)
        await asyncio.sleep(0.6)
        self.assertEqual(len(r.sessions), 0)


if __name__ == "__main__":
    unittest.main()
