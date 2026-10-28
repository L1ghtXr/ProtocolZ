"""Game Shield for Minecraft.

Java (TCP): validates the first packet is a well-formed Handshake before any byte reaches the
backend, limits new connections and logins per source IP, and caps concurrent connections.
Bedrock (UDP/RakNet): validates offline-message framing (magic, lengths), only lets valid
unconnected-ping / open-connection-request-1 datagrams create a session, and relays per-client sessions.

Limits (see docs): the shield cannot absorb more traffic than the host's uplink; legacy (pre-1.7)
Java pings are dropped; Bedrock has no PROXY protocol so the backend sees the shield's address
(firewall the backend to the shield); encryption/auth is never inspected or terminated.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass

from protocolz_common.ratelimit import ConnectionCounter, TokenBucketLimiter


class Incomplete(Exception):
    """Need more bytes."""


class ProtocolError(ValueError):
    """Bytes are not a valid Minecraft packet."""


def read_varint(buf: bytes, pos: int, max_bytes: int = 5):
    result = 0
    for i in range(max_bytes):
        if pos + i >= len(buf):
            raise Incomplete
        b = buf[pos + i]
        result |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return result, pos + i + 1
    raise ProtocolError("varint too long")


@dataclass(frozen=True)
class Handshake:
    protocol: int
    address: str
    port: int
    next_state: int  # 1 status, 2 login, 3 transfer
    consumed: int


def parse_java_handshake(buf: bytes, max_packet: int = 1024) -> Handshake:
    if buf[:1] == b"\xfe":
        raise ProtocolError("legacy ping not supported")
    length, pos = read_varint(buf, 0)
    if length < 4 or length > max_packet:
        raise ProtocolError(f"bad packet length {length}")
    end = pos + length
    if len(buf) > pos and buf[pos] != 0x00:  # reject early: packet id must be 0 (a 1-byte varint)
        raise ProtocolError("first packet must be Handshake (id 0)")
    if len(buf) < end:
        raise Incomplete
    body = buf[:end]

    def v(p):
        try:
            return read_varint(body, p)
        except Incomplete:
            raise ProtocolError("truncated packet") from None

    pid, p = v(pos)
    if pid != 0:
        raise ProtocolError("first packet must be Handshake (id 0)")
    protocol, p = v(p)
    slen, p = v(p)
    if slen > 767 or p + slen + 2 > end:
        raise ProtocolError("bad server address length")
    try:
        address = body[p:p + slen].decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("address is not UTF-8") from None
    if any(ord(c) < 32 and c != "\x00" for c in address):
        raise ProtocolError("control characters in address")
    p += slen
    port = int.from_bytes(body[p:p + 2], "big")
    p += 2
    state, p = v(p)
    if state not in (1, 2, 3):
        raise ProtocolError(f"bad next state {state}")
    if p != end:
        raise ProtocolError("trailing bytes inside handshake packet")
    if protocol >= 2 ** 32:
        raise ProtocolError("bad protocol version")
    return Handshake(protocol, address, port, state, end)


@dataclass
class JavaShieldConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 25565
    backend_host: str = "127.0.0.1"
    backend_port: int = 25566
    conn_rate: float = 5.0        # new connections/second per IP
    conn_burst: float = 10.0
    login_rate: float = 0.5       # login attempts/second per IP
    login_burst: float = 3.0
    max_conns_per_ip: int = 10
    handshake_timeout: float = 5.0
    idle_timeout: float = 300.0
    proxy_protocol_v1: bool = False  # tell the backend the real client IP (backend must trust only the shield)


class JavaShield:
    def __init__(self, cfg: JavaShieldConfig, events=None):
        self.cfg, self.events = cfg, events
        self.conn_limiter = TokenBucketLimiter(cfg.conn_rate, cfg.conn_burst)
        self.login_limiter = TokenBucketLimiter(cfg.login_rate, cfg.login_burst)
        self.conns = ConnectionCounter(cfg.max_conns_per_ip)
        self.stats: Counter = Counter()
        self.server = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, self.cfg.listen_host, self.cfg.listen_port)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    def _log(self, kind: str, ip: str, **kw) -> None:
        self.stats[kind] += 1
        if self.events:
            self.events.emit(f"minecraft.{kind}", client=ip, **kw)

    async def _read_handshake(self, reader):
        buf = b""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.cfg.handshake_timeout
        while True:
            try:
                return parse_java_handshake(buf), buf
            except Incomplete:
                pass
            if len(buf) > 1100:
                raise ProtocolError("handshake too large")
            chunk = await asyncio.wait_for(reader.read(1024), max(0.01, deadline - loop.time()))
            if not chunk:
                raise ConnectionError("closed before handshake")
            buf += chunk

    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        if not self.conns.acquire(ip):
            self._log("conn_limit", ip)
            writer.close()
            return
        try:
            if not self.conn_limiter.allow(ip):
                self._log("conn_rate_limited", ip)
                return
            try:
                hs, buf = await self._read_handshake(reader)
            except asyncio.TimeoutError:
                self._log("handshake_timeout", ip)
                return
            except ProtocolError as exc:
                self._log("invalid_handshake", ip, why=str(exc))
                return
            except ConnectionError:
                return
            if hs.next_state in (2, 3) and not self.login_limiter.allow(ip):
                self._log("login_rate_limited", ip)
                return
            await self._pipe(reader, writer, ip, peer, buf)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.conns.release(ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _pipe(self, reader, writer, ip, peer, first: bytes) -> None:
        try:
            breader, bwriter = await asyncio.wait_for(
                asyncio.open_connection(self.cfg.backend_host, self.cfg.backend_port), 5)
        except (OSError, asyncio.TimeoutError):
            self._log("backend_unavailable", ip)
            return
        try:
            if self.cfg.proxy_protocol_v1:
                local = writer.get_extra_info("sockname")
                fam = "TCP6" if ":" in ip else "TCP4"
                bwriter.write(f"PROXY {fam} {ip} {local[0]} {peer[1]} {local[1]}\r\n".encode())
            bwriter.write(first)
            await bwriter.drain()
            self.stats["proxied"] += 1

            async def copy(src, dst):
                while True:
                    data = await asyncio.wait_for(src.read(65536), self.cfg.idle_timeout)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()

            tasks = [asyncio.create_task(copy(reader, bwriter)), asyncio.create_task(copy(breader, writer))]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done:
                try:
                    t.result()
                except (ConnectionError, asyncio.TimeoutError):
                    pass
        finally:
            bwriter.close()


# ---------------------------------------------------------------------------------------- Bedrock
RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")


def classify_bedrock(data: bytes) -> str:
    """unconnected_ping | open_conn_1 | open_conn_2 | connected | invalid"""
    if not data or len(data) > 1500:
        return "invalid"
    pid = data[0]
    if pid in (0x01, 0x02):  # id + time(8) + magic(16) + guid(8)
        return "unconnected_ping" if len(data) == 33 and data[9:25] == RAKNET_MAGIC else "invalid"
    if pid == 0x05:  # id + magic(16) + protocol(1) + MTU padding
        return "open_conn_1" if len(data) >= 18 and data[1:17] == RAKNET_MAGIC else "invalid"
    if pid == 0x07:  # id + magic + address(7 or 29) + mtu(2) + guid(8)
        return "open_conn_2" if len(data) in (34, 56) and data[1:17] == RAKNET_MAGIC else "invalid"
    if pid & 0x80:  # datagram / ACK / NAK -- only meaningful inside an established session
        return "connected"
    return "invalid"


@dataclass
class BedrockShieldConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 19132
    backend_host: str = "127.0.0.1"
    backend_port: int = 19133
    new_session_rate: float = 2.0   # per IP per second
    new_session_burst: float = 5.0
    ping_rate: float = 5.0          # unconnected pings per IP per second
    ping_burst: float = 10.0
    max_sessions: int = 10_000
    idle_timeout: float = 30.0


class _Upstream(asyncio.DatagramProtocol):
    def __init__(self, relay, client):
        self.relay, self.client = relay, client

    def datagram_received(self, data, addr):
        s = self.relay.sessions.get(self.client)
        if s:
            s["last"] = asyncio.get_running_loop().time()
        self.relay.transport.sendto(data, self.client)


class BedrockRelay(asyncio.DatagramProtocol):
    def __init__(self, cfg: BedrockShieldConfig, events=None):
        self.cfg, self.events = cfg, events
        self.new_limiter = TokenBucketLimiter(cfg.new_session_rate, cfg.new_session_burst)
        self.ping_limiter = TokenBucketLimiter(cfg.ping_rate, cfg.ping_burst)
        self.sessions: dict = {}
        self.stats: Counter = Counter()
        self.transport = None
        self._sweeper = None

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=(self.cfg.listen_host, self.cfg.listen_port))
        self._sweeper = asyncio.create_task(self._sweep())
        return self.transport.get_extra_info("sockname")[1]

    async def stop(self) -> None:
        self._sweeper.cancel()
        for s in self.sessions.values():
            s["transport"] and s["transport"].close()
        self.sessions.clear()
        self.transport.close()

    def connection_made(self, transport):
        self.transport = transport

    def _log(self, kind, ip, **kw):
        self.stats[kind] += 1
        if self.events:
            self.events.emit(f"bedrock.{kind}", client=ip, **kw)

    async def _sweep(self):
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(max(0.05, self.cfg.idle_timeout / 4))
            now = loop.time()
            for client in [c for c, s in self.sessions.items() if now - s["last"] > self.cfg.idle_timeout]:
                s = self.sessions.pop(client)
                s["transport"] and s["transport"].close()

    def datagram_received(self, data, addr):
        ip = addr[0]
        kind = classify_bedrock(data)
        if kind == "invalid":
            self._log("invalid_datagram", ip)
            return
        if kind == "unconnected_ping" and not self.ping_limiter.allow(ip):
            self._log("ping_rate_limited", ip)
            return
        loop = asyncio.get_running_loop()
        sess = self.sessions.get(addr)
        if sess is None:
            if kind not in ("unconnected_ping", "open_conn_1"):
                self._log("no_session", ip, packet=kind)  # replayed/spoofed mid-session traffic
                return
            if len(self.sessions) >= self.cfg.max_sessions or not self.new_limiter.allow(ip):
                self._log("session_limited", ip)
                return
            sess = self.sessions[addr] = {"transport": None, "pending": [], "last": loop.time()}
            asyncio.create_task(self._open(addr, sess))
        sess["last"] = loop.time()
        if sess["transport"] is None:
            if len(sess["pending"]) < 8:
                sess["pending"].append(data)
        else:
            sess["transport"].sendto(data)
        self.stats["relayed"] += 1

    async def _open(self, client, sess):
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _Upstream(self, client), remote_addr=(self.cfg.backend_host, self.cfg.backend_port))
        except OSError:
            self.sessions.pop(client, None)
            return
        sess["transport"] = transport
        for d in sess["pending"]:
            transport.sendto(d)
        sess["pending"].clear()
