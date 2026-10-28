"""Web Shield: a small HTTP/1.1 reverse proxy that validates, rate-limits and audits requests.

Deliberately simple and strict (limits stated in docs/architecture.md):
 * one request per connection (`Connection: close` both ways) -- no keep-alive, no pipelining;
 * request bodies need Content-Length; Transfer-Encoding requests are refused (501) which closes the
   classic request-smuggling surface; no CONNECT / absolute-form targets; no Upgrade/WebSocket;
 * client IP is the TCP peer address; forwarding headers from clients are discarded, never trusted;
 * TLS is NOT terminated here -- put it behind a TLS terminator or use an established proxy.
This is basic abuse control, not a full WAF: `block_patterns` are plain regexes over the request target.
"""
from __future__ import annotations

import asyncio
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

from protocolz_common.ratelimit import ConnectionCounter, TokenBucketLimiter

_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
        "transfer-encoding", "upgrade", "proxy-connection"}
_UNTRUSTED = {"x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-proto", "x-forwarded-host"}
_REASONS = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 408: "Request Timeout",
            413: "Payload Too Large", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
            501: "Not Implemented", 502: "Bad Gateway", 504: "Gateway Timeout"}


@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    origin_host: str = "127.0.0.1"
    origin_port: int = 8081
    rate: float = 20.0                  # requests/second per client IP
    burst: float = 40.0
    max_conns_per_ip: int = 50
    max_header_bytes: int = 16384
    max_headers: int = 100
    max_body_bytes: int = 1_048_576
    head_timeout: float = 10.0          # slow-header (slowloris) bound
    body_timeout: float = 15.0
    origin_timeout: float = 30.0
    allowed_methods: tuple = ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
    block_patterns: tuple = ()
    security_headers: dict = field(default_factory=lambda: {
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "no-referrer"})


class _Reject(Exception):
    def __init__(self, status: int, why: str):
        self.status, self.why = status, why


class ReverseProxy:
    def __init__(self, cfg: ProxyConfig, events=None, clock=None):
        self.cfg, self.events = cfg, events
        kw = {"clock": clock} if clock else {}
        self.limiter = TokenBucketLimiter(cfg.rate, cfg.burst, **kw)
        self.conns = ConnectionCounter(cfg.max_conns_per_ip)
        self.patterns = [re.compile(p) for p in cfg.block_patterns]
        self.stats: Counter = Counter()
        self.server = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, self.cfg.listen_host, self.cfg.listen_port,
                                                 limit=self.cfg.max_header_bytes)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    def _log(self, kind: str, ip: str, **kw) -> None:
        self.stats[kind] += 1
        if self.events:
            self.events.emit(f"proxy.{kind}", client=ip, **kw)

    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        if not self.conns.acquire(ip):
            self._log("conn_limit", ip)
            writer.close()
            return
        try:
            await self._serve(reader, writer, ip)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # never let one connection crash the server
            self._log("internal_error", ip, error=type(exc).__name__)
        finally:
            self.conns.release(ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _respond(self, writer, status: int, body: str = "", extra=()) -> None:
        data = body.encode()
        head = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}", "Content-Type: text/plain; charset=utf-8",
                f"Content-Length: {len(data)}", "Connection: close"]
        head += [f"{k}: {v}" for k, v in self.cfg.security_headers.items()]
        head += list(extra)
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + data)
        await writer.drain()

    def _parse(self, head: bytes):
        lines = head[:-4].split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) != 3:
            raise _Reject(400, "malformed request line")
        try:
            method, target, version = (p.decode("ascii") for p in parts)
        except UnicodeDecodeError:
            raise _Reject(400, "non-ascii request line") from None
        if method not in self.cfg.allowed_methods:
            raise _Reject(405, f"method {method[:16]!r} not allowed")
        if not target.startswith("/") or len(target) > 8192 or "\x00" in target:
            raise _Reject(400, "bad request target")
        if version not in ("HTTP/1.0", "HTTP/1.1"):
            raise _Reject(400, "unsupported HTTP version")
        if len(lines) - 1 > self.cfg.max_headers:
            raise _Reject(431, "too many headers")
        headers = []
        for raw in lines[1:]:
            name, sep, value = raw.partition(b":")
            if not sep or not _TOKEN.match(name):
                raise _Reject(400, "malformed header")  # also rejects obs-fold (leading whitespace)
            if b"\x00" in value:
                raise _Reject(400, "NUL in header")
            headers.append((name.decode("ascii"), value.strip().decode("latin-1")))
        names = [n.lower() for n, _ in headers]
        if "transfer-encoding" in names:
            raise _Reject(501, "Transfer-Encoding not supported")
        if version == "HTTP/1.1" and names.count("host") != 1:
            raise _Reject(400, "exactly one Host header required")
        length = 0
        if "content-length" in names:
            if names.count("content-length") != 1:
                raise _Reject(400, "duplicate Content-Length")
            raw_len = dict((n.lower(), v) for n, v in headers)["content-length"]
            if not (raw_len.isascii() and raw_len.isdigit()):
                raise _Reject(400, "invalid Content-Length")
            length = int(raw_len)
            if length > self.cfg.max_body_bytes:
                raise _Reject(413, "body too large")
        return method, target, headers, length

    async def _serve(self, reader, writer, ip: str) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.cfg.head_timeout)
        except asyncio.TimeoutError:
            self._log("head_timeout", ip)
            await self._respond(writer, 408, "request timeout")
            return
        except asyncio.LimitOverrunError:
            self._log("invalid", ip, why="headers too large")
            await self._respond(writer, 431, "headers too large")
            return
        self.stats["requests"] += 1
        if not self.limiter.allow(ip):  # charged before validation so invalid requests also cost tokens
            self._log("rate_limited", ip)
            await self._respond(writer, 429, "rate limit exceeded", ["Retry-After: 1"])
            return
        try:
            method, target, headers, length = self._parse(head)
            decoded = urllib.parse.unquote(target)
            for pat in self.patterns:
                if pat.search(target) or pat.search(decoded):
                    raise _Reject(403, "blocked by rule")
        except _Reject as rej:
            self._log("blocked" if rej.status == 403 else "invalid", ip, status=rej.status, why=rej.why)
            await self._respond(writer, rej.status, rej.why)
            return
        try:
            body = await asyncio.wait_for(reader.readexactly(length), self.cfg.body_timeout) if length else b""
        except asyncio.TimeoutError:
            self._log("body_timeout", ip)
            await self._respond(writer, 408, "request timeout")
            return
        await self._forward(writer, ip, method, target, headers, body)

    async def _forward(self, writer, ip, method, target, headers, body) -> None:
        try:
            oreader, owriter = await asyncio.wait_for(
                asyncio.open_connection(self.cfg.origin_host, self.cfg.origin_port, limit=65536), 5)
        except (OSError, asyncio.TimeoutError):
            self._log("bad_gateway", ip)
            await self._respond(writer, 502, "origin unavailable")
            return
        try:
            out = [f"{method} {target} HTTP/1.1"]
            out += [f"{n}: {v}" for n, v in headers if n.lower() not in _HOP | _UNTRUSTED | {"content-length"}]
            out += [f"X-Forwarded-For: {ip}", f"Content-Length: {len(body)}", "Connection: close"]
            owriter.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
            await owriter.drain()
            try:
                rhead = await asyncio.wait_for(oreader.readuntil(b"\r\n\r\n"), self.cfg.origin_timeout)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                self._log("bad_gateway", ip)
                await self._respond(writer, 502, "bad response from origin")
                return
            lines = rhead[:-4].split(b"\r\n")
            present = {l.split(b":", 1)[0].strip().lower() for l in lines[1:] if b":" in l}
            kept = [lines[0]] + [l for l in lines[1:] if l.split(b":", 1)[0].strip().lower() not in (b"connection", b"keep-alive")]
            for k, v in self.cfg.security_headers.items():
                if k.lower().encode() not in present:
                    kept.append(f"{k}: {v}".encode())
            kept.append(b"Connection: close")
            writer.write(b"\r\n".join(kept) + b"\r\n\r\n")
            while True:
                chunk = await asyncio.wait_for(oreader.read(65536), self.cfg.origin_timeout)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
            self.stats["forwarded"] += 1
        finally:
            owriter.close()
