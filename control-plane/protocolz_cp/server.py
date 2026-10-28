"""Stdlib HTTP/JSON API + static dashboard. Serves plain HTTP: run it on loopback behind a TLS terminator."""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .service import CPError, ControlPlane, Invalid

MAX_BODY = 65536
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class Ctx:
    def __init__(self, body, match, query, ip):
        self.body, self.match, self.query, self.ip = body, match, query, ip
        self.actor = None
        self.node_id = None
        self.token = ""


def _field(body, name, default=None):
    if not isinstance(body, dict):
        raise Invalid("JSON object expected")
    return body.get(name, default)


def build_routes():
    R = []

    def route(method, pattern, kind="user"):
        def deco(fn):
            R.append((method, re.compile(pattern), kind, fn))
            return fn
        return deco

    @route("GET", r"/healthz", "public")
    def _health(cp, x):
        return 200, {"ok": True}

    @route("POST", r"/api/login", "public")
    def _login(cp, x):
        return 200, cp.login(_field(x.body, "username"), _field(x.body, "password"), _field(x.body, "otp"), x.ip)

    @route("POST", r"/api/logout")
    def _logout(cp, x):
        cp.logout(x.token)
        return 200, {"ok": True}

    @route("GET", r"/api/me")
    def _me(cp, x):
        return 200, x.actor

    @route("POST", r"/api/totp/enroll")
    def _te(cp, x):
        return 200, cp.totp_enroll(x.actor)

    @route("POST", r"/api/totp/confirm")
    def _tc(cp, x):
        cp.totp_confirm(x.actor, _field(x.body, "code"))
        return 200, {"ok": True}

    @route("GET", r"/api/tenants")
    def _tl(cp, x):
        return 200, cp.list_tenants(x.actor)

    @route("POST", r"/api/tenants")
    def _tn(cp, x):
        return 201, cp.create_tenant(x.actor, _field(x.body, "name"))

    @route("POST", r"/api/users")
    def _un(cp, x):
        return 201, cp.create_user(x.actor, _field(x.body, "username"), _field(x.body, "password"),
                                   _field(x.body, "role"), _field(x.body, "tenant_id"))

    @route("GET", r"/api/assets")
    def _al(cp, x):
        return 200, cp.list_assets(x.actor)

    @route("POST", r"/api/assets")
    def _an(cp, x):
        return 201, cp.create_asset(x.actor, _field(x.body, "name"), _field(x.body, "kind"),
                                    _field(x.body, "address"), _field(x.body, "tenant_id"))

    @route("DELETE", r"/api/assets/(\d+)")
    def _ad(cp, x):
        cp.delete_asset(x.actor, int(x.match.group(1)))
        return 200, {"ok": True}

    @route("GET", r"/api/providers")
    def _pl(cp, x):
        return 200, cp.list_providers(x.actor)

    @route("POST", r"/api/providers")
    def _pn(cp, x):
        return 201, cp.register_provider(x.actor, _field(x.body, "name"), _field(x.body, "kind"),
                                         _field(x.body, "config"))

    @route("GET", r"/api/nodes")
    def _nl(cp, x):
        return 200, cp.list_nodes(x.actor)

    @route("POST", r"/api/nodes")
    def _nn(cp, x):
        return 201, cp.register_node(x.actor, _field(x.body, "name"), _field(x.body, "region"),
                                     _field(x.body, "tenant_id"))

    @route("PUT", r"/api/nodes/(n_[0-9a-f]{16})/policy")
    def _np(cp, x):
        return 200, cp.set_node_policy(x.actor, x.match.group(1), _field(x.body, "policy"))

    @route("GET", r"/api/events")
    def _el(cp, x):
        return 200, cp.list_events(x.actor, _int(x.query.get("limit", ["100"])[0]))

    @route("GET", r"/api/audit")
    def _auditl(cp, x):
        return 200, cp.list_audit(x.actor, _int(x.query.get("limit", ["200"])[0]))

    @route("GET", r"/api/audit/verify")
    def _av(cp, x):
        cp._require(x.actor, "superadmin")
        ok, bad = cp.verify_audit()
        return 200, {"intact": ok, "first_bad_id": bad}

    @route("GET", r"/api/mitigations")
    def _ml(cp, x):
        return 200, cp.list_mitigations(x.actor)

    @route("POST", r"/api/mitigations")
    def _mn(cp, x):
        return 201, cp.request_mitigation(x.actor, _field(x.body, "provider"), _field(x.body, "target"),
                                          _field(x.body, "reason", ""), _field(x.body, "ttl_seconds", 3600))

    @route("DELETE", r"/api/mitigations/(\d+)")
    def _md(cp, x):
        cp.withdraw_mitigation(x.actor, int(x.match.group(1)))
        return 200, {"ok": True}

    @route("GET", r"/node/v1/policy", "node")
    def _nodepol(cp, x):
        env = cp.node_get_bundle(x.node_id)
        return (200, env) if env else (204, None)

    @route("POST", r"/node/v1/events", "node")
    def _nodeev(cp, x):
        return 200, {"accepted": cp.node_ingest_events(x.node_id, _field(x.body, "events", []))}

    return R


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        raise Invalid("limit must be an integer") from None


def make_handler(cp: ControlPlane, static_dir, trusted_proxies=frozenset()):
    routes = build_routes()
    static_dir = Path(static_dir) if static_dir else None

    class Handler(BaseHTTPRequestHandler):
        server_version = "ProtocolZ"
        sys_version = ""

        def log_message(self, *a):  # the audit log is the record; no request logging to stderr
            pass

        def _send(self, status, body: bytes, ctype: str):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status, obj):
            self._send(status, b"" if obj is None else json.dumps(obj).encode(), "application/json")

        def _client_ip(self) -> str:
            """TCP peer, unless the peer is a configured trusted proxy: then the RIGHTMOST X-Forwarded-For entry
            (the one that proxy appended; anything to its left is client-controlled and ignored)."""
            peer = self.client_address[0]
            xff = self.headers.get("X-Forwarded-For")
            if peer in trusted_proxies and xff:
                last = xff.split(",")[-1].strip()
                if last:
                    return last[:64]
            return peer

        def _bearer(self) -> str:
            h = self.headers.get("Authorization", "")
            return h[7:].strip() if h.startswith("Bearer ") else ""

        def _body(self):
            n = self.headers.get("Content-Length")
            if n is None:
                return {}
            if not n.isdigit():
                raise Invalid("bad Content-Length")
            if int(n) > MAX_BODY:
                raise _TooLarge()
            raw = self.rfile.read(int(n))
            try:
                return json.loads(raw) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise Invalid("invalid JSON") from None

        def _dispatch(self, method):
            u = urllib.parse.urlparse(self.path)
            if method == "GET" and u.path in STATIC and static_dir:
                name, ctype = STATIC[u.path]
                f = static_dir / name
                if f.is_file():
                    return self._send(200, f.read_bytes(), ctype)
            for m, rx, kind, fn in routes:
                mt = rx.fullmatch(u.path)
                if m != method or not mt:
                    continue
                try:
                    ctx = Ctx({}, mt, urllib.parse.parse_qs(u.query), self._client_ip())
                    ctx.token = self._bearer()
                    if kind == "user":
                        ctx.actor = cp.authenticate(ctx.token)
                    elif kind == "node":
                        ctx.node_id = self.headers.get("X-Node-Id", "")
                        cp.node_auth(ctx.node_id, ctx.token)
                    if method in ("POST", "PUT"):
                        ctx.body = self._body()
                    status, obj = fn(cp, ctx)
                    return self._json(status, obj)
                except CPError as exc:
                    return self._json(exc.status, {"error": str(exc)})
                except _TooLarge:
                    return self._json(413, {"error": "request body too large"})
                except Exception as exc:
                    sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
                    return self._json(500, {"error": "internal error"})
            return self._json(404, {"error": "not found"})

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PUT(self):
            self._dispatch("PUT")

        def do_DELETE(self):
            self._dispatch("DELETE")

    return Handler


class _TooLarge(Exception):
    pass


def make_server(cp: ControlPlane, host: str, port: int, static_dir=None, trusted_proxies=()) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), make_handler(cp, static_dir, frozenset(trusted_proxies)))
    srv.daemon_threads = True
    return srv
