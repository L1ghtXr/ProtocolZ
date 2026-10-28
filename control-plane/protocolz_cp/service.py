"""Control-plane domain logic. Every public method takes an authenticated `actor` (except login/node_*)
and enforces RBAC + tenant isolation itself, so the HTTP layer cannot forget to."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from protocolz_common import signing
from protocolz_common.ratelimit import TokenBucketLimiter
from protocolz_nft.policy import FirewallPolicy, PolicyError
from protocolz_providers import MitigationRequest, ProviderError, WebhookProvider, build_provider

from . import auth, totp

ROLES = ("superadmin", "tenant_admin", "viewer")
ASSET_KINDS = ("vps", "game_server", "web", "api", "dns", "other")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
EVENT_TYPE_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")
MIN_PREFIX = {"tenant_admin": {4: 16, 6: 32}, "superadmin": {4: 8, 6: 16}}  # blocks claiming huge ranges

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL, tenant_id INTEGER REFERENCES tenants(id), totp_secret TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL, kind TEXT NOT NULL, address TEXT NOT NULL, UNIQUE(tenant_id, name));
CREATE TABLE IF NOT EXISTS providers(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
  config TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL, region TEXT NOT NULL, policy TEXT, version INTEGER NOT NULL DEFAULT 0, last_seen REAL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL NOT NULL, tenant_id INTEGER, node_id TEXT,
  type TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mitigations(id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, provider TEXT NOT NULL,
  target TEXT NOT NULL, reason TEXT, status TEXT NOT NULL, handle TEXT, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT NOT NULL, tenant_id INTEGER,
  action TEXT NOT NULL, target TEXT, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


class CPError(Exception):
    status = 400


class Invalid(CPError):
    status = 400


class Unauthorized(CPError):
    status = 401


class Forbidden(CPError):
    status = 403


class NotFound(CPError):
    status = 404


class RateLimited(CPError):
    status = 429


class Upstream(CPError):
    status = 502


def load_or_create_master_key(path) -> bytes:
    env = os.environ.get("PROTOCOLZ_CP_MASTER_KEY")
    if env:
        key = bytes.fromhex(env.strip())
    else:
        p = Path(path)
        if p.exists():
            key = bytes.fromhex(p.read_text().strip())
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(os.urandom(32).hex())
            key = bytes.fromhex(p.read_text().strip())
    if len(key) < 32:
        raise ValueError("master key must be at least 32 bytes")
    return key


class ControlPlane:
    def __init__(self, db_path, master_key: bytes, clock=time.time, session_ttl: float = 8 * 3600,
                 environ=None, login_rate: float = 0.2, login_burst: float = 5,
                 lockout_after: int = 5, lockout_seconds: float = 900):
        if len(master_key) < 32:
            raise ValueError("master key must be at least 32 bytes")
        self.db_path, self.master, self.clock = str(db_path), master_key, clock
        self.session_ttl, self.environ = session_ttl, os.environ if environ is None else environ
        self.lockout_after, self.lockout_seconds = lockout_after, lockout_seconds
        self.login_limiter = TokenBucketLimiter(login_rate, login_burst)
        self._dummy = None
        c = self._connect()
        try:
            c.executescript(SCHEMA)
        finally:
            c.close()
        os.chmod(self.db_path, 0o600)

    # ------------------------------------------------------------------ db helpers
    def _connect(self):
        c = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    @contextmanager
    def _tx(self):
        c = self._connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.execute("COMMIT")
        except BaseException:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            c.close()

    def _q(self, sql, args=()):
        c = self._connect()
        try:
            return c.execute(sql, args).fetchall()
        finally:
            c.close()

    def _audit(self, c, actor: str, action: str, tenant_id=None, target=None, detail=None):
        row = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "0" * 64
        entry = {"ts": self.clock(), "actor": actor, "tenant_id": tenant_id, "action": action,
                 "target": target, "detail": json.dumps(detail or {}, sort_keys=True, default=str)}
        h = hashlib.sha256((prev + "|" + signing.canonical(entry).decode()).encode()).hexdigest()
        c.execute("INSERT INTO audit(ts,actor,tenant_id,action,target,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                  (entry["ts"], actor, tenant_id, action, target, entry["detail"], prev, h))

    def verify_audit(self):
        """(True, None) if the hash chain is intact, else (False, id_of_first_bad_row)."""
        prev = "0" * 64
        for r in self._q("SELECT * FROM audit ORDER BY id"):
            entry = {"ts": r["ts"], "actor": r["actor"], "tenant_id": r["tenant_id"], "action": r["action"],
                     "target": r["target"], "detail": r["detail"]}
            h = hashlib.sha256((prev + "|" + signing.canonical(entry).decode()).encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != h:
                return False, r["id"]
            prev = h
        return True, None

    # ------------------------------------------------------------------ authz helpers
    @staticmethod
    def _require(actor, *roles):
        if actor["role"] not in roles:
            raise Forbidden("insufficient role")

    @staticmethod
    def _scope(actor, tenant_id=None):
        """Tenant to operate on: tenant users are pinned to their own; superadmin must name one."""
        if actor["role"] == "superadmin":
            if tenant_id is None:
                raise Invalid("tenant_id is required")
            return tenant_id
        return actor["tenant_id"]

    @staticmethod
    def _visible_tenant(actor):
        return None if actor["role"] == "superadmin" else actor["tenant_id"]

    # ------------------------------------------------------------------ users / auth
    def bootstrap_superadmin(self, username: str, password: str) -> None:
        self._validate_user(username, password)
        with self._tx() as c:
            try:
                c.execute("INSERT INTO users(username,pw_hash,role) VALUES(?,?,'superadmin')",
                          (username, auth.hash_password(password)))
            except sqlite3.IntegrityError:
                raise Invalid("username taken") from None
            self._audit(c, "system", "bootstrap_superadmin", target=username)

    @staticmethod
    def _validate_user(username, password):
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise Invalid("username must match [a-z0-9._-]{3,64}")
        if not isinstance(password, str) or len(password) < 12 or password == username:
            raise Invalid("password must be at least 12 characters")

    def create_user(self, actor, username, password, role, tenant_id=None):
        self._require(actor, "superadmin", "tenant_admin")
        if role not in ROLES:
            raise Invalid("unknown role")
        self._validate_user(username, password)
        if actor["role"] == "tenant_admin":
            if role == "superadmin":
                raise Forbidden("cannot create superadmins")
            tenant_id = actor["tenant_id"]
        elif role == "superadmin":
            tenant_id = None
        elif tenant_id is None:
            raise Invalid("tenant_id is required for tenant users")
        with self._tx() as c:
            if tenant_id is not None and not c.execute("SELECT 1 FROM tenants WHERE id=?", (tenant_id,)).fetchone():
                raise NotFound("tenant not found")
            try:
                cur = c.execute("INSERT INTO users(username,pw_hash,role,tenant_id) VALUES(?,?,?,?)",
                                (username, auth.hash_password(password), role, tenant_id))
            except sqlite3.IntegrityError:
                raise Invalid("username taken") from None
            self._audit(c, actor["username"], "create_user", tenant_id, username, {"role": role})
            return {"id": cur.lastrowid, "username": username, "role": role, "tenant_id": tenant_id}

    def login(self, username, password, otp, ip) -> dict:
        if not self.login_limiter.allow(ip):
            raise RateLimited("too many login attempts from this address")
        username = username if isinstance(username, str) else ""
        password = password if isinstance(password, str) else ""
        now = self.clock()
        result = None
        with self._tx() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

            def fail(why, extra=None):
                self._audit(c, username[:64] or "?", "login_failed", row["tenant_id"] if row else None,
                            detail={"ip": ip, "why": why})
                if extra:
                    c.execute(extra[0], extra[1])

            if row is None:
                if self._dummy is None:
                    self._dummy = auth.dummy_hash()
                auth.verify_password(password, self._dummy)  # equalise timing with the real path
                fail("unknown_user")
            else:
                pw_ok = auth.verify_password(password, row["pw_hash"])
                locked = row["locked_until"] > now
                otp_counter = None
                if pw_ok and row["totp_enabled"] and not locked:
                    otp_counter = totp.verify(row["totp_secret"], otp if isinstance(otp, str) else "", now,
                                              row["totp_last"])
                ok = pw_ok and not locked and (not row["totp_enabled"] or otp_counter is not None)
                if not ok:
                    if locked:
                        fail("locked")
                    else:
                        failed = row["failed"] + 1
                        if failed >= self.lockout_after:
                            fail("bad_credentials", ("UPDATE users SET failed=0, locked_until=? WHERE id=?",
                                                     (now + self.lockout_seconds, row["id"])))
                        else:
                            fail("bad_password" if not pw_ok else "bad_otp",
                                 ("UPDATE users SET failed=? WHERE id=?", (failed, row["id"])))
                else:
                    token = secrets.token_urlsafe(32)
                    c.execute("DELETE FROM sessions WHERE expires < ?", (now,))
                    c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",
                              (hashlib.sha256(token.encode()).hexdigest(), row["id"], now + self.session_ttl))
                    c.execute("UPDATE users SET failed=0, locked_until=0, totp_last=? WHERE id=?",
                              (otp_counter if otp_counter is not None else row["totp_last"], row["id"]))
                    self._audit(c, username, "login", row["tenant_id"], detail={"ip": ip})
                    result = {"token": token, "expires": now + self.session_ttl}
        if result is None:
            raise Unauthorized("invalid credentials")  # one generic message for every failure cause
        return result

    def authenticate(self, token: str) -> dict:
        if not token:
            raise Unauthorized("authentication required")
        rows = self._q("SELECT u.id,u.username,u.role,u.tenant_id,s.expires FROM sessions s JOIN users u "
                       "ON u.id=s.user_id WHERE s.token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        if not rows or rows[0]["expires"] <= self.clock():
            raise Unauthorized("authentication required")
        r = rows[0]
        return {"id": r["id"], "username": r["username"], "role": r["role"], "tenant_id": r["tenant_id"]}

    def logout(self, token: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def totp_enroll(self, actor) -> dict:
        with self._tx() as c:
            row = c.execute("SELECT totp_enabled FROM users WHERE id=?", (actor["id"],)).fetchone()
            if row["totp_enabled"]:
                raise Invalid("MFA already enabled")
            secret = totp.new_secret()
            c.execute("UPDATE users SET totp_secret=?, totp_last=0 WHERE id=?", (secret, actor["id"]))
            self._audit(c, actor["username"], "totp_enroll", actor["tenant_id"])
        return {"secret": secret, "uri": totp.provisioning_uri(secret, actor["username"])}

    def totp_confirm(self, actor, code) -> None:
        with self._tx() as c:
            row = c.execute("SELECT totp_secret FROM users WHERE id=?", (actor["id"],)).fetchone()
            counter = totp.verify(row["totp_secret"], code, self.clock()) if row["totp_secret"] else None
            if counter is None:
                raise Invalid("invalid code")
            c.execute("UPDATE users SET totp_enabled=1, totp_last=? WHERE id=?", (counter, actor["id"]))
            self._audit(c, actor["username"], "totp_enabled", actor["tenant_id"])

    # ------------------------------------------------------------------ tenants
    def create_tenant(self, actor, name):
        self._require(actor, "superadmin")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise Invalid("invalid tenant name")
        with self._tx() as c:
            try:
                cur = c.execute("INSERT INTO tenants(name) VALUES(?)", (name,))
            except sqlite3.IntegrityError:
                raise Invalid("tenant exists") from None
            self._audit(c, actor["username"], "create_tenant", cur.lastrowid, name)
            return {"id": cur.lastrowid, "name": name}

    def list_tenants(self, actor):
        t = self._visible_tenant(actor)
        rows = self._q("SELECT id,name FROM tenants" + (" WHERE id=?" if t is not None else ""),
                       (t,) if t is not None else ())
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ assets
    def create_asset(self, actor, name, kind, address, tenant_id=None):
        self._require(actor, "superadmin", "tenant_admin")
        tid = self._scope(actor, tenant_id)
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise Invalid("invalid asset name")
        if kind not in ASSET_KINDS:
            raise Invalid(f"kind must be one of {ASSET_KINDS}")
        try:
            net = ipaddress.ip_network(address, strict=False)
        except (ValueError, TypeError):
            raise Invalid("address must be an IP or CIDR") from None
        if net.prefixlen < MIN_PREFIX[actor["role"]][net.version]:
            raise Forbidden(f"prefix /{net.prefixlen} is too broad for your role")
        with self._tx() as c:
            if not c.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
                raise NotFound("tenant not found")
            for r in c.execute("SELECT tenant_id,address FROM assets"):
                other = ipaddress.ip_network(r["address"])
                if r["tenant_id"] != tid and other.version == net.version and other.overlaps(net):
                    raise Forbidden("address overlaps an asset owned by another tenant")
            try:
                cur = c.execute("INSERT INTO assets(tenant_id,name,kind,address) VALUES(?,?,?,?)",
                                (tid, name, kind, str(net)))
            except sqlite3.IntegrityError:
                raise Invalid("asset name already used in this tenant") from None
            self._audit(c, actor["username"], "create_asset", tid, name, {"address": str(net), "kind": kind})
            return {"id": cur.lastrowid, "tenant_id": tid, "name": name, "kind": kind, "address": str(net)}

    def list_assets(self, actor):
        t = self._visible_tenant(actor)
        rows = self._q("SELECT * FROM assets" + (" WHERE tenant_id=?" if t is not None else "") + " ORDER BY id",
                       (t,) if t is not None else ())
        return [dict(r) for r in rows]

    def delete_asset(self, actor, asset_id):
        self._require(actor, "superadmin", "tenant_admin")
        t = self._visible_tenant(actor)
        with self._tx() as c:
            row = c.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
            if row is None or (t is not None and row["tenant_id"] != t):
                raise NotFound("asset not found")  # same answer for foreign and missing: no existence leak
            c.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            self._audit(c, actor["username"], "delete_asset", row["tenant_id"], row["name"])

    # ------------------------------------------------------------------ providers
    def register_provider(self, actor, name, kind, config):
        self._require(actor, "superadmin")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise Invalid("invalid provider name")
        if kind != "webhook" or not isinstance(config, dict):
            raise Invalid("only kind 'webhook' with an object config is supported")
        allowed = {"url", "secret_env", "allow_insecure_loopback", "timeout"}
        if set(config) - allowed or not isinstance(config.get("url"), str) or not config.get("secret_env"):
            raise Invalid(f"config needs url and secret_env; allowed keys {sorted(allowed)}")
        try:
            WebhookProvider(config["url"], b"x", allow_insecure_loopback=bool(config.get("allow_insecure_loopback")))
        except ProviderError as exc:
            raise Invalid(str(exc)) from None
        with self._tx() as c:
            try:
                cur = c.execute("INSERT INTO providers(name,kind,config) VALUES(?,?,?)",
                                (name, kind, json.dumps(config, sort_keys=True)))
            except sqlite3.IntegrityError:
                raise Invalid("provider exists") from None
            self._audit(c, actor["username"], "register_provider", None, name, {"kind": kind, "url": config["url"]})
            return {"id": cur.lastrowid, "name": name, "kind": kind}

    def list_providers(self, actor):
        out = []
        for r in self._q("SELECT * FROM providers ORDER BY id"):
            item = {"id": r["id"], "name": r["name"], "kind": r["kind"]}
            if actor["role"] == "superadmin":
                item["config"] = json.loads(r["config"])
            out.append(item)
        return out

    # ------------------------------------------------------------------ nodes
    def register_node(self, actor, name, region, tenant_id=None):
        self._require(actor, "superadmin", "tenant_admin")
        tid = self._scope(actor, tenant_id)
        if not isinstance(name, str) or not NAME_RE.match(name) or not isinstance(region, str) or not NAME_RE.match(region):
            raise Invalid("invalid node name or region")
        node_id = "n_" + secrets.token_hex(8)
        with self._tx() as c:
            if not c.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
                raise NotFound("tenant not found")
            c.execute("INSERT INTO nodes(id,tenant_id,name,region) VALUES(?,?,?,?)", (node_id, tid, name, region))
            self._audit(c, actor["username"], "register_node", tid, node_id, {"name": name, "region": region})
        return {"node_id": node_id,  # credentials are shown once and derived on demand; not stored
                "auth_token": signing.derive(self.master, "auth", node_id).hex(),
                "sign_key": signing.derive(self.master, "sign", node_id).hex()}

    def list_nodes(self, actor):
        t = self._visible_tenant(actor)
        rows = self._q("SELECT id,tenant_id,name,region,version,last_seen,policy IS NOT NULL AS has_policy FROM nodes"
                       + (" WHERE tenant_id=?" if t is not None else "") + " ORDER BY name",
                       (t,) if t is not None else ())
        return [dict(r) for r in rows]

    def set_node_policy(self, actor, node_id, policy):
        self._require(actor, "superadmin", "tenant_admin")
        try:
            FirewallPolicy.from_dict(policy)
        except PolicyError as exc:
            raise Invalid(f"policy rejected: {exc}") from None
        t = self._visible_tenant(actor)
        with self._tx() as c:
            row = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
            if row is None or (t is not None and row["tenant_id"] != t):
                raise NotFound("node not found")
            version = row["version"] + 1
            c.execute("UPDATE nodes SET policy=?, version=? WHERE id=?",
                      (json.dumps(policy, sort_keys=True), version, node_id))
            self._audit(c, actor["username"], "set_node_policy", row["tenant_id"], node_id, {"version": version})
        return {"node_id": node_id, "version": version}

    def node_auth(self, node_id, token):
        rows = self._q("SELECT * FROM nodes WHERE id=?", (node_id if isinstance(node_id, str) else "",))
        expected = signing.derive(self.master, "auth", node_id if rows else "none").hex()
        if not rows or not hmac.compare_digest(expected, token if isinstance(token, str) else ""):
            raise Unauthorized("node authentication failed")
        return rows[0]

    def node_get_bundle(self, node_id):
        rows = self._q("SELECT * FROM nodes WHERE id=?", (node_id,))
        with self._tx() as c:
            c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (self.clock(), node_id))
        if not rows or rows[0]["policy"] is None:
            return None
        r = rows[0]
        bundle = {"node_id": node_id, "version": r["version"], "policy": json.loads(r["policy"])}
        return signing.sign(bundle, signing.derive(self.master, "sign", node_id))

    def node_ingest_events(self, node_id, events) -> int:
        if not isinstance(events, list) or len(events) > 100:
            raise Invalid("events must be a list of at most 100")
        row = self._q("SELECT tenant_id FROM nodes WHERE id=?", (node_id,))[0]
        clean = []
        for e in events:
            if not isinstance(e, dict) or not isinstance(e.get("type"), str) or not EVENT_TYPE_RE.match(e["type"]):
                raise Invalid("each event needs a valid 'type'")
            data = json.dumps(e.get("data", {}), sort_keys=True, default=str)
            if len(data) > 2000:
                raise Invalid("event data too large")
            clean.append((e["type"], data))
        now = self.clock()
        with self._tx() as c:
            for typ, data in clean:
                c.execute("INSERT INTO events(ts,tenant_id,node_id,type,data) VALUES(?,?,?,?,?)",
                          (now, row["tenant_id"], node_id, typ, data))
            c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (now, node_id))
        return len(clean)

    def list_events(self, actor, limit: int = 100):
        limit = max(1, min(int(limit), 500))
        t = self._visible_tenant(actor)
        rows = self._q("SELECT * FROM events" + (" WHERE tenant_id=?" if t is not None else "")
                       + " ORDER BY id DESC LIMIT ?", ((t, limit) if t is not None else (limit,)))
        return [{"id": r["id"], "ts": r["ts"], "node_id": r["node_id"], "type": r["type"],
                 "data": json.loads(r["data"])} for r in rows]

    # ------------------------------------------------------------------ mitigations (upstream)
    def _provider(self, name):
        rows = self._q("SELECT * FROM providers WHERE name=?", (name,))
        if not rows:
            raise NotFound("provider not found")
        try:
            return build_provider(rows[0]["kind"], json.loads(rows[0]["config"]), self.environ)
        except ProviderError as exc:
            raise Upstream(f"provider misconfigured: {exc}") from None

    def request_mitigation(self, actor, provider_name, target, reason="", ttl_seconds=3600):
        self._require(actor, "superadmin", "tenant_admin")
        try:
            req = MitigationRequest(target, reason, ttl_seconds)
        except ProviderError as exc:
            raise Invalid(str(exc)) from None
        net = ipaddress.ip_network(target, strict=False)
        req = MitigationRequest(str(net), reason, ttl_seconds)  # send exactly what was authorized (normalized)
        owner = None
        for a in self.list_assets(actor):  # tenant-scoped: you can only mitigate inside your own assets
            asset_net = ipaddress.ip_network(a["address"])
            if asset_net.version == net.version and net.subnet_of(asset_net):
                owner = a["tenant_id"]
                break
        if owner is None:
            with self._tx() as c:
                self._audit(c, actor["username"], "mitigation_denied", actor["tenant_id"], target,
                            {"provider": provider_name})
            raise Forbidden("target is not inside a protected asset you own")
        provider = self._provider(provider_name)
        status, handle, error = "active", None, None
        try:
            handle = provider.request_mitigation(req)
        except ProviderError as exc:
            status, error = "failed", str(exc)
        with self._tx() as c:
            cur = c.execute("INSERT INTO mitigations(tenant_id,provider,target,reason,status,handle,created) "
                            "VALUES(?,?,?,?,?,?,?)", (owner, provider_name, str(net), reason, status, handle, self.clock()))
            self._audit(c, actor["username"], "mitigation_" + status, owner, str(net),
                        {"provider": provider_name, "error": error})
            c.execute("INSERT INTO events(ts,tenant_id,node_id,type,data) VALUES(?,?,?,?,?)",
                      (self.clock(), owner, None, "mitigation." + status,
                       json.dumps({"target": str(net), "provider": provider_name})))
        if error:
            raise Upstream(error)
        return {"id": cur.lastrowid, "status": status, "target": str(net), "provider": provider_name}

    def withdraw_mitigation(self, actor, mitigation_id):
        self._require(actor, "superadmin", "tenant_admin")
        t = self._visible_tenant(actor)
        rows = self._q("SELECT * FROM mitigations WHERE id=?", (mitigation_id,))
        if not rows or (t is not None and rows[0]["tenant_id"] != t):
            raise NotFound("mitigation not found")
        m = rows[0]
        if m["status"] != "active":
            raise Invalid(f"mitigation is {m['status']}")
        try:
            self._provider(m["provider"]).withdraw(m["handle"])
        except ProviderError as exc:
            raise Upstream(str(exc)) from None
        with self._tx() as c:
            c.execute("UPDATE mitigations SET status='withdrawn' WHERE id=?", (mitigation_id,))
            self._audit(c, actor["username"], "mitigation_withdrawn", m["tenant_id"], m["target"])

    def list_mitigations(self, actor):
        t = self._visible_tenant(actor)
        rows = self._q("SELECT id,tenant_id,provider,target,reason,status,created FROM mitigations"
                       + (" WHERE tenant_id=?" if t is not None else "") + " ORDER BY id DESC",
                       (t,) if t is not None else ())
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ audit
    def list_audit(self, actor, limit: int = 200):
        self._require(actor, "superadmin", "tenant_admin")
        limit = max(1, min(int(limit), 1000))
        t = self._visible_tenant(actor)
        rows = self._q("SELECT id,ts,actor,tenant_id,action,target,detail FROM audit"
                       + (" WHERE tenant_id=?" if t is not None else "") + " ORDER BY id DESC LIMIT ?",
                       ((t, limit) if t is not None else (limit,)))
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]
