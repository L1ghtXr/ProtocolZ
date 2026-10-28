import base64
import http.server
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from protocolz_common import signing
from protocolz_cp import auth, totp
from protocolz_cp.server import make_server
from protocolz_cp.service import (ControlPlane, Forbidden, Invalid, NotFound, RateLimited, Unauthorized,
                                  Upstream, load_or_create_master_key)

from test_providers import Receiver

auth.SCRYPT_N = 2 ** 4  # fast hashes for tests; production default is 2**14
PW = "correct horse battery"
POLICY = {"management_cidrs": ["203.0.113.0/24"], "services": [{"name": "web", "proto": "tcp", "port": 443}]}


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.cp = self.make_cp()
        self.cp.bootstrap_superadmin("root", PW)
        self.root = self.actor("root")
        self.ta = self.cp.create_tenant(self.root, "tenant-a")["id"]
        self.tb = self.cp.create_tenant(self.root, "tenant-b")["id"]
        self.cp.create_user(self.root, "alice", PW, "tenant_admin", self.ta)
        self.cp.create_user(self.root, "bob", PW, "tenant_admin", self.tb)
        self.cp.create_user(self.root, "vera", PW, "viewer", self.ta)
        self.alice, self.bob, self.vera = self.actor("alice"), self.actor("bob"), self.actor("vera")

    def make_cp(self, **kw):
        kw.setdefault("login_rate", 1000)
        kw.setdefault("login_burst", 1000)
        return ControlPlane(Path(self.tmp.name) / "cp.db", b"m" * 32, clock=self.clock, **kw)

    def actor(self, name, password=PW):
        return self.cp.authenticate(self.cp.login(name, password, None, "10.9.9.9")["token"])


class TotpTests(unittest.TestCase):
    KEY = b"12345678901234567890"

    def test_rfc4226_vectors(self):
        want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([totp.hotp(self.KEY, i) for i in range(10)], want)

    def test_rfc6238_vector(self):
        self.assertEqual(totp.hotp(self.KEY, 59 // 30, 8), "94287082")

    def test_window_and_replay(self):
        secret = base64.b32encode(self.KEY).decode()
        now = 3000  # counter 100
        self.assertEqual(totp.verify(secret, totp.hotp(self.KEY, 100), now), 100)
        self.assertEqual(totp.verify(secret, totp.hotp(self.KEY, 99), now), 99)
        self.assertEqual(totp.verify(secret, totp.hotp(self.KEY, 101), now), 101)
        self.assertIsNone(totp.verify(secret, totp.hotp(self.KEY, 98), now))
        self.assertIsNone(totp.verify(secret, totp.hotp(self.KEY, 100), now, last_counter=100))  # replay
        for bad in ("", "12345", "1234567", "abcdef", None, 123456, "１２３４５６"):
            self.assertIsNone(totp.verify(secret, bad, now))

    def test_password_hashing(self):
        h = auth.hash_password("hunter2hunter2")
        self.assertTrue(auth.verify_password("hunter2hunter2", h))
        self.assertFalse(auth.verify_password("hunter3hunter3", h))
        self.assertNotEqual(h, auth.hash_password("hunter2hunter2"))  # salted
        for junk in ("", "scrypt$x", "md5$1$2$3$4$5", "scrypt$16$8$1$!!$!!"):
            self.assertFalse(auth.verify_password("x", junk))


class AuthTests(Base):
    def test_generic_failure_message_for_unknown_user_and_bad_password(self):
        msgs = set()
        for u, p in (("nobody", PW), ("alice", "wrong-password-1")):
            with self.assertRaises(Unauthorized) as cm:
                self.cp.login(u, p, None, "1.1.1.1")
            msgs.add(str(cm.exception))
        self.assertEqual(len(msgs), 1)

    def test_lockout_and_recovery(self):
        cp = self.make_cp(lockout_after=3, lockout_seconds=900)
        for _ in range(3):
            with self.assertRaises(Unauthorized):
                cp.login("alice", "wrong-password-1", None, "1.1.1.1")
        with self.assertRaises(Unauthorized):  # correct password refused while locked
            cp.login("alice", PW, None, "1.1.1.1")
        self.clock.t += 901
        self.assertIn("token", cp.login("alice", PW, None, "1.1.1.1"))

    def test_success_resets_failure_counter(self):
        cp = self.make_cp(lockout_after=3)
        for _ in range(2):
            with self.assertRaises(Unauthorized):
                cp.login("alice", "wrong-password-1", None, "1.1.1.1")
        cp.login("alice", PW, None, "1.1.1.1")
        for _ in range(2):
            with self.assertRaises(Unauthorized):
                cp.login("alice", "wrong-password-1", None, "1.1.1.1")
        self.assertIn("token", cp.login("alice", PW, None, "1.1.1.1"))  # 2 < 3: not locked

    def test_per_ip_login_rate_limit(self):
        cp = self.make_cp(login_rate=0.001, login_burst=2)
        cp.login("alice", PW, None, "5.5.5.5")
        cp.login("alice", PW, None, "5.5.5.5")
        with self.assertRaises(RateLimited):
            cp.login("alice", PW, None, "5.5.5.5")
        cp.login("alice", PW, None, "6.6.6.6")

    def test_session_expiry_and_logout(self):
        tok = self.cp.login("alice", PW, None, "1.1.1.1")["token"]
        self.cp.authenticate(tok)
        self.cp.logout(tok)
        with self.assertRaises(Unauthorized):
            self.cp.authenticate(tok)
        tok = self.cp.login("alice", PW, None, "1.1.1.1")["token"]
        self.clock.t += 8 * 3600 + 1
        with self.assertRaises(Unauthorized):
            self.cp.authenticate(tok)
        for bad in ("", "garbage", None):
            with self.assertRaises(Unauthorized):
                self.cp.authenticate(bad)

    def test_mfa_enrollment_login_and_replay_protection(self):
        info = self.cp.totp_enroll(self.alice)
        key = base64.b32decode(info["secret"])
        self.assertTrue(info["uri"].startswith("otpauth://totp/"))
        self.cp.totp_confirm(self.alice, totp.hotp(key, int(self.clock.t // 30)))
        with self.assertRaises(Unauthorized):
            self.cp.login("alice", PW, None, "1.1.1.1")  # password alone no longer enough
        with self.assertRaises(Unauthorized):
            self.cp.login("alice", PW, "000000", "1.1.1.1")
        self.clock.t += 30
        code = totp.hotp(key, int(self.clock.t // 30))
        self.assertIn("token", self.cp.login("alice", PW, code, "1.1.1.1"))
        with self.assertRaises(Unauthorized):
            self.cp.login("alice", PW, code, "1.1.1.1")  # same code replayed
        self.clock.t += 30
        self.assertIn("token", self.cp.login("alice", PW, totp.hotp(key, int(self.clock.t // 30)), "1.1.1.1"))
        with self.assertRaises(Invalid):
            self.cp.totp_enroll(self.alice)  # cannot silently re-enroll over an active MFA

    def test_bad_confirm_code_does_not_enable_mfa(self):
        self.cp.totp_enroll(self.alice)
        with self.assertRaises(Invalid):
            self.cp.totp_confirm(self.alice, "000000")
        self.assertIn("token", self.cp.login("alice", PW, None, "1.1.1.1"))

    def test_user_creation_rules(self):
        with self.assertRaises(Forbidden):
            self.cp.create_user(self.alice, "mallory", PW, "superadmin")
        u = self.cp.create_user(self.alice, "carol", PW, "viewer", self.tb)  # tenant_id arg must be ignored
        self.assertEqual(u["tenant_id"], self.ta)
        with self.assertRaises(Forbidden):
            self.cp.create_user(self.vera, "dave", PW, "viewer")
        for pw in ("short", "carol"):
            with self.assertRaises(Invalid):
                self.cp.create_user(self.alice, "erin", pw, "viewer")
        with self.assertRaises(Invalid):
            self.cp.create_user(self.alice, "carol", PW, "viewer")
        with self.assertRaises(Invalid):
            self.cp.create_user(self.alice, "Bad Name", PW, "viewer")
        with self.assertRaises(Invalid):
            self.cp.create_user(self.root, "frank", PW, "viewer")  # tenant required


class IsolationTests(Base):
    def test_assets_are_tenant_scoped(self):
        a = self.cp.create_asset(self.alice, "vps1", "vps", "203.0.113.0/24")
        self.cp.create_asset(self.bob, "vps1", "vps", "198.51.100.0/24")  # same name, other tenant: fine
        self.assertEqual([x["name"] for x in self.cp.list_assets(self.alice)], ["vps1"])
        self.assertEqual(len(self.cp.list_assets(self.vera)), 1)
        self.assertEqual(len(self.cp.list_assets(self.root)), 2)
        with self.assertRaises(NotFound):
            self.cp.delete_asset(self.bob, a["id"])  # foreign asset looks nonexistent
        self.cp.delete_asset(self.alice, a["id"])

    def test_viewer_cannot_write(self):
        for call in (lambda: self.cp.create_asset(self.vera, "x", "vps", "203.0.113.1"),
                     lambda: self.cp.register_node(self.vera, "n", "eu"),
                     lambda: self.cp.create_tenant(self.alice, "evil"),
                     lambda: self.cp.register_provider(self.alice, "p", "webhook", {}),
                     lambda: self.cp.list_audit(self.vera)):
            with self.assertRaises(Forbidden):
                call()

    def test_address_ownership_rules(self):
        self.cp.create_asset(self.alice, "net", "vps", "203.0.113.0/24")
        self.cp.create_asset(self.alice, "host", "vps", "203.0.113.5")  # same tenant overlap is fine
        for addr in ("203.0.113.64/26", "203.0.113.0/24", "203.0.113.7"):
            with self.assertRaises(Forbidden, msg=addr):
                self.cp.create_asset(self.bob, "steal", "vps", addr)
        for addr in ("10.0.0.0/8", "0.0.0.0/0", "2001:db8::/16"):
            with self.assertRaises(Forbidden, msg=addr):
                self.cp.create_asset(self.alice, "huge", "vps", addr)
        self.cp.create_asset(self.root, "isp", "other", "10.0.0.0/8", self.ta)
        with self.assertRaises(Forbidden):
            self.cp.create_asset(self.root, "all", "other", "0.0.0.0/0", self.ta)
        self.cp.create_asset(self.alice, "v6", "vps", "2001:db8::/48")
        for kind, addr in (("bogus", "1.2.3.4"), ("vps", "not-an-ip"), ("vps", None)):
            with self.assertRaises(Invalid):
                self.cp.create_asset(self.alice, "z", kind, addr)

    def test_nodes_policies_and_events_are_tenant_scoped(self):
        n = self.cp.register_node(self.alice, "edge-1", "eu-west")
        self.assertEqual(len(self.cp.list_nodes(self.alice)), 1)
        self.assertEqual(self.cp.list_nodes(self.bob), [])
        with self.assertRaises(NotFound):
            self.cp.set_node_policy(self.bob, n["node_id"], POLICY)
        self.cp.node_ingest_events(n["node_id"], [{"type": "firewall.applied", "data": {"v": 1}}])
        self.assertEqual(len(self.cp.list_events(self.alice)), 1)
        self.assertEqual(self.cp.list_events(self.bob), [])
        self.assertEqual(len(self.cp.list_events(self.root)), 1)

    def test_audit_scoped_to_tenant(self):
        self.cp.create_asset(self.alice, "a", "vps", "203.0.113.0/24")
        self.cp.create_asset(self.bob, "b", "vps", "198.51.100.0/24")
        names = {e["target"] for e in self.cp.list_audit(self.alice) if e["action"] == "create_asset"}
        self.assertEqual(names, {"a"})


class NodeTests(Base):
    def setUp(self):
        super().setUp()
        self.node = self.cp.register_node(self.alice, "edge-1", "eu-west")
        self.nid = self.node["node_id"]

    def test_node_authentication(self):
        self.assertEqual(self.cp.node_auth(self.nid, self.node["auth_token"])["id"], self.nid)
        for nid, tok in ((self.nid, "0" * 64), (self.nid, ""), (self.nid, None), ("n_missing", self.node["auth_token"]),
                         (None, "x")):
            with self.assertRaises(Unauthorized):
                self.cp.node_auth(nid, tok)
        other = self.cp.register_node(self.bob, "edge-2", "us")
        with self.assertRaises(Unauthorized):  # another node's token is useless here
            self.cp.node_auth(self.nid, other["auth_token"])

    def test_policy_validation_and_versioning(self):
        with self.assertRaises(Invalid):
            self.cp.set_node_policy(self.alice, self.nid, {"management_cidrs": []})
        with self.assertRaises(Invalid):
            self.cp.set_node_policy(self.alice, self.nid, {"nonsense": 1})
        self.assertEqual(self.cp.list_nodes(self.alice)[0]["version"], 0)
        self.assertEqual(self.cp.set_node_policy(self.alice, self.nid, POLICY)["version"], 1)
        self.assertEqual(self.cp.set_node_policy(self.alice, self.nid, POLICY)["version"], 2)

    def test_bundle_is_signed_for_this_node_only(self):
        self.assertIsNone(self.cp.node_get_bundle(self.nid))
        self.cp.set_node_policy(self.alice, self.nid, POLICY)
        env = self.cp.node_get_bundle(self.nid)
        key = bytes.fromhex(self.node["sign_key"])
        self.assertEqual(signing.verify(env, key, self.nid, 0)["policy"], POLICY)
        other = self.cp.register_node(self.alice, "edge-2", "us")
        with self.assertRaises(signing.SignatureError):
            signing.verify(env, bytes.fromhex(other["sign_key"]), self.nid, 0)

    def test_event_ingest_validation(self):
        self.assertEqual(self.cp.node_ingest_events(self.nid, [{"type": "a.b", "data": {"x": 1}}]), 1)
        for bad in ("nope", [{"type": "Bad Type"}], [{"data": {}}], [1], [{"type": "x", "data": {"k": "v" * 3000}}],
                    [{"type": "x"}] * 101):
            with self.assertRaises(Invalid):
                self.cp.node_ingest_events(self.nid, bad)
        self.assertIsNotNone(self.cp.list_nodes(self.alice)[0]["last_seen"])


class MitigationTests(Base):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/hook"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def make_cp(self, **kw):
        return super().make_cp(environ={"PZ_SECRET": "s3cret"}, **kw)

    def setUp(self):
        super().setUp()
        Receiver.calls.clear()
        Receiver.mode = "ok"
        self.cp.register_provider(self.root, "scrub", "webhook",
                                  {"url": self.url, "secret_env": "PZ_SECRET", "allow_insecure_loopback": True})
        self.cp.create_asset(self.alice, "net", "vps", "203.0.113.0/24")

    def test_mitigation_inside_own_asset_then_withdraw(self):
        m = self.cp.request_mitigation(self.alice, "scrub", "203.0.113.9", "udp flood", 600)
        self.assertEqual(m["status"], "active")
        self.assertEqual(Receiver.calls[0][0]["target"], "203.0.113.9/32")
        self.assertTrue(Receiver.calls[0][1])  # signature verified by receiver
        self.assertEqual(self.cp.list_mitigations(self.alice)[0]["status"], "active")
        self.assertEqual(self.cp.list_mitigations(self.bob), [])
        with self.assertRaises(NotFound):
            self.cp.withdraw_mitigation(self.bob, m["id"])
        self.cp.withdraw_mitigation(self.alice, m["id"])
        self.assertEqual(Receiver.calls[-1][0]["action"], "withdraw")
        with self.assertRaises(Invalid):
            self.cp.withdraw_mitigation(self.alice, m["id"])

    def test_cannot_mitigate_addresses_you_do_not_own(self):
        for target in ("198.51.100.1", "203.0.113.0/23", "8.8.8.8"):
            with self.assertRaises(Forbidden, msg=target):
                self.cp.request_mitigation(self.alice, "scrub", target, "x")
        with self.assertRaises(Forbidden):
            self.cp.request_mitigation(self.bob, "scrub", "203.0.113.9", "x")  # alice's range
        with self.assertRaises(Forbidden):
            self.cp.request_mitigation(self.vera, "scrub", "203.0.113.9", "x")
        self.assertEqual(Receiver.calls, [])  # provider never contacted
        self.assertTrue(any(e["action"] == "mitigation_denied" for e in self.cp.list_audit(self.alice)))

    def test_provider_failure_is_recorded_and_surfaced(self):
        Receiver.mode = "500"
        with self.assertRaises(Upstream):
            self.cp.request_mitigation(self.alice, "scrub", "203.0.113.9", "x")
        self.assertEqual(self.cp.list_mitigations(self.alice)[0]["status"], "failed")

    def test_unknown_provider_and_missing_secret(self):
        with self.assertRaises(NotFound):
            self.cp.request_mitigation(self.alice, "nope", "203.0.113.9", "x")
        cp2 = ControlPlane(Path(self.tmp.name) / "cp.db", b"m" * 32, clock=self.clock, environ={})
        with self.assertRaises(Upstream):
            cp2.request_mitigation(self.alice, "scrub", "203.0.113.9", "x")

    def test_provider_registration_rules(self):
        for cfg in ({}, {"url": "http://example.com/x", "secret_env": "S"}, {"url": "https://x.example/y"},
                    {"url": "https://x.example/y", "secret_env": "S", "extra": 1}):
            with self.assertRaises(Invalid):
                self.cp.register_provider(self.root, "bad", "webhook", cfg)
        with self.assertRaises(Invalid):
            self.cp.register_provider(self.root, "bad", "cloudflare", {})
        listed = {p["name"]: p for p in self.cp.list_providers(self.alice)}
        self.assertNotIn("config", listed["scrub"])  # tenants don't see provider config
        self.assertIn("config", self.cp.list_providers(self.root)[0])


class AuditTests(Base):
    def test_chain_intact_then_tamper_detected(self):
        self.cp.create_asset(self.alice, "a", "vps", "203.0.113.0/24")
        self.assertEqual(self.cp.verify_audit(), (True, None))
        db = sqlite3.connect(self.cp.db_path)
        row = db.execute("SELECT id FROM audit WHERE action='create_asset'").fetchone()[0]
        db.execute("UPDATE audit SET actor='mallory' WHERE id=?", (row,))
        db.commit()
        self.assertEqual(self.cp.verify_audit(), (False, row))

    def test_deleted_row_detected(self):
        self.cp.create_asset(self.alice, "a", "vps", "203.0.113.0/24")
        db = sqlite3.connect(self.cp.db_path)
        victim = db.execute("SELECT id FROM audit WHERE action='create_asset'").fetchone()[0]
        db.execute("DELETE FROM audit WHERE id=?", (victim,))
        db.commit()
        # note: deleting the LAST row is undetectable by a bare hash chain (documented limitation)
        self.cp.create_asset(self.alice, "b", "vps", "203.0.113.0/24")
        self.assertTrue(self.cp.verify_audit()[0])  # chain re-extends from the new tail
        db.execute("DELETE FROM audit WHERE id=(SELECT MIN(id)+1 FROM audit)")
        db.commit()
        self.assertFalse(self.cp.verify_audit()[0])  # deleting a middle row breaks the chain

    def test_failed_logins_audited_and_secrets_never_logged(self):
        with self.assertRaises(Unauthorized):
            self.cp.login("alice", "wrong-password-xyz", "123456", "7.7.7.7")
        dump = json.dumps(self.cp.list_audit(self.root, 1000))
        self.assertIn("login_failed", dump)
        self.assertIn("7.7.7.7", dump)
        for secret in ("wrong-password-xyz", PW, "123456"):
            self.assertNotIn(secret, dump)
        raw = sqlite3.connect(self.cp.db_path).execute("SELECT group_concat(detail || actor || target) FROM audit").fetchone()[0]
        self.assertNotIn(PW, raw)

    def test_db_and_key_file_permissions(self):
        self.assertEqual(os.stat(self.cp.db_path).st_mode & 0o077, 0)
        key = Path(self.tmp.name) / "k" / "master.key"
        k1 = load_or_create_master_key(key)
        self.assertEqual(os.stat(key).st_mode & 0o077, 0)
        self.assertEqual(load_or_create_master_key(key), k1)
        with unittest.mock.patch.dict(os.environ, {"PROTOCOLZ_CP_MASTER_KEY": "ab" * 8}):
            with self.assertRaises(ValueError):
                load_or_create_master_key(key)


import unittest.mock  # noqa: E402


class HttpTests(Base):
    def setUp(self):
        super().setUp()
        self.static = Path(self.tmp.name) / "dash"
        self.static.mkdir()
        (self.static / "index.html").write_text("<h1>dash</h1>")
        self.srv = make_server(self.cp, "127.0.0.1", 0, self.static)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close()))

    def call(self, method, path, body=None, token=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = dict(headers or {})
        if token:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw and r.headers["Content-Type"].startswith("application/json") else raw), r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, (json.loads(raw) if raw else None), e.headers

    def login(self, user="alice"):
        return self.call("POST", "/api/login", {"username": user, "password": PW})[1]["token"]

    def test_login_me_and_security_headers(self):
        status, body, headers = self.call("POST", "/api/login", {"username": "alice", "password": PW})
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, me, _ = self.call("GET", "/api/me", token=body["token"])
        self.assertEqual((status, me["username"], me["role"]), (200, "alice", "tenant_admin"))
        self.assertEqual(self.call("GET", "/api/me")[0], 401)
        self.assertEqual(self.call("GET", "/api/me", token="bogus")[0], 401)
        self.assertEqual(self.call("POST", "/api/login", {"username": "alice", "password": "nope-nope-nope"})[0], 401)

    def test_rbac_over_http(self):
        vera = self.login("vera")
        status, body, _ = self.call("POST", "/api/assets", {"name": "x", "kind": "vps", "address": "203.0.113.1"}, vera)
        self.assertEqual(status, 403)
        alice = self.login("alice")
        status, body, _ = self.call("POST", "/api/assets", {"name": "x", "kind": "vps", "address": "203.0.113.1"}, alice)
        self.assertEqual((status, body["address"]), (201, "203.0.113.1/32"))
        self.assertEqual(len(self.call("GET", "/api/assets", token=vera)[1]), 1)
        self.assertEqual(self.call("DELETE", f"/api/assets/{body['id']}", token=vera)[0], 403)

    def test_bad_input_handling(self):
        alice = self.login("alice")
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/assets", data=b"{not json", method="POST",
                                     headers={"Authorization": f"Bearer {alice}"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(self.call("GET", "/api/events?limit=abc", token=alice)[0], 400)
        self.assertEqual(self.call("GET", "/nope")[0], 404)
        self.assertEqual(self.call("POST", "/api/assets", [1, 2], alice)[0], 400)  # not an object

    def test_oversized_body_rejected_before_reading(self):
        alice = self.login("alice")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(f"POST /api/assets HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {alice}\r\n"
                      f"Content-Length: 70000\r\n\r\n".encode())
            self.assertIn(b" 413 ", s.recv(4096).split(b"\r\n")[0])

    def test_unauthenticated_requests_never_reach_handlers(self):
        for method, path in (("GET", "/api/assets"), ("POST", "/api/tenants"), ("GET", "/api/audit"),
                             ("GET", "/api/mitigations"), ("PUT", "/api/nodes/n_0123456789abcdef/policy")):
            self.assertEqual(self.call(method, path, {} if method != "GET" else None)[0], 401, path)

    def test_node_endpoints(self):
        node = self.cp.register_node(self.alice, "edge", "eu")
        h = {"X-Node-Id": node["node_id"]}
        self.assertEqual(self.call("GET", "/node/v1/policy", token="0" * 64, headers=h)[0], 401)
        self.assertEqual(self.call("GET", "/node/v1/policy", token=node["auth_token"], headers=h)[0], 204)
        self.cp.set_node_policy(self.alice, node["node_id"], POLICY)
        status, env, _ = self.call("GET", "/node/v1/policy", token=node["auth_token"], headers=h)
        self.assertEqual(status, 200)
        self.assertEqual(signing.verify(env, bytes.fromhex(node["sign_key"]), node["node_id"], 0)["version"], 1)
        status, body, _ = self.call("POST", "/node/v1/events", {"events": [{"type": "agent.test"}]},
                                    node["auth_token"], h)
        self.assertEqual((status, body), (200, {"accepted": 1}))
        # a user token is not a node credential
        self.assertEqual(self.call("GET", "/node/v1/policy", token=self.login(), headers=h)[0], 401)

    def test_static_dashboard_served_with_csp(self):
        status, body, headers = self.call("GET", "/")
        self.assertEqual((status, body), (200, b"<h1>dash</h1>"))
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(self.call("GET", "/app.js")[0], 404)  # file absent in this temp dir


class TrustedProxyTests(Base):
    def serve(self, trusted):
        cp = ControlPlane(Path(self.tmp.name) / "cp.db", b"m" * 32, clock=self.clock, login_rate=0.001, login_burst=2)
        srv = make_server(cp, "127.0.0.1", 0, None, trusted)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return srv.server_address[1]

    def login_codes(self, port, xffs):
        codes = []
        for xff in xffs:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/login", method="POST",
                                         data=json.dumps({"username": "alice", "password": PW}).encode(),
                                         headers={"X-Forwarded-For": xff})
            try:
                codes.append(urllib.request.urlopen(req, timeout=5).status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        return codes

    def test_untrusted_peer_cannot_choose_its_own_ip(self):
        port = self.serve(())
        self.assertEqual(self.login_codes(port, ["1.1.1.1", "2.2.2.2", "3.3.3.3"]), [200, 200, 429])

    def test_trusted_proxy_gives_each_client_its_own_bucket(self):
        port = self.serve(("127.0.0.1",))
        self.assertEqual(self.login_codes(port, ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]), [200] * 4)

    def test_same_real_client_is_still_limited_and_leftmost_spoofing_does_not_help(self):
        port = self.serve(("127.0.0.1",))
        self.assertEqual(self.login_codes(port, ["9.9.9.9, 5.5.5.5", "8.8.8.8, 5.5.5.5", "7.7.7.7, 5.5.5.5"]), [200, 200, 429])


if __name__ == "__main__":
    unittest.main()
