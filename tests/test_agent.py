import json
import os
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

from protocolz_cp import auth
from protocolz_cp.server import make_server
from protocolz_cp.service import ControlPlane
from protocolz_dp.agent import NodeAgent
from protocolz_nft.manager import FirewallManager

from test_nft_manager import FakeRunner

auth.SCRYPT_N = 2 ** 4
PW = "correct horse battery"
POLICY1 = {"management_cidrs": ["203.0.113.0/24"], "services": [{"name": "web", "proto": "tcp", "port": 443}]}
POLICY2 = {"management_cidrs": ["203.0.113.0/24"], "services": [{"name": "mc", "proto": "tcp", "port": 25565,
                                                                  "new_conn_rate": 100}]}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cp = ControlPlane(self.dir / "cp.db", b"m" * 32, login_rate=1000, login_burst=1000)
        self.cp.bootstrap_superadmin("root", PW)
        root = self.cp.authenticate(self.cp.login("root", PW, None, "1.1.1.1")["token"])
        tid = self.cp.create_tenant(root, "t")["id"]
        self.cp.create_user(root, "alice", PW, "tenant_admin", tid)
        self.alice = self.cp.authenticate(self.cp.login("alice", PW, None, "1.1.1.1")["token"])
        self.node = self.cp.register_node(self.alice, "edge", "eu")
        self.cp.set_node_policy(self.alice, self.node["node_id"], POLICY1)
        self.srv = make_server(self.cp, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.stopped = False
        self.addCleanup(self.stop_cp)
        self.runner = FakeRunner()
        self.agent = self.make_agent(self.runner)

    def stop_cp(self):
        if not self.stopped:
            self.stopped = True
            self.srv.shutdown()
            self.srv.server_close()

    def make_agent(self, runner, **over):
        mgr = FirewallManager(runner, self.dir / "fw")
        args = dict(cp_url=self.url, node_id=self.node["node_id"], auth_token=self.node["auth_token"],
                    sign_key=bytes.fromhex(self.node["sign_key"]), state_dir=self.dir / "agent", manager=mgr,
                    timeout=3, allow_insecure_loopback=True)
        args.update(over)
        return NodeAgent(**args)

    def test_applies_policy_then_is_idempotent(self):
        self.assertEqual(self.agent.poll_once(), "applied")
        self.assertEqual(len(self.runner.applied), 1)
        self.assertIn('tcp dport 443 accept comment "svc-web"', self.runner.applied[0])
        self.assertEqual(self.agent.version, 1)
        self.assertEqual(self.agent.poll_once(), "unchanged")
        self.assertEqual(len(self.runner.applied), 1)

    def test_new_version_is_applied(self):
        self.agent.poll_once()
        self.cp.set_node_policy(self.alice, self.node["node_id"], POLICY2)
        self.assertEqual(self.agent.poll_once(), "applied")
        self.assertEqual(self.agent.version, 2)
        self.assertIn("tcp dport 25565", self.runner.applied[-1])

    def test_no_policy_yet(self):
        n2 = self.cp.register_node(self.alice, "empty", "us")
        a = self.make_agent(FakeRunner(), node_id=n2["node_id"], auth_token=n2["auth_token"],
                            sign_key=bytes.fromhex(n2["sign_key"]), state_dir=self.dir / "agent2")
        self.assertEqual(a.poll_once(), "no_policy")

    def test_control_plane_outage_keeps_enforcing_and_changes_nothing(self):
        self.assertEqual(self.agent.poll_once(), "applied")
        calls_before = list(self.runner.calls)
        self.stop_cp()
        for _ in range(3):
            self.assertEqual(self.agent.poll_once(), "unreachable")
        self.assertEqual(self.runner.calls, calls_before)  # not a single nft invocation during the outage
        self.assertEqual(self.agent.version, 1)
        self.assertFalse(self.agent.report())  # events queue up instead of being lost
        self.assertTrue(len(self.agent.outbox) >= 3)

    def test_outbox_is_delivered_when_cp_returns(self):
        self.agent.poll_once()
        self.assertTrue(self.agent.report())
        types = [e["type"] for e in self.cp.list_events(self.alice)]
        self.assertIn("agent.policy_applied", types)
        self.assertEqual(self.agent.outbox, [])

    def test_forged_bundle_rejected(self):
        evil = self.make_agent(self.runner, sign_key=b"x" * 32)  # models a MITM that cannot sign with the real key
        self.assertEqual(evil.poll_once(), "rejected")
        self.assertEqual(self.runner.applied, [])
        self.assertEqual(evil.version, 0)

    def test_replay_of_older_bundle_rejected(self):
        self.agent.version = 5  # pretend v5 is applied; CP (or an attacker replaying) offers v1
        self.assertEqual(self.agent.poll_once(), "rejected")
        self.assertEqual(self.runner.applied, [])

    def test_bundle_for_other_node_rejected(self):
        n2 = self.cp.register_node(self.alice, "other", "us")
        self.cp.set_node_policy(self.alice, n2["node_id"], POLICY2)
        # agent for node 1 talking as node 1 cannot be fed node 2's bundle: the node-id binding is signed
        env = self.cp.node_get_bundle(n2["node_id"])
        from protocolz_common import signing
        with self.assertRaises(signing.SignatureError):
            signing.verify(env, bytes.fromhex(self.node["sign_key"]), self.node["node_id"], 0)

    def test_bad_credentials(self):
        a = self.make_agent(self.runner, auth_token="0" * 64)
        self.assertEqual(a.poll_once(), "rejected")
        self.assertEqual(self.runner.applied, [])

    def test_failed_apply_does_not_advance_version_and_retries(self):
        bad = FakeRunner(fail_check=True)
        a = self.make_agent(bad)
        self.assertEqual(a.poll_once(), "apply_failed")
        self.assertEqual(a.version, 0)
        bad.fail_check = False
        self.assertEqual(a.poll_once(), "applied")
        self.assertEqual(a.version, 1)

    def test_restore_from_cache_after_restart_with_cp_down(self):
        self.agent.poll_once()
        self.assertEqual(os.stat(self.agent.cache_path).st_mode & 0o077, 0)
        self.stop_cp()
        runner2 = FakeRunner()
        fresh = self.make_agent(runner2)  # simulates reboot: new process, empty kernel, CP unreachable
        self.assertEqual(fresh.restore(), "restored")
        self.assertEqual(len(runner2.applied), 1)
        self.assertEqual(fresh.version, 1)
        self.assertEqual(fresh.poll_once(), "unreachable")
        self.assertEqual(len(runner2.applied), 1)

    def test_corrupt_or_forged_cache_is_not_applied(self):
        self.agent.poll_once()
        self.assertEqual(self.make_agent(FakeRunner(), state_dir=self.dir / "empty").restore(), "no_cache")
        Path(self.agent.cache_path).write_text("{not json")
        r = FakeRunner()
        self.assertEqual(self.make_agent(r).restore(), "cache_invalid")
        env = self.cp.node_get_bundle(self.node["node_id"])
        env["bundle"]["policy"]["management_cidrs"] = ["0.0.0.0/0"]  # attacker edits the cache on disk
        Path(self.agent.cache_path).write_text(json.dumps(env))
        self.assertEqual(self.make_agent(r).restore(), "cache_invalid")
        self.assertEqual(r.applied, [])

    def test_insecure_urls_refused(self):
        mgr = FirewallManager(FakeRunner(), self.dir / "fw3")
        kw = dict(node_id="n", auth_token="t", sign_key=b"k" * 32, state_dir=self.dir / "a3", manager=mgr)
        for url, flag in (("http://example.com", True), (self.url, False), ("ftp://x", True)):
            with self.assertRaises(ValueError, msg=url):
                NodeAgent(url, allow_insecure_loopback=flag, **kw)
        NodeAgent("https://cp.example.com", **kw)

    def test_run_loop_backs_off_and_stops(self):
        self.stop_cp()
        stop = threading.Event()
        waits = []
        stop.wait = lambda t: (waits.append(t), len(waits) >= 3 and stop.set())
        with unittest.mock.patch("protocolz_dp.agent.random.uniform", lambda a, b: 1.0):  # pin the jitter
            self.agent.run(stop, interval=10, max_backoff=35)
        self.assertEqual(waits, [20, 35, 35])  # doubles while unreachable, capped at max_backoff

    def test_jitter_stays_within_ten_percent(self):
        self.stop_cp()
        stop, waits = threading.Event(), []
        stop.wait = lambda t: (waits.append(t), len(waits) >= 50 and stop.set())
        self.agent.run(stop, interval=10, max_backoff=10)
        self.assertTrue(all(9.0 <= w <= 11.0 for w in waits), waits)


if __name__ == "__main__":
    unittest.main()
