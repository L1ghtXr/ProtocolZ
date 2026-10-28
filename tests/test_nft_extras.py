import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from protocolz_nft import watchdog
from protocolz_nft.manager import FirewallManager, SubprocessRunner
from protocolz_nft.policy import FirewallPolicy, PolicyError
from protocolz_nft.render import render

from test_nft_manager import POLICY, FakeRunner

FAKE_NFT = """#!/bin/sh
echo "$@" >> "$FAKE_NFT_LOG"
case "$1" in list) exit 1;; esac
exit 0
"""


def pol(svc):
    return FirewallPolicy.from_dict({"management_cidrs": ["203.0.113.0/24"], "services": [svc]})


class PerSourceTests(unittest.TestCase):
    def test_per_source_sets_and_rules_render(self):
        text = render(pol({"name": "mc-java", "proto": "tcp", "port": 25565, "per_source_rate": 10}))
        self.assertIn("set pz_mc_java_v4 { type ipv4_addr; flags dynamic;", text)
        self.assertIn("set pz_mc_java_v6 { type ipv6_addr; flags dynamic;", text)
        self.assertIn("tcp dport 25565 ct state new add @pz_mc_java_v4 { ip saddr limit rate over 10/second burst 20 packets } "
                      'counter drop comment "ps-mc-java"', text)
        self.assertIn("add @pz_mc_java_v6 { ip6 saddr limit rate over 10/second", text)
        self.assertLess(text.index("add @pz_mc_java_v4"), text.index('accept comment "svc-mc-java"'))
        self.assertLess(text.index("set pz_mc_java_v4"), text.index("chain input"))

    def test_per_source_with_allowlist_only_emits_matching_family(self):
        text = render(pol({"name": "w", "proto": "tcp", "port": 80, "allow_cidrs": ["198.51.100.0/24"],
                           "per_source_rate": 5, "per_source_burst": 7}))
        self.assertIn("ip saddr { 198.51.100.0/24 } tcp dport 80 ct state new add @pz_w_v4 { ip saddr limit rate over 5/second burst 7", text)
        self.assertNotIn("add @pz_w_v6", text)

    def test_no_sets_when_unused(self):
        self.assertNotIn("set pz_", render(pol({"name": "w", "proto": "tcp", "port": 80})))

    def test_validation(self):
        with self.assertRaises(PolicyError):
            pol({"name": "w", "proto": "tcp", "port": 80, "per_source_burst": 5})
        with self.assertRaises(PolicyError):
            pol({"name": "w", "proto": "tcp", "port": 80, "per_source_rate": 0})


class PersistTests(unittest.TestCase):
    def test_persist_only_after_success(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "etc" / "protocolz.nft"
            ok = FirewallManager(FakeRunner(), Path(d) / "s1", persist_path=target)
            res = ok.apply(POLICY)
            self.assertTrue(res.ok)
            self.assertEqual(target.read_text(), render(POLICY))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode) & 0o077, 0)
            self.assertFalse(target.with_name("protocolz.nft.tmp").exists())

            target.unlink()
            bad = FirewallManager(FakeRunner(), Path(d) / "s2", health_check=lambda: False, persist_path=target)
            self.assertFalse(bad.apply(POLICY).ok)
            self.assertFalse(target.exists())


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.nft = self.dir / "fake-nft"
        self.nft.write_text(FAKE_NFT)
        self.nft.chmod(0o755)
        self.log = self.dir / "nft.log"
        env = mock.patch.dict(os.environ, {"FAKE_NFT_LOG": str(self.log)})
        env.start()
        self.addCleanup(env.stop)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_fires_when_unconfirmed(self):
        backup = self.dir / "backup.nft"
        backup.write_text("table inet protocolz\n")
        wd = watchdog.spawn(str(self.nft), backup, self.dir / "confirm", 0.5, self.dir / "events.jsonl")
        self.assertEqual(wd.wait(10), 0)
        self.assertEqual(self.calls(), [f"-f {backup}"])
        rec = json.loads((self.dir / "events.jsonl").read_text().splitlines()[-1])
        self.assertEqual(rec["type"], "firewall.watchdog_rollback")

    def test_stands_down_when_confirmed(self):
        flag = self.dir / "confirm"
        flag.write_text("")
        wd = watchdog.spawn(str(self.nft), self.dir / "b.nft", flag, 0.5, self.dir / "e.jsonl")
        self.assertEqual(wd.wait(10), 0)
        self.assertEqual(self.calls(), [])

    def test_cancel_prevents_firing(self):
        wd = watchdog.spawn(str(self.nft), self.dir / "b.nft", self.dir / "confirm", 0.5, self.dir / "e.jsonl")
        wd.cancel()
        time.sleep(1.0)
        self.assertEqual(self.calls(), [])

    def test_manager_end_to_end_with_real_subprocess_runner(self):
        m = FirewallManager(SubprocessRunner(), self.dir / "state", nft_bin=str(self.nft), use_watchdog=True,
                            watchdog_grace=1.0)
        res = m.apply(POLICY, confirm_timeout=1, poll=0.2)
        self.assertTrue(res.rolled_back and not res.ok)
        time.sleep(2.5)  # past timeout + grace: a cancelled watchdog must NOT restore a second time
        restores = [c for c in self.calls() if c.startswith("-f") and "backups" in c]
        self.assertEqual(len(restores), 1, self.calls())

    def test_watchdog_rescues_a_dead_process(self):
        """Simulates the CLI dying mid-window: watchdog armed, nobody confirms or cancels."""
        m = FirewallManager(SubprocessRunner(), self.dir / "state", nft_bin=str(self.nft))
        backup = m._snapshot()
        wd = watchdog.spawn(str(self.nft), backup, m.confirm_flag, 0.5, m.events.path)
        wd.wait(10)
        self.assertIn(f"-f {backup}", self.calls())


if __name__ == "__main__":
    unittest.main()
