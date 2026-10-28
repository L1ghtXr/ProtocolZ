import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from protocolz_nft.manager import CmdResult, FirewallManager
from protocolz_nft.policy import FirewallPolicy

POLICY = FirewallPolicy.from_dict({"management_cidrs": ["203.0.113.0/24"],
                                   "services": [{"name": "web", "proto": "tcp", "port": 443}]})
PRIOR = "chain input { PRIOR_MARKER }"


class FakeRunner:
    def __init__(self, table_present=False, fail_check=False, fail_first_apply=False):
        self.table_present, self.fail_check, self.fail_first_apply = table_present, fail_check, fail_first_apply
        self.calls, self.applied = [], []  # applied: contents of every non-check `nft -f`
        self._apply_n = 0

    def run(self, args, stdin=None):
        self.calls.append(list(args))
        if "-c" in args:
            return CmdResult(1, "", "syntax error") if self.fail_check else CmdResult(0, "", "")
        if args[1] == "list":
            return CmdResult(0, PRIOR, "") if self.table_present else CmdResult(1, "", "No such file")
        if args[1] == "-f":
            self.applied.append(Path(args[2]).read_text())
            self._apply_n += 1
            if self.fail_first_apply and self._apply_n == 1:
                return CmdResult(1, "", "Error: conflict")
            return CmdResult(0, "", "")
        raise AssertionError(f"unexpected call {args}")


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()

    def mgr(self, runner, health=None, sleep=None):
        return FirewallManager(runner, Path(self.tmp.name) / "state", health_check=health,
                               clock=self.clock.now, sleep=sleep or self.clock.sleep)

    def events(self, m):
        return [json.loads(l)["type"] for l in m.events.path.read_text().splitlines()]

    def test_dry_run_never_touches_live_rules(self):
        r = FakeRunner()
        res = self.mgr(r).dry_run(POLICY)
        self.assertTrue(res.ok)
        self.assertEqual(r.applied, [])
        self.assertTrue(all("-c" in c for c in r.calls))

    def test_failed_check_refuses_apply_before_any_change(self):
        r = FakeRunner(fail_check=True)
        res = self.mgr(r).apply(POLICY)
        self.assertFalse(res.ok)
        self.assertEqual(r.applied, [])
        self.assertFalse(any(c[1] == "list" for c in r.calls))  # not even a snapshot

    def test_apply_success_without_prior_table_records_absent_backup(self):
        r = FakeRunner()
        m = self.mgr(r)
        res = m.apply(POLICY)
        self.assertTrue(res.ok and not res.rolled_back)
        self.assertEqual(len(r.applied), 1)
        self.assertEqual(Path(res.backup_path).read_text(), "table inet protocolz\ndelete table inet protocolz\n")
        self.assertEqual(self.events(m), ["firewall.dry_run", "firewall.applied"])

    def test_health_failure_rolls_back_to_prior_table(self):
        r = FakeRunner(table_present=True)
        m = self.mgr(r, health=lambda: False)
        res = m.apply(POLICY)
        self.assertFalse(res.ok)
        self.assertTrue(res.rolled_back)
        self.assertEqual(len(r.applied), 2)
        self.assertIn(PRIOR, r.applied[-1])
        self.assertIn("delete table inet protocolz", r.applied[-1])
        self.assertIn("firewall.rollback", self.events(m))

    def test_crashing_health_check_counts_as_unhealthy(self):
        def boom():
            raise RuntimeError("probe broke")

        res = self.mgr(FakeRunner(), health=boom).apply(POLICY)
        self.assertTrue(res.rolled_back)

    def test_nft_rejecting_ruleset_at_apply_time_rolls_back(self):
        r = FakeRunner(fail_first_apply=True)
        res = self.mgr(r).apply(POLICY)
        self.assertFalse(res.ok)
        self.assertTrue(res.rolled_back)
        self.assertEqual(r.applied[-1], "table inet protocolz\ndelete table inet protocolz\n")

    def test_unconfirmed_apply_rolls_back_after_timeout(self):
        r = FakeRunner(table_present=True)
        res = self.mgr(r).apply(POLICY, confirm_timeout=10, poll=1)
        self.assertFalse(res.ok)
        self.assertTrue(res.rolled_back)
        self.assertIn("not confirmed", res.message)
        self.assertGreaterEqual(self.clock.t, 10)
        self.assertIn(PRIOR, r.applied[-1])

    def test_confirmed_apply_is_kept(self):
        r = FakeRunner()
        holder = {}

        def sleep(s):
            self.clock.sleep(s)
            holder["m"].confirm()  # simulates the admin confirming from a second session

        m = holder["m"] = self.mgr(r, sleep=sleep)
        res = m.apply(POLICY, confirm_timeout=10, poll=1)
        self.assertTrue(res.ok and not res.rolled_back)
        self.assertEqual(len(r.applied), 1)
        self.assertIn("firewall.confirmed", self.events(m))

    def test_health_failure_inside_confirmation_window_rolls_back(self):
        answers = iter([True, True, False])
        res = self.mgr(FakeRunner(), health=lambda: next(answers, False)).apply(POLICY, confirm_timeout=30, poll=1)
        self.assertTrue(res.rolled_back)
        self.assertIn("during confirmation window", res.message)

    def test_stale_confirm_flag_does_not_confirm_a_new_apply(self):
        m = self.mgr(FakeRunner())
        m.confirm()  # leftover from an earlier session
        res = m.apply(POLICY, confirm_timeout=3, poll=1)
        self.assertFalse(res.ok)
        self.assertTrue(res.rolled_back)

    def test_manual_rollback_restores_latest_backup(self):
        r = FakeRunner(table_present=True)
        m = self.mgr(r)
        self.assertFalse(m.rollback().ok)  # nothing yet
        m.apply(POLICY)
        res = m.rollback()
        self.assertTrue(res.ok and res.rolled_back)
        self.assertIn(PRIOR, r.applied[-1])

    @unittest.skipIf(os.name != "posix", "posix permissions only")
    def test_state_files_are_owner_only(self):
        m = self.mgr(FakeRunner())
        res = m.apply(POLICY)
        for p in (Path(res.backup_path), Path(res.ruleset_path), m.events.path, m.state_dir):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode) & 0o077, 0, p)


if __name__ == "__main__":
    unittest.main()
