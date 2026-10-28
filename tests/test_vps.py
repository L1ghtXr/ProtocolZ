import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from protocolz_dp import vps
from protocolz_nft.policy import FirewallPolicy

TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3
   3: 0100007F:C000 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 4
"""
TCP6 = """  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A
"""
UDP = """  sl  local_address rem_address   st
   0: 00000000:4A7C 00000000:0000 07
   1: 0100007F:0035 00000000:0000 07
   2: 0100007F:9999 0100007F:0035 01
"""
NETDEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: {rxb} {rxp} 0 0 0 0 0 0 5000 50 0 0 0 0 0 0
"""
STAT = "cpu  {u} 0 {s} {i} {w} 0 0 0 0 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n"
MEM = "MemTotal:       1000000 kB\nMemFree:  100 kB\nMemAvailable:    {a} kB\n"


def fake_proc(root: Path):
    (root / "net").mkdir(parents=True)
    (root / "net" / "tcp").write_text(TCP)
    (root / "net" / "tcp6").write_text(TCP6)
    (root / "net" / "udp").write_text(UDP)
    (root / "net" / "udp6").write_text("header\n")


class PortTests(unittest.TestCase):
    def test_parse_listening(self):
        with tempfile.TemporaryDirectory() as d:
            fake_proc(Path(d))
            got = vps.listening_ports(d)
        self.assertIn(("tcp", "0.0.0.0", 22), got)
        self.assertIn(("tcp", "127.0.0.1", 8080), got)
        self.assertIn(("tcp", "0.0.0.0", 8080), got)
        self.assertIn(("tcp", "::1", 3306), got)
        self.assertIn(("tcp", "::", 443), got)
        self.assertIn(("udp", "0.0.0.0", 19068), got)
        self.assertNotIn(("tcp", "127.0.0.1", 49152), got)  # ESTABLISHED, not listening
        self.assertFalse([g for g in got if g[2] == 0x9999])  # connected UDP socket is not a listener

    def test_audit_flags_unauthorized_wildcard_listeners_only(self):
        pol = FirewallPolicy.from_dict({"management_cidrs": ["203.0.113.0/24"],
                                        "services": [{"name": "web", "proto": "tcp", "port": 443}]})
        listening = [("tcp", "0.0.0.0", 22), ("tcp", "::", 443), ("tcp", "0.0.0.0", 8080), ("tcp", "127.0.0.1", 3306),
                     ("udp", "0.0.0.0", 19068)]
        f = vps.audit_ports(listening, pol)
        flagged = {x.what.split(" listening")[0] for x in f}
        self.assertEqual(flagged, {"tcp/8080", "udp/19068"})
        self.assertTrue(all(x.severity == "warn" for x in f))

    def test_without_policy_only_informational(self):
        f = vps.audit_ports([("tcp", "0.0.0.0", 80)], None)
        self.assertEqual([x.severity for x in f], ["info"])

    @unittest.skipUnless(os.path.exists("/proc/net/tcp"), "needs Linux /proc")
    def test_runs_on_real_proc(self):
        self.assertIsInstance(vps.listening_ports(), list)


class SshTests(unittest.TestCase):
    def cfg(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        f.write(text)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_insecure_config(self):
        f = vps.check_sshd_config(self.cfg("PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords no\n"
                                           "X11Forwarding no\nMaxAuthTries 10\n"))
        by = {x.what.split(" ")[0]: x for x in f}
        self.assertEqual(by["permitrootlogin"].severity, "high")
        self.assertEqual(by["passwordauthentication"].severity, "high")
        self.assertEqual(by["MaxAuthTries"].severity, "warn")
        self.assertNotIn("permitemptypasswords", by)
        self.assertNotIn("x11forwarding", by)

    def test_hardened_config_has_no_findings(self):
        self.assertEqual(vps.check_sshd_config(self.cfg(
            "# comment\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
            "X11Forwarding no\nMaxAuthTries 3\n")), [])

    def test_first_value_wins_and_match_blocks_ignored(self):
        f = vps.check_sshd_config(self.cfg("PasswordAuthentication no\nPasswordAuthentication yes\nPermitRootLogin no\n"
                                           "PermitEmptyPasswords no\nX11Forwarding no\nMatch User bob\nPasswordAuthentication yes\n"))
        self.assertEqual(f, [])

    def test_unset_and_unreadable(self):
        self.assertEqual({x.severity for x in vps.check_sshd_config(self.cfg(""))}, {"warn"})
        self.assertEqual(vps.check_sshd_config("/nonexistent/sshd_config")[0].severity, "warn")

    def test_never_modifies_file(self):
        p = self.cfg("PermitRootLogin yes\n")
        before = os.stat(p)
        vps.check_sshd_config(p)
        self.assertEqual(Path(p).read_text(), "PermitRootLogin yes\n")
        self.assertEqual(os.stat(p).st_mtime_ns, before.st_mtime_ns)


class FimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / "etc").mkdir()
        (self.d / "etc" / "a.conf").write_text("alpha")
        (self.d / "etc" / "b.conf").write_text("beta")
        self.base = self.d / "baseline.json"
        self.assertEqual(vps.fim_init([self.d / "etc"], self.base), 2)

    def kinds(self):
        return sorted(f.what.split(":")[0] for f in vps.fim_check(self.base))

    def test_clean_then_each_change_type(self):
        self.assertEqual(vps.fim_check(self.base), [])
        (self.d / "etc" / "a.conf").write_text("ALPHA")
        self.assertEqual(self.kinds(), ["modified"])
        (self.d / "etc" / "b.conf").unlink()
        (self.d / "etc" / "c.conf").write_text("new")
        self.assertEqual(self.kinds(), ["added", "modified", "removed"])

    def test_permission_change(self):
        os.chmod(self.d / "etc" / "a.conf", 0o777)
        f = vps.fim_check(self.base)
        self.assertEqual([x.what.split(":")[0] for x in f], ["permissions/ownership changed"])

    def test_same_size_content_change_detected(self):
        (self.d / "etc" / "a.conf").write_text("alphX")  # same length
        self.assertEqual(self.kinds(), ["modified"])

    def test_symlinks_not_followed(self):
        (self.d / "outside.txt").write_text("secret")
        os.symlink(self.d / "outside.txt", self.d / "etc" / "link")
        self.assertEqual(vps.fim_check(self.base), [])

    def test_baseline_private_and_old_one_backed_up(self):
        self.assertEqual(stat.S_IMODE(self.base.stat().st_mode) & 0o077, 0)
        vps.fim_init([self.d / "etc"], self.base)
        self.assertTrue(self.base.with_name("baseline.json.bak").exists())


class SamplerTests(unittest.TestCase):
    def write(self, root, rxb, rxp, u, s, i, w, avail):
        (root / "net").mkdir(parents=True, exist_ok=True)
        (root / "net" / "dev").write_text(NETDEV.format(rxb=rxb, rxp=rxp))
        (root / "stat").write_text(STAT.format(u=u, s=s, i=i, w=w))
        (root / "meminfo").write_text(MEM.format(a=avail))

    def test_rates(self):
        with tempfile.TemporaryDirectory() as d:
            root, t = Path(d), [100.0]
            s = vps.HostSampler(d, clock=lambda: t[0])
            self.write(root, 1000, 100, 100, 100, 700, 100, 500000)
            self.assertIsNone(s.sample())
            t[0] = 102.0
            self.write(root, 5000, 1100, 200, 100, 800, 100, 250000)
            m = s.sample()
        self.assertAlmostEqual(m["rx_pps"], 500.0)            # eth0 only: lo excluded
        self.assertAlmostEqual(m["rx_bytes_per_sec"], 2000.0)
        self.assertAlmostEqual(m["cpu_pct"], 50.0)            # busy +100, idle +100
        self.assertAlmostEqual(m["mem_pct"], 75.0)

    def test_counter_reset_never_goes_negative(self):
        with tempfile.TemporaryDirectory() as d:
            root, t = Path(d), [0.0]
            s = vps.HostSampler(d, clock=lambda: t[0])
            self.write(root, 9000, 900, 100, 0, 100, 0, 500000)
            s.sample()
            t[0] = 1.0
            self.write(root, 10, 1, 110, 0, 110, 0, 500000)
            self.assertEqual(s.sample()["rx_pps"], 0)

    @unittest.skipUnless(os.path.exists("/proc/stat"), "needs Linux /proc")
    def test_real_proc_two_samples(self):
        s = vps.HostSampler()
        s.sample()
        import time
        time.sleep(0.1)
        m = s.sample()
        self.assertTrue(0 <= m["cpu_pct"] <= 100 and 0 <= m["mem_pct"] <= 100)


if __name__ == "__main__":
    unittest.main()
