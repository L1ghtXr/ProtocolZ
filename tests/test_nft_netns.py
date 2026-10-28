"""Real-kernel integration tests for the nftables module, using two network namespaces joined by a veth.

STATUS: NEVER EXECUTED in the authoring sandbox (no nft, no iproute2, no network). They skip unless run as
root on Linux with `nft` and `ip` installed. Run them on a disposable host/VM: `sudo make test`.
They only touch namespaces named pz-a-<pid>/pz-b-<pid>, never the host's own firewall.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from protocolz_nft.manager import FirewallManager, SubprocessRunner
from protocolz_nft.policy import FirewallPolicy

CAPABLE = sys.platform.startswith("linux") and os.geteuid() == 0 and shutil.which("nft") and shutil.which("ip")

LISTEN = """
import socket, sys, time
socks = []
for port in (8080, 9090):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16); socks.append(s)
import selectors
sel = selectors.DefaultSelector()
for s in socks: sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        c, _ = key.fileobj.accept(); c.close()
"""
CONNECT = ("import socket,sys; s=socket.socket(); s.settimeout(2); s.bind((sys.argv[1],0)); "
           "s.connect(('10.200.0.1', int(sys.argv[2])))")


class NetnsRunner(SubprocessRunner):
    def __init__(self, ns):
        super().__init__(timeout=20)
        self.ns = ns

    def run(self, args, stdin=None):
        return super().run(["ip", "netns", "exec", self.ns, *args], stdin)


@unittest.skipUnless(CAPABLE, "needs root + Linux + nft + ip (never run in the authoring sandbox)")
class NetnsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pid = os.getpid()
        cls.a, cls.b = f"pz-a-{pid}", f"pz-b-{pid}"
        sh = lambda *c: subprocess.run(c, check=True, capture_output=True, text=True, timeout=20)
        sh("ip", "netns", "add", cls.a)
        sh("ip", "netns", "add", cls.b)
        sh("ip", "link", "add", "pzva", "type", "veth", "peer", "name", "pzvb")
        sh("ip", "link", "set", "pzva", "netns", cls.a)
        sh("ip", "link", "set", "pzvb", "netns", cls.b)
        ex = lambda ns, *c: sh("ip", "netns", "exec", ns, *c)
        ex(cls.a, "ip", "addr", "add", "10.200.0.1/24", "dev", "pzva")
        ex(cls.a, "ip", "link", "set", "pzva", "up")
        ex(cls.a, "ip", "link", "set", "lo", "up")
        ex(cls.b, "ip", "addr", "add", "10.200.0.2/24", "dev", "pzvb")
        ex(cls.b, "ip", "addr", "add", "10.200.0.3/24", "dev", "pzvb")
        ex(cls.b, "ip", "link", "set", "pzvb", "up")
        cls.listener = subprocess.Popen(["ip", "netns", "exec", cls.a, sys.executable, "-c", LISTEN],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.7)

    @classmethod
    def tearDownClass(cls):
        cls.listener.kill()
        for ns in (cls.a, cls.b):
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mgr = FirewallManager(NetnsRunner(self.a), Path(self.tmp.name) / "state")
        self.addCleanup(lambda: subprocess.run(["ip", "netns", "exec", self.a, "nft", "delete", "table", "inet", "protocolz"],
                                               capture_output=True))

    def can_connect(self, src, port) -> bool:
        r = subprocess.run(["ip", "netns", "exec", self.b, sys.executable, "-c", CONNECT, src, str(port)],
                           capture_output=True, timeout=15)
        return r.returncode == 0

    def policy(self, **svc):
        s = {"name": "web", "proto": "tcp", "port": 8080, "allow_cidrs": ["10.200.0.2/32"], **svc}
        return FirewallPolicy.from_dict({"management_cidrs": ["10.200.0.2/32"], "services": [s]})

    def test_dry_run_passes_real_nft_check_including_per_source_syntax(self):
        self.assertTrue(self.mgr.dry_run(self.policy()).ok)
        res = self.mgr.dry_run(self.policy(per_source_rate=10, new_conn_rate=100))
        self.assertTrue(res.ok, res.message)  # validates the dynamic-set syntax that unit tests cannot

    def test_enforcement_and_rollback_on_a_real_kernel(self):
        self.assertTrue(self.can_connect("10.200.0.2", 8080) and self.can_connect("10.200.0.2", 9090))  # baseline
        res = self.mgr.apply(self.policy())
        self.assertTrue(res.ok, res.message)
        self.assertTrue(self.can_connect("10.200.0.2", 8080), "allowed service from allowed source")
        self.assertFalse(self.can_connect("10.200.0.2", 9090), "listening but not authorized -> dropped")
        self.assertFalse(self.can_connect("10.200.0.3", 8080), "authorized port, non-allowlisted source -> dropped")
        self.assertTrue(self.mgr.rollback().ok)
        self.assertTrue(self.can_connect("10.200.0.2", 9090), "rollback restored the pre-apply state")

    def test_reapply_replaces_rather_than_duplicates(self):
        self.mgr.apply(self.policy())
        self.mgr.apply(self.policy())
        out = subprocess.run(["ip", "netns", "exec", self.a, "nft", "list", "table", "inet", "protocolz"],
                             capture_output=True, text=True).stdout
        self.assertEqual(out.count('comment "svc-web"'), 1)

    def test_failed_health_check_rolls_back_on_real_kernel(self):
        mgr = FirewallManager(NetnsRunner(self.a), Path(self.tmp.name) / "s2", health_check=lambda: False)
        res = mgr.apply(self.policy())
        self.assertTrue(res.rolled_back)
        out = subprocess.run(["ip", "netns", "exec", self.a, "nft", "list", "table", "inet", "protocolz"],
                             capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)  # table is gone again


if __name__ == "__main__":
    unittest.main()
