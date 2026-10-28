import unittest

from protocolz_nft.policy import FirewallPolicy, PolicyError

BASE = {"management_cidrs": ["203.0.113.0/24"]}


def pol(**extra):
    return FirewallPolicy.from_dict({**BASE, **extra})


class PolicyTests(unittest.TestCase):
    def test_minimal_valid(self):
        p = pol()
        self.assertEqual(p.ssh_port, 22)
        self.assertEqual(p.warnings(), [])

    def test_lockout_guard_missing_or_empty_management(self):
        with self.assertRaises(PolicyError):
            FirewallPolicy.from_dict({})
        with self.assertRaises(PolicyError):
            FirewallPolicy.from_dict({"management_cidrs": []})

    def test_bad_cidr_and_types(self):
        for bad in (["not-a-cidr"], "203.0.113.0/24", [123], [None]):
            with self.assertRaises(PolicyError, msg=repr(bad)):
                FirewallPolicy.from_dict({"management_cidrs": bad})

    def test_bad_ports(self):
        for port in (0, 65536, -1, "80", True, 1.5):
            with self.assertRaises(PolicyError, msg=repr(port)):
                pol(services=[{"name": "web", "proto": "tcp", "port": port}])
        with self.assertRaises(PolicyError):
            pol(ssh_port=0)

    def test_bad_proto_and_names(self):
        with self.assertRaises(PolicyError):
            pol(services=[{"name": "web", "proto": "icmp", "port": 80}])
        for name in ('x"; drop', "Web", "", "a b", "a" * 40, "-lead"):
            with self.assertRaises(PolicyError, msg=repr(name)):
                pol(services=[{"name": name, "proto": "tcp", "port": 80}])

    def test_unknown_fields_rejected(self):
        with self.assertRaises(PolicyError):
            pol(surprise=1)
        with self.assertRaises(PolicyError):
            pol(services=[{"name": "web", "proto": "tcp", "port": 80, "oops": 1}])

    def test_duplicates_and_ssh_collision(self):
        s = {"name": "web", "proto": "tcp", "port": 80}
        with self.assertRaises(PolicyError):
            pol(services=[s, {**s, "name": "web2"}])
        with self.assertRaises(PolicyError):
            pol(services=[s, {**s, "port": 8080}])  # duplicate name
        with self.assertRaises(PolicyError):
            pol(services=[{"name": "sshdup", "proto": "tcp", "port": 22}])
        pol(services=[{"name": "udp22", "proto": "udp", "port": 22}])  # same number, other proto: fine

    def test_rate_rules(self):
        with self.assertRaises(PolicyError):
            pol(services=[{"name": "web", "proto": "tcp", "port": 80, "burst": 10}])
        with self.assertRaises(PolicyError):
            pol(services=[{"name": "web", "proto": "tcp", "port": 80, "new_conn_rate": 0}])
        p = pol(services=[{"name": "web", "proto": "tcp", "port": 80, "new_conn_rate": 50}])
        self.assertEqual(p.services[0].effective_burst, 100)

    def test_warnings(self):
        self.assertTrue(any("/0" in w for w in FirewallPolicy.from_dict({"management_cidrs": ["0.0.0.0/0"]}).warnings()))
        p = pol(services=[{"name": "web", "proto": "tcp", "port": 80}])
        self.assertTrue(any("no rate limit" in w for w in p.warnings()))


if __name__ == "__main__":
    unittest.main()
