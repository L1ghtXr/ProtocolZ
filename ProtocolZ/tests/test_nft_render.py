import unittest

from protocolz_nft.policy import FirewallPolicy
from protocolz_nft.render import render


def build(**extra):
    return render(FirewallPolicy.from_dict({"management_cidrs": ["203.0.113.0/24", "2001:db8::/32"], **extra}))


class RenderTests(unittest.TestCase):
    def test_atomic_replace_header_and_default_deny(self):
        text = build()
        lines = [l for l in text.splitlines() if not l.startswith("#")]
        self.assertEqual(lines[:3], ["table inet protocolz", "delete table inet protocolz", "table inet protocolz {"])
        self.assertIn("policy drop;", text)
        self.assertIn("ct state established,related accept", text)
        self.assertTrue(text.rstrip().endswith("}"))

    def test_only_input_hook_is_managed(self):
        text = build()
        self.assertNotIn("hook forward", text)
        self.assertNotIn("hook output", text)

    def test_management_split_by_family_and_rate_limited(self):
        text = build()
        self.assertIn("ip saddr { 203.0.113.0/24 } tcp dport 22 ct state new limit rate", text)
        self.assertIn("ip6 saddr { 2001:db8::/32 } tcp dport 22 ct state new limit rate", text)

    def test_ipv6_icmp_always_allowed(self):
        self.assertIn("ipv6-icmp", build(allow_icmp=False))
        self.assertNotIn("meta l4proto icmp ", build(allow_icmp=False))
        self.assertIn("meta l4proto icmp ", build())

    def test_service_rate_limit_precedes_accept(self):
        text = build(services=[{"name": "mc", "proto": "tcp", "port": 25565, "new_conn_rate": 100}])
        drop = text.index("tcp dport 25565 ct state new limit rate over 100/second burst 200 packets counter drop")
        accept = text.index('tcp dport 25565 accept comment "svc-mc"')
        self.assertLess(drop, accept)

    def test_udp_service_and_allowlist(self):
        text = build(services=[{"name": "bedrock", "proto": "udp", "port": 19132, "allow_cidrs": ["198.51.100.7/32"]}])
        self.assertIn('ip saddr { 198.51.100.7/32 } udp dport 19132 accept comment "svc-bedrock"', text)
        self.assertNotIn("ip6 saddr { 198.51.100.7", text)

    def test_open_service_has_no_source_match(self):
        text = build(services=[{"name": "web", "proto": "tcp", "port": 443}])
        self.assertIn('        tcp dport 443 accept comment "svc-web"', text)

    def test_default_deny_is_last_rule_and_output_deterministic(self):
        svc = [{"name": "web", "proto": "tcp", "port": 443}]
        text = build(services=svc)
        self.assertEqual(text, build(services=svc))
        body = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(body[-3], 'counter drop comment "default-deny"')


if __name__ == "__main__":
    unittest.main()
