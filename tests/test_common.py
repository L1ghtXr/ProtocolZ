import unittest

from protocolz_common import signing
from protocolz_common.ratelimit import ConnectionCounter, TokenBucketLimiter


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


class RateLimitTests(unittest.TestCase):
    def test_burst_then_refill(self):
        c = Clock()
        lim = TokenBucketLimiter(rate=2, burst=3, clock=c)
        self.assertEqual([lim.allow("a") for _ in range(4)], [True, True, True, False])
        c.t = 0.5  # +1 token
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))
        self.assertTrue(lim.allow("b"))  # independent key

    def test_never_exceeds_burst_after_long_idle(self):
        c = Clock()
        lim = TokenBucketLimiter(rate=10, burst=2, clock=c)
        lim.allow("a")
        c.t = 1000
        self.assertEqual([lim.allow("a") for _ in range(3)], [True, True, False])

    def test_memory_bounded(self):
        lim = TokenBucketLimiter(rate=1, burst=1, max_keys=100)
        for i in range(1000):
            lim.allow(i)
        self.assertEqual(len(lim), 100)

    def test_invalid_args(self):
        for kw in ({"rate": 0, "burst": 1}, {"rate": 1, "burst": 0}):
            with self.assertRaises(ValueError):
                TokenBucketLimiter(**kw)

    def test_connection_counter(self):
        cc = ConnectionCounter(2)
        self.assertTrue(cc.acquire("x") and cc.acquire("x"))
        self.assertFalse(cc.acquire("x"))
        cc.release("x")
        self.assertTrue(cc.acquire("x"))
        cc.release("x"); cc.release("x")
        self.assertEqual(cc.current("x"), 0)
        cc.release("x")  # extra release must not go negative
        self.assertEqual(cc.current("x"), 0)


class SigningTests(unittest.TestCase):
    KEY = b"k" * 32

    def env(self, **over):
        b = {"node_id": "n1", "version": 2, "policy": {"a": 1}}
        b.update(over)
        return signing.sign(b, self.KEY)

    def test_roundtrip(self):
        self.assertEqual(signing.verify(self.env(), self.KEY, "n1", 1)["version"], 2)

    def test_tamper_detected(self):
        e = self.env()
        e["bundle"]["policy"]["a"] = 2
        with self.assertRaises(signing.SignatureError):
            signing.verify(e, self.KEY, "n1", 0)

    def test_wrong_key_wrong_node_stale_version(self):
        with self.assertRaises(signing.SignatureError):
            signing.verify(self.env(), b"x" * 32, "n1", 0)
        with self.assertRaises(signing.SignatureError):
            signing.verify(self.env(), self.KEY, "n2", 0)
        with self.assertRaises(signing.SignatureError):
            signing.verify(self.env(), self.KEY, "n1", 2)  # replay of same/older version
        with self.assertRaises(signing.SignatureError):
            signing.verify(self.env(version=True), self.KEY, "n1", 0)

    def test_malformed(self):
        for bad in (None, [], {"bundle": {}}, {"bundle": {}, "sig": 1}, {"bundle": 1, "sig": "x"},
                    {"bundle": {}, "sig": "x", "extra": 1}):
            with self.assertRaises(signing.SignatureError):
                signing.verify(bad, self.KEY, "n1", 0)

    def test_derived_keys_differ_by_label_and_node(self):
        m = b"m" * 32
        self.assertNotEqual(signing.derive(m, "sign", "n1"), signing.derive(m, "auth", "n1"))
        self.assertNotEqual(signing.derive(m, "sign", "n1"), signing.derive(m, "sign", "n2"))


if __name__ == "__main__":
    unittest.main()
