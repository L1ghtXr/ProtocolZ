import http.server
import socket
import threading
import unittest

from protocolz_dp.health import HealthMonitor, HealthTracker, HttpCheck, TcpCheck, run_check


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = 500 if self.path == "/bad" else 200
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class CheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_tcp_up_and_down(self):
        self.assertTrue(run_check(TcpCheck("127.0.0.1", self.port)).ok)
        r = run_check(TcpCheck("127.0.0.1", closed_port(), timeout=0.5))
        self.assertFalse(r.ok)

    def test_http_status_expectation(self):
        self.assertTrue(run_check(HttpCheck("127.0.0.1", self.port)).ok)
        r = run_check(HttpCheck("127.0.0.1", self.port, path="/bad"))
        self.assertFalse(r.ok)
        self.assertEqual(r.detail, "HTTP 500")
        self.assertTrue(run_check(HttpCheck("127.0.0.1", self.port, path="/bad", expect_status=(500,))).ok)


class TrackerTests(unittest.TestCase):
    def test_hysteresis(self):
        t = HealthTracker(fail_threshold=3, recover_threshold=2)
        self.assertIsNone(t.observe(True))
        self.assertEqual(t.state, "up")
        self.assertIsNone(t.observe(False))
        self.assertIsNone(t.observe(False))
        self.assertEqual(t.state, "up")  # two failures: still up
        self.assertEqual(t.observe(False), "down")
        self.assertIsNone(t.observe(True))
        self.assertEqual(t.state, "down")  # one success is not enough
        self.assertEqual(t.observe(True), "up")

    def test_single_blip_does_not_flap(self):
        t = HealthTracker(3, 2)
        t.observe(True)
        for ok in (False, True, False, True, False, True):
            self.assertIsNone(t.observe(ok))
        self.assertEqual(t.state, "up")

    def test_starts_down_when_first_probes_fail(self):
        t = HealthTracker(2, 2)
        self.assertIsNone(t.observe(False))
        self.assertEqual(t.observe(False), "down")


class MonitorTests(unittest.TestCase):
    def test_transitions_are_reported_once(self):
        from protocolz_dp.health import CheckResult
        seq = iter([True, True, False, False, False, True, True])
        events = []
        m = HealthMonitor({"svc": object()}, on_transition=lambda n, c, r: events.append((n, c)),
                          runner=lambda c: CheckResult(next(seq), 1.0, ""), fail_threshold=3, recover_threshold=2)
        states = [m.run_once()["svc"] for _ in range(7)]
        self.assertEqual(states, ["up", "up", "up", "up", "down", "down", "up"])
        self.assertEqual(events, [("svc", "down"), ("svc", "up")])
        self.assertTrue(m.all_up())


if __name__ == "__main__":
    unittest.main()
