import random
import unittest

from protocolz_detect.baseline import Detector, MetricConfig

PPS = MetricConfig("pps")
CPU = MetricConfig("cpu", floor_abs=2.0)


def noisy(rng, mean, sd):
    return max(0.0, rng.gauss(mean, sd))


def new_detector(**kw):
    return Detector([PPS, CPU], warmup=30, confirm=3, clear_after=5, **kw)


def warm(det, rng, n=60):
    for _ in range(n):
        det.observe({"pps": noisy(rng, 1000, 50), "cpu": noisy(rng, 20, 2)})


class DetectorTests(unittest.TestCase):
    def test_warmup_never_alerts(self):
        d, rng = new_detector(), random.Random(1)
        for i in range(30):
            v = d.observe({"pps": 1000 if i < 29 else 50000, "cpu": 20})
            self.assertEqual(v.level, "warming_up")

    def test_no_false_positives_on_stationary_gaussian_noise(self):
        d, rng = new_detector(), random.Random(7)
        levels = {d.observe({"pps": noisy(rng, 1000, 50), "cpu": noisy(rng, 20, 2)}).level for _ in range(5000)}
        self.assertEqual(levels - {"warming_up", "normal"}, set())

    def test_flood_detected_within_confirm_samples_with_explanation(self):
        d, rng = new_detector(), random.Random(3)
        warm(d, rng)
        verdicts = [d.observe({"pps": noisy(rng, 8000, 400), "cpu": noisy(rng, 20, 2)}) for _ in range(5)]
        self.assertEqual(verdicts[0].level, "suspect")
        self.assertEqual(verdicts[1].level, "suspect")
        self.assertEqual(verdicts[2].level, "attack")  # detection latency = confirm (3) samples
        self.assertEqual(verdicts[2].reasons[0].metric, "pps")
        self.assertIn("pps=", verdicts[2].explain())

    def test_single_spike_is_only_suspect(self):
        d, rng = new_detector(), random.Random(4)
        warm(d, rng)
        self.assertEqual(d.observe({"pps": 9000, "cpu": 20}).level, "suspect")
        self.assertEqual(d.observe({"pps": 1000, "cpu": 20}).level, "normal")

    def test_decreases_ignored_when_one_sided(self):
        d, rng = new_detector(), random.Random(5)
        warm(d, rng)
        for _ in range(10):
            self.assertEqual(d.observe({"pps": 10, "cpu": 20}).level, "normal")

    def test_service_down_escalates_immediately(self):
        d, rng = new_detector(), random.Random(6)
        warm(d, rng)
        v = d.observe({"pps": 9000, "cpu": 20}, service_up=False)
        self.assertEqual(v.level, "attack")
        self.assertTrue(v.service_impacted)

    def test_service_down_without_traffic_anomaly_is_not_an_attack(self):
        d, rng = new_detector(), random.Random(8)
        warm(d, rng)
        self.assertEqual(d.observe({"pps": 1000, "cpu": 20}, service_up=False).level, "normal")

    def test_min_metrics_requires_correlation(self):
        d, rng = Detector([PPS, CPU], warmup=30, confirm=2, min_metrics=2), random.Random(9)
        warm(d, rng)
        for _ in range(5):
            self.assertNotEqual(d.observe({"pps": 9000, "cpu": 20}).level, "attack")
        d2 = Detector([PPS, CPU], warmup=30, confirm=2, min_metrics=2)
        warm(d2, random.Random(9))
        levels = [d2.observe({"pps": 9000, "cpu": 95}).level for _ in range(3)]
        self.assertEqual(levels[-1], "attack")

    def test_attack_clears_only_after_calm_period(self):
        d, rng = new_detector(), random.Random(10)
        warm(d, rng)
        for _ in range(4):
            d.observe({"pps": 9000, "cpu": 20})
        calm = [d.observe({"pps": 1000, "cpu": 20}) for _ in range(5)]
        self.assertTrue(all(v.level == "attack" for v in calm[:4]))
        self.assertEqual(calm[4].level, "normal")

    def test_baseline_resists_poisoning_by_sustained_flood(self):
        d, rng = new_detector(), random.Random(11)
        warm(d, rng)
        for _ in range(100):  # 100 samples of flood
            v = d.observe({"pps": 8000, "cpu": 20})
        self.assertEqual(v.level, "attack")  # baseline has not "learned" the flood as normal
        self.assertLess(d.state["pps"].mean, 8000 * 0.9)

    def test_legit_step_change_is_eventually_learned_documented_tradeoff(self):
        d, rng = new_detector(), random.Random(12)
        warm(d, rng)
        for _ in range(1500):
            v = d.observe({"pps": noisy(rng, 2000, 100), "cpu": 20})
        self.assertEqual(v.level, "normal")  # a 2x step is absorbed in ~600 samples

    def test_reset_relearns_immediately(self):
        d, rng = new_detector(), random.Random(13)
        warm(d, rng)
        d.reset()
        self.assertEqual(d.observe({"pps": 9000, "cpu": 20}).level, "warming_up")

    def test_unknown_metric_rejected(self):
        with self.assertRaises(KeyError):
            new_detector().observe({"bogus": 1})


if __name__ == "__main__":
    unittest.main()
