"""Explainable anomaly detection: per-metric adaptive baselines + correlation + hysteresis.

No machine learning. Each metric keeps an EWMA mean and an EWMA mean-absolute-deviation. A sample's
score is (x - mean) / scale, scale = max(1.4826 * deviation, floor). The floor (absolute and relative
to the mean) stops near-zero variance from making tiny wobbles look huge.

Attack-resistance of the baseline itself: while a metric is anomalous its deviation estimate is frozen
and its mean adapts 100x slower, so a sustained flood does not quickly become "normal" (an earlier
version that adapted both at 10x slower failed a test: the inflated deviation hid a 100-sample flood).
Trade-off: a legitimate permanent step change is also learned slowly (a 2x step takes ~600 samples,
an 8x flood ~1700 samples to be absorbed); call reset() after a known change. Every verdict lists the
metrics, values, baselines and scores that caused it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MetricConfig:
    name: str
    alpha: float = 0.05          # baseline adaptation speed
    threshold: float = 6.0       # robust z-score that counts as anomalous
    floor_abs: float = 1.0       # minimum scale, absolute units
    floor_rel: float = 0.10      # minimum scale, as a fraction of the baseline mean
    two_sided: bool = False      # False: only increases are anomalous (rates, load)


@dataclass
class _State:
    mean: float = 0.0
    dev: float = 0.0
    n: int = 0


@dataclass(frozen=True)
class Reason:
    metric: str
    value: float
    baseline: float
    score: float
    threshold: float

    def __str__(self) -> str:
        return (f"{self.metric}={self.value:g} vs baseline {self.baseline:g} "
                f"(score {self.score:.1f} >= {self.threshold:g})")


@dataclass(frozen=True)
class Verdict:
    level: str                    # warming_up | normal | suspect | attack
    reasons: tuple = ()
    streak: int = 0
    service_impacted: bool = False
    note: str = ""

    def explain(self) -> str:
        parts = [self.level]
        if self.reasons:
            parts.append("; ".join(str(r) for r in self.reasons))
        if self.service_impacted:
            parts.append("service is unavailable")
        if self.note:
            parts.append(self.note)
        return " | ".join(parts)


class Detector:
    def __init__(self, metrics, warmup: int = 30, confirm: int = 3, clear_after: int = 5, min_metrics: int = 1):
        self.cfg = {m.name: m for m in metrics}
        if not self.cfg:
            raise ValueError("at least one metric is required")
        self.state = {name: _State() for name in self.cfg}
        self.warmup, self.confirm, self.clear_after, self.min_metrics = warmup, confirm, clear_after, min_metrics
        self._streak = 0
        self._calm = 0
        self._in_attack = False
        self._samples = 0

    def reset(self) -> None:
        """Forget all baselines (e.g. after a known, legitimate capacity or traffic change)."""
        self.state = {name: _State() for name in self.cfg}
        self._streak = self._calm = self._samples = 0
        self._in_attack = False

    def _score(self, cfg: MetricConfig, st: _State, x: float) -> float:
        scale = max(1.4826 * st.dev, cfg.floor_abs, cfg.floor_rel * abs(st.mean))
        z = (x - st.mean) / scale
        return abs(z) if cfg.two_sided else z

    def _learn(self, cfg: MetricConfig, st: _State, x: float, anomalous: bool) -> None:
        if st.n == 0:
            st.mean, st.dev = x, 0.0
        else:
            err = x - st.mean
            if anomalous:
                st.mean += cfg.alpha * 0.01 * err
            else:
                st.mean += cfg.alpha * err
                st.dev += cfg.alpha * (abs(err) - st.dev)
        st.n += 1

    def observe(self, values: dict, service_up: bool = True) -> Verdict:
        unknown = set(values) - set(self.cfg)
        if unknown:
            raise KeyError(f"unknown metric(s): {sorted(unknown)}")
        self._samples += 1
        warming = self._samples <= self.warmup
        reasons = []
        for name, x in values.items():
            cfg, st = self.cfg[name], self.state[name]
            anomalous = False
            if not warming and st.n > 0:
                score = self._score(cfg, st, x)
                if score >= cfg.threshold:
                    anomalous = True
                    reasons.append(Reason(name, x, st.mean, score, cfg.threshold))
            self._learn(cfg, st, x, anomalous)
        if warming:
            return Verdict("warming_up", note=f"{self._samples}/{self.warmup} baseline samples")

        hit = len(reasons) >= self.min_metrics
        impacted = hit and not service_up
        self._streak = self._streak + 1 if hit else 0
        if hit:
            self._calm = 0
        elif self._in_attack:
            self._calm += 1

        if hit and (self._streak >= self.confirm or impacted):
            self._in_attack = True
            return Verdict("attack", tuple(reasons), self._streak, impacted)
        if self._in_attack and not hit:
            if self._calm >= self.clear_after:
                self._in_attack = False
                return Verdict("normal", note="attack cleared")
            return Verdict("attack", (), 0, False, note=f"cooling down {self._calm}/{self.clear_after}")
        if hit:
            return Verdict("suspect", tuple(reasons), self._streak, False)
        return Verdict("normal")
