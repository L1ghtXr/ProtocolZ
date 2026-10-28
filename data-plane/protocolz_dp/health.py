"""Service health monitoring with hysteresis (no flapping on a single failed probe)."""
from __future__ import annotations

import http.client
import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class TcpCheck:
    host: str
    port: int
    timeout: float = 2.0


@dataclass(frozen=True)
class HttpCheck:
    host: str
    port: int
    path: str = "/"
    expect_status: tuple = (200,)
    timeout: float = 3.0


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    latency_ms: float
    detail: str


def run_check(check) -> CheckResult:
    start = time.monotonic()
    try:
        if isinstance(check, TcpCheck):
            with socket.create_connection((check.host, check.port), timeout=check.timeout):
                pass
            return CheckResult(True, (time.monotonic() - start) * 1000, "connected")
        conn = http.client.HTTPConnection(check.host, check.port, timeout=check.timeout)
        try:
            conn.request("GET", check.path, headers={"User-Agent": "protocolz-health", "Connection": "close"})
            status = conn.getresponse().status
        finally:
            conn.close()
        ok = status in check.expect_status
        return CheckResult(ok, (time.monotonic() - start) * 1000, f"HTTP {status}")
    except (OSError, http.client.HTTPException) as exc:
        return CheckResult(False, (time.monotonic() - start) * 1000, f"{type(exc).__name__}: {exc}")


class HealthTracker:
    """unknown -> up/down. Goes down after `fail_threshold` consecutive failures and back up after
    `recover_threshold` consecutive successes. observe() returns "down"/"up" on a transition."""

    def __init__(self, fail_threshold: int = 3, recover_threshold: int = 2):
        self.fail_threshold, self.recover_threshold = fail_threshold, recover_threshold
        self.state = "unknown"
        self._fails = self._oks = 0

    def observe(self, ok: bool) -> Optional[str]:
        if ok:
            self._oks, self._fails = self._oks + 1, 0
            if self.state != "up" and (self._oks >= self.recover_threshold or self.state == "unknown"):
                changed = self.state == "down"
                self.state = "up"
                return "up" if changed else None
        else:
            self._fails, self._oks = self._fails + 1, 0
            if self.state != "down" and self._fails >= self.fail_threshold:
                self.state = "down"
                return "down"
        return None


class HealthMonitor:
    def __init__(self, checks: dict, on_transition: Optional[Callable[[str, str, CheckResult], None]] = None,
                 runner=run_check, fail_threshold: int = 3, recover_threshold: int = 2):
        self.checks = dict(checks)
        self.trackers = {n: HealthTracker(fail_threshold, recover_threshold) for n in self.checks}
        self.on_transition, self.runner = on_transition, runner
        self.last: dict = {}

    def run_once(self) -> dict:
        for name, check in self.checks.items():
            res = self.runner(check)
            self.last[name] = res
            change = self.trackers[name].observe(res.ok)
            if change and self.on_transition:
                self.on_transition(name, change, res)
        return {n: t.state for n, t in self.trackers.items()}

    def all_up(self) -> bool:
        return all(t.state == "up" for t in self.trackers.values())
