"""Safe apply pipeline: validate -> render -> `nft -c` -> snapshot -> apply -> health -> confirm-or-rollback.

Rollback files are plain nft scripts. The "table did not exist before" state is
encoded as `table X` + `delete table X`, so restoring ANY previous state is just
`nft -f <backup>`.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NamedTuple, Optional, Protocol, Sequence

from .events import EventLog
from .policy import FirewallPolicy
from .render import TABLE, render

_ABSENT = f"table inet {TABLE}\ndelete table inet {TABLE}\n"


class CmdResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def run(self, args: Sequence[str], stdin: Optional[str] = None) -> CmdResult: ...


class SubprocessRunner:
    """Runs a command without a shell, with a timeout."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def run(self, args, stdin=None) -> CmdResult:
        try:
            p = subprocess.run(list(args), input=stdin, capture_output=True, text=True,
                               timeout=self.timeout, shell=False, check=False)
        except FileNotFoundError:
            return CmdResult(127, "", f"command not found: {args[0]}")
        except subprocess.TimeoutExpired:
            return CmdResult(124, "", f"timed out after {self.timeout}s: {' '.join(args)}")
        return CmdResult(p.returncode, p.stdout, p.stderr)


@dataclass
class Result:
    ok: bool
    action: str
    message: str
    warnings: list = field(default_factory=list)
    rolled_back: bool = False
    ruleset_path: Optional[str] = None
    backup_path: Optional[str] = None


class FirewallManager:
    def __init__(self, runner: Runner, state_dir, health_check: Optional[Callable[[], bool]] = None,
                 nft_bin: str = "nft", clock=time.monotonic, sleep=time.sleep):
        self.runner = runner
        self.state_dir = Path(state_dir)
        self.health_check = health_check
        self.nft = nft_bin
        self._clock = clock
        self._sleep = sleep
        self._staged = self.state_dir / "staged"
        self._backups = self.state_dir / "backups"
        for d in (self.state_dir, self._staged, self._backups):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        self.confirm_flag = self.state_dir / "confirm"
        self.events = EventLog(self.state_dir / "events.jsonl")

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _write(directory: Path, text: str) -> Path:
        path = directory / f"{time.time_ns()}.nft"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _healthy(self) -> bool:
        if self.health_check is None:
            return True
        try:
            return bool(self.health_check())
        except Exception:  # a crashing probe must count as unhealthy, never as healthy
            return False

    def _snapshot(self) -> Path:
        r = self.runner.run([self.nft, "list", "table", "inet", TABLE])
        text = _ABSENT + r.stdout if r.returncode == 0 else _ABSENT
        return self._write(self._backups, text)

    def _restore(self, backup: Path, reason: str) -> Result:
        r = self.runner.run([self.nft, "-f", str(backup)])
        if r.returncode == 0:
            self.events.emit("firewall.rollback", reason=reason, backup=str(backup))
            return Result(True, "rollback", f"restored previous state ({reason})", rolled_back=True,
                          backup_path=str(backup))
        self.events.emit("firewall.rollback_failed", reason=reason, backup=str(backup), stderr=r.stderr.strip())
        return Result(False, "rollback",
                      f"ROLLBACK FAILED ({r.stderr.strip()}). Manual recovery: nft -f {backup}",
                      backup_path=str(backup))

    def _fail_with_rollback(self, why: str, backup: Path, ruleset: Path) -> Result:
        rb = self._restore(backup, why)
        tail = "previous rules restored" if rb.ok else rb.message
        return Result(False, "apply", f"{why}; {tail}", rolled_back=rb.ok,
                      ruleset_path=str(ruleset), backup_path=str(backup))

    # -- public API -----------------------------------------------------------
    def dry_run(self, policy: FirewallPolicy) -> Result:
        """Render and syntax/semantics-check with `nft -c`. Never changes the live ruleset."""
        warnings = policy.warnings()
        path = self._write(self._staged, render(policy))
        r = self.runner.run([self.nft, "-c", "-f", str(path)])
        ok = r.returncode == 0
        msg = "ruleset passed nft check" if ok else f"nft check failed: {r.stderr.strip() or r.returncode}"
        self.events.emit("firewall.dry_run", ok=ok, ruleset=str(path), warnings=warnings)
        return Result(ok, "dry-run", msg, warnings=warnings, ruleset_path=str(path))

    def apply(self, policy: FirewallPolicy, confirm_timeout: float = 0.0, poll: float = 1.0) -> Result:
        """Apply atomically. With confirm_timeout > 0, roll back unless confirm() is called in time."""
        dry = self.dry_run(policy)
        if not dry.ok:
            return Result(False, "apply", f"refused, live ruleset untouched: {dry.message}",
                          warnings=dry.warnings, ruleset_path=dry.ruleset_path)
        ruleset = Path(dry.ruleset_path)
        backup = self._snapshot()
        self.confirm_flag.unlink(missing_ok=True)

        r = self.runner.run([self.nft, "-f", str(ruleset)])
        if r.returncode != 0:
            return self._fail_with_rollback(f"nft rejected ruleset at apply time: {r.stderr.strip()}", backup, ruleset)
        self.events.emit("firewall.applied", ruleset=str(ruleset), backup=str(backup),
                         confirm_timeout=confirm_timeout)

        if not self._healthy():
            return self._fail_with_rollback("health check failed after apply", backup, ruleset)

        if confirm_timeout > 0:
            deadline = self._clock() + confirm_timeout
            while True:
                if self.confirm_flag.exists():
                    self.events.emit("firewall.confirmed", ruleset=str(ruleset))
                    break
                if not self._healthy():
                    return self._fail_with_rollback("health check failed during confirmation window", backup, ruleset)
                if self._clock() >= deadline:
                    return self._fail_with_rollback("not confirmed in time", backup, ruleset)
                self._sleep(poll)
            msg = "applied and confirmed"
        else:
            msg = "applied (no confirmation window; run `rollback` to undo)"
        return Result(True, "apply", msg, warnings=dry.warnings, ruleset_path=str(ruleset), backup_path=str(backup))

    def confirm(self) -> Result:
        fd = os.open(self.confirm_flag, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        self.events.emit("firewall.confirm_requested")
        return Result(True, "confirm", "confirmation recorded")

    def rollback(self) -> Result:
        backups = sorted(self._backups.glob("*.nft"))
        if not backups:
            return Result(False, "rollback", "no backup available")
        return self._restore(backups[-1], "manual rollback")
