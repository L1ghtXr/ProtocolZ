"""Detached rollback watchdog: survives the death of the process (e.g. a dropped SSH session).

Spawned in its own session. If the confirm flag does not appear before the deadline it restores
the backup with `nft -f`. It is cancelled by the manager on any handled outcome.
"""
from __future__ import annotations

import subprocess
import sys

_SCRIPT = r"""
import json, os, subprocess, sys, time
from datetime import datetime, timezone
nft, backup, flag, seconds, events = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
end = time.monotonic() + seconds
while time.monotonic() < end:
    if os.path.exists(flag):
        sys.exit(0)
    time.sleep(0.2)
if os.path.exists(flag):
    sys.exit(0)
r = subprocess.run([nft, "-f", backup], capture_output=True, text=True)
rec = {"ts": datetime.now(timezone.utc).isoformat(), "type": "firewall.watchdog_rollback",
       "backup": backup, "returncode": r.returncode}
fd = os.open(events, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
with os.fdopen(fd, "a") as fh:
    fh.write(json.dumps(rec, sort_keys=True) + "\n")
"""


class Watchdog:
    def __init__(self, proc: subprocess.Popen):
        self.proc = proc

    def cancel(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def wait(self, timeout: float) -> int:
        return self.proc.wait(timeout=timeout)


def spawn(nft_bin: str, backup, confirm_flag, seconds: float, events_path) -> Watchdog:
    proc = subprocess.Popen(
        [sys.executable, "-c", _SCRIPT, nft_bin, str(backup), str(confirm_flag), str(seconds), str(events_path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )
    return Watchdog(proc)
