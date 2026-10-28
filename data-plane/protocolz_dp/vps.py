"""VPS Shield: READ-ONLY host auditing and monitoring. It never changes the system.

 * listening_ports / audit_ports : exposed-port audit vs. the firewall policy
 * check_sshd_config             : SSH hardening recommendations (text only, nothing is edited)
 * fim_init / fim_check          : file-integrity baseline + comparison (SHA-256, mode, owner)
 * HostSampler                   : /proc metrics (rx pps, rx B/s, CPU %, memory %) to feed the detector
Linux only (/proc). Findings are advice for a human; applying any change is the operator's decision.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    severity: str   # high | warn | info
    what: str
    advice: str = ""


# ----------------------------------------------------------------------------- exposed ports
def _addr(hexaddr: str, v6: bool) -> str:
    raw = bytes.fromhex(hexaddr)
    if not v6:
        return socket.inet_ntoa(raw[::-1])
    return str(ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))


def listening_ports(proc_root="/proc") -> list:
    """[(proto, address, port)] for TCP LISTEN and unconnected UDP sockets."""
    out = []
    for name, proto, v6 in (("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True)):
        path = Path(proc_root) / "net" / name
        try:
            lines = path.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4:
                continue
            local, remote, state = f[1], f[2], f[3]
            if proto == "tcp" and state != "0A":
                continue
            if proto == "udp" and not (state == "07" and set(remote.split(":")[0]) <= {"0"}):
                continue
            host, _, port = local.partition(":")
            out.append((proto, _addr(host, v6), int(port, 16)))
    return sorted(set(out))


def audit_ports(listening, policy=None) -> list:
    """Flag non-loopback listeners that the firewall policy does not authorize."""
    findings = []
    allowed = {("tcp", policy.ssh_port)} if policy else set()
    if policy:
        allowed |= {(s.proto, s.port) for s in policy.services}
    for proto, addr, port in listening:
        if ipaddress.ip_address(addr).is_loopback:
            continue
        wildcard = ipaddress.ip_address(addr).is_unspecified
        if policy is None:
            findings.append(Finding("info", f"{proto}/{port} listening on {addr}", "no policy given: cannot judge"))
        elif (proto, port) not in allowed:
            findings.append(Finding("warn", f"{proto}/{port} listening on {addr} but not authorized by the firewall policy",
                                    "bind it to 127.0.0.1 or add an explicit service rule; default-deny drops it meanwhile"
                                    if wildcard else "verify this service is intended"))
    return findings


# ----------------------------------------------------------------------------- sshd hardening
_SSH_RULES = {
    "permitrootlogin": (("no", "prohibit-password", "without-password"), "PermitRootLogin no (or prohibit-password)", "high"),
    "passwordauthentication": (("no",), "PasswordAuthentication no (use keys)", "high"),
    "permitemptypasswords": (("no",), "PermitEmptyPasswords no", "high"),
    "x11forwarding": (("no",), "X11Forwarding no", "warn"),
}


def check_sshd_config(path="/etc/ssh/sshd_config") -> list:
    try:
        text = Path(path).read_text()
    except OSError as exc:
        return [Finding("warn", f"cannot read {path}: {exc}", "run as root or pass the right path")]
    seen = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        key = key.lower()
        if key == "match":
            break  # only the global section is judged; Match blocks are conditional
        seen.setdefault(key, value.strip().strip('"').lower())  # sshd: first occurrence wins
    findings = []
    for key, (good, advice, sev) in _SSH_RULES.items():
        val = seen.get(key)
        if val is None:
            findings.append(Finding("warn", f"{key} not set explicitly (default depends on version)", f"set {advice}"))
        elif val not in good:
            findings.append(Finding(sev, f"{key} is '{val}'", f"set {advice}"))
    tries = seen.get("maxauthtries")
    if tries is not None and tries.isdigit() and int(tries) > 4:
        findings.append(Finding("warn", f"MaxAuthTries is {tries}", "set MaxAuthTries 4 or lower"))
    return findings


# ----------------------------------------------------------------------------- file integrity
def _walk(paths, limit=200_000):
    n = 0
    for p in paths:
        p = Path(p)
        if p.is_symlink():
            continue
        if p.is_file():
            yield p
            n += 1
        elif p.is_dir():
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for f in sorted(files):
                    fp = Path(root) / f
                    if fp.is_symlink() or not fp.is_file():
                        continue
                    yield fp
                    n += 1
                    if n >= limit:
                        raise RuntimeError(f"more than {limit} files; narrow the tracked paths")


def _digest(p: Path) -> dict:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    st = p.stat()
    return {"sha256": h.hexdigest(), "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size}


def fim_init(paths, baseline_path) -> int:
    """Write a baseline (0600). An existing baseline is kept as <name>.bak, never silently destroyed."""
    entries = {}
    for fp in _walk(paths):
        try:
            entries[str(fp)] = _digest(fp)
        except OSError:
            continue
    bp = Path(baseline_path)
    if bp.exists():
        os.replace(bp, bp.with_name(bp.name + ".bak"))
    fd = os.open(bp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"tracked": [str(p) for p in paths], "files": entries}, fh, indent=1, sort_keys=True)
    return len(entries)


def fim_check(baseline_path) -> list:
    base = json.loads(Path(baseline_path).read_text())
    old, findings, now = base["files"], [], {}
    for fp in _walk(base["tracked"]):
        try:
            now[str(fp)] = _digest(fp)
        except OSError:
            continue
    for path, was in old.items():
        cur = now.get(path)
        if cur is None:
            findings.append(Finding("high", f"removed: {path}"))
        elif cur["sha256"] != was["sha256"]:
            findings.append(Finding("high", f"modified: {path}", "compare against a trusted copy / package manager"))
        elif (cur["mode"], cur["uid"], cur["gid"]) != (was["mode"], was["uid"], was["gid"]):
            findings.append(Finding("warn", f"permissions/ownership changed: {path}"))
    findings += [Finding("warn", f"added: {p}") for p in sorted(set(now) - set(old))]
    return findings


# ----------------------------------------------------------------------------- resource metrics
class HostSampler:
    """sample() returns None the first time (needs a previous reading), then per-second rates."""

    def __init__(self, proc_root="/proc", clock=time.monotonic):
        self.root, self.clock, self._prev = Path(proc_root), clock, None

    def _read(self):
        rx_p = rx_b = 0
        for line in (self.root / "net" / "dev").read_text().splitlines()[2:]:
            name, _, rest = line.partition(":")
            if name.strip() == "lo":
                continue
            f = rest.split()
            rx_b, rx_p = rx_b + int(f[0]), rx_p + int(f[1])
        cpu = [int(x) for x in (self.root / "stat").read_text().splitlines()[0].split()[1:9]]
        mem = {l.split(":")[0]: int(l.split()[1]) for l in (self.root / "meminfo").read_text().splitlines() if ":" in l}
        return {"t": self.clock(), "rx_p": rx_p, "rx_b": rx_b, "cpu_total": sum(cpu), "cpu_idle": cpu[3] + cpu[4],
                "mem_pct": 100.0 * (1 - mem["MemAvailable"] / mem["MemTotal"])}

    def sample(self):
        cur, prev, self._prev = self._read(), self._prev, None
        self._prev = cur
        if prev is None or cur["t"] <= prev["t"]:
            return None
        dt, dtotal = cur["t"] - prev["t"], cur["cpu_total"] - prev["cpu_total"]
        return {"rx_pps": max(0, cur["rx_p"] - prev["rx_p"]) / dt, "rx_bytes_per_sec": max(0, cur["rx_b"] - prev["rx_b"]) / dt,
                "cpu_pct": 100.0 * (1 - (cur["cpu_idle"] - prev["cpu_idle"]) / dtotal) if dtotal > 0 else 0.0,
                "mem_pct": cur["mem_pct"]}
