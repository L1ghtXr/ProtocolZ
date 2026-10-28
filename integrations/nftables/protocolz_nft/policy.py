"""Firewall policy model. Everything is validated at construction time.

Safety property: a policy without a management allow-list is rejected, so a
rendered default-deny ruleset can never be generated that locks out SSH by
construction (it can still be wrong for your network -- hence dry-run and
confirm-or-rollback in manager.py).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
PROTOS = ("tcp", "udp")


class PolicyError(ValueError):
    """Policy is invalid or unsafe to apply."""


def _check_port(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PolicyError(f"{what}: port must be an integer 1-65535, got {value!r}")
    return value


def _positive_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyError(f"{what}: must be a positive integer, got {value!r}")
    return value


def _networks(values: Any, what: str) -> tuple:
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise PolicyError(f"{what}: must be a list of CIDR strings")
    out = []
    for v in values:
        try:
            if not isinstance(v, str):  # ip_network() would silently accept ints like 123
                raise TypeError
            out.append(ipaddress.ip_network(v, strict=False))
        except (ValueError, TypeError):
            raise PolicyError(f"{what}: invalid CIDR {v!r}") from None
    return tuple(out)


def _reject_unknown(data: dict, allowed: set, what: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{what}: unknown field(s) {sorted(unknown)}")


@dataclass(frozen=True)
class ServicePolicy:
    name: str
    proto: str
    port: int
    allow: tuple = ()  # ip_network objects; empty = any source
    rate: int | None = None  # max new flows/second per rule (see docs: not per-source)
    burst: int | None = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not NAME_RE.match(self.name):
            raise PolicyError(f"service name {self.name!r} must match {NAME_RE.pattern}")
        if self.proto not in PROTOS:
            raise PolicyError(f"service {self.name}: proto must be one of {PROTOS}")
        _check_port(self.port, f"service {self.name}")
        if self.rate is not None:
            _positive_int(self.rate, f"service {self.name} new_conn_rate")
        if self.burst is not None:
            _positive_int(self.burst, f"service {self.name} burst")
            if self.rate is None:
                raise PolicyError(f"service {self.name}: burst requires new_conn_rate")

    @property
    def effective_burst(self) -> int | None:
        if self.rate is None:
            return None
        return self.burst if self.burst is not None else self.rate * 2

    @classmethod
    def from_dict(cls, data: Any) -> "ServicePolicy":
        if not isinstance(data, dict):
            raise PolicyError("each service must be a JSON object")
        _reject_unknown(data, {"name", "proto", "port", "allow_cidrs", "new_conn_rate", "burst"}, "service")
        for key in ("name", "proto", "port"):
            if key not in data:
                raise PolicyError(f"service: missing required field {key!r}")
        return cls(
            name=data["name"],
            proto=data["proto"],
            port=data["port"],
            allow=_networks(data.get("allow_cidrs", []), f"service {data['name']} allow_cidrs"),
            rate=data.get("new_conn_rate"),
            burst=data.get("burst"),
        )


@dataclass(frozen=True)
class FirewallPolicy:
    management: tuple  # ip_network objects allowed to reach SSH (required, non-empty)
    ssh_port: int = 22
    services: tuple = ()
    allow_icmp: bool = True

    def __post_init__(self):
        if not self.management:
            raise PolicyError(
                "management_cidrs is required and must be non-empty: refusing to build a "
                "default-deny policy that could lock out administrative access"
            )
        _check_port(self.ssh_port, "ssh_port")
        seen = set()
        for svc in self.services:
            key = (svc.proto, svc.port)
            if key in seen:
                raise PolicyError(f"duplicate service for {svc.proto}/{svc.port}")
            seen.add(key)
            if svc.proto == "tcp" and svc.port == self.ssh_port:
                raise PolicyError(
                    f"service {svc.name} uses the SSH port {self.ssh_port}; "
                    "control SSH access through management_cidrs instead"
                )
        names = [s.name for s in self.services]
        if len(set(names)) != len(names):
            raise PolicyError("service names must be unique")

    def warnings(self) -> list:
        out = []
        if any(n.prefixlen == 0 for n in self.management):
            out.append("management_cidrs contains a /0: SSH is reachable from the whole internet")
        for svc in self.services:
            if not svc.allow and svc.rate is None:
                out.append(f"service {svc.name}: open to any source with no rate limit")
        return out

    @classmethod
    def from_dict(cls, data: Any) -> "FirewallPolicy":
        if not isinstance(data, dict):
            raise PolicyError("policy must be a JSON object")
        _reject_unknown(data, {"management_cidrs", "ssh_port", "services", "allow_icmp"}, "policy")
        if "management_cidrs" not in data:
            raise PolicyError("management_cidrs is required")
        allow_icmp = data.get("allow_icmp", True)
        if not isinstance(allow_icmp, bool):
            raise PolicyError("allow_icmp must be true or false")
        services = data.get("services", [])
        if not isinstance(services, list):
            raise PolicyError("services must be a list")
        return cls(
            management=_networks(data["management_cidrs"], "management_cidrs"),
            ssh_port=data.get("ssh_port", 22),
            services=tuple(ServicePolicy.from_dict(s) for s in services),
            allow_icmp=allow_icmp,
        )
