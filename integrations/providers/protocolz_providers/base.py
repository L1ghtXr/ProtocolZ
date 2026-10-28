from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass


class ProviderError(Exception):
    pass


@dataclass(frozen=True)
class MitigationRequest:
    target: str          # IP or CIDR the operator is authorized to protect
    reason: str
    ttl_seconds: int = 3600

    def __post_init__(self):
        try:
            ipaddress.ip_network(self.target, strict=False)
        except (ValueError, TypeError):
            raise ProviderError(f"invalid target {self.target!r}") from None
        if not 60 <= self.ttl_seconds <= 86400:
            raise ProviderError("ttl_seconds must be between 60 and 86400")
        if len(self.reason) > 200:
            raise ProviderError("reason too long")


class Provider(ABC):
    @abstractmethod
    def request_mitigation(self, req: MitigationRequest) -> str:
        """Ask the provider to start upstream mitigation. Returns a provider handle."""

    @abstractmethod
    def withdraw(self, handle: str) -> None:
        """Ask the provider to stop mitigation."""
