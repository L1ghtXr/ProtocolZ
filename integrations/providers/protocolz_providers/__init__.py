"""Upstream-mitigation provider adapters.

Implemented: a generic signed-webhook adapter (talks to any provider or gateway you put behind a
webhook). NOT implemented: vendor-specific adapters (Cloudflare, OVH, Hetzner, BGP/RTBH, ...) -- those
need provider accounts and contracts to build and verify.
"""
from __future__ import annotations

import os

from .base import MitigationRequest, Provider, ProviderError
from .webhook import WebhookProvider


def build_provider(kind: str, config: dict, environ=None) -> Provider:
    environ = os.environ if environ is None else environ
    if kind == "webhook":
        env_name = config.get("secret_env")
        secret = environ.get(env_name or "")
        if not secret:
            raise ProviderError(f"secret environment variable {env_name!r} is not set")
        return WebhookProvider(config["url"], secret.encode(), timeout=float(config.get("timeout", 10)),
                               allow_insecure_loopback=bool(config.get("allow_insecure_loopback", False)))
    raise ProviderError(f"unknown provider kind {kind!r}")


__all__ = ["MitigationRequest", "Provider", "ProviderError", "WebhookProvider", "build_provider"]
