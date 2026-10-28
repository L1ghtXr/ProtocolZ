"""HMAC-SHA256 signed policy bundles with node binding and anti-rollback versioning."""
from __future__ import annotations

import hashlib
import hmac
import json


class SignatureError(ValueError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def derive(master: bytes, label: str, node_id: str) -> bytes:
    """Per-node key material derived from the control plane master key (never stored per node)."""
    return hmac.new(master, f"{label}:{node_id}".encode(), hashlib.sha256).digest()


def sign(bundle: dict, key: bytes) -> dict:
    return {"bundle": bundle, "sig": hmac.new(key, canonical(bundle), hashlib.sha256).hexdigest()}


def verify(envelope, key: bytes, expect_node_id: str, min_version: int) -> dict:
    """Return the bundle if authentic, for this node, and version > min_version; else raise."""
    if not isinstance(envelope, dict) or set(envelope) != {"bundle", "sig"}:
        raise SignatureError("malformed envelope")
    bundle, sig = envelope["bundle"], envelope["sig"]
    if not isinstance(bundle, dict) or not isinstance(sig, str):
        raise SignatureError("malformed envelope")
    expected = hmac.new(key, canonical(bundle), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise SignatureError("bad signature")
    if bundle.get("node_id") != expect_node_id:
        raise SignatureError("bundle is for a different node")
    version = bundle.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise SignatureError("missing version")
    if version <= min_version:
        raise SignatureError(f"stale bundle version {version} <= {min_version}")
    return bundle
