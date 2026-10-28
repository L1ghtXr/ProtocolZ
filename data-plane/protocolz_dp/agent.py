"""Regional node agent: pull signed policy from the control plane and enforce it locally.

Guarantees (each covered by a test):
 * Control-plane outage never changes enforcement: on any fetch failure the agent keeps the rules
   already loaded and just retries with backoff.
 * Only bundles that are authentic (HMAC), addressed to THIS node, strictly newer than what is applied
   (no replay/rollback), and valid under FirewallPolicy are applied -- through the same dry-run +
   snapshot + rollback pipeline as a manual change.
 * The last good bundle is cached (0600) so rules can be re-applied after a reboot with the control plane down.
 * Credentials never travel over cleartext HTTP (https, or loopback with explicit opt-in).
Risk to know about: policy pushed remotely is applied without a human confirmation step; stage changes on a
canary node first. management_cidrs is mandatory in every policy, which bounds lockout risk.
"""
from __future__ import annotations

import json
import os
import random
import threading
import urllib.error
import urllib.parse
import urllib.request

from protocolz_common import signing
from protocolz_nft.manager import FirewallManager
from protocolz_nft.policy import FirewallPolicy, PolicyError

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # never forward our bearer token to a redirect target
        return None


class NodeAgent:
    def __init__(self, cp_url: str, node_id: str, auth_token: str, sign_key: bytes, state_dir,
                 manager: FirewallManager, timeout: float = 10.0, allow_insecure_loopback: bool = False):
        u = urllib.parse.urlparse(cp_url)
        if not (u.scheme == "https" or (u.scheme == "http" and allow_insecure_loopback and u.hostname in _LOOPBACK)):
            raise ValueError("control-plane URL must be https (http only for loopback with explicit opt-in)")
        self.base = cp_url.rstrip("/")
        self.node_id, self.token, self.key = node_id, auth_token, sign_key
        self.manager, self.timeout = manager, timeout
        self.state_dir = state_dir
        self.cache_path = os.path.join(str(state_dir), "agent_bundle.json")
        os.makedirs(str(state_dir), mode=0o700, exist_ok=True)
        self.version = 0
        self.outbox: list = []
        self._opener = urllib.request.build_opener(_NoRedirect)

    # -- events ---------------------------------------------------------------------------
    def _event(self, typ: str, **data) -> None:
        self.manager.events.emit(typ, **data)
        if len(self.outbox) < 200:
            self.outbox.append({"type": typ, "data": data})

    # -- transport --------------------------------------------------------------------------
    def _request(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "X-Node-Id": self.node_id, "Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw = r.read(1_000_000)
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            return exc.code, None

    # -- cache ------------------------------------------------------------------------------
    def _save_cache(self, envelope: dict) -> None:
        tmp = self.cache_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(envelope, fh)
        os.replace(tmp, self.cache_path)

    def restore(self) -> str:
        """Re-apply the cached bundle (e.g. after reboot) without contacting the control plane."""
        try:
            with open(self.cache_path) as fh:
                envelope = json.load(fh)
        except FileNotFoundError:
            return "no_cache"
        except (OSError, json.JSONDecodeError):
            return "cache_invalid"
        try:
            bundle = signing.verify(envelope, self.key, self.node_id, 0)
            policy = FirewallPolicy.from_dict(bundle["policy"])
        except (signing.SignatureError, PolicyError, KeyError, TypeError):
            self._event("agent.cache_invalid")
            return "cache_invalid"
        res = self.manager.apply(policy, confirm_timeout=0)
        if not res.ok:
            self._event("agent.restore_failed", message=res.message)
            return "apply_failed"
        self.version = bundle["version"]
        self._event("agent.policy_restored", version=self.version)
        return "restored"

    # -- main step --------------------------------------------------------------------------
    def poll_once(self) -> str:
        try:
            status, data = self._request("GET", "/node/v1/policy")
        except (OSError, ValueError) as exc:  # URLError/timeouts/refused/invalid JSON: all mean "no news"
            self._event("agent.cp_unreachable", error=type(exc).__name__)
            return "unreachable"
        if status == 204:
            return "no_policy"
        if status in (401, 403):
            self._event("agent.auth_failed", status=status)
            return "rejected"
        if status != 200:
            self._event("agent.cp_unreachable", status=status)
            return "unreachable"
        try:
            bundle = signing.verify(data, self.key, self.node_id, self.version - 1 if self.version else 0)
        except signing.SignatureError as exc:
            self._event("agent.bundle_rejected", reason=str(exc))
            return "rejected"
        if bundle["version"] == self.version:
            return "unchanged"
        try:
            policy = FirewallPolicy.from_dict(bundle["policy"])
        except PolicyError as exc:
            self._event("agent.bundle_rejected", reason=f"invalid policy: {exc}")
            return "rejected"
        res = self.manager.apply(policy, confirm_timeout=0)
        if not res.ok:
            self._event("agent.apply_failed", version=bundle["version"], message=res.message)
            return "apply_failed"
        self.version = bundle["version"]
        self._save_cache(data)
        self._event("agent.policy_applied", version=self.version)
        return "applied"

    def report(self) -> bool:
        """Best-effort delivery of queued events; kept in the outbox if the control plane is down."""
        if not self.outbox:
            return True
        batch = self.outbox[:100]
        try:
            status, _ = self._request("POST", "/node/v1/events", {"events": batch})
        except (OSError, ValueError):
            return False
        if status == 200:
            del self.outbox[:len(batch)]
            return True
        return False

    def run(self, stop: threading.Event, interval: float = 30.0, max_backoff: float = 300.0) -> None:
        delay = interval
        while not stop.is_set():
            result = self.poll_once()
            self.report()
            delay = min(max_backoff, delay * 2) if result == "unreachable" else interval
            stop.wait(delay * random.uniform(0.9, 1.1))


def main(argv=None) -> int:
    import argparse
    import signal

    from protocolz_nft.manager import SubprocessRunner

    p = argparse.ArgumentParser(prog="protocolz-agent")
    p.add_argument("--cp-url", required=True)
    p.add_argument("--node-id", required=True)
    p.add_argument("--state-dir", default=os.environ.get("PROTOCOLZ_STATE_DIR", "/var/lib/protocolz"))
    p.add_argument("--persist", default=None, help="also write applied rules to this file")
    p.add_argument("--interval", type=float, default=30.0)
    p.add_argument("--allow-insecure-loopback", action="store_true")
    args = p.parse_args(argv)
    token, key = os.environ.get("PROTOCOLZ_NODE_AUTH_TOKEN"), os.environ.get("PROTOCOLZ_NODE_SIGN_KEY")
    if not token or not key:
        print("set PROTOCOLZ_NODE_AUTH_TOKEN and PROTOCOLZ_NODE_SIGN_KEY", flush=True)
        return 2
    mgr = FirewallManager(SubprocessRunner(), args.state_dir, nft_bin=os.environ.get("PROTOCOLZ_NFT_BIN", "nft"),
                          persist_path=args.persist)
    agent = NodeAgent(args.cp_url, args.node_id, token, bytes.fromhex(key), args.state_dir, mgr,
                      allow_insecure_loopback=args.allow_insecure_loopback)
    print("restore:", agent.restore(), flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    signal.signal(signal.SIGINT, lambda *a: stop.set())
    agent.run(stop, args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
