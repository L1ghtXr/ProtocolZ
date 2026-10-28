"""Generic webhook adapter: POST JSON signed with HMAC-SHA256 over `timestamp.body`.

Receiver contract: verify `X-ProtocolZ-Signature: sha256=<hex>` against HMAC(secret, ts + "." + body),
reject stale `X-ProtocolZ-Timestamp`, respond 2xx JSON; for "mitigate" include {"handle": "<id>"}.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import MitigationRequest, Provider, ProviderError

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class WebhookProvider(Provider):
    def __init__(self, url: str, secret: bytes, timeout: float = 10.0, allow_insecure_loopback: bool = False):
        u = urllib.parse.urlparse(url)
        if u.scheme == "https":
            pass
        elif u.scheme == "http" and allow_insecure_loopback and u.hostname in _LOOPBACK:
            pass
        else:
            raise ProviderError("webhook URL must be https (http only for loopback with explicit opt-in)")
        if not u.hostname:
            raise ProviderError("webhook URL has no host")
        self.url, self.secret, self.timeout = url, secret, timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _post(self, payload: dict) -> dict:
        body = json.dumps(payload, sort_keys=True).encode()
        ts = str(int(time.time()))
        sig = hmac.new(self.secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-ProtocolZ-Timestamp": ts,
            "X-ProtocolZ-Signature": f"sha256={sig}", "User-Agent": "protocolz-provider/0.1"})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(65536)
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"provider returned HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise ProviderError(f"provider unreachable: {exc}") from None
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ProviderError("provider returned invalid JSON") from None
        return data if isinstance(data, dict) else {}

    def request_mitigation(self, req: MitigationRequest) -> str:
        data = self._post({"action": "mitigate", "target": req.target, "reason": req.reason,
                           "ttl_seconds": req.ttl_seconds})
        handle = data.get("handle")
        if not isinstance(handle, str) or not handle or len(handle) > 200:
            raise ProviderError("provider did not return a handle")
        return handle

    def withdraw(self, handle: str) -> None:
        self._post({"action": "withdraw", "handle": handle})
