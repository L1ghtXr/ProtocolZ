"""RFC 4226 / RFC 6238 one-time passwords (HMAC-SHA1, 6 digits, 30 s step) using only the stdlib."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def verify(secret_b32: str, code: str, now: float, last_counter: int = 0, window: int = 1, step: int = 30):
    """Return the matched counter (> last_counter, so a code cannot be replayed) or None."""
    if not (isinstance(code, str) and len(code) == 6 and code.isascii() and code.isdigit()):
        return None
    key = base64.b32decode(secret_b32)
    cur = int(now // step)
    match = None
    for c in range(cur - window, cur + window + 1):  # no early exit: constant work
        if hmac.compare_digest(hotp(key, c), code) and c > last_counter:
            match = c
    return match


def provisioning_uri(secret_b32: str, account: str, issuer: str = "ProtocolZ") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={urllib.parse.quote(issuer)}"
