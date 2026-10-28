from __future__ import annotations

import base64
import hashlib
import hmac
import os

SCRYPT_N = 2 ** 14  # tests lower this for speed; stored hashes carry their own parameters
_R, _P = 8, 1


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=_R, p=_P, dklen=32, maxmem=64 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${_R}${_P}${_b64(salt)}${_b64(h)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        h = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                           dklen=32, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(h, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


def dummy_hash() -> str:
    """Used to equalise timing when a username does not exist."""
    return hash_password("dummy-password-for-timing")
