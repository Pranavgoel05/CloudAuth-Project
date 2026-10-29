"""Minimal RFC 6238 TOTP implementation using Python's standard library.

This keeps the local demo portable. Codes are 6 digits and rotate every 30 seconds.
For a production product, prefer a well-maintained authentication library and add
recovery codes, replay prevention, enrollment expiration and account recovery.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode


def random_base32(length: int = 20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


class TOTP:
    def __init__(self, secret: str, digits: int = 6, interval: int = 30):
        self.secret = secret
        self.digits = digits
        self.interval = interval

    def _at(self, timestamp: float) -> str:
        key = base64.b32decode(self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8))
        counter = int(timestamp // self.interval)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(value % (10 ** self.digits)).zfill(self.digits)

    def now(self) -> str:
        return self._at(time.time())

    def verify(self, code: str, valid_window: int = 0) -> bool:
        if not isinstance(code, str) or not code.isdigit() or len(code) != self.digits:
            return False
        current = time.time()
        for offset in range(-valid_window, valid_window + 1):
            if hmac.compare_digest(self._at(current + offset * self.interval), code):
                return True
        return False

    def provisioning_uri(self, name: str, issuer_name: str) -> str:
        label = quote(f"{issuer_name}:{name}", safe=":")
        query = urlencode({"secret": self.secret, "issuer": issuer_name, "algorithm": "SHA1",
                           "digits": self.digits, "period": self.interval})
        return f"otpauth://totp/{label}?{query}"


def random_base32_secret() -> str:
    return random_base32()
