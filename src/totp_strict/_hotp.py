import hashlib
import hmac
import struct
from typing import Literal

Algo = Literal["sha1", "sha256", "sha512"]

HASH = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


class HOTP:
    """HMAC-based One-Time Password (RFC 4226)."""

    def __init__(
        self,
        secret: bytes,
        digits: int = 6,
        algorithm: Algo = "sha1",
    ) -> None:
        if not 1 <= digits <= 10:
            raise ValueError("digits must be between 1 and 10")
        if algorithm not in HASH:
            raise ValueError(f"algorithm must be one of {list(HASH)}")
        self.secret = secret
        self.digits = digits
        self.algo = algorithm

    def at(self, counter: int) -> str:
        """HOTP code for the given counter."""
        buf = struct.pack(">Q", counter)
        digest = hmac.new(self.secret, buf, digestmod=HASH[self.algo]).digest()
        offset = digest[-1] & 0x0F
        trunc = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(trunc % (10 ** self.digits)).zfill(self.digits)

    def verify(self, code: str, counter: int) -> bool:
        """Return True if code matches at this counter."""
        return hmac.compare_digest(self.at(counter), code)
