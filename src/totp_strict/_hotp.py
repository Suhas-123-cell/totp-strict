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
    """HMAC-based One-Time Password (RFC 4226).

    Accepts both ``bytes`` and :class:`~totp_strict.SecureBytes` for the
    *secret* parameter.  Intermediate HMAC digests are wiped from memory
    after truncation.
    """

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
        # Convert SecureBytes → bytes if needed; store as plain bytes
        # because HMAC needs the key for every call.
        self.secret = bytes(secret)
        self.digits = digits
        self.algo = algorithm

    def at(self, counter: int) -> str:
        """HOTP code for the given counter.

        The intermediate HMAC digest is zeroed after use to reduce the
        window during which it is readable in memory.
        """
        buf = struct.pack(">Q", counter)
        digest_buf = bytearray(
            hmac.new(self.secret, buf, digestmod=HASH[self.algo]).digest()
        )
        offset = digest_buf[-1] & 0x0F
        trunc = (
            struct.unpack(">I", digest_buf[offset : offset + 4])[0]
            & 0x7FFFFFFF
        )
        code = str(trunc % (10 ** self.digits)).zfill(self.digits)

        # Wipe the mutable digest copy
        for i in range(len(digest_buf)):
            digest_buf[i] = 0

        return code

    def verify(self, code: str, counter: int) -> bool:
        """Return True if code matches at this counter."""
        return hmac.compare_digest(self.at(counter), code)
