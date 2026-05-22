import base64
import hmac
import time
import urllib.parse

from ._hotp import HOTP, Algo


class TOTP:
    """Time-based One-Time Password (RFC 6238)."""

    def __init__(
        self,
        secret: bytes,
        digits: int = 6,
        algorithm: Algo = "sha1",
        interval: int = 30,
        t0: int = 0,
    ) -> None:
        self.hotp = HOTP(secret, digits, algorithm)
        self.secret = secret
        self.digits = digits
        self.algo = algorithm
        self.interval = interval
        self.t0 = t0

    def timecode(self, t: float) -> int:
        return int((int(t) - self.t0) // self.interval)

    def at(self, timestamp: float) -> str:
        """TOTP code for the given Unix timestamp."""
        return self.hotp.at(self.timecode(timestamp))

    def now(self) -> str:
        """Current TOTP code."""
        return self.at(time.time())

    def verify(self, code: str, timestamp: float | None = None, window: int = 1) -> bool:
        """Return True if code is valid, accepting ±window intervals for clock drift."""
        t = timestamp if timestamp is not None else time.time()
        tc = self.timecode(t)
        return any(
            hmac.compare_digest(self.hotp.at(tc + i), code)
            for i in range(-window, window + 1)
        )

    def provisioning_uri(self, name: str, issuer: str | None = None) -> str:
        """otpauth:// URI for QR code generation (Google Authenticator compatible)."""
        b32 = base64.b32encode(self.secret).decode("ascii").rstrip("=")
        params = {
            "secret": b32,
            "algorithm": self.algo.upper(),
            "digits": str(self.digits),
            "period": str(self.interval),
        }
        if issuer:
            params["issuer"] = issuer
        label = urllib.parse.quote(f"{issuer}:{name}" if issuer else name, safe=":@")
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{label}?{query}"
