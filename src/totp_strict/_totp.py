"""Time-based One-Time Password (RFC 6238) with optional security guards.

The core :meth:`TOTP.verify` method remains **fully backward-compatible**
— it returns a plain ``bool`` and requires no extra arguments.

For server-side hardening, use :meth:`TOTP.verify_strict`, which
enforces replay prevention and rate limiting, raising
:class:`~totp_strict.RateLimitExceeded` or
:class:`~totp_strict.CodeAlreadyUsed` on policy violations.
"""

from __future__ import annotations

import base64
import hmac
import time
import urllib.parse

from ._exceptions import CodeAlreadyUsed, RateLimitExceeded
from ._guards import RateLimiter, ReplayGuard
from ._hotp import HOTP, Algo


class TOTP:
    """Time-based One-Time Password (RFC 6238).

    Parameters
    ----------
    secret:
        Raw secret bytes.  Both ``bytes`` and
        :class:`~totp_strict.SecureBytes` are accepted.
    digits:
        OTP length (1–10).
    algorithm:
        HMAC hash function (``"sha1"``, ``"sha256"``, ``"sha512"``).
    interval:
        Time-step in seconds.
    t0:
        Unix epoch start (T0).
    replay_guard:
        Optional :class:`~totp_strict.ReplayGuard` implementation for
        tracking used codes.  Required by :meth:`verify_strict`.
    rate_limiter:
        Optional :class:`~totp_strict.RateLimiter` implementation for
        throttling failed attempts.  Required by :meth:`verify_strict`.
    """

    def __init__(
        self,
        secret: bytes,
        digits: int = 6,
        algorithm: Algo = "sha1",
        interval: int = 30,
        t0: int = 0,
        replay_guard: ReplayGuard | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.hotp = HOTP(secret, digits, algorithm)
        self.secret = bytes(secret)
        self.digits = digits
        self.algo = algorithm
        self.interval = interval
        self.t0 = t0
        self._replay_guard = replay_guard
        self._rate_limiter = rate_limiter

    def timecode(self, t: float) -> int:
        return int((int(t) - self.t0) // self.interval)

    def at(self, timestamp: float) -> str:
        """TOTP code for the given Unix timestamp."""
        return self.hotp.at(self.timecode(timestamp))

    def now(self) -> str:
        """Current TOTP code."""
        return self.at(time.time())

    def verify(
        self,
        code: str,
        timestamp: float | None = None,
        window: int = 1,
    ) -> bool:
        """Return True if code is valid, accepting ±window intervals for clock drift.

        This method is **backward-compatible** — it returns a ``bool``
        and never raises guard-related exceptions.  For server-side
        hardening see :meth:`verify_strict`.
        """
        t = timestamp if timestamp is not None else time.time()
        tc = self.timecode(t)
        return any(
            hmac.compare_digest(self.hotp.at(tc + i), code)
            for i in range(-window, window + 1)
        )

    def verify_strict(
        self,
        code: str,
        user_id: str,
        timestamp: float | None = None,
        window: int = 1,
    ) -> bool:
        """Verify *code* with replay prevention and rate limiting.

        This method **requires** a ``replay_guard`` and ``rate_limiter``
        to have been set on the :class:`TOTP` instance (passed via the
        constructor).

        Parameters
        ----------
        code:
            The OTP string submitted by the user.
        user_id:
            A unique identifier for the user (used to scope replay
            tracking and rate limiting).
        timestamp:
            Unix timestamp to verify against (defaults to now).
        window:
            Number of adjacent time-steps to accept (default ±1).

        Returns
        -------
        bool
            ``True`` if the code is valid *and* has not been used before.

        Raises
        ------
        ValueError
            If ``replay_guard`` or ``rate_limiter`` was not configured.
        RateLimitExceeded
            If *user_id* has exceeded the allowed number of failed
            attempts and is locked out.
        CodeAlreadyUsed
            If *code* was already successfully verified within the
            current validity window (replay attempt).
        """
        if self._replay_guard is None or self._rate_limiter is None:
            raise ValueError(
                "verify_strict() requires both a replay_guard and a "
                "rate_limiter.  Pass them to the TOTP constructor."
            )

        # 1. Rate-limit check
        if not self._rate_limiter.check(user_id):
            retry = self._rate_limiter.retry_after(user_id)
            raise RateLimitExceeded(user_id, retry)

        t = timestamp if timestamp is not None else time.time()
        tc = self.timecode(t)

        # 2. Find a matching timecode
        matched_tc: int | None = None
        for i in range(-window, window + 1):
            candidate_tc = tc + i
            if hmac.compare_digest(self.hotp.at(candidate_tc), code):
                matched_tc = candidate_tc
                break

        if matched_tc is None:
            # Invalid code → record failure
            self._rate_limiter.record_failure(user_id)
            return False

        # 3. Replay check
        if self._replay_guard.is_used(user_id, code, matched_tc):
            raise CodeAlreadyUsed(user_id)

        # 4. Success → mark used and reset limiter
        self._replay_guard.mark_used(user_id, code, matched_tc)
        self._rate_limiter.reset(user_id)
        return True

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
