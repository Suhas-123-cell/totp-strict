"""Server-side verification guards: replay prevention and rate limiting.

Both guards ship with lightweight, in-memory implementations that work
out of the box for single-process deployments.  For production systems
that span multiple processes or machines, subclass the protocols and
back them with Redis, a database, or any shared store.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


# ── Replay Guard ─────────────────────────────────────────────────────


@runtime_checkable
class ReplayGuard(Protocol):
    """Interface for tracking used TOTP codes.

    Implementations must be **thread-safe**.
    """

    def mark_used(self, user_id: str, code: str, timecode: int) -> None:
        """Record that *code* was successfully verified for *user_id*
        at the given *timecode* (time-step counter)."""
        ...

    def is_used(self, user_id: str, code: str, timecode: int) -> bool:
        """Return ``True`` if *code* was already verified for *user_id*
        at *timecode*."""
        ...


class MemoryReplayGuard:
    """In-memory replay guard backed by a ``dict``.

    Expired entries are lazily purged on every :meth:`is_used` call.

    Parameters
    ----------
    ttl:
        Seconds after which a recorded code is forgotten.  Should be
        ``interval * (2 * window + 1)`` at minimum — the default of
        ``90`` covers the standard 30 s interval with ±1 window.
    """

    def __init__(self, ttl: int = 90) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        # (user_id, code, timecode) → monotonic timestamp when recorded
        self._store: dict[tuple[str, str, int], float] = {}

    def _purge(self) -> None:
        """Remove entries older than *ttl*."""
        cutoff = time.monotonic() - self._ttl
        expired = [k for k, ts in self._store.items() if ts < cutoff]
        for k in expired:
            del self._store[k]

    def mark_used(self, user_id: str, code: str, timecode: int) -> None:
        with self._lock:
            self._store[(user_id, code, timecode)] = time.monotonic()

    def is_used(self, user_id: str, code: str, timecode: int) -> bool:
        with self._lock:
            self._purge()
            return (user_id, code, timecode) in self._store


# ── Rate Limiter ─────────────────────────────────────────────────────


@runtime_checkable
class RateLimiter(Protocol):
    """Interface for throttling verification attempts.

    Implementations must be **thread-safe**.
    """

    def check(self, user_id: str) -> bool:
        """Return ``True`` if *user_id* is allowed to attempt
        verification right now, ``False`` if locked out."""
        ...

    def record_failure(self, user_id: str) -> None:
        """Record a failed verification attempt for *user_id*.
        Implementations should lock the user out after
        *max_attempts* consecutive failures."""
        ...

    def reset(self, user_id: str) -> None:
        """Clear failure history for *user_id* (e.g. after a
        successful verification)."""
        ...

    def retry_after(self, user_id: str) -> float:
        """Seconds remaining until *user_id*'s lockout expires.
        Returns ``0.0`` if the user is not locked out."""
        ...


class MemoryRateLimiter:
    """In-memory rate limiter backed by a ``dict``.

    Parameters
    ----------
    max_attempts:
        Number of consecutive failures before lockout.
    lockout_seconds:
        Duration of the lockout period in seconds.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_seconds: float = 300,
    ) -> None:
        self._max = max_attempts
        self._lockout = lockout_seconds
        self._lock = threading.Lock()
        # user_id → [failure_count, lockout_expiry (monotonic)]
        self._store: dict[str, list[int | float]] = {}

    def check(self, user_id: str) -> bool:
        with self._lock:
            entry = self._store.get(user_id)
            if entry is None:
                return True
            count, expiry = int(entry[0]), float(entry[1])
            if count >= self._max:
                if time.monotonic() < expiry:
                    return False
                # Lockout expired — reset
                del self._store[user_id]
            return True

    def record_failure(self, user_id: str) -> None:
        with self._lock:
            entry = self._store.get(user_id)
            if entry is None:
                self._store[user_id] = [1, 0.0]
            else:
                entry[0] = int(entry[0]) + 1
                if int(entry[0]) >= self._max:
                    entry[1] = time.monotonic() + self._lockout

    def reset(self, user_id: str) -> None:
        with self._lock:
            self._store.pop(user_id, None)

    def retry_after(self, user_id: str) -> float:
        with self._lock:
            entry = self._store.get(user_id)
            if entry is None:
                return 0.0
            count, expiry = int(entry[0]), float(entry[1])
            if count >= self._max:
                remaining = expiry - time.monotonic()
                return max(0.0, remaining)
            return 0.0
