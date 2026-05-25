"""Secure memory primitives for handling TOTP secrets.

This module provides :class:`SecureBytes` — a mutable buffer that can be
explicitly zeroed — and :func:`generate_secret` for producing
cryptographically-strong secrets sized to RFC 6238 requirements.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Literal

# HMAC block sizes per algorithm (RFC 6238 errata #2866).
_KEY_SIZES: dict[str, int] = {
    "sha1": 20,
    "sha256": 32,
    "sha512": 64,
}


class SecureBytes:
    """A secret stored in a mutable ``bytearray`` that can be wiped.

    Unlike immutable ``bytes``, a ``bytearray`` lets us overwrite every
    byte with ``0x00`` when the secret is no longer needed — minimising
    the window during which an attacker with memory access could extract
    the key.

    Usage as a context manager guarantees the buffer is wiped on exit::

        with SecureBytes(raw_key) as sb:
            totp = TOTP(bytes(sb))
            code = totp.now()
        # sb is wiped here, even if an exception occurred

    Direct attribute access::

        sb = SecureBytes(raw_key)
        totp = TOTP(bytes(sb))
        sb.wipe()              # explicit wipe when done

    Safety features:

    * ``str()`` / ``repr()`` never reveal the payload.
    * Equality uses constant-time comparison (``hmac.compare_digest``).
    * ``__del__`` wipes on garbage collection as a last-resort safety net.
    """

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray) -> None:
        self._buf = bytearray(data)
        self._wiped = False

    # --- context-manager interface ------------------------------------

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.wipe()

    # --- explicit wipe ------------------------------------------------

    def wipe(self) -> None:
        """Overwrite every byte with ``0x00`` and mark as wiped."""
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._wiped = True

    @property
    def is_wiped(self) -> bool:
        """``True`` after :meth:`wipe` has been called."""
        return self._wiped

    # --- controlled access --------------------------------------------

    def __bytes__(self) -> bytes:
        """Return an immutable snapshot.

        Raises :class:`ValueError` if the buffer has been wiped.
        """
        if self._wiped:
            raise ValueError("SecureBytes has been wiped")
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    # --- comparison (constant-time) -----------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecureBytes):
            return hmac.compare_digest(self._buf, other._buf)
        if isinstance(other, (bytes, bytearray)):
            return hmac.compare_digest(self._buf, other)
        return NotImplemented

    def __hash__(self) -> int:  # unhashable — mutable
        raise TypeError("SecureBytes is unhashable")

    # --- leak prevention ----------------------------------------------

    def __repr__(self) -> str:
        state = "wiped" if self._wiped else f"{len(self._buf)} bytes"
        return f"SecureBytes({state})"

    def __str__(self) -> str:
        return self.__repr__()

    # --- last-resort cleanup ------------------------------------------

    def __del__(self) -> None:
        try:
            if not self._wiped:
                self.wipe()
        except Exception:  # noqa: BLE001 — destructor must not raise
            pass


def generate_secret(
    algorithm: Literal["sha1", "sha256", "sha512"] = "sha1",
    length: int | None = None,
) -> SecureBytes:
    """Generate a cryptographically-secure TOTP secret.

    Parameters
    ----------
    algorithm:
        HMAC algorithm the secret will be used with.  The default length
        is chosen to match the HMAC block size per RFC 6238 errata #2866
        (20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512).
    length:
        Override the automatic sizing.  Must be a positive integer.

    Returns
    -------
    SecureBytes
        The generated secret wrapped in a wipeable buffer.
    """
    if length is not None:
        if length < 1:
            raise ValueError("length must be a positive integer")
        n = length
    else:
        if algorithm not in _KEY_SIZES:
            raise ValueError(f"algorithm must be one of {list(_KEY_SIZES)}")
        n = _KEY_SIZES[algorithm]

    return SecureBytes(secrets.token_bytes(n))
