"""Encrypt and decrypt TOTP secrets at rest — zero dependencies.

This module provides a simple **encrypt → store → decrypt** workflow so
that TOTP shared secrets never sit in plaintext in a database or config
file.  It uses only the Python standard library:

* **Key derivation** — PBKDF2-HMAC-SHA-256 with a random 16-byte salt
  and 600 000 iterations (OWASP 2024 recommendation).
* **Encryption** — HMAC-SHA-256 keystream XOR (a.k.a. *HMAC-based
  stream cipher*).  Each message gets a unique random IV.
* **Integrity** — HMAC-SHA-256 tag over ``salt ‖ iv ‖ ciphertext``.

.. warning::

   This is **not** AES and is **not** a substitute for
   ``cryptography.fernet``, AWS KMS, or an HSM.  It is provided as a
   *zero-dependency fallback* so that users who cannot add
   ``cryptography`` still get meaningful protection.  For production
   secrets management, prefer a battle-tested library or cloud KMS.

Token format (binary)::

    salt (16 B) ‖ iv (16 B) ‖ ciphertext (N B) ‖ hmac_tag (32 B)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from ._secure import SecureBytes

# ── Constants ────────────────────────────────────────────────────────

_SALT_LEN = 16
_IV_LEN = 16
_TAG_LEN = 32  # HMAC-SHA-256 output
_KDF_ITERATIONS = 600_000
_HEADER_LEN = _SALT_LEN + _IV_LEN


def _derive_keys(master_key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive an encryption key and a MAC key from *master_key*.

    We use PBKDF2 twice with different info bytes so the two keys are
    cryptographically independent.
    """
    enc_key = hashlib.pbkdf2_hmac(
        "sha256", master_key, salt + b"\x01", _KDF_ITERATIONS
    )
    mac_key = hashlib.pbkdf2_hmac(
        "sha256", master_key, salt + b"\x02", _KDF_ITERATIONS
    )
    return enc_key, mac_key


def _keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """Generate *length* bytes of HMAC-SHA-256 keystream."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            key,
            iv + struct.pack(">I", counter),
            digestmod=hashlib.sha256,
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class SecretVault:
    """Encrypt and decrypt TOTP secrets with a master key.

    Example::

        vault = SecretVault(master_key=b"my-32-byte-master-key-here....!!")
        token = vault.encrypt(raw_secret)   # store this in your DB
        secret = vault.decrypt(token)       # returns SecureBytes
        totp = TOTP(bytes(secret))
        secret.wipe()

    Parameters
    ----------
    master_key:
        A high-entropy key (at least 32 bytes recommended).  Keep this
        in an environment variable, OS keyring, or cloud KMS — never in
        source code or in the same database as the encrypted tokens.
    """

    def __init__(self, master_key: bytes | bytearray) -> None:
        if len(master_key) < 16:
            raise ValueError(
                "master_key must be at least 16 bytes "
                "(32+ bytes recommended)"
            )
        self._master_key = bytes(master_key)

    def encrypt(self, secret: bytes | bytearray | SecureBytes) -> bytes:
        """Encrypt *secret* and return a self-contained binary token.

        Each call produces a different token (random salt + IV), so the
        same secret encrypted twice will yield different ciphertexts.
        """
        plaintext = bytes(secret)
        salt = os.urandom(_SALT_LEN)
        iv = os.urandom(_IV_LEN)

        enc_key, mac_key = _derive_keys(self._master_key, salt)
        ks = _keystream(enc_key, iv, len(plaintext))
        ciphertext = _xor(plaintext, ks)

        # MAC covers salt ‖ iv ‖ ciphertext
        payload = salt + iv + ciphertext
        tag = hmac.new(mac_key, payload, digestmod=hashlib.sha256).digest()

        return payload + tag

    def decrypt(self, token: bytes | bytearray) -> SecureBytes:
        """Decrypt a token produced by :meth:`encrypt`.

        Returns a :class:`SecureBytes` so the caller can wipe the
        plaintext after use.

        Raises :class:`ValueError` on truncated tokens or
        authentication failure (wrong key / tampered data).
        """
        min_len = _HEADER_LEN + _TAG_LEN  # salt + iv + tag (empty body OK)
        if len(token) < min_len:
            raise ValueError("Token too short")

        tag = token[-_TAG_LEN:]
        payload = token[:-_TAG_LEN]
        salt = payload[:_SALT_LEN]
        iv = payload[_SALT_LEN : _SALT_LEN + _IV_LEN]
        ciphertext = payload[_HEADER_LEN:]

        enc_key, mac_key = _derive_keys(self._master_key, salt)

        # Verify integrity first
        expected_tag = hmac.new(
            mac_key, payload, digestmod=hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError(
                "Authentication failed — wrong master key or tampered token"
            )

        ks = _keystream(enc_key, iv, len(ciphertext))
        plaintext = _xor(ciphertext, ks)
        return SecureBytes(plaintext)
