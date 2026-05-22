# totp-strict

[![CI](https://github.com/Suhas-123-cell/totp-strict/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/totp-strict/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/totp-strict)](https://pypi.org/project/totp-strict/)
[![Python](https://img.shields.io/pypi/pyversions/totp-strict)](https://pypi.org/project/totp-strict/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

RFC 6238 TOTP and RFC 4226 HOTP — full HMAC-SHA-1/256/512 support, zero external dependencies.

## Why not pyotp?

[pyotp](https://github.com/pyauth/pyotp) is the standard choice and works fine for HMAC-SHA-1. The gap shows up with HMAC-SHA-512.

[RFC 6238 errata #2866](https://www.rfc-editor.org/errata/eid2866) corrects a mistake in the original spec's test vectors: the secret length must match the HMAC block size for each algorithm. SHA-512 uses a 128-byte block, so the key should be 64 bytes — not the 20-byte key used for SHA-1. pyotp does not enforce this. The result is a silent mismatch against the official test vectors.

```python
import base64, hashlib, pyotp
from totp_strict import TOTP

# RFC 6238 Appendix B test vector: T=59, HMAC-SHA-512, 8 digits
short_key = b"12345678901234567890"                                                # 20 bytes — pre-errata
long_key  = b"1234567890123456789012345678901234567890123456789012345678901234"    # 64 bytes — errata #2866

p = pyotp.TOTP(base64.b32encode(short_key).decode(), digits=8, digest=hashlib.sha512)
print(p.at(59))   # 69342147  ← does not match RFC 6238

t = TOTP(long_key, digits=8, algorithm="sha512")
print(t.at(59))   # 90693936  ← matches RFC 6238 ✓
```

`totp-strict` passes all 18 RFC 6238 test vectors across SHA-1, SHA-256, and SHA-512.

| Feature | `pyotp` | `totp-strict` |
|---|:---:|:---:|
| HMAC-SHA-1 | ✓ | ✓ |
| HMAC-SHA-256 | ✓ | ✓ |
| HMAC-SHA-512 (errata-correct) | ✗ | ✓ |
| All RFC 4226 test vectors | ✓ | ✓ |
| All RFC 6238 test vectors (SHA-1/256/512) | partial | ✓ |
| QR provisioning URI (Key URI Format) | ✓ | ✓ |
| Zero external dependencies | ✓ | ✓ |
| Python 3.11+ typed | — | ✓ |

## Installation

```bash
pip install totp-strict
```

Requires Python 3.11+. No external dependencies — only the standard library.

## Usage

### TOTP (time-based)

```python
from totp_strict import TOTP

# Standard 6-digit TOTP (Google Authenticator compatible)
totp = TOTP(secret=b"your-secret-key", digits=6, algorithm="sha1")
print(totp.now())           # current code, e.g. "123456"
print(totp.at(1234567890))  # code at a specific Unix timestamp

# Verify with ±1-window drift tolerance (default)
totp.verify("123456")

# Strict — accept only the current window
totp.verify("123456", window=0)

# 8-digit TOTP with HMAC-SHA-256
totp = TOTP(secret=b"your-32-byte-key-here-xxxxxxxxxxx", digits=8, algorithm="sha256")
print(totp.now())

# Generate a QR code URI for Google Authenticator
uri = totp.provisioning_uri("alice@example.com", issuer="MyApp")
# → otpauth://totp/MyApp:alice@example.com?secret=...&algorithm=SHA1&digits=6&period=30
```

### HOTP (counter-based)

```python
from totp_strict import HOTP

hotp = HOTP(secret=b"12345678901234567890", digits=6)
print(hotp.at(0))                    # "755224"  (RFC 4226 test vector)
print(hotp.at(1))                    # "287082"
hotp.verify("755224", counter=0)     # True
```

## API reference

### `TOTP(secret, digits=6, algorithm="sha1", interval=30, t0=0)`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `secret` | `bytes` | — | Raw secret bytes (not base32-encoded) |
| `digits` | `int` | `6` | OTP length, 1–10 |
| `algorithm` | `"sha1"` \| `"sha256"` \| `"sha512"` | `"sha1"` | HMAC hash function |
| `interval` | `int` | `30` | Time-step in seconds |
| `t0` | `int` | `0` | Unix epoch start (T0) |

| Method | Returns | Description |
|---|---|---|
| `.now()` | `str` | Current TOTP code |
| `.at(timestamp)` | `str` | TOTP code at a Unix timestamp |
| `.verify(code, timestamp=None, window=1)` | `bool` | Constant-time verification with drift tolerance |
| `.provisioning_uri(name, issuer=None)` | `str` | `otpauth://` URI — see below |

`window=1` (default) accepts codes from the previous, current, and next interval (±30 s with the default step).

#### Provisioning URI

`.provisioning_uri()` produces an `otpauth://totp/` URI that follows the [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

- Label format: `issuer:account` — the colon and `@` are left unencoded, all other special characters are percent-encoded
- Secret: base32-encoded, padding stripped (no `=`)
- Algorithm: uppercase (`SHA1`, `SHA256`, `SHA512`)

Scannable by Google Authenticator, Authy, and any app that supports the Key URI Format.

### `HOTP(secret, digits=6, algorithm="sha1")`

| Method | Returns | Description |
|---|---|---|
| `.at(counter)` | `str` | HOTP code at a counter value |
| `.verify(code, counter)` | `bool` | Constant-time verification |

## RFC compliance

### RFC 4226 — HOTP test vectors

Secret: `b"12345678901234567890"`, HMAC-SHA-1, 6 digits ([Appendix D](https://www.rfc-editor.org/rfc/rfc4226#appendix-D))

| Counter | Expected | Status |
|---|---|---|
| 0 | 755224 | ✓ |
| 1 | 287082 | ✓ |
| 2 | 359152 | ✓ |
| 3 | 969429 | ✓ |
| 4 | 338314 | ✓ |
| 5 | 254676 | ✓ |
| 6 | 287922 | ✓ |
| 7 | 162583 | ✓ |
| 8 | 399871 | ✓ |
| 9 | 520489 | ✓ |

### RFC 6238 — TOTP test vectors

8-digit TOTP, interval=30, T0=0 ([Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B) + [errata #2866](https://www.rfc-editor.org/errata/eid2866))

| Unix time | SHA-1 | SHA-256 | SHA-512 |
|---|---|---|---|
| 59 | 94287082 ✓ | 46119246 ✓ | 90693936 ✓ |
| 1111111109 | 07081804 ✓ | 68084774 ✓ | 25091201 ✓ |
| 1111111111 | 14050471 ✓ | 67062674 ✓ | 99943326 ✓ |
| 1234567890 | 89005924 ✓ | 91819424 ✓ | 93441116 ✓ |
| 2000000000 | 69279037 ✓ | 90698825 ✓ | 38618901 ✓ |
| 20000000000 | 65353130 ✓ | 77737706 ✓ | 47863826 ✓ |

Run `pytest tests/ -v` to verify locally.

## Development

```bash
git clone https://github.com/Suhas-123-cell/totp-strict
cd totp-strict
pip install -e ".[dev]"
pytest tests/ -v
```

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/Suhas-123-cell/totp-strict).

When filing a bug report, include the secret, algorithm, and timestamp (or counter) that produces the wrong output, plus the expected value and a reference (RFC section or errata ID).

When opening a pull request, add a test case that covers the change and make sure all existing tests pass.

## License

MIT — see [LICENSE](LICENSE).
