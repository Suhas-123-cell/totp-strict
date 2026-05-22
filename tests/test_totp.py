"""RFC 6238 test vectors — https://www.rfc-editor.org/rfc/rfc6238#appendix-B
RFC 6238 errata #2866: each algorithm requires a differently-sized secret.
"""
import pytest
from totp_strict import TOTP

KEY1   = b"12345678901234567890"
KEY256 = b"12345678901234567890123456789012"
KEY512 = b"1234567890123456789012345678901234567890123456789012345678901234"

# (unix_time, algorithm, secret, expected_8digit_code)
VECTORS = [
    (59,          "sha1",   KEY1,   "94287082"),
    (59,          "sha256", KEY256, "46119246"),
    (59,          "sha512", KEY512, "90693936"),
    (1111111109,  "sha1",   KEY1,   "07081804"),
    (1111111109,  "sha256", KEY256, "68084774"),
    (1111111109,  "sha512", KEY512, "25091201"),
    (1111111111,  "sha1",   KEY1,   "14050471"),
    (1111111111,  "sha256", KEY256, "67062674"),
    (1111111111,  "sha512", KEY512, "99943326"),
    (1234567890,  "sha1",   KEY1,   "89005924"),
    (1234567890,  "sha256", KEY256, "91819424"),
    (1234567890,  "sha512", KEY512, "93441116"),
    (2000000000,  "sha1",   KEY1,   "69279037"),
    (2000000000,  "sha256", KEY256, "90698825"),
    (2000000000,  "sha512", KEY512, "38618901"),
    (20000000000, "sha1",   KEY1,   "65353130"),
    (20000000000, "sha256", KEY256, "77737706"),
    (20000000000, "sha512", KEY512, "47863826"),
]


@pytest.mark.parametrize("unix_time,algorithm,secret,expected", VECTORS)
def test_rfc6238_vectors(unix_time, algorithm, secret, expected):
    totp = TOTP(secret, digits=8, algorithm=algorithm, interval=30, t0=0)
    assert totp.at(unix_time) == expected


def test_verify_current_window():
    totp = TOTP(KEY1, digits=8)
    code = totp.at(1234567890)
    assert totp.verify(code, timestamp=1234567890, window=0)


def test_verify_same_window():
    # T=1234567890 and T=1234567919 fall in the same 30-second window
    totp = TOTP(KEY1, digits=8)
    code = totp.at(1234567890)
    assert totp.verify(code, timestamp=1234567919, window=0)


def test_rejects_next_window():
    # T=1234567921 is one window ahead; window=0 must reject it
    totp = TOTP(KEY1, digits=8)
    code = totp.at(1234567890)
    assert not totp.verify(code, timestamp=1234567921, window=0)


def test_verify_with_drift():
    # window=1 should accept a code from an adjacent window
    totp = TOTP(KEY1, digits=8)
    code = totp.at(1234567890)
    assert totp.verify(code, timestamp=1234567921, window=1)


def test_rejects_bad_code():
    totp = TOTP(KEY1, digits=8)
    assert not totp.verify("00000000", timestamp=1234567890, window=0)


def test_provisioning_uri():
    totp = TOTP(KEY1, digits=6)
    uri = totp.provisioning_uri("alice@example.com", issuer="Example")
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
    assert "issuer=Example" in uri


def test_provisioning_uri_no_issuer():
    totp = TOTP(KEY1, digits=6)
    uri = totp.provisioning_uri("alice@example.com")
    assert "issuer" not in uri


def test_sha512_ten_digit():
    """The HENNGE coding challenge uses SHA-512, 10 digits, raw UTF-8 secret."""
    secret = b"test@example.comHENNGECHALLENGE004"
    totp = TOTP(secret, digits=10, algorithm="sha512", interval=30)
    code = totp.now()
    assert len(code) == 10
    assert code.isdigit()
