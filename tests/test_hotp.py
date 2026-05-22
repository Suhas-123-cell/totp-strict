"""RFC 4226 test vectors — https://www.rfc-editor.org/rfc/rfc4226#appendix-D"""
import pytest
from totp_strict import HOTP

SECRET = b"12345678901234567890"

VECTORS = [
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
]


@pytest.mark.parametrize("counter,expected", VECTORS)
def test_rfc4226_sha1(counter, expected):
    assert HOTP(SECRET, digits=6, algorithm="sha1").at(counter) == expected


def test_verify_valid():
    assert HOTP(SECRET, digits=6).verify("755224", counter=0)


def test_verify_rejects_invalid():
    assert not HOTP(SECRET, digits=6).verify("000000", counter=0)


def test_zero_padding():
    hotp = HOTP(SECRET, digits=6)
    for counter, _ in VECTORS:
        assert len(hotp.at(counter)) == 6


def test_rejects_digits_too_low():
    with pytest.raises(ValueError):
        HOTP(SECRET, digits=0)


def test_rejects_digits_too_high():
    with pytest.raises(ValueError):
        HOTP(SECRET, digits=11)


def test_rejects_bad_algorithm():
    with pytest.raises(ValueError):
        HOTP(SECRET, algorithm="md5")  # type: ignore[arg-type]
