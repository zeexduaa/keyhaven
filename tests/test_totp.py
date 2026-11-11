import base64

import pytest

from keyhaven import totp

# RFC 4226, appendix D: HOTP values for counters 0-9 with this secret.
RFC4226_SECRET = b"12345678901234567890"
RFC4226_CODES = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

# RFC 6238, appendix B: 8-digit TOTP values (30-second steps) for SHA-1, SHA-256 and SHA-512.
SEEDS = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890123456789012",
         "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
RFC6238 = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def test_hotp_rfc4226_vectors():
    assert [totp.hotp(RFC4226_SECRET, i) for i in range(10)] == RFC4226_CODES


@pytest.mark.parametrize("moment, sha1, sha256, sha512", RFC6238)
def test_totp_rfc6238_vectors(moment, sha1, sha256, sha512):
    for algorithm, expected in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
        config = totp.TotpConfig(SEEDS[algorithm], digits=8, period=30, algorithm=algorithm)
        assert totp.code(config, moment) == expected


def test_base32_secrets_as_sites_show_them():
    secret = base64.b32encode(b"12345678901234567890").decode()          # GEZDGNBV...
    spaced = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)).lower()
    assert totp.parse(spaced).secret == b"12345678901234567890"
    assert totp.parse(secret.rstrip("=")).secret == b"12345678901234567890"


def test_otpauth_links():
    secret = base64.b32encode(SEEDS["SHA256"]).decode().rstrip("=")
    config = totp.parse(f"otpauth://totp/Example%20Co:ada@example.com?secret={secret}&issuer=Example%20Co"
                        "&algorithm=SHA256&digits=8&period=60")
    assert (config.issuer, config.account, config.algorithm, config.digits, config.period) == \
        ("Example Co", "ada@example.com", "SHA256", 8, 60)
    assert config.secret == SEEDS["SHA256"]


@pytest.mark.parametrize("text, message", [
    ("", "empty"), ("not base32!!", "isn't a valid 2FA secret"), ("AAAA", "too short"),
    ("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ", "only time-based"),
    ("otpauth://totp/x?issuer=a", "no secret"),
    ("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5", "unsupported algorithm"),
    ("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=4", "6 to 8 digits"),
])
def test_bad_secrets(text, message):
    with pytest.raises(totp.TotpError, match=message):
        totp.parse(text)


def test_seconds_left_and_verify_with_drift():
    config = totp.TotpConfig(RFC4226_SECRET)
    assert totp.seconds_left(config, 59) == 1 and totp.seconds_left(config, 60) == 30
    now = 1_700_000_000
    current = totp.code(config, now)
    previous = totp.code(config, now - 30)
    assert totp.verify(config, current, now) and totp.verify(config, previous, now)
    assert not totp.verify(config, totp.code(config, now - 120), now)


def test_verify_edge_cases():
    config = totp.TotpConfig(RFC4226_SECRET)
    # Near the start of Unix time the step before would be negative, which HOTP can't encode.
    assert totp.verify(config, totp.code(config, 5), at=5)
    # Codes are ASCII digits: anything else is simply wrong, not an error.
    assert not totp.verify(config, "１２３４５６", at=59)          # full-width digits
    assert not totp.verify(config, "abcdef", at=59)
    assert not totp.verify(config, totp.code(config, 59)[:5], at=59)
    assert totp.verify(config, totp.code(config, 59)[:3] + " " + totp.code(config, 59)[3:], at=59)
