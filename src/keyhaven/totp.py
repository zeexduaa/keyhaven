"""Time-based one-time passwords (the 6-digit codes of authenticator apps).

Implements HOTP (RFC 4226) and TOTP (RFC 6238) with Python's hmac. A site's
two-factor secret can be stored as the base32 secret it shows (``JBSW Y3DP ...``)
or as the ``otpauth://totp/...`` link inside its QR code, which also says how
many digits, how long each code lasts and which hash to use.

Keeping 2FA secrets in the same vault as the passwords is convenient, but it
means the vault holds both factors: see docs/security.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TotpError(ValueError):
    pass


@dataclass(frozen=True)
class TotpConfig:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    account: str = ""


def decode_secret(text: str) -> bytes:
    """Base32, as sites show it: any case, with spaces or dashes, padding optional."""
    cleaned = "".join(text.split()).replace("-", "").upper()
    if not cleaned:
        raise TotpError("the 2FA secret is empty")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned)
    except (ValueError, base64.binascii.Error):
        raise TotpError("that isn't a valid 2FA secret (it should be base32: letters A-Z and digits 2-7)") from None
    if len(secret) < 5:
        raise TotpError("that 2FA secret is too short to be real")
    return secret


def parse(text: str) -> TotpConfig:
    """A base32 secret or an otpauth://totp/ URI."""
    text = text.strip()
    if not text.lower().startswith("otpauth://"):
        return TotpConfig(decode_secret(text))
    url = urlparse(text)
    if url.netloc.lower() != "totp":
        raise TotpError(f"only time-based codes (otpauth://totp/) are supported, not {url.netloc or '?'}")
    query = {k.lower(): v[0] for k, v in parse_qs(url.query).items()}
    if "secret" not in query:
        raise TotpError("the otpauth link has no secret")
    label = unquote(url.path.lstrip("/"))
    issuer, _, account = label.partition(":") if ":" in label else ("", "", label)
    try:
        digits = int(query.get("digits", 6))
        period = int(query.get("period", 30))
    except ValueError:
        raise TotpError("the otpauth link has a bad digits or period value") from None
    algorithm = query.get("algorithm", "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise TotpError(f"unsupported algorithm {algorithm} (use SHA1, SHA256 or SHA512)")
    if not 6 <= digits <= 8:
        raise TotpError("codes must have 6 to 8 digits")
    if not 10 <= period <= 300:
        raise TotpError("the code period must be between 10 and 300 seconds")
    return TotpConfig(decode_secret(query["secret"]), digits, period, algorithm,
                      query.get("issuer", issuer).strip(), account.strip())


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """RFC 4226: HMAC the counter, take 4 bytes at an offset given by the last nibble, keep the low digits."""
    mac = hmac.new(secret, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


def code(config: TotpConfig, at: float | None = None) -> str:
    """The code for time ``at`` (default: now)."""
    moment = time.time() if at is None else at
    return hotp(config.secret, int(moment // config.period), config.digits, config.algorithm)


def seconds_left(config: TotpConfig, at: float | None = None) -> int:
    moment = time.time() if at is None else at
    return config.period - int(moment % config.period)


def verify(config: TotpConfig, candidate: str, at: float | None = None, window: int = 1) -> bool:
    """True if ``candidate`` is the code for now or ``window`` periods either side (clock drift)."""
    moment = time.time() if at is None else at
    candidate = candidate.strip().replace(" ", "")
    # compare_digest refuses non-ASCII text (TypeError), and a code is only ever ASCII digits.
    if not (candidate.isascii() and candidate.isdigit() and len(candidate) == config.digits):
        return False
    steps = (moment + k * config.period for k in range(-window, window + 1))
    return any(hmac.compare_digest(code(config, t), candidate) for t in steps if t >= 0)   # no time before 1970
