"""Key derivation and authenticated encryption.

Nothing here is hand-written cryptography: encryption is AES-256-GCM from the
`cryptography` package, key derivation is scrypt from Python's hashlib (OpenSSL),
and randomness comes from the operating system via `secrets`.

- :func:`derive_key` turns the master password into a key-encryption key with
  scrypt. scrypt is deliberately slow and memory-hungry, so each guess at the
  password costs an attacker the same.
- :func:`encrypt` / :func:`decrypt` use AES-256-GCM with a fresh random 96-bit
  nonce per message. GCM also authenticates: any change to the ciphertext, the
  nonce or the associated data makes decryption fail.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32           # AES-256
NONCE_BYTES = 12         # the GCM standard nonce size
SALT_BYTES = 16

# scrypt cost. N=2**17, r=8 uses 128 MiB and takes roughly half a second on a laptop:
# a deliberate cost per guess. Lower values are allowed (tests, slow machines), but not absurd ones.
DEFAULT_N = 2 ** 17
DEFAULT_R = 8
DEFAULT_P = 1
MIN_N, MAX_N = 2 ** 10, 2 ** 22
MAX_MEMORY = 1024 * 1024 * 1024          # 1 GiB: reject a header that asks for more (it may be hostile)


class CryptoError(Exception):
    pass


class DecryptError(CryptoError):
    """The key is wrong, or the data was changed or damaged. GCM can't tell which, by design."""


@dataclass(frozen=True)
class KdfParams:
    n: int
    r: int
    p: int
    salt: bytes

    @classmethod
    def new(cls, n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P) -> KdfParams:
        params = cls(n, r, p, secrets.token_bytes(SALT_BYTES))
        params.validate()
        return params

    @property
    def memory(self) -> int:
        return 128 * self.r * self.n * self.p

    def validate(self) -> None:
        """Rejects parameters that are weak or that would exhaust memory (a tampered header)."""
        if not (MIN_N <= self.n <= MAX_N) or self.n & (self.n - 1):
            raise CryptoError(f"scrypt N must be a power of two between {MIN_N} and {MAX_N}, not {self.n}")
        if not 1 <= self.r <= 32:
            raise CryptoError(f"scrypt r must be between 1 and 32, not {self.r}")
        if not 1 <= self.p <= 16:
            raise CryptoError(f"scrypt p must be between 1 and 16, not {self.p}")
        if self.memory > MAX_MEMORY:
            raise CryptoError("these scrypt settings would need more than 1 GiB of memory")
        if len(self.salt) < SALT_BYTES:
            raise CryptoError(f"the salt must be at least {SALT_BYTES} bytes")


def normalize_password(password: str) -> bytes:
    """The same password typed on different keyboards can produce different Unicode
    (e.g. 'é' as one character or as 'e' + an accent). NFKC makes them the same bytes."""
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def derive_key(password: str, params: KdfParams) -> bytes:
    params.validate()
    return hashlib.scrypt(normalize_password(password), salt=params.salt, n=params.n, r=params.r, p=params.p,
                          maxmem=params.memory + 1024 * 1024, dklen=KEY_BYTES)


def new_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext-with-tag). A new random nonce every time: with 96-bit random
    nonces, a key is safe for far more messages than a vault will ever save."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise DecryptError("bad key or nonce length")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptError("decryption failed: wrong key, or the data was changed") from None
