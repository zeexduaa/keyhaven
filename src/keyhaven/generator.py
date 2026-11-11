"""Password, passphrase and PIN generation.

All randomness comes from :mod:`secrets` (the operating system's secure random
source). Each function also reports the result's *entropy*: how many bits of
randomness an attacker who knows exactly how it was made would have to guess.
That's the honest measure of strength for a generated password (unlike the
estimate in :mod:`keyhaven.strength`, which has to guess how a human chose).

Passphrases are made of pronounceable invented words (``tamiko-veludo-...``)
built from syllables, so no word list is needed and every word is easy to say.
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
AMBIGUOUS = set("Il1O0o|`'\"")

CONSONANTS = "bdfgjklmnprstvz"      # no c/q/x (ambiguous sounds), no h/w/y (odd as syllable starts)
VOWELS = "aeiou"
SYLLABLES = [c + v for c in CONSONANTS for v in VOWELS]      # 75
SYLLABLES_PER_WORD = 3

_random = secrets.SystemRandom()


class GeneratorError(ValueError):
    pass


@dataclass(frozen=True)
class Generated:
    value: str
    entropy: float      # bits

    def __str__(self) -> str:
        return self.value


def password(length: int = 20, lower: bool = True, upper: bool = True, digits: bool = True, symbols: bool = True,
             avoid_ambiguous: bool = False) -> Generated:
    """A random password with at least one character from each chosen kind."""
    pools = [pool for pool, wanted in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols)) if wanted]
    if not pools:
        raise GeneratorError("choose at least one kind of character")
    if avoid_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
    if length < len(pools):
        raise GeneratorError(f"a password with {len(pools)} kinds of character needs at least {len(pools)} characters")
    if length > 1024:
        raise GeneratorError("that's too long (1024 characters at most)")
    alphabet = "".join(pools)
    while True:
        chars = [secrets.choice(alphabet) for _ in range(length)]
        # Rejection sampling, not "insert one of each": that would make some positions predictable.
        if all(any(ch in pool for ch in chars) for pool in pools):
            break
    return Generated("".join(chars), _password_entropy(length, pools))


def _password_entropy(length: int, pools: list[str]) -> float:
    """Exact entropy of a uniformly random string over the alphabet, minus the strings that
    miss a required kind (counted with inclusion-exclusion)."""
    from itertools import combinations
    total = 0
    for k in range(len(pools) + 1):
        for excluded in combinations(pools, k):
            size = sum(len(p) for p in pools) - sum(len(p) for p in excluded)
            total += (-1) ** k * size ** length
    return math.log2(total)


def word() -> str:
    return "".join(secrets.choice(SYLLABLES) for _ in range(SYLLABLES_PER_WORD))


def passphrase(words: int = 5, separator: str = "-", capitalize: bool = False, with_number: bool = False) -> Generated:
    """Pronounceable invented words: each is 3 random syllables (75^3, about 18.7 bits).
    Five words is about 93 bits."""
    if not 3 <= words <= 20:
        raise GeneratorError("a passphrase needs between 3 and 20 words")
    parts = [word() for _ in range(words)]
    entropy = words * SYLLABLES_PER_WORD * math.log2(len(SYLLABLES))
    if capitalize:
        parts = [p.capitalize() for p in parts]       # always all words: no entropy, just accepted by more sites
    if with_number:
        position = secrets.randbelow(words)
        digit = secrets.choice(DIGITS)
        parts[position] = parts[position] + digit
        entropy += math.log2(words * 10)
    return Generated(separator.join(parts), entropy)


def pin(length: int = 6) -> Generated:
    if not 4 <= length <= 32:
        raise GeneratorError("a PIN needs between 4 and 32 digits")
    return Generated("".join(secrets.choice(DIGITS) for _ in range(length)), length * math.log2(10))


def describe_entropy(bits: float) -> str:
    if bits < 40:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "good"
    return "excellent"
