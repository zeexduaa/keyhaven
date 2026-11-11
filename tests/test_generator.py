import math
import string
from collections import Counter

import pytest

from keyhaven import generator as g


def test_passwords_have_the_length_and_every_requested_kind():
    for _ in range(200):
        pw = g.password(8).value
        assert len(pw) == 8
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in g.SYMBOLS for c in pw)


def test_kinds_can_be_left_out_and_ambiguous_characters_avoided():
    pw = g.password(64, symbols=False, upper=False).value
    assert set(pw) <= set(string.ascii_lowercase + string.digits)
    clear = "".join(g.password(64, avoid_ambiguous=True).value for _ in range(20))
    assert not set(clear) & g.AMBIGUOUS


def test_characters_are_spread_evenly():
    # Rough check that no character is strongly favoured (catches modulo bias or a broken shuffle).
    counts = Counter("".join(g.password(100, symbols=False, upper=False, digits=False).value for _ in range(400)))
    expected = 40000 / 26
    assert all(abs(n - expected) < expected * 0.15 for n in counts.values())


def test_password_entropy_is_exact():
    # 20 characters from 26 letters only: exactly 20 * log2(26).
    assert g.password(20, upper=False, digits=False, symbols=False).entropy == pytest.approx(20 * math.log2(26))
    # Requiring every kind removes a little entropy compared with the full alphabet.
    full = 20 * math.log2(26 + 26 + 10 + len(g.SYMBOLS))
    assert full - 1 < g.password(20).entropy < full


@pytest.mark.parametrize("kwargs, message", [
    ({"lower": False, "upper": False, "digits": False, "symbols": False}, "at least one kind"),
    ({"length": 3}, "at least 4 characters"),
    ({"length": 5000}, "too long"),
])
def test_bad_password_requests(kwargs, message):
    with pytest.raises(g.GeneratorError, match=message):
        g.password(**kwargs)


def test_passphrases():
    phrase = g.passphrase(5)
    words = phrase.value.split("-")
    assert len(words) == 5 and all(len(w) == 6 and w.isalpha() and w.islower() for w in words)
    assert phrase.entropy == pytest.approx(5 * 3 * math.log2(75))
    assert phrase.entropy > 90
    fancy = g.passphrase(4, separator=" ", capitalize=True, with_number=True)
    parts = fancy.value.split(" ")
    assert all(p[0].isupper() for p in parts) and sum(any(c.isdigit() for c in p) for p in parts) == 1
    assert fancy.entropy > g.passphrase(4).entropy
    with pytest.raises(g.GeneratorError):
        g.passphrase(2)


def test_pins_and_descriptions():
    p = g.pin(6)
    assert p.value.isdigit() and len(p.value) == 6 and p.entropy == pytest.approx(6 * math.log2(10))
    assert [g.describe_entropy(b) for b in (30, 50, 70, 100)] == ["weak", "fair", "good", "excellent"]


def test_generated_values_differ():
    assert len({g.password(16).value for _ in range(50)}) == 50
    assert len({g.passphrase(4).value for _ in range(50)}) == 50
