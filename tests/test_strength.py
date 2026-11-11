import pytest

from keyhaven.strength import crack_time, estimate


@pytest.mark.parametrize("password", [
    "", "password", "123456", "qwertyuiop", "P@ssw0rd1", "Password2024!", "letmein!!", "aaaaaaaaaaaa",
    "abcabcabcabc", "MyDogRex2015", "sunflowerpurple",
])
def test_weak_passwords(password):
    assert estimate(password).score <= 1, password


@pytest.mark.parametrize("password", [
    "correct horse battery staple", "jogevi-mugire-ruveko-buboro-nuzeke", "YxQT^^1&pD5],5bm[wtw",
])
def test_strong_passwords(password):
    assert estimate(password).score >= 3, password


def test_classic_comparison():
    # The xkcd comparison: a mangled word is weak, four random words are strong.
    assert estimate("Tr0ub4dor&3").bits < 40 < 60 < estimate("correct horse battery staple").bits


def test_warnings_explain_what_was_found():
    assert "one of the most common passwords" in estimate("password").warnings[0]
    assert "small changes" in estimate("P4ssword!").warnings[0]
    assert "it has a keyboard pattern" in estimate("ytrewq!9Kz#x").warnings     # qwerty backwards
    assert "it has a sequence like abcd or 1234" in estimate("lmnopq!9Kz#x").warnings
    assert "it repeats characters or chunks" in estimate("xxxxxx!9Kq#z").warnings
    assert "it has a year, which is easy to guess" in estimate("Kq#z!x1987").warnings


def test_personal_details_count_against_it():
    plain = estimate("lovelace!K9x")
    personal = estimate("lovelace!K9x", ["ada.lovelace@example.com"])
    assert personal.bits < plain.bits
    assert "it contains your name, email or the site's name" in personal.warnings


def test_short_passwords_are_capped_and_suggestions_given():
    s = estimate("zK8#mQ2v")
    assert s.score <= 2 and any("longer" in tip for tip in s.suggestions)
    assert any("keyhaven generate" in tip for tip in estimate("password").suggestions + estimate("abc12").suggestions)


def test_crack_times():
    assert crack_time(0) == "instantly"
    assert crack_time(40) == "less than a minute"
    assert "days" in crack_time(55)
    assert crack_time(200) == "longer than the universe has existed"


def test_random_letters_are_not_mistaken_for_words():
    # Letter runs from a generated password ("LmzR4!pQ" reads as "lmzraipq" after undoing l33t)
    # aren't word-like, so they count as random characters.
    assert estimate("Kx8$wq2LmzR4!pQ").score == 4
    assert estimate("CorrectHorseBatteryStaple").bits < estimate("Kx8$wq2LmzR4!pQyT").bits


def test_very_long_passwords_dont_overflow():
    # The generator allows up to 1024 characters; 2 ** bits overflows a float past about 1024 bits.
    result = estimate("Zq8!vL2#pW9&kR4m" * 40)
    assert result.score == 4 and result.crack_time == "longer than the universe has existed"
    assert crack_time(5000) == "longer than the universe has existed"
