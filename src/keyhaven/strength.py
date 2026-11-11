"""Estimating how strong a human-chosen password is.

Counting character kinds ("has a digit and a symbol!") says little: ``P@ssw0rd1``
has all four kinds and is among the first guesses any attacker tries. Instead,
this module looks for what attackers try first and charges each pattern only
what it would cost to guess:

- very common passwords, also after undoing l33t speak (``p@$$w0rd``);
- keyboard runs (``qwerty``, ``asdf``) and sequences (``abcd``, ``4321``);
- repeated characters or chunks (``aaaa``, ``abcabc``);
- years (``1987``), and the user's own name, email or site (``user_inputs``).

What's left is counted as random characters from the kinds present. The result is
an estimate of the bits an attacker must guess, a 0 to 4 score, a crack time, and
feedback in plain words. It's an estimate (zxcvbn does the same thing far more
thoroughly); a generated password's real entropy comes from :mod:`generator`.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field

# A short list of the passwords people choose most. Matching these (and their l33t forms)
# catches most of the real-world worst cases.
COMMON = [
    "password", "123456", "123456789", "12345678", "12345", "qwerty", "1234567", "111111", "123123", "abc123",
    "1234567890", "password1", "1234", "000000", "iloveyou", "aa123456", "qwerty123", "dragon", "monkey", "letmein",
    "football", "baseball", "sunshine", "princess", "shadow", "master", "welcome", "login", "admin", "passw0rd",
    "starwars", "superman", "batman", "trustno1", "hello", "freedom", "whatever", "qazwsx", "michael", "jennifer",
    "jordan", "hunter", "hunter2", "ranger", "buster", "soccer", "hockey", "killer", "george", "charlie", "andrew",
    "michelle", "love", "jessica", "pepper", "daniel", "access", "joshua", "maggie", "ginger", "summer", "flower",
    "cheese", "computer", "secret", "internet", "samsung", "google", "apple", "orange", "banana", "chocolate",
    "pokemon", "minecraft", "fortnite", "liverpool", "chelsea", "arsenal", "matrix", "thomas", "robert", "william",
    "nicole", "ashley", "tigger", "purple", "silver", "golden", "diamond", "angel", "angels", "lovely", "family",
    "friends", "forever", "heaven", "blessed", "london", "berlin", "paris", "newyork", "money", "dollar", "player",
    "gamer", "changeme", "default", "guest", "root", "toor", "test", "testing", "temp", "temppass", "letmein1",
    "welcome1", "admin123", "root123", "pass", "pass123", "mypassword", "mypass", "abcdef", "abcd1234", "qwertyuiop",
    "asdfgh", "asdfghjkl", "zxcvbnm", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "q1w2e3r4", "987654321", "654321",
    "666666", "121212", "112233", "123321", "7777777", "88888888", "11111111", "123qwe", "qwe123", "a1b2c3",
    "dragon1", "monkey1", "iloveu", "loveyou", "babygirl", "cookie", "snoopy", "butterfly", "princess1", "sunshine1",
]
COMMON_RANK = {pw: i for i, pw in enumerate(COMMON)}

LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t",
                      "+": "t", "9": "g", "8": "b", "|": "l"})
KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"]

GUESSES_PER_SECOND = 1e10      # an offline attack on a fast hash with a few GPUs


@dataclass
class Strength:
    score: int                      # 0 (terrible) to 4 (strong)
    bits: float                     # estimated bits an attacker must guess
    crack_time: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return ["very weak", "weak", "fair", "strong", "very strong"][self.score]


def estimate(password: str, user_inputs: list[str] | None = None) -> Strength:
    if not password:
        return Strength(0, 0.0, crack_time(0), ["the password is empty"], ["use a generated password"])
    warnings: list[str] = []
    suggestions: list[str] = []
    lower = password.lower()

    # 1. The whole password is a common one (maybe in l33t, maybe with a number or symbol stuck on).
    core = lower.translate(LEET)
    stripped = core.rstrip(string.digits + string.punctuation)
    # Strip what's stuck on the end before undoing l33t too, or "P4ssword!" becomes "passwordi".
    stripped_first = lower.rstrip(string.digits + string.punctuation).translate(LEET)
    for candidate in (lower, core, stripped, stripped_first):
        if candidate in COMMON_RANK:
            extra = len(lower) - len(candidate)
            bits = math.log2(COMMON_RANK[candidate] + 2) + (2 if candidate != lower else 0) + \
                (math.log2(1 + extra) * 3 if extra > 0 else 0)
            return Strength(0, bits, crack_time(bits),
                            ["this is one of the most common passwords" if candidate == lower else
                             "this is a common password with small changes, which attackers try early"],
                            ["use a generated password or a passphrase of several random words"])

    pool = pool_size(password)
    covered = [False] * len(password)
    bits = 0.0

    def charge(start: int, end: int, cost: float, warning: str | None = None) -> None:
        nonlocal bits
        if any(covered[start:end]):
            return
        for i in range(start, end):
            covered[i] = True
        bits += cost
        if warning and warning not in warnings:
            warnings.append(warning)

    # 2. The user's own details.
    for item in user_inputs or []:
        for piece in _pieces(item):
            pos = lower.find(piece)
            if pos >= 0:
                charge(pos, pos + len(piece), 2, "it contains your name, email or the site's name")

    # 3. Common passwords inside it.
    for i in range(len(core)):
        for j in range(len(core), i + 3, -1):
            word = core[i:j]
            if word in COMMON_RANK:
                charge(i, j, math.log2(COMMON_RANK[word] + 2) + _caps_bits(password[i:j]),
                       "it contains a common password or word")
                break

    # 4. Repeats (before sequences, so abcabc counts as one repeated chunk), keyboard runs,
    #    sequences and years.
    for start, end, unit in _repeats(password):
        charge(start, end, unit * math.log2(pool) + math.log2(end - start), "it repeats characters or chunks")
    for start, end in _years(password):        # before sequences, so 1987 isn't read as 987
        charge(start, end, math.log2(150), "it has a year, which is easy to guess")
    for start, end in _keyboard_runs(lower):
        charge(start, end, math.log2(len(KEYBOARD_ROWS) * 40) + math.log2(end - start), "it has a keyboard pattern")
    for start, end in _sequences(lower):
        charge(start, end, math.log2(36 * 2) + math.log2(end - start), "it has a sequence like abcd or 1234")

    # 5. Runs of letters might be dictionary words. Without shipping a dictionary, charge each run
    #    at most what one word from a large one (50,000 words) would cost, so real-word passphrases
    #    aren't mistaken for random letters. Only runs that look like words count (see _word_like);
    #    the rest, like the letters of a generated password, stay random.
    #    Words are found after undoing l33t (Tr0ub4dor -> troubador); LEET maps one character to one,
    #    so positions line up with the original password.
    import re
    for m in re.finditer(r"[a-z]{4,}", core):
        # CamelCase is several words: split where a lower-case letter is followed by a capital.
        cuts = [m.start()] + [i for i in range(m.start() + 1, m.end())
                              if password[i - 1].islower() and password[i].isupper()] + [m.end()]
        for start, end in zip(cuts, cuts[1:]):
            original, letters_only = password[start:end], core[start:end]
            if end - start < 2 or not _word_like(original, letters_only):
                continue
            substitutions = sum(1 for a, b in zip(original.lower(), letters_only) if a != b)
            letters = 52 if (original.lower() != original and original.upper() != original) else 26
            # Short words come from much smaller lists: there are only about 200 two-letter
            # and 1,000 three-letter words in common use.
            dictionary = {2: 200, 3: 1_000}.get(end - start, 50_000)
            charge(start, end, min((end - start) * math.log2(letters),
                                   math.log2(dictionary) + _caps_bits(original) + min(substitutions, 3)))

    # 6. Everything else counts as random characters, except that repeating a separator
    #    (the spaces in "correct horse battery staple") adds almost nothing.
    separators_seen: set[str] = set()
    for i, ch in enumerate(password):
        if covered[i]:
            continue
        if not ch.isalnum() and ch in separators_seen:
            bits += 1
        else:
            bits += math.log2(pool)
            if not ch.isalnum():
                separators_seen.add(ch)
    bits = max(bits, 0.0)

    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    if len(password) < 10:
        suggestions.append("make it longer: length matters more than odd characters")
        score = min(score, 2)
    if score < 3 and not suggestions:
        suggestions.append("add a few more random words or characters")
    if score < 3:
        suggestions.append("or let keyhaven generate one: keyhaven generate")
    return Strength(score, bits, crack_time(bits), warnings, suggestions)


def pool_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100
    return max(size, 10)


def crack_time(bits: float) -> str:
    if bits > 200:          # 2 ** bits overflows a float past about 1024 bits; anything here is beyond reach
        return "longer than the universe has existed"
    seconds = 2 ** bits / 2 / GUESSES_PER_SECOND        # on average, half the space is searched
    for unit, size in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400), ("hours", 3600), ("minutes", 60)):
        if seconds >= size:
            amount = seconds / size
            if unit == "centuries" and amount > 1e6:
                return "longer than the universe has existed" if amount > 1.4e8 else "millions of years"
            return f"about {amount:,.0f} {unit}" if amount >= 2 else f"about 1 {unit[:-1] if unit != 'centuries' else 'century'}"
    return "less than a minute" if seconds >= 1 else "instantly"


def _word_like(original: str, letters: str) -> bool:
    """Could this run be a real word? Words are written lower, Title or UPPER case, have vowels,
    and don't start with more than three consonants or bunch up more than four (strengths has
    "ngths", but random letters like "lmzrpq" fail). Runs that fail are counted as random letters."""
    if not (original.islower() or original.isupper() or (original[:1].isupper() and original[1:].islower())):
        if not any(not c.isalpha() for c in original):       # l33t forms keep the case check loose
            return False
    vowels = sum(c in "aeiouy" for c in letters)
    if vowels == 0 or vowels / len(letters) < 0.12:
        return False
    import re
    clusters = re.findall(r"[^aeiouy]+", letters)
    leading = re.match(r"[^aeiouy]*", letters).group()
    return len(leading) <= 3 and all(len(c) <= 5 for c in clusters)


def _caps_bits(word: str) -> float:
    if word.islower() or not any(c.isalpha() for c in word):
        return 0.0
    if word[:1].isupper() and word[1:].islower():
        return 1.0
    return 2.0


def _pieces(item: str) -> list[str]:
    """'ada.lovelace@example.com' -> ['ada', 'lovelace', 'example']: the parts worth checking."""
    import re
    parts = re.split(r"[^a-z0-9]+", item.lower())
    return [p for p in parts if len(p) >= 3 and p not in ("com", "org", "net", "www", "http", "https")]


def _keyboard_runs(text: str) -> list[tuple[int, int]]:
    runs = []
    i = 0
    while i < len(text):
        best = 0
        for row in KEYBOARD_ROWS:
            for direction in (row, row[::-1]):
                pos = direction.find(text[i])
                if pos < 0:
                    continue
                length = 1
                while i + length < len(text) and pos + length < len(direction) and \
                        text[i + length] == direction[pos + length]:
                    length += 1
                best = max(best, length)
        if best >= 4:
            runs.append((i, i + best))
            i += best
        else:
            i += 1
    return runs


def _sequences(text: str) -> list[tuple[int, int]]:
    runs = []
    i = 0
    while i < len(text) - 2:
        step = ord(text[i + 1]) - ord(text[i])
        if step in (1, -1) and text[i].isalnum():
            j = i + 1
            while j + 1 < len(text) and ord(text[j + 1]) - ord(text[j]) == step and text[j + 1].isalnum():
                j += 1
            if j - i + 1 >= 3:
                runs.append((i, j + 1))
                i = j + 1
                continue
        i += 1
    return runs


def _repeats(text: str) -> list[tuple[int, int, int]]:
    """(start, end, unit length) for runs like aaaa or abcabc (the repeated unit costs once)."""
    found = []
    i = 0
    while i < len(text):
        best = None
        for unit in range(1, len(text) // 2 + 1):
            chunk = text[i:i + unit]
            if len(chunk) < unit:
                break
            reps = 1
            while text[i + reps * unit:i + (reps + 1) * unit] == chunk:
                reps += 1
            total = reps * unit
            if reps >= 2 and total >= 3 and (best is None or total > best[1] - best[0]):
                best = (i, i + total, unit)
        if best:
            found.append(best)
            i = best[1]
        else:
            i += 1
    return found


def _years(text: str) -> list[tuple[int, int]]:
    import re
    return [(m.start(), m.end()) for m in re.finditer(r"(?<!\d)(19\d\d|20[0-4]\d)(?!\d)", text)]
