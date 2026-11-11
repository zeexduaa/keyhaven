"""Checking a vault for passwords that should be changed.

Offline checks (nothing leaves the computer):

- weak: the strength estimate scores it below "strong";
- reused: the same password is stored in more than one entry, so one breached
  site exposes the others;
- old: not changed for a long time (default: a year);
- similar: it differs from another entry's password only by a number or a
  symbol at the end (``Summer2023!`` and ``Summer2024!``).

The optional online check asks the Have I Been Pwned "Pwned Passwords" service
whether a password appears in known breaches. It uses k-anonymity: only the
first 5 hex characters of the password's SHA-1 hash are sent, the service replies
with every breached hash that starts with them (hundreds), and the match is done
here. The password and its full hash never leave the computer.
"""

from __future__ import annotations

import hashlib
import string
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from . import strength
from .entries import Entry

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"


@dataclass
class Finding:
    entry: Entry
    kind: str            # weak, reused, similar, old, breached
    detail: str


@dataclass
class Report:
    checked: int
    findings: list[Finding] = field(default_factory=list)
    online_error: str = ""

    def by_kind(self, kind: str) -> list[Finding]:
        return [f for f in self.findings if f.kind == kind]

    @property
    def entries_with_problems(self) -> int:
        return len({f.entry.id for f in self.findings})


Fetcher = Callable[[str], str]


def fetch_range(prefix: str) -> str:
    request = urllib.request.Request(PWNED_RANGE_URL + prefix, headers={
        "User-Agent": "keyhaven-password-manager", "Add-Padding": "true"})   # padding hides the reply size too
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8")


def breach_count(password: str, fetch: Fetcher = fetch_range) -> int:
    """How many times the password appears in known breaches (0 = not found)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    for line in fetch(prefix).splitlines():
        rest, _, count = line.strip().partition(":")
        if rest == suffix:
            return int(count or 0)       # padding lines have a count of 0
    return 0


def _days_since(stamp: str, today: datetime) -> int:
    try:
        then = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (today - then).days


def _base(password: str) -> str:
    return password.rstrip(string.digits + string.punctuation).lower()


def audit(entries: Iterable[Entry], max_age_days: int = 365, online: bool = False,
          fetch: Fetcher = fetch_range, today: datetime | None = None) -> Report:
    today = today or datetime.now(timezone.utc)
    with_password = [e for e in entries if e.password]
    report = Report(len(with_password))

    by_password: dict[str, list[Entry]] = defaultdict(list)
    by_base: dict[str, list[Entry]] = defaultdict(list)
    for entry in with_password:
        by_password[entry.password].append(entry)
        base = _base(entry.password)
        if len(base) >= 4:
            by_base[base].append(entry)

    for entry in with_password:
        result = strength.estimate(entry.password, [entry.title, entry.username, entry.url])
        if result.score < 3:
            reason = result.warnings[0] if result.warnings else f"about {result.bits:.0f} bits"
            report.findings.append(Finding(entry, "weak", f"{result.label}: {reason}"))
        others = [e.title for e in by_password[entry.password] if e is not entry]
        if others:
            report.findings.append(Finding(entry, "reused", "same password as " + ", ".join(sorted(others))))
        else:
            near = [e.title for e in by_base.get(_base(entry.password), []) if e is not entry]
            if near:
                report.findings.append(Finding(entry, "similar", "nearly the same password as " + ", ".join(sorted(near))))
        age = _days_since(entry.password_changed, today)
        if max_age_days and age > max_age_days:
            report.findings.append(Finding(entry, "old", f"not changed for {age // 30} months"))

    if online:
        checked: dict[str, int] = {}
        try:
            for entry in with_password:
                if entry.password not in checked:
                    checked[entry.password] = breach_count(entry.password, fetch)
                count = checked[entry.password]
                if count:
                    report.findings.append(Finding(entry, "breached",
                                                   f"seen {count:,} times in known data breaches: change it now"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            report.online_error = f"the breach check couldn't reach the service ({exc}); the offline checks still ran"
    order = {"breached": 0, "reused": 1, "weak": 2, "similar": 3, "old": 4}
    report.findings.sort(key=lambda f: (order[f.kind], f.entry.title.lower()))
    return report
