import hashlib
import urllib.error
from datetime import datetime, timezone

from keyhaven import audit
from keyhaven.entries import Entry

STRONG = "vT9#qLm2&xR8pW!z"
TODAY = datetime(2026, 11, 1, tzinfo=timezone.utc)


def entry(title, password, changed="2026-10-01T00:00:00Z"):
    return Entry(title=title, password=password, password_changed=changed)


def fake_service(breached: dict[str, int], calls: list[str]):
    def fetch(prefix):
        calls.append(prefix)
        lines = ["0123456789ABCDEF0123456789ABCDEF012:0"]          # a padding line
        for pw, count in breached.items():
            digest = hashlib.sha1(pw.encode()).hexdigest().upper()
            if digest.startswith(prefix):
                lines.append(f"{digest[5:]}:{count}")
        return "\r\n".join(lines)
    return fetch


def kinds(report):
    return {(f.entry.title, f.kind) for f in report.findings}


def test_offline_checks():
    report = audit.audit([
        entry("Mail", STRONG), entry("Bank", STRONG),                       # reused
        entry("Forum", "password123"),                                      # weak
        entry("Shop", "Kx8$wq2LmzR4!pQ2023"), entry("Store", "Kx8$wq2LmzR4!pQ2024"),   # similar
        entry("Old", "Hq7&nV3!zLw9#tB5", "2024-01-01T00:00:00Z"),           # old
        Entry(title="Note only"),                                           # no password: skipped
    ], today=TODAY)
    assert report.checked == 6
    assert kinds(report) == {("Mail", "reused"), ("Bank", "reused"), ("Forum", "weak"),
                             ("Shop", "similar"), ("Store", "similar"), ("Old", "old")}
    assert report.entries_with_problems == 6
    assert report.findings[0].kind == "reused"
    assert "Bank" in report.by_kind("reused")[1].detail or "Mail" in report.by_kind("reused")[1].detail


def test_a_clean_vault():
    report = audit.audit([entry("A", STRONG), entry("B", "Hq7&nV3!zLw9#tB5")], today=TODAY)
    assert report.findings == [] and report.checked == 2
    assert audit.audit([entry("Old", STRONG, "2020-01-01T00:00:00Z")], max_age_days=0, today=TODAY).findings == []


def test_breach_check_sends_only_a_prefix_and_asks_once_per_password():
    calls = []
    fetch = fake_service({"hunter2-but-longer": 1234}, calls)
    report = audit.audit([entry("A", "hunter2-but-longer"), entry("B", "hunter2-but-longer"), entry("C", STRONG)],
                         online=True, fetch=fetch, today=TODAY)
    assert all(len(c) == 5 for c in calls) and len(calls) == 2
    assert {f.entry.title for f in report.by_kind("breached")} == {"A", "B"}
    assert "1,234 times" in report.by_kind("breached")[0].detail
    assert report.findings[0].kind == "breached"


def test_breach_check_failure_is_reported_not_fatal():
    def offline(prefix):
        raise urllib.error.URLError("no network")
    report = audit.audit([entry("A", STRONG), entry("B", STRONG)], online=True, fetch=offline, today=TODAY)
    assert "couldn't reach" in report.online_error
    assert {f.kind for f in report.findings} == {"reused"}


def test_padding_lines_are_not_matches():
    digest = hashlib.sha1(b"x").hexdigest().upper()
    assert audit.breach_count("x", lambda p: f"{digest[5:]}:0\n") == 0
