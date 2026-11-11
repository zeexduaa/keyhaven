"""Moving entries in and out: CSV exports from other password managers, and keyhaven's own exports.

Recognised CSV layouts (found from the header row):

- Bitwarden:  folder, favorite, type, name, notes, fields, reprompt, login_uri, login_username, login_password, login_totp
- Chrome, Edge, Brave and other Chromium browsers:  name, url, username, password, note
- Firefox:    url, username, password, httpRealm, formActionOrigin, guid, timeCreated, timeLastUsed, timePasswordChanged
- 1Password:  Title, Url, Username, Password, OTPAuth, Favorite, Archived, Tags, Notes
- keyhaven:   title, username, password, url, notes, tags, totp

An export file holds every password in plain text. It's meant for moving to
another manager, after which it should be deleted (keyhaven warns about this).
For an encrypted copy, use ``keyhaven backup``.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

from .entries import Entries, Entry, clean_tags
from .vault import now


class TransferError(ValueError):
    pass


KEYHAVEN_COLUMNS = ["title", "username", "password", "url", "notes", "tags", "totp"]

FORMATS = {
    "bitwarden": {"name", "login_uri", "login_username", "login_password"},
    "1password": {"title", "url", "username", "password", "otpauth"},
    "firefox": {"url", "username", "password", "httprealm", "formactionorigin"},
    "keyhaven": {"title", "username", "password", "url", "tags"},
    "chrome": {"name", "url", "username", "password"},
}


@dataclass
class ImportResult:
    format: str
    added: list[Entry] = field(default_factory=list)
    duplicates: int = 0          # identical to an existing entry: skipped
    renamed: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def detect(columns: Iterable[str]) -> str:
    names = {c.strip().lower() for c in columns}
    for name, needed in FORMATS.items():       # most specific first
        if needed <= names:
            return name
    raise TransferError("this CSV doesn't look like an export keyhaven knows (Bitwarden, Chrome, Firefox, "
                        f"1Password or keyhaven); its columns are: {', '.join(sorted(names)) or 'none'}")


def _title_from_url(url: str) -> str:
    host = urlparse(url if "//" in url else "//" + url).hostname or url
    return host.removeprefix("www.") if host else ""


def _firefox_time(value: str) -> str:
    """Firefox writes milliseconds since 1970."""
    try:
        moment = datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return now()
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_entry(fmt: str, row: dict[str, str]) -> Entry | None:
    get = lambda *names: next((row[n].strip() for n in names if row.get(n)), "")      # noqa: E731
    if fmt == "bitwarden":
        if get("type") not in ("", "login", "note"):
            return None                         # cards and identities aren't supported yet
        fields = {}
        for line in get("fields").splitlines():
            name, sep, value = line.partition(": ")
            if sep:
                fields[name] = value
        folder = get("folder")
        return Entry(title=get("name"), username=get("login_username"), password=row.get("login_password", ""),
                     url=get("login_uri").split(",")[0], notes=row.get("notes", ""), totp=get("login_totp"),
                     tags=[folder] if folder else [], fields=fields, favorite=get("favorite") == "1")
    if fmt == "1password":
        return Entry(title=get("title"), username=get("username"), password=row.get("password", ""),
                     url=get("url"), notes=row.get("notes", ""), totp=get("otpauth"),
                     tags=clean_tags(get("tags").replace(";", ",")), favorite=get("favorite").lower() in ("1", "true"))
    if fmt == "firefox":
        url = get("url")
        entry = Entry(title=_title_from_url(url), username=get("username"), password=row.get("password", ""), url=url)
        if get("timepasswordchanged"):
            entry.password_changed = _firefox_time(get("timepasswordchanged"))
        return entry
    if fmt == "chrome":
        url = get("url")
        return Entry(title=get("name") or _title_from_url(url), username=get("username"),
                     password=row.get("password", ""), url=url, notes=get("note", "notes"))
    return Entry(title=get("title"), username=get("username"), password=row.get("password", ""), url=get("url"),
                 notes=row.get("notes", ""), tags=clean_tags(get("tags")), totp=get("totp"))


def read_csv(text: str) -> tuple[str, list[Entry], list[str]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if not reader.fieldnames:
        raise TransferError("the CSV file is empty")
    fmt = detect(reader.fieldnames)
    entries, skipped = [], []
    for number, raw in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v if isinstance(v, str) else "") for k, v in raw.items()}
        entry = _row_to_entry(fmt, row)
        if entry is None:
            skipped.append(f"line {number}: not a login (cards and identities aren't imported)")
            continue
        if not entry.title:
            entry.title = entry.username or f"imported {number - 1}"
        if not (entry.password or entry.username or entry.notes or entry.url):
            skipped.append(f"line {number}: empty")
            continue
        entries.append(entry)
    return fmt, entries, skipped


def _signature(entry: Entry) -> tuple[str, ...]:
    """What makes two entries the same login. Entries without login details (secure notes) all
    share an empty URL, username and password, so for those the title and notes decide."""
    login = (entry.url.strip().lower(), entry.username.strip().lower(), entry.password)
    if any(login):
        return ("login", *login)
    return ("note", entry.title.strip().lower(), entry.notes)


def import_entries(target: Entries, incoming: list[Entry], fmt: str, skipped: list[str] | None = None) -> ImportResult:
    """Adds entries; identical ones are skipped and title clashes get a number: 'GitHub (2)'.
    The same login is recognised by URL, username and password, a note by its title and text."""
    result = ImportResult(fmt, skipped=list(skipped or []))
    existing = list(target)
    signatures = {_signature(e) for e in existing}
    titles = {e.title.lower() for e in existing}
    for entry in incoming:
        signature = _signature(entry)
        if signature in signatures:
            result.duplicates += 1
            continue
        original = entry.title.strip()
        title, n = original, 2
        while title.lower() in titles:
            title, n = f"{original} ({n})", n + 1
        if title != original:
            result.renamed.append((original, title))
        entry.title = title
        if entry.totp:
            from . import totp
            try:
                totp.parse(entry.totp)
            except totp.TotpError as exc:
                result.skipped.append(f"{title}: 2FA secret dropped ({exc})")
                entry.totp = ""
        target.add(entry)
        signatures.add(signature)
        titles.add(title.lower())
        result.added.append(entry)
    return result


def to_csv(entries: Iterable[Entry]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(KEYHAVEN_COLUMNS)
    for e in entries:
        writer.writerow([e.title, e.username, e.password, e.url, e.notes, ",".join(e.tags), e.totp])
    return out.getvalue()


def to_json(entries: Iterable[Entry]) -> str:
    """Everything, including custom fields and password history."""
    return json.dumps({"format": "keyhaven-export", "version": 1, "exported": now(),
                       "entries": [e.to_dict() for e in entries]}, indent=2, ensure_ascii=False) + "\n"


def read_json(text: str) -> list[Entry]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TransferError(f"the file isn't valid JSON ({exc})") from None
    if not isinstance(doc, dict) or doc.get("format") != "keyhaven-export" or not isinstance(doc.get("entries"), list):
        raise TransferError("this JSON file isn't a keyhaven export")
    entries = []
    for item in doc["entries"]:
        if not isinstance(item, dict) or not item.get("title"):
            raise TransferError("the export has an entry without a title")
        entry = Entry.from_dict(item)
        fresh = Entry(title=entry.title)          # new id, so importing twice can't make id clashes
        entry.id = fresh.id
        entries.append(entry)
    return entries
