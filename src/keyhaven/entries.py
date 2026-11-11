"""Entries (one login each) and the operations on them.

Entries are found by title, case-insensitively, or by the start of their id
(``keyhaven show 3f2a``). A search that matches several entries is an error
listing them, rather than a guess, so you never copy the wrong password.

Changing an entry's password keeps the old one in its history (up to the
vault's ``history_limit``), with the date it was replaced.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from typing import Any

from .vault import Vault, VaultError, now


class EntryError(VaultError):
    pass


@dataclass
class Entry:
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    totp: str = ""                                   # a base32 secret or an otpauth:// URI
    fields: dict[str, str] = field(default_factory=dict)
    favorite: bool = False
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    created: str = field(default_factory=now)
    modified: str = field(default_factory=now)
    password_changed: str = field(default_factory=now)
    history: list[dict[str, str]] = field(default_factory=list)   # [{"password": ..., "changed": ...}]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        known = {f for f in cls.__dataclass_fields__}
        entry = cls(**{k: v for k, v in data.items() if k in known})
        entry.tags = [str(t) for t in entry.tags or []]
        entry.fields = {str(k): str(v) for k, v in (entry.fields or {}).items()}
        return entry

    def matches(self, query: str) -> int:
        """How well the entry matches a search (0 = not at all). Passwords and notes' secrets
        are never searched: only title, username, URL, tags, notes and custom field names."""
        q = query.lower()
        title = self.title.lower()
        if title == q:
            return 100
        if title.startswith(q):
            return 80
        if q in title:
            return 60
        if any(q == t.lower() for t in self.tags):
            return 50
        if q in self.username.lower() or q in self.url.lower():
            return 40
        if any(q in t.lower() for t in self.tags) or any(q in k.lower() for k in self.fields):
            return 30
        if q in self.notes.lower():
            return 10
        return 0


class Entries:
    """The entries of an open vault. Changes are written when you call save()."""

    def __init__(self, vault: Vault):
        self.vault = vault
        self._entries = [Entry.from_dict(d) for d in vault.payload["entries"]]

    def __iter__(self):
        return iter(sorted(self._entries, key=lambda e: (not e.favorite, e.title.lower())))

    def __len__(self) -> int:
        return len(self._entries)

    def save(self) -> None:
        self.vault.payload["entries"] = [e.to_dict() for e in self._entries]
        self.vault.save()

    @property
    def history_limit(self) -> int:
        return int(self.vault.payload.get("settings", {}).get("history_limit", 10))

    # -- finding ----------------------------------------------------------------------------------

    def find(self, query: str) -> Entry:
        """One entry by exact title (any case) or id prefix; else a unique partial title match."""
        query = query.strip()
        if not query:
            raise EntryError("which entry? give a title or an id")
        q = query.lower()
        exact = [e for e in self._entries if e.title.lower() == q]
        if len(exact) == 1:
            return exact[0]
        by_id = [e for e in self._entries if e.id.startswith(q)] if len(q) >= 4 else []
        if len(by_id) == 1:
            return by_id[0]
        candidates = exact or by_id or [e for e in self._entries if q in e.title.lower()]
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise EntryError(f"no entry called '{query}'" + self._suggest(query))
        listing = ", ".join(f"{e.title} ({e.id[:6]})" for e in sorted(candidates, key=lambda e: e.title.lower())[:8])
        raise EntryError(f"'{query}' matches {len(candidates)} entries: {listing}; be more specific or use the id")

    def _suggest(self, query: str) -> str:
        import difflib
        close = difflib.get_close_matches(query.lower(), [e.title.lower() for e in self._entries], n=1, cutoff=0.6)
        if close:
            original = next(e.title for e in self._entries if e.title.lower() == close[0])
            return f"; did you mean '{original}'?"
        return ""

    def search(self, query: str = "", tag: str | None = None) -> list[Entry]:
        entries = [e for e in self._entries if tag is None or tag.lower() in (t.lower() for t in e.tags)]
        if not query:
            return sorted(entries, key=lambda e: (not e.favorite, e.title.lower()))
        scored = [(e.matches(query), e) for e in entries]
        return [e for score, e in sorted(scored, key=lambda s: (-s[0], s[1].title.lower())) if score > 0]

    def tags(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self._entries:
            for t in e.tags:
                counts[t] = counts.get(t, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: kv[0].lower()))

    # -- changing --------------------------------------------------------------------------------------

    def add(self, entry: Entry) -> Entry:
        entry.title = entry.title.strip()
        if not entry.title:
            raise EntryError("an entry needs a title")
        if any(e.title.lower() == entry.title.lower() for e in self._entries):
            raise EntryError(f"there's already an entry called '{entry.title}'; use edit to change it, "
                             "or give this one another title")
        entry.tags = clean_tags(entry.tags)
        self._entries.append(entry)
        return entry

    def update(self, entry: Entry, **changes: Any) -> Entry:
        """Changes fields of an entry. A new password moves the old one into the history."""
        unknown = set(changes) - {"title", "username", "password", "url", "notes", "tags", "totp", "fields", "favorite"}
        if unknown:
            raise EntryError(f"unknown field(s): {', '.join(sorted(unknown))}")
        if "title" in changes:
            title = str(changes["title"]).strip()
            if not title:
                raise EntryError("an entry needs a title")
            if any(e is not entry and e.title.lower() == title.lower() for e in self._entries):
                raise EntryError(f"there's already an entry called '{title}'")
            changes["title"] = title
        if "password" in changes and changes["password"] != entry.password:
            if entry.password:
                entry.history.insert(0, {"password": entry.password, "changed": now()})
                del entry.history[self.history_limit:]
            entry.password_changed = now()
        if "tags" in changes:
            changes["tags"] = clean_tags(changes["tags"])
        for name, value in changes.items():
            setattr(entry, name, value)
        entry.modified = now()
        return entry

    def remove(self, entry: Entry) -> None:
        self._entries.remove(entry)


def clean_tags(tags: list[str] | str) -> list[str]:
    """'Work, mail ,work' -> ['work', 'mail']: trimmed, no empties, no duplicates (any case)."""
    if isinstance(tags, str):
        tags = tags.split(",")
    seen: dict[str, str] = {}
    for tag in tags:
        tag = str(tag).strip()
        if tag and tag.lower() not in seen:
            seen[tag.lower()] = tag
    return list(seen.values())
