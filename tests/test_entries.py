import pytest

from keyhaven.entries import Entries, Entry, EntryError, clean_tags
from keyhaven.vault import Vault


@pytest.fixture
def store(tmp_path, fast_kdf):
    vault = Vault.create(tmp_path / "vault.json", "pw", fast_kdf())
    entries = Entries(vault)
    entries.add(Entry("GitHub", username="ada", password="gh-pass", url="https://github.com", tags=["work", "dev"]))
    entries.add(Entry("Gmail", username="ada@example.com", password="mail-pass", tags=["personal"]))
    entries.add(Entry("Bank of Example", username="ada1", password="bank-pass", notes="branch 42", favorite=True))
    entries.save()
    return entries


def test_entries_survive_reopening(store, tmp_path):
    reopened = Entries(Vault.open(tmp_path / "vault.json", "pw"))
    assert [e.title for e in reopened] == ["Bank of Example", "GitHub", "Gmail"]     # favorites first
    assert reopened.find("github").password == "gh-pass"


def test_find_by_title_id_or_unique_part(store):
    gh = store.find("GITHUB")
    assert store.find(gh.id[:6]) is gh
    assert store.find("bank").title == "Bank of Example"


def test_ambiguous_and_missing_lookups_explain_themselves(store):
    with pytest.raises(EntryError, match="'g' matches 2 entries: GitHub .*, Gmail"):
        store.find("g")
    with pytest.raises(EntryError, match="no entry called 'Githb'; did you mean 'GitHub'?"):
        store.find("Githb")


def test_search_ranks_and_never_looks_at_passwords(store):
    assert [e.title for e in store.search("gmail")] == ["Gmail"]
    assert [e.title for e in store.search("ada")] == ["Bank of Example", "GitHub", "Gmail"]
    assert store.search("mail-pass") == []
    assert [e.title for e in store.search("42")] == ["Bank of Example"]          # notes
    assert [e.title for e in store.search(tag="WORK")] == ["GitHub"]
    assert store.tags() == {"dev": 1, "personal": 1, "work": 1}


def test_titles_are_unique(store):
    with pytest.raises(EntryError, match="already an entry called 'github'"):
        store.add(Entry("github"))
    with pytest.raises(EntryError, match="already an entry called 'Gmail'"):
        store.update(store.find("GitHub"), title="Gmail")
    with pytest.raises(EntryError, match="needs a title"):
        store.add(Entry("   "))


def test_password_changes_are_kept_in_history(store, tmp_path):
    gh = store.find("GitHub")
    store.update(gh, password="new-1")
    store.update(gh, password="new-2")
    store.update(gh, username="ada2")                     # not a password change
    store.save()
    reopened = Entries(Vault.open(tmp_path / "vault.json", "pw")).find("GitHub")
    assert reopened.password == "new-2" and reopened.username == "ada2"
    assert [h["password"] for h in reopened.history] == ["new-1", "gh-pass"]


def test_history_is_limited(store):
    gh = store.find("GitHub")
    store.vault.payload["settings"]["history_limit"] = 3
    for i in range(6):
        store.update(gh, password=f"p{i}")
    assert [h["password"] for h in gh.history] == ["p4", "p3", "p2"]


def test_remove(store):
    store.remove(store.find("Gmail"))
    assert len(store) == 2
    with pytest.raises(EntryError):
        store.find("Gmail")


def test_unknown_fields_and_tags_cleanup(store):
    with pytest.raises(EntryError, match="unknown field"):
        store.update(store.find("GitHub"), colour="red")
    assert clean_tags("Work, mail ,work,, ") == ["Work", "mail"]


def test_entries_from_older_or_newer_versions_load(store):
    data = Entry("x").to_dict()
    data["future_field"] = "ignored"
    del data["fields"]
    assert Entry.from_dict(data).fields == {}
