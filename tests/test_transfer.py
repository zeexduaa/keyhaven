import json

import pytest

from keyhaven import transfer
from keyhaven.entries import Entries, Entry
from keyhaven.vault import Vault

BITWARDEN = """folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,GitHub,my notes,"recovery: abc
team: core",0,"https://github.com,https://gist.github.com",ada,gh-Secret-123,JBSWY3DPEHPK3PXP
,,card,Visa,,,0,,,,
,,login,Mail,,,0,https://mail.example.com,ada@example.com,m41l-pass,not-a-secret!
"""
CHROME = "﻿name,url,username,password,note\n,https://www.reddit.com/login,ada,r3dd1t,\nBank,https://bank.example,ada,b4nk,pin hint\n"
FIREFOX = ("url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
           "https://news.ycombinator.com,ada,hn-pass,,https://news.ycombinator.com,{x},1600000000000,1600000000000,"
           "1600000000000\n")
ONEPASSWORD = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nSlack,https://slack.com,ada,sl4ck,,true,false,work;chat,\n"


def test_detects_formats():
    assert transfer.read_csv(BITWARDEN)[0] == "bitwarden"
    assert transfer.read_csv(CHROME)[0] == "chrome"
    assert transfer.read_csv(FIREFOX)[0] == "firefox"
    assert transfer.read_csv(ONEPASSWORD)[0] == "1password"
    with pytest.raises(transfer.TransferError, match="doesn't look like an export"):
        transfer.read_csv("a,b,c\n1,2,3\n")
    with pytest.raises(transfer.TransferError, match="empty"):
        transfer.read_csv("")


def test_bitwarden_rows():
    fmt, entries, skipped = transfer.read_csv(BITWARDEN)
    github, mail = entries
    assert (github.title, github.username, github.password, github.url) == \
        ("GitHub", "ada", "gh-Secret-123", "https://github.com")
    assert github.tags == ["Work"] and github.favorite and github.totp == "JBSWY3DPEHPK3PXP"
    assert github.fields == {"recovery": "abc", "team": "core"}
    assert "line 3" in skipped[0] and mail.title == "Mail"


def test_browser_rows():
    _, (reddit, bank), _ = transfer.read_csv(CHROME)
    assert reddit.title == "reddit.com" and bank.notes == "pin hint"
    _, (hn,), _ = transfer.read_csv(FIREFOX)
    assert hn.title == "news.ycombinator.com" and hn.password_changed == "2020-09-13T12:26:40Z"
    _, (slack,), _ = transfer.read_csv(ONEPASSWORD)
    assert slack.tags == ["work", "chat"] and slack.favorite


def test_import_skips_duplicates_renames_clashes_and_drops_bad_2fa(tmp_path, fast_kdf):
    entries = Entries(Vault.create(tmp_path / "v.json", "pw", fast_kdf()))
    entries.add(Entry(title="GitHub", username="someone-else", password="x"))
    fmt, incoming, skipped = transfer.read_csv(BITWARDEN)
    result = transfer.import_entries(entries, incoming, fmt, skipped)
    assert [e.title for e in result.added] == ["GitHub (2)", "Mail"]
    assert result.renamed == [("GitHub", "GitHub (2)")]
    assert any("2FA secret dropped" in s for s in result.skipped)
    again = transfer.import_entries(entries, transfer.read_csv(BITWARDEN)[1], fmt)
    assert again.duplicates == 2 and not again.added


def test_round_trips(tmp_path, fast_kdf):
    original = [Entry(title="A, with comma", username="u", password='p"q', notes="two\nlines", tags=["x", "y"],
                      fields={"pin": "1234"})]
    _, back, _ = transfer.read_csv(transfer.to_csv(original))
    assert (back[0].title, back[0].password, back[0].notes, back[0].tags) == ("A, with comma", 'p"q', "two\nlines", ["x", "y"])
    restored = transfer.read_json(transfer.to_json(original))
    assert restored[0].fields == {"pin": "1234"} and restored[0].id != original[0].id
    with pytest.raises(transfer.TransferError, match="isn't a keyhaven export"):
        transfer.read_json(json.dumps({"entries": []}))


def test_secure_notes_are_not_mistaken_for_duplicates(tmp_path, fast_kdf):
    notes = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
             ",,note,Wifi codes,home: abc123,,0,,,,\n"
             ",,note,Passport number,X1234567,,0,,,,\n"
             ",,note,Recovery codes,1111 2222,,0,,,,\n")
    entries = Entries(Vault.create(tmp_path / "v.json", "pw", fast_kdf()))
    first = transfer.import_entries(entries, transfer.read_csv(notes)[1], "bitwarden")
    assert len(first.added) == 3 and first.duplicates == 0
    again = transfer.import_entries(entries, transfer.read_csv(notes)[1], "bitwarden")
    assert not again.added and again.duplicates == 3
