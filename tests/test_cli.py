import base64
import json
import os

import pytest

from keyhaven import cli, clipboard, totp

MASTER = "correct horse battery staple 42"
STRONG = "vT9#qLm2&xR8pW!z"


class Terminal:
    """Stands in for the person at the keyboard: answers password prompts and y/N questions in order."""

    def __init__(self, monkeypatch):
        self.secrets: list[str] = []
        self.answers: list[str] = []
        self.prompts: list[str] = []
        monkeypatch.setattr(cli, "ask_secret", self._secret)
        monkeypatch.setattr(cli, "ask", self._ask)

    def _secret(self, prompt):
        self.prompts.append(prompt)
        if not self.secrets:
            raise AssertionError(f"unexpected password prompt: {prompt}")
        return self.secrets.pop(0)

    def _ask(self, prompt):
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""


@pytest.fixture
def term(monkeypatch):
    return Terminal(monkeypatch)


@pytest.fixture
def vault(tmp_path, term, monkeypatch):
    path = tmp_path / "vault.json"
    monkeypatch.setenv("KEYHAVEN_VAULT", str(path))
    term.secrets = [MASTER, MASTER]
    assert cli.main(["init", "--scrypt-log-n", "10"]) == 0
    return path


def run(term, args, secrets=(), answers=()):
    term.secrets = [MASTER, *secrets]
    term.answers = list(answers)
    return cli.main(args)


def test_init_add_show_and_list(vault, term, capsys):
    assert run(term, ["add", "GitHub", "-u", "ada", "--url", "https://github.com", "--tags", "work,code"],
               [STRONG, STRONG]) == 0
    assert run(term, ["show", "git"]) == 0
    out = capsys.readouterr().out
    assert "GitHub" in out and "ada" in out and STRONG not in out and "--reveal" in out
    run(term, ["show", "github", "--reveal"])
    assert STRONG in capsys.readouterr().out
    run(term, ["list"])
    out = capsys.readouterr().out
    assert "GitHub" in out and "work, code" in out and "1 of 1 entries" in out


def test_the_vault_file_never_contains_secrets(vault, term):
    run(term, ["add", "Bank", "-u", "ada@example.com", "--notes", "the pin is 4321"], [STRONG, STRONG])
    raw = vault.read_text()
    for secret in (STRONG, "ada@example.com", "Bank", "4321"):
        assert secret not in raw
    assert json.loads(raw)["format"] == "keyhaven"


def test_weak_passwords_are_questioned(vault, term, capsys):
    assert run(term, ["add", "Forum"], ["password1", "password1", STRONG, STRONG], answers=["n"]) == 0
    err = capsys.readouterr().err
    assert "very weak" in err and "common password" in err
    run(term, ["show", "Forum", "-r"])
    assert STRONG in capsys.readouterr().out


def test_mismatched_passwords_are_asked_again(vault, term, capsys):
    assert run(term, ["add", "Mail"], [STRONG, "typo", STRONG, STRONG]) == 0
    assert "don't match" in capsys.readouterr().err


def test_wrong_master_password_gets_three_tries(vault, term, capsys):
    term.secrets = ["nope", "still no", "wrong again"]
    assert cli.main(["list"]) == 2
    assert "wrong master password" in capsys.readouterr().err
    term.secrets = ["nope", MASTER]
    assert cli.main(["list"]) == 0


def test_generate_on_add_and_edit_keeps_history(vault, term, capsys):
    run(term, ["add", "Shop", "--generate", "--length", "32"])
    run(term, ["show", "Shop", "-r"])
    first = [l for l in capsys.readouterr().out.splitlines() if "password:" in l][0].split()[-1]
    assert len(first) == 32
    run(term, ["edit", "Shop", "--generate", "--words", "4"])
    run(term, ["history", "Shop", "--reveal"])
    out = capsys.readouterr().out
    assert first in out and "earlier passwords" in out


def test_edit_fields_tags_and_favorites(vault, term, capsys):
    run(term, ["add", "VPN", "--no-password", "--tags", "work", "--field", "server=vpn.example.com"])
    assert run(term, ["edit", "VPN", "--add-tag", "travel", "--remove-tag", "work", "--field", "port=443",
                      "--favorite", "--title", "Office VPN"]) == 0
    run(term, ["show", "office"])
    out = capsys.readouterr().out
    assert "Office VPN  *" in out and "travel" in out and "work" not in out
    assert "server:" in out and "port:" in out
    assert run(term, ["edit", "Office VPN"]) == 1
    assert "nothing to change" in capsys.readouterr().err


def test_rm_asks_first(vault, term, capsys):
    run(term, ["add", "Old", "--no-password"])
    assert run(term, ["rm", "Old"], answers=["n"]) == 1
    assert run(term, ["rm", "Old"], answers=["y"]) == 0
    assert run(term, ["show", "Old"]) == 1
    assert "no entry called 'Old'" in capsys.readouterr().err


def test_ambiguous_and_misspelled_names(vault, term, capsys):
    for title in ("Google Mail", "Google Drive"):
        run(term, ["add", title, "--no-password"])
    assert run(term, ["show", "google"]) == 1
    assert "matches 2 entries" in capsys.readouterr().err
    assert run(term, ["show", "Gogle Mail"]) == 1
    assert "did you mean 'Google Mail'" in capsys.readouterr().err


def test_totp_codes(vault, term, capsys, monkeypatch):
    secret = base64.b32encode(b"12345678901234567890").decode()
    run(term, ["add", "Cloud", "--no-password", "--totp", secret])
    capsys.readouterr()
    monkeypatch.setattr(totp.time, "time", lambda: 59)
    run(term, ["totp", "Cloud"])
    assert capsys.readouterr().out == "287082   (1 s left)\n"
    assert run(term, ["add", "Bad", "--no-password", "--totp", "not base32!"]) == 1
    assert "isn't a valid 2FA secret" in capsys.readouterr().err


def test_copy_uses_the_clipboard_and_the_setting(vault, term, capsys, monkeypatch):
    copied = []
    monkeypatch.setattr(clipboard, "copy_and_clear_later", lambda text, seconds: copied.append((text, seconds)))
    run(term, ["add", "Wifi", "-u", "guest"], [STRONG, STRONG])
    run(term, ["set", "clipboard_seconds", "45"])
    assert run(term, ["copy", "Wifi"]) == 0
    assert run(term, ["copy", "Wifi", "username"]) == 0
    assert copied == [(STRONG, 45), ("guest", 45)]
    assert "cleared in 45 s" in capsys.readouterr().out
    assert run(term, ["copy", "Wifi", "pin"]) == 1
    assert run(term, ["set", "clipboard_seconds", "9999"]) == 1


def test_change_master_password(vault, term):
    run(term, ["add", "X", "--no-password"])
    new = "a brand new master passphrase 2026"
    assert run(term, ["passwd"], [new, new]) == 0
    term.secrets = [MASTER, MASTER, MASTER]
    assert cli.main(["list"]) == 2
    term.secrets = [new]
    assert cli.main(["list"]) == 0


def test_info_needs_no_password(vault, term, capsys):
    term.secrets = []
    assert cli.main(["info"]) == 0
    out = capsys.readouterr().out
    assert "scrypt N=2^10" in out and "aes-256-gcm" in out


def test_generate_and_check_store_nothing(term, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("KEYHAVEN_VAULT", str(tmp_path / "none.json"))
    assert cli.main(["generate", "-n", "3", "--length", "12", "--no-symbols"]) == 0
    lines = capsys.readouterr().out.split()
    assert len(lines) == 3 and all(len(l) == 12 and l.isalnum() for l in lines)
    term.secrets = ["Summer2024!"]
    assert cli.main(["check"]) == 1
    assert "common password with small changes" in capsys.readouterr().out
    term.secrets = ["lmnopq-Kestrel-1987"]
    cli.main(["check"])
    assert "it has a year" in capsys.readouterr().out
    assert not (tmp_path / "none.json").exists()


def test_missing_vault_and_existing_vault(vault, term, capsys, tmp_path, monkeypatch):
    term.secrets = [MASTER, MASTER]
    assert cli.main(["init", "--scrypt-log-n", "10"]) == 1
    assert "already a vault" in capsys.readouterr().err
    monkeypatch.setenv("KEYHAVEN_VAULT", str(tmp_path / "missing.json"))
    assert cli.main(["list"]) == 1
    assert "keyhaven init" in capsys.readouterr().err


def test_clipboard_clears_only_its_own_text(monkeypatch):
    board = {"text": ""}
    monkeypatch.setattr(clipboard, "copy", lambda text, tool=None: board.update(text=text))
    monkeypatch.setattr(clipboard, "paste", lambda tool=None: board["text"])
    tool = clipboard.Backend("fake", [], [])
    clipboard.copy("s3cret", tool)
    assert clipboard.clear_if_unchanged(clipboard.fingerprint("s3cret"), tool) and board["text"] == ""
    clipboard.copy("something you copied since", tool)
    assert not clipboard.clear_if_unchanged(clipboard.fingerprint("s3cret"), tool)
    assert board["text"] == "something you copied since"


def test_audit_command(vault, term, capsys):
    run(term, ["add", "A"], [STRONG, STRONG])
    run(term, ["add", "B"], [STRONG, STRONG])
    capsys.readouterr()
    assert run(term, ["audit"]) == 1
    out = capsys.readouterr().out
    assert "used in more than one entry (2)" in out and "2 of 2 entries need attention" in out
    run(term, ["rm", "B", "-y"])
    assert run(term, ["audit"]) == 0
    assert "no problems found" in capsys.readouterr().out


def test_import_export_and_backup(vault, term, capsys, tmp_path):
    source = tmp_path / "chrome.csv"
    source.write_text("name,url,username,password,note\nReddit,https://reddit.com,ada,r3dd1t-Pass,\n")
    assert run(term, ["import", str(source), "--dry-run"]) == 0
    assert "1 new" in capsys.readouterr().out
    assert run(term, ["list"]) == 0 and "no entries" in capsys.readouterr().out
    assert run(term, ["import", str(source)]) == 0
    assert "delete it" in capsys.readouterr().out

    out = tmp_path / "export.csv"
    assert run(term, ["export", str(out)], answers=["n"]) == 1 and not out.exists()
    assert run(term, ["export", str(out)], answers=["y"]) == 0
    assert "r3dd1t-Pass" in out.read_text()
    assert run(term, ["export", str(out), "-y"]) == 1          # won't overwrite
    if os.name == "posix":
        assert out.stat().st_mode & 0o077 == 0

    term.secrets = []
    assert cli.main(["backup", str(tmp_path)]) == 0
    copies = list(tmp_path.glob("keyhaven-*.json"))
    assert len(copies) == 1 and copies[0].read_bytes() == vault.read_bytes()
